// Package backup makes consistent backups of the storage root — images,
// users, projects, settings and the audit log — to S3 or a directory, on a
// cron schedule, and restores them.
package backup

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"rgstr/internal/config"
)

// ManifestName is the first entry of every archive.
const ManifestName = "rgstr-backup.json"

// Manifest describes an archive.
type Manifest struct {
	Format  int       `json:"format"`
	Version string    `json:"rgstr_version"`
	Created time.Time `json:"created"`
}

// ErrBusy is returned when a backup is already running.
var ErrBusy = errors.New("a backup is already running")

// Runner makes scheduled and manual backups.
type Runner struct {
	cfg     config.BackupConfig
	root    string
	version string
	target  Target
	sched   *Schedule

	// Hold, when set, pauses garbage collection for the duration of a
	// backup and returns the function that resumes it.
	Hold func() (release func())
	// OnRun, when set, is told about every finished backup; user is who
	// started it ("" for the schedule).
	OnRun func(o Object, user string, err error)

	running sync.Mutex
	mu      sync.Mutex
	status  Status
}

// Status is shown in the admin and the metrics.
type Status struct {
	Target      string     `json:"target"`
	Schedule    string     `json:"schedule"`
	Keep        int        `json:"keep"`
	Running     bool       `json:"running"`
	Next        *time.Time `json:"next,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastSize    int64      `json:"last_size,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

// New creates a Runner from cfg; nil (and no error) when backups are off.
func New(cfg config.BackupConfig, root, version string) (*Runner, error) {
	if cfg.Target == "" {
		return nil, nil
	}
	target, err := NewTarget(cfg)
	if err != nil {
		return nil, err
	}
	sched, err := ParseSchedule(cfg.Schedule)
	if err != nil {
		return nil, fmt.Errorf("RGSTR_BACKUP_SCHEDULE: %w", err)
	}
	if cfg.Keep < 1 {
		return nil, errors.New("RGSTR_BACKUP_KEEP must be at least 1")
	}
	r := &Runner{cfg: cfg, root: root, version: version, target: target, sched: sched}
	r.status = Status{Target: target.String(), Schedule: sched.String(), Keep: cfg.Keep}
	return r, nil
}

// Target is where backups go.
func (r *Runner) Target() Target { return r.target }

// Status returns the current state.
func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	st.Running = !r.running.TryLock()
	if !st.Running {
		r.running.Unlock()
	}
	return st
}

// Start runs backups on schedule until ctx is cancelled. A backup missed
// while rgstr was down runs right after the start.
func (r *Runner) Start(ctx context.Context) {
	go func() {
		var last time.Time
		lctx, cancel := context.WithTimeout(ctx, time.Minute)
		if objs, err := List(lctx, r.target); err != nil {
			log.Printf("backup: list %s: %v", r.target, err)
		} else if len(objs) > 0 {
			last = objs[len(objs)-1].Time
			r.mu.Lock()
			r.status.LastSuccess, r.status.LastSize = &last, objs[len(objs)-1].Size
			r.mu.Unlock()
		}
		cancel()
		next := r.sched.Next(time.Now())
		if !last.IsZero() {
			if due := r.sched.Next(last); due.Before(next) {
				next = due // missed: due already, runs now
			}
		}
		for {
			if next.IsZero() {
				log.Printf("backup: schedule %q never matches", r.sched)
				return
			}
			r.mu.Lock()
			r.status.Next = &next
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Until(next)):
			}
			if _, err := r.Run(ctx, ""); err != nil && !errors.Is(err, ErrBusy) {
				log.Printf("backup: %v", err)
			}
			next = r.sched.Next(time.Now())
		}
	}()
}

// Run makes a backup now and then deletes backups beyond Keep. user is
// who asked for it ("" for the schedule).
func (r *Runner) Run(ctx context.Context, user string) (Object, error) {
	if !r.running.TryLock() {
		return Object{}, ErrBusy
	}
	defer r.running.Unlock()
	if r.Hold != nil {
		defer r.Hold()()
	}
	start := time.Now().UTC()
	obj, err := Create(ctx, r.root, r.version, r.target, start)
	if err == nil {
		err = r.prune(ctx)
	}
	r.mu.Lock()
	if err != nil {
		now := time.Now().UTC()
		r.status.LastError, r.status.LastErrorAt = err.Error(), &now
	} else {
		r.status.LastSuccess, r.status.LastSize = &obj.Time, obj.Size
		r.status.LastError, r.status.LastErrorAt = "", nil
	}
	r.mu.Unlock()
	if r.OnRun != nil {
		r.OnRun(obj, user, err)
	}
	if err == nil {
		log.Printf("backup: %s (%d bytes) to %s in %s", obj.Name, obj.Size, r.target, time.Since(start).Round(time.Second))
	}
	return obj, err
}

func (r *Runner) prune(ctx context.Context) error {
	objs, err := List(ctx, r.target)
	if err != nil {
		return err
	}
	for i := 0; i < len(objs)-r.cfg.Keep; i++ {
		if err := r.target.Delete(ctx, objs[i].Name); err != nil {
			return fmt.Errorf("delete old backup %s: %w", objs[i].Name, err)
		}
	}
	return nil
}

// skip reports top-level entries of the storage root that are not backed
// up: unfinished uploads, the process lock, Trivy's database and restore
// leftovers.
func skip(rel string) bool {
	top, _, _ := strings.Cut(rel, "/")
	base := filepath.Base(rel)
	return top == "uploads" || top == ".rgstr.lock" || top == ".trivy" || strings.HasPrefix(top, ".restore-") ||
		strings.HasPrefix(top, ".before-restore-") || strings.HasSuffix(base, ".tmp") ||
		strings.HasPrefix(base, ".tmp-")
}

// Create writes an archive of root to t as the backup taken at at.
//
// Consistency without stopping the registry: files are replaced atomically
// (written aside, then renamed), and the archive holds everything but the
// blobs first, then the blobs. A manifest is written only after its blobs,
// and blobs are deleted only by GC (paused by the caller), so every
// manifest in the archive finds its blobs in it.
func Create(ctx context.Context, root, version string, t Target, at time.Time) (Object, error) {
	var meta, blobs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed while walking
			}
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if skip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			if strings.HasPrefix(rel, "blobs/") {
				blobs = append(blobs, rel)
			} else {
				meta = append(meta, rel)
			}
		}
		return nil
	})
	if err != nil {
		return Object{}, err
	}
	sort.Strings(meta)
	sort.Strings(blobs)

	var estimate int64
	for _, rel := range blobs {
		if info, err := os.Stat(filepath.Join(root, rel)); err == nil {
			estimate += info.Size()
		}
	}

	pr, pw := io.Pipe()
	counter := &countingReader{r: pr}
	done := make(chan error, 1)
	name := objectName(at)
	go func() { done <- t.Put(ctx, name, counter, estimate) }()

	werr := writeArchive(ctx, pw, root, version, at, append(meta, blobs...))
	pw.CloseWithError(werr)
	perr := <-done
	if werr != nil {
		return Object{}, werr
	}
	if perr != nil {
		return Object{}, perr
	}
	return Object{Name: name, Size: counter.n, Time: at}, nil
}

func writeArchive(ctx context.Context, w io.Writer, root, version string, at time.Time, files []string) error {
	tw := tar.NewWriter(w)
	man, _ := json.MarshalIndent(Manifest{Format: 1, Version: version, Created: at}, "", "  ")
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0644, Size: int64(len(man)), ModTime: at,
		Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := tw.Write(man); err != nil {
		return err
	}
	for _, rel := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := addFile(tw, root, rel); err != nil {
			return err
		}
	}
	return tw.Close()
}

func addFile(tw *tar.Writer, root, rel string) error {
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil // deleted meanwhile (a tag, an expired upload)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	// The open file keeps its content even if it is replaced meanwhile;
	// append-only files (audit.log) are cut at the size seen here.
	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: rel, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: info.ModTime(),
		Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.CopyN(tw, f, info.Size())
	return err
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
