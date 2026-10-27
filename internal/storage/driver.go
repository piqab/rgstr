package storage

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Driver stores the registry's files: blobs, manifests, tags, links and
// upload sessions. Paths are relative and slash-separated
// ("blobs/sha256/ab/cdef…"). Two drivers exist: the local filesystem (one
// process, or several sharing a RWX volume) and S3 (any number of
// processes).
type Driver interface {
	// Name is "filesystem" or "s3".
	Name() string
	// Stat returns a file's size and modification time, or an error
	// matching fs.ErrNotExist.
	Stat(ctx context.Context, p string) (FileInfo, error)
	// GetContent reads a small file.
	GetContent(ctx context.Context, p string) ([]byte, error)
	// PutContent replaces a small file atomically (readers see the old or
	// the new content). It also refreshes the modification time.
	PutContent(ctx context.Context, p string, data []byte) error
	// Reader reads a file from offset on.
	Reader(ctx context.Context, p string, offset int64) (io.ReadCloser, error)
	// Writer streams a new file that appears at p only on Commit.
	Writer(ctx context.Context, p string) (FileWriter, error)
	// List returns the entries directly inside dir (names, not paths),
	// sorted; a missing dir is empty.
	List(ctx context.Context, dir string) ([]Entry, error)
	// Walk calls fn for every file under dir, recursively, in no
	// particular order.
	Walk(ctx context.Context, dir string, fn func(p string, info FileInfo) error) error
	// Delete removes a file, or a directory with everything in it. A
	// missing path is not an error.
	Delete(ctx context.Context, p string) error
	// Concat writes dst from srcs, in order, replacing dst. The caller
	// deletes srcs afterwards (the filesystem may move a single source).
	Concat(ctx context.Context, dst string, srcs []string) error
	// RedirectURL returns a URL clients can download p from directly, or
	// "" when the driver serves only through rgstr.
	RedirectURL(p string, ttl time.Duration) string
}

// FileInfo describes a stored file.
type FileInfo struct {
	Size    int64
	ModTime time.Time
}

// Entry is an item of a directory listing.
type Entry struct {
	Name  string
	IsDir bool
	FileInfo
}

// FileWriter receives a file's content.
type FileWriter interface {
	io.Writer
	// Commit makes the file visible; Cancel discards it.
	Commit() error
	Cancel()
}

func notExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// ─── Local filesystem ────────────────────────────────────────────────────────

// FSDriver keeps files under a root directory.
type FSDriver struct{ root string }

// NewFSDriver stores files under root.
func NewFSDriver(root string) *FSDriver { return &FSDriver{root: root} }

func (d *FSDriver) Name() string { return "filesystem" }

// Root is the storage directory.
func (d *FSDriver) Root() string { return d.root }

func (d *FSDriver) full(p string) string { return filepath.Join(d.root, filepath.FromSlash(p)) }

func (d *FSDriver) Stat(_ context.Context, p string) (FileInfo, error) {
	fi, err := os.Stat(d.full(p))
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

func (d *FSDriver) GetContent(_ context.Context, p string) ([]byte, error) {
	return os.ReadFile(d.full(p))
}

func (d *FSDriver) PutContent(_ context.Context, p string, data []byte) error {
	full := d.full(p)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	return atomicWrite(full, data)
}

func (d *FSDriver) Reader(_ context.Context, p string, offset int64) (io.ReadCloser, error) {
	f, err := os.Open(d.full(p))
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

// File opens p for random access (http.ServeContent).
func (d *FSDriver) File(p string) (*os.File, error) { return os.Open(d.full(p)) }

type fsWriter struct {
	f    *os.File
	dest string
}

func (d *FSDriver) Writer(_ context.Context, p string) (FileWriter, error) {
	full := d.full(p)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(full), ".tmp-")
	if err != nil {
		return nil, err
	}
	return &fsWriter{f: f, dest: full}, nil
}

func (w *fsWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

func (w *fsWriter) Commit() error {
	if err := w.f.Close(); err != nil {
		os.Remove(w.f.Name())
		return err
	}
	if err := os.Rename(w.f.Name(), w.dest); err != nil {
		os.Remove(w.f.Name())
		return err
	}
	return nil
}

func (w *fsWriter) Cancel() {
	w.f.Close()
	os.Remove(w.f.Name())
}

func (d *FSDriver) List(_ context.Context, dir string) ([]Entry, error) {
	entries, err := os.ReadDir(d.full(dir))
	if notExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue // temp files of writes in progress
		}
		en := Entry{Name: e.Name(), IsDir: e.IsDir()}
		if info, err := e.Info(); err == nil {
			en.Size, en.ModTime = info.Size(), info.ModTime()
		}
		out = append(out, en)
	}
	return out, nil
}

func (d *FSDriver) Walk(_ context.Context, dir string, fn func(p string, info FileInfo) error) error {
	root := d.full(dir)
	err := filepath.WalkDir(root, func(full string, e fs.DirEntry, err error) error {
		if err != nil {
			if notExist(err) {
				return nil
			}
			return err
		}
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return nil // removed meanwhile
		}
		rel, _ := filepath.Rel(d.root, full)
		return fn(filepath.ToSlash(rel), FileInfo{Size: info.Size(), ModTime: info.ModTime()})
	})
	if notExist(err) {
		return nil
	}
	return err
}

func (d *FSDriver) Delete(_ context.Context, p string) error {
	err := os.RemoveAll(d.full(p))
	if notExist(err) {
		return nil
	}
	return err
}

func (d *FSDriver) Concat(ctx context.Context, dst string, srcs []string) error {
	if len(srcs) == 1 {
		// The common case (one chunk): move instead of copy. The source
		// is the caller's temporary data.
		full := d.full(dst)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		return os.Rename(d.full(srcs[0]), full)
	}
	w, err := d.Writer(ctx, dst)
	if err != nil {
		return err
	}
	for _, s := range srcs {
		f, err := os.Open(d.full(s))
		if err != nil {
			w.Cancel()
			return err
		}
		_, err = io.Copy(w, f)
		f.Close()
		if err != nil {
			w.Cancel()
			return err
		}
	}
	return w.Commit()
}

func (d *FSDriver) RedirectURL(string, time.Duration) string { return "" }

// sortEntries orders a listing by name.
func sortEntries(e []Entry) { sort.Slice(e, func(i, j int) bool { return e[i].Name < e[j].Name }) }

// join builds a driver path.
func join(parts ...string) string { return path.Join(parts...) }
