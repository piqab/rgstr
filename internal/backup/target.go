package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"rgstr/internal/config"
)

// Object is one backup in a target.
type Object struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"` // from the name
}

// Target stores backup archives.
type Target interface {
	// Put stores r under name; sizeHint estimates its length.
	Put(ctx context.Context, name string, r io.Reader, sizeHint int64) error
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	Delete(ctx context.Context, name string) error
	// list returns every object name with its size (unfiltered).
	list(ctx context.Context) ([]Object, error)
	String() string // for logs and the admin: no credentials
}

const (
	namePrefix = "rgstr-backup-"
	nameSuffix = ".tar"
	nameTime   = "20060102-150405"
)

func objectName(t time.Time) string { return namePrefix + t.UTC().Format(nameTime) + nameSuffix }

// List returns the backups in t, oldest first.
func List(ctx context.Context, t Target) ([]Object, error) {
	all, err := t.list(ctx)
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, o := range all {
		stamp, ok := strings.CutPrefix(o.Name, namePrefix)
		stamp, ok2 := strings.CutSuffix(stamp, nameSuffix)
		if !ok || !ok2 {
			continue
		}
		ts, err := time.Parse(nameTime, stamp)
		if err != nil {
			continue
		}
		o.Time = ts
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// NewTarget opens the target of cfg.
func NewTarget(cfg config.BackupConfig) (Target, error) {
	t := cfg.Target
	switch {
	case t == "":
		return nil, errors.New("RGSTR_BACKUP_TARGET is not set")
	case strings.HasPrefix(t, "s3://"):
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(t, "s3://"), "/")
		if bucket == "" {
			return nil, fmt.Errorf("RGSTR_BACKUP_TARGET %q: no bucket", t)
		}
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		return newS3(cfg.S3, bucket, prefix)
	case strings.HasPrefix(t, "file://"):
		t = strings.TrimPrefix(t, "file://")
	case strings.Contains(t, "://"):
		return nil, fmt.Errorf("RGSTR_BACKUP_TARGET %q: use s3://bucket/prefix or a directory", t)
	}
	if err := os.MkdirAll(t, 0750); err != nil {
		return nil, err
	}
	return dirTarget(t), nil
}

// dirTarget keeps backups in a directory (a mounted NFS share, a second
// disk). Archives appear only when complete.
type dirTarget string

func (d dirTarget) String() string { return string(d) }

func (d dirTarget) path(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("bad backup name %q", name)
	}
	return filepath.Join(string(d), name), nil
}

func (d dirTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	tmp := filepath.Join(string(d), "."+name+".partial")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}

func (d dirTarget) Get(_ context.Context, name string) (io.ReadCloser, error) {
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (d dirTarget) Delete(_ context.Context, name string) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (d dirTarget) list(context.Context) ([]Object, error) {
	entries, err := os.ReadDir(string(d))
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			out = append(out, Object{Name: e.Name(), Size: info.Size()})
		}
	}
	return out, nil
}
