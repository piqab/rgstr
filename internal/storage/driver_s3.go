package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"rgstr/internal/s3"
)

// S3Driver keeps files as objects in a bucket under a prefix. S3 is
// strongly consistent (read-after-write, list-after-write), so any number
// of rgstr processes can share it. Objects have no rename and no append:
// uploads are kept as one object per chunk and composed server side.
type S3Driver struct {
	c        *s3.Client
	prefix   string // "" or "dir/"
	redirect bool
}

// NewS3Driver stores files in c under prefix. With redirect, blob
// downloads are sent to presigned S3 URLs instead of through rgstr.
func NewS3Driver(c *s3.Client, prefix string, redirect bool) *S3Driver {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &S3Driver{c: c, prefix: prefix, redirect: redirect}
}

func (d *S3Driver) Name() string { return "s3" }

func (d *S3Driver) String() string { return d.c.String() + "/" + d.prefix }

func (d *S3Driver) key(p string) string { return d.prefix + strings.TrimPrefix(p, "/") }

// mapErr turns ErrNotFound into fs.ErrNotExist, as the filesystem reports.
func mapErr(err error) error {
	if errors.Is(err, s3.ErrNotFound) {
		return fmt.Errorf("%w: %v", fs.ErrNotExist, err)
	}
	return err
}

func (d *S3Driver) Stat(ctx context.Context, p string) (FileInfo, error) {
	o, err := d.c.Head(ctx, d.key(p))
	if err != nil {
		return FileInfo{}, mapErr(err)
	}
	return FileInfo{Size: o.Size, ModTime: o.ModTime}, nil
}

func (d *S3Driver) GetContent(ctx context.Context, p string) ([]byte, error) {
	rc, err := d.c.Get(ctx, d.key(p), 0)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (d *S3Driver) PutContent(ctx context.Context, p string, data []byte) error {
	return d.c.Put(ctx, d.key(p), data)
}

func (d *S3Driver) Reader(ctx context.Context, p string, offset int64) (io.ReadCloser, error) {
	rc, err := d.c.Get(ctx, d.key(p), offset)
	return rc, mapErr(err)
}

// s3Writer streams into a multipart upload through a pipe; the object
// exists only once Commit completes the upload.
type s3Writer struct {
	pw   *io.PipeWriter
	done chan error
}

func (d *S3Driver) Writer(ctx context.Context, p string) (FileWriter, error) {
	pr, pw := io.Pipe()
	w := &s3Writer{pw: pw, done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		err := d.c.Upload(ctx, d.key(p), pr, 8<<20)
		pr.CloseWithError(err) // unblock a writer if the upload failed
		w.done <- err
	}()
	return w, nil
}

func (w *s3Writer) Write(p []byte) (int, error) { return w.pw.Write(p) }

func (w *s3Writer) Commit() error {
	w.pw.Close()
	return <-w.done
}

func (w *s3Writer) Cancel() {
	// The upload sees an error instead of EOF and aborts.
	w.pw.CloseWithError(errors.New("cancelled"))
	<-w.done
}

func (d *S3Driver) List(ctx context.Context, dir string) ([]Entry, error) {
	prefix := d.key(dir)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var out []Entry
	err := d.c.List(ctx, prefix, "/", func(o s3.Object) error {
		name := strings.TrimPrefix(o.Key, prefix)
		if name != "" {
			out = append(out, Entry{Name: name, FileInfo: FileInfo{Size: o.Size, ModTime: o.ModTime}})
		}
		return nil
	}, func(sub string) error {
		out = append(out, Entry{Name: strings.TrimSuffix(strings.TrimPrefix(sub, prefix), "/"), IsDir: true})
		return nil
	})
	sortEntries(out)
	return out, err
}

func (d *S3Driver) Walk(ctx context.Context, dir string, fn func(p string, info FileInfo) error) error {
	prefix := d.key(dir)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return d.c.List(ctx, prefix, "", func(o s3.Object) error {
		return fn(strings.TrimPrefix(o.Key, d.prefix), FileInfo{Size: o.Size, ModTime: o.ModTime})
	}, nil)
}

func (d *S3Driver) Delete(ctx context.Context, p string) error {
	key := d.key(p)
	if err := d.c.Delete(ctx, key); err != nil {
		return err
	}
	// A "directory": everything under key/.
	var keys []string
	if err := d.c.List(ctx, key+"/", "", func(o s3.Object) error {
		keys = append(keys, o.Key)
		return nil
	}, nil); err != nil {
		return err
	}
	for _, k := range keys {
		if err := d.c.Delete(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

func (d *S3Driver) Concat(ctx context.Context, dst string, srcs []string) error {
	objs := make([]s3.Object, 0, len(srcs))
	for _, s := range srcs {
		o, err := d.c.Head(ctx, d.key(s))
		if err != nil {
			return mapErr(err)
		}
		objs = append(objs, o)
	}
	if len(objs) == 1 {
		return d.c.Copy(ctx, objs[0].Key, d.key(dst))
	}
	return d.c.Compose(ctx, d.key(dst), objs)
}

func (d *S3Driver) RedirectURL(p string, ttl time.Duration) string {
	if !d.redirect {
		return ""
	}
	return d.c.Presign(d.key(p), ttl)
}
