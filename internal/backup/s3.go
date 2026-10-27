package backup

import (
	"context"
	"io"
	"strings"

	"rgstr/internal/config"
	"rgstr/internal/s3"
)

// s3Target stores backups in an S3-compatible object store. Archives are
// sent as multipart uploads, a part at a time, so neither memory nor disk
// needs to hold a whole backup.
type s3Target struct {
	c      *s3.Client
	prefix string
}

const minPartSize = 16 << 20

func newS3(cfg config.S3Config, bucket, prefix string) (*s3Target, error) {
	c, err := s3.New(cfg, bucket)
	if err != nil {
		return nil, err
	}
	return &s3Target{c: c, prefix: prefix}, nil
}

func (s *s3Target) String() string { return s.c.String() + "/" + s.prefix }

func (s *s3Target) Put(ctx context.Context, name string, r io.Reader, sizeHint int64) error {
	return s.c.Upload(ctx, s.prefix+name, r, max(minPartSize, s3.PartSizeFor(sizeHint)))
}

func (s *s3Target) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return s.c.Get(ctx, s.prefix+name, 0)
}

func (s *s3Target) Delete(ctx context.Context, name string) error {
	return s.c.Delete(ctx, s.prefix+name)
}

func (s *s3Target) list(ctx context.Context) ([]Object, error) {
	var out []Object
	err := s.c.List(ctx, s.prefix, "/", func(o s3.Object) error {
		out = append(out, Object{Name: strings.TrimPrefix(o.Key, s.prefix), Size: o.Size})
		return nil
	}, nil)
	return out, err
}
