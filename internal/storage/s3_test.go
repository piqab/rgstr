package storage

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"rgstr/internal/config"
	"rgstr/internal/s3"
)

// TestS3Driver runs the store on a real S3-compatible service when
// RGSTR_TEST_S3 is set (see internal/backup/s3_test.go).
func TestS3Driver(t *testing.T) {
	endpoint := os.Getenv("RGSTR_TEST_S3")
	if endpoint == "" {
		t.Skip("RGSTR_TEST_S3 not set")
	}
	c, err := s3.New(config.S3Config{Endpoint: endpoint, Region: "us-east-1", PathStyle: true,
		AccessKey: envOr("RGSTR_TEST_S3_KEY", "minioadmin"), SecretKey: envOr("RGSTR_TEST_S3_SECRET", "minioadmin")},
		envOr("RGSTR_TEST_S3_BUCKET", "rgstr-test"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "storage-test/" + newUUID()
	d := NewS3Driver(c, prefix, true)
	t.Cleanup(func() { d.Delete(bg, "") })
	fs := New(d, &config.Config{UploadTTL: time.Hour})

	// Chunked uploads: small chunks (composed by streaming) and big ones
	// (composed server side).
	for name, sizes := range map[string][]int{"small": {1000, 2000, 3}, "big": {6 << 20, 6 << 20, 100}} {
		var all []byte
		info, err := fs.StartUpload("team/app")
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range sizes[:len(sizes)-1] {
			chunk := make([]byte, n)
			rand.Read(chunk)
			all = append(all, chunk...)
			if _, err := fs.AppendUpload(info.UUID, bytes.NewReader(chunk), int64(len(all)-n)); err != nil {
				t.Fatalf("%s: append: %v", name, err)
			}
		}
		last := make([]byte, sizes[len(sizes)-1])
		rand.Read(last)
		all = append(all, last...)
		dg := digestOf(all)
		blob, err := fs.CompleteUpload(info.UUID, dg, bytes.NewReader(last))
		if err != nil || blob.Size != int64(len(all)) {
			t.Fatalf("%s: complete: %+v %v", name, blob, err)
		}
		f, err := fs.OpenBlob(dg)
		if err != nil {
			t.Fatal(err)
		}
		f.Seek(int64(len(all)-50), io.SeekStart)
		tail, _ := io.ReadAll(f)
		f.Close()
		if !bytes.Equal(tail, all[len(all)-50:]) {
			t.Errorf("%s: ranged read differs", name)
		}
		if !fs.BlobLinked("team/app", dg) {
			t.Errorf("%s: blob not linked", name)
		}
		if _, err := fs.GetUpload(info.UUID); err != ErrUploadNotFound {
			t.Errorf("%s: upload left behind: %v", name, err)
		}
	}

	// A wrong digest fails and leaves no blob.
	info, _ := fs.StartUpload("team/app")
	if _, err := fs.CompleteUpload(info.UUID, digestOf([]byte("other")), bytes.NewReader([]byte("data"))); err == nil {
		t.Error("digest mismatch accepted")
	}

	// Manifests, tags, repositories.
	layer := []byte("layer")
	ld := digestOf(layer)
	fs.PutBlob(ld, bytes.NewReader(layer))
	fs.LinkBlob("team/app", ld)
	mf := &Manifest{ContentType: "application/vnd.oci.image.manifest.v1+json",
		Content: []byte(`{"schemaVersion":2,"layers":[{"digest":"` + string(ld) + `"}]}`)}
	if err := fs.PutManifest("team/app", "1.0", mf); err != nil {
		t.Fatal(err)
	}
	if got, err := fs.GetManifest("team/app", "1.0"); err != nil || got.Digest != mf.Digest {
		t.Fatalf("get manifest: %v", err)
	}
	if tags, _ := fs.ListTags("team/app"); len(tags) != 1 || tags[0] != "1.0" {
		t.Errorf("tags: %v", tags)
	}
	fs.PutManifest("team/app/sub", "x", &Manifest{ContentType: mf.ContentType, Content: []byte(`{"schemaVersion":2}`)})
	if repos, _ := fs.ListRepositories(); len(repos) != 2 || repos[0] != "team/app" || repos[1] != "team/app/sub" {
		t.Errorf("repositories: %v", repos)
	}

	// The presigned URL serves the blob without credentials.
	resp, err := http.Get(fs.BlobRedirectURL(ld))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(body, layer) {
		t.Errorf("presigned URL: %d %q", resp.StatusCode, body)
	}

	// GC keeps what the tag reaches and removes the rest.
	if err := fs.DeleteRepository("team/app/sub"); err != nil {
		t.Fatal(err)
	}
	res, err := fs.CollectGarbage(GCOptions{IgnoreGrace: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.StatBlob(ld); err != nil {
		t.Error("GC removed a referenced blob")
	}
	if res.BlobsRemoved != 2 { // the two uploads above
		t.Errorf("GC removed %d blobs, want 2", res.BlobsRemoved)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
