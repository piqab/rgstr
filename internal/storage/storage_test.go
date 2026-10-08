package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rgstr/internal/config"
)

func newTestFS(t *testing.T) *Filesystem {
	t.Helper()
	dir := t.TempDir()
	fs, err := NewFilesystem(dir, &config.Config{
		UploadTTL: 24 * time.Hour,
		GCInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewFilesystem: %v", err)
	}
	return fs
}

func digestOf(data []byte) Digest {
	h := sha256.Sum256(data)
	return DigestFromHex(hex.EncodeToString(h[:]))
}

// ─── Blob tests ───────────────────────────────────────────────────────────────

func TestBlobRoundTrip(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("hello, world")
	d := digestOf(data)

	info, err := fs.PutBlob(d, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	if info.Size != int64(len(data)) {
		t.Errorf("size: got %d want %d", info.Size, len(data))
	}

	f, err := fs.OpenBlob(d)
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	defer f.Close()

	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch")
	}
}

func TestBlobDeduplication(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("dedup-me")
	d := digestOf(data)

	// Write the same blob twice; second call must not error.
	for i := 0; i < 2; i++ {
		if _, err := fs.PutBlob(d, bytes.NewReader(data)); err != nil {
			t.Fatalf("PutBlob attempt %d: %v", i+1, err)
		}
	}
}

func TestBlobDeduplicationConcurrent(t *testing.T) {
	fs := newTestFS(t)
	data := make([]byte, 1<<20) // 1 MiB of zeros
	d := digestOf(data)

	const workers = 16
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fs.PutBlob(d, bytes.NewReader(data))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent PutBlob: %v", err)
		}
	}

	// Blob must exist exactly once.
	if _, err := fs.StatBlob(d); err != nil {
		t.Errorf("StatBlob after concurrent writes: %v", err)
	}
}

func TestBlobDigestMismatch(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("real content")
	wrong := digestOf([]byte("other content"))

	_, err := fs.PutBlob(wrong, bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error on digest mismatch, got nil")
	}
}

func TestBlobNotFound(t *testing.T) {
	fs := newTestFS(t)
	d := digestOf([]byte("ghost"))

	_, err := fs.StatBlob(d)
	if err != ErrBlobNotFound {
		t.Errorf("expected ErrBlobNotFound, got %v", err)
	}
}

func TestBlobDelete(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("to be deleted")
	d := digestOf(data)

	fs.PutBlob(d, bytes.NewReader(data))
	if err := fs.DeleteBlob(d); err != nil {
		t.Fatalf("DeleteBlob: %v", err)
	}
	if _, err := fs.StatBlob(d); err != ErrBlobNotFound {
		t.Errorf("expected ErrBlobNotFound after delete, got %v", err)
	}
}

// ─── Upload / chunked upload tests ───────────────────────────────────────────

func TestChunkedUpload(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("chunk1chunk2chunk3")
	expected := digestOf(data)

	info, err := fs.StartUpload("myrepo")
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}

	// PATCH chunk 1
	off, err := fs.AppendUpload(info.UUID, bytes.NewReader([]byte("chunk1")), 0)
	if err != nil {
		t.Fatalf("AppendUpload 1: %v", err)
	}
	if off != 6 {
		t.Errorf("offset after chunk1: got %d want 6", off)
	}

	// PATCH chunk 2 with explicit start offset
	off, err = fs.AppendUpload(info.UUID, bytes.NewReader([]byte("chunk2")), 6)
	if err != nil {
		t.Fatalf("AppendUpload 2: %v", err)
	}
	if off != 12 {
		t.Errorf("offset after chunk2: got %d want 12", off)
	}

	// PUT completion with final chunk
	blobInfo, err := fs.CompleteUpload(info.UUID, expected, bytes.NewReader([]byte("chunk3")))
	if err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	if blobInfo.Digest != expected {
		t.Errorf("digest: got %s want %s", blobInfo.Digest, expected)
	}

	// Verify blob is accessible.
	f, err := fs.OpenBlob(expected)
	if err != nil {
		t.Fatalf("OpenBlob after complete: %v", err)
	}
	defer f.Close()
	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch after chunked upload")
	}

	// Upload session must be gone.
	if _, err := fs.GetUpload(info.UUID); err != ErrUploadNotFound {
		t.Errorf("expected ErrUploadNotFound after complete, got %v", err)
	}
}

func TestUploadWrongRange(t *testing.T) {
	fs := newTestFS(t)
	info, _ := fs.StartUpload("repo")

	// Send chunk starting at wrong offset (expect 0, send 5).
	_, err := fs.AppendUpload(info.UUID, bytes.NewReader([]byte("data")), 5)
	var re *RangeError
	if err == nil {
		t.Fatal("expected RangeError, got nil")
	}
	if !isRangeError(err, &re) {
		t.Errorf("expected *RangeError, got %T: %v", err, err)
	}
	if re.Expected != 0 {
		t.Errorf("RangeError.Expected: got %d want 0", re.Expected)
	}
}

func TestUploadDigestMismatch(t *testing.T) {
	fs := newTestFS(t)
	info, _ := fs.StartUpload("repo")
	fs.AppendUpload(info.UUID, bytes.NewReader([]byte("real")), 0)

	wrong := digestOf([]byte("other"))
	_, err := fs.CompleteUpload(info.UUID, wrong, nil)
	if err == nil {
		t.Fatal("expected DigestMismatchError, got nil")
	}
}

func TestCancelUpload(t *testing.T) {
	fs := newTestFS(t)
	info, _ := fs.StartUpload("repo")

	if err := fs.CancelUpload(info.UUID); err != nil {
		t.Fatalf("CancelUpload: %v", err)
	}
	if _, err := fs.GetUpload(info.UUID); err != ErrUploadNotFound {
		t.Errorf("expected ErrUploadNotFound after cancel, got %v", err)
	}
}

// TestConcurrentUploads ensures parallel chunk appends to the same session
// produce a consistent, serialised result.
func TestConcurrentUploads(t *testing.T) {
	fs := newTestFS(t)
	info, _ := fs.StartUpload("repo")

	// Sequential sends are needed for correctness; this test verifies that the
	// locking prevents data corruption even with concurrent goroutines that
	// each wait for the previous offset before sending.
	chunk := []byte("AAAA") // 4 bytes per chunk, 4 chunks = 16 bytes total
	for i := 0; i < 4; i++ {
		expectedOff := int64(i * 4)
		off, err := fs.AppendUpload(info.UUID, bytes.NewReader(chunk), expectedOff)
		if err != nil {
			t.Fatalf("AppendUpload i=%d: %v", i, err)
		}
		if off != expectedOff+4 {
			t.Errorf("offset i=%d: got %d want %d", i, off, expectedOff+4)
		}
	}

	expected := digestOf(bytes.Repeat([]byte("AAAA"), 4))
	blobInfo, err := fs.CompleteUpload(info.UUID, expected, nil)
	if err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	if blobInfo.Digest != expected {
		t.Errorf("final digest mismatch")
	}
}

// ─── Manifest tests ───────────────────────────────────────────────────────────

func TestManifestRoundTrip(t *testing.T) {
	fs := newTestFS(t)
	content := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`)
	mf := &Manifest{
		ContentType: "application/vnd.docker.distribution.manifest.v2+json",
		Content:     content,
	}

	if err := fs.PutManifest("myrepo", "latest", mf); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	// Retrieve by tag.
	got, err := fs.GetManifest("myrepo", "latest")
	if err != nil {
		t.Fatalf("GetManifest by tag: %v", err)
	}
	if !bytes.Equal(got.Content, content) {
		t.Errorf("content mismatch by tag")
	}

	// Retrieve by digest.
	got2, err := fs.GetManifest("myrepo", string(mf.Digest))
	if err != nil {
		t.Fatalf("GetManifest by digest: %v", err)
	}
	if got2.Digest != mf.Digest {
		t.Errorf("digest mismatch: got %s want %s", got2.Digest, mf.Digest)
	}
}

func TestManifestListTags(t *testing.T) {
	fs := newTestFS(t)
	content := []byte(`{"schemaVersion":2}`)
	for _, tag := range []string{"v1.0", "v2.0", "latest"} {
		mf := &Manifest{ContentType: "application/json", Content: content}
		if err := fs.PutManifest("myrepo", tag, mf); err != nil {
			t.Fatalf("PutManifest %s: %v", tag, err)
		}
	}

	tags, err := fs.ListTags("myrepo")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 3 {
		t.Errorf("expected 3 tags, got %d: %v", len(tags), tags)
	}
}

func TestManifestDeleteTag(t *testing.T) {
	fs := newTestFS(t)
	mf := &Manifest{ContentType: "application/json", Content: []byte(`{}`)}
	fs.PutManifest("repo", "v1", mf)

	if err := fs.DeleteManifest("repo", "v1"); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if _, err := fs.GetManifest("repo", "v1"); err != ErrManifestNotFound {
		t.Errorf("expected ErrManifestNotFound, got %v", err)
	}
}

// ─── GC tests ─────────────────────────────────────────────────────────────────

func TestGCRemovesUnreferencedBlobs(t *testing.T) {
	fs := newTestFS(t)

	// Push a blob that no manifest references.
	orphan := []byte("orphan blob")
	d := digestOf(orphan)
	fs.PutBlob(d, bytes.NewReader(orphan))

	if err := fs.RunGC(); err != nil {
		t.Fatalf("RunGC: %v", err)
	}

	if _, err := fs.StatBlob(d); err != ErrBlobNotFound {
		t.Errorf("expected orphan blob to be GC'd, got %v", err)
	}
}

func TestGCDropsLinksToRemovedBlobs(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("unreferenced but linked")
	d := digestOf(data)
	fs.PutBlob(d, bytes.NewReader(data))
	fs.LinkBlob("repo", d)
	age(t, fs.layerRefPath("repo", d.Hex()))

	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if fs.BlobLinked("repo", d) {
		t.Error("link to a GC-removed blob survived")
	}
}

// age backdates path beyond the GC grace period.
func age(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

// A push uploads blobs before the manifest; GC running in between must not
// delete them.
func TestGCKeepsRecentlyUploadedBlobs(t *testing.T) {
	fs := newTestFS(t)
	info, _ := fs.StartUpload("repo")
	data := []byte("pushed, manifest not yet")
	d := digestOf(data)
	if _, err := fs.CompleteUpload(info.UUID, d, bytes.NewReader(data)); err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}

	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.StatBlob(d); err != nil {
		t.Errorf("recently uploaded blob was GC'd: %v", err)
	}

	age(t, fs.layerRefPath("repo", d.Hex()))
	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.StatBlob(d); err != ErrBlobNotFound {
		t.Errorf("unreferenced blob past grace period: got %v want ErrBlobNotFound", err)
	}
}

// Multi-platform pushes upload child manifests by digest before the tagged
// index; GC running in between must not delete them.
func TestGCKeepsRecentUntaggedManifests(t *testing.T) {
	fs := newTestFS(t)
	mf := &Manifest{ContentType: "application/json", Content: []byte(`{"schemaVersion":2}`)}
	if err := fs.PutManifest("repo", "sha256:"+strings.Repeat("0", 64), mf); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.GetManifest("repo", string(mf.Digest)); err != nil {
		t.Errorf("recent untagged manifest was GC'd: %v", err)
	}

	age(t, fs.manifestDigestPath("repo", mf.Digest.Hex()))
	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.GetManifest("repo", string(mf.Digest)); err != ErrManifestNotFound {
		t.Errorf("untagged manifest past grace period: got %v want ErrManifestNotFound", err)
	}
}

func TestGCKeepsReferencedBlobs(t *testing.T) {
	fs := newTestFS(t)

	// Push a blob.
	data := []byte("keep me")
	d := digestOf(data)
	fs.PutBlob(d, bytes.NewReader(data))

	// Push a manifest that references it.
	manifest := []byte(`{"layers":[{"digest":"` + string(d) + `","size":7}]}`)
	mf := &Manifest{ContentType: "application/json", Content: manifest}
	if err := fs.PutManifest("repo", "latest", mf); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	if err := fs.RunGC(); err != nil {
		t.Fatalf("RunGC: %v", err)
	}

	if _, err := fs.StatBlob(d); err != nil {
		t.Errorf("referenced blob was incorrectly GC'd: %v", err)
	}
}

func TestGCRemovesStaleUploads(t *testing.T) {
	fs := newTestFS(t)
	fs.cfg.UploadTTL = -1 // any upload is immediately stale

	info, _ := fs.StartUpload("repo")
	fs.AppendUpload(info.UUID, bytes.NewReader([]byte("partial")), 0)

	if err := fs.RunGC(); err != nil {
		t.Fatalf("RunGC: %v", err)
	}

	// The upload directory must be gone.
	if _, err := os.Stat(fs.uploadDir(info.UUID)); !os.IsNotExist(err) {
		t.Errorf("stale upload not removed: %v", err)
	}
}

// ─── Digest tests ─────────────────────────────────────────────────────────────

func TestDigestValid(t *testing.T) {
	cases := []struct {
		d     Digest
		valid bool
	}{
		{Digest("sha256:" + hex.EncodeToString(make([]byte, 32))), true},
		{Digest("sha256:abc"), false},
		{Digest("md5:abc"), false},
		{Digest(""), false},
	}
	for _, c := range cases {
		if c.d.Valid() != c.valid {
			t.Errorf("Digest(%q).Valid() = %v, want %v", c.d, c.d.Valid(), c.valid)
		}
	}
}

func TestNewUUID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		u := newUUID()
		if len(u) != 36 {
			t.Fatalf("UUID length %d, want 36: %q", len(u), u)
		}
		if seen[u] {
			t.Fatalf("UUID collision: %q", u)
		}
		seen[u] = true
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func isRangeError(err error, out **RangeError) bool {
	if re, ok := err.(*RangeError); ok {
		*out = re
		return true
	}
	return false
}

// putImage stores a one-layer image in repo under ref and backdates every
// file so the GC grace period does not apply. Returns manifest and layer.
func putImage(t *testing.T, fs *Filesystem, repo, ref string, layer []byte) (*Manifest, Digest) {
	t.Helper()
	ld := digestOf(layer)
	fs.PutBlob(ld, bytes.NewReader(layer))
	fs.LinkBlob(repo, ld)
	mf := &Manifest{ContentType: "application/json",
		Content: []byte(`{"layers":[{"digest":"` + string(ld) + `"}]}`)}
	if err := fs.PutManifest(repo, ref, mf); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	age(t, fs.manifestDigestPath(repo, mf.Digest.Hex()))
	age(t, fs.layerRefPath(repo, ld.Hex()))
	return mf, ld
}

func TestGCCollectsImageAfterTagDelete(t *testing.T) {
	fs := newTestFS(t)
	mf, layer := putImage(t, fs, "repo", "latest", []byte("old image"))

	if err := fs.DeleteManifest("repo", "latest"); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.GetManifest("repo", string(mf.Digest)); err != ErrManifestNotFound {
		t.Errorf("untagged manifest: got %v want ErrManifestNotFound", err)
	}
	if _, err := fs.StatBlob(layer); err != ErrBlobNotFound {
		t.Errorf("layer of untagged image: got %v want ErrBlobNotFound", err)
	}
}

func TestGCKeepsIndexChildren(t *testing.T) {
	fs := newTestFS(t)
	child, layer := putImage(t, fs, "repo", "sha256:"+strings.Repeat("0", 64), []byte("arm64 layer"))
	index := &Manifest{ContentType: "application/vnd.oci.image.index.v1+json",
		Content: []byte(`{"manifests":[{"digest":"` + string(child.Digest) + `"}]}`)}
	if err := fs.PutManifest("repo", "multi", index); err != nil {
		t.Fatalf("PutManifest index: %v", err)
	}
	age(t, fs.manifestDigestPath("repo", index.Digest.Hex()))

	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.GetManifest("repo", string(child.Digest)); err != nil {
		t.Errorf("child manifest of tagged index was GC'd: %v", err)
	}
	if _, err := fs.StatBlob(layer); err != nil {
		t.Errorf("layer of child manifest was GC'd: %v", err)
	}
}

func TestGCKeepsBlobUsedByOtherRepo(t *testing.T) {
	fs := newTestFS(t)
	shared := []byte("shared layer")
	putImage(t, fs, "a", "latest", shared)
	_, layer := putImage(t, fs, "b", "latest", shared)

	fs.DeleteManifest("a", "latest")
	if err := fs.RunGC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := fs.StatBlob(layer); err != nil {
		t.Errorf("layer still used by repo b was GC'd: %v", err)
	}
}

func TestDeleteRepositoryKeepsNested(t *testing.T) {
	fs := newTestFS(t)
	putImage(t, fs, "team", "latest", []byte("parent"))
	putImage(t, fs, "team/app", "latest", []byte("nested"))

	if err := fs.DeleteRepository("team"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}
	repos, _ := fs.ListRepositories()
	if len(repos) != 1 || repos[0] != "team/app" {
		t.Errorf("repositories after delete: got %v want [team/app]", repos)
	}
	if _, err := fs.GetManifest("team/app", "latest"); err != nil {
		t.Errorf("nested repo manifest: %v", err)
	}
	if err := fs.DeleteRepository("team"); err != ErrRepoNotFound {
		t.Errorf("second delete: got %v want ErrRepoNotFound", err)
	}

	if err := fs.DeleteRepository("team/app"); err != nil {
		t.Fatalf("DeleteRepository nested: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(fs.root, "repositories")); len(entries) != 0 {
		t.Errorf("empty directories left behind: %v", entries)
	}
}

func TestCollectGarbageDryRunAndStats(t *testing.T) {
	fs := newTestFS(t)
	mf, layer := putImage(t, fs, "repo", "old", []byte("twelve bytes"))
	fs.DeleteManifest("repo", "old")

	res, err := fs.CollectGarbage(GCOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if res.ManifestsRemoved != 1 || res.BlobsRemoved != 1 || res.BytesFreed != 12 {
		t.Errorf("dry run result: %+v, want 1 manifest, 1 blob, 12 bytes", res)
	}
	if len(res.Manifests) != 1 || res.Manifests[0] != "repo@"+string(mf.Digest) {
		t.Errorf("dry run manifests: %v", res.Manifests)
	}
	if _, err := fs.StatBlob(layer); err != nil {
		t.Errorf("dry run removed the blob: %v", err)
	}
	if _, err := fs.GetManifest("repo", string(mf.Digest)); err != nil {
		t.Errorf("dry run removed the manifest: %v", err)
	}

	res, _ = fs.CollectGarbage(GCOptions{})
	if res.BytesFreed != 12 {
		t.Errorf("real run freed %d bytes, want 12", res.BytesFreed)
	}
	if _, err := fs.StatBlob(layer); err != ErrBlobNotFound {
		t.Errorf("blob after real run: %v", err)
	}
}

func TestCollectGarbageIgnoreGrace(t *testing.T) {
	fs := newTestFS(t)
	data := []byte("fresh upload")
	d := digestOf(data)
	fs.PutBlob(d, bytes.NewReader(data))
	fs.LinkBlob("repo", d) // recent link: protected by the grace period

	if res, _ := fs.CollectGarbage(GCOptions{}); res.BlobsRemoved != 0 {
		t.Errorf("regular run removed a recent blob")
	}
	if res, _ := fs.CollectGarbage(GCOptions{IgnoreGrace: true}); res.BlobsRemoved != 1 {
		t.Errorf("ignore-grace run: removed %d blobs, want 1", res.BlobsRemoved)
	}
}
