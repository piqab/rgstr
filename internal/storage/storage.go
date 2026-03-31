// Package storage provides a content-addressable, OCI-compatible blob and
// manifest store backed by the local filesystem.
//
// Layout under <root>:
//
//	blobs/sha256/<2-hex-prefix>/<62-hex-suffix>   — deduplicated blob content
//	uploads/<uuid>/data                            — in-progress upload bytes
//	uploads/<uuid>/info.json                       — upload metadata
//	repositories/<name>/manifests/by-digest/<hex>  — manifest JSON + content-type
//	repositories/<name>/manifests/tags/<tag>        — contains hex digest string
//	repositories/<name>/layers/<hex>               — empty marker for GC ref-tracking
//
// Notes on Windows compatibility: colons are illegal in NTFS file names, so we
// store digests as plain hex strings and reconstruct "sha256:<hex>" in memory.
package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rgstr/internal/config"
)

// ─── Error sentinels ──────────────────────────────────────────────────────────

var (
	ErrBlobNotFound    = errors.New("blob not found")
	ErrManifestNotFound = errors.New("manifest not found")
	ErrUploadNotFound  = errors.New("upload not found")
)

// RangeError is returned when a PATCH chunk has an unexpected start offset.
type RangeError struct {
	Expected int64
	Got      int64
}

func (e *RangeError) Error() string {
	return fmt.Sprintf("range mismatch: expected offset %d, got %d", e.Expected, e.Got)
}

// DigestMismatchError is returned when the computed digest does not match the
// expected digest supplied by the client.
type DigestMismatchError struct {
	Expected Digest
	Actual   Digest
}

func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("digest mismatch: expected %s, got %s", e.Expected, e.Actual)
}

// ─── Digest ───────────────────────────────────────────────────────────────────

// Digest is a string of the form "sha256:<64 hex chars>".
type Digest string

// Algorithm returns the hash algorithm prefix (e.g. "sha256").
func (d Digest) Algorithm() string {
	if i := strings.Index(string(d), ":"); i >= 0 {
		return string(d)[:i]
	}
	return ""
}

// Hex returns the hex-encoded hash value without the algorithm prefix.
func (d Digest) Hex() string {
	if i := strings.Index(string(d), ":"); i >= 0 {
		return string(d)[i+1:]
	}
	return string(d)
}

// Valid reports whether d is a well-formed sha256 digest.
func (d Digest) Valid() bool {
	if d.Algorithm() != "sha256" {
		return false
	}
	h := d.Hex()
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// DigestFromHex creates a Digest from a raw hex string.
func DigestFromHex(h string) Digest { return Digest("sha256:" + h) }

// ─── Value types ──────────────────────────────────────────────────────────────

// BlobInfo holds metadata about a stored blob.
type BlobInfo struct {
	Digest    Digest
	Size      int64
	CreatedAt time.Time
}

// Manifest is a stored OCI/Docker manifest with its content-type.
type Manifest struct {
	ContentType string
	Content     []byte
	Digest      Digest // set by PutManifest; caller need not provide it
}

// UploadInfo records the current state of an in-progress chunked upload.
type UploadInfo struct {
	UUID      string    `json:"uuid"`
	Repo      string    `json:"repo"`
	StartedAt time.Time `json:"started_at"`
	Offset    int64     `json:"offset"`
}

// ─── Filesystem ───────────────────────────────────────────────────────────────

// Filesystem is a thread-safe, content-addressable OCI registry store.
type Filesystem struct {
	root string
	cfg  *config.Config

	// gcMu serialises GC against all read/write operations.
	// All normal operations hold a Read lock; GC holds the Write lock.
	gcMu sync.RWMutex

	// blobMu ensures only one goroutine writes a particular blob at a time,
	// preventing duplicate file creation races.
	blobMu sync.Map // Digest → *sync.Mutex

	// uploadMu serialises concurrent chunk appends within a single session.
	uploadMu sync.Map // uuid → *sync.Mutex
}

// NewFilesystem initialises (or reopens) the store at root.
func NewFilesystem(root string, cfg *config.Config) (*Filesystem, error) {
	dirs := []string{
		filepath.Join(root, "blobs", "sha256"),
		filepath.Join(root, "uploads"),
		filepath.Join(root, "repositories"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return &Filesystem{root: root, cfg: cfg}, nil
}

// ─── Blob operations ──────────────────────────────────────────────────────────

// blobPath returns the absolute path for a stored blob.
func (fs *Filesystem) blobPath(d Digest) string {
	h := d.Hex()
	return filepath.Join(fs.root, "blobs", "sha256", h[:2], h[2:])
}

// StatBlob returns metadata for a blob, or ErrBlobNotFound.
func (fs *Filesystem) StatBlob(d Digest) (*BlobInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	return fs.statBlobLocked(d)
}

func (fs *Filesystem) statBlobLocked(d Digest) (*BlobInfo, error) {
	fi, err := os.Stat(fs.blobPath(d))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBlobNotFound
		}
		return nil, err
	}
	return &BlobInfo{Digest: d, Size: fi.Size(), CreatedAt: fi.ModTime()}, nil
}

// OpenBlob opens a blob for reading. The caller must close the returned file.
func (fs *Filesystem) OpenBlob(d Digest) (*os.File, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	f, err := os.Open(fs.blobPath(d))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBlobNotFound
		}
		return nil, err
	}
	return f, nil
}

// PutBlob writes a blob from r, verifying it matches d.
// If the blob already exists the call is a no-op (deduplication).
func (fs *Filesystem) PutBlob(d Digest, r io.Reader) (*BlobInfo, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("invalid digest: %s", d)
	}

	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	// Acquire per-digest lock so only one goroutine writes this blob.
	raw, _ := fs.blobMu.LoadOrStore(d, &sync.Mutex{})
	mu := raw.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Fast path: blob already present (deduplication).
	if fi, err := os.Stat(fs.blobPath(d)); err == nil {
		return &BlobInfo{Digest: d, Size: fi.Size(), CreatedAt: fi.ModTime()}, nil
	}

	blobDir := filepath.Dir(fs.blobPath(d))
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir blob dir: %w", err)
	}

	// Write to a temp file, verify digest, then rename atomically.
	tmp, err := os.CreateTemp(blobDir, ".tmp-")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	tmp.Close()
	if err != nil {
		return nil, fmt.Errorf("write blob: %w", err)
	}

	actual := DigestFromHex(hex.EncodeToString(h.Sum(nil)))
	if actual != d {
		return nil, &DigestMismatchError{Expected: d, Actual: actual}
	}

	if err := os.Rename(tmpName, fs.blobPath(d)); err != nil {
		return nil, fmt.Errorf("commit blob: %w", err)
	}
	return &BlobInfo{Digest: d, Size: n}, nil
}

// DeleteBlob removes a blob from the store.
func (fs *Filesystem) DeleteBlob(d Digest) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	err := os.Remove(fs.blobPath(d))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// MountBlob attempts a cross-repository blob mount. Returns true when the blob
// exists in the store (regardless of which repo originally pushed it).
func (fs *Filesystem) MountBlob(d Digest) bool {
	_, err := fs.StatBlob(d)
	return err == nil
}

// ─── Upload session operations ────────────────────────────────────────────────

func (fs *Filesystem) uploadDir(uuid string) string {
	return filepath.Join(fs.root, "uploads", uuid)
}

// StartUpload begins a new chunked upload for repo and returns its metadata.
func (fs *Filesystem) StartUpload(repo string) (*UploadInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	uuid := newUUID()
	dir := fs.uploadDir(uuid)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create upload dir: %w", err)
	}

	// Create empty data file.
	f, err := os.Create(filepath.Join(dir, "data"))
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("create data file: %w", err)
	}
	f.Close()

	info := &UploadInfo{
		UUID:      uuid,
		Repo:      repo,
		StartedAt: time.Now(),
		Offset:    0,
	}
	if err := fs.saveUploadInfo(info); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	fs.uploadMu.Store(uuid, &sync.Mutex{})
	return info, nil
}

// GetUpload returns the current state of an upload session.
func (fs *Filesystem) GetUpload(uuid string) (*UploadInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	return fs.loadUploadInfo(uuid)
}

// AppendUpload appends a chunk to an upload session.
//
// startOffset must equal the current upload offset; pass -1 to skip the check
// and always append sequentially (for PUT completion with no Content-Range).
// Returns the new total offset after writing.
func (fs *Filesystem) AppendUpload(uuid string, r io.Reader, startOffset int64) (int64, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	raw, _ := fs.uploadMu.LoadOrStore(uuid, &sync.Mutex{})
	mu := raw.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	info, err := fs.loadUploadInfo(uuid)
	if err != nil {
		return 0, err
	}

	if startOffset >= 0 && startOffset != info.Offset {
		return info.Offset, &RangeError{Expected: info.Offset, Got: startOffset}
	}

	dataPath := filepath.Join(fs.uploadDir(uuid), "data")
	f, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return info.Offset, fmt.Errorf("open data: %w", err)
	}
	defer f.Close()

	n, err := io.Copy(f, r)
	if err != nil {
		return info.Offset, fmt.Errorf("write chunk: %w", err)
	}
	f.Close() // close before saving info

	info.Offset += n
	if err := fs.saveUploadInfo(info); err != nil {
		return info.Offset, err
	}
	return info.Offset, nil
}

// CompleteUpload finalises a chunked upload.
//
// If finalChunk is non-nil it is appended before the digest is verified
// (this handles the case where the client sends data in the PUT request).
// The upload session is removed on success.
func (fs *Filesystem) CompleteUpload(uuid string, expected Digest, finalChunk io.Reader) (*BlobInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	raw, _ := fs.uploadMu.LoadOrStore(uuid, &sync.Mutex{})
	mu := raw.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Verify the upload session exists; we only need its presence, not its fields.
	if _, err := fs.loadUploadInfo(uuid); err != nil {
		return nil, err
	}

	dataPath := filepath.Join(fs.uploadDir(uuid), "data")

	// Append the optional final chunk.
	if finalChunk != nil {
		f, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("open data for final chunk: %w", err)
		}
		_, err = io.Copy(f, finalChunk)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("write final chunk: %w", err)
		}
	}

	// Compute the digest of the full upload.
	f, err := os.Open(dataPath)
	if err != nil {
		return nil, fmt.Errorf("open data for digest: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("compute digest: %w", err)
	}
	actual := DigestFromHex(hex.EncodeToString(h.Sum(nil)))
	if expected != "" && actual != expected {
		return nil, &DigestMismatchError{Expected: expected, Actual: actual}
	}

	// Move the data file into the blob store (atomic, dedup-safe).
	blobPath := fs.blobPath(actual)
	blobDir := filepath.Dir(blobPath)
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir blob dir: %w", err)
	}

	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		// Blob doesn't exist yet — move it in.
		if err := os.Rename(dataPath, blobPath); err != nil {
			return nil, fmt.Errorf("commit blob: %w", err)
		}
	}
	// If the blob already exists, the rename is skipped (deduplication wins).

	// Clean up the upload session.
	os.RemoveAll(fs.uploadDir(uuid))
	fs.uploadMu.Delete(uuid)

	return &BlobInfo{Digest: actual, Size: n}, nil
}

// CancelUpload deletes an in-progress upload session.
func (fs *Filesystem) CancelUpload(uuid string) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	os.RemoveAll(fs.uploadDir(uuid))
	fs.uploadMu.Delete(uuid)
	return nil
}

// ─── Manifest operations ──────────────────────────────────────────────────────

// repoBase returns the filesystem root for a repository.
// Repo names with slashes (e.g. "library/ubuntu") are stored as nested dirs.
func (fs *Filesystem) repoBase(repo string) string {
	return filepath.Join(fs.root, "repositories", filepath.FromSlash(repo))
}

func (fs *Filesystem) manifestDigestPath(repo, hexHash string) string {
	return filepath.Join(fs.repoBase(repo), "manifests", "by-digest", hexHash)
}

func (fs *Filesystem) manifestTagPath(repo, tag string) string {
	return filepath.Join(fs.repoBase(repo), "manifests", "tags", tag)
}

type manifestFile struct {
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
}

// GetManifest retrieves a manifest by tag or digest.
func (fs *Filesystem) GetManifest(repo, reference string) (*Manifest, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	hexHash, err := fs.resolveReference(repo, reference)
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(fs.manifestDigestPath(repo, hexHash))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound
		}
		return nil, err
	}

	var mf manifestFile
	if err := json.Unmarshal(b, &mf); err != nil {
		return nil, fmt.Errorf("corrupt manifest file: %w", err)
	}
	return &Manifest{
		ContentType: mf.ContentType,
		Content:     mf.Content,
		Digest:      DigestFromHex(hexHash),
	}, nil
}

// PutManifest stores a manifest under the given tag or digest reference.
// It populates m.Digest with the computed sha256 of the content.
func (fs *Filesystem) PutManifest(repo, reference string, m *Manifest) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	// Compute canonical digest.
	h := sha256.New()
	h.Write(m.Content)
	hexHash := hex.EncodeToString(h.Sum(nil))
	m.Digest = DigestFromHex(hexHash)

	// Write manifest file (atomic).
	mfDir := filepath.Dir(fs.manifestDigestPath(repo, hexHash))
	if err := os.MkdirAll(mfDir, 0755); err != nil {
		return fmt.Errorf("mkdir manifest dir: %w", err)
	}

	mf := manifestFile{ContentType: m.ContentType, Content: m.Content}
	raw, err := json.Marshal(mf)
	if err != nil {
		return err
	}
	if err := atomicWrite(fs.manifestDigestPath(repo, hexHash), raw); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	// Update tag reference if the reference is a tag (not a digest).
	if d := Digest(reference); !d.Valid() {
		tagDir := filepath.Dir(fs.manifestTagPath(repo, reference))
		if err := os.MkdirAll(tagDir, 0755); err != nil {
			return fmt.Errorf("mkdir tag dir: %w", err)
		}
		if err := atomicWrite(fs.manifestTagPath(repo, reference), []byte(hexHash)); err != nil {
			return fmt.Errorf("write tag: %w", err)
		}
	}

	// Record blob references so GC can find them.
	return fs.recordBlobRefs(repo, m.Content)
}

// DeleteManifest removes a manifest reference.
// Deleting by digest removes the manifest file.
// Deleting by tag removes only the tag pointer (the manifest by-digest file
// remains until GC determines it has no more tag pointers).
func (fs *Filesystem) DeleteManifest(repo, reference string) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	if d := Digest(reference); d.Valid() {
		err := os.Remove(fs.manifestDigestPath(repo, d.Hex()))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	// It's a tag.
	err := os.Remove(fs.manifestTagPath(repo, reference))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListTags returns all tags for a repository in lexicographic order.
func (fs *Filesystem) ListTags(repo string) ([]string, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	tagsDir := filepath.Join(fs.repoBase(repo), "manifests", "tags")
	entries, err := os.ReadDir(tagsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var tags []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			tags = append(tags, e.Name())
		}
	}
	return tags, nil
}

// ListRepositories returns all known repository names.
func (fs *Filesystem) ListRepositories() ([]string, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	reposDir := filepath.Join(fs.root, "repositories")
	var repos []string

	err := filepath.WalkDir(reposDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		// A directory with a "manifests" sub-directory is a repository root.
		if _, e := os.Stat(filepath.Join(path, "manifests")); e == nil {
			rel, _ := filepath.Rel(reposDir, path)
			repos = append(repos, filepath.ToSlash(rel))
		}
		return nil
	})
	return repos, err
}

// ─── GC reference tracking ────────────────────────────────────────────────────

func (fs *Filesystem) layerRefPath(repo, hexHash string) string {
	return filepath.Join(fs.repoBase(repo), "layers", hexHash)
}

// recordBlobRefs parses manifest content and creates empty marker files for
// each referenced blob so the GC knows they are reachable.
func (fs *Filesystem) recordBlobRefs(repo string, content []byte) error {
	layerDir := filepath.Join(fs.repoBase(repo), "layers")
	if err := os.MkdirAll(layerDir, 0755); err != nil {
		return err
	}
	for _, d := range extractDigests(content) {
		if d.Algorithm() != "sha256" {
			continue
		}
		path := fs.layerRefPath(repo, d.Hex())
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644); err == nil {
			f.Close()
		}
	}
	return nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func (fs *Filesystem) resolveReference(repo, reference string) (hexHash string, err error) {
	if d := Digest(reference); d.Valid() {
		return d.Hex(), nil
	}
	// It's a tag.
	b, err := os.ReadFile(fs.manifestTagPath(repo, reference))
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrManifestNotFound
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (fs *Filesystem) saveUploadInfo(info *UploadInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(fs.uploadDir(info.UUID), "info.json"), b)
}

func (fs *Filesystem) loadUploadInfo(uuid string) (*UploadInfo, error) {
	b, err := os.ReadFile(filepath.Join(fs.uploadDir(uuid), "info.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUploadNotFound
		}
		return nil, err
	}
	var info UploadInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("corrupt upload info: %w", err)
	}
	return &info, nil
}

// atomicWrite writes data to path via a temp file + rename to avoid partial
// reads by concurrent readers.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// newUUID generates a random UUID v4 in the canonical 8-4-4-4-12 format.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	h := hex.EncodeToString(b)   // 32 lowercase hex chars
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ─── Manifest digest extraction for GC ───────────────────────────────────────

// extractDigests does a generic JSON walk and collects every value of every
// field named "digest". This works for OCI manifests, Docker manifests, and
// manifest lists without needing to import the spec packages.
func extractDigests(content []byte) []Digest {
	var root interface{}
	if err := json.Unmarshal(content, &root); err != nil {
		return nil
	}
	var result []Digest
	walkDigests(root, &result)
	return result
}

func walkDigests(v interface{}, out *[]Digest) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			if k == "digest" {
				if s, ok := child.(string); ok {
					d := Digest(s)
					if d.Valid() {
						*out = append(*out, d)
					}
				}
			} else {
				walkDigests(child, out)
			}
		}
	case []interface{}:
		for _, item := range val {
			walkDigests(item, out)
		}
	}
}
