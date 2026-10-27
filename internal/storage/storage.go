// Package storage provides a content-addressable, OCI-compatible blob and
// manifest store on a Driver: the local filesystem, or S3 for several
// rgstr processes.
//
// Layout (driver paths):
//
//	blobs/sha256/<2-hex-prefix>/<62-hex-suffix>   — deduplicated blob content
//	uploads/<uuid>/chunk-<offset>                  — in-progress upload bytes
//	uploads/<uuid>/info.json                       — upload metadata
//	repositories/<name>/manifests/by-digest/<hex>  — manifest JSON + content-type
//	repositories/<name>/manifests/tags/<tag>        — contains hex digest string
//	repositories/<name>/layers/<hex>               — empty marker: blob belongs to this repo
//
// Notes on Windows compatibility: colons are illegal in NTFS file names, so we
// store digests as plain hex strings and reconstruct "sha256:<hex>" in memory.
package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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
	ErrBlobNotFound     = errors.New("blob not found")
	ErrManifestNotFound = errors.New("manifest not found")
	ErrUploadNotFound   = errors.New("upload not found")
	ErrRepoNotFound     = errors.New("repository not found")
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
	// HashState is the sha256 state after Offset bytes, so finishing the
	// upload need not read it again (and any process can continue it).
	HashState string `json:"hash_state,omitempty"`
}

// ─── Store ────────────────────────────────────────────────────────────────────

// Locker coordinates garbage collection with writes across processes: GC
// holds it exclusively, writes that make data reachable hold it shared.
type Locker interface {
	Shared(ctx context.Context) (release func(), err error)
	Exclusive(ctx context.Context) (release func(), err error)
}

// Store is a thread-safe, content-addressable OCI registry store.
type Store struct {
	d   Driver
	cfg *config.Config

	// gcMu serialises GC against all read/write operations in this
	// process. All normal operations hold a Read lock; GC holds the Write
	// lock. dist, when set, extends this to other processes for writes.
	gcMu sync.RWMutex
	dist Locker

	// blobMu ensures only one goroutine writes a particular blob at a time,
	// preventing duplicate file creation races.
	blobMu sync.Map // Digest → *sync.Mutex

	// uploadMu serialises concurrent chunk appends within a single session.
	uploadMu sync.Map // uuid → *sync.Mutex
}

// Filesystem is the former name of Store.
type Filesystem = Store

// NewFilesystem initialises (or reopens) a store in the directory root.
func NewFilesystem(root string, cfg *config.Config) (*Store, error) {
	for _, d := range []string{"blobs/sha256", "uploads", "repositories"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return New(NewFSDriver(root), cfg), nil
}

// New creates a store on driver d.
func New(d Driver, cfg *config.Config) *Store { return &Store{d: d, cfg: cfg} }

// Driver is the store's driver.
func (fs *Store) Driver() Driver { return fs.d }

// SetLocker coordinates GC with other processes sharing the storage.
func (fs *Store) SetLocker(l Locker) { fs.dist = l }

// bg is the context of store operations (the API predates contexts).
var bg = context.Background()

// writeLock is held by operations that make data reachable (link a blob,
// store a manifest): GC must not sweep in between, here or elsewhere.
func (fs *Store) writeLock() (func(), error) {
	fs.gcMu.RLock()
	if fs.dist == nil {
		return fs.gcMu.RUnlock, nil
	}
	release, err := fs.dist.Shared(bg)
	if err != nil {
		fs.gcMu.RUnlock()
		return nil, fmt.Errorf("storage lock: %w", err)
	}
	return func() { release(); fs.gcMu.RUnlock() }, nil
}

// localPath is the file of p on a filesystem driver ("" otherwise).
func (fs *Store) localPath(p string) string {
	if d, ok := fs.d.(*FSDriver); ok {
		return d.full(p)
	}
	return ""
}

// ─── Blob operations ──────────────────────────────────────────────────────────

// blobPath returns the path of a stored blob.
func (fs *Store) blobPath(d Digest) string {
	h := d.Hex()
	return join("blobs", "sha256", h[:2], h[2:])
}

// StatBlob returns metadata for a blob, or ErrBlobNotFound.
func (fs *Store) StatBlob(d Digest) (*BlobInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	return fs.statBlobLocked(d)
}

func (fs *Store) statBlobLocked(d Digest) (*BlobInfo, error) {
	if !d.Valid() {
		return nil, ErrBlobNotFound
	}
	fi, err := fs.d.Stat(bg, fs.blobPath(d))
	if err != nil {
		if notExist(err) {
			return nil, ErrBlobNotFound
		}
		return nil, err
	}
	return &BlobInfo{Digest: d, Size: fi.Size, CreatedAt: fi.ModTime}, nil
}

// Blob is an open blob for reading with random access (Range requests).
type Blob struct {
	io.ReadSeeker
	io.Closer
	Size    int64
	ModTime time.Time
}

// OpenBlob opens a blob for reading. The caller must close it.
func (fs *Store) OpenBlob(d Digest) (*Blob, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	info, err := fs.statBlobLocked(d)
	if err != nil {
		return nil, err
	}
	if fd, ok := fs.d.(*FSDriver); ok {
		f, err := fd.File(fs.blobPath(d))
		if err != nil {
			if notExist(err) {
				return nil, ErrBlobNotFound
			}
			return nil, err
		}
		return &Blob{ReadSeeker: f, Closer: f, Size: info.Size, ModTime: info.CreatedAt}, nil
	}
	r := &seekReader{d: fs.d, p: fs.blobPath(d), size: info.Size}
	return &Blob{ReadSeeker: r, Closer: r, Size: info.Size, ModTime: info.CreatedAt}, nil
}

// BlobRedirectURL is a URL the client may download blob d from directly
// (presigned S3), or "".
func (fs *Store) BlobRedirectURL(d Digest) string {
	return fs.d.RedirectURL(fs.blobPath(d), 20*time.Minute)
}

// seekReader reads a file of a driver without random access, reopening
// it at the new offset after a Seek.
type seekReader struct {
	d    Driver
	p    string
	size int64
	off  int64
	rc   io.ReadCloser
}

func (r *seekReader) Read(b []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	if r.rc == nil {
		rc, err := r.d.Reader(bg, r.p, r.off)
		if err != nil {
			return 0, err
		}
		r.rc = rc
	}
	n, err := r.rc.Read(b)
	r.off += int64(n)
	return n, err
}

func (r *seekReader) Seek(offset int64, whence int) (int64, error) {
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = r.off + offset
	case io.SeekEnd:
		next = r.size + offset
	}
	if next < 0 {
		return 0, errors.New("negative position")
	}
	if next != r.off && r.rc != nil {
		r.rc.Close()
		r.rc = nil
	}
	r.off = next
	return next, nil
}

func (r *seekReader) Close() error {
	if r.rc != nil {
		return r.rc.Close()
	}
	return nil
}

// PutBlob writes a blob from r, verifying it matches d.
// If the blob already exists the call is a no-op (deduplication).
func (fs *Store) PutBlob(d Digest, r io.Reader) (*BlobInfo, error) {
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
	if info, err := fs.statBlobLocked(d); err == nil {
		return info, nil
	}

	// The blob appears only on Commit, after its digest is verified.
	w, err := fs.d.Writer(bg, fs.blobPath(d))
	if err != nil {
		return nil, fmt.Errorf("create blob: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), r)
	if err != nil {
		w.Cancel()
		return nil, fmt.Errorf("write blob: %w", err)
	}
	actual := DigestFromHex(hex.EncodeToString(h.Sum(nil)))
	if actual != d {
		w.Cancel()
		return nil, &DigestMismatchError{Expected: d, Actual: actual}
	}
	if err := w.Commit(); err != nil {
		return nil, fmt.Errorf("commit blob: %w", err)
	}
	return &BlobInfo{Digest: d, Size: n}, nil
}

// DeleteBlob removes a blob from the store.
func (fs *Store) DeleteBlob(d Digest) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	return fs.d.Delete(bg, fs.blobPath(d))
}

// MountBlob links blob d from repository from into repository to without
// transferring data. Returns false when the blob is missing or does not
// belong to from.
func (fs *Store) MountBlob(from, to string, d Digest) bool {
	unlock, err := fs.writeLock()
	if err != nil {
		return false
	}
	defer unlock()

	if !fs.blobLinkedLocked(from, d) {
		return false
	}
	if _, err := fs.statBlobLocked(d); err != nil {
		return false
	}
	return fs.linkBlobLocked(to, d) == nil
}

// ─── Repository blob links ────────────────────────────────────────────────────
//
// Blobs are stored once for all repositories, but a repository may only serve
// the blobs linked to it: uploaded to it, mounted into it, or referenced by
// one of its manifests. Without this, anyone who can read one repository could
// fetch any blob in the store by digest.

// LinkBlob records that blob d belongs to repo. Linking refreshes the link's
// mtime, which GC treats as a grace period (see RunGC).
func (fs *Store) LinkBlob(repo string, d Digest) error {
	unlock, err := fs.writeLock()
	if err != nil {
		return err
	}
	defer unlock()
	return fs.linkBlobLocked(repo, d)
}

func (fs *Store) linkBlobLocked(repo string, d Digest) error {
	if !d.Valid() {
		return fmt.Errorf("invalid digest %q", d)
	}
	p := fs.layerRefPath(repo, d.Hex())
	if local := fs.localPath(p); local != "" {
		now := time.Now()
		if os.Chtimes(local, now, now) == nil {
			return nil
		}
	}
	return fs.d.PutContent(bg, p, nil)
}

// BlobLinked reports whether blob d belongs to repo.
func (fs *Store) BlobLinked(repo string, d Digest) bool {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	return fs.blobLinkedLocked(repo, d)
}

func (fs *Store) blobLinkedLocked(repo string, d Digest) bool {
	if !d.Valid() {
		return false
	}
	_, err := fs.d.Stat(bg, fs.layerRefPath(repo, d.Hex()))
	return err == nil
}

// UnlinkBlob removes blob d from repo. The data stays on disk while other
// repositories use it; GC removes it once no manifest references it.
func (fs *Store) UnlinkBlob(repo string, d Digest) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	if !d.Valid() {
		return ErrBlobNotFound
	}
	p := fs.layerRefPath(repo, d.Hex())
	if _, err := fs.d.Stat(bg, p); notExist(err) {
		return ErrBlobNotFound
	}
	return fs.d.Delete(bg, p)
}

// ─── Upload session operations ────────────────────────────────────────────────
//
// An upload is a series of chunks (one per PATCH, usually just one), each
// stored as its own file, plus info.json with the offset and the sha256
// state. Any process can take the next chunk; completing the upload
// verifies the digest from the saved state and composes the chunks into
// the blob.

func (fs *Store) uploadDir(uuid string) string { return join("uploads", uuid) }

func chunkName(offset int64) string { return fmt.Sprintf("chunk-%020d", offset) }

// StartUpload begins a new chunked upload for repo and returns its metadata.
func (fs *Store) StartUpload(repo string) (*UploadInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	info := &UploadInfo{
		UUID:      newUUID(),
		Repo:      repo,
		StartedAt: time.Now(),
		Offset:    0,
	}
	if err := fs.saveUploadInfo(info); err != nil {
		return nil, err
	}
	fs.uploadMu.Store(info.UUID, &sync.Mutex{})
	return info, nil
}

// GetUpload returns the current state of an upload session.
func (fs *Store) GetUpload(uuid string) (*UploadInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	return fs.loadUploadInfo(uuid)
}

// AppendUpload appends a chunk to an upload session.
//
// startOffset must equal the current upload offset; pass -1 to skip the check
// and always append sequentially (for PUT completion with no Content-Range).
// Returns the new total offset after writing.
func (fs *Store) AppendUpload(uuid string, r io.Reader, startOffset int64) (int64, error) {
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
	if err := fs.appendChunkLocked(info, r); err != nil {
		return info.Offset, err
	}
	return info.Offset, nil
}

// appendChunkLocked stores r as the next chunk and saves the new state.
func (fs *Store) appendChunkLocked(info *UploadInfo, r io.Reader) error {
	h, err := fs.uploadHash(info)
	if err != nil {
		return err
	}
	w, err := fs.d.Writer(bg, join(fs.uploadDir(info.UUID), chunkName(info.Offset)))
	if err != nil {
		return fmt.Errorf("create chunk: %w", err)
	}
	n, err := io.Copy(io.MultiWriter(w, h), r)
	if err != nil {
		w.Cancel()
		return fmt.Errorf("write chunk: %w", err)
	}
	if n == 0 {
		w.Cancel()
		return nil
	}
	if err := w.Commit(); err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return err
	}
	info.Offset += n
	info.HashState = base64.StdEncoding.EncodeToString(state)
	return fs.saveUploadInfo(info)
}

// uploadHash returns the sha256 state after the bytes already uploaded.
func (fs *Store) uploadHash(info *UploadInfo) (hash.Hash, error) {
	h := sha256.New()
	if info.Offset == 0 {
		return h, nil
	}
	if info.HashState != "" {
		state, err := base64.StdEncoding.DecodeString(info.HashState)
		if err == nil {
			err = h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state)
		}
		return h, err
	}
	// Uploads started before hash states were saved: read them.
	chunks, err := fs.uploadChunks(info.UUID)
	if err != nil {
		return nil, err
	}
	for _, c := range chunks {
		rc, err := fs.d.Reader(bg, c, 0)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(h, rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	return h, nil
}

// uploadChunks lists an upload's chunk files in order ("data" is the
// single file of uploads started by earlier versions).
func (fs *Store) uploadChunks(uuid string) ([]string, error) {
	entries, err := fs.d.List(bg, fs.uploadDir(uuid))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		switch {
		case e.Name == "data": // always the first bytes
			out = append([]string{join(fs.uploadDir(uuid), e.Name)}, out...)
		case strings.HasPrefix(e.Name, "chunk-"):
			out = append(out, join(fs.uploadDir(uuid), e.Name))
		}
	}
	return out, nil
}

// CompleteUpload finalises a chunked upload.
//
// If finalChunk is non-nil it is appended before the digest is verified
// (this handles the case where the client sends data in the PUT request).
// The blob is linked to the session's repository under the same lock, so GC
// cannot remove it before the client pushes the manifest. The upload session
// is removed on success.
func (fs *Store) CompleteUpload(uuid string, expected Digest, finalChunk io.Reader) (*BlobInfo, error) {
	unlock, err := fs.writeLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	raw, _ := fs.uploadMu.LoadOrStore(uuid, &sync.Mutex{})
	mu := raw.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	info, err := fs.loadUploadInfo(uuid)
	if err != nil {
		return nil, err
	}
	if finalChunk != nil {
		if err := fs.appendChunkLocked(info, finalChunk); err != nil {
			return nil, err
		}
	}

	h, err := fs.uploadHash(info)
	if err != nil {
		return nil, fmt.Errorf("compute digest: %w", err)
	}
	actual := DigestFromHex(hex.EncodeToString(h.Sum(nil)))
	if expected != "" && actual != expected {
		return nil, &DigestMismatchError{Expected: expected, Actual: actual}
	}

	// Compose the chunks into the blob, unless it exists (deduplication).
	if _, err := fs.statBlobLocked(actual); errors.Is(err, ErrBlobNotFound) {
		chunks, err := fs.uploadChunks(uuid)
		if err != nil {
			return nil, err
		}
		if len(chunks) == 0 {
			err = fs.d.PutContent(bg, fs.blobPath(actual), nil)
		} else {
			err = fs.d.Concat(bg, fs.blobPath(actual), chunks)
		}
		if err != nil {
			return nil, fmt.Errorf("commit blob: %w", err)
		}
	} else if err != nil {
		return nil, err
	}

	if err := fs.linkBlobLocked(info.Repo, actual); err != nil {
		return nil, fmt.Errorf("link blob: %w", err)
	}

	// Clean up the upload session.
	fs.d.Delete(bg, fs.uploadDir(uuid))
	fs.uploadMu.Delete(uuid)

	return &BlobInfo{Digest: actual, Size: info.Offset}, nil
}

// CancelUpload deletes an in-progress upload session.
func (fs *Store) CancelUpload(uuid string) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	fs.d.Delete(bg, fs.uploadDir(uuid))
	fs.uploadMu.Delete(uuid)
	return nil
}

// ─── Manifest operations ──────────────────────────────────────────────────────

// repoBase returns the path of a repository.
// Repo names with slashes (e.g. "library/ubuntu") are stored as nested dirs.
func (fs *Store) repoBase(repo string) string { return join("repositories", repo) }

func (fs *Store) manifestDigestPath(repo, hexHash string) string {
	return join(fs.repoBase(repo), "manifests", "by-digest", hexHash)
}

func (fs *Store) manifestTagPath(repo, tag string) string {
	return join(fs.repoBase(repo), "manifests", "tags", tag)
}

func (fs *Store) tagsDir(repo string) string { return join(fs.repoBase(repo), "manifests", "tags") }

type manifestFile struct {
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
}

// readManifestFile reads a stored manifest by hex digest.
func (fs *Store) readManifestFile(repo, hexHash string) (manifestFile, error) {
	var mf manifestFile
	b, err := fs.d.GetContent(bg, fs.manifestDigestPath(repo, hexHash))
	if err != nil {
		if notExist(err) {
			return mf, ErrManifestNotFound
		}
		return mf, err
	}
	if err := json.Unmarshal(b, &mf); err != nil {
		return mf, fmt.Errorf("corrupt manifest file: %w", err)
	}
	return mf, nil
}

// GetManifest retrieves a manifest by tag or digest.
func (fs *Store) GetManifest(repo, reference string) (*Manifest, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	hexHash, err := fs.resolveReference(repo, reference)
	if err != nil {
		return nil, err
	}
	mf, err := fs.readManifestFile(repo, hexHash)
	if err != nil {
		return nil, err
	}
	return &Manifest{
		ContentType: mf.ContentType,
		Content:     mf.Content,
		Digest:      DigestFromHex(hexHash),
	}, nil
}

// PutManifest stores a manifest under the given tag or digest reference.
// It populates m.Digest with the computed sha256 of the content.
func (fs *Store) PutManifest(repo, reference string, m *Manifest) error {
	unlock, err := fs.writeLock()
	if err != nil {
		return err
	}
	defer unlock()

	// Compute canonical digest.
	sum := sha256.Sum256(m.Content)
	hexHash := hex.EncodeToString(sum[:])
	m.Digest = DigestFromHex(hexHash)

	raw, err := json.Marshal(manifestFile{ContentType: m.ContentType, Content: m.Content})
	if err != nil {
		return err
	}
	if err := fs.d.PutContent(bg, fs.manifestDigestPath(repo, hexHash), raw); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	// Update tag reference if the reference is a tag (not a digest).
	if d := Digest(reference); !d.Valid() {
		if err := fs.d.PutContent(bg, fs.manifestTagPath(repo, reference), []byte(hexHash)); err != nil {
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
func (fs *Store) DeleteManifest(repo, reference string) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	if d := Digest(reference); d.Valid() {
		if err := fs.d.Delete(bg, fs.manifestDigestPath(repo, d.Hex())); err != nil {
			return err
		}
		// Also remove any tags that pointed to this digest.
		entries, _ := fs.d.List(bg, fs.tagsDir(repo))
		for _, e := range entries {
			if e.IsDir {
				continue
			}
			p := join(fs.tagsDir(repo), e.Name)
			b, err := fs.d.GetContent(bg, p)
			if err == nil && strings.TrimSpace(string(b)) == d.Hex() {
				fs.d.Delete(bg, p)
			}
		}
		return nil
	}

	// It's a tag.
	return fs.d.Delete(bg, fs.manifestTagPath(repo, reference))
}

// ListTags returns all tags for a repository in lexicographic order.
func (fs *Store) ListTags(repo string) ([]string, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	entries, err := fs.d.List(bg, fs.tagsDir(repo))
	if err != nil {
		return nil, err
	}
	tags := []string{}
	for _, e := range entries {
		if !e.IsDir {
			tags = append(tags, e.Name)
		}
	}
	return tags, nil
}

// TagInfo is a tag pointer: the manifest it points to and when it was pushed.
type TagInfo struct {
	Name     string
	Digest   Digest
	PushedAt time.Time
}

// RepoTags returns every tag of repo with its digest and push time (the tag
// file's mtime, set on every push of the tag).
func (fs *Store) RepoTags(repo string) ([]TagInfo, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	entries, err := fs.d.List(bg, fs.tagsDir(repo))
	if err != nil {
		return nil, err
	}
	var out []TagInfo
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		b, err := fs.d.GetContent(bg, join(fs.tagsDir(repo), e.Name))
		if err != nil {
			continue
		}
		out = append(out, TagInfo{
			Name:     e.Name,
			Digest:   DigestFromHex(strings.TrimSpace(string(b))),
			PushedAt: e.ModTime,
		})
	}
	return out, nil
}

// DeleteRepository removes repo's manifests, tags and blob links. Nested
// repositories (repo/sub) live in subdirectories and are left untouched.
// Blob data is removed later by GC once nothing references it.
func (fs *Store) DeleteRepository(repo string) error {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	base := fs.repoBase(repo)
	if !fs.isRepo(base) {
		return ErrRepoNotFound
	}
	for _, sub := range []string{"manifests", "layers"} {
		if err := fs.d.Delete(bg, join(base, sub)); err != nil {
			return err
		}
	}
	// Remove now-empty directories up to repositories/, keeping parents
	// that still hold nested repositories. (Object stores have none.)
	if local := fs.localPath(base); local != "" {
		reposDir := fs.localPath("repositories")
		for dir := local; dir != reposDir && strings.HasPrefix(dir, reposDir); dir = filepath.Dir(dir) {
			if os.Remove(dir) != nil {
				break
			}
		}
	}
	return nil
}

// isRepo reports whether dir is a repository (has manifests).
func (fs *Store) isRepo(dir string) bool {
	entries, _ := fs.d.List(bg, dir)
	for _, e := range entries {
		if e.IsDir && e.Name == "manifests" {
			return true
		}
	}
	return false
}

// ListRepositories returns all known repository names.
func (fs *Store) ListRepositories() ([]string, error) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	var repos []string
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := fs.d.List(bg, dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir {
				continue
			}
			if e.Name == "manifests" {
				repos = append(repos, strings.TrimPrefix(dir, "repositories/"))
				continue
			}
			if e.Name == "layers" {
				continue
			}
			if err := walk(join(dir, e.Name)); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk("repositories")
	return repos, err
}

// ─── GC reference tracking ────────────────────────────────────────────────────

func (fs *Store) layerRefPath(repo, hexHash string) string {
	return join(fs.repoBase(repo), "layers", hexHash)
}

// recordBlobRefs links every blob referenced by manifest content to repo.
func (fs *Store) recordBlobRefs(repo string, content []byte) error {
	for _, d := range extractDigests(content) {
		if err := fs.linkBlobLocked(repo, d); err != nil {
			return err
		}
	}
	return nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func (fs *Store) resolveReference(repo, reference string) (hexHash string, err error) {
	if d := Digest(reference); d.Valid() {
		return d.Hex(), nil
	}
	// It's a tag.
	b, err := fs.d.GetContent(bg, fs.manifestTagPath(repo, reference))
	if err != nil {
		if notExist(err) {
			return "", ErrManifestNotFound
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (fs *Store) saveUploadInfo(info *UploadInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return fs.d.PutContent(bg, join(fs.uploadDir(info.UUID), "info.json"), b)
}

func (fs *Store) loadUploadInfo(uuid string) (*UploadInfo, error) {
	if uuid == "" || strings.ContainsAny(uuid, "/\\.") {
		return nil, ErrUploadNotFound
	}
	b, err := fs.d.GetContent(bg, join(fs.uploadDir(uuid), "info.json"))
	if err != nil {
		if notExist(err) {
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
	h := hex.EncodeToString(b)  // 32 lowercase hex chars
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

// isManifest reports whether hexHash names a manifest stored in repo.
func (fs *Store) isManifest(repo, hexHash string) bool {
	_, err := fs.d.Stat(bg, fs.manifestDigestPath(repo, hexHash))
	return err == nil
}

// ReachableBlobs adds to into every blob (with its size on disk) reachable
// from repo's tags: configs and layers, following the platform manifests
// of an index.
func (fs *Store) ReachableBlobs(repo string, into map[Digest]int64) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()

	entries, _ := fs.d.List(bg, fs.tagsDir(repo))
	seen := map[string]bool{}
	var stack []string
	for _, e := range entries {
		if b, err := fs.d.GetContent(bg, join(fs.tagsDir(repo), e.Name)); err == nil {
			stack = append(stack, strings.TrimSpace(string(b)))
		}
	}
	for len(stack) > 0 {
		hexHash := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[hexHash] || len(hexHash) != 64 {
			continue
		}
		seen[hexHash] = true
		mf, err := fs.readManifestFile(repo, hexHash)
		if err != nil {
			continue
		}
		fs.addManifestBlobsLocked(repo, mf.Content, into, &stack)
	}
}

// ManifestBlobs adds to into the blobs referenced by manifest content,
// following platform manifests already stored in repo.
func (fs *Store) ManifestBlobs(repo string, content []byte, into map[Digest]int64) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	var stack []string
	fs.addManifestBlobsLocked(repo, content, into, &stack)
	seen := map[string]bool{}
	for len(stack) > 0 {
		hexHash := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[hexHash] {
			continue
		}
		seen[hexHash] = true
		if mf, err := fs.readManifestFile(repo, hexHash); err == nil {
			fs.addManifestBlobsLocked(repo, mf.Content, into, &stack)
		}
	}
}

// addManifestBlobsLocked records blobs referenced by content; digests that
// name a manifest in repo are pushed onto stack instead.
func (fs *Store) addManifestBlobsLocked(repo string, content []byte, into map[Digest]int64, stack *[]string) {
	for _, d := range extractDigests(content) {
		if fs.isManifest(repo, d.Hex()) {
			*stack = append(*stack, d.Hex())
			continue
		}
		if info, err := fs.statBlobLocked(d); err == nil {
			into[d] = info.Size
		}
	}
}

// DiskInfo describes the filesystem holding the storage root.
type DiskInfo struct {
	Total     uint64 // bytes
	Free      uint64 // bytes available to the registry process
	Supported bool   // false where the platform (or driver) cannot report it
}

// DataSize returns the bytes of all blobs.
func (fs *Store) DataSize() int64 {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	var total int64
	fs.d.Walk(bg, "blobs", func(_ string, info FileInfo) error {
		total += info.Size
		return nil
	})
	return total
}

// ImageParts lists what an image (manifest digest in repo) consists of:
// its manifests (the index and its platform manifests) and blobs, as hex.
func (fs *Store) ImageParts(repo string, digest Digest) (manifests, blobs []string) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	seen := map[string]bool{}
	stack := []string{digest.Hex()}
	for len(stack) > 0 {
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[h] {
			continue
		}
		seen[h] = true
		mf, err := fs.readManifestFile(repo, h)
		if errors.Is(err, ErrManifestNotFound) {
			continue
		}
		manifests = append(manifests, h)
		if err != nil {
			continue
		}
		var children []string
		fs.addManifestBlobsHexLocked(repo, mf.Content, &blobs, &children)
		stack = append(stack, children...)
	}
	return manifests, blobs
}

// RepoParts lists the manifests and linked blobs of a repository, as hex.
func (fs *Store) RepoParts(repo string) (manifests, blobs []string) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	if entries, err := fs.d.List(bg, join(fs.repoBase(repo), "manifests", "by-digest")); err == nil {
		for _, e := range entries {
			manifests = append(manifests, e.Name)
		}
	}
	if entries, err := fs.d.List(bg, join(fs.repoBase(repo), "layers")); err == nil {
		for _, e := range entries {
			blobs = append(blobs, e.Name)
		}
	}
	return manifests, blobs
}

// BlobsSize returns the bytes of the listed blobs (hex) still stored.
func (fs *Store) BlobsSize(blobs []string) (size int64, present int) {
	fs.gcMu.RLock()
	defer fs.gcMu.RUnlock()
	for _, h := range blobs {
		if info, err := fs.statBlobLocked(DigestFromHex(h)); err == nil {
			size += info.Size
			present++
		}
	}
	return size, present
}

func (fs *Store) addManifestBlobsHexLocked(repo string, content []byte, blobs, children *[]string) {
	for _, d := range extractDigests(content) {
		if fs.isManifest(repo, d.Hex()) {
			*children = append(*children, d.Hex())
		} else {
			*blobs = append(*blobs, d.Hex())
		}
	}
}

// UploadsInProgress returns the number of unfinished upload sessions.
func (fs *Store) UploadsInProgress() int {
	entries, _ := fs.d.List(bg, "uploads")
	n := 0
	for _, e := range entries {
		if e.IsDir {
			n++
		}
	}
	return n
}
