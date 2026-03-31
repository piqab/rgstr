// Package registry implements the OCI Distribution Specification v1.1 and the
// Docker Registry HTTP API v2.
//
// Routing is handled by a single catch-all handler that dispatches via regex
// because repository names may contain slashes (e.g. "library/ubuntu") and
// the standard http.ServeMux wildcard patterns cannot match mid-path segments.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
	"rgstr/internal/ui"
)

// ─── URL patterns ─────────────────────────────────────────────────────────────
//
// All patterns are anchored. The capture groups are:
//   reTags:     (1) repo
//   reManifest: (1) repo, (2) reference (tag or digest)
//   reBlob:     (1) repo, (2) digest (sha256:<hex>)
//   reUpload:   (1) repo
//   reUploadID: (1) repo, (2) uuid

var (
	reTags     = regexp.MustCompile(`^/v2/(.+)/tags/list$`)
	reManifest = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)
	reBlob     = regexp.MustCompile(`^/v2/(.+)/blobs/(sha256:[a-f0-9]{64})$`)
	reUpload   = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/?$`)
	reUploadID = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/([0-9a-f-]{36})$`)
	reCatalog  = regexp.MustCompile(`^/v2/_catalog$`)
)

// Registry is the top-level HTTP handler for the OCI registry.
type Registry struct {
	store       *storage.Filesystem
	tokenSvc    *auth.TokenService
	cfg         *config.Config
	counter     *stats.Counter
	authHandler *auth.Handler
}

// New creates a Registry.
func New(store *storage.Filesystem, tokenSvc *auth.TokenService, cfg *config.Config, counter *stats.Counter) *Registry {
	return &Registry{store: store, tokenSvc: tokenSvc, cfg: cfg, counter: counter}
}

// Mount registers the registry handler on mux. The auth middleware is always
// installed so that /v2/auth works even when auth is disabled.
func (reg *Registry) Mount(mux *http.ServeMux) {
	inner := http.HandlerFunc(reg.dispatch)
	reg.authHandler = auth.NewHandler(reg.cfg, reg.tokenSvc, inner)
	mux.Handle("/v2/", reg.authHandler)

	// /healthz is intentionally unauthenticated — used by load balancers and
	// container orchestrators to determine liveness.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/stats", reg.handleStats)

	ui.New(reg.cfg, reg.authHandler).Mount(mux)
}

// dispatch is the central router.
func (reg *Registry) dispatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")

	path := r.URL.Path
	method := r.Method

	log.Printf("%s %s", method, r.URL.RequestURI())

	// ── GET /v2/ ── version check ──────────────────────────────────────────
	if path == "/v2/" || path == "/v2" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
		return
	}

	// ── GET /v2/_catalog ──────────────────────────────────────────────────
	if reCatalog.MatchString(path) {
		if method == http.MethodGet {
			reg.handleCatalog(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	// ── Tags list ─────────────────────────────────────────────────────────
	if m := reTags.FindStringSubmatch(path); m != nil {
		if method == http.MethodGet {
			reg.handleTagsList(w, r, m[1])
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	// ── Manifests ─────────────────────────────────────────────────────────
	if m := reManifest.FindStringSubmatch(path); m != nil {
		repo, ref := m[1], m[2]
		switch method {
		case http.MethodHead:
			reg.handleHeadManifest(w, r, repo, ref)
		case http.MethodGet:
			reg.handleGetManifest(w, r, repo, ref)
		case http.MethodPut:
			reg.handlePutManifest(w, r, repo, ref)
		case http.MethodDelete:
			reg.handleDeleteManifest(w, r, repo, ref)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	// ── Upload chunk/complete/status/cancel (UUID path) ───────────────────
	// Must be checked before the "start upload" pattern.
	if m := reUploadID.FindStringSubmatch(path); m != nil {
		repo, uuid := m[1], m[2]
		switch method {
		case http.MethodGet:
			reg.handleGetUpload(w, r, repo, uuid)
		case http.MethodPatch:
			reg.handlePatchUpload(w, r, repo, uuid)
		case http.MethodPut:
			reg.handlePutUpload(w, r, repo, uuid)
		case http.MethodDelete:
			reg.handleDeleteUpload(w, r, repo, uuid)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	// ── Start upload / cross-repo mount ───────────────────────────────────
	if m := reUpload.FindStringSubmatch(path); m != nil {
		if method == http.MethodPost {
			reg.handleStartUpload(w, r, m[1])
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	// ── Blobs ─────────────────────────────────────────────────────────────
	if m := reBlob.FindStringSubmatch(path); m != nil {
		repo, dgst := m[1], storage.Digest(m[2])
		switch method {
		case http.MethodHead:
			reg.handleHeadBlob(w, r, repo, dgst)
		case http.MethodGet:
			reg.handleGetBlob(w, r, repo, dgst)
		case http.MethodDelete:
			reg.handleDeleteBlob(w, r, repo, dgst)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	writeError(w, http.StatusNotFound, CodeNameUnknown, "endpoint not found", nil)
}

// ─── Blob handlers ────────────────────────────────────────────────────────────

func (reg *Registry) handleHeadBlob(w http.ResponseWriter, r *http.Request, repo string, d storage.Digest) {
	info, err := reg.store.StatBlob(d)
	if err != nil {
		if errors.Is(err, storage.ErrBlobNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob unknown",
				map[string]string{"digest": string(d)})
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", string(d))
	w.WriteHeader(http.StatusOK)
}

func (reg *Registry) handleGetBlob(w http.ResponseWriter, r *http.Request, repo string, d storage.Digest) {
	f, err := reg.store.OpenBlob(d)
	if err != nil {
		if errors.Is(err, storage.ErrBlobNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob unknown",
				map[string]string{"digest": string(d)})
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	defer f.Close()

	fi, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", string(d))
	// http.ServeContent handles Range, If-Range, Content-Length, 206 etc.
	http.ServeContent(w, r, "", fi.ModTime(), f)
}

func (reg *Registry) handleDeleteBlob(w http.ResponseWriter, _ *http.Request, repo string, d storage.Digest) {
	if err := reg.store.DeleteBlob(d); err != nil {
		if errors.Is(err, storage.ErrBlobNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ─── Upload handlers ──────────────────────────────────────────────────────────

// handleStartUpload handles POST /v2/<repo>/blobs/uploads/
//
// Supports three modes:
//  1. Plain: starts a new session → 202
//  2. Cross-repo mount (?mount=<digest>&from=<repo>): reuse existing blob → 201
//  3. Single-step (?digest=<digest>): client will send the entire blob in the
//     subsequent PUT; we still return 202 and let handlePutUpload do the work.
func (reg *Registry) handleStartUpload(w http.ResponseWriter, r *http.Request, repo string) {
	q := r.URL.Query()
	mount := q.Get("mount")
	fromRepo := q.Get("from")

	// ── Cross-repo mount ──────────────────────────────────────────────────
	if mount != "" {
		d := storage.Digest(mount)
		if d.Valid() && reg.store.MountBlob(d) {
			// Blob already exists — no data transfer needed.
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, d))
			w.Header().Set("Docker-Content-Digest", string(d))
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusCreated)
			return
		}
		// Blob not found in store — fall through and start a fresh upload.
		// (The from-repo hint is informational only.)
		_ = fromRepo
	}

	info, err := reg.store.StartUpload(repo)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	uploadURL := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, info.UUID)
	w.Header().Set("Location", uploadURL)
	w.Header().Set("Docker-Upload-UUID", info.UUID)
	w.Header().Set("Range", "0-0")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
}

// handleGetUpload handles GET /v2/<repo>/blobs/uploads/<uuid> — reports progress.
func (reg *Registry) handleGetUpload(w http.ResponseWriter, r *http.Request, repo, uuid string) {
	info, err := reg.store.GetUpload(uuid)
	if err != nil {
		if errors.Is(err, storage.ErrUploadNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	if info.Repo != repo {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found in this repository", nil)
		return
	}

	end := info.Offset
	if end > 0 {
		end-- // Range header is inclusive: 0-N means N+1 bytes received
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uuid))
	w.Header().Set("Docker-Upload-UUID", uuid)
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

// handlePatchUpload handles PATCH /v2/<repo>/blobs/uploads/<uuid> — append a chunk.
//
// Content-Range format: "<start>-<end>" where start must equal the current
// upload offset. If Content-Range is absent, the chunk is appended at the
// current offset.
func (reg *Registry) handlePatchUpload(w http.ResponseWriter, r *http.Request, repo, uuid string) {
	// Quick existence / repo check before acquiring the upload lock.
	info, err := reg.store.GetUpload(uuid)
	if err != nil {
		if errors.Is(err, storage.ErrUploadNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	if info.Repo != repo {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found in this repository", nil)
		return
	}

	// Parse optional Content-Range header.
	startOffset := int64(-1) // -1 means "append at current offset"
	if cr := r.Header.Get("Content-Range"); cr != "" {
		var start, end int64
		if _, scanErr := fmt.Sscanf(cr, "%d-%d", &start, &end); scanErr == nil {
			startOffset = start
		} else {
			writeError(w, http.StatusBadRequest, CodeRangeInvalid, "invalid Content-Range header", nil)
			return
		}
	}

	newOffset, err := reg.store.AppendUpload(uuid, r.Body, startOffset)
	if err != nil {
		var re *storage.RangeError
		if errors.As(err, &re) {
			end := re.Expected
			if end > 0 {
				end--
			}
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uuid))
			w.Header().Set("Range", fmt.Sprintf("0-%d", end))
			writeError(w, http.StatusRequestedRangeNotSatisfiable, CodeRangeInvalid,
				fmt.Sprintf("expected offset %d", re.Expected), nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	end := newOffset
	if end > 0 {
		end--
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uuid))
	w.Header().Set("Docker-Upload-UUID", uuid)
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
}

// handlePutUpload handles PUT /v2/<repo>/blobs/uploads/<uuid>?digest=<digest>
// — finalise a chunked upload.
//
// The request body may be empty (if all data was sent via PATCH) or may contain
// the final chunk (monolithic upload or last piece).
func (reg *Registry) handlePutUpload(w http.ResponseWriter, r *http.Request, repo, uuid string) {
	info, err := reg.store.GetUpload(uuid)
	if err != nil {
		if errors.Is(err, storage.ErrUploadNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	if info.Repo != repo {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found in this repository", nil)
		return
	}

	digestStr := r.URL.Query().Get("digest")
	if digestStr == "" {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, "digest query parameter is required", nil)
		return
	}
	expected := storage.Digest(digestStr)
	if !expected.Valid() {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, "invalid digest format", nil)
		return
	}

	// The body may carry the final chunk. Pass it only when non-empty.
	var finalChunk io.Reader
	if r.ContentLength > 0 {
		finalChunk = r.Body
	} else if r.ContentLength < 0 {
		// Unknown length — always pass and let the store handle empty reads.
		finalChunk = r.Body
	}

	blobInfo, err := reg.store.CompleteUpload(uuid, expected, finalChunk)
	if err != nil {
		var mm *storage.DigestMismatchError
		if errors.As(err, &mm) {
			writeError(w, http.StatusBadRequest, CodeDigestInvalid, "digest mismatch",
				map[string]string{
					"expected": string(mm.Expected),
					"actual":   string(mm.Actual),
				})
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, blobInfo.Digest))
	w.Header().Set("Docker-Content-Digest", string(blobInfo.Digest))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// handleDeleteUpload handles DELETE /v2/<repo>/blobs/uploads/<uuid> — cancel.
func (reg *Registry) handleDeleteUpload(w http.ResponseWriter, _ *http.Request, repo, uuid string) {
	info, err := reg.store.GetUpload(uuid)
	if err != nil {
		if errors.Is(err, storage.ErrUploadNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	if info.Repo != repo {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found in this repository", nil)
		return
	}
	if err := reg.store.CancelUpload(uuid); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Manifest handlers ────────────────────────────────────────────────────────

func (reg *Registry) handleHeadManifest(w http.ResponseWriter, r *http.Request, repo, reference string) {
	mf, err := reg.store.GetManifest(repo, reference)
	if err != nil {
		if errors.Is(err, storage.ErrManifestNotFound) {
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	// Honour Accept header: if the client does not accept the stored
	// content-type we still return it (clients generally accept everything).
	w.Header().Set("Content-Type", mf.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(mf.Content)))
	w.Header().Set("Docker-Content-Digest", string(mf.Digest))
	w.WriteHeader(http.StatusOK)
}

func (reg *Registry) handleGetManifest(w http.ResponseWriter, r *http.Request, repo, reference string) {
	mf, err := reg.store.GetManifest(repo, reference)
	if err != nil {
		if errors.Is(err, storage.ErrManifestNotFound) {
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	reg.counter.RecordPull(repo)
	w.Header().Set("Content-Type", mf.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(mf.Content)))
	w.Header().Set("Docker-Content-Digest", string(mf.Digest))
	w.WriteHeader(http.StatusOK)
	w.Write(mf.Content)
}

func (reg *Registry) handlePutManifest(w http.ResponseWriter, r *http.Request, repo, reference string) {
	// Limit manifest size to 10 MiB (generous upper bound per OCI spec).
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeManifestInvalid, "failed to read body", nil)
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, CodeManifestInvalid, "empty manifest", nil)
		return
	}

	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/vnd.docker.distribution.manifest.v2+json"
	}

	mf := &storage.Manifest{
		ContentType: ct,
		Content:     body,
	}
	if err := reg.store.PutManifest(repo, reference, mf); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, mf.Digest))
	w.Header().Set("Docker-Content-Digest", string(mf.Digest))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

func (reg *Registry) handleDeleteManifest(w http.ResponseWriter, _ *http.Request, repo, reference string) {
	if err := reg.store.DeleteManifest(repo, reference); err != nil {
		if errors.Is(err, storage.ErrManifestNotFound) {
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ─── Tags list ────────────────────────────────────────────────────────────────

// handleTagsList handles GET /v2/<repo>/tags/list with optional ?n=&last= pagination.
func (reg *Registry) handleTagsList(w http.ResponseWriter, r *http.Request, repo string) {
	tags, err := reg.store.ListTags(repo)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	tags = paginate(tags, r.URL.Query().Get("last"), queryInt(r, "n"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name": repo,
		"tags": nullableStringSlice(tags),
	})
}

// ─── Catalog ──────────────────────────────────────────────────────────────────

// handleCatalog handles GET /v2/_catalog with optional ?n=&last= pagination.
func (reg *Registry) handleCatalog(w http.ResponseWriter, r *http.Request) {
	repos, err := reg.store.ListRepositories()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	repos = paginate(repos, r.URL.Query().Get("last"), queryInt(r, "n"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"repositories": nullableStringSlice(repos),
	})
}

// ─── Pagination helpers ───────────────────────────────────────────────────────

// paginate applies cursor-based pagination to a sorted slice.
// last is the exclusive lower bound; n is the maximum number of items (0 = all).
func paginate(items []string, last string, n int) []string {
	if last == "" && n == 0 {
		return items
	}
	var out []string
	past := last == ""
	for _, item := range items {
		if !past {
			if item == last {
				past = true
			}
			continue
		}
		out = append(out, item)
		if n > 0 && len(out) >= n {
			break
		}
	}
	return out
}

func queryInt(r *http.Request, key string) int {
	v, _ := strconv.Atoi(r.URL.Query().Get(key))
	return v
}

// nullableStringSlice returns an empty (non-nil) JSON array instead of null
// when the slice is nil, as required by the OCI distribution spec.
func nullableStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type repoStat struct {
	Name  string   `json:"name"`
	Tags  []string `json:"tags"`
	Pulls int64    `json:"pulls"`
}

type statsResponse struct {
	Repositories []repoStat `json:"repositories"`
	TotalRepos   int        `json:"total_repos"`
	TotalPulls   int64      `json:"total_pulls"`
}

func (reg *Registry) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if reg.cfg.AuthEnabled {
		if _, ok := reg.authHandler.CheckBasic(r); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="rgstr"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
			return
		}
	}

	repos, err := reg.store.ListRepositories()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}

	snap := reg.counter.Snapshot()
	var totalPulls int64
	repoStats := make([]repoStat, 0, len(repos))

	for _, name := range repos {
		tags, _ := reg.store.ListTags(name)
		pulls := snap.Pulls[name]
		totalPulls += pulls
		repoStats = append(repoStats, repoStat{
			Name:  name,
			Tags:  nullableStringSlice(tags),
			Pulls: pulls,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statsResponse{
		Repositories: repoStats,
		TotalRepos:   len(repos),
		TotalPulls:   totalPulls,
	})
}

// ─── Repository name validation ───────────────────────────────────────────────

var repoNameRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)

func validRepoName(name string) bool {
	return repoNameRe.MatchString(strings.ToLower(name))
}
