// Package registry implements the OCI Distribution Specification v1.1 and the
// Docker Registry HTTP API v2.
//
// Routing is handled by a single catch-all handler that dispatches via regex
// because repository names may contain slashes (e.g. "library/ubuntu") and
// the standard http.ServeMux wildcard patterns cannot match mid-path segments.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/auth"
	"rgstr/internal/backup"
	"rgstr/internal/config"
	"rgstr/internal/db"
	"rgstr/internal/maint"
	"rgstr/internal/meta"
	"rgstr/internal/metrics"
	"rgstr/internal/ops"
	"rgstr/internal/proxy"
	"rgstr/internal/scan"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
	"rgstr/internal/ui"
	"rgstr/internal/webhook"
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
	ops         *ops.Ops
	meta        *meta.Store
	maint       *maint.Runner
	hooks       *webhook.Notifier
	metrics     *metrics.Registry // nil unless RGSTR_METRICS_ENABLED
	backup      *backup.Runner    // nil unless RGSTR_BACKUP_TARGET
	db          *db.DB            // nil unless RGSTR_DATABASE_URL (cluster)
	proxy       *proxy.Cache      // pull-through cache projects
	scanner     *scan.Scanner     // nil unless RGSTR_SCAN_ENABLED

	sizeMu sync.Mutex
	size   int64
	sizeAt time.Time
}

// registryHost is how clients address the registry, taken from the token
// realm URL (RGSTR_AUTH_REALM), for links in webhook events.
func registryHost(cfg *config.Config) string {
	if u, err := url.Parse(cfg.AuthRealm); err == nil {
		return u.Host
	}
	return ""
}

// New creates a Registry.
func New(store *storage.Filesystem, tokenSvc *auth.TokenService, cfg *config.Config, counter *stats.Counter) *Registry {
	return NewCluster(store, tokenSvc, cfg, counter, nil)
}

// NewCluster creates a Registry whose state is shared through database
// with the other processes of a cluster (nil: one process, files in
// the storage directory).
func NewCluster(store *storage.Filesystem, tokenSvc *auth.TokenService, cfg *config.Config, counter *stats.Counter, database *db.DB) *Registry {
	var m *meta.Store
	var err error
	if database != nil {
		m, err = meta.OpenShared(database.Doc("meta"))
	} else {
		m, err = meta.Open(cfg.StorageRoot)
	}
	if err != nil {
		log.Fatalf("metadata: %v", err)
	}
	if cfg.TrustedProxies != nil {
		if err := audit.TrustProxies(cfg.TrustedProxies); err != nil {
			log.Fatalf("RGSTR_TRUSTED_PROXIES: %v", err)
		}
	}
	var alog *audit.Log
	if database != nil {
		alog = audit.OpenShared(database)
	} else if alog, err = audit.Open(cfg.StorageRoot); err != nil {
		log.Fatalf("audit log: %v", err)
	}
	o := ops.New(store, m, alog)
	hooks := webhook.New(m, registryHost(cfg))
	o.SetNotifier(hooks)
	r := &Registry{
		store:    store,
		tokenSvc: tokenSvc,
		cfg:      cfg,
		counter:  counter,
		ops:      o,
		meta:     m,
		maint:    maint.New(cfg, store, m, o),
		hooks:    hooks,
		db:       database,
	}
	r.proxy = proxy.New(store, m, cfg.ProxyTTL)
	if cfg.Scan.Enabled {
		r.scanner = scan.New(cfg, store, func(repo string) (string, error) {
			return tokenSvc.Issue(scan.Subject, []auth.Access{{Type: "repository", Name: repo, Actions: []string{"pull"}}})
		})
		r.scanner.Claim = r.maint.Claim
		r.scanner.OnScan = r.metrics.ScanRun
		if r.scanner.OnPush() {
			r.proxy.OnCached = r.scanner.Enqueue
		}
	}
	if err := applyProxyEnv(m, cfg.Proxies); err != nil {
		log.Fatalf("RGSTR_PROXIES: %v", err)
	}
	if database != nil {
		store.SetLocker(database)
		r.maint.Claim = func(job string, interval time.Duration) bool {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ok, err := database.Claim(ctx, job, interval)
			if err != nil {
				log.Printf("%s: claim: %v", job, err)
			}
			return ok
		}
		if cfg.Backup.Target != "" {
			log.Fatalf("backup: RGSTR_BACKUP_TARGET does not work in a cluster (RGSTR_DATABASE_URL): " +
				"the data is in S3 and PostgreSQL, back those up (bucket versioning or replication, database backups)")
		}
	}
	if cfg.MetricsEnabled {
		r.metrics = metrics.New(cfg.Version, r.gauges)
		alog.OnAdd(r.metrics.Event)
		r.maint.OnGC = r.metrics.GCRun
	}
	if r.backup, err = backup.New(cfg.Backup, cfg.StorageRoot, cfg.Version); err != nil {
		log.Fatalf("backup: %v", err)
	}
	if r.backup != nil {
		r.backup.Hold = r.maint.Hold
		r.backup.OnRun = func(obj backup.Object, user string, err error) {
			r.metrics.BackupRun(err)
			detail := obj.Name
			if err == nil {
				detail = fmt.Sprintf("%s, %d bytes", obj.Name, obj.Size)
			}
			if user == "" { // manual runs are recorded by the web admin
				o.Audit(ops.System, audit.BackupRun, r.backup.Target().String(), detail, err)
			}
		}
	}
	return r
}

// Mount registers the registry handler on mux. The auth middleware is always
// installed so that /v2/auth works even when auth is disabled.
func (reg *Registry) Mount(mux *http.ServeMux) {
	inner := http.HandlerFunc(reg.dispatch)
	if reg.db != nil {
		reg.authHandler = auth.NewSharedHandler(reg.cfg, reg.tokenSvc, inner, reg.db.Doc("users"))
	} else {
		reg.authHandler = auth.NewHandler(reg.cfg, reg.tokenSvc, inner)
	}
	reg.authHandler.SetAudit(reg.ops.AuditLog())
	reg.authHandler.SetMeta(reg.meta)
	mux.Handle("/v2/", reg.authHandler)

	// /healthz is intentionally unauthenticated — used by load balancers and
	// container orchestrators to determine liveness.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]string{"status": "ok", "version": reg.cfg.Version}
		if reg.backup != nil {
			// When the last backup succeeded, for monitoring and the operator.
			if st := reg.backup.Status(); st.LastSuccess != nil {
				resp["last_backup"] = st.LastSuccess.Format(time.RFC3339)
			}
		}
		json.NewEncoder(w).Encode(resp)
	})

	// /readyz also checks the database and the storage: a process that
	// cannot reach them is taken out of the load balancer, not restarted.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		check := func() error {
			if reg.db != nil {
				if err := reg.db.Ping(ctx); err != nil {
					return fmt.Errorf("database: %w", err)
				}
			}
			if _, err := reg.store.Driver().List(ctx, "repositories"); err != nil {
				return fmt.Errorf("storage: %w", err)
			}
			return nil
		}
		w.Header().Set("Content-Type", "application/json")
		if err := check(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unavailable", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/stats", reg.handleStats)
	if reg.metrics != nil {
		mux.Handle("/metrics", reg.metrics)
	}

	ui.New(ui.Deps{
		Auth:    reg.authHandler,
		Store:   reg.store,
		Counter: reg.counter,
		Ops:     reg.ops,
		Meta:    reg.meta,
		Maint:   reg.maint,
		Hooks:   reg.hooks,
		Backup:  reg.backup,
		Scanner: reg.scanner,
	}).Mount(mux)
}

// Start launches background maintenance (scheduled GC) until ctx ends.
func (reg *Registry) Start(ctx context.Context) {
	reg.maint.Start(ctx)
	if reg.scanner != nil {
		reg.scanner.Start(ctx)
	}
	if reg.backup != nil {
		reg.backup.Start(ctx)
	}
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
		if p, ok := reg.proxy.For(repo); ok {
			switch method {
			case http.MethodGet, http.MethodHead:
				// Fetch or refresh from the upstream; then served as usual.
				if err := reg.proxy.EnsureManifest(r.Context(), p, repo, ref, r.Header.Values("Accept")); err != nil {
					status, code := proxy.Status(err)
					writeError(w, status, code, err.Error(), nil)
					return
				}
			case http.MethodPut:
				writeError(w, http.StatusForbidden, CodeDenied, proxy.ErrReadOnly.Error(), nil)
				return
			}
		}
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
		if _, ok := reg.proxy.For(repo); ok {
			writeError(w, http.StatusForbidden, CodeDenied, proxy.ErrReadOnly.Error(), nil)
			return
		}
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
		if _, ok := reg.proxy.For(m[1]); ok {
			writeError(w, http.StatusForbidden, CodeDenied, proxy.ErrReadOnly.Error(), nil)
			return
		}
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
		if p, ok := reg.proxy.For(repo); ok && (method == http.MethodGet || method == http.MethodHead) && dgst.Valid() {
			if reg.proxy.ServeBlob(w, r, p, repo, dgst) {
				return
			}
		}
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
	info, err := reg.repoBlob(repo, d)
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
	if _, err := reg.repoBlob(repo, d); err != nil {
		if errors.Is(err, storage.ErrBlobNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob unknown",
				map[string]string{"digest": string(d)})
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	// Object storage may let clients download directly.
	if u := reg.store.BlobRedirectURL(d); u != "" {
		w.Header().Set("Docker-Content-Digest", string(d))
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
		return
	}
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", string(d))
	// http.ServeContent handles Range, If-Range, Content-Length, 206 etc.
	http.ServeContent(w, r, "", f.ModTime, f)
}

// repoBlob returns blob metadata if the blob exists and belongs to repo,
// otherwise ErrBlobNotFound — blobs of other repositories stay invisible.
func (reg *Registry) repoBlob(repo string, d storage.Digest) (*storage.BlobInfo, error) {
	if !reg.store.BlobLinked(repo, d) {
		return nil, storage.ErrBlobNotFound
	}
	return reg.store.StatBlob(d)
}

// handleDeleteBlob unlinks the blob from repo only; other repositories that
// share it are unaffected, and GC removes the data once unreferenced.
func (reg *Registry) handleDeleteBlob(w http.ResponseWriter, _ *http.Request, repo string, d storage.Digest) {
	if err := reg.store.UnlinkBlob(repo, d); err != nil {
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
	// Only from a repository the client may pull, and only blobs that belong
	// to it — otherwise a known digest would expose another repo's data.
	if mount != "" {
		d := storage.Digest(mount)
		if d.Valid() && fromRepo != "" &&
			auth.HasAccess(r.Context(), "repository", fromRepo, "pull") &&
			reg.store.MountBlob(fromRepo, repo, d) {
			// Blob already exists — no data transfer needed.
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, d))
			w.Header().Set("Docker-Content-Digest", string(d))
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusCreated)
			return
		}
		// Mount refused — fall through and start a fresh upload.
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
	if msg := reg.blockedPull(r, repo, mf.Digest); msg != "" {
		writeError(w, http.StatusForbidden, CodeDenied, msg, nil)
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
	if msg := reg.blockedPull(r, repo, mf.Digest); msg != "" {
		writeError(w, http.StatusForbidden, CodeDenied, msg, nil)
		return
	}
	if subject := auth.SubjectFromCtx(r.Context()); subject != scan.Subject { // scans are not pulls
		reg.counter.RecordPull(repo)
		reg.ops.RecordPull(ops.ActorFrom(r, subject), repo, reference, mf.Digest)
	}
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
	actor := ops.ActorFrom(r, auth.SubjectFromCtx(r.Context()))
	if err := reg.ops.PutManifest(actor, repo, reference, mf); err != nil {
		if errors.Is(err, ops.ErrImmutable) || errors.Is(err, ops.ErrQuota) {
			writeError(w, http.StatusForbidden, CodeDenied, err.Error(), nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	if reg.scanner.OnPush() {
		reg.scanner.Enqueue(repo, mf.Digest)
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, mf.Digest))
	w.Header().Set("Docker-Content-Digest", string(mf.Digest))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// handleDeleteManifest deletes by tag (only that tag) or by digest (the
// manifest and every tag pointing to it).
func (reg *Registry) handleDeleteManifest(w http.ResponseWriter, r *http.Request, repo, reference string) {
	actor := ops.ActorFrom(r, auth.SubjectFromCtx(r.Context()))
	var err error
	if d := storage.Digest(reference); d.Valid() {
		_, err = reg.ops.DeleteImage(actor, repo, d)
	} else {
		err = reg.ops.DeleteTag(actor, repo, reference)
	}
	if err != nil {
		if errors.Is(err, ops.ErrNotFound) {
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown", nil)
			return
		}
		if errors.Is(err, ops.ErrImmutable) {
			writeError(w, http.StatusForbidden, CodeDenied, err.Error(), nil)
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
	repos = reg.visible(auth.SubjectFromCtx(r.Context()), repos)

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

	subject := ""
	if reg.cfg.AuthEnabled {
		sub, access, ok := reg.authHandler.Authenticate(r)
		subject = sub
		if !ok || !auth.Allowed(access, "registry", "catalog", "*") {
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

	repos = reg.visible(subject, repos)
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

// visible filters repos to those subject may pull.
func (reg *Registry) visible(subject string, repos []string) []string {
	out := repos[:0:0]
	for _, repo := range repos {
		if reg.authHandler.Can(subject, repo, "pull") {
			out = append(out, repo)
		}
	}
	return out
}

// Handler wraps the server's root handler: with metrics enabled, every
// request is counted.
func (reg *Registry) Handler(h http.Handler) http.Handler {
	if reg.metrics == nil {
		return h
	}
	return reg.metrics.Instrument(h)
}

// gauges computes scrape-time metrics. The data size walk is cached for a
// minute: it reads every blob's size.
func (reg *Registry) gauges() metrics.Gauges {
	g := metrics.Gauges{Uploads: reg.store.UploadsInProgress()}
	if repos, err := reg.store.ListRepositories(); err == nil {
		g.Repositories = len(repos)
	}
	reg.sizeMu.Lock()
	// Summing every blob costs a listing of the whole bucket on S3.
	every := time.Minute
	if reg.store.Driver().Name() != "filesystem" {
		every = 10 * time.Minute
	}
	if time.Since(reg.sizeAt) > every {
		reg.size, reg.sizeAt = reg.store.DataSize(), time.Now()
	}
	g.StorageBytes = reg.size
	reg.sizeMu.Unlock()
	if d, err := reg.store.Disk(); err == nil && d.Supported {
		g.DiskSupported, g.DiskTotalBytes, g.DiskFreeBytes = true, d.Total, d.Free
	}
	if h := reg.maint.History(); len(h) > 0 {
		g.LastGC = h[0].Start
	}
	if reg.backup != nil {
		g.Backups = true
		if st := reg.backup.Status(); st.LastSuccess != nil {
			g.LastBackup = *st.LastSuccess
		}
	}
	return g
}

// applyProxyEnv creates or updates the cache projects of RGSTR_PROXIES.
// They are edited in env: a project dropped from it stops being a cache
// (its cached images stay).
func applyProxyEnv(m *meta.Store, envs []config.ProxyEnv) error {
	nameRe := regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	for _, e := range envs {
		if !nameRe.MatchString(e.Name) {
			return fmt.Errorf("project name %q: lowercase letters, digits and . _ - between them", e.Name)
		}
		if !strings.HasPrefix(e.URL, "https://") && !strings.HasPrefix(e.URL, "http://") {
			return fmt.Errorf("%s: upstream %q is not a URL", e.Name, e.URL)
		}
	}
	return m.Update(func(d *meta.Data) error {
		if d.Projects == nil {
			d.Projects = map[string]meta.Project{}
		}
		inEnv := map[string]bool{}
		for _, e := range envs {
			inEnv[e.Name] = true
			p, ok := d.Projects[e.Name]
			if !ok {
				p = meta.Project{Name: e.Name, Members: map[string]string{}, CreatedAt: time.Now().UTC(),
					Description: "Pull-through cache of " + e.URL}
			}
			p.Public = e.Public
			p.Proxy = &meta.ProxyConfig{URL: e.URL, Username: e.Username, Password: e.Password, FromEnv: true}
			d.Projects[e.Name] = p
		}
		for name, p := range d.Projects {
			if p.Proxy != nil && p.Proxy.FromEnv && !inEnv[name] {
				p.Proxy = nil
				d.Projects[name] = p
			}
		}
		return nil
	})
}

// blockedPull explains why the project's policy refuses to serve this
// image ("" when allowed): its scan found vulnerabilities at or above the
// project's limit. Images not scanned yet are served; so is the scanner.
func (reg *Registry) blockedPull(r *http.Request, repo string, d storage.Digest) string {
	if reg.scanner == nil || auth.SubjectFromCtx(r.Context()) == scan.Subject {
		return ""
	}
	name := meta.ProjectOf(repo)
	if name == "" {
		return ""
	}
	p, ok := reg.meta.Project(name)
	if !ok || p.BlockSeverity == "" {
		return ""
	}
	sum := reg.scanner.ImageSummary(repo, d)
	if sum == nil || sum.Status != scan.StatusDone {
		return ""
	}
	if n := sum.AtLeast(p.BlockSeverity); n > 0 {
		return fmt.Sprintf("image %s has %d vulnerabilities of severity %s or worse; project %q refuses to serve it "+
			"(see the image in the web admin)", d, n, p.BlockSeverity, name)
	}
	return ""
}
