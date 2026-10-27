package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"rgstr/internal/meta"
	"rgstr/internal/storage"
)

// ErrReadOnly is returned for pushes into a cache project.
var ErrReadOnly = errors.New("this project is a pull-through cache: push to the upstream registry instead")

// Cache serves the repositories of proxy projects. Manifests by tag are
// re-checked upstream at most every TTL (a HEAD request, which Docker Hub
// does not count against its pull limit); manifests by digest and blobs
// never change and are fetched once. When the upstream is unreachable,
// cached content is served as is.
type Cache struct {
	store *storage.Store
	meta  *meta.Store
	ttl   time.Duration

	// OnCached is told about every manifest fetched from upstream (to
	// scan it); nil: nothing.
	OnCached func(repo string, digest storage.Digest)

	mu      sync.Mutex
	clients map[string]*client   // project → client for its current config
	keys    map[string]string    // project → config the client was made for
	checked map[string]time.Time // repo:tag → last upstream check

	blobMu sync.Map // digest → *sync.Mutex: one upstream download per blob
}

// New creates a Cache; ttl is how long a cached tag is trusted.
func New(store *storage.Store, m *meta.Store, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Cache{store: store, meta: m, ttl: ttl,
		clients: map[string]*client{}, keys: map[string]string{}, checked: map[string]time.Time{}}
}

// For returns the proxy project repo belongs to.
func (c *Cache) For(repo string) (meta.Project, bool) {
	if c == nil {
		return meta.Project{}, false
	}
	name := meta.ProjectOf(repo)
	if name == "" {
		return meta.Project{}, false
	}
	p, ok := c.meta.Project(name)
	return p, ok && p.Proxy != nil && p.Proxy.URL != ""
}

func (c *Cache) client(p meta.Project) (*client, error) {
	key := p.Proxy.URL + "\x00" + p.Proxy.Username + "\x00" + p.Proxy.Password
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.clients[p.Name]; ok && c.keys[p.Name] == key {
		return cl, nil
	}
	cl, err := newClient(p.Proxy.URL, p.Proxy.Username, p.Proxy.Password)
	if err != nil {
		return nil, err
	}
	c.clients[p.Name], c.keys[p.Name] = cl, key
	return cl, nil
}

// remote is the upstream repository of repo in project p.
func remote(cl *client, p meta.Project, repo string) string {
	return cl.remoteName(strings.TrimPrefix(repo, p.Name+"/"))
}

func (c *Cache) fresh(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.checked[key]) < c.ttl
}

func (c *Cache) markChecked(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked[key] = time.Now()
	if len(c.checked) > 100000 { // bounded: forget everything, re-check lazily
		c.checked = map[string]time.Time{key: time.Now()}
	}
}

// EnsureManifest makes repo:ref available locally, fetching or refreshing
// it from the upstream. A nil error means the store can serve it.
func (c *Cache) EnsureManifest(ctx context.Context, p meta.Project, repo, ref string, accept []string) error {
	cl, err := c.client(p)
	if err != nil {
		return err
	}
	byDigest := storage.Digest(ref).Valid()
	local, lerr := c.store.GetManifest(repo, ref)
	key := repo + ":" + ref
	switch {
	case lerr == nil && byDigest:
		return nil // content-addressed: never changes
	case lerr == nil && c.fresh(key):
		return nil
	}
	rname := remote(cl, p, repo)
	if lerr == nil {
		// Cached tag: is it still the same image upstream?
		_, _, dg, err := cl.manifest(ctx, rname, ref, accept, true)
		if err != nil {
			log.Printf("proxy %s: %s:%s: %v (serving the cached image)", p.Name, rname, ref, err)
			c.markChecked(key) // do not hammer a failing upstream
			return nil
		}
		if dg == string(local.Digest) {
			c.markChecked(key)
			return nil
		}
	}
	body, ct, dg, err := cl.manifest(ctx, rname, ref, accept, false)
	if err != nil {
		if lerr == nil {
			log.Printf("proxy %s: %s:%s: %v (serving the cached image)", p.Name, rname, ref, err)
			return nil
		}
		return err
	}
	sum := sha256.Sum256(body)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if (dg != "" && dg != actual) || (byDigest && ref != actual) {
		return fmt.Errorf("upstream manifest %s:%s does not match its digest", rname, ref)
	}
	if ct == "" {
		ct = "application/vnd.docker.distribution.manifest.v2+json"
	}
	mf := &storage.Manifest{ContentType: ct, Content: body}
	if err := c.store.PutManifest(repo, ref, mf); err != nil {
		return err
	}
	c.markChecked(key)
	if c.OnCached != nil {
		c.OnCached(repo, mf.Digest)
	}
	return nil
}

// ServeBlob answers a blob request of a proxy repository that is not
// cached yet: it streams the blob from the upstream to the client while
// storing it. It reports false when the blob is cached (the caller serves
// it as usual).
func (c *Cache) ServeBlob(w http.ResponseWriter, r *http.Request, p meta.Project, repo string, d storage.Digest) bool {
	if _, err := c.store.StatBlob(d); err == nil {
		c.store.LinkBlob(repo, d) // fetched for another repository
		return false
	}
	cl, err := c.client(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return true
	}
	rname := remote(cl, p, repo)
	if r.Method == http.MethodHead {
		rc, size, err := cl.blob(r.Context(), rname, string(d), true)
		if err != nil {
			blobError(w, err)
			return true
		}
		rc.Close()
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", string(d))
		w.WriteHeader(http.StatusOK)
		return true
	}

	raw, _ := c.blobMu.LoadOrStore(d, &sync.Mutex{})
	mu := raw.(*sync.Mutex)
	caching := mu.TryLock()
	if caching {
		defer mu.Unlock()
		if _, err := c.store.StatBlob(d); err == nil { // fetched meanwhile
			c.store.LinkBlob(repo, d)
			return false
		}
	}
	// Caching: the download outlives a client that goes away, so the
	// cache fills. Not caching (the blob is being cached by another
	// request, e.g. the client retrying a slow download): pass it through
	// instead of making the client wait without an answer.
	ctx := r.Context()
	if caching {
		ctx = context.WithoutCancel(ctx)
	}
	rc, size, err := cl.blob(ctx, rname, string(d), false)
	if err != nil {
		blobError(w, err)
		return true
	}
	defer rc.Close()
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", string(d))
	w.WriteHeader(http.StatusOK)
	if !caching {
		io.Copy(w, rc)
		return true
	}
	if _, err := c.store.PutBlob(d, io.TeeReader(rc, &lenient{w: w})); err != nil {
		log.Printf("proxy %s: blob %s of %s: %v", p.Name, d, rname, err)
		return true
	}
	c.store.LinkBlob(repo, d)
	return true
}

func blobError(w http.ResponseWriter, err error) {
	status, code := Status(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"errors":[{"code":%q,"message":%q}]}`, code, err.Error())
}

// Status maps an upstream error to the HTTP status and OCI error code to
// answer the client with.
func Status(err error) (int, string) {
	var ue *UpstreamError
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "MANIFEST_UNKNOWN"
	case errors.As(err, &ue) && ue.Status == http.StatusTooManyRequests:
		return http.StatusTooManyRequests, "TOOMANYREQUESTS"
	case errors.As(err, &ue) && (ue.Status == http.StatusUnauthorized || ue.Status == http.StatusForbidden):
		return http.StatusBadGateway, "UNAUTHORIZED" // our upstream credentials, not the client's
	}
	return http.StatusBadGateway, "UNAVAILABLE"
}

// lenient passes writes to the client until the first error, then drops
// them, so a client going away does not stop caching the blob.
type lenient struct {
	w      io.Writer
	failed bool
}

func (l *lenient) Write(p []byte) (int, error) {
	if !l.failed {
		if _, err := l.w.Write(p); err != nil {
			l.failed = true
		}
	}
	return len(p), nil
}
