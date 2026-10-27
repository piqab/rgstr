package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/registry"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

// newRegistry starts an rgstr; edit adjusts its config (the realm is set
// to the server's own address).
func newRegistry(t *testing.T, edit func(*config.Config)) (*httptest.Server, *storage.Filesystem) {
	t.Helper()
	cfg := &config.Config{
		AuthSecret: "test-secret", AuthService: "test", AuthIssuer: "test",
		TokenTTL: time.Hour, GCInterval: time.Hour, UploadTTL: 24 * time.Hour,
		Users: map[string]string{}, StorageRoot: t.TempDir(), Version: "v0.0.0-test",
		ProxyTTL: time.Hour,
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	cfg.AuthRealm = srv.URL + "/v2/auth"
	cfg.ListenAddr = srv.Listener.Addr().String() // the scanner pulls from here
	if edit != nil {
		edit(cfg)
	}
	store, err := storage.NewFilesystem(cfg.StorageRoot, cfg)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(store, auth.NewTokenService(cfg), cfg, stats.New(cfg.StorageRoot))
	mux := http.NewServeMux()
	reg.Mount(mux)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg.Start(ctx) // scanner workers
	srv.Config.Handler = mux
	t.Cleanup(srv.Close)
	return srv, store
}

// storeImage puts a one-layer image straight into a store.
func storeImage(t *testing.T, s *storage.Filesystem, repo, tag, content string) (manifest, layer string) {
	t.Helper()
	data := []byte(content)
	ld := storage.Digest(digest(data))
	if _, err := s.PutBlob(ld, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	s.LinkBlob(repo, ld)
	cfgBlob := []byte(`{"os":"linux","architecture":"amd64"}`)
	cd := storage.Digest(digest(cfgBlob))
	s.PutBlob(cd, bytes.NewReader(cfgBlob))
	s.LinkBlob(repo, cd)
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},`+
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}`,
		cd, len(cfgBlob), ld, len(data))
	m := &storage.Manifest{ContentType: "application/vnd.oci.image.manifest.v1+json", Content: []byte(body)}
	if err := s.PutManifest(repo, tag, m); err != nil {
		t.Fatal(err)
	}
	return string(m.Digest), string(ld)
}

func get(t *testing.T, url string) (int, []byte, http.Header) {
	t.Helper()
	resp := do(t, "GET", url, nil, map[string]string{"Accept": "application/vnd.oci.image.manifest.v1+json"})
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func TestPullThroughCache(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("upstream-pw"), bcrypt.MinCost)
	// The upstream requires the Docker token flow: anonymous pull of
	// library/*, credentials for team/*.
	up, upStore := newRegistry(t, func(c *config.Config) {
		c.AuthEnabled = true
		c.PublicRepos = []string{"library/**"}
		c.Users = map[string]string{"bot": string(hash)}
	})
	mDigest, lDigest := storeImage(t, upStore, "library/alpine", "3.20", "alpine layer v1")
	privDigest, _ := storeImage(t, upStore, "team/app", "1.0", "private layer")

	proxy, proxyStore := newRegistry(t, func(c *config.Config) {
		c.Proxies = []config.ProxyEnv{
			{Name: "hub", URL: up.URL},
			{Name: "priv", URL: up.URL, Username: "bot", Password: "upstream-pw"},
			{Name: "badcreds", URL: up.URL, Username: "bot", Password: "wrong"},
		}
		c.ProxyTTL = 50 * time.Millisecond
	})

	// A miss is fetched from the upstream, then served from the cache.
	code, body, hdr := get(t, proxy.URL+"/v2/hub/library/alpine/manifests/3.20")
	if code != 200 || hdr.Get("Docker-Content-Digest") != mDigest {
		t.Fatalf("manifest through the cache: %d %s %s", code, hdr.Get("Docker-Content-Digest"), body)
	}
	code, body, _ = get(t, proxy.URL+"/v2/hub/library/alpine/blobs/"+lDigest)
	if code != 200 || string(body) != "alpine layer v1" {
		t.Fatalf("blob through the cache: %d %q", code, body)
	}
	if _, err := proxyStore.StatBlob(storage.Digest(lDigest)); err != nil {
		t.Error("blob was not cached")
	}

	// Credentials for private upstream repositories; wrong ones fail.
	if code, _, hdr = get(t, proxy.URL+"/v2/priv/team/app/manifests/1.0"); code != 200 || hdr.Get("Docker-Content-Digest") != privDigest {
		t.Errorf("private upstream image: %d", code)
	}
	if code, _, _ = get(t, proxy.URL+"/v2/badcreds/team/app/manifests/1.0"); code == 200 {
		t.Error("wrong upstream credentials worked")
	}
	if code, _, _ = get(t, proxy.URL+"/v2/hub/library/missing/manifests/1"); code != 404 {
		t.Errorf("image missing upstream: %d, want 404", code)
	}

	// A tag moved upstream is refreshed once the TTL has passed.
	m2, _ := storeImage(t, upStore, "library/alpine", "3.20", "alpine layer v2")
	time.Sleep(100 * time.Millisecond)
	if _, _, hdr = get(t, proxy.URL+"/v2/hub/library/alpine/manifests/3.20"); hdr.Get("Docker-Content-Digest") != m2 {
		t.Errorf("tag not refreshed: %s, want %s", hdr.Get("Docker-Content-Digest"), m2)
	}

	// The cache is read-only.
	resp := do(t, "POST", proxy.URL+"/v2/hub/library/alpine/blobs/uploads/", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("push into the cache: %d, want 403", resp.StatusCode)
	}

	// The upstream goes down: cached images are still served.
	up.Close()
	time.Sleep(100 * time.Millisecond)
	if code, _, hdr = get(t, proxy.URL+"/v2/hub/library/alpine/manifests/3.20"); code != 200 || hdr.Get("Docker-Content-Digest") != m2 {
		t.Errorf("cached manifest with the upstream down: %d", code)
	}
	if code, body, _ = get(t, proxy.URL+"/v2/hub/library/alpine/blobs/"+lDigest); code != 200 || string(body) != "alpine layer v1" {
		t.Errorf("cached blob with the upstream down: %d", code)
	}
	if code, _, _ = get(t, proxy.URL+"/v2/hub/library/other/manifests/1"); code != http.StatusBadGateway {
		t.Errorf("uncached image with the upstream down: %d, want 502", code)
	}
}
