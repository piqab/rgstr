// Integration tests that exercise the full HTTP registry surface.
// Run with: go test -v -run TestIntegration ./...
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/registry"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*httptest.Server, *storage.Filesystem) {
	t.Helper()
	cfg := &config.Config{
		AuthEnabled: false,
		AuthSecret:  "test-secret",
		AuthRealm:   "http://localhost/v2/auth",
		AuthService: "test",
		AuthIssuer:  "test",
		TokenTTL:    time.Hour,
		GCInterval:  time.Hour,
		UploadTTL:   24 * time.Hour,
		Users:       map[string]string{},
		StorageRoot: t.TempDir(),
	}
	store, err := storage.NewFilesystem(cfg.StorageRoot, cfg)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	tokenSvc := auth.NewTokenService(cfg)
	counter := stats.New(cfg.StorageRoot)
	reg := registry.New(store, tokenSvc, cfg, counter)

	mux := http.NewServeMux()
	reg.Mount(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

func digest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// doJSON performs an HTTP request and returns the response.
func do(t *testing.T, method, url string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	var rb io.Reader
	if body != nil {
		rb = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rb)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestIntegrationV2Base(t *testing.T) {
	srv, _ := newTestServer(t)

	resp := do(t, "GET", srv.URL+"/v2/", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v2/: got %d want 200", resp.StatusCode)
	}
	if v := resp.Header.Get("Docker-Distribution-API-Version"); v != "registry/2.0" {
		t.Errorf("API version header: got %q want registry/2.0", v)
	}
}

func TestIntegrationBlobPushPull(t *testing.T) {
	srv, _ := newTestServer(t)
	repo := "testns/myimage"
	data := []byte("layer content for testing")
	dgst := digest(data)

	// POST — start upload
	resp := do(t, "POST", fmt.Sprintf("%s/v2/%s/blobs/uploads/", srv.URL, repo), nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST start upload: got %d want 202", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("no Location header")
	}
	// Location may be relative; make it absolute.
	if !strings.HasPrefix(loc, "http") {
		loc = srv.URL + loc
	}

	// PATCH — send the full blob as one chunk
	resp = do(t, "PATCH", loc, data, map[string]string{
		"Content-Type":   "application/octet-stream",
		"Content-Range":  fmt.Sprintf("0-%d", len(data)-1),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("PATCH chunk: got %d want 202", resp.StatusCode)
	}

	// PUT — complete the upload
	putURL := loc + "?digest=" + dgst
	resp = do(t, "PUT", putURL, nil, map[string]string{"Content-Length": "0"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT complete: got %d want 201", resp.StatusCode)
	}

	// HEAD — verify blob exists
	resp = do(t, "HEAD", fmt.Sprintf("%s/v2/%s/blobs/%s", srv.URL, repo, dgst), nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD blob: got %d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != dgst {
		t.Errorf("Docker-Content-Digest: got %q want %q", got, dgst)
	}

	// GET — download the blob
	resp = do(t, "GET", fmt.Sprintf("%s/v2/%s/blobs/%s", srv.URL, repo, dgst), nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET blob: got %d want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, data) {
		t.Errorf("blob content mismatch")
	}
}

func TestIntegrationManifestPushPull(t *testing.T) {
	srv, _ := newTestServer(t)
	repo := "library/busybox"

	manifest := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": {"mediaType":"application/vnd.docker.container.image.v1+json","size":0,"digest":"sha256:` + hex.EncodeToString(make([]byte, 32)) + `"},
		"layers": []
	}`)
	ct := "application/vnd.docker.distribution.manifest.v2+json"

	// PUT manifest by tag
	resp := do(t, "PUT", fmt.Sprintf("%s/v2/%s/manifests/latest", srv.URL, repo),
		manifest, map[string]string{"Content-Type": ct})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT manifest: got %d want 201", resp.StatusCode)
	}
	dgst := resp.Header.Get("Docker-Content-Digest")
	if dgst == "" {
		t.Fatal("no Docker-Content-Digest in PUT response")
	}

	// GET by tag
	resp = do(t, "GET", fmt.Sprintf("%s/v2/%s/manifests/latest", srv.URL, repo),
		nil, map[string]string{"Accept": ct})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET manifest by tag: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(manifest)) {
		t.Errorf("manifest content mismatch")
	}

	// GET by digest
	resp2 := do(t, "GET", fmt.Sprintf("%s/v2/%s/manifests/%s", srv.URL, repo, dgst),
		nil, nil)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET manifest by digest: got %d want 200", resp2.StatusCode)
	}
}

func TestIntegrationTagsList(t *testing.T) {
	srv, _ := newTestServer(t)
	repo := "myns/myrepo"
	manifest := []byte(`{"schemaVersion":2}`)

	for _, tag := range []string{"v1", "v2", "latest"} {
		resp := do(t, "PUT", fmt.Sprintf("%s/v2/%s/manifests/%s", srv.URL, repo, tag),
			manifest, map[string]string{"Content-Type": "application/json"})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT manifest %s: %d", tag, resp.StatusCode)
		}
	}

	resp := do(t, "GET", fmt.Sprintf("%s/v2/%s/tags/list", srv.URL, repo), nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET tags list: %d", resp.StatusCode)
	}

	var result struct {
		Tags []string `json:"tags"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Tags) != 3 {
		t.Errorf("expected 3 tags, got %d: %v", len(result.Tags), result.Tags)
	}
}

func TestIntegrationCrossRepoMount(t *testing.T) {
	srv, _ := newTestServer(t)
	data := []byte("shared layer")
	dgst := digest(data)

	// First, push the blob to repo A.
	startResp := do(t, "POST", fmt.Sprintf("%s/v2/repoA/blobs/uploads/", srv.URL), nil, nil)
	startResp.Body.Close()
	loc := startResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http") {
		loc = srv.URL + loc
	}
	patchResp := do(t, "PATCH", loc, data, map[string]string{"Content-Type": "application/octet-stream"})
	patchResp.Body.Close()
	putResp := do(t, "PUT", loc+"?digest="+dgst, nil, nil)
	putResp.Body.Close()

	// Now mount from repoA to repoB — should return 201 with no data transfer.
	mountURL := fmt.Sprintf("%s/v2/repoB/blobs/uploads/?mount=%s&from=repoA", srv.URL, dgst)
	resp := do(t, "POST", mountURL, nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("cross-repo mount: got %d want 201", resp.StatusCode)
	}
}

func TestIntegrationMonolithicUpload(t *testing.T) {
	// Single-step: POST + PUT with full body (no PATCH)
	srv, _ := newTestServer(t)
	data := []byte("monolithic blob content")
	dgst := digest(data)
	repo := "mono/test"

	startResp := do(t, "POST", fmt.Sprintf("%s/v2/%s/blobs/uploads/", srv.URL, repo), nil, nil)
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST: %d", startResp.StatusCode)
	}
	loc := startResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http") {
		loc = srv.URL + loc
	}

	// PUT with body + digest query param
	putResp := do(t, "PUT", loc+"?digest="+dgst, data, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT monolithic: got %d want 201", putResp.StatusCode)
	}

	// Verify
	head := do(t, "HEAD", fmt.Sprintf("%s/v2/%s/blobs/%s", srv.URL, repo, dgst), nil, nil)
	head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Errorf("HEAD after monolithic: %d", head.StatusCode)
	}
}

func TestIntegrationCatalog(t *testing.T) {
	srv, _ := newTestServer(t)
	manifest := []byte(`{"schemaVersion":2}`)

	for _, repo := range []string{"ns1/repoA", "ns1/repoB", "ns2/repoC"} {
		resp := do(t, "PUT", fmt.Sprintf("%s/v2/%s/manifests/latest", srv.URL, repo),
			manifest, map[string]string{"Content-Type": "application/json"})
		resp.Body.Close()
	}

	resp := do(t, "GET", srv.URL+"/v2/_catalog", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET catalog: %d", resp.StatusCode)
	}
	var result struct {
		Repositories []string `json:"repositories"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Repositories) < 3 {
		t.Errorf("expected ≥3 repos, got %d: %v", len(result.Repositories), result.Repositories)
	}
}

func TestIntegrationBlobRangeRequest(t *testing.T) {
	srv, _ := newTestServer(t)
	data := []byte("0123456789abcdef") // 16 bytes
	dgst := digest(data)
	repo := "range/test"

	// Push the blob
	startResp := do(t, "POST", fmt.Sprintf("%s/v2/%s/blobs/uploads/", srv.URL, repo), nil, nil)
	startResp.Body.Close()
	loc := startResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http") {
		loc = srv.URL + loc
	}
	patchResp := do(t, "PATCH", loc, data, map[string]string{"Content-Type": "application/octet-stream"})
	patchResp.Body.Close()
	putResp := do(t, "PUT", loc+"?digest="+dgst, nil, nil)
	putResp.Body.Close()

	// Request bytes 4-7 (inclusive)
	blobURL := fmt.Sprintf("%s/v2/%s/blobs/%s", srv.URL, repo, dgst)
	req, _ := http.NewRequest("GET", blobURL, nil)
	req.Header.Set("Range", "bytes=4-7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("range request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("range GET: got %d want 206", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "4567" {
		t.Errorf("range content: got %q want %q", string(got), "4567")
	}
}
