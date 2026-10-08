// Integration tests for the web UI API (/ui/api/*).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/registry"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

// newAuthTestServer starts a registry with auth enabled, users alice (admin)
// and bob (regular), both with password "secret", and the given public repos.
func newAuthTestServer(t *testing.T, publicRepos ...string) *httptest.Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.Config{
		AuthEnabled: true,
		AuthSecret:  "test-secret",
		AuthRealm:   "http://localhost/v2/auth",
		AuthService: "test",
		AuthIssuer:  "test",
		TokenTTL:    time.Hour,
		GCInterval:  time.Hour,
		UploadTTL:   24 * time.Hour,
		Users:       map[string]string{"alice": string(hash), "bob": string(hash)},
		Admins:      []string{"alice"},
		PublicRepos: publicRepos,
		StorageRoot: t.TempDir(),
	}
	store, err := storage.NewFilesystem(cfg.StorageRoot, cfg)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	reg := registry.New(store, auth.NewTokenService(cfg), cfg, stats.New(cfg.StorageRoot))
	mux := http.NewServeMux()
	reg.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func pushBlob(t *testing.T, srvURL, repo string, data []byte) string {
	t.Helper()
	dgst := digest(data)
	start := do(t, "POST", fmt.Sprintf("%s/v2/%s/blobs/uploads/", srvURL, repo), nil, nil)
	start.Body.Close()
	put := do(t, "PUT", srvURL+start.Header.Get("Location")+"?digest="+dgst, data, nil)
	put.Body.Close()
	if put.StatusCode != http.StatusCreated {
		t.Fatalf("push blob: got %d", put.StatusCode)
	}
	return dgst
}

func pushManifest(t *testing.T, srvURL, repo, ref, mediaType string, body []byte) string {
	t.Helper()
	resp := do(t, "PUT", fmt.Sprintf("%s/v2/%s/manifests/%s", srvURL, repo, ref), body,
		map[string]string{"Content-Type": mediaType})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push manifest %s:%s: got %d", repo, ref, resp.StatusCode)
	}
	return resp.Header.Get("Docker-Content-Digest")
}

// pushImage uploads a one-layer image for os/arch and returns the manifest
// digest and the total size of config + layer.
func pushImage(t *testing.T, srvURL, repo, ref, arch string) (string, int64) {
	t.Helper()
	config := []byte(`{"os":"linux","architecture":"` + arch + `"}`)
	layer := []byte("layer for " + arch)
	cfgDigest := pushBlob(t, srvURL, repo, config)
	layerDigest := pushBlob(t, srvURL, repo, layer)
	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},`+
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}`,
		cfgDigest, len(config), layerDigest, len(layer))
	d := pushManifest(t, srvURL, repo, ref, "application/vnd.oci.image.manifest.v1+json", []byte(manifest))
	return d, int64(len(config) + len(layer))
}

type uiRepos struct {
	Repositories []struct {
		Name string `json:"name"`
		Tags []struct {
			Name      string `json:"name"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			Platforms []struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Size         int64  `json:"size"`
			} `json:"platforms"`
		} `json:"tags"`
	} `json:"repositories"`
}

func getRepos(t *testing.T, srvURL string, headers map[string]string) uiRepos {
	t.Helper()
	resp := do(t, "GET", srvURL+"/ui/api/repos", nil, headers)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/api/repos: got %d", resp.StatusCode)
	}
	var out uiRepos
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestUIReposSingleAndMultiPlatform(t *testing.T) {
	srv, _ := newTestServer(t)

	_, singleSize := pushImage(t, srv.URL, "app", "single", "amd64")

	amdDigest, amdSize := pushImage(t, srv.URL, "app", "amd64-only", "amd64")
	armDigest, armSize := pushImage(t, srv.URL, "app", "arm64-only", "arm64")
	index := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[`+
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"linux","architecture":"amd64"}},`+
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"linux","architecture":"arm64"}},`+
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"unknown","architecture":"unknown"}}]}`,
		amdDigest, armDigest, amdDigest)
	pushManifest(t, srv.URL, "app", "multi", "application/vnd.oci.image.index.v1+json", []byte(index))

	repos := getRepos(t, srv.URL, nil)
	if len(repos.Repositories) != 1 {
		t.Fatalf("repositories: got %d want 1", len(repos.Repositories))
	}
	tags := map[string]int{}
	for i, tg := range repos.Repositories[0].Tags {
		tags[tg.Name] = i
	}
	all := repos.Repositories[0].Tags

	single := all[tags["single"]]
	if single.Size != singleSize || len(single.Platforms) != 1 || single.Platforms[0].Architecture != "amd64" {
		t.Errorf("single: got size %d platforms %+v, want %d linux/amd64", single.Size, single.Platforms, singleSize)
	}

	multi := all[tags["multi"]]
	if multi.Size != amdSize+armSize {
		t.Errorf("multi size: got %d want %d", multi.Size, amdSize+armSize)
	}
	if len(multi.Platforms) != 2 || multi.Platforms[0].Architecture != "amd64" || multi.Platforms[1].Architecture != "arm64" {
		t.Errorf("multi platforms: got %+v want amd64, arm64 (attestation skipped)", multi.Platforms)
	}
	if multi.Platforms[1].Size != armSize {
		t.Errorf("arm64 size: got %d want %d", multi.Platforms[1].Size, armSize)
	}
}

func TestDeleteTagKeepsOtherTags(t *testing.T) {
	srv, _ := newTestServer(t)
	pushImage(t, srv.URL, "app", "latest", "amd64")
	// Tag the same manifest as 1.0 by re-pushing identical content.
	mf := do(t, "GET", srv.URL+"/v2/app/manifests/latest", nil, nil)
	body, _ := io.ReadAll(mf.Body)
	mf.Body.Close()
	pushManifest(t, srv.URL, "app", "1.0", mf.Header.Get("Content-Type"), body)

	del := do(t, "DELETE", srv.URL+"/v2/app/manifests/latest", nil, nil)
	del.Body.Close()
	if del.StatusCode != http.StatusAccepted {
		t.Fatalf("DELETE tag: got %d want 202", del.StatusCode)
	}

	gone := do(t, "GET", srv.URL+"/v2/app/manifests/latest", nil, nil)
	gone.Body.Close()
	if gone.StatusCode != http.StatusNotFound {
		t.Errorf("deleted tag: got %d want 404", gone.StatusCode)
	}
	kept := do(t, "GET", srv.URL+"/v2/app/manifests/1.0", nil, nil)
	kept.Body.Close()
	if kept.StatusCode != http.StatusOK {
		t.Errorf("sibling tag after delete: got %d want 200", kept.StatusCode)
	}
}

func TestUIMeAuthDisabled(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := do(t, "GET", srv.URL+"/ui/api/me", nil, nil)
	defer resp.Body.Close()
	var me struct {
		AuthEnabled bool     `json:"auth_enabled"`
		Actions     []string `json:"actions"`
	}
	json.NewDecoder(resp.Body).Decode(&me)
	if me.AuthEnabled || len(me.Actions) != 3 {
		t.Errorf("me with auth disabled: got %+v", me)
	}
}

func TestUILoginFlow(t *testing.T) {
	srv := newAuthTestServer(t)

	// Anonymous: auth on, no user, repos refused.
	resp := do(t, "GET", srv.URL+"/ui/api/me", nil, nil)
	var me struct {
		AuthEnabled bool     `json:"auth_enabled"`
		User        string   `json:"user"`
		Actions     []string `json:"actions"`
	}
	json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if !me.AuthEnabled || me.User != "" {
		t.Errorf("anonymous me: got %+v", me)
	}
	if r := do(t, "GET", srv.URL+"/ui/api/repos", nil, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous repos: got %d want 401", r.StatusCode)
	}

	login := func(user, pass string) (int, string) {
		r := do(t, "POST", srv.URL+"/ui/api/login",
			[]byte(`{"username":"`+user+`","password":"`+pass+`"}`),
			map[string]string{"Content-Type": "application/json"})
		defer r.Body.Close()
		var s struct {
			Token string `json:"token"`
		}
		json.NewDecoder(r.Body).Decode(&s)
		return r.StatusCode, s.Token
	}

	if code, _ := login("bob", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong password: got %d want 401", code)
	}
	code, tok := login("bob", "secret")
	if code != http.StatusOK || tok == "" {
		t.Fatalf("login: got %d token %q", code, tok)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok}

	resp = do(t, "GET", srv.URL+"/ui/api/me", nil, bearer)
	json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if me.User != "bob" || strings.Join(me.Actions, ",") != "pull,push" {
		t.Errorf("bob me: got %+v want user bob, actions pull,push", me)
	}
	getRepos(t, srv.URL, bearer)

	// bob is not an admin: deleting is forbidden even with his session token.
	if r := do(t, "DELETE", srv.URL+"/v2/app/manifests/latest", nil, bearer); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("non-admin delete: got %d want 401", r.StatusCode)
	}
}
