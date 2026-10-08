// Integration tests for the web admin API.
package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func postJSON(t *testing.T, url, body string, headers map[string]string) *http.Response {
	t.Helper()
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return do(t, "POST", url, []byte(body), h)
}

func TestUIDeleteTagsImageRepo(t *testing.T) {
	srv, _ := newTestServer(t)
	pushImage(t, srv.URL, "app", "a", "amd64")
	pushImage(t, srv.URL, "app", "b", "arm64")
	// c points to the same image as b.
	mf := do(t, "GET", srv.URL+"/v2/app/manifests/b", nil, nil)
	var raw json.RawMessage
	json.NewDecoder(mf.Body).Decode(&raw)
	mf.Body.Close()
	bDigest := pushManifest(t, srv.URL, "app", "c", mf.Header.Get("Content-Type"), raw)
	pushImage(t, srv.URL, "other", "x", "amd64")

	// Bulk tag delete: one existing, one missing.
	r := postJSON(t, srv.URL+"/ui/api/tags/delete", `{"repo":"app","tags":["a","nope"]}`, nil)
	var res struct {
		Results []struct{ Tag, Error string } `json:"results"`
	}
	json.NewDecoder(r.Body).Decode(&res)
	r.Body.Close()
	if len(res.Results) != 2 || res.Results[0].Error != "" || res.Results[1].Error == "" {
		t.Errorf("bulk delete results: %+v", res.Results)
	}
	if code := status(t, "GET", srv.URL+"/v2/app/manifests/a", nil); code != http.StatusNotFound {
		t.Errorf("deleted tag a: got %d want 404", code)
	}

	// Image delete removes b and c.
	r = postJSON(t, srv.URL+"/ui/api/images/delete", `{"repo":"app","digest":"`+bDigest+`"}`, nil)
	var img struct {
		Removed []string `json:"removed_tags"`
	}
	json.NewDecoder(r.Body).Decode(&img)
	r.Body.Close()
	if len(img.Removed) != 2 {
		t.Errorf("image delete removed tags: got %v want [b c]", img.Removed)
	}

	// Repository delete.
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"other"}`, nil); r.StatusCode != http.StatusNoContent {
		t.Errorf("repo delete: got %d want 204", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"other"}`, nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("repo delete again: got %d want 404", r.StatusCode)
	}
	if repos := getRepos(t, srv.URL, nil); len(repos.Repositories) != 0 {
		t.Errorf("repositories left: %+v", repos.Repositories)
	}
}

func TestUIDeleteRequiresDeleteRight(t *testing.T) {
	srv := newAuthTestServer(t) // alice admin, bob regular
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"x"}`, bob); r.StatusCode != http.StatusForbidden {
		t.Errorf("bob repo delete: got %d want 403", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/tags/delete", `{"repo":"x","tags":["a"]}`, bob); r.StatusCode != http.StatusForbidden {
		t.Errorf("bob tag delete: got %d want 403", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"x"}`, alice); r.StatusCode != http.StatusNotFound {
		t.Errorf("alice repo delete (missing repo): got %d want 404", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"x"}`, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous repo delete: got %d want 401", r.StatusCode)
	}
}
