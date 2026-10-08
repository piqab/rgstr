// Integration tests for the web admin API.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
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

func TestUIGarbageCollection(t *testing.T) {
	srv := newAuthTestServer(t)
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}

	if code := status(t, "GET", srv.URL+"/ui/api/gc", bob); code != http.StatusForbidden {
		t.Errorf("non-admin GC status: got %d want 403", code)
	}
	r := postJSON(t, srv.URL+"/ui/api/gc/run", `{"dry_run":true}`, alice)
	var run struct {
		DryRun bool   `json:"dry_run"`
		User   string `json:"user"`
	}
	json.NewDecoder(r.Body).Decode(&run)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || !run.DryRun || run.User != "alice" {
		t.Errorf("dry run: got %d %+v", r.StatusCode, run)
	}

	r = postJSON(t, srv.URL+"/ui/api/gc/settings", `{"interval":"6h"}`, alice)
	var st struct {
		Interval string            `json:"interval"`
		FromUI   bool              `json:"from_ui"`
		History  []json.RawMessage `json:"history"`
	}
	json.NewDecoder(r.Body).Decode(&st)
	r.Body.Close()
	if st.Interval != "6h0m0s" || !st.FromUI || len(st.History) != 1 {
		t.Errorf("settings: %+v", st)
	}
	if r := postJSON(t, srv.URL+"/ui/api/gc/settings", `{"interval":"often"}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad interval: got %d want 400", r.StatusCode)
	}
}

func TestImmutableTags(t *testing.T) {
	srv, _ := newTestServer(t)
	pushImage(t, srv.URL, "app", "v1", "amd64")
	if r := postJSON(t, srv.URL+"/ui/api/policies/immutable", `{"rules":[{"repos":"app","tags":"v*"}]}`, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("save rule: %d", r.StatusCode)
	}

	// Re-pushing the same image is fine; another image under v1 is refused.
	mf := do(t, "GET", srv.URL+"/v2/app/manifests/v1", nil, nil)
	var raw json.RawMessage
	json.NewDecoder(mf.Body).Decode(&raw)
	mf.Body.Close()
	pushManifest(t, srv.URL, "app", "v1", mf.Header.Get("Content-Type"), raw)

	other := `{"schemaVersion":2,"layers":[]}`
	resp := do(t, "PUT", srv.URL+"/v2/app/manifests/v1", []byte(other), map[string]string{"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("overwrite immutable tag: got %d want 403", resp.StatusCode)
	}
	// A new tag matching the rule can still be pushed once.
	pushManifest(t, srv.URL, "app", "v2", "application/vnd.oci.image.manifest.v1+json", []byte(other))

	if code := status(t, "DELETE", srv.URL+"/v2/app/manifests/v1", nil); code != http.StatusForbidden {
		t.Errorf("docker API delete immutable: got %d want 403", code)
	}
	r := postJSON(t, srv.URL+"/ui/api/tags/delete", `{"repo":"app","tags":["v1"]}`, nil)
	var res struct {
		Results []struct{ Error string } `json:"results"`
	}
	json.NewDecoder(r.Body).Decode(&res)
	r.Body.Close()
	if len(res.Results) != 1 || res.Results[0].Error == "" {
		t.Errorf("UI delete immutable tag: %+v", res.Results)
	}
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"app"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("delete repo with immutable tags: got %d want 403", r.StatusCode)
	}
}

func TestRetentionRun(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, tag := range []string{"a", "b", "c"} {
		pushImage(t, srv.URL, "app", tag, tag)
	}
	if r := postJSON(t, srv.URL+"/ui/api/policies/retention", `{"rules":[{"repos":"**","tags":"*"}]}`, nil); r.StatusCode != http.StatusBadRequest {
		t.Errorf("rule without keep: got %d want 400", r.StatusCode)
	}
	postJSON(t, srv.URL+"/ui/api/policies/retention", `{"rules":[{"repos":"**","tags":"*","keep_last":1}]}`, nil).Body.Close()

	run := func(dry bool) (n int) {
		body := `{"dry_run":false}`
		if dry {
			body = `{"dry_run":true}`
		}
		r := postJSON(t, srv.URL+"/ui/api/policies/retention/run", body, nil)
		var res struct {
			Count int `json:"tags_count"`
		}
		json.NewDecoder(r.Body).Decode(&res)
		r.Body.Close()
		return res.Count
	}
	if n := run(true); n != 2 {
		t.Errorf("dry run: %d tags, want 2", n)
	}
	if len(getRepos(t, srv.URL, nil).Repositories[0].Tags) != 3 {
		t.Error("dry run deleted tags")
	}
	if n := run(false); n != 2 {
		t.Errorf("run: %d tags, want 2", n)
	}
	if tags := getRepos(t, srv.URL, nil).Repositories[0].Tags; len(tags) != 1 {
		t.Errorf("after run: %d tags, want 1", len(tags))
	}
}

func TestUIUserManagement(t *testing.T) {
	srv := newAuthTestServer(t)
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}

	if code := status(t, "GET", srv.URL+"/ui/api/users", bob); code != http.StatusForbidden {
		t.Errorf("non-admin list: got %d want 403", code)
	}
	if r := postJSON(t, srv.URL+"/ui/api/users/create", `{"name":"carol","role":"readonly","password":"carol-pass","must_change":false}`, alice); r.StatusCode != http.StatusNoContent {
		t.Fatalf("create: got %d", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/users/create", `{"name":"carol","role":"user","password":"carol-pass"}`, alice); r.StatusCode != http.StatusConflict {
		t.Errorf("duplicate: got %d want 409", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/users/delete", `{"name":"alice"}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("delete self: got %d want 400", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/users/role", `{"name":"bob","role":"admin"}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("env user role: got %d want 400", r.StatusCode)
	}

	resp := do(t, "GET", srv.URL+"/ui/api/users", nil, alice)
	var list struct {
		Users []struct {
			Name, Source, Role string
		} `json:"users"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	got := map[string]string{}
	for _, u := range list.Users {
		got[u.Name] = u.Source + "/" + u.Role
	}
	want := map[string]string{"admin": "bootstrap/admin", "alice": "env/admin", "bob": "env/user", "carol": "admin/readonly"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("user %s: got %q want %q", k, got[k], v)
		}
	}

	// carol can pull via docker but not push.
	carol := map[string]string{"Authorization": "Basic Y2Fyb2w6Y2Fyb2wtcGFzcw=="} // carol:carol-pass
	if code := status(t, "GET", srv.URL+"/v2/_catalog", carol); code != http.StatusOK {
		t.Errorf("carol catalog: got %d", code)
	}
	if code := status(t, "POST", srv.URL+"/v2/x/blobs/uploads/", carol); code != http.StatusForbidden {
		t.Errorf("carol push: got %d want 403", code)
	}
}

func TestAuditLog(t *testing.T) {
	srv := newAuthTestServer(t)
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}

	start := do(t, "POST", srv.URL+"/v2/app/blobs/uploads/", nil, alice)
	start.Body.Close()
	m := []byte(`{"schemaVersion":2,"layers":[]}`)
	put := do(t, "PUT", srv.URL+"/v2/app/manifests/v1", m, map[string]string{
		"Authorization": alice["Authorization"], "Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	put.Body.Close()
	status(t, "GET", srv.URL+"/v2/app/manifests/v1", bob)
	status(t, "DELETE", srv.URL+"/v2/app/manifests/v1", alice)
	// failed docker login and failed UI login
	bad := do(t, "GET", srv.URL+"/v2/auth?service=test", nil, map[string]string{"Authorization": "Basic Ym9iOndyb25n"}) // bob:wrong
	bad.Body.Close()
	postJSON(t, srv.URL+"/ui/api/login", `{"username":"mallory","password":"x"}`, nil).Body.Close()

	if code := status(t, "GET", srv.URL+"/ui/api/audit", bob); code != http.StatusForbidden {
		t.Errorf("non-admin audit: got %d want 403", code)
	}
	resp := do(t, "GET", srv.URL+"/ui/api/audit", nil, alice)
	var res struct {
		Entries []struct {
			User, Action, Resource, Detail string
		} `json:"entries"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.User+" "+e.Action+" "+e.Resource+" "+e.Detail)
	}
	want := []string{
		"mallory login_failed  web admin",
		"bob login_failed  docker",
		"alice delete_tag app:v1 ",
		"bob pull app:v1 sha256:",
		"alice push app:v1 sha256:",
	}
	if len(got) != len(want) {
		t.Fatalf("entries:\n%s", strings.Join(got, "\n"))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("entry %d: got %q want prefix %q", i, got[i], want[i])
		}
	}
}
