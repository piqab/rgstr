// Integration tests for the web admin API.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"rgstr/internal/storage"
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
	if r := postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"other"}`, nil); r.StatusCode != http.StatusOK {
		t.Errorf("repo delete: got %d want 200", r.StatusCode)
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

func TestUIImageDetails(t *testing.T) {
	srv, _ := newTestServer(t)
	config := []byte(`{"os":"linux","architecture":"amd64","created":"2026-01-02T03:04:05Z",
		"config":{"Env":["PATH=/bin"],"Cmd":["/app"],"ExposedPorts":{"8080/tcp":{}},"Labels":{"team":"core"}},
		"history":[{"created_by":"/bin/sh -c #(nop) ADD file:abc in / "},{"created_by":"/bin/sh -c #(nop)  ENV PATH=/bin","empty_layer":true},
		{"created_by":"/bin/sh -c apk add curl"}]}`)
	l1, l2 := []byte("layer one"), []byte("layer two!")
	cd, d1, d2 := pushBlob(t, srv.URL, "app", config), pushBlob(t, srv.URL, "app", l1), pushBlob(t, srv.URL, "app", l2)
	m := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
		"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},
		"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d},
		{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}`,
		cd, len(config), d1, len(l1), d2, len(l2))
	digest := pushManifest(t, srv.URL, "app", "1.0", "application/vnd.oci.image.manifest.v1+json", []byte(m))

	resp := do(t, "GET", srv.URL+"/ui/api/image?repo=app&ref=1.0", nil, nil)
	var img struct {
		Digest string   `json:"digest"`
		Tags   []string `json:"tags"`
		Image  struct {
			Env    []string `json:"env"`
			Cmd    []string `json:"cmd"`
			Ports  []string `json:"exposed_ports"`
			Labels map[string]string
			Layers []struct {
				CreatedBy string `json:"created_by"`
				Digest    string `json:"digest"`
				Size      int64  `json:"size"`
				Empty     bool   `json:"empty"`
			} `json:"layers"`
		} `json:"image"`
	}
	json.NewDecoder(resp.Body).Decode(&img)
	resp.Body.Close()
	if img.Digest != digest || len(img.Tags) != 1 {
		t.Errorf("digest/tags: %+v", img)
	}
	if len(img.Image.Env) != 1 || img.Image.Cmd[0] != "/app" || img.Image.Ports[0] != "8080/tcp" || img.Image.Labels["team"] != "core" {
		t.Errorf("config: %+v", img.Image)
	}
	ls := img.Image.Layers
	if len(ls) != 3 || ls[0].Digest != d1 || !ls[1].Empty || ls[2].Digest != d2 || ls[2].CreatedBy != "apk add curl" || ls[2].Size != int64(len(l2)) {
		t.Errorf("layers: %+v", ls)
	}

	// Index: platforms listed, attestation skipped.
	idx := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
		{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"linux","architecture":"amd64"}},
		{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"os":"unknown","architecture":"unknown"}}]}`, digest, digest)
	pushManifest(t, srv.URL, "app", "multi", "application/vnd.oci.image.index.v1+json", []byte(idx))
	resp = do(t, "GET", srv.URL+"/ui/api/image?repo=app&ref=multi", nil, nil)
	var ix struct {
		Platforms []struct{ Digest string } `json:"platforms"`
		Image     *struct{}                  `json:"image"`
	}
	json.NewDecoder(resp.Body).Decode(&ix)
	resp.Body.Close()
	if len(ix.Platforms) != 1 || ix.Platforms[0].Digest != digest || ix.Image != nil {
		t.Errorf("index: %+v", ix)
	}

	if code := status(t, "GET", srv.URL+"/ui/api/image?repo=app&ref=nope", nil); code != http.StatusNotFound {
		t.Errorf("missing tag: got %d want 404", code)
	}
}

func TestUIImageRequiresPull(t *testing.T) {
	srv := newAuthTestServer(t)
	if code := status(t, "GET", srv.URL+"/ui/api/image?repo=app&ref=1", nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous: got %d want 401", code)
	}
}

func TestUIProjects(t *testing.T) {
	srv := newAuthTestServer(t) // alice admin, bob user
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}

	if r := postJSON(t, srv.URL+"/ui/api/projects/create", `{"name":"team"}`, bob); r.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin create: got %d want 403", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/projects/create", `{"name":"Bad Name"}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad name: got %d want 400", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/projects/create", `{"name":"team"}`, alice); r.StatusCode != http.StatusNoContent {
		t.Fatalf("create: got %d", r.StatusCode)
	}

	// alice pushes into the project; bob (no member) cannot see or push.
	m := []byte(`{"schemaVersion":2,"layers":[]}`)
	ct := "application/vnd.oci.image.manifest.v1+json"
	put := func(auth map[string]string) int {
		h := map[string]string{"Content-Type": ct}
		for k, v := range auth {
			h[k] = v
		}
		r := do(t, "PUT", srv.URL+"/v2/team/app/manifests/1", m, h)
		r.Body.Close()
		return r.StatusCode
	}
	if code := put(alice); code != http.StatusCreated {
		t.Fatalf("admin push: %d", code)
	}
	if code := put(bob); code != http.StatusForbidden {
		t.Errorf("non-member push: got %d want 403", code)
	}
	catalog := func(auth map[string]string) string {
		r := do(t, "GET", srv.URL+"/v2/_catalog", nil, auth)
		var c struct{ Repositories []string }
		json.NewDecoder(r.Body).Decode(&c)
		r.Body.Close()
		return strings.Join(c.Repositories, ",")
	}
	if got := catalog(bob); got != "" {
		t.Errorf("non-member catalog: %q", got)
	}

	// Make bob a developer: he sees and can push, not delete.
	if r := postJSON(t, srv.URL+"/ui/api/projects/member", `{"name":"team","user":"bob","role":"developer"}`, alice); r.StatusCode != http.StatusNoContent {
		t.Fatalf("add member: %d", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/projects/member", `{"name":"team","user":"ghost","role":"guest"}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown user: got %d want 400", r.StatusCode)
	}
	if got := catalog(bob); got != "team/app" {
		t.Errorf("member catalog: %q", got)
	}
	if code := put(bob); code != http.StatusCreated {
		t.Errorf("developer push: got %d", code)
	}
	if code := status(t, "DELETE", srv.URL+"/v2/team/app/manifests/1", bob); code != http.StatusForbidden {
		t.Errorf("developer delete: got %d want 403", code)
	}
	// bob is not a project admin: cannot manage members.
	if r := postJSON(t, srv.URL+"/ui/api/projects/member", `{"name":"team","user":"bob","role":"admin"}`, bob); r.StatusCode != http.StatusForbidden {
		t.Errorf("developer manages members: got %d want 403", r.StatusCode)
	}

	// Public project: anonymous pull.
	postJSON(t, srv.URL+"/ui/api/projects/update", `{"name":"team","public":true}`, alice).Body.Close()
	if code := status(t, "GET", srv.URL+"/v2/team/app/manifests/1", nil); code != http.StatusOK {
		t.Errorf("anonymous pull from public project: got %d", code)
	}

	// Deleting a project with repositories is refused.
	if r := postJSON(t, srv.URL+"/ui/api/projects/delete", `{"name":"team"}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("delete non-empty project: got %d want 400", r.StatusCode)
	}
	postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"team/app"}`, alice).Body.Close()
	if r := postJSON(t, srv.URL+"/ui/api/projects/delete", `{"name":"team"}`, alice); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete empty project: got %d", r.StatusCode)
	}
}

func TestUIRobots(t *testing.T) {
	srv := newAuthTestServer(t)
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}

	if r := postJSON(t, srv.URL+"/ui/api/robots/create", `{"name":"ci","permissions":[{"project":"*","actions":["pull"]}]}`, bob); r.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin create: got %d", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/robots/create", `{"name":"ci","permissions":[]}`, alice); r.StatusCode != http.StatusBadRequest {
		t.Errorf("no permissions: got %d", r.StatusCode)
	}
	create := func() (name, secret string) {
		r := postJSON(t, srv.URL+"/ui/api/robots/create", `{"name":"ci","permissions":[{"project":"*","actions":["pull","push"]}],"expires_days":30}`, alice)
		var res struct{ Name, Secret string }
		json.NewDecoder(r.Body).Decode(&res)
		r.Body.Close()
		return res.Name, res.Secret
	}
	name, secret := create()
	if name != "robot$ci" || len(secret) < 40 {
		t.Fatalf("create: %q %q", name, secret)
	}
	robot := func(secret string) map[string]string {
		req, _ := http.NewRequest("GET", "/", nil)
		req.SetBasicAuth(name, secret)
		return map[string]string{"Authorization": req.Header.Get("Authorization")}
	}
	if code := status(t, "POST", srv.URL+"/v2/x/blobs/uploads/", robot(secret)); code != http.StatusAccepted {
		t.Errorf("robot push: got %d want 202", code)
	}
	// Robots cannot use the admin API.
	if code := status(t, "GET", srv.URL+"/ui/api/repos", robot(secret)); code != http.StatusUnauthorized {
		t.Errorf("robot admin API: got %d want 401", code)
	}

	r := postJSON(t, srv.URL+"/ui/api/robots/secret", `{"name":"robot$ci"}`, alice)
	var res struct{ Secret string }
	json.NewDecoder(r.Body).Decode(&res)
	r.Body.Close()
	if code := status(t, "GET", srv.URL+"/v2/_catalog", robot(secret)); code != http.StatusUnauthorized {
		t.Errorf("old secret after regenerate: got %d want 401", code)
	}
	if code := status(t, "GET", srv.URL+"/v2/x/manifests/1", robot(res.Secret)); code == http.StatusUnauthorized {
		t.Errorf("new secret rejected")
	}

	postJSON(t, srv.URL+"/ui/api/robots/update", `{"name":"robot$ci","permissions":[{"project":"*","actions":["pull"]}],"disabled":true}`, alice).Body.Close()
	if code := status(t, "GET", srv.URL+"/v2/x/manifests/1", robot(res.Secret)); code != http.StatusUnauthorized {
		t.Errorf("disabled robot: got %d want 401", code)
	}
	if r := postJSON(t, srv.URL+"/ui/api/robots/delete", `{"name":"robot$ci"}`, alice); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete: got %d", r.StatusCode)
	}
}

func TestProjectQuota(t *testing.T) {
	srv, _ := newTestServer(t)
	// 20-byte quota.
	postJSON(t, srv.URL+"/ui/api/projects/create", `{"name":"team","quota_bytes":20}`, nil).Body.Close()

	small := pushBlob(t, srv.URL, "team/app", []byte("0123456789")) // 10 bytes
	big := pushBlob(t, srv.URL, "team/app", []byte("0123456789abcdef"))
	manifest := func(digest string, size int) []byte {
		return []byte(fmt.Sprintf(`{"schemaVersion":2,"layers":[{"digest":"%s","size":%d}]}`, digest, size))
	}
	put := func(tag string, body []byte) int {
		r := do(t, "PUT", srv.URL+"/v2/team/app/manifests/"+tag, body, map[string]string{"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
		r.Body.Close()
		return r.StatusCode
	}
	if code := put("a", manifest(small, 10)); code != http.StatusCreated {
		t.Fatalf("within quota: got %d", code)
	}
	if code := put("b", manifest(big, 16)); code != http.StatusForbidden {
		t.Errorf("over quota: got %d want 403", code)
	}
	// Re-tagging existing data adds nothing and passes.
	if code := put("c", manifest(small, 10)); code != http.StatusCreated {
		t.Errorf("re-tag: got %d want 201", code)
	}
	// Raising the quota lets the push through.
	postJSON(t, srv.URL+"/ui/api/projects/update", `{"name":"team","quota_bytes":100}`, nil).Body.Close()
	if code := put("b", manifest(big, 16)); code != http.StatusCreated {
		t.Errorf("after raising quota: got %d", code)
	}
	// Repositories outside projects are not limited.
	pushImage(t, srv.URL, "free", "x", "amd64")

	resp := do(t, "GET", srv.URL+"/ui/api/projects", nil, nil)
	var res struct {
		Projects []struct {
			Used int64 `json:"used_bytes"`
		} `json:"projects"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.Projects[0].Used != 26 {
		t.Errorf("usage: %d want 26", res.Projects[0].Used)
	}
}

func TestUIWebhooks(t *testing.T) {
	var mu sync.Mutex
	var events []string
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Type string }
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		events = append(events, b.Type)
		mu.Unlock()
	}))
	defer recv.Close()

	srv := newAuthTestServer(t)
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	bob := map[string]string{"Authorization": "Basic Ym9iOnNlY3JldA=="}
	postJSON(t, srv.URL+"/ui/api/projects/create", `{"name":"team"}`, alice).Body.Close()
	postJSON(t, srv.URL+"/ui/api/projects/member", `{"name":"team","user":"bob","role":"admin"}`, alice).Body.Close()

	// bob (project admin) can add a hook for his project, not a global one.
	if r := postJSON(t, srv.URL+"/ui/api/webhooks/save", `{"name":"g","url":"`+recv.URL+`","project":"","events":["push"]}`, bob); r.StatusCode != http.StatusForbidden {
		t.Errorf("project admin global hook: got %d want 403", r.StatusCode)
	}
	r := postJSON(t, srv.URL+"/ui/api/webhooks/save", `{"name":"team hook","url":"`+recv.URL+`","project":"team","events":["push","delete"],"auth_header":"Bearer s3cret"}`, bob)
	var saved struct{ ID string }
	json.NewDecoder(r.Body).Decode(&saved)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || saved.ID == "" {
		t.Fatalf("save: %d", r.StatusCode)
	}
	if r := postJSON(t, srv.URL+"/ui/api/webhooks/save", `{"name":"bad","url":"ftp://x","project":"team","events":["push"]}`, bob); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad URL: got %d", r.StatusCode)
	}

	// The auth header is never returned.
	resp := do(t, "GET", srv.URL+"/ui/api/webhooks", nil, bob)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "s3cret") || !strings.Contains(string(raw), `"has_auth":true`) {
		t.Errorf("webhook list leaks or misses auth: %s", raw)
	}

	// Push and delete in the project fire the hook; outside the project not.
	m := []byte(`{"schemaVersion":2,"layers":[]}`)
	for _, repo := range []string{"team/app", "free"} {
		p := do(t, "PUT", srv.URL+"/v2/"+repo+"/manifests/1", m, map[string]string{
			"Authorization": alice["Authorization"], "Content-Type": "application/vnd.oci.image.manifest.v1+json"})
		p.Body.Close()
	}
	status(t, "DELETE", srv.URL+"/v2/team/app/manifests/1", alice)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	got := strings.Join(events, ",")
	mu.Unlock()
	if got != "PUSH_ARTIFACT,DELETE_ARTIFACT" {
		t.Errorf("events: %s", got)
	}

	r = postJSON(t, srv.URL+"/ui/api/webhooks/test", `{"id":"`+saved.ID+`"}`, bob)
	var d struct {
		Status int
		Error  string
	}
	json.NewDecoder(r.Body).Decode(&d)
	r.Body.Close()
	if d.Status != 200 || d.Error != "" {
		t.Errorf("test delivery: %+v", d)
	}
}

func TestFreeSpaceAfterDelete(t *testing.T) {
	srv, store := newTestServer(t)
	pushImage(t, srv.URL, "app", "1", "amd64")
	// A fresh upload of someone else's push in progress: no manifest yet.
	inflight := pushBlob(t, srv.URL, "other", []byte("push in progress"))

	r := postJSON(t, srv.URL+"/ui/api/tags/delete", `{"repo":"app","tags":["1"],"free_space":true}`, nil)
	var res struct {
		GC struct {
			Bytes int64 `json:"bytes_freed"`
		} `json:"gc"`
	}
	json.NewDecoder(r.Body).Decode(&res)
	r.Body.Close()
	if res.GC.Bytes == 0 {
		t.Errorf("free_space freed nothing: %+v", res)
	}
	if _, err := store.StatBlob(storage.Digest(inflight)); err != nil {
		t.Errorf("in-progress upload was removed: %v", err)
	}
}

func TestPendingFreeAndGCReport(t *testing.T) {
	srv, _ := newTestServer(t)
	pushImage(t, srv.URL, "app", "1", "amd64")
	postJSON(t, srv.URL+"/ui/api/repos/delete", `{"repo":"app"}`, nil).Body.Close()

	resp := do(t, "GET", srv.URL+"/ui/api/disk?details=1", nil, nil)
	var disk struct {
		Supported bool
		Total     uint64
		Data      int64 `json:"data_bytes"`
		Pending   []struct {
			Ref   string
			Kind  string
			Bytes int64
		}
		Estimate struct{ Next int64 }
	}
	json.NewDecoder(resp.Body).Decode(&disk)
	resp.Body.Close()
	if len(disk.Pending) != 1 || disk.Pending[0].Ref != "app" || disk.Pending[0].Kind != "repository" || disk.Pending[0].Bytes == 0 {
		t.Errorf("pending: %+v", disk.Pending)
	}
	if disk.Estimate.Next == 0 || disk.Data == 0 || !disk.Supported || disk.Total == 0 {
		t.Errorf("disk details: %+v", disk)
	}

	r := postJSON(t, srv.URL+"/ui/api/gc/run", `{}`, nil)
	var run struct {
		Freed []string `json:"freed"`
	}
	json.NewDecoder(r.Body).Decode(&run)
	r.Body.Close()
	if len(run.Freed) != 1 || run.Freed[0] != "repository app" {
		t.Errorf("GC freed: %v", run.Freed)
	}
	resp = do(t, "GET", srv.URL+"/ui/api/disk?details=1", nil, nil)
	disk.Pending = nil
	json.NewDecoder(resp.Body).Decode(&disk)
	resp.Body.Close()
	if len(disk.Pending) != 0 {
		t.Errorf("pending after GC: %+v", disk.Pending)
	}
}
