// Integration tests for the web admin API.
package main

import (
	"encoding/json"
	"fmt"
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
