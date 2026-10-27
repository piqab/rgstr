package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"rgstr/internal/config"
)

func TestRepositoryGrantsAPI(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	srv, _ := newRegistry(t, func(c *config.Config) {
		c.AuthEnabled = true
		c.Users = map[string]string{"alice": string(hash), "bob": string(hash)}
		c.Admins = []string{"alice"}
	})
	call := func(user, method, path string, body []byte) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		req.SetBasicAuth(user, "pw")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, b
	}
	if code, b := call("alice", "POST", "/ui/api/projects/create", []byte(`{"name":"team"}`)); code != 204 {
		t.Fatalf("create project: %d %s", code, b)
	}
	if code, b := call("alice", "POST", "/ui/api/projects/grant",
		[]byte(`{"name":"team","user":"bob","repos":"app-*","role":"developer"}`)); code != 204 {
		t.Fatalf("grant: %d %s", code, b)
	}
	if code, _ := call("alice", "POST", "/ui/api/projects/grant",
		[]byte(`{"name":"team","user":"bob","repos":"../x","role":"developer"}`)); code == 204 {
		t.Error("bad pattern accepted")
	}
	if code, _ := call("bob", "POST", "/ui/api/projects/grant",
		[]byte(`{"name":"team","user":"bob","repos":"*","role":"maintainer"}`)); code == 204 {
		t.Error("bob granted himself access")
	}

	// bob may push to team/app-*, not to the rest of the project.
	push := func(repo string) int {
		code, _ := call("bob", "POST", "/v2/"+repo+"/blobs/uploads/", nil)
		return code
	}
	if code := push("team/app-web"); code != http.StatusAccepted {
		t.Errorf("push to a granted repository: %d", code)
	}
	if code := push("team/db"); code == http.StatusAccepted {
		t.Errorf("push to a repository without a grant: %d", code)
	}

	// The project is listed for bob, with the grant.
	_, b := call("bob", "GET", "/ui/api/projects", nil)
	if !strings.Contains(string(b), `"name":"team"`) {
		t.Errorf("project not visible to a user with a grant: %s", b)
	}
	_, b = call("alice", "GET", "/ui/api/project?name=team", nil)
	var p struct {
		Grants []struct{ User, Repos, Role string }
	}
	json.Unmarshal(b, &p)
	if len(p.Grants) != 1 || p.Grants[0].User != "bob" || p.Grants[0].Repos != "app-*" {
		t.Errorf("grants: %+v", p.Grants)
	}
	// Taking it back.
	call("alice", "POST", "/ui/api/projects/grant", []byte(`{"name":"team","user":"bob","repos":"app-*","role":""}`))
	if code := push("team/app-web"); code == http.StatusAccepted {
		t.Error("push still allowed after the grant was removed")
	}
}
