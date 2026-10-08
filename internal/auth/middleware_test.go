package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rgstr/internal/config"
)

// newAuthHandler builds a Handler with one user (alice/secret) and the given
// public repo patterns. The inner handler always returns 200.
func newAuthHandler(t *testing.T, publicRepos []string) *Handler {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.Config{
		AuthEnabled: true,
		AuthSecret:  "test-secret",
		AuthRealm:   "http://localhost/v2/auth",
		AuthService: "test",
		AuthIssuer:  "test",
		TokenTTL:    time.Hour,
		Users:       map[string]string{"alice": string(hash)},
		PublicRepos: publicRepos,
	}
	tokenSvc := NewTokenService(cfg)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return NewHandler(cfg, tokenSvc, inner)
}

func get(t *testing.T, h http.Handler, path string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result()
}

// ─── matchGlob tests ──────────────────────────────────────────────────────────

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"alpine", "alpine", true},
		{"alpine", "busybox", false},
		{"library/*", "library/ubuntu", true},
		{"library/*", "library/alpine", true},
		{"library/*", "library/ns/ubuntu", false}, // * doesn't cross /
		{"public/**", "public/myimage", true},
		{"public/**", "public/ns/myimage", true},
		{"public/**", "other/myimage", false},
		{"*", "anything", true},
		{"*", "ns/something", false},            // * doesn't cross /
		{"**", "anything/at/all", true},
		{"**/public/**", "alex/public/alpine", true},
		{"**/public/**", "alex/public/ns/alpine", true},
		{"**/public/**", "public/alpine", true},
		{"**/public/**", "alex/private/alpine", false},
		{"**/public", "alex/public", true},
		{"**/public", "alex/private", false},
	}
	for _, c := range cases {
		got := matchGlob(c.pattern, c.name)
		if got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// ─── Public repo anonymous access ────────────────────────────────────────────

func TestPublicRepoAnonymousPull(t *testing.T) {
	h := newAuthHandler(t, []string{"public/**"})

	// Anonymous GET on a public repo → 200
	resp := get(t, h, "/v2/public/myimage/manifests/latest", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous pull on public repo: got %d want 200", resp.StatusCode)
	}
}

func TestPrivateRepoAnonymousPullBlocked(t *testing.T) {
	h := newAuthHandler(t, []string{"public/**"})

	// Anonymous GET on a private repo → 401
	resp := get(t, h, "/v2/private/myimage/manifests/latest", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous pull on private repo: got %d want 401", resp.StatusCode)
	}
}

func TestPublicRepoAnonymousPushBlocked(t *testing.T) {
	h := newAuthHandler(t, []string{"public/**"})

	// Anonymous PUT on a public repo → 401 (push always requires auth)
	req := httptest.NewRequest(http.MethodPut, "/v2/public/myimage/manifests/latest", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("anonymous push on public repo: got %d want 401", rr.Code)
	}
}

func TestAuthenticatedAccessPrivateRepo(t *testing.T) {
	h := newAuthHandler(t, []string{"public/**"})

	// Get a token for alice.
	tokenReq := httptest.NewRequest(http.MethodGet,
		"/v2/auth?service=test&scope=repository:private/myimage:pull,push", nil)
	tokenReq.SetBasicAuth("alice", "secret")
	tokenRR := httptest.NewRecorder()
	h.ServeHTTP(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("token request: got %d want 200", tokenRR.Code)
	}

	var body struct {
		Token string `json:"token"`
	}
	json.NewDecoder(tokenRR.Body).Decode(&body)
	if body.Token == "" {
		t.Fatal("empty token")
	}

	// Use the token to pull from a private repo → 200.
	resp := get(t, h, "/v2/private/myimage/manifests/latest",
		map[string]string{"Authorization": "Bearer " + body.Token})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated pull on private repo: got %d want 200", resp.StatusCode)
	}
}

func TestTokenAnonymousPublicScope(t *testing.T) {
	h := newAuthHandler(t, []string{"library/*"})

	// Anonymous token request for a public repo scope.
	req := httptest.NewRequest(http.MethodGet,
		"/v2/auth?service=test&scope=repository:library/ubuntu:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("anonymous token for public repo: got %d want 200", rr.Code)
	}
	var body struct {
		Token string `json:"token"`
	}
	json.NewDecoder(rr.Body).Decode(&body)
	if body.Token == "" {
		t.Fatal("empty token")
	}
}

func TestTokenAnonymousPrivateScopeBlocked(t *testing.T) {
	h := newAuthHandler(t, []string{"library/*"})

	// Anonymous token request for a private repo scope → 401.
	req := httptest.NewRequest(http.MethodGet,
		"/v2/auth?service=test&scope=repository:secret/project:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("anonymous token for private repo: got %d want 401", rr.Code)
	}
}

func TestTokenWrongPassword(t *testing.T) {
	h := newAuthHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/v2/auth?service=test", nil)
	req.SetBasicAuth("alice", "wrongpassword")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: got %d want 401", rr.Code)
	}
}

func TestNoPublicReposAllPrivate(t *testing.T) {
	h := newAuthHandler(t, nil) // no public repos configured

	// Anonymous GET → 401 for any repo.
	resp := get(t, h, "/v2/anyrepo/manifests/latest", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("all-private: got %d want 401", resp.StatusCode)
	}
}

func TestAllPublicStar(t *testing.T) {
	h := newAuthHandler(t, []string{"**"}) // everything is public

	resp := get(t, h, "/v2/anything/manifests/latest", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("all-public: got %d want 200", resp.StatusCode)
	}
}

// ─── Scope enforcement and roles ─────────────────────────────────────────────

// newRoleHandler builds a Handler with users alice (admin), carol (regular)
// and bob (read-only), all with password "secret".
func newRoleHandler(t *testing.T) *Handler {
	t.Helper()
	h := newAuthHandler(t, []string{"public/**"})
	hash := h.cfg.Users["alice"]
	h.cfg.Users["bob"] = hash
	h.cfg.Users["carol"] = hash
	h.cfg.Admins = []string{"alice"}
	h.cfg.ReadOnlyUsers = []string{"bob"}
	return h
}

func serve(t *testing.T, h http.Handler, method, path string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func basic(user string) map[string]string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, "secret")
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

// token requests a token for scope as user ("" = anonymous).
func token(t *testing.T, h http.Handler, user, scope string) map[string]string {
	t.Helper()
	path := "/v2/auth?service=test"
	if scope != "" {
		path += "&scope=" + scope
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if user != "" {
		req.SetBasicAuth(user, "secret")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("token for %q scope %q: got %d", user, scope, rr.Code)
	}
	var body struct {
		Token string `json:"token"`
	}
	json.NewDecoder(rr.Body).Decode(&body)
	return map[string]string{"Authorization": "Bearer " + body.Token}
}

func TestAnonymousTokenGrantsNothing(t *testing.T) {
	h := newAuthHandler(t, []string{"public/**"})
	anon := token(t, h, "", "")

	if code := serve(t, h, http.MethodGet, "/v2/private/app/manifests/latest", anon); code != http.StatusUnauthorized {
		t.Errorf("anonymous token pull on private repo: got %d want 401", code)
	}
	if code := serve(t, h, http.MethodPost, "/v2/private/app/blobs/uploads/", anon); code != http.StatusUnauthorized {
		t.Errorf("anonymous token push on private repo: got %d want 401", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", anon); code != http.StatusUnauthorized {
		t.Errorf("anonymous token catalog: got %d want 401", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/", anon); code != http.StatusOK {
		t.Errorf("anonymous token /v2/ ping: got %d want 200", code)
	}
}

func TestPublicPullTokenCannotPush(t *testing.T) {
	h := newAuthHandler(t, []string{"public/**"})
	tok := token(t, h, "", "repository:public/app:pull,push")

	if code := serve(t, h, http.MethodGet, "/v2/public/app/manifests/latest", tok); code != http.StatusOK {
		t.Errorf("pull: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodPut, "/v2/public/app/manifests/latest", tok); code != http.StatusUnauthorized {
		t.Errorf("push: got %d want 401", code)
	}
}

func TestAnonymousWildcardScopeNotPublic(t *testing.T) {
	h := newAuthHandler(t, []string{"*"})
	req := httptest.NewRequest(http.MethodGet, "/v2/auth?service=test&scope=repository:*:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("anonymous wildcard scope: got %d want 401", rr.Code)
	}
}

func TestTokenScopeLimitedToRepo(t *testing.T) {
	h := newAuthHandler(t, nil)
	tok := token(t, h, "alice", "repository:a:pull")

	if code := serve(t, h, http.MethodGet, "/v2/a/manifests/latest", tok); code != http.StatusOK {
		t.Errorf("pull a: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/b/manifests/latest", tok); code != http.StatusUnauthorized {
		t.Errorf("pull b: got %d want 401", code)
	}
	if code := serve(t, h, http.MethodPut, "/v2/a/manifests/latest", tok); code != http.StatusUnauthorized {
		t.Errorf("push a: got %d want 401", code)
	}
}

func TestRoles(t *testing.T) {
	h := newRoleHandler(t)
	manifest := "/v2/private/app/manifests/latest"
	cases := []struct {
		user, method, path string
		want               int
	}{
		{"bob", http.MethodGet, manifest, http.StatusOK},
		{"bob", http.MethodPut, manifest, http.StatusForbidden},
		{"bob", http.MethodDelete, manifest, http.StatusForbidden},
		{"carol", http.MethodPut, manifest, http.StatusOK},
		{"carol", http.MethodDelete, manifest, http.StatusForbidden},
		// Cancelling an upload is part of push, not delete.
		{"carol", http.MethodDelete, "/v2/private/app/blobs/uploads/0f8fad5b-d9cb-469f-a165-70867728950e", http.StatusOK},
		{"alice", http.MethodDelete, manifest, http.StatusOK},
		{"bob", http.MethodGet, "/v2/_catalog", http.StatusOK},
	}
	for _, c := range cases {
		if code := serve(t, h, c.method, c.path, basic(c.user)); code != c.want {
			t.Errorf("basic %s %s %s: got %d want %d", c.user, c.method, c.path, code, c.want)
		}
	}
}

func TestTokenGrantLimitedByRole(t *testing.T) {
	h := newRoleHandler(t)

	bob := token(t, h, "bob", "repository:app:pull,push")
	if code := serve(t, h, http.MethodPut, "/v2/app/manifests/latest", bob); code != http.StatusUnauthorized {
		t.Errorf("read-only push with token: got %d want 401", code)
	}

	carol := token(t, h, "carol", "repository:app:*")
	if code := serve(t, h, http.MethodPut, "/v2/app/manifests/latest", carol); code != http.StatusOK {
		t.Errorf("user push with * token: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodDelete, "/v2/app/manifests/latest", carol); code != http.StatusUnauthorized {
		t.Errorf("user delete with * token: got %d want 401", code)
	}

	alice := token(t, h, "alice", "repository:app:delete")
	if code := serve(t, h, http.MethodDelete, "/v2/app/manifests/latest", alice); code != http.StatusOK {
		t.Errorf("admin delete with token: got %d want 200", code)
	}
}

func TestNoAdminsMeansEveryoneDeletes(t *testing.T) {
	h := newAuthHandler(t, nil)
	if code := serve(t, h, http.MethodDelete, "/v2/app/manifests/latest", basic("alice")); code != http.StatusOK {
		t.Errorf("delete without RGSTR_ADMINS: got %d want 200", code)
	}
}

func TestLoginToken(t *testing.T) {
	h := newRoleHandler(t)
	if _, ok := h.Login("bob", "wrong"); ok {
		t.Fatal("login with wrong password succeeded")
	}
	tok, ok := h.Login("bob", "secret")
	if !ok {
		t.Fatal("login failed")
	}
	auth := map[string]string{"Authorization": "Bearer " + tok}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", auth); code != http.StatusOK {
		t.Errorf("login token catalog: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/x/manifests/latest", auth); code != http.StatusOK {
		t.Errorf("login token pull: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodPut, "/v2/x/manifests/latest", auth); code != http.StatusUnauthorized {
		t.Errorf("read-only login token push: got %d want 401", code)
	}
}

// containerd (docker push/pull) POSTs an OAuth2 password grant form.
func TestTokenOAuthPasswordGrant(t *testing.T) {
	h := newAuthHandler(t, nil)
	form := "grant_type=password&service=test&client_id=containerd-client" +
		"&username=alice&password=secret&scope=repository%3Aapp%3Apull%2Cpush"
	req := httptest.NewRequest(http.MethodPost, "/v2/auth", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("oauth token: got %d want 200", rr.Code)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(rr.Body).Decode(&body)
	bearer := map[string]string{"Authorization": "Bearer " + body.AccessToken}
	if code := serve(t, h, http.MethodPut, "/v2/app/manifests/latest", bearer); code != http.StatusOK {
		t.Errorf("push with oauth token: got %d want 200", code)
	}
}
