package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
