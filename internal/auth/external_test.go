package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"rgstr/internal/config"
)

// fakeLDAP accepts the passwords in users and returns their groups.
type fakeLDAP struct {
	users map[string]string
	group map[string][]string
	calls int
}

func (f *fakeLDAP) authenticate(user, password string) ([]string, error) {
	f.calls++
	if pw, ok := f.users[user]; !ok || password == "" || pw != password {
		return nil, errLDAPDenied
	}
	return f.group[user], nil
}

func ldapHandler(t *testing.T, roles config.GroupRoles) (*Handler, *fakeLDAP) {
	t.Helper()
	cfg := bootstrapCfg(t)
	cfg.LDAP = config.LDAPConfig{URL: "ldap://test", UserFilter: "(uid=%s)", Roles: roles}
	h := handlerFor(cfg)
	f := &fakeLDAP{
		users: map[string]string{"bob": "bobpw", "carol": "carolpw", "admin": "dirpw", "alice": "dirpw"},
		group: map[string][]string{
			"bob":   {"CN=Registry Admins,OU=Groups,DC=corp"},
			"carol": {"cn=devs,ou=groups,dc=corp"},
		},
	}
	h.ldap = f
	return h, f
}

func TestLDAPSignIn(t *testing.T) {
	h, _ := ldapHandler(t, config.GroupRoles{AdminGroups: []string{"Registry Admins"}, DefaultRole: RoleReadOnly})

	// First sign-in creates the user (lower-cased), role from groups.
	subject, _, err := h.LoginAs("Bob", "bobpw")
	if err != nil || subject != "bob" {
		t.Fatalf("LoginAs: %q %v", subject, err)
	}
	if h.Role("bob") != RoleAdmin || h.Source("bob") != SourceLDAP {
		t.Errorf("bob: role %q source %q", h.Role("bob"), h.Source("bob"))
	}
	if _, _, err := h.LoginAs("carol", "carolpw"); err != nil || h.Role("carol") != RoleReadOnly {
		t.Errorf("carol: %v role %q", err, h.Role("carol"))
	}
	if _, _, err := h.LoginAs("bob", "wrong"); err != ErrInvalidCredentials {
		t.Errorf("wrong password: %v", err)
	}
	if _, _, err := h.LoginAs("bob", ""); err != ErrInvalidCredentials {
		t.Errorf("empty password: %v", err)
	}
	// docker login with the directory password.
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("bob", "bobpw")); code != http.StatusOK {
		t.Errorf("Basic auth with LDAP password: %d", code)
	}
	// The password is the directory's: it cannot be changed or reset here.
	if err := h.ChangePassword("bob", "bobpw", "something-new"); err != ErrExternalUser {
		t.Errorf("ChangePassword: %v", err)
	}
	if err := h.ResetPassword("bob", "something-new", false); err != ErrExternalUser {
		t.Errorf("ResetPassword: %v", err)
	}
}

func TestLDAPCannotTakeOverLocalUsers(t *testing.T) {
	h, _ := ldapHandler(t, config.GroupRoles{DefaultRole: RoleAdmin})
	// "alice" is an env user and "admin" the bootstrap admin: the directory
	// password of a namesake must not work.
	for _, u := range []string{"alice", "admin", "ALICE"} {
		if _, _, err := h.LoginAs(u, "dirpw"); err == nil {
			t.Errorf("%s signed in with the directory password", u)
		}
	}
	if _, _, err := h.LoginAs("alice", "secret"); err != nil {
		t.Errorf("alice with her local password: %v", err)
	}
}

func TestLDAPAllowedGroups(t *testing.T) {
	h, _ := ldapHandler(t, config.GroupRoles{AllowedGroups: []string{"devs"}, DefaultRole: RoleUser})
	if _, _, err := h.LoginAs("carol", "carolpw"); err != nil {
		t.Errorf("carol (in devs): %v", err)
	}
	if _, _, err := h.LoginAs("bob", "bobpw"); err == nil {
		t.Error("bob is not in an allowed group but signed in")
	}
	if h.UserExists("bob") {
		t.Error("a refused user was created")
	}
}

func TestLDAPRoleManagedInAdmin(t *testing.T) {
	// No role groups: the role set in the admin survives later sign-ins.
	h, _ := ldapHandler(t, config.GroupRoles{DefaultRole: RoleUser})
	h.LoginAs("carol", "carolpw")
	if err := h.SetRole("carol", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	h.LoginAs("carol", "carolpw")
	if h.Role("carol") != RoleAdmin {
		t.Errorf("role after sign-in: %q", h.Role("carol"))
	}
}

func TestCLISecret(t *testing.T) {
	h, f := ldapHandler(t, config.GroupRoles{DefaultRole: RoleUser})
	if _, err := h.NewCLISecret("alice"); err == nil {
		t.Error("local users have no CLI secret")
	}
	h.LoginAs("carol", "carolpw")
	secret, err := h.NewCLISecret("carol")
	if err != nil {
		t.Fatal(err)
	}
	f.users["carol"] = "changed-in-directory"
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("carol", secret)); code != http.StatusOK {
		t.Errorf("docker login with CLI secret: %d", code)
	}
	// The CLI secret is for docker, not for the web admin.
	if _, _, err := h.LoginAs("carol", secret); err == nil {
		t.Error("web admin accepted the CLI secret")
	}
	next, _ := h.NewCLISecret("carol")
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("carol", secret)); code == http.StatusOK {
		t.Error("old CLI secret still works")
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("carol", next)); code != http.StatusOK {
		t.Errorf("new CLI secret: %d", code)
	}
}

func TestGroupMatches(t *testing.T) {
	cases := []struct {
		group, want string
		ok          bool
	}{
		{"devs", "DEVS", true},
		{"CN=Devs,OU=Groups,DC=corp", "devs", true},
		{"CN=Devs,OU=Groups,DC=corp", "cn=devs,ou=groups,dc=corp", true},
		{"CN=Devs Team,OU=Groups", "devs", false},
		{"OU=devs,DC=corp", "devs", false},
	}
	for _, c := range cases {
		if got := groupMatches(c.group, c.want); got != c.ok {
			t.Errorf("groupMatches(%q, %q) = %v", c.group, c.want, got)
		}
	}
}

// ─── OIDC ────────────────────────────────────────────────────────────────────

// fakeIdP is a minimal OpenID provider: discovery, JWKS and a token
// endpoint that returns an ID token with the claims of the next sign-in.
type fakeIdP struct {
	*httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // merged into the ID token
	nonce  string         // from the authorization request
	alg    string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &fakeIdP{key: key, alg: "RS256"}
	mux := http.NewServeMux()
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize",
			"token_endpoint": p.URL + "/token", "jwks_uri": p.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if id, sec, _ := r.BasicAuth(); id != "rgstr" || sec != "s3cret" || r.Form.Get("code") != "the-code" ||
			r.Form.Get("code_verifier") == "" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": p.idToken(), "access_token": "at"})
	})
	return p
}

func (p *fakeIdP) idToken() string {
	claims := map[string]any{
		"iss": p.URL, "aud": "rgstr", "sub": "123", "nonce": p.nonce,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
	for k, v := range p.claims {
		claims[k] = v
	}
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signed := enc(map[string]string{"alg": p.alg, "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func oidcHandler(t *testing.T, p *fakeIdP, roles config.GroupRoles) *Handler {
	cfg := bootstrapCfg(t)
	cfg.OIDC = config.OIDCConfig{Issuer: p.URL, ClientID: "rgstr", ClientSecret: "s3cret", Scopes: []string{"openid"},
		UsernameClaim: "preferred_username", GroupsClaim: "groups", Name: "Test", Roles: roles}
	return handlerFor(cfg)
}

// signIn runs the browser flow: begin, provider redirect, callback.
func signIn(t *testing.T, h *Handler, p *fakeIdP) (string, string, error) {
	t.Helper()
	authURL, cookie, err := h.OIDCBegin(context.Background(), "https://reg.example/ui/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if !strings.HasPrefix(authURL, p.URL+"/authorize?") || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != "https://reg.example/ui/oidc/callback" {
		t.Fatalf("authorization URL: %s", authURL)
	}
	p.nonce = q.Get("nonce")
	return h.OIDCFinish(context.Background(), cookie, q.Get("state"), "the-code")
}

func TestOIDCSignIn(t *testing.T) {
	p := newFakeIdP(t)
	h := oidcHandler(t, p, config.GroupRoles{AdminGroups: []string{"registry-admins"}, DefaultRole: RoleUser})

	p.claims = map[string]any{"preferred_username": "Dave", "groups": []string{"registry-admins"}}
	subject, token, err := signIn(t, h, p)
	if err != nil || subject != "dave" || token == "" {
		t.Fatalf("sign-in: %q %v", subject, err)
	}
	if h.Role("dave") != RoleAdmin || h.Source("dave") != SourceOIDC {
		t.Errorf("dave: role %q source %q", h.Role("dave"), h.Source("dave"))
	}
	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if sub, _, ok := h.Authenticate(req); !ok || sub != "dave" {
		t.Errorf("session token: %q %v", sub, ok)
	}
	// Removed from the admin group at the provider: next sign-in demotes.
	p.claims["groups"] = []string{}
	signIn(t, h, p)
	if h.Role("dave") != RoleUser {
		t.Errorf("role after leaving the group: %q", h.Role("dave"))
	}
	// No password: docker login needs a CLI secret.
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("dave", "")); code == http.StatusOK {
		t.Error("empty password accepted")
	}
}

func TestOIDCRejects(t *testing.T) {
	p := newFakeIdP(t)
	h := oidcHandler(t, p, config.GroupRoles{AllowedGroups: []string{"staff"}, DefaultRole: RoleUser})

	p.claims = map[string]any{"preferred_username": "erin", "groups": []string{"guests"}}
	if _, _, err := signIn(t, h, p); err != ErrOIDCDenied {
		t.Errorf("not in allowed group: %v", err)
	}
	p.claims = map[string]any{"preferred_username": "alice", "groups": []string{"staff"}}
	if _, _, err := signIn(t, h, p); err != ErrLocalUser {
		t.Errorf("local name: %v", err)
	}
	p.claims = map[string]any{"preferred_username": "erin", "groups": []string{"staff"}, "aud": "someone-else"}
	if _, _, err := signIn(t, h, p); err == nil {
		t.Error("token for another client accepted")
	}
	p.claims = map[string]any{"preferred_username": "erin", "groups": []string{"staff"}, "exp": time.Now().Add(-time.Hour).Unix()}
	if _, _, err := signIn(t, h, p); err == nil {
		t.Error("expired token accepted")
	}
	p.claims = map[string]any{"preferred_username": "erin", "groups": []string{"staff"}}
	p.alg = "none"
	if _, _, err := signIn(t, h, p); err == nil {
		t.Error(`alg "none" accepted`)
	}
	p.alg = "RS256"

	// A forged or replayed state is refused.
	_, cookie, _ := h.OIDCBegin(context.Background(), "https://reg.example/ui/oidc/callback")
	if _, _, err := h.OIDCFinish(context.Background(), cookie, "other-state", "the-code"); err != ErrOIDCState {
		t.Errorf("wrong state: %v", err)
	}
	if _, _, err := h.OIDCFinish(context.Background(), cookie+"x", "x", "the-code"); err != ErrOIDCState {
		t.Errorf("tampered cookie: %v", err)
	}
}
