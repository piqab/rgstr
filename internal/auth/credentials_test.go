package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rgstr/internal/config"
)

// bootstrapCfg: auth on, bootstrap admin "admin"/"changeme", env user
// alice/secret, and storage in a temp dir.
func bootstrapCfg(t *testing.T) *config.Config {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	return &config.Config{
		AuthEnabled:   true,
		AuthSecret:    "test-secret",
		AuthRealm:     "http://localhost/v2/auth",
		AuthService:   "test",
		AuthIssuer:    "test",
		TokenTTL:      time.Hour,
		Users:         map[string]string{"alice": string(hash)},
		AdminUser:     "admin",
		AdminPassword: "changeme",
		Admins:        []string{"alice"},
		StorageRoot:   t.TempDir(),
	}
}

func handlerFor(cfg *config.Config) *Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	return NewHandler(cfg, NewTokenService(cfg), inner)
}

func basicAuth(user, pass string) map[string]string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

func TestBootstrapPasswordOnlyAllowsChange(t *testing.T) {
	h := handlerFor(bootstrapCfg(t))

	if _, err := h.Login("admin", "changeme"); err != ErrPasswordChangeRequired {
		t.Errorf("UI login with bootstrap password: got %v want ErrPasswordChangeRequired", err)
	}
	if _, err := h.Login("admin", "wrong"); err != ErrInvalidCredentials {
		t.Errorf("UI login with wrong password: got %v want ErrInvalidCredentials", err)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("admin", "changeme")); code != http.StatusUnauthorized {
		t.Errorf("Basic auth with bootstrap password: got %d want 401", code)
	}

	// docker login asks the token endpoint; the error says what to do.
	req := httptest.NewRequest(http.MethodGet, "/v2/auth?service=test", nil)
	req.SetBasicAuth("admin", "changeme")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "/ui") {
		t.Errorf("token with bootstrap password: got %d %s, want 401 pointing to /ui", rr.Code, rr.Body)
	}
}

func TestChangeBootstrapPassword(t *testing.T) {
	cfg := bootstrapCfg(t)
	h := handlerFor(cfg)

	cases := []struct {
		current, next string
		want          error
	}{
		{"wrong", "new-password", ErrInvalidCredentials},
		{"changeme", "short", ErrWeakPassword},
		{"changeme", "changeme", ErrSamePassword},
	}
	for _, c := range cases {
		if err := h.ChangePassword("admin", c.current, c.next); err != c.want {
			t.Errorf("change(%q→%q): got %v want %v", c.current, c.next, err, c.want)
		}
	}

	if err := h.ChangePassword("admin", "changeme", "new-password"); err != nil {
		t.Fatalf("change: %v", err)
	}
	if _, err := h.Login("admin", "new-password"); err != nil {
		t.Errorf("login with new password: %v", err)
	}
	if _, err := h.Login("admin", "changeme"); err != ErrInvalidCredentials {
		t.Errorf("login with old bootstrap password: got %v want ErrInvalidCredentials", err)
	}
	if code := serve(t, h, http.MethodDelete, "/v2/x/manifests/latest", basicAuth("admin", "new-password")); code != http.StatusOK {
		t.Errorf("bootstrap admin delete (not in RGSTR_ADMINS): got %d want 200", code)
	}

	// Survives a restart.
	h2 := handlerFor(cfg)
	if _, err := h2.Login("admin", "new-password"); err != nil {
		t.Errorf("login after restart: %v", err)
	}

	// The file holds hashes only.
	raw, _ := os.ReadFile(filepath.Join(cfg.StorageRoot, "users.json"))
	if strings.Contains(string(raw), "new-password") || strings.Contains(string(raw), "changeme") {
		t.Errorf("users.json contains a plain-text password: %s", raw)
	}
	if fi, _ := os.Stat(filepath.Join(cfg.StorageRoot, "users.json")); fi.Mode().Perm() != 0600 {
		t.Errorf("users.json mode: got %v want 0600", fi.Mode().Perm())
	}
}

func TestResetBootstrapPasswordViaEnv(t *testing.T) {
	cfg := bootstrapCfg(t)
	if err := handlerFor(cfg).ChangePassword("admin", "changeme", "forgotten-pw"); err != nil {
		t.Fatalf("change: %v", err)
	}

	// Operator sets a new env password and restarts.
	cfg.AdminPassword = "reset-me"
	h := handlerFor(cfg)
	if _, err := h.Login("admin", "forgotten-pw"); err != ErrInvalidCredentials {
		t.Errorf("old stored password after reset: got %v want ErrInvalidCredentials", err)
	}
	if _, err := h.Login("admin", "reset-me"); err != ErrPasswordChangeRequired {
		t.Errorf("new env password after reset: got %v want ErrPasswordChangeRequired", err)
	}

	// The stale entry is gone from disk: reverting env does not revive it.
	cfg.AdminPassword = "changeme"
	if _, err := handlerFor(cfg).Login("admin", "forgotten-pw"); err != ErrInvalidCredentials {
		t.Errorf("stale stored password revived: got %v", err)
	}
}

func TestChangeEnvUserPassword(t *testing.T) {
	cfg := bootstrapCfg(t)
	h := handlerFor(cfg)
	if err := h.ChangePassword("alice", "secret", "alice-new-pw"); err != nil {
		t.Fatalf("change: %v", err)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("alice", "alice-new-pw")); code != http.StatusOK {
		t.Errorf("docker auth with changed password: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("alice", "secret")); code != http.StatusUnauthorized {
		t.Errorf("docker auth with old password: got %d want 401", code)
	}

	// Rotating alice's hash in RGSTR_USERS resets her stored password.
	hash, _ := bcrypt.GenerateFromPassword([]byte("rotated"), bcrypt.MinCost)
	cfg.Users["alice"] = string(hash)
	if _, err := handlerFor(cfg).Login("alice", "rotated"); err != nil {
		t.Errorf("login with rotated env hash: %v", err)
	}
}

func TestRemovedUserLosesStoredPassword(t *testing.T) {
	cfg := bootstrapCfg(t)
	if err := handlerFor(cfg).ChangePassword("alice", "secret", "alice-new-pw"); err != nil {
		t.Fatalf("change: %v", err)
	}
	delete(cfg.Users, "alice")
	if _, err := handlerFor(cfg).Login("alice", "alice-new-pw"); err != ErrInvalidCredentials {
		t.Errorf("removed user: got %v want ErrInvalidCredentials", err)
	}
	var f usersFile
	raw, _ := os.ReadFile(filepath.Join(cfg.StorageRoot, "users.json"))
	json.Unmarshal(raw, &f)
	if _, ok := f.Users["alice"]; ok {
		t.Error("removed user still in users.json")
	}
}
