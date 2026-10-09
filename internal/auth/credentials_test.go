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

func TestManagedUsers(t *testing.T) {
	cfg := bootstrapCfg(t) // alice is an env admin
	h := handlerFor(cfg)

	if err := h.CreateUser("bad name", RoleUser, "password1", false); err != ErrInvalidName {
		t.Errorf("invalid name: got %v", err)
	}
	if err := h.CreateUser("alice", RoleUser, "password1", false); err != ErrUserExists {
		t.Errorf("env name: got %v", err)
	}
	if err := h.CreateUser("dave", "root", "password1", false); err != ErrInvalidRole {
		t.Errorf("invalid role: got %v", err)
	}
	if err := h.CreateUser("dave", RoleUser, "short", false); err != ErrWeakPassword {
		t.Errorf("weak password: got %v", err)
	}

	// Temporary password: UI login asks for a change, docker login refused.
	if err := h.CreateUser("dave", RoleUser, "temp-pass", true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Login("dave", "temp-pass"); err != ErrPasswordChangeRequired {
		t.Errorf("temporary password login: got %v", err)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", basicAuth("dave", "temp-pass")); code != http.StatusUnauthorized {
		t.Errorf("docker auth with temporary password: got %d want 401", code)
	}
	if err := h.ChangePassword("dave", "temp-pass", "dave-own-pw"); err != nil {
		t.Fatal(err)
	}
	tok, err := h.Login("dave", "dave-own-pw")
	if err != nil {
		t.Fatalf("login after change: %v", err)
	}

	// Managed "user" role: no delete, even though RGSTR_ADMINS... is set
	// here; and no legacy delete rule for managed users.
	if h.Can("dave", "app", "delete") || !h.Can("dave", "app", "push") {
		t.Errorf("user role rights: %v", h.UserActions("dave"))
	}
	h.SetRole("dave", RoleReadOnly)
	if h.Can("dave", "app", "push") {
		t.Error("read-only can push")
	}
	h.SetRole("dave", RoleAdmin)
	if !h.IsAdmin("dave") || !h.Can("dave", "app", "delete") {
		t.Error("admin role lacks rights")
	}
	if err := h.SetRole("alice", RoleUser); err != ErrEnvUser {
		t.Errorf("set role of env user: got %v", err)
	}

	// Persisted.
	if role := handlerFor(cfg).Role("dave"); role != RoleAdmin {
		t.Errorf("role after restart: %q", role)
	}

	// Deleted user loses access at once, token or not.
	if err := h.DeleteUser("dave"); err != nil {
		t.Fatal(err)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok}
	if code := serve(t, h, http.MethodGet, "/v2/x/manifests/latest", bearer); code != http.StatusUnauthorized {
		t.Errorf("deleted user's token: got %d want 401", code)
	}
	if err := h.DeleteUser("alice"); err != ErrEnvUser {
		t.Errorf("delete env user: got %v", err)
	}
}

func TestResetEnvUserPassword(t *testing.T) {
	h := handlerFor(bootstrapCfg(t))
	if err := h.ResetPassword("alice", "temporary1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Login("alice", "secret"); err != ErrInvalidCredentials {
		t.Errorf("old env password: got %v", err)
	}
	if _, err := h.Login("alice", "temporary1"); err != ErrPasswordChangeRequired {
		t.Errorf("reset password: got %v", err)
	}
	if err := h.ResetPassword("nobody", "temporary1", true); err != ErrUserNotFound {
		t.Errorf("unknown user: got %v", err)
	}
}

func TestEnvShadowsManagedUser(t *testing.T) {
	cfg := bootstrapCfg(t)
	if err := handlerFor(cfg).CreateUser("erin", RoleAdmin, "erin-password", false); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("env-pw"), bcrypt.MinCost)
	cfg.Users["erin"] = string(hash)
	h := handlerFor(cfg)
	if _, err := h.Login("erin", "env-pw"); err != nil {
		t.Errorf("env password: %v", err)
	}
	if h.IsAdmin("erin") {
		t.Error("shadowed managed role still applies")
	}
}

func TestLegacyDeleteRuleOnlyForEnvUsers(t *testing.T) {
	cfg := bootstrapCfg(t)
	cfg.Admins = nil // nobody in RGSTR_ADMINS: env users may delete
	h := handlerFor(cfg)
	h.CreateUser("frank", RoleUser, "frank-password", false)
	if !h.Can("alice", "app", "delete") {
		t.Error("env user without RGSTR_ADMINS cannot delete")
	}
	if h.Can("frank", "app", "delete") {
		t.Error("managed user got the legacy delete right")
	}
}

// Removing RGSTR_ADMIN_PASSWORD after the first admin set its own password
// must not delete the account (it did up to 1.5.0).
func TestFirstAdminSurvivesEnvRemoval(t *testing.T) {
	cfg := bootstrapCfg(t)
	if err := handlerFor(cfg).ChangePassword("admin", "changeme", "own-password"); err != nil {
		t.Fatal(err)
	}
	cfg.AdminPassword = ""
	h := handlerFor(cfg)
	if _, err := h.Login("admin", "own-password"); err != nil {
		t.Fatalf("login after removing RGSTR_ADMIN_PASSWORD: %v", err)
	}
	if !h.IsAdmin("admin") {
		t.Error("first admin lost admin rights")
	}
	// Setting it again to the same value changes nothing…
	cfg.AdminPassword = "changeme"
	if _, err := handlerFor(cfg).Login("admin", "own-password"); err != nil {
		t.Errorf("same env value again: %v", err)
	}
	// …a new value resets the password.
	cfg.AdminPassword = "reset-value"
	h = handlerFor(cfg)
	if _, err := h.Login("admin", "reset-value"); err != ErrPasswordChangeRequired {
		t.Errorf("new env value: got %v want ErrPasswordChangeRequired", err)
	}
	// The recovery account can be deleted in the admin.
	h.ChangePassword("admin", "reset-value", "after-reset")
	if err := h.DeleteUser("admin"); err != nil {
		t.Errorf("delete first admin: %v", err)
	}
}

// Entries written by older versions (not marked managed) are migrated.
func TestLegacyFirstAdminEntryMigrated(t *testing.T) {
	cfg := bootstrapCfg(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("own-password"), bcrypt.MinCost)
	base, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.MinCost)
	legacy := `{"users":{"admin":{"hash":"` + string(hash) + `","base":"` + string(base) + `","changed_at":"2026-10-01T00:00:00Z"}}}`
	os.WriteFile(filepath.Join(cfg.StorageRoot, "users.json"), []byte(legacy), 0600)
	cfg.AdminPassword = ""
	if _, err := handlerFor(cfg).Login("admin", "own-password"); err != nil {
		t.Errorf("legacy first admin without env: %v", err)
	}
}
