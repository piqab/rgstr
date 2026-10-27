package auth

import (
	"net/http"
	"testing"
	"time"

	"rgstr/internal/meta"
)

func sessionHandler(t *testing.T) (*Handler, *meta.Store) {
	t.Helper()
	cfg := bootstrapCfg(t)
	cfg.SessionTTL = 12 * time.Hour
	h := handlerFor(cfg)
	m, err := meta.Open(cfg.StorageRoot)
	if err != nil {
		t.Fatal(err)
	}
	h.SetMeta(m)
	return h, m
}

func bearerOf(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

func TestSessionLifecycle(t *testing.T) {
	h, m := sessionHandler(t)
	tok, err := h.Login("alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := h.tokenSvc.Verify(tok)
	if c.SessionID == "" || time.Until(time.Unix(c.ExpiresAt, 0)) < 11*time.Hour {
		t.Errorf("session token: sid=%q exp in %v", c.SessionID, time.Until(time.Unix(c.ExpiresAt, 0)))
	}

	refreshed, err := h.RefreshSession(tok)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if c2, _ := h.tokenSvc.Verify(refreshed); c2.SessionID != c.SessionID || c2.SessionStart != c.SessionStart {
		t.Errorf("refresh changed the session: %+v", c2)
	}

	h.Logout(refreshed)
	for _, tk := range []string{tok, refreshed} {
		if code := serve(t, h, http.MethodGet, "/v2/_catalog", bearerOf(tk)); code != http.StatusUnauthorized {
			t.Errorf("token after logout: got %d want 401", code)
		}
	}
	if _, err := h.RefreshSession(refreshed); err != ErrSessionEnded {
		t.Errorf("refresh after logout: %v", err)
	}

	// The revocation survives a restart.
	h2 := handlerFor(h.cfg)
	h2.SetMeta(m)
	if code := serve(t, h2, http.MethodGet, "/v2/_catalog", bearerOf(tok)); code != http.StatusUnauthorized {
		t.Errorf("revoked token after restart: got %d", code)
	}
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	h, _ := sessionHandler(t)
	old, _ := h.Login("alice", "secret")
	docker, _ := h.tokenSvc.Issue("alice", h.FullAccess("alice")) // a docker login token

	if err := h.ChangePassword("alice", "secret", "new-secret-1"); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", bearerOf(old)); code != http.StatusUnauthorized {
		t.Errorf("old session after password change: got %d want 401", code)
	}
	// A new session started right away (same second) works.
	fresh, err := h.Login("alice", "new-secret-1")
	if err != nil {
		t.Fatal(err)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", bearerOf(fresh)); code != http.StatusOK {
		t.Errorf("new session: got %d want 200", code)
	}
	// Docker tokens are not sessions and keep working until they expire.
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", bearerOf(docker)); code != http.StatusOK {
		t.Errorf("docker token: got %d want 200", code)
	}

	// An admin's reset ends the user's sessions too.
	if err := h.ResetPassword("alice", "temporary-9", false); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, h, http.MethodGet, "/v2/_catalog", bearerOf(fresh)); code != http.StatusUnauthorized {
		t.Errorf("session after an admin reset: got %d want 401", code)
	}
}
