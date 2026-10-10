package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"rgstr/internal/meta"
)

// ErrSessionEnded is returned when a web admin session can no longer be
// refreshed: signed out, ended by a password change, or expired.
var ErrSessionEnded = errors.New("session ended")

// sessionState keeps revocations in memory when there is no metadata store
// (tests); otherwise they live in meta.json and survive restarts.
type sessionState struct {
	mu        sync.Mutex
	revoked   map[string]time.Time
	notBefore map[string]time.Time
}

func newSID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessionValid reports whether a token's session is still alive. Tokens
// without a session (docker logins) are always valid here.
func (h *Handler) sessionValid(c *Claims) bool {
	if c.SessionID == "" {
		return true
	}
	start := time.Unix(0, c.SessionStart)
	valid := true
	h.viewSessions(func(revoked, notBefore map[string]time.Time) {
		if _, ok := revoked[c.SessionID]; ok {
			valid = false
		}
		if nb, ok := notBefore[c.Subject]; ok && start.Before(nb) {
			valid = false
		}
	})
	return valid
}

func (h *Handler) viewSessions(fn func(revoked, notBefore map[string]time.Time)) {
	if h.meta != nil {
		h.meta.View(func(d *meta.Data) { fn(d.RevokedSessions, d.SessionsNotBefore) })
		return
	}
	h.sessions.mu.Lock()
	defer h.sessions.mu.Unlock()
	fn(h.sessions.revoked, h.sessions.notBefore)
}

// updateSessions changes the revocation maps and drops entries that no
// longer matter (their sessions have expired anyway).
func (h *Handler) updateSessions(fn func(revoked, notBefore map[string]time.Time)) {
	apply := func(revoked, notBefore map[string]time.Time) {
		fn(revoked, notBefore)
		now := time.Now()
		for sid, until := range revoked {
			if now.After(until) {
				delete(revoked, sid)
			}
		}
		for user, nb := range notBefore {
			if now.Sub(nb) > h.cfg.SessionTTL {
				delete(notBefore, user)
			}
		}
	}
	if h.meta != nil {
		h.meta.Update(func(d *meta.Data) error {
			if d.RevokedSessions == nil {
				d.RevokedSessions = map[string]time.Time{}
			}
			if d.SessionsNotBefore == nil {
				d.SessionsNotBefore = map[string]time.Time{}
			}
			apply(d.RevokedSessions, d.SessionsNotBefore)
			return nil
		})
		return
	}
	h.sessions.mu.Lock()
	defer h.sessions.mu.Unlock()
	if h.sessions.revoked == nil {
		h.sessions.revoked, h.sessions.notBefore = map[string]time.Time{}, map[string]time.Time{}
	}
	apply(h.sessions.revoked, h.sessions.notBefore)
}

func (h *Handler) sessionTTL() time.Duration {
	if h.cfg.SessionTTL > 0 {
		return h.cfg.SessionTTL
	}
	return h.cfg.TokenTTL
}

// newSession issues the first token of a web admin session.
func (h *Handler) newSession(user string) (string, error) {
	return h.tokenSvc.IssueSession(user, h.FullAccess(user), newSID(), time.Now(), h.sessionTTL())
}

// RefreshSession extends a web admin session: it returns a new token for
// the same session, valid for another RGSTR_SESSION_TTL.
func (h *Handler) RefreshSession(token string) (string, error) {
	c, err := h.tokenSvc.Verify(token)
	if err != nil || c.SessionID == "" || !h.sessionValid(c) || !h.creds.exists(c.Subject) {
		return "", ErrSessionEnded
	}
	return h.tokenSvc.IssueSession(c.Subject, c.Access, c.SessionID, time.Unix(0, c.SessionStart), h.sessionTTL())
}

// Logout ends the session of token on the server: its tokens stop working
// even though they have not expired.
func (h *Handler) Logout(token string) {
	c, err := h.tokenSvc.Verify(token)
	if err != nil || c.SessionID == "" {
		return
	}
	until := time.Now().Add(h.sessionTTL())
	h.updateSessions(func(revoked, _ map[string]time.Time) { revoked[c.SessionID] = until })
}

// endSessions ends every web admin session user started until now.
func (h *Handler) endSessions(user string) {
	now := time.Now()
	h.updateSessions(func(_, notBefore map[string]time.Time) { notBefore[user] = now })
}
