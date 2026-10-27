package ui

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"rgstr/internal/audit"
	"rgstr/internal/auth"
)

// ─── OIDC sign-in ────────────────────────────────────────────────────────────
//
// /ui/oidc/login sends the browser to the identity provider; the provider
// sends it back to /ui/oidc/callback, which opens a session and hands it to
// the page like the password form does (rgstr_handoff cookie).

const oidcCookie = "rgstr_oidc"

// oidcRedirectURL is the callback URL registered at the provider:
// RGSTR_OIDC_REDIRECT_URL, else derived from RGSTR_AUTH_REALM (the
// registry's external URL), else from the request.
func (h *Handler) oidcRedirectURL(r *http.Request) string {
	if u := h.auth.OIDCRedirectURL(); u != "" {
		return u
	}
	if realm := h.auth.Config().AuthRealm; strings.HasSuffix(realm, "/v2/auth") &&
		!strings.Contains(realm, "://localhost:") {
		return strings.TrimSuffix(realm, "/v2/auth") + "/ui/oidc/callback"
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/ui/oidc/callback"
}

func (h *Handler) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if h.auth.OIDCName() == "" {
		http.NotFound(w, r)
		return
	}
	authURL, state, err := h.auth.OIDCBegin(r.Context(), h.oidcRedirectURL(r))
	if err != nil {
		log.Printf("ui: oidc: %v", err)
		backToUI(w, r, url.Values{"error": {"sso"}, "reason": {"provider"}})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: state, Path: "/ui/oidc", MaxAge: 600, HttpOnly: true,
		// Lax: the provider's redirect back is a cross-site navigation.
		SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(h.oidcRedirectURL(r), "https:"),
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if h.auth.OIDCName() == "" {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/ui/oidc", MaxAge: -1})
	q := r.URL.Query()
	fail := func(user, reason string, err error) {
		if err != nil {
			log.Printf("ui: oidc sign-in: %v", err)
		}
		if user != "" {
			h.audit(r, user, audit.LoginFailed, "", "sso: "+reason, nil)
		}
		backToUI(w, r, url.Values{"error": {"sso"}, "reason": {reason}})
	}
	if e := q.Get("error"); e != "" {
		fail("", "provider", errors.New(e+": "+q.Get("error_description")))
		return
	}
	c, err := r.Cookie(oidcCookie)
	if err != nil {
		fail("", "state", nil)
		return
	}
	user, token, err := h.auth.OIDCFinish(r.Context(), c.Value, q.Get("state"), q.Get("code"))
	switch {
	case errors.Is(err, auth.ErrOIDCState):
		fail(user, "state", nil)
	case errors.Is(err, auth.ErrOIDCDenied):
		fail(user, "denied", nil)
	case errors.Is(err, auth.ErrOIDCUsername), errors.Is(err, auth.ErrInvalidName):
		fail(user, "username", err)
	case errors.Is(err, auth.ErrLocalUser):
		fail(user, "local", nil)
	case err != nil:
		fail(user, "provider", err)
	default:
		h.audit(r, user, audit.Login, "", "sso", nil)
		h.handoff(w, r, token)
		backToUI(w, r, nil)
	}
}

// handleCLISecret makes a new docker login secret for the signed-in
// external (LDAP / OIDC) user. The secret is shown once.
func (h *Handler) handleCLISecret(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	secret, err := h.auth.NewCLISecret(user)
	h.audit(r, user, audit.CLISecret, user, "", err)
	if err != nil {
		writeError(w, http.StatusBadRequest, "only LDAP and SSO users have a CLI secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "user": user})
}
