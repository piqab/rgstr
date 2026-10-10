package ui

import (
	"errors"
	"net/http"
	"net/url"

	"rgstr/internal/audit"
	"rgstr/internal/auth"
)

type meResponse struct {
	Version      string `json:"version"`
	AuthEnabled  bool   `json:"auth_enabled"`
	User         string `json:"user,omitempty"`
	Admin        bool   `json:"admin"`
	ProjectAdmin bool   `json:"project_admin"` // manages at least one project
}

// handleMe reports whether auth is on and, if the request carries a valid
// token, who the user is and whether they administer the registry.
func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	resp := meResponse{AuthEnabled: h.auth.AuthEnabled(), Version: h.auth.Config().Version}
	if !resp.AuthEnabled {
		resp.Admin = true
	} else if subject, _, ok := h.auth.Authenticate(r); ok && subject != "" {
		resp.User = subject
		resp.Admin = h.auth.IsAdmin(subject)
		resp.ProjectAdmin = len(h.managedProjects(subject)) > 0
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleLogin exchanges a username and password for a session token, so the
// browser keeps a short-lived token instead of the password.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	token, err := h.auth.Login(req.Username, req.Password)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		h.audit(r, req.Username, audit.LoginFailed, "", "web admin", nil)
	} else if err == nil {
		h.audit(r, req.Username, audit.Login, "", "web admin", nil)
	}
	switch {
	case errors.Is(err, auth.ErrPasswordChangeRequired):
		// The UI then asks for a new password and calls /ui/api/password.
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error":       err.Error(),
			"must_change": true,
		})
		return
	case err != nil:
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":         token,
		"user":          req.Username,
		"admin":         h.auth.IsAdmin(req.Username),
		"project_admin": len(h.managedProjects(req.Username)) > 0,
	})
}

// handlePassword changes a user's password. The current password proves
// identity, so it also serves the forced change of a temporary password,
// for which no session token can be issued.
func (h *Handler) handlePassword(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !h.auth.AuthEnabled() {
		writeError(w, http.StatusBadRequest, "authentication is disabled")
		return
	}
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := h.auth.ChangePassword(req.Username, req.Password, req.NewPassword)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		h.audit(r, req.Username, audit.LoginFailed, "", "password change", nil)
	} else {
		h.audit(r, req.Username, audit.PasswordChange, req.Username, "", err)
	}
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "current password is wrong")
	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrSamePassword):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── Native form sign-in ─────────────────────────────────────────────────────
//
// Password managers reliably offer to save credentials only after a real
// form submission that navigates the page. So the sign-in and password
// forms POST here; on success the session token is handed to the page in a
// short-lived cookie (rgstr_handoff, read and deleted by the page at once,
// never used for authentication) and the browser is redirected to /ui.

const handoffCookie = "rgstr_handoff"

// sameOrigin rejects cross-site form posts (login CSRF).
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return origin == ""
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func (h *Handler) handoff(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: handoffCookie, Value: token, Path: "/ui", MaxAge: 60,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
}

func backToUI(w http.ResponseWriter, r *http.Request, q url.Values) {
	loc := "/ui"
	if len(q) > 0 {
		loc += "?" + q.Encode()
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loc, http.StatusSeeOther)
}

// handleFormLogin signs in from the login form.
func (h *Handler) handleFormLogin(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-site sign-in refused")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	r.ParseForm()
	user, pass := r.PostForm.Get("username"), r.PostForm.Get("password")
	token, err := h.auth.Login(user, pass)
	q := url.Values{}
	switch {
	case errors.Is(err, auth.ErrPasswordChangeRequired):
		q.Set("must_change", "1")
		q.Set("user", user)
	case err != nil:
		h.audit(r, user, audit.LoginFailed, "", "web admin", nil)
		q.Set("error", "invalid")
		q.Set("user", user)
	default:
		h.audit(r, user, audit.Login, "", "web admin", nil)
		h.handoff(w, r, token)
	}
	backToUI(w, r, q)
}

// handleFormPassword changes a password from the password form (also the
// forced change of a temporary password) and signs in with the new one.
func (h *Handler) handleFormPassword(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	r.ParseForm()
	f := r.PostForm
	user, current, next := f.Get("username"), f.Get("current-password"), f.Get("new-password")
	q := url.Values{"user": {user}, "mode": {f.Get("mode")}}
	var err error
	if next != f.Get("new-password-repeat") {
		q.Set("pw_error", "mismatch")
		backToUI(w, r, q)
		return
	}
	err = h.auth.ChangePassword(user, current, next)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		h.audit(r, user, audit.LoginFailed, "", "password change", nil)
		q.Set("pw_error", "current")
	case errors.Is(err, auth.ErrWeakPassword):
		q.Set("pw_error", "weak")
	case errors.Is(err, auth.ErrSamePassword):
		q.Set("pw_error", "same")
	case err != nil:
		q.Set("pw_error", "failed")
	default:
		h.audit(r, user, audit.PasswordChange, user, "", nil)
		if token, err := h.auth.Login(user, next); err == nil {
			h.audit(r, user, audit.Login, "", "web admin", nil)
			h.handoff(w, r, token)
		}
		q = url.Values{"pw": {"changed"}}
	}
	backToUI(w, r, q)
}

// bearer returns the request's Bearer token.
func bearer(r *http.Request) string {
	const p = "Bearer "
	if h := r.Header.Get("Authorization"); len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

// handleRefresh extends the caller's web admin session.
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	token, err := h.auth.RefreshSession(bearer(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// handleLogout ends the caller's web admin session on the server.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	h.auth.Logout(bearer(r))
	w.WriteHeader(http.StatusNoContent)
}
