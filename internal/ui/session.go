package ui

import (
	"errors"
	"net/http"

	"rgstr/internal/audit"
	"rgstr/internal/auth"
)

type meResponse struct {
	AuthEnabled bool   `json:"auth_enabled"`
	User        string `json:"user,omitempty"`
	Admin       bool   `json:"admin"`
}

// handleMe reports whether auth is on and, if the request carries a valid
// token, who the user is and whether they administer the registry.
func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	resp := meResponse{AuthEnabled: h.auth.AuthEnabled()}
	if !resp.AuthEnabled {
		resp.Admin = true
	} else if subject, _, ok := h.auth.Authenticate(r); ok && subject != "" {
		resp.User = subject
		resp.Admin = h.auth.IsAdmin(subject)
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
		"token": token,
		"user":  req.Username,
		"admin": h.auth.IsAdmin(req.Username),
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
