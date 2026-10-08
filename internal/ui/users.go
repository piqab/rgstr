package ui

import (
	"errors"
	"net/http"

	"rgstr/internal/auth"
)

// handleUsers lists users (administrators only).
func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	me, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	users := h.auth.Users()
	if users == nil {
		users = []auth.UserInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users":        users,
		"me":           me,
		"auth_enabled": h.auth.AuthEnabled(),
	})
}

// userError maps user management errors to HTTP statuses.
func userError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUserExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, auth.ErrUserNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errSelf), errors.Is(err, auth.ErrEnvUser), errors.Is(err, auth.ErrInvalidName),
		errors.Is(err, auth.ErrInvalidRole), errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

type userRequest struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Password   string `json:"password"`
	MustChange bool   `json:"must_change"`
}

// userAction runs fn for an administrator, with the request decoded.
func (h *Handler) userAction(w http.ResponseWriter, r *http.Request, fn func(me string, req userRequest) error) {
	if !method(w, r, http.MethodPost) {
		return
	}
	me, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	if !h.auth.AuthEnabled() {
		writeError(w, http.StatusBadRequest, "authentication is disabled: users have no effect")
		return
	}
	var req userRequest
	if !decode(w, r, &req) {
		return
	}
	if err := fn(me, req); err != nil {
		userError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errSelf = errors.New("you cannot do this to your own account")

func (h *Handler) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	h.userAction(w, r, func(_ string, req userRequest) error {
		return h.auth.CreateUser(req.Name, req.Role, req.Password, req.MustChange)
	})
}

func (h *Handler) handleUserRole(w http.ResponseWriter, r *http.Request) {
	h.userAction(w, r, func(me string, req userRequest) error {
		if req.Name == me {
			return errSelf
		}
		return h.auth.SetRole(req.Name, req.Role)
	})
}

func (h *Handler) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	h.userAction(w, r, func(_ string, req userRequest) error {
		return h.auth.ResetPassword(req.Name, req.Password, req.MustChange)
	})
}

func (h *Handler) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	h.userAction(w, r, func(me string, req userRequest) error {
		if req.Name == me {
			return errSelf
		}
		return h.auth.DeleteUser(req.Name)
	})
}
