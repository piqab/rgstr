package ui

import (
	"net/http"
	"strconv"
	"time"

	"rgstr/internal/audit"
)

var auditActions = []string{
	audit.Push, audit.Pull, audit.DeleteTag, audit.DeleteImage, audit.DeleteRepo,
	audit.Login, audit.LoginFailed, audit.PasswordChange,
	audit.UserCreate, audit.UserDelete, audit.UserRole, audit.UserPassword,
	audit.GCRun, audit.GCSettings, audit.RetentionRun, audit.PolicyChange,
	audit.ProjectCreate, audit.ProjectUpdate, audit.ProjectDelete, audit.ProjectMember,
	audit.RobotCreate, audit.RobotUpdate, audit.RobotSecret, audit.RobotDelete,
	audit.WebhookChange, audit.WebhookDelete,
}

// handleAudit returns audit entries, newest first (administrators only).
// Query: user, action, q (text), before (RFC 3339, for paging), limit.
func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	q := r.URL.Query()
	query := audit.Query{User: q.Get("user"), Action: q.Get("action"), Text: q.Get("q")}
	if b := q.Get("before"); b != "" {
		t, err := time.Parse(time.RFC3339Nano, b)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad before: "+err.Error())
			return
		}
		query.Before = t
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 1000 {
		query.Limit = n
	}
	entries, err := h.ops.AuditLog().Find(query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries, "actions": auditActions})
}
