package ui

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/backup"
	"rgstr/internal/ops"
)

// handleBackup reports the backup settings, state and stored backups
// (administrators only).
func (h *Handler) handleBackup(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	if h.backup == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	resp := map[string]interface{}{"enabled": true, "status": h.backup.Status()}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	objs, err := backup.List(ctx, h.backup.Target())
	if err != nil {
		resp["list_error"] = err.Error()
	}
	// Newest first.
	for i, j := 0, len(objs)-1; i < j; i, j = i+1, j-1 {
		objs[i], objs[j] = objs[j], objs[i]
	}
	if objs == nil {
		objs = []backup.Object{}
	}
	resp["backups"] = objs
	writeJSON(w, http.StatusOK, resp)
}

// handleBackupRun starts a backup now. It runs in the background (large
// registries take a while); the page follows the status.
func (h *Handler) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	if h.backup == nil {
		writeError(w, http.StatusBadRequest, "backups are not configured (RGSTR_BACKUP_TARGET)")
		return
	}
	if h.backup.Status().Running {
		writeError(w, http.StatusConflict, backup.ErrBusy.Error())
		return
	}
	actor := ops.ActorFrom(r, user)
	go func() {
		obj, err := h.backup.Run(context.Background(), user)
		if errors.Is(err, backup.ErrBusy) {
			return
		}
		if err != nil {
			log.Printf("backup: %v", err)
		}
		h.ops.Audit(actor, audit.BackupRun, h.backup.Target().String(), obj.Name, err)
	}()
	w.WriteHeader(http.StatusAccepted)
}
