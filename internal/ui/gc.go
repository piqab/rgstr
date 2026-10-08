package ui

import (
	"errors"
	"net/http"
	"time"

	"rgstr/internal/maint"
	"rgstr/internal/meta"
	"rgstr/internal/storage"
)

type gcStatus struct {
	Interval    string       `json:"interval"`     // effective, Go duration ("0s" = off)
	FromUI      bool         `json:"from_ui"`      // set in the admin, not env
	EnvInterval string       `json:"env_interval"` // RGSTR_GC_INTERVAL
	GracePeriod string       `json:"grace_period"` // RGSTR_UPLOAD_TTL
	Running     bool         `json:"running"`
	NextRun     *time.Time   `json:"next_run,omitempty"`
	History     []meta.GCRun `json:"history"`
}

// handleGC reports the GC schedule and history.
func (h *Handler) handleGC(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.gcStatus())
}

func (h *Handler) gcStatus() gcStatus {
	interval, fromUI := h.maint.Interval()
	st := gcStatus{
		Interval:    interval.String(),
		FromUI:      fromUI,
		EnvInterval: h.auth.Config().GCInterval.String(),
		GracePeriod: h.auth.Config().UploadTTL.String(),
		Running:     h.maint.Running(),
		History:     h.maint.History(),
	}
	if st.History == nil {
		st.History = []meta.GCRun{}
	}
	if next := h.maint.NextRun(); !next.IsZero() {
		st.NextRun = &next
	}
	return st
}

// handleGCRun runs GC now and returns the run record.
func (h *Handler) handleGCRun(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	var req struct {
		DryRun      bool `json:"dry_run"`
		IgnoreGrace bool `json:"ignore_grace"`
	}
	if !decode(w, r, &req) {
		return
	}
	run, err := h.maint.Run("manual", user, storage.GCOptions{DryRun: req.DryRun, IgnoreGrace: req.IgnoreGrace})
	switch {
	case errors.Is(err, maint.ErrBusy):
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, run)
	}
}

// handleGCSettings changes the GC schedule. An empty interval restores
// RGSTR_GC_INTERVAL; "0" disables scheduled runs.
func (h *Handler) handleGCSettings(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	var req struct {
		Interval string `json:"interval"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := h.maint.SetInterval(req.Interval); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.gcStatus())
}
