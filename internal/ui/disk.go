package ui

import (
	"net/http"

	"rgstr/internal/maint"
)

// LowDiskPercent is the free-space share below which admins are warned.
const LowDiskPercent = 10

type diskResponse struct {
	Supported bool            `json:"supported"`
	Total     uint64          `json:"total"`
	Free      uint64          `json:"free"`
	Low       bool            `json:"low"`
	Data      int64           `json:"data_bytes,omitempty"` // details only
	Estimate  *maint.Estimate `json:"estimate,omitempty"`   // details only
	Pending   []maint.Pending `json:"pending,omitempty"`    // details only
}

// handleDisk reports disk space (administrators only). ?data=1 adds the
// registry's data size; ?details=1 also what GC would free and deleted data
// waiting for GC.
func (h *Handler) handleDisk(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	d, err := h.store.Disk()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := diskResponse{Supported: d.Supported, Total: d.Total, Free: d.Free}
	resp.Low = d.Supported && d.Total > 0 && d.Free*100 < d.Total*LowDiskPercent
	q := r.URL.Query()
	if q.Get("details") != "" || q.Get("data") != "" {
		resp.Data = h.store.DataSize()
	}
	if q.Get("details") != "" {
		resp.Pending = h.maint.Pending()
		if est, err := h.maint.Estimate(); err == nil {
			resp.Estimate = &est
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// freeNow runs GC for just-deleted refs when an administrator asked for
// it, and describes the result for the response.
func (h *Handler) freeNow(user string, want bool, refs []string) map[string]interface{} {
	if !want || len(refs) == 0 || !h.auth.IsAdmin(user) {
		return nil
	}
	run, err := h.maint.FreeNow(user, refs)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	return map[string]interface{}{"bytes_freed": run.BytesFreed, "blobs_removed": run.BlobsRemoved}
}
