package ui

import (
	"fmt"
	"net/http"

	"rgstr/internal/audit"
	"rgstr/internal/meta"
	"rgstr/internal/policy"
)

type policiesResponse struct {
	Retention        []meta.RetentionRule `json:"retention"`
	Immutable        []meta.ImmutableRule `json:"immutable"`
	RetentionHistory []meta.RetentionRun  `json:"retention_history"`
	GCInterval       string               `json:"gc_interval"` // retention runs before each scheduled GC
}

func (h *Handler) policies() policiesResponse {
	resp := policiesResponse{
		Retention:        []meta.RetentionRule{},
		Immutable:        []meta.ImmutableRule{},
		RetentionHistory: []meta.RetentionRun{},
	}
	h.meta.View(func(d *meta.Data) {
		resp.Retention = append(resp.Retention, d.Retention...)
		resp.Immutable = append(resp.Immutable, d.Immutable...)
		resp.RetentionHistory = append(resp.RetentionHistory, d.RetentionHistory...)
	})
	interval, _ := h.maint.Interval()
	resp.GCInterval = interval.String()
	return resp
}

// handlePolicies returns retention and immutability rules.
func (h *Handler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.policies())
}

// handleRetentionRules replaces the retention rules.
func (h *Handler) handleRetentionRules(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Rules []meta.RetentionRule `json:"rules"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := policy.ValidateRetention(req.Rules); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err := h.meta.Update(func(d *meta.Data) error { d.Retention = req.Rules; return nil })
	h.audit(r, user, audit.PolicyChange, "retention", fmt.Sprintf("%d rule(s)", len(req.Rules)), err)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.policies())
}

// handleImmutableRules replaces the immutability rules.
func (h *Handler) handleImmutableRules(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Rules []meta.ImmutableRule `json:"rules"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := policy.ValidateImmutable(req.Rules); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err := h.meta.Update(func(d *meta.Data) error { d.Immutable = req.Rules; return nil })
	h.audit(r, user, audit.PolicyChange, "immutable", fmt.Sprintf("%d rule(s)", len(req.Rules)), err)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.policies())
}

// handleRetentionRun applies retention now (or as a dry run).
func (h *Handler) handleRetentionRun(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	if !decode(w, r, &req) {
		return
	}
	run, err := h.maint.RunRetention("manual", user, req.DryRun)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}
