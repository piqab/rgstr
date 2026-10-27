package ui

import (
	"encoding/json"
	"net/http"

	"rgstr/internal/scan"
	"rgstr/internal/storage"
)

type scanPlatform struct {
	Platform string        `json:"platform"`
	Digest   string        `json:"digest"`
	Summary  *scan.Summary `json:"summary"`
}

// handleScan returns the vulnerabilities of an image: for an index, each
// platform's summary and the findings of the one asked for (?platform=).
func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	repo, ref := q.Get("repo"), q.Get("ref")
	if repo == "" || ref == "" || !h.auth.Can(user, repo, "pull") {
		writeError(w, http.StatusNotFound, "image not found")
		return
	}
	resp := map[string]interface{}{"enabled": h.scanner != nil}
	if h.scanner == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	m, err := h.store.GetManifest(repo, ref)
	if err != nil {
		writeError(w, http.StatusNotFound, "image not found")
		return
	}
	resp["can_scan"] = h.auth.Can(user, repo, "push")
	target := m.Digest
	var doc manifestDoc
	if json.Unmarshal(m.Content, &doc) == nil && len(doc.Manifests) > 0 {
		platforms := []scanPlatform{}
		for _, c := range doc.Manifests {
			if c.Platform == nil || c.Platform.OS == "unknown" || !c.Digest.Valid() {
				continue
			}
			if _, err := h.store.GetManifest(repo, string(c.Digest)); err != nil {
				continue // not stored (a cache that never pulled this platform)
			}
			name := c.Platform.OS + "/" + c.Platform.Architecture
			if c.Platform.Variant != "" {
				name += "/" + c.Platform.Variant
			}
			platforms = append(platforms, scanPlatform{Platform: name, Digest: string(c.Digest),
				Summary: h.scanner.Summary(c.Digest)})
			if string(c.Digest) == q.Get("platform") || (q.Get("platform") == "" && target == m.Digest) {
				target = c.Digest
			}
		}
		resp["platforms"] = platforms
		resp["summary"] = h.scanner.ImageSummary(repo, m.Digest)
	} else {
		resp["summary"] = h.scanner.Summary(m.Digest)
	}
	resp["digest"] = string(target)
	if target != m.Digest || len(doc.Manifests) == 0 {
		if rep, err := h.scanner.Report(target); err == nil {
			if len(rep.Vulnerabilities) > 3000 {
				rep.Vulnerabilities = rep.Vulnerabilities[:3000]
				resp["truncated"] = true
			}
			resp["report"] = rep
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleScanRun scans an image now (users who may push to it).
func (h *Handler) handleScanRun(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	var req struct {
		Repo   string `json:"repo"`
		Digest string `json:"digest"`
	}
	if !decode(w, r, &req) {
		return
	}
	if h.scanner == nil {
		writeError(w, http.StatusBadRequest, "scanning is not configured (RGSTR_SCAN_ENABLED)")
		return
	}
	if !h.auth.Can(user, req.Repo, "push") && !h.auth.IsAdmin(user) {
		writeError(w, http.StatusForbidden, "you may not scan this repository")
		return
	}
	h.scanner.Enqueue(req.Repo, storage.Digest(req.Digest))
	w.WriteHeader(http.StatusAccepted)
}
