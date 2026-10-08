// Package ui serves a minimal web interface for the registry.
// The UI is a single embedded HTML page with vanilla JS backed by a small
// JSON API under /ui/api/.
package ui

import (
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"rgstr/internal/auth"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

//go:embed index.html
var page []byte

// Handler serves the web UI and its API.
type Handler struct {
	auth    *auth.Handler
	store   *storage.Filesystem
	counter *stats.Counter
}

// New creates a UI handler.
func New(authHandler *auth.Handler, store *storage.Filesystem, counter *stats.Counter) *Handler {
	return &Handler{auth: authHandler, store: store, counter: counter}
}

// Mount registers the UI handlers on mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/ui", h.servePage)
	mux.HandleFunc("/ui/", h.servePage)
	mux.HandleFunc("/ui/api/me", h.handleMe)
	mux.HandleFunc("/ui/api/login", h.handleLogin)
	mux.HandleFunc("/ui/api/repos", h.handleRepos)
}

func (h *Handler) servePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page)
}

// ─── Session ──────────────────────────────────────────────────────────────────

type meResponse struct {
	AuthEnabled bool     `json:"auth_enabled"`
	User        string   `json:"user,omitempty"`
	Actions     []string `json:"actions"`
}

// handleMe reports whether auth is on and, if the request carries a valid
// token, who the user is and which repository actions they may perform.
func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	resp := meResponse{AuthEnabled: h.auth.AuthEnabled(), Actions: []string{}}
	if !resp.AuthEnabled {
		resp.Actions = h.auth.UserActions("")
	} else if subject, access, ok := h.auth.Authenticate(r); ok && subject != "" {
		resp.User = subject
		resp.Actions = repoActions(access)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleLogin exchanges a username and password for a session token, so the
// browser keeps a short-lived token instead of the password.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	token, ok := h.auth.Login(req.Username, req.Password)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":   token,
		"user":    req.Username,
		"actions": h.auth.UserActions(req.Username),
	})
}

// repoActions lists the actions access grants on every repository.
func repoActions(access []auth.Access) []string {
	out := []string{}
	for _, act := range []string{"pull", "push", "delete"} {
		if auth.Allowed(access, "repository", "*", act) {
			out = append(out, act)
		}
	}
	return out
}

// ─── Repositories ─────────────────────────────────────────────────────────────

type platformInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	Size         int64  `json:"size"`
}

type tagInfo struct {
	Name      string         `json:"name"`
	Digest    string         `json:"digest,omitempty"`
	MediaType string         `json:"media_type,omitempty"`
	Size      int64          `json:"size"`
	Platforms []platformInfo `json:"platforms"`
	Error     string         `json:"error,omitempty"`
}

type repoInfo struct {
	Name  string    `json:"name"`
	Pulls int64     `json:"pulls"`
	Tags  []tagInfo `json:"tags"`
}

type reposResponse struct {
	Repositories []repoInfo `json:"repositories"`
	TotalPulls   int64      `json:"total_pulls"`
}

// handleRepos returns every tagged repository with its tags, digests, sizes
// and platforms in one response.
func (h *Handler) handleRepos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.auth.AuthEnabled() {
		_, access, ok := h.auth.Authenticate(r)
		if !ok || !auth.Allowed(access, "registry", "catalog", "*") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
	}

	names, err := h.store.ListRepositories()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	snap := h.counter.Snapshot()

	resp := reposResponse{Repositories: []repoInfo{}}
	for _, name := range names {
		resp.TotalPulls += snap.Pulls[name]
		tags, _ := h.store.ListTags(name)
		if len(tags) == 0 {
			continue
		}
		repo := repoInfo{Name: name, Pulls: snap.Pulls[name]}
		for _, tag := range tags {
			repo.Tags = append(repo.Tags, h.describeTag(name, tag))
		}
		resp.Repositories = append(resp.Repositories, repo)
	}
	writeJSON(w, http.StatusOK, resp)
}

type descriptor struct {
	MediaType string         `json:"mediaType"`
	Digest    storage.Digest `json:"digest"`
	Size      int64          `json:"size"`
	Platform  *platformInfo  `json:"platform,omitempty"`
}

type manifestDoc struct {
	MediaType string       `json:"mediaType"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

// describeTag resolves a tag to its digest, size and platforms. For a
// multi-platform index, each child manifest is sized separately and the tag
// size counts every distinct blob once.
func (h *Handler) describeTag(repo, tag string) tagInfo {
	info := tagInfo{Name: tag, Platforms: []platformInfo{}}
	m, err := h.store.GetManifest(repo, tag)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Digest = string(m.Digest)
	info.MediaType = m.ContentType

	var doc manifestDoc
	if err := json.Unmarshal(m.Content, &doc); err != nil {
		info.Error = "unreadable manifest"
		return info
	}

	if len(doc.Manifests) == 0 {
		blobs := imageBlobs(&doc)
		info.Size = sumSizes(blobs)
		if p := h.configPlatform(&doc); p != nil {
			p.Size = info.Size
			info.Platforms = append(info.Platforms, *p)
		}
		return info
	}

	seen := map[storage.Digest]int64{}
	for _, child := range doc.Manifests {
		// Skip attestation manifests (buildx provenance/SBOM).
		if child.Platform == nil || child.Platform.OS == "unknown" {
			continue
		}
		p := *child.Platform
		if !child.Digest.Valid() {
			info.Platforms = append(info.Platforms, p)
			continue
		}
		if cm, err := h.store.GetManifest(repo, string(child.Digest)); err == nil {
			var cd manifestDoc
			if json.Unmarshal(cm.Content, &cd) == nil {
				blobs := imageBlobs(&cd)
				p.Size = sumSizes(blobs)
				for d, size := range blobs {
					seen[d] = size
				}
			}
		}
		info.Platforms = append(info.Platforms, p)
	}
	info.Size = sumSizes(seen)
	return info
}

// imageBlobs returns the config and layer blobs of an image manifest.
func imageBlobs(doc *manifestDoc) map[storage.Digest]int64 {
	blobs := map[storage.Digest]int64{}
	if doc.Config != nil {
		blobs[doc.Config.Digest] = doc.Config.Size
	}
	for _, l := range doc.Layers {
		blobs[l.Digest] = l.Size
	}
	return blobs
}

func sumSizes(blobs map[storage.Digest]int64) int64 {
	var total int64
	for _, size := range blobs {
		total += size
	}
	return total
}

// configPlatform reads os/architecture from a single-platform image's config
// blob. Returns nil when the config is missing or not an image config.
func (h *Handler) configPlatform(doc *manifestDoc) *platformInfo {
	if doc.Config == nil || !doc.Config.Digest.Valid() || !strings.Contains(doc.Config.MediaType, "config") {
		return nil
	}
	f, err := h.store.OpenBlob(doc.Config.Digest)
	if err != nil {
		return nil
	}
	defer f.Close()
	var p platformInfo
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&p); err != nil || p.OS == "" {
		return nil
	}
	return &p
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
