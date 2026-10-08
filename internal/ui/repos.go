package ui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"rgstr/internal/ops"
	"rgstr/internal/storage"
)

// ─── Repository list ──────────────────────────────────────────────────────────

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
	PushedAt  time.Time      `json:"pushed_at"`
	Error     string         `json:"error,omitempty"`
}

type repoInfo struct {
	Name      string    `json:"name"`
	Pulls     int64     `json:"pulls"`
	CanPush   bool      `json:"can_push"`
	CanDelete bool      `json:"can_delete"`
	Tags      []tagInfo `json:"tags"`
}

type reposResponse struct {
	Repositories []repoInfo `json:"repositories"`
	TotalPulls   int64      `json:"total_pulls"`
}

// handleRepos returns every tagged repository the user may pull, with its
// tags, digests, sizes and platforms, in one response.
func (h *Handler) handleRepos(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	names, err := h.store.ListRepositories()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	snap := h.counter.Snapshot()

	resp := reposResponse{Repositories: []repoInfo{}}
	for _, name := range names {
		if !h.auth.Can(user, name, "pull") {
			continue
		}
		resp.TotalPulls += snap.Pulls[name]
		tags, _ := h.store.RepoTags(name)
		if len(tags) == 0 {
			continue
		}
		sort.Slice(tags, func(i, j int) bool { return tags[i].Name < tags[j].Name })
		repo := repoInfo{
			Name:      name,
			Pulls:     snap.Pulls[name],
			CanPush:   h.auth.Can(user, name, "push"),
			CanDelete: h.auth.Can(user, name, "delete"),
		}
		for _, t := range tags {
			info := h.describeTag(name, t.Name)
			info.PushedAt = t.PushedAt
			repo.Tags = append(repo.Tags, info)
		}
		resp.Repositories = append(resp.Repositories, repo)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── Deletion ─────────────────────────────────────────────────────────────────

// canDelete checks the session may delete in repo, writing 401/403 if not.
func (h *Handler) canDelete(w http.ResponseWriter, r *http.Request, repo string) (ops.Actor, bool) {
	user, ok := h.session(w, r)
	if !ok {
		return ops.Actor{}, false
	}
	if repo == "" || !h.auth.Can(user, repo, "delete") {
		writeError(w, http.StatusForbidden, "you are not allowed to delete in this repository")
		return ops.Actor{}, false
	}
	return ops.ActorFrom(r, user), true
}

// opError maps an ops error to an HTTP status.
func opError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ops.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

type tagResult struct {
	Tag   string `json:"tag"`
	Error string `json:"error,omitempty"`
}

// handleDeleteTags deletes several tags of one repository. Each tag is
// deleted independently; the response reports per-tag errors.
func (h *Handler) handleDeleteTags(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Repo string   `json:"repo"`
		Tags []string `json:"tags"`
	}
	if !decode(w, r, &req) {
		return
	}
	actor, ok := h.canDelete(w, r, req.Repo)
	if !ok {
		return
	}
	results := []tagResult{}
	for _, tag := range req.Tags {
		res := tagResult{Tag: tag}
		if err := h.ops.DeleteTag(actor, req.Repo, tag); err != nil {
			res.Error = err.Error()
		}
		results = append(results, res)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"results": results})
}

// handleDeleteImage deletes a manifest by digest with all its tags.
func (h *Handler) handleDeleteImage(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Repo   string `json:"repo"`
		Digest string `json:"digest"`
	}
	if !decode(w, r, &req) {
		return
	}
	actor, ok := h.canDelete(w, r, req.Repo)
	if !ok {
		return
	}
	removed, err := h.ops.DeleteImage(actor, req.Repo, storage.Digest(req.Digest))
	if err != nil {
		opError(w, err)
		return
	}
	if removed == nil {
		removed = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"removed_tags": removed})
}

// handleDeleteRepo deletes a whole repository.
func (h *Handler) handleDeleteRepo(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Repo string `json:"repo"`
	}
	if !decode(w, r, &req) {
		return
	}
	actor, ok := h.canDelete(w, r, req.Repo)
	if !ok {
		return
	}
	if err := h.ops.DeleteRepository(actor, req.Repo); err != nil {
		opError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Manifest inspection ──────────────────────────────────────────────────────

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
