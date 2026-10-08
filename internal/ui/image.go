package ui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"rgstr/internal/storage"
)

// imageResponse describes one manifest: an index (platforms) or an image.
type imageResponse struct {
	Repo      string          `json:"repo"`
	Ref       string          `json:"ref"`
	Digest    string          `json:"digest"`
	MediaType string          `json:"media_type"`
	Size      int64           `json:"size"`
	Tags      []string        `json:"tags"`      // tags pointing to this digest
	Immutable bool            `json:"immutable"` // ref is an immutable tag
	Platforms []platformRef   `json:"platforms,omitempty"`
	Image     *imageDetails   `json:"image,omitempty"`
	Raw       json.RawMessage `json:"manifest"`
}

type platformRef struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
}

type imageDetails struct {
	Created      *time.Time        `json:"created,omitempty"`
	Author       string            `json:"author,omitempty"`
	OS           string            `json:"os,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	Variant      string            `json:"variant,omitempty"`
	Entrypoint   []string          `json:"entrypoint"`
	Cmd          []string          `json:"cmd"`
	Env          []string          `json:"env"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	User         string            `json:"user,omitempty"`
	ExposedPorts []string          `json:"exposed_ports"`
	Volumes      []string          `json:"volumes"`
	Labels       map[string]string `json:"labels"`
	Layers       []layerInfo       `json:"layers"`
}

// layerInfo is a build step: a history entry, with the layer it created
// (empty for metadata-only steps such as ENV or CMD).
type layerInfo struct {
	CreatedBy string     `json:"created_by,omitempty"`
	Created   *time.Time `json:"created,omitempty"`
	Comment   string     `json:"comment,omitempty"`
	Digest    string     `json:"digest,omitempty"`
	Size      int64      `json:"size"`
	Empty     bool       `json:"empty"`
}

// imageConfig is the part of an OCI/Docker image config we show.
type imageConfig struct {
	Created      *time.Time `json:"created"`
	Author       string     `json:"author"`
	OS           string     `json:"os"`
	Architecture string     `json:"architecture"`
	Variant      string     `json:"variant"`
	Config       struct {
		Entrypoint   []string               `json:"Entrypoint"`
		Cmd          []string               `json:"Cmd"`
		Env          []string               `json:"Env"`
		WorkingDir   string                 `json:"WorkingDir"`
		User         string                 `json:"User"`
		ExposedPorts map[string]interface{} `json:"ExposedPorts"`
		Volumes      map[string]interface{} `json:"Volumes"`
		Labels       map[string]string      `json:"Labels"`
	} `json:"config"`
	History []struct {
		Created    *time.Time `json:"created"`
		CreatedBy  string     `json:"created_by"`
		Comment    string     `json:"comment"`
		EmptyLayer bool       `json:"empty_layer"`
	} `json:"history"`
}

// handleImage describes a manifest for the image page.
// Query: repo, ref (tag or digest).
func (h *Handler) handleImage(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	repo, ref := r.URL.Query().Get("repo"), r.URL.Query().Get("ref")
	if repo == "" || ref == "" || !h.auth.Can(user, repo, "pull") {
		writeError(w, http.StatusNotFound, "image not found")
		return
	}
	m, err := h.store.GetManifest(repo, ref)
	if err != nil {
		if errors.Is(err, storage.ErrManifestNotFound) {
			writeError(w, http.StatusNotFound, "image not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var doc manifestDoc
	if err := json.Unmarshal(m.Content, &doc); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "unreadable manifest")
		return
	}

	resp := imageResponse{
		Repo: repo, Ref: ref, Digest: string(m.Digest), MediaType: m.ContentType,
		Tags: []string{}, Raw: m.Content,
	}
	if !storage.Digest(ref).Valid() {
		resp.Immutable = h.ops.IsImmutable(repo, ref)
	}
	if tags, err := h.store.RepoTags(repo); err == nil {
		for _, t := range tags {
			if t.Digest == m.Digest {
				resp.Tags = append(resp.Tags, t.Name)
			}
		}
		sort.Strings(resp.Tags)
	}

	if len(doc.Manifests) > 0 {
		info := h.describeTag(repo, string(m.Digest))
		resp.Size = info.Size
		for _, c := range doc.Manifests {
			if c.Platform == nil || c.Platform.OS == "unknown" {
				continue // attestation
			}
			p := platformRef{OS: c.Platform.OS, Architecture: c.Platform.Architecture,
				Variant: c.Platform.Variant, Digest: string(c.Digest)}
			if c.Digest.Valid() {
				if cm, err := h.store.GetManifest(repo, string(c.Digest)); err == nil {
					var cd manifestDoc
					if json.Unmarshal(cm.Content, &cd) == nil {
						p.Size = sumSizes(imageBlobs(&cd))
					}
				}
			}
			resp.Platforms = append(resp.Platforms, p)
		}
	} else {
		resp.Size = sumSizes(imageBlobs(&doc))
		resp.Image = h.imageDetails(&doc)
	}
	writeJSON(w, http.StatusOK, resp)
}

// imageDetails reads an image's config blob and pairs history with layers.
func (h *Handler) imageDetails(doc *manifestDoc) *imageDetails {
	d := &imageDetails{
		Entrypoint: []string{}, Cmd: []string{}, Env: []string{},
		ExposedPorts: []string{}, Volumes: []string{}, Labels: map[string]string{},
	}
	var cfg imageConfig
	if doc.Config != nil && doc.Config.Digest.Valid() {
		if f, err := h.store.OpenBlob(doc.Config.Digest); err == nil {
			json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(&cfg)
			f.Close()
		}
	}
	d.Created, d.Author = cfg.Created, cfg.Author
	d.OS, d.Architecture, d.Variant = cfg.OS, cfg.Architecture, cfg.Variant
	c := cfg.Config
	if c.Entrypoint != nil {
		d.Entrypoint = c.Entrypoint
	}
	if c.Cmd != nil {
		d.Cmd = c.Cmd
	}
	if c.Env != nil {
		d.Env = c.Env
	}
	if c.Labels != nil {
		d.Labels = c.Labels
	}
	d.WorkingDir, d.User = c.WorkingDir, c.User
	for p := range c.ExposedPorts {
		d.ExposedPorts = append(d.ExposedPorts, p)
	}
	for v := range c.Volumes {
		d.Volumes = append(d.Volumes, v)
	}
	sort.Strings(d.ExposedPorts)
	sort.Strings(d.Volumes)

	// Each non-empty history entry produced the next layer, in order.
	li := 0
	for _, hst := range cfg.History {
		step := layerInfo{CreatedBy: cleanCreatedBy(hst.CreatedBy), Created: hst.Created,
			Comment: hst.Comment, Empty: hst.EmptyLayer}
		if !hst.EmptyLayer && li < len(doc.Layers) {
			step.Digest = string(doc.Layers[li].Digest)
			step.Size = doc.Layers[li].Size
			li++
		}
		d.Layers = append(d.Layers, step)
	}
	// Layers without history (or more layers than history entries).
	for ; li < len(doc.Layers); li++ {
		d.Layers = append(d.Layers, layerInfo{Digest: string(doc.Layers[li].Digest), Size: doc.Layers[li].Size})
	}
	if d.Layers == nil {
		d.Layers = []layerInfo{}
	}
	return d
}

// cleanCreatedBy strips the shell wrapper Docker adds to build steps.
func cleanCreatedBy(s string) string {
	s = strings.TrimPrefix(s, "/bin/sh -c #(nop) ")
	s = strings.TrimPrefix(s, "/bin/sh -c ")
	return strings.TrimSpace(s)
}
