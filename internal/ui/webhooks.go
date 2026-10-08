package ui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/meta"
	"rgstr/internal/webhook"
)

type webhookInfo struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	URL        string             `json:"url"`
	Project    string             `json:"project"`
	Events     []string           `json:"events"`
	Format     string             `json:"format"`
	HasAuth    bool               `json:"has_auth"` // the header itself is never returned
	SkipVerify bool               `json:"skip_verify"`
	Disabled   bool               `json:"disabled"`
	CreatedBy  string             `json:"created_by"`
	Deliveries []webhook.Delivery `json:"deliveries"`
}

// managedProjects lists the projects whose webhooks user may manage.
func (h *Handler) managedProjects(user string) []string {
	out := []string{}
	for _, p := range h.meta.Projects() {
		if h.auth.IsProjectAdmin(user, p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}

// canManageHook: registry admins manage every webhook; project admins
// manage their projects' webhooks.
func (h *Handler) canManageHook(user, project string) bool {
	if h.auth.IsAdmin(user) {
		return true
	}
	return project != "" && h.auth.IsProjectAdmin(user, project)
}

// handleWebhooks lists the webhooks the user may manage, with recent
// deliveries.
func (h *Handler) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	projects := h.managedProjects(user)
	isAdmin := h.auth.IsAdmin(user)
	if !isAdmin && len(projects) == 0 {
		writeError(w, http.StatusForbidden, "you do not manage any project")
		return
	}
	var hooks []meta.Webhook
	h.meta.View(func(d *meta.Data) { hooks = append(hooks, d.Webhooks...) })
	out := []webhookInfo{}
	for _, wh := range hooks {
		if !h.canManageHook(user, wh.Project) {
			continue
		}
		deliveries := h.hooks.Deliveries(wh.ID)
		if deliveries == nil {
			deliveries = []webhook.Delivery{}
		}
		out = append(out, webhookInfo{
			ID: wh.ID, Name: wh.Name, URL: wh.URL, Project: wh.Project, Events: wh.Events, Format: wh.Format,
			HasAuth: wh.AuthHeader != "", SkipVerify: wh.SkipVerify, Disabled: wh.Disabled,
			CreatedBy: wh.CreatedBy, Deliveries: deliveries,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"webhooks": out, "projects": projects, "is_admin": isAdmin,
	})
}

type webhookRequest struct {
	ID         string   `json:"id"` // empty: create
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Project    string   `json:"project"`
	Events     []string `json:"events"`
	Format     string   `json:"format"`
	AuthHeader *string  `json:"auth_header"` // nil keeps the current header
	SkipVerify bool     `json:"skip_verify"`
	Disabled   bool     `json:"disabled"`
}

var errHookNotFound = errors.New("webhook not found")

func validateHook(req *webhookRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return errors.New("name is required")
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("URL must start with http:// or https://")
	}
	if len(req.Events) == 0 {
		return errors.New("choose at least one event")
	}
	for _, e := range req.Events {
		switch e {
		case meta.EventPush, meta.EventPull, meta.EventDelete, meta.EventQuotaExceeded:
		default:
			return errors.New("unknown event " + e)
		}
	}
	if req.Format == "" {
		req.Format = "default"
	}
	if req.Format != "default" && req.Format != "slack" {
		return errors.New("format must be default or slack")
	}
	return nil
}

// handleWebhookSave creates or updates a webhook.
func (h *Handler) handleWebhookSave(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	var req webhookRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.canManageHook(user, req.Project) {
		writeError(w, http.StatusForbidden, "you are not allowed to manage webhooks of this scope")
		return
	}
	if err := validateHook(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err := h.meta.Update(func(d *meta.Data) error {
		if req.ID == "" {
			id := make([]byte, 8)
			rand.Read(id)
			wh := meta.Webhook{ID: hex.EncodeToString(id), CreatedAt: time.Now().UTC(), CreatedBy: user}
			req.ID = wh.ID
			apply(&wh, &req)
			d.Webhooks = append(d.Webhooks, wh)
			return nil
		}
		for i := range d.Webhooks {
			if d.Webhooks[i].ID == req.ID {
				// Moving a webhook needs rights on its current scope too.
				if !h.canManageHook(user, d.Webhooks[i].Project) {
					return errForbidden
				}
				apply(&d.Webhooks[i], &req)
				return nil
			}
		}
		return errHookNotFound
	})
	h.audit(r, user, audit.WebhookChange, req.Name, req.URL+" ["+strings.Join(req.Events, ",")+"]", err)
	switch {
	case errors.Is(err, errHookNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errForbidden):
		writeError(w, http.StatusForbidden, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]string{"id": req.ID})
	}
}

func apply(wh *meta.Webhook, req *webhookRequest) {
	wh.Name, wh.URL, wh.Project, wh.Events, wh.Format = req.Name, req.URL, req.Project, req.Events, req.Format
	wh.SkipVerify, wh.Disabled = req.SkipVerify, req.Disabled
	if req.AuthHeader != nil {
		wh.AuthHeader = *req.AuthHeader
	}
}

// findHook returns a webhook the user may manage.
func (h *Handler) findHook(user, id string) (meta.Webhook, error) {
	var found *meta.Webhook
	h.meta.View(func(d *meta.Data) {
		for _, wh := range d.Webhooks {
			if wh.ID == id {
				wh := wh
				found = &wh
			}
		}
	})
	if found == nil {
		return meta.Webhook{}, errHookNotFound
	}
	if !h.canManageHook(user, found.Project) {
		return meta.Webhook{}, errForbidden
	}
	return *found, nil
}

func (h *Handler) handleWebhookDelete(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &req) {
		return
	}
	wh, err := h.findHook(user, req.ID)
	if err == nil {
		err = h.meta.Update(func(d *meta.Data) error {
			for i := range d.Webhooks {
				if d.Webhooks[i].ID == req.ID {
					d.Webhooks = append(d.Webhooks[:i], d.Webhooks[i+1:]...)
					return nil
				}
			}
			return errHookNotFound
		})
	}
	h.audit(r, user, audit.WebhookDelete, wh.Name, wh.URL, err)
	switch {
	case errors.Is(err, errHookNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errForbidden):
		writeError(w, http.StatusForbidden, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleWebhookTest sends a ping event now and returns the delivery.
func (h *Handler) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &req) {
		return
	}
	wh, err := h.findHook(user, req.ID)
	switch {
	case errors.Is(err, errHookNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeJSON(w, http.StatusOK, h.hooks.Test(wh, user))
	}
}
