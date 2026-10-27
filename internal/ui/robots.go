package ui

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/auth"
	"rgstr/internal/meta"
)

var robotNameRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

type robotInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions []meta.RobotPermission `json:"permissions"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Expired     bool                   `json:"expired"`
	Disabled    bool                   `json:"disabled"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   string                 `json:"created_by"`
}

// handleRobots lists robot accounts (administrators only).
func (h *Handler) handleRobots(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.adminSession(w, r); !ok {
		return
	}
	now := time.Now()
	out := []robotInfo{}
	h.meta.View(func(d *meta.Data) {
		for _, rb := range d.Robots {
			out = append(out, robotInfo{
				Name: rb.Name, Description: rb.Description,
				Permissions: append([]meta.RobotPermission{}, rb.Permissions...),
				ExpiresAt:   rb.ExpiresAt, Expired: rb.ExpiresAt != nil && !now.Before(*rb.ExpiresAt),
				Disabled: rb.Disabled, CreatedAt: rb.CreatedAt, CreatedBy: rb.CreatedBy,
			})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	projects := []string{}
	for _, p := range h.meta.Projects() {
		projects = append(projects, p.Name)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"robots": out, "projects": projects})
}

type robotRequest struct {
	Name        string                 `json:"name"` // full name for update/secret/delete
	Description string                 `json:"description"`
	Permissions []meta.RobotPermission `json:"permissions"`
	ExpiresDays *int                   `json:"expires_days"` // nil = keep, 0 = never
	Disabled    bool                   `json:"disabled"`
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validatePermissions(perms []meta.RobotPermission) error {
	if len(perms) == 0 {
		return errors.New("add at least one permission")
	}
	for _, p := range perms {
		if p.Project != "*" && !projectNameRe.MatchString(p.Project) {
			return fmt.Errorf("invalid project %q", p.Project)
		}
		if len(p.Actions) == 0 {
			return fmt.Errorf("project %s: choose at least one action", p.Project)
		}
		if p.Repos != "" && !meta.ValidRepoPattern(p.Repos) {
			return fmt.Errorf("project %s: repositories %q is not a pattern such as app-* or app/**", p.Project, p.Repos)
		}
		for _, a := range p.Actions {
			if a != "pull" && a != "push" && a != "delete" {
				return fmt.Errorf("unknown action %q", a)
			}
		}
	}
	return nil
}

func expiry(days *int) (*time.Time, error) {
	if days == nil || *days == 0 {
		return nil, nil
	}
	if *days < 0 {
		return nil, errors.New("expiry must not be negative")
	}
	t := time.Now().UTC().Add(time.Duration(*days) * 24 * time.Hour)
	return &t, nil
}

func permsDetail(perms []meta.RobotPermission) string {
	var parts []string
	for _, p := range perms {
		scope := p.Project
		if p.Repos != "" {
			scope += " (" + p.Repos + ")"
		}
		parts = append(parts, scope+": "+strings.Join(p.Actions, ","))
	}
	return strings.Join(parts, "; ")
}

// robotAction runs fn for an administrator and audits it. fn may return a
// JSON body; otherwise the response is 204.
func (h *Handler) robotAction(w http.ResponseWriter, r *http.Request, action string,
	fn func(user string, req *robotRequest) (resp interface{}, detail string, err error)) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	var req robotRequest
	if !decode(w, r, &req) {
		return
	}
	resp, detail, err := fn(user, &req)
	h.audit(r, user, action, req.Name, detail, err)
	switch {
	case errors.Is(err, errRobotNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
	case resp != nil:
		writeJSON(w, http.StatusOK, resp)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

var errRobotNotFound = errors.New("robot account not found")

func (h *Handler) handleRobotCreate(w http.ResponseWriter, r *http.Request) {
	h.robotAction(w, r, audit.RobotCreate, func(user string, req *robotRequest) (interface{}, string, error) {
		short := strings.TrimPrefix(req.Name, meta.RobotPrefix)
		if len(short) > 64 || !robotNameRe.MatchString(short) {
			return nil, "", errors.New("invalid name: lowercase letters, digits and . _ - between them")
		}
		req.Name = meta.RobotPrefix + short
		if err := validatePermissions(req.Permissions); err != nil {
			return nil, "", err
		}
		exp, err := expiry(req.ExpiresDays)
		if err != nil {
			return nil, "", err
		}
		secret, err := newSecret()
		if err != nil {
			return nil, "", err
		}
		err = h.meta.Update(func(d *meta.Data) error {
			if _, exists := d.Robots[req.Name]; exists {
				return errors.New("robot account already exists")
			}
			if d.Robots == nil {
				d.Robots = map[string]meta.Robot{}
			}
			d.Robots[req.Name] = meta.Robot{
				Name: req.Name, Description: req.Description, SecretHash: auth.HashSecret(secret),
				Permissions: req.Permissions, ExpiresAt: exp, CreatedAt: time.Now().UTC(), CreatedBy: user,
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		return map[string]string{"name": req.Name, "secret": secret}, permsDetail(req.Permissions), nil
	})
}

func (h *Handler) handleRobotUpdate(w http.ResponseWriter, r *http.Request) {
	h.robotAction(w, r, audit.RobotUpdate, func(user string, req *robotRequest) (interface{}, string, error) {
		if err := validatePermissions(req.Permissions); err != nil {
			return nil, "", err
		}
		detail := permsDetail(req.Permissions)
		if req.Disabled {
			detail += "; disabled"
		}
		return nil, detail, h.meta.Update(func(d *meta.Data) error {
			rb, ok := d.Robots[req.Name]
			if !ok {
				return errRobotNotFound
			}
			rb.Description, rb.Permissions, rb.Disabled = req.Description, req.Permissions, req.Disabled
			if req.ExpiresDays != nil {
				exp, err := expiry(req.ExpiresDays)
				if err != nil {
					return err
				}
				rb.ExpiresAt = exp
			}
			d.Robots[req.Name] = rb
			return nil
		})
	})
}

// handleRobotSecret issues a new secret; the old one stops working.
func (h *Handler) handleRobotSecret(w http.ResponseWriter, r *http.Request) {
	h.robotAction(w, r, audit.RobotSecret, func(user string, req *robotRequest) (interface{}, string, error) {
		secret, err := newSecret()
		if err != nil {
			return nil, "", err
		}
		err = h.meta.Update(func(d *meta.Data) error {
			rb, ok := d.Robots[req.Name]
			if !ok {
				return errRobotNotFound
			}
			rb.SecretHash = auth.HashSecret(secret)
			d.Robots[req.Name] = rb
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		return map[string]string{"name": req.Name, "secret": secret}, "", nil
	})
}

func (h *Handler) handleRobotDelete(w http.ResponseWriter, r *http.Request) {
	h.robotAction(w, r, audit.RobotDelete, func(user string, req *robotRequest) (interface{}, string, error) {
		return nil, "", h.meta.Update(func(d *meta.Data) error {
			if _, ok := d.Robots[req.Name]; !ok {
				return errRobotNotFound
			}
			delete(d.Robots, req.Name)
			return nil
		})
	})
}
