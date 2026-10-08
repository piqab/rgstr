package ui

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/meta"
)

var projectNameRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

type projectInfo struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Public      bool      `json:"public"`
	MyRole      string    `json:"my_role,omitempty"`
	CanManage   bool      `json:"can_manage"`
	Members     int       `json:"members"`
	Repos       int       `json:"repos"`
	QuotaBytes  int64     `json:"quota_bytes"`
	UsedBytes   int64     `json:"used_bytes"`
	CreatedAt   time.Time `json:"created_at"`
}

type memberInfo struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// projectVisible reports whether user may see the project: admins, members
// and anyone for public projects.
func (h *Handler) projectVisible(user string, p meta.Project) bool {
	return p.Public || h.auth.IsAdmin(user) || p.Members[user] != ""
}

func (h *Handler) projectInfo(user string, p meta.Project, repos []string) projectInfo {
	info := projectInfo{
		Name: p.Name, Description: p.Description, Public: p.Public,
		MyRole: p.Members[user], CanManage: h.auth.IsProjectAdmin(user, p.Name),
		Members: len(p.Members), QuotaBytes: p.QuotaBytes, CreatedAt: p.CreatedAt,
	}
	for _, r := range repos {
		if meta.ProjectOf(r) == p.Name {
			info.Repos++
		}
	}
	info.UsedBytes = h.ops.ProjectUsage(p.Name)
	return info
}

// handleProjects lists the projects the user can see.
func (h *Handler) handleProjects(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	repos, _ := h.store.ListRepositories()
	out := []projectInfo{}
	for _, p := range h.meta.Projects() {
		if h.projectVisible(user, p) {
			out = append(out, h.projectInfo(user, p, repos))
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"projects": out, "can_create": h.auth.IsAdmin(user)})
}

// handleProject returns one project with members and repositories.
func (h *Handler) handleProject(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	p, found := h.meta.Project(r.URL.Query().Get("name"))
	if !found || !h.projectVisible(user, p) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	all, _ := h.store.ListRepositories()
	var repos []string
	for _, repo := range all {
		if meta.ProjectOf(repo) == p.Name && h.auth.Can(user, repo, "pull") {
			repos = append(repos, repo)
		}
	}
	members := []memberInfo{}
	for u, role := range p.Members {
		members = append(members, memberInfo{User: u, Role: role})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].User < members[j].User })
	if repos == nil {
		repos = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project":  h.projectInfo(user, p, all),
		"members":  members,
		"repos":    repos,
		"is_admin": h.auth.IsAdmin(user),
	})
}

type projectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Public      bool   `json:"public"`
	QuotaBytes  *int64 `json:"quota_bytes"` // registry admins only
	User        string `json:"user"`
	Role        string `json:"role"`
}

var (
	errProjectNotFound = errors.New("project not found")
	errForbidden       = errors.New("you are not allowed to manage this project")
)

// projectAction decodes a request, checks the caller manages the project
// (or is a registry admin when adminOnly), runs fn and audits it.
func (h *Handler) projectAction(w http.ResponseWriter, r *http.Request, action string, adminOnly bool,
	fn func(user string, req projectRequest) (detail string, err error)) {
	if !method(w, r, http.MethodPost) {
		return
	}
	user, ok := h.session(w, r)
	if !ok {
		return
	}
	var req projectRequest
	if !decode(w, r, &req) {
		return
	}
	allowed := h.auth.IsAdmin(user) || (!adminOnly && h.auth.IsProjectAdmin(user, req.Name))
	if !allowed {
		writeError(w, http.StatusForbidden, errForbidden.Error())
		return
	}
	detail, err := fn(user, req)
	h.audit(r, user, action, req.Name, detail, err)
	switch {
	case errors.Is(err, errProjectNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	h.projectAction(w, r, audit.ProjectCreate, true, func(user string, req projectRequest) (string, error) {
		if len(req.Name) > 64 || !projectNameRe.MatchString(req.Name) {
			return "", errors.New("invalid project name: lowercase letters, digits and . _ - between them")
		}
		return fmt.Sprintf("public: %v", req.Public), h.meta.Update(func(d *meta.Data) error {
			if _, exists := d.Projects[req.Name]; exists {
				return errors.New("project already exists")
			}
			if d.Projects == nil {
				d.Projects = map[string]meta.Project{}
			}
			p := meta.Project{Name: req.Name, Description: req.Description, Public: req.Public,
				Members: map[string]string{}, CreatedAt: time.Now().UTC()}
			if req.QuotaBytes != nil && *req.QuotaBytes > 0 {
				p.QuotaBytes = *req.QuotaBytes
			}
			d.Projects[req.Name] = p
			return nil
		})
	})
}

func (h *Handler) handleProjectUpdate(w http.ResponseWriter, r *http.Request) {
	h.projectAction(w, r, audit.ProjectUpdate, false, func(user string, req projectRequest) (string, error) {
		if req.QuotaBytes != nil && !h.auth.IsAdmin(user) {
			return "", errors.New("only registry administrators can change the quota")
		}
		detail := fmt.Sprintf("public: %v", req.Public)
		if req.QuotaBytes != nil {
			detail += fmt.Sprintf(", quota: %d bytes", *req.QuotaBytes)
		}
		return detail, h.meta.Update(func(d *meta.Data) error {
			p, ok := d.Projects[req.Name]
			if !ok {
				return errProjectNotFound
			}
			p.Description, p.Public = req.Description, req.Public
			if req.QuotaBytes != nil {
				if *req.QuotaBytes < 0 {
					return errors.New("quota must not be negative")
				}
				p.QuotaBytes = *req.QuotaBytes
			}
			d.Projects[req.Name] = p
			return nil
		})
	})
}

// handleProjectMember adds, changes or (with an empty role) removes a member.
func (h *Handler) handleProjectMember(w http.ResponseWriter, r *http.Request) {
	h.projectAction(w, r, audit.ProjectMember, false, func(user string, req projectRequest) (string, error) {
		switch req.Role {
		case "", meta.ProjectAdmin, meta.ProjectMaintainer, meta.ProjectDeveloper, meta.ProjectGuest:
		default:
			return "", errors.New("role must be admin, maintainer, developer or guest")
		}
		if req.Role != "" && !h.auth.UserExists(req.User) {
			return "", fmt.Errorf("user %q does not exist", req.User)
		}
		if req.User == user && !h.auth.IsAdmin(user) {
			return "", errors.New("you cannot change your own project role")
		}
		detail := req.User + " → " + req.Role
		if req.Role == "" {
			detail = req.User + " removed"
		}
		return detail, h.meta.Update(func(d *meta.Data) error {
			p, ok := d.Projects[req.Name]
			if !ok {
				return errProjectNotFound
			}
			if p.Members == nil {
				p.Members = map[string]string{}
			}
			if req.Role == "" {
				delete(p.Members, req.User)
			} else {
				p.Members[req.User] = req.Role
			}
			d.Projects[req.Name] = p
			return nil
		})
	})
}

// handleProjectDelete deletes an empty project.
func (h *Handler) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	h.projectAction(w, r, audit.ProjectDelete, true, func(user string, req projectRequest) (string, error) {
		repos, _ := h.store.ListRepositories()
		for _, repo := range repos {
			if meta.ProjectOf(repo) == req.Name {
				return "", errors.New("the project still has repositories; delete them first")
			}
		}
		return "", h.meta.Update(func(d *meta.Data) error {
			if _, ok := d.Projects[req.Name]; !ok {
				return errProjectNotFound
			}
			delete(d.Projects, req.Name)
			return nil
		})
	})
}
