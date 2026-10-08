// Package ui serves the registry's web admin: a static single-page app
// (vanilla JS, embedded) backed by a JSON API under /ui/api/.
package ui

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"

	"rgstr/internal/auth"
	"rgstr/internal/maint"
	"rgstr/internal/meta"
	"rgstr/internal/ops"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
	"rgstr/internal/webhook"
)

//go:embed static
var staticFiles embed.FS

// Deps are the services the UI is built on.
type Deps struct {
	Auth    *auth.Handler
	Store   *storage.Filesystem
	Counter *stats.Counter
	Ops     *ops.Ops
	Meta    *meta.Store
	Maint   *maint.Runner
	Hooks   *webhook.Notifier
}

// Handler serves the web UI and its API.
type Handler struct {
	auth    *auth.Handler
	store   *storage.Filesystem
	counter *stats.Counter
	ops     *ops.Ops
	meta    *meta.Store
	maint   *maint.Runner
	hooks   *webhook.Notifier
}

// New creates a UI handler.
func New(d Deps) *Handler {
	return &Handler{auth: d.Auth, store: d.Store, counter: d.Counter, ops: d.Ops, meta: d.Meta, maint: d.Maint, hooks: d.Hooks}
}

// Mount registers the UI handlers on mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	static, _ := fs.Sub(staticFiles, "static")
	files := http.StripPrefix("/ui/static/", http.FileServer(http.FS(static)))
	mux.Handle("/ui/static/", noCache(files))
	mux.HandleFunc("/ui", h.servePage)
	mux.HandleFunc("/ui/", h.servePage)

	mux.HandleFunc("/ui/api/me", h.handleMe)
	mux.HandleFunc("/ui/api/login", h.handleLogin)
	mux.HandleFunc("/ui/api/password", h.handlePassword)

	mux.HandleFunc("/ui/api/repos", h.handleRepos)
	mux.HandleFunc("/ui/api/repos/delete", h.handleDeleteRepo)
	mux.HandleFunc("/ui/api/tags/delete", h.handleDeleteTags)
	mux.HandleFunc("/ui/api/images/delete", h.handleDeleteImage)
	mux.HandleFunc("/ui/api/image", h.handleImage)

	mux.HandleFunc("/ui/api/gc", h.handleGC)
	mux.HandleFunc("/ui/api/gc/run", h.handleGCRun)
	mux.HandleFunc("/ui/api/gc/settings", h.handleGCSettings)

	mux.HandleFunc("/ui/api/policies", h.handlePolicies)
	mux.HandleFunc("/ui/api/policies/retention", h.handleRetentionRules)
	mux.HandleFunc("/ui/api/policies/retention/run", h.handleRetentionRun)
	mux.HandleFunc("/ui/api/policies/immutable", h.handleImmutableRules)

	mux.HandleFunc("/ui/api/users", h.handleUsers)
	mux.HandleFunc("/ui/api/users/create", h.handleUserCreate)
	mux.HandleFunc("/ui/api/users/role", h.handleUserRole)
	mux.HandleFunc("/ui/api/users/password", h.handleUserPassword)
	mux.HandleFunc("/ui/api/users/delete", h.handleUserDelete)

	mux.HandleFunc("/ui/api/audit", h.handleAudit)

	mux.HandleFunc("/ui/api/projects", h.handleProjects)
	mux.HandleFunc("/ui/api/project", h.handleProject)
	mux.HandleFunc("/ui/api/projects/create", h.handleProjectCreate)
	mux.HandleFunc("/ui/api/projects/update", h.handleProjectUpdate)
	mux.HandleFunc("/ui/api/projects/member", h.handleProjectMember)
	mux.HandleFunc("/ui/api/projects/delete", h.handleProjectDelete)

	mux.HandleFunc("/ui/api/robots", h.handleRobots)
	mux.HandleFunc("/ui/api/robots/create", h.handleRobotCreate)
	mux.HandleFunc("/ui/api/robots/update", h.handleRobotUpdate)
	mux.HandleFunc("/ui/api/robots/secret", h.handleRobotSecret)
	mux.HandleFunc("/ui/api/robots/delete", h.handleRobotDelete)

	mux.HandleFunc("/ui/api/webhooks", h.handleWebhooks)
	mux.HandleFunc("/ui/api/webhooks/save", h.handleWebhookSave)
	mux.HandleFunc("/ui/api/webhooks/delete", h.handleWebhookDelete)
	mux.HandleFunc("/ui/api/webhooks/test", h.handleWebhookTest)
}

// servePage serves the app shell; navigation happens client-side (#hash).
func (h *Handler) servePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	page, _ := staticFiles.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(page)
}

// noCache makes browsers revalidate static files, so an upgrade is picked
// up without a hard refresh.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// ─── Request helpers ──────────────────────────────────────────────────────────

// session authenticates a UI API request and returns the user. With auth
// disabled the user is anonymous ("") with full rights. On failure it writes
// 401 and returns ok=false.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) (user string, ok bool) {
	if !h.auth.AuthEnabled() {
		return "", true
	}
	subject, _, ok := h.auth.Authenticate(r)
	if !ok || subject == "" || auth.IsRobot(subject) {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return "", false
	}
	return subject, true
}

// adminSession is session restricted to registry admins (403 otherwise).
func (h *Handler) adminSession(w http.ResponseWriter, r *http.Request) (user string, ok bool) {
	user, ok = h.session(w, r)
	if !ok {
		return "", false
	}
	if !h.auth.IsAdmin(user) {
		writeError(w, http.StatusForbidden, "administrator rights required")
		return "", false
	}
	return user, true
}

// method writes 405 unless r uses the given method.
func method(w http.ResponseWriter, r *http.Request, m string) bool {
	if r.Method != m {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// decode reads a JSON request body (up to 64 KiB) into v, writing 400 on error.
func decode(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// audit records an admin action by user.
func (h *Handler) audit(r *http.Request, user, action, resource, detail string, err error) {
	h.ops.Audit(ops.ActorFrom(r, user), action, resource, detail, err)
}
