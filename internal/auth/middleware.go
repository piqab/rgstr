package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/config"
	"rgstr/internal/glob"
	"rgstr/internal/meta"
)

type ctxKey int

const (
	ctxSubject ctxKey = iota
	ctxAccess
)

// Handler wraps an inner http.Handler and enforces Bearer token authentication.
// It also exposes the token endpoint at /v2/auth and /v2/token.
//
// Public / private model (when AuthEnabled = true):
//
//	                | pull | push | delete |
//	anonymous       |  public repos only     |
//	read-only user  |  ✓   |  ✗   |   ✗    |  RGSTR_READONLY_USERS
//	user            |  ✓   |  ✓   |   ✗    |  (✓ when RGSTR_ADMINS is empty)
//	admin           |  ✓   |  ✓   |   ✓    |  RGSTR_ADMINS
//
// Every request is checked against the access claims of its token (or the
// user's role for Basic auth). Public repos are configured via
// RGSTR_PUBLIC_REPOS (glob patterns).
type Handler struct {
	cfg      *config.Config
	tokenSvc *TokenService
	inner    http.Handler
	creds    *credentials
	audit    *audit.Log
	meta     *meta.Store // projects; nil = none
	sessions sessionState
	ldap     ldapChecker // nil: LDAP off
	oidc     *oidcAuth   // nil: OIDC off
}

// SetMeta enables projects (membership and public flags) from m.
func (h *Handler) SetMeta(m *meta.Store) { h.meta = m }

// SetAudit makes the handler record failed docker logins in log.
func (h *Handler) SetAudit(log *audit.Log) { h.audit = log }

// NewHandler creates an auth handler that protects inner. It exits if the
// stored passwords file (<storage>/users.json) exists but cannot be read.
func NewHandler(cfg *config.Config, tokenSvc *TokenService, inner http.Handler) *Handler {
	return NewSharedHandler(cfg, tokenSvc, inner, nil)
}

// NewSharedHandler is NewHandler with the stored users in users (shared
// by the processes of a cluster) instead of <storage>/users.json.
func NewSharedHandler(cfg *config.Config, tokenSvc *TokenService, inner http.Handler, users UsersBackend) *Handler {
	creds, err := openCredentials(cfg, users)
	if err != nil {
		log.Fatalf("auth: load stored passwords: %v", err)
	}
	h := &Handler{cfg: cfg, tokenSvc: tokenSvc, inner: inner, creds: creds}
	if cfg.LDAP.Enabled() {
		l, err := newLDAPAuth(cfg.LDAP)
		if err != nil {
			log.Fatalf("auth: %v", err)
		}
		h.ldap = l
	}
	if cfg.OIDC.Enabled() {
		h.oidc = newOIDCAuth(cfg)
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")

	// Token endpoint — always open.
	if r.URL.Path == "/v2/auth" || r.URL.Path == "/v2/token" {
		h.handleToken(w, r)
		return
	}

	// Auth disabled → let everything through.
	if !h.cfg.AuthEnabled {
		h.inner.ServeHTTP(w, r)
		return
	}

	// Try to authenticate with the provided credentials / token.
	subject, access, ok := h.Authenticate(r)
	if ok {
		typ, name, action := requiredAccess(r)
		// The token must grant the action, and the subject must still be
		// allowed it now — role changes apply without waiting for expiry.
		if typ == "" || (Allowed(access, typ, name, action) &&
			(typ != "repository" || h.Can(subject, name, action))) {
			ctx := context.WithValue(r.Context(), ctxSubject, subject)
			ctx = context.WithValue(ctx, ctxAccess, access)
			h.inner.ServeHTTP(w, r.WithContext(ctx))
			return
		}
	}

	// No sufficient grant — allow anonymous read on public repositories.
	if h.isPublicReadRequest(r) {
		h.inner.ServeHTTP(w, r)
		return
	}

	// Valid password, but the user's role forbids this action. Re-asking for
	// credentials would not help, so deny outright.
	if ok && strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errBody("DENIED", "requested access to the resource is denied"))
		return
	}

	// Otherwise challenge the client to (re-)authenticate. For a Bearer token
	// that lacks the scope, the challenge names the scope to request.
	h.challenge(w, r)
}

// Authenticate parses the Authorization header and returns the subject and
// access claims if authentication succeeds. It does NOT write any response.
// Basic auth yields the user's full role-based access.
func (h *Handler) Authenticate(r *http.Request) (subject string, access []Access, ok bool) {
	hdr := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(hdr, "Bearer "):
		claims, err := h.tokenSvc.Verify(strings.TrimPrefix(hdr, "Bearer "))
		if err != nil || !h.sessionValid(claims) {
			return "", nil, false
		}
		return claims.Subject, claims.Access, true

	case strings.HasPrefix(hdr, "Basic "):
		user, pass, err := parseBasic(hdr)
		if err != nil {
			return "", nil, false
		}
		// A temporary password only allows changing it in the web UI.
		subject, ok, mustChange := h.resolve(user, pass)
		if !ok || mustChange {
			return "", nil, false
		}
		return subject, h.FullAccess(subject), true
	}
	return "", nil, false
}

// handleToken issues a JWT token to a client that presents valid credentials.
//
// Public-repo anonymous pull:
//   - If auth is enabled but the client provides no (or invalid) credentials,
//     we still issue a pull-only token for any public repos in the requested scope.
//   - Private repos in the scope are silently dropped from the issued token,
//     so the client gets partial access (pull on public only).
//   - If the scope contains only private repos and no credentials → 401.
func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	var username, password string

	// GET passes parameters in the query; containerd's OAuth2 flow POSTs them
	// as a form (grant_type=password&username=&password=&scope=).
	// ParseForm merges both into r.Form.
	r.ParseForm()

	if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Basic ") {
		user, pass, err := parseBasic(hdr)
		if err == nil {
			username, password = user, pass
		}
	}
	if username == "" {
		username = r.Form.Get("username")
		if username == "" {
			username = r.Form.Get("account")
		}
		password = r.Form.Get("password")
	}

	subject, valid, mustChange := h.resolve(username, password)
	if valid {
		username = subject
	}
	if h.cfg.AuthEnabled && username != "" && !valid {
		h.audit.Add(audit.Entry{User: username, IP: audit.ClientIP(r), Action: audit.LoginFailed, Detail: "docker"})
	}
	if h.cfg.AuthEnabled && valid && mustChange {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errBody("UNAUTHORIZED",
			"password change required: sign in to the web UI at /ui and set a new password"))
		return
	}
	authenticated := !h.cfg.AuthEnabled || valid

	// Parse requested scopes. Clients may repeat scope= or separate scopes
	// with spaces.
	var requestedAccess []Access
	for _, raw := range r.Form["scope"] {
		for _, scope := range strings.Fields(raw) {
			requestedAccess = append(requestedAccess, ParseScope(scope)...)
		}
	}

	var grantedAccess []Access

	if !h.cfg.AuthEnabled {
		grantedAccess = requestedAccess
	} else if authenticated {
		// Authenticated users get what they asked for, limited by their role.
		grantedAccess = h.grantForUser(username, requestedAccess)
	} else {
		// Unauthenticated: grant pull-only on public repos, drop the rest.
		for _, a := range requestedAccess {
			// A wildcard name could match more than the public patterns allow.
			if a.Type != "repository" || strings.ContainsAny(a.Name, "*?[") || !h.isPublicRepo(a.Name) {
				continue
			}
			// Only grant pull, even if the client asked for push too.
			grantedAccess = append(grantedAccess, Access{
				Type:    a.Type,
				Name:    a.Name,
				Actions: []string{"pull"},
			})
		}

		// If nothing was granted and credentials were actually provided (but
		// wrong), respond with 401 so the client knows to re-authenticate.
		if len(grantedAccess) == 0 {
			if username != "" {
				// Wrong credentials.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errBody("UNAUTHORIZED", "invalid credentials"))
				return
			}
			// Truly anonymous request for a private repo — challenge.
			if len(requestedAccess) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errBody("UNAUTHORIZED", "authentication required"))
				return
			}
			// Empty scope (e.g. /v2/ ping) — issue an empty token.
		}
	}

	token, err := h.tokenSvc.Issue(username, grantedAccess)
	if err != nil {
		http.Error(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":        token,
		"access_token": token,
		"expires_in":   int(h.tokenSvc.TokenTTL().Seconds()),
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// challenge writes a 401 response with a WWW-Authenticate header.
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request) {
	scope := inferScope(r)
	realm := h.tokenSvc.AuthRealm()
	service := h.tokenSvc.AuthService()

	challenge := fmt.Sprintf(`Bearer realm="%s",service="%s"`, realm, service)
	if scope != "" {
		challenge += fmt.Sprintf(`,scope="%s"`, scope)
	}

	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(errBody("UNAUTHORIZED", "authentication required"))
}

// Login checks credentials and issues a token carrying the user's full
// role-based access. Used by the web UI so it never stores the password.
// Returns ErrPasswordChangeRequired for the bootstrap password.
func (h *Handler) Login(username, password string) (string, error) {
	_, token, err := h.LoginAs(username, password)
	return token, err
}

// LoginAs is Login that also returns the signed-in name: directory users
// are stored in lower case whatever case they typed.
func (h *Handler) LoginAs(username, password string) (subject, token string, err error) {
	if IsRobot(username) {
		return "", "", ErrInvalidCredentials // robots use docker login only
	}
	subject, ok, mustChange := h.resolveUser(username, password, false)
	switch {
	case !ok:
		return "", "", ErrInvalidCredentials
	case mustChange:
		return "", "", ErrPasswordChangeRequired
	}
	token, err = h.newSession(subject)
	return subject, token, err
}

// ChangePassword sets a new password for username after verifying the
// current one (which may be the bootstrap password).
// Every web admin session of the user ends; the UI signs in again with the
// new password.
func (h *Handler) ChangePassword(username, current, next string) error {
	if _, ext := h.creds.external(strings.ToLower(username)); ext && !h.creds.isLocal(username) {
		return ErrExternalUser
	}
	if err := h.creds.change(username, current, next); err != nil {
		return err
	}
	h.endSessions(username)
	return nil
}

// AuthEnabled reports whether authentication is switched on.
func (h *Handler) AuthEnabled() bool { return h.cfg.AuthEnabled }

// ─── Roles ───────────────────────────────────────────────────────────────────

// Can reports whether subject ("" = anonymous) may perform action (pull,
// push, delete) on repo right now. Deleted users lose access immediately,
// even with an unexpired token.
//
// Repositories inside a project ("<project>/…") are open to registry
// admins and project members according to their project role; others use
// the global role.
func (h *Handler) Can(subject, repo, action string) bool {
	if !h.cfg.AuthEnabled {
		return true
	}
	if subject == ScannerSubject { // rgstr's own scanner, with a token rgstr signed
		return action == "pull"
	}
	if action == "pull" && h.isPublicRepo(repo) {
		return true
	}
	if IsRobot(subject) {
		return h.robotCan(subject, repo, action)
	}
	if !h.creds.exists(subject) {
		return false
	}
	if h.IsAdmin(subject) {
		return true
	}
	if proj, ok := h.project(repo); ok {
		return contains(memberActions(proj, subject, repo), action)
	}
	return contains(h.UserActions(subject), action)
}

// project returns the project repo belongs to, if it exists.
func (h *Handler) project(repo string) (meta.Project, bool) {
	if h.meta == nil {
		return meta.Project{}, false
	}
	name := meta.ProjectOf(repo)
	if name == "" {
		return meta.Project{}, false
	}
	return h.meta.Project(name)
}

// memberActions is what subject may do in repo of project p: their role
// on the whole project plus their grants matching the repository.
func memberActions(p meta.Project, subject, repo string) []string {
	actions := projectActions(p.Members[subject])
	rel := meta.RepoInProject(p.Name, repo)
	for _, g := range p.Grants {
		if g.User == subject && glob.Match(g.Repos, rel) {
			for _, a := range projectActions(g.Role) {
				if !contains(actions, a) {
					actions = append(actions, a)
				}
			}
		}
	}
	return actions
}

// projectActions maps a project role to repository actions.
func projectActions(role string) []string {
	switch role {
	case meta.ProjectAdmin, meta.ProjectMaintainer:
		return allActions
	case meta.ProjectDeveloper:
		return []string{"pull", "push"}
	case meta.ProjectGuest:
		return []string{"pull"}
	}
	return nil
}

// IsProjectAdmin reports whether subject may manage the project's members
// and webhooks: registry admins and the project's admins.
func (h *Handler) IsProjectAdmin(subject, project string) bool {
	if h.IsAdmin(subject) {
		return true
	}
	if h.meta == nil || !h.creds.exists(subject) {
		return false
	}
	p, ok := h.meta.Project(project)
	return ok && p.Members[subject] == meta.ProjectAdmin
}

// IsAdmin reports whether subject may administer the registry: manage
// users, policies and GC. Everyone is an admin when auth is disabled.
func (h *Handler) IsAdmin(subject string) bool {
	if !h.cfg.AuthEnabled {
		return true
	}
	return !IsRobot(subject) && h.creds.exists(subject) && h.Role(subject) == RoleAdmin
}

// ─── Robot accounts ──────────────────────────────────────────────────────────

// ScannerSubject is the token subject of rgstr's vulnerability scanner.
// It cannot be a user name (names start with a letter or digit).
const ScannerSubject = "@scanner"

// IsRobot reports whether name is a robot account.
func IsRobot(name string) bool { return strings.HasPrefix(name, meta.RobotPrefix) }

// HashSecret returns the stored form of a robot secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// check verifies a password or robot secret. mustChange reports a
// temporary password.
func (h *Handler) check(user, password string) (ok, mustChange bool) {
	_, ok, mustChange = h.resolve(user, password)
	return ok, mustChange
}

// resolve verifies docker credentials: a robot secret, a local password,
// an external user's CLI secret or an LDAP password. subject is the user
// name to use from now on (directory names are lower-cased).
func (h *Handler) resolve(user, password string) (subject string, ok, mustChange bool) {
	if IsRobot(user) {
		return user, h.checkRobot(user, password), false
	}
	return h.resolveUser(user, password, true)
}

// resolveUser checks a person's password. cliSecret allows an external
// user's CLI secret (docker login, not the web admin).
func (h *Handler) resolveUser(user, password string, cliSecret bool) (subject string, ok, mustChange bool) {
	if user == "" {
		return "", false, false
	}
	// Local users first: a directory account cannot take over a local name.
	if h.creds.isLocal(user) {
		ok, mustChange = h.creds.check(user, password)
		return user, ok, mustChange
	}
	name := strings.ToLower(user)
	if h.creds.isLocal(name) {
		return "", false, false
	}
	if cliSecret && h.creds.checkCLISecret(name, password) {
		return name, true, false
	}
	if h.ldap == nil {
		return "", false, false
	}
	groups, err := h.ldap.authenticate(name, password)
	if err != nil {
		if !errors.Is(err, errLDAPDenied) {
			log.Printf("auth: ldap: %v", err)
		}
		return "", false, false
	}
	role, keepRole, allowed := roleForGroups(groups, h.cfg.LDAP.Roles)
	if !allowed {
		return "", false, false
	}
	if err := h.creds.signInExternal(name, SourceLDAP, role, keepRole); err != nil {
		log.Printf("auth: ldap user %q: %v", name, err)
		return "", false, false
	}
	return name, true, false
}

// checkRobot verifies a robot secret.
func (h *Handler) checkRobot(user, password string) bool {
	r, found := h.robot(user)
	if !found {
		return false
	}
	got := HashSecret(password)
	return subtle.ConstantTimeCompare([]byte(got), []byte(r.SecretHash)) == 1
}

// robot returns an active robot account.
func (h *Handler) robot(name string) (meta.Robot, bool) {
	if h.meta == nil {
		return meta.Robot{}, false
	}
	r, ok := h.meta.Robot(name)
	if !ok || !r.Active(time.Now()) {
		return meta.Robot{}, false
	}
	return r, true
}

// robotCan checks a robot's explicit permissions. A disabled, expired or
// deleted robot can do nothing, even with an unexpired token.
func (h *Handler) robotCan(name, repo, action string) bool {
	r, ok := h.robot(name)
	if !ok {
		return false
	}
	project := meta.ProjectOf(repo)
	for _, p := range r.Permissions {
		if !contains(p.Actions, action) {
			continue
		}
		switch {
		case p.Project == "*":
			if p.Repos == "" || glob.Match(p.Repos, repo) {
				return true
			}
		case project != "" && p.Project == project:
			if p.Repos == "" || glob.Match(p.Repos, meta.RepoInProject(project, repo)) {
				return true
			}
		}
	}
	return false
}

// Role returns the user's role: set in the admin for users created there;
// from env otherwise (RGSTR_READONLY_USERS, RGSTR_ADMINS, the bootstrap
// admin).
func (h *Handler) Role(user string) string {
	if role, ok := h.creds.managedRole(user); ok {
		return role
	}
	switch {
	case contains(h.cfg.ReadOnlyUsers, user):
		return RoleReadOnly
	case contains(h.cfg.Admins, user) || h.creds.isBootstrap(user):
		return RoleAdmin
	default:
		return RoleUser
	}
}

var allActions = []string{"pull", "push", "delete"}

// UserActions returns the repository actions the user's role permits.
// Env users with role "user" may also delete while RGSTR_ADMINS is empty
// (the behaviour before roles existed).
func (h *Handler) UserActions(username string) []string {
	if !h.cfg.AuthEnabled {
		return allActions
	}
	switch h.Role(username) {
	case RoleReadOnly:
		return []string{"pull"}
	case RoleAdmin:
		return allActions
	}
	if _, managed := h.creds.managedRole(username); !managed && len(h.cfg.Admins) == 0 {
		return allActions
	}
	return []string{"pull", "push"}
}

// FullAccess is the access of Basic auth and web admin sessions: the token
// does not restrict anything, and every request is checked with Can.
func (h *Handler) FullAccess(username string) []Access {
	return []Access{
		{Type: "repository", Name: "*", Actions: []string{"*"}},
		{Type: "registry", Name: "catalog", Actions: []string{"*"}},
	}
}

// grantForUser narrows the requested access to what the user may do in
// each requested repository.
func (h *Handler) grantForUser(username string, requested []Access) []Access {
	var granted []Access
	for _, a := range requested {
		switch {
		case a.Type == "repository":
			var acts []string
			for _, act := range expandActions(a.Actions) {
				if h.Can(username, a.Name, act) {
					acts = append(acts, act)
				}
			}
			if len(acts) > 0 {
				granted = append(granted, Access{Type: a.Type, Name: a.Name, Actions: acts})
			}
		case a.Type == "registry" && a.Name == "catalog":
			granted = append(granted, Access{Type: a.Type, Name: a.Name, Actions: []string{"*"}})
		}
	}
	return granted
}

// expandActions replaces "*" with every concrete repository action.
func expandActions(actions []string) []string {
	var out []string
	for _, a := range actions {
		if a == "*" {
			for _, x := range allActions {
				if !contains(out, x) {
					out = append(out, x)
				}
			}
		} else if !contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// isPublicReadRequest returns true when the request is a read operation (GET/HEAD)
// targeting a repository that matches one of the public repo patterns.
func (h *Handler) isPublicReadRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	repo := repoFromPath(r.URL.Path)
	return repo != "" && h.isPublicRepo(repo)
}

// isPublicRepo reports whether name is in a public project or matches one
// of the RGSTR_PUBLIC_REPOS patterns.
func (h *Handler) isPublicRepo(name string) bool {
	if p, ok := h.project(name); ok && p.Public {
		return true
	}
	for _, pattern := range h.cfg.PublicRepos {
		if matchGlob(pattern, name) {
			return true
		}
	}
	return false
}

// ─── Context accessors ────────────────────────────────────────────────────────

// SubjectFromCtx returns the authenticated username from a request context.
func SubjectFromCtx(ctx context.Context) string {
	s, _ := ctx.Value(ctxSubject).(string)
	return s
}

// HasAccess checks whether the request in ctx was granted action on the given
// resource. Requests that bypassed authentication (auth disabled) have no
// access list in ctx and are always granted.
func HasAccess(ctx context.Context, resourceType, name, action string) bool {
	access, ok := ctx.Value(ctxAccess).([]Access)
	if !ok {
		return true
	}
	return Allowed(access, resourceType, name, action)
}

// Allowed reports whether access grants action on the given resource.
// A name of "*" matches every resource; an action of "*" matches every action.
func Allowed(access []Access, resourceType, name, action string) bool {
	for _, a := range access {
		if a.Type != resourceType || (a.Name != name && a.Name != "*") {
			continue
		}
		for _, act := range a.Actions {
			if act == action || act == "*" {
				return true
			}
		}
	}
	return false
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func parseBasic(hdr string) (user, pass string, err error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(b), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("bad basic auth format")
	}
	return parts[0], parts[1], nil
}

// repoFromPath extracts the repository name from a /v2/<name>/... URL.
func repoFromPath(urlPath string) string {
	p := strings.TrimPrefix(urlPath, "/v2/")
	for _, marker := range []string{"/manifests/", "/blobs/", "/tags/"} {
		if idx := strings.Index(p, marker); idx >= 0 {
			return p[:idx]
		}
	}
	return ""
}

// requiredAccess returns the grant a /v2/ request needs. An empty type means
// any authenticated identity suffices (e.g. the /v2/ version check).
func requiredAccess(r *http.Request) (typ, name, action string) {
	if r.URL.Path == "/v2/_catalog" {
		return "registry", "catalog", "*"
	}
	repo := repoFromPath(r.URL.Path)
	if repo == "" {
		return "", "", ""
	}
	return "repository", repo, actionFor(r)
}

// actionFor maps a request to the repository action it performs.
func actionFor(r *http.Request) string {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return "pull"
	case http.MethodDelete:
		// Cancelling an upload is part of pushing, not deleting content.
		if strings.Contains(r.URL.Path, "/blobs/uploads/") {
			return "push"
		}
		return "delete"
	default:
		return "push"
	}
}

// inferScope derives a scope string from the request for WWW-Authenticate.
func inferScope(r *http.Request) string {
	typ, name, action := requiredAccess(r)
	if typ == "" {
		return ""
	}
	return typ + ":" + name + ":" + action
}

// matchGlob matches a repository name against a pattern; see glob.Match.
func matchGlob(pattern, name string) bool { return glob.Match(pattern, name) }

func errBody(code, msg string) map[string]interface{} {
	return map[string]interface{}{
		"errors": []map[string]string{
			{"code": code, "message": msg},
		},
	}
}

// Config returns the configuration the handler was built with.
func (h *Handler) Config() *config.Config { return h.cfg }

// ─── User management ─────────────────────────────────────────────────────────

// UserInfo describes a user for the web admin.
type UserInfo struct {
	Name       string     `json:"name"`
	Source     string     `json:"source"` // "env", "bootstrap" or "admin"
	Role       string     `json:"role"`
	Actions    []string   `json:"actions"`
	MustChange bool       `json:"must_change"`
	Managed    bool       `json:"managed"` // stored in users.json: role editable, deletable
	Changed    *time.Time `json:"password_changed,omitempty"`
	Created    *time.Time `json:"created,omitempty"`
	LastLogin  *time.Time `json:"last_login,omitempty"` // external users
	CLISecret  bool       `json:"cli_secret,omitempty"` // external user has a docker login secret
}

// Users lists every user.
func (h *Handler) Users() []UserInfo {
	var out []UserInfo
	for _, name := range h.creds.names() {
		u := UserInfo{Name: name, Source: "env", Role: h.Role(name), Actions: h.UserActions(name)}
		if h.creds.isBootstrap(name) {
			u.Source = "bootstrap"
			u.MustChange = true
		}
		if sp, ok := h.creds.stored(name); ok {
			u.MustChange = sp.MustChange
			changed := sp.ChangedAt
			u.Changed = &changed
			u.Managed = sp.Managed
			if sp.Source != "" {
				u.Source = sp.Source // "ldap" or "oidc"
				u.Changed = nil
				last := sp.LastLogin
				u.LastLogin = &last
				u.CLISecret = sp.CLISecret != ""
			} else if sp.Managed && sp.Base == "" {
				u.Source = "admin"
				created := sp.CreatedAt
				u.Created = &created
			} else if sp.Managed {
				u.Source = "bootstrap" // first admin with its own password
			}
		}
		out = append(out, u)
	}
	return out
}

// CreateUser adds a user with a role. With mustChange the password is
// temporary and must be replaced at the first sign-in.
func (h *Handler) CreateUser(name, role, password string, mustChange bool) error {
	return h.creds.createUser(name, role, password, mustChange)
}

// SetRole changes the role of a user created in the admin.
func (h *Handler) SetRole(name, role string) error { return h.creds.setRole(name, role) }

// DeleteUser removes a user created in the admin.
func (h *Handler) DeleteUser(name string) error { return h.creds.deleteUser(name) }

// ResetPassword sets a new password for any user. With mustChange it is
// temporary.
func (h *Handler) ResetPassword(name, password string, mustChange bool) error {
	if !h.creds.exists(name) {
		return ErrUserNotFound
	}
	if len(password) < minPasswordLen {
		return ErrWeakPassword
	}
	if err := h.creds.setPassword(name, password, mustChange); err != nil {
		return err
	}
	h.endSessions(name)
	return nil
}

// Source is where user signs in: "ldap", "oidc", or "" for local users.
func (h *Handler) Source(user string) string {
	if sp, ok := h.creds.external(user); ok {
		return sp.Source
	}
	return ""
}

// LDAPEnabled reports whether LDAP passwords are accepted.
func (h *Handler) LDAPEnabled() bool { return h.ldap != nil && h.cfg.AuthEnabled }

// NewCLISecret makes a new docker login secret for an external user,
// replacing the previous one. Only its hash is stored.
func (h *Handler) NewCLISecret(user string) (string, error) {
	if _, ok := h.creds.external(user); !ok {
		return "", ErrUserNotFound
	}
	secret := randomString()
	if err := h.creds.setCLISecret(user, HashSecret(secret)); err != nil {
		return "", err
	}
	return secret, nil
}

// UserExists reports whether name is a known user.
func (h *Handler) UserExists(name string) bool { return h.creds.exists(name) }
