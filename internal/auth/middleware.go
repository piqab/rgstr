package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rgstr/internal/config"
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
//	                 | pull | push |
//	 public repo     |  ✓   |  ✗   |  anonymous pull allowed
//	 private repo    |  ✗   |  ✗   |  credentials required for everything
//	 authenticated   |  ✓   |  ✓   |  valid token grants full access
//
// Public repos are configured via RGSTR_PUBLIC_REPOS (glob patterns).
type Handler struct {
	cfg      *config.Config
	tokenSvc *TokenService
	inner    http.Handler
}

// NewHandler creates an auth handler that protects inner.
func NewHandler(cfg *config.Config, tokenSvc *TokenService, inner http.Handler) *Handler {
	return &Handler{cfg: cfg, tokenSvc: tokenSvc, inner: inner}
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
	subject, access, ok := h.tryAuthenticate(r)
	if ok {
		ctx := context.WithValue(r.Context(), ctxSubject, subject)
		ctx = context.WithValue(ctx, ctxAccess, access)
		h.inner.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// No valid credentials — allow anonymous read on public repositories.
	if h.isPublicReadRequest(r) {
		h.inner.ServeHTTP(w, r)
		return
	}

	// Otherwise challenge the client to authenticate.
	h.challenge(w, r)
}

// tryAuthenticate parses the Authorization header and returns the subject and
// access claims if authentication succeeds. It does NOT write any response.
func (h *Handler) tryAuthenticate(r *http.Request) (subject string, access []Access, ok bool) {
	hdr := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(hdr, "Bearer "):
		claims, err := h.tokenSvc.Verify(strings.TrimPrefix(hdr, "Bearer "))
		if err != nil {
			return "", nil, false
		}
		return claims.Subject, claims.Access, true

	case strings.HasPrefix(hdr, "Basic "):
		user, pass, err := parseBasic(hdr)
		if err != nil || !h.checkPassword(user, pass) {
			return "", nil, false
		}
		// Basic auth grants full access (no scope restriction).
		return user, nil, true
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

	if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Basic ") {
		user, pass, err := parseBasic(hdr)
		if err == nil {
			username, password = user, pass
		}
	}
	if username == "" {
		q := r.URL.Query()
		username = q.Get("account")
		password = q.Get("password")
	}

	authenticated := !h.cfg.AuthEnabled || h.checkPassword(username, password)

	// Parse requested scope.
	scope := r.URL.Query().Get("scope")
	requestedAccess := ParseScope(scope)

	var grantedAccess []Access

	if authenticated {
		// Authenticated users get exactly what they asked for.
		grantedAccess = requestedAccess
	} else {
		// Unauthenticated: grant pull-only on public repos, drop the rest.
		for _, a := range requestedAccess {
			if a.Type != "repository" || !h.isPublicRepo(a.Name) {
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

func (h *Handler) checkPassword(username, password string) bool {
	if username == "" {
		return false
	}
	hash, ok := h.cfg.Users[username]
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// CheckBasic validates a Basic Authorization header against the configured users.
// Returns the username and true on success.
func (h *Handler) CheckBasic(r *http.Request) (string, bool) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Basic ") {
		return "", false
	}
	user, pass, err := parseBasic(hdr)
	if err != nil {
		return "", false
	}
	return user, h.checkPassword(user, pass)
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

// isPublicRepo reports whether name matches any of the configured public repo patterns.
func (h *Handler) isPublicRepo(name string) bool {
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

// HasAccess checks whether the token in ctx grants action on the given resource.
// If there is no access list (Basic auth or auth disabled), access is granted.
func HasAccess(ctx context.Context, resourceType, name, action string) bool {
	access, ok := ctx.Value(ctxAccess).([]Access)
	if !ok || access == nil {
		return true
	}
	for _, a := range access {
		if a.Type == resourceType && (a.Name == name || a.Name == "*") {
			for _, act := range a.Actions {
				if act == action || act == "*" {
					return true
				}
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

// inferScope derives a scope string from the request for WWW-Authenticate.
func inferScope(r *http.Request) string {
	repo := repoFromPath(r.URL.Path)
	if repo == "" {
		return ""
	}
	action := "pull"
	switch r.Method {
	case http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete:
		action = "push"
	}
	return "repository:" + repo + ":" + action
}

// matchGlob matches name against a glob pattern where:
//   - "*"  matches any sequence of characters except "/"
//   - "**" matches any sequence of path segments (zero or more), including "/"
//   - "?"  matches any single character except "/"
//
// Examples:
//
//	matchGlob("public/**",    "public/myimage")      → true
//	matchGlob("public/**",    "public/ns/myimage")   → true
//	matchGlob("**/public/**", "alex/public/alpine")  → true
//	matchGlob("library/*",    "library/ubuntu")      → true
//	matchGlob("library/*",    "library/ns/ubuntu")   → false
//	matchGlob("alpine",       "alpine")              → true
func matchGlob(pattern, name string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchSegments recursively matches pattern segments against name segments.
// "**" consumes zero or more name segments.
func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			if len(pat) == 0 {
				return true // ** at end matches everything remaining
			}
			// Try consuming 0, 1, 2, … name segments for **.
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], name[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		name = name[1:]
	}
	return len(name) == 0
}

func errBody(code, msg string) map[string]interface{} {
	return map[string]interface{}{
		"errors": []map[string]string{
			{"code": code, "message": msg},
		},
	}
}
