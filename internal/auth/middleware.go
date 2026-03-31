package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
	// Always add the API version header.
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")

	// Token endpoint — open to all.
	if r.URL.Path == "/v2/auth" || r.URL.Path == "/v2/token" {
		h.handleToken(w, r)
		return
	}

	if !h.cfg.AuthEnabled {
		h.inner.ServeHTTP(w, r)
		return
	}

	subject, access, ok := h.authenticate(w, r)
	if !ok {
		return // challenge already written
	}

	ctx := context.WithValue(r.Context(), ctxSubject, subject)
	ctx = context.WithValue(ctx, ctxAccess, access)
	h.inner.ServeHTTP(w, r.WithContext(ctx))
}

// authenticate parses the Authorization header. Returns false and writes a
// challenge if the request is not properly authenticated.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (subject string, access []Access, ok bool) {
	hdr := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(hdr, "Bearer "):
		claims, err := h.tokenSvc.Verify(strings.TrimPrefix(hdr, "Bearer "))
		if err != nil {
			h.challenge(w, r)
			return "", nil, false
		}
		return claims.Subject, claims.Access, true

	case strings.HasPrefix(hdr, "Basic "):
		user, pass, err := parseBasic(hdr)
		if err != nil || !h.checkPassword(user, pass) {
			h.challenge(w, r)
			return "", nil, false
		}
		// Basic auth grants full access; actual scope is enforced by token claims
		// when the client subsequently obtains a token.
		return user, nil, true

	default:
		h.challenge(w, r)
		return "", nil, false
	}
}

// handleToken issues a JWT token to a client that presents valid credentials.
// Supports both GET (Docker CLI) and POST (some tooling).
func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	var username, password string

	// Credentials may come from Basic auth header or query params.
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

	if h.cfg.AuthEnabled && !h.checkPassword(username, password) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errBody("UNAUTHORIZED", "invalid credentials"))
		return
	}

	scope := r.URL.Query().Get("scope")
	var access []Access
	if scope != "" {
		access = ParseScope(scope)
	}

	token, err := h.tokenSvc.Issue(username, access)
	if err != nil {
		http.Error(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"access_token": token, // some clients expect this field name
		"expires_in": int(h.tokenSvc.TokenTTL().Seconds()),
		"issued_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// challenge writes a 401 response with a WWW-Authenticate header that tells
// the Docker client where and how to obtain a token.
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

// ─── helpers ─────────────────────────────────────────────────────────────────

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

// inferScope derives a reasonable scope string from the request URL and method
// to include in the WWW-Authenticate challenge so that Docker CLI requests
// the right scope from the token endpoint automatically.
func inferScope(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	if path == "" {
		return ""
	}
	for _, marker := range []string{"/manifests/", "/blobs/", "/tags/"} {
		if idx := strings.Index(path, marker); idx >= 0 {
			repo := path[:idx]
			action := "pull"
			switch r.Method {
			case http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete:
				action = "push"
			}
			return "repository:" + repo + ":" + action
		}
	}
	return ""
}

func errBody(code, msg string) map[string]interface{} {
	return map[string]interface{}{
		"errors": []map[string]string{
			{"code": code, "message": msg},
		},
	}
}
