// Package auth implements Docker/OCI Bearer token authentication.
//
// Flow:
//  1. Client → registry:  any request (no token)
//  2. Registry → client:  401  WWW-Authenticate: Bearer realm="...",service="...",scope="..."
//  3. Client → /v2/auth:  GET ?service=&scope=  (Basic auth or username/password)
//  4. /v2/auth → client:  200  {"token":"<jwt>","expires_in":3600}
//  5. Client → registry:  original request + Authorization: Bearer <jwt>
//  6. Registry verifies JWT, checks access claims, proceeds.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"rgstr/internal/config"
)

// Access represents a single resource access grant inside a token.
type Access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// Claims is the JWT payload for Docker registry tokens.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti"`
	Access    []Access `json:"access"`
}

// TokenService creates and verifies JWT tokens signed with HMAC-SHA256.
type TokenService struct {
	cfg *config.Config
}

// NewTokenService creates a TokenService from the given configuration.
func NewTokenService(cfg *config.Config) *TokenService {
	return &TokenService{cfg: cfg}
}

// Issue mints a new signed token for the given subject and access list.
func (s *TokenService) Issue(subject string, access []Access) (string, error) {
	now := time.Now()
	jti := make([]byte, 16)
	rand.Read(jti)

	claims := Claims{
		Issuer:    s.cfg.AuthIssuer,
		Subject:   subject,
		Audience:  s.cfg.AuthService,
		ExpiresAt: now.Add(s.cfg.TokenTTL).Unix(),
		IssuedAt:  now.Unix(),
		JWTID:     base64.RawURLEncoding.EncodeToString(jti),
		Access:    access,
	}
	return sign(claims, s.cfg.AuthSecret)
}

// Verify validates a token string and returns its claims.
func (s *TokenService) Verify(tokenStr string) (*Claims, error) {
	return verify(tokenStr, s.cfg.AuthSecret, s.cfg.AuthService)
}

// AuthRealm returns the configured token endpoint URL.
func (s *TokenService) AuthRealm() string { return s.cfg.AuthRealm }

// AuthService returns the configured service name.
func (s *TokenService) AuthService() string { return s.cfg.AuthService }

// TokenTTL returns how long tokens are valid.
func (s *TokenService) TokenTTL() time.Duration { return s.cfg.TokenTTL }

// ─── JWT helpers (HS256) ──────────────────────────────────────────────────────

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func sign(claims Claims, secret string) (string, error) {
	hb, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	msg := h + "." + p

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig, nil
}

func verify(tokenStr, secret, audience string) (*Claims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}

	// Verify signature.
	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	expected := mac.Sum(nil)

	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding")
	}
	if !hmac.Equal(expected, got) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims.
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad claims encoding")
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("bad claims: %w", err)
	}

	if time.Now().Unix() > c.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	if c.Audience != audience {
		return nil, fmt.Errorf("wrong audience: got %q want %q", c.Audience, audience)
	}
	return &c, nil
}

// ParseScope parses a Docker scope string "repository:name:pull,push".
func ParseScope(scope string) []Access {
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 {
		return nil
	}
	actions := strings.Split(parts[2], ",")
	var clean []string
	for _, a := range actions {
		if a = strings.TrimSpace(a); a != "" {
			clean = append(clean, a)
		}
	}
	return []Access{{Type: parts[0], Name: parts[1], Actions: clean}}
}
