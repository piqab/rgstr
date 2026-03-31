package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration.
type Config struct {
	ListenAddr  string
	StorageRoot string
	TLSCert     string
	TLSKey      string

	AuthEnabled bool
	AuthSecret  string // HMAC-SHA256 secret for JWT signing
	AuthRealm   string // full URL of the token endpoint
	AuthService string // "service" claim in tokens
	AuthIssuer  string // "iss" claim in tokens
	TokenTTL    time.Duration

	// Users is username → bcrypt hash, loaded from RGSTR_USERS env var.
	// Format: "alice:$2b$...,bob:$2b$..."
	Users map[string]string

	// PublicRepos is a list of repository name patterns that are readable
	// without authentication. Supports glob wildcards:
	//   *        — any single path segment   (e.g. "alpine" but not "ns/alpine")
	//   **       — any path including slashes (e.g. "public/**")
	//   ?        — any single character
	// Examples: "public/**", "library/ubuntu", "*"
	PublicRepos []string

	GCInterval time.Duration
	UploadTTL  time.Duration // stale upload sessions older than this are GC'd
}

// Load reads configuration from environment variables.
func Load() *Config {
	return &Config{
		ListenAddr:  env("RGSTR_ADDR", ":5000"),
		StorageRoot: env("RGSTR_STORAGE", "./data"),
		TLSCert:     env("RGSTR_TLS_CERT", ""),
		TLSKey:      env("RGSTR_TLS_KEY", ""),

		AuthEnabled: envBool("RGSTR_AUTH_ENABLED", false),
		AuthSecret:  env("RGSTR_AUTH_SECRET", "change-me-in-production"),
		AuthRealm:   env("RGSTR_AUTH_REALM", "http://localhost:5000/v2/auth"),
		AuthService: env("RGSTR_AUTH_SERVICE", "rgstr"),
		AuthIssuer:  env("RGSTR_AUTH_ISSUER", "rgstr"),
		TokenTTL:    envDuration("RGSTR_TOKEN_TTL", time.Hour),

		Users:       parseUsers(env("RGSTR_USERS", "")),
		PublicRepos: parseList(env("RGSTR_PUBLIC_REPOS", "")),

		GCInterval: envDuration("RGSTR_GC_INTERVAL", time.Hour),
		UploadTTL:  envDuration("RGSTR_UPLOAD_TTL", 24*time.Hour),
	}
}

func parseList(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseUsers(raw string) map[string]string {
	m := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// username:bcrypt-hash (hash may contain colons)
		idx := strings.Index(entry, ":")
		if idx <= 0 {
			continue
		}
		m[entry[:idx]] = entry[idx+1:]
	}
	return m
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
