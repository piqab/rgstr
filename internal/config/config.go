package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration.
type Config struct {
	// Version of the running build (set by main, not from env).
	Version string

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
	// SessionTTL is how long a web admin session lasts without activity
	// (RGSTR_SESSION_TTL); sessions are extended while in use.
	SessionTTL time.Duration

	// Users is username → bcrypt hash, loaded from RGSTR_USERS env var.
	// Format: "alice:$2b$...,bob:$2b$..."
	Users map[string]string

	// AdminUser / AdminPassword define a bootstrap admin with a plain-text
	// password (RGSTR_ADMIN_USER, default "admin"; RGSTR_ADMIN_PASSWORD).
	// The password only allows setting a new one in the web UI; the new
	// password is stored hashed in <storage>/users.json. Changing
	// RGSTR_ADMIN_PASSWORD later resets the stored password.
	AdminUser     string
	AdminPassword string

	// Admins may delete manifests and blobs (RGSTR_ADMINS). When empty, every
	// non-read-only user may delete — the behaviour before roles existed.
	Admins []string

	// ReadOnlyUsers may only pull (RGSTR_READONLY_USERS).
	ReadOnlyUsers []string

	// TrustedProxies are networks (CIDRs or IPs) whose X-Forwarded-For
	// header is believed when logging client addresses
	// (RGSTR_TRUSTED_PROXIES; unset = loopback and private networks,
	// "none" = never).
	TrustedProxies []string

	// PublicRepos is a list of repository name patterns that are readable
	// without authentication. Supports glob wildcards:
	//   *        — any single path segment   (e.g. "alpine" but not "ns/alpine")
	//   **       — any path including slashes (e.g. "public/**")
	//   ?        — any single character
	// Examples: "public/**", "library/ubuntu", "*"
	PublicRepos []string

	// MetricsEnabled serves Prometheus metrics at /metrics
	// (RGSTR_METRICS_ENABLED).
	MetricsEnabled bool

	GCInterval time.Duration
	UploadTTL  time.Duration // stale upload sessions older than this are GC'd

	LDAP LDAPConfig
	OIDC OIDCConfig
}

// GroupRoles maps directory groups to rgstr roles for external users (LDAP,
// OIDC). Groups match by full name/DN or by the CN of a DN, ignoring case.
type GroupRoles struct {
	// AdminGroups and ReadOnlyGroups grant those roles; members of neither
	// get DefaultRole. With neither set, the role is managed in the admin.
	AdminGroups    []string
	ReadOnlyGroups []string
	// AllowedGroups, when set, limits sign-in to their members (and to
	// members of AdminGroups and ReadOnlyGroups).
	AllowedGroups []string
	DefaultRole   string
}

// LDAPConfig enables sign-in with LDAP / Active Directory passwords
// (RGSTR_LDAP_*). Local users are checked first.
type LDAPConfig struct {
	URL                string // ldap://host:389 or ldaps://host:636; empty: LDAP off
	StartTLS           bool
	InsecureSkipVerify bool
	CAFile             string
	BindDN             string // service account for the user search; empty: anonymous
	BindPassword       string
	BaseDN             string
	UserFilter         string // %s is the escaped user name
	GroupAttr          string // attribute of the user entry listing its groups
	GroupBaseDN        string
	GroupFilter        string // optional group search; %s is the escaped user DN
	Roles              GroupRoles
}

// Enabled reports whether LDAP sign-in is configured.
func (l LDAPConfig) Enabled() bool { return l.URL != "" }

// OIDCConfig enables web admin sign-in through an OpenID Connect provider
// (RGSTR_OIDC_*).
type OIDCConfig struct {
	Issuer        string // empty: OIDC off
	ClientID      string
	ClientSecret  string
	RedirectURL   string // default: <external URL>/ui/oidc/callback
	Scopes        []string
	UsernameClaim string
	GroupsClaim   string
	Name          string // shown on the sign-in button
	Roles         GroupRoles
}

// Enabled reports whether OIDC sign-in is configured.
func (o OIDCConfig) Enabled() bool { return o.Issuer != "" && o.ClientID != "" }

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
		SessionTTL:  envDuration("RGSTR_SESSION_TTL", 12*time.Hour),

		Users:          parseUsers(env("RGSTR_USERS", "")),
		AdminUser:      env("RGSTR_ADMIN_USER", "admin"),
		AdminPassword:  os.Getenv("RGSTR_ADMIN_PASSWORD"),
		Admins:         parseList(env("RGSTR_ADMINS", "")),
		ReadOnlyUsers:  parseList(env("RGSTR_READONLY_USERS", "")),
		PublicRepos:    parseList(env("RGSTR_PUBLIC_REPOS", "")),
		TrustedProxies: trustedProxies(),

		MetricsEnabled: envBool("RGSTR_METRICS_ENABLED", false),

		GCInterval: envDuration("RGSTR_GC_INTERVAL", time.Hour),
		UploadTTL:  envDuration("RGSTR_UPLOAD_TTL", 24*time.Hour),

		LDAP: LDAPConfig{
			URL:                env("RGSTR_LDAP_URL", ""),
			StartTLS:           envBool("RGSTR_LDAP_STARTTLS", false),
			InsecureSkipVerify: envBool("RGSTR_LDAP_INSECURE_SKIP_VERIFY", false),
			CAFile:             env("RGSTR_LDAP_CA_FILE", ""),
			BindDN:             env("RGSTR_LDAP_BIND_DN", ""),
			BindPassword:       os.Getenv("RGSTR_LDAP_BIND_PASSWORD"),
			BaseDN:             env("RGSTR_LDAP_BASE_DN", ""),
			UserFilter:         env("RGSTR_LDAP_USER_FILTER", "(&(objectClass=person)(uid=%s))"),
			GroupAttr:          env("RGSTR_LDAP_GROUP_ATTR", "memberOf"),
			GroupBaseDN:        env("RGSTR_LDAP_GROUP_BASE_DN", ""),
			GroupFilter:        env("RGSTR_LDAP_GROUP_FILTER", ""),
			Roles:              groupRoles("RGSTR_LDAP_"),
		},
		OIDC: OIDCConfig{
			Issuer:        strings.TrimSuffix(env("RGSTR_OIDC_ISSUER", ""), "/"),
			ClientID:      env("RGSTR_OIDC_CLIENT_ID", ""),
			ClientSecret:  os.Getenv("RGSTR_OIDC_CLIENT_SECRET"),
			RedirectURL:   env("RGSTR_OIDC_REDIRECT_URL", ""),
			Scopes:        strings.Fields(strings.ReplaceAll(env("RGSTR_OIDC_SCOPES", "openid profile email"), ",", " ")),
			UsernameClaim: env("RGSTR_OIDC_USERNAME_CLAIM", "preferred_username"),
			GroupsClaim:   env("RGSTR_OIDC_GROUPS_CLAIM", "groups"),
			Name:          env("RGSTR_OIDC_NAME", "SSO"),
			Roles:         groupRoles("RGSTR_OIDC_"),
		},
	}
}

func groupRoles(prefix string) GroupRoles {
	return GroupRoles{
		AdminGroups:    parseList(env(prefix+"ADMIN_GROUPS", "")),
		ReadOnlyGroups: parseList(env(prefix+"READONLY_GROUPS", "")),
		AllowedGroups:  parseList(env(prefix+"ALLOWED_GROUPS", "")),
		DefaultRole:    env(prefix+"DEFAULT_ROLE", "user"),
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

// trustedProxies reads RGSTR_TRUSTED_PROXIES. nil means the defaults.
func trustedProxies() []string {
	v, set := os.LookupEnv("RGSTR_TRUSTED_PROXIES")
	if !set || strings.TrimSpace(v) == "" {
		return nil
	}
	if strings.TrimSpace(v) == "none" {
		return []string{}
	}
	return parseList(v)
}
