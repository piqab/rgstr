package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rgstr/internal/config"
)

// Credential errors returned by Login, ChangePassword and user management.
var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrPasswordChangeRequired = errors.New("password change required")
	ErrWeakPassword           = errors.New("password must be at least 8 characters")
	ErrSamePassword           = errors.New("new password must differ from the current one")
	ErrUserExists             = errors.New("user already exists")
	ErrUserNotFound           = errors.New("user not found")
	ErrEnvUser                = errors.New("this user is configured in the environment; change it there")
	ErrInvalidName            = errors.New("invalid user name: use letters, digits, '.', '_' or '-' (up to 64)")
	ErrInvalidRole            = errors.New("role must be admin, user or readonly")
	ErrExternalUser           = errors.New("this user signs in through LDAP or SSO; the password is managed there")
	ErrLocalUser              = errors.New("a local user with this name exists")
)

const minPasswordLen = 8

// Roles.
const (
	RoleAdmin    = "admin"
	RoleUser     = "user"
	RoleReadOnly = "readonly"
)

var userNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// credentials resolves passwords from three sources, in order:
//
//  1. <storage>/users.json: users created in the web admin, and passwords
//     changed or reset there, as bcrypt hashes.
//  2. The bootstrap admin (RGSTR_ADMIN_USER / RGSTR_ADMIN_PASSWORD): a plain
//     password that only allows changing it.
//  3. RGSTR_USERS bcrypt hashes.
//
// A stored password of an env user remembers the env credential it replaced.
// When that env value changes (an operator resets a forgotten password, or
// rotates a hash), the stored password is discarded and the env value
// applies again.
type credentials struct {
	cfg  *config.Config
	path string // empty: keep changes in memory only

	mu    sync.RWMutex
	users map[string]storedPassword
}

type storedPassword struct {
	Hash       string    `json:"hash"`                  // bcrypt of the password
	Base       string    `json:"base,omitempty"`        // env users: bcrypt of the env credential replaced
	ChangedAt  time.Time `json:"changed_at"`            // informational
	Managed    bool      `json:"managed,omitempty"`     // created in the web admin
	Role       string    `json:"role,omitempty"`        // managed users only
	MustChange bool      `json:"must_change,omitempty"` // temporary password set by an admin
	CreatedAt  time.Time `json:"created_at,omitempty"`
	// External users (LDAP, OIDC) have no password here: Source names the
	// provider, CLISecret is the hash of their docker login secret.
	Source    string    `json:"source,omitempty"`
	CLISecret string    `json:"cli_secret,omitempty"`
	LastLogin time.Time `json:"last_login,omitempty"`
}

type usersFile struct {
	Users map[string]storedPassword `json:"users"`
}

func loadCredentials(cfg *config.Config) (*credentials, error) {
	c := &credentials{cfg: cfg, users: make(map[string]storedPassword)}
	if cfg.StorageRoot == "" {
		return c, nil
	}
	c.path = filepath.Join(cfg.StorageRoot, "users.json")

	raw, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var f usersFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", c.path, err)
	}

	stale := false
	for user, sp := range f.Users {
		env := c.envCredential(user)
		_, inEnvUsers := c.cfg.Users[user]
		baseMatches := sp.Base != "" && env != "" &&
			bcrypt.CompareHashAndPassword([]byte(sp.Base), []byte(env)) == nil
		switch {
		case sp.Managed && sp.Base != "":
			// The first admin after setting their own password: kept even
			// when RGSTR_ADMIN_PASSWORD is removed; a new value resets it.
			if env != "" && !baseMatches {
				log.Printf("auth: password of %q reset by RGSTR_ADMIN_PASSWORD", user)
				stale = true
				continue
			}
			c.users[user] = sp
		case sp.Managed && env != "":
			// A user of the same name was added to env later: env wins.
			log.Printf("auth: user %q from the admin is shadowed by env; using env", user)
			stale = true
		case sp.Managed:
			c.users[user] = sp
		case !inEnvUsers && user == c.cfg.AdminUser && (env == "" || baseMatches):
			// First admin stored by rgstr ≤1.5.0: make it independent of env
			// (it used to vanish when RGSTR_ADMIN_PASSWORD was removed).
			sp.Managed, sp.Role = true, RoleAdmin
			c.users[user] = sp
			stale = true
		case env == "" || !baseMatches:
			// User removed from env, or its env credential was reset.
			stale = true
		default:
			c.users[user] = sp
		}
	}
	if stale {
		if err := c.saveLocked(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// envCredential returns the credential env configures for user: the plain
// bootstrap password or the RGSTR_USERS hash. Empty if env does not define
// the user.
func (c *credentials) envCredential(user string) string {
	if c.isBootstrap(user) {
		return c.cfg.AdminPassword
	}
	return c.cfg.Users[user]
}

func (c *credentials) isBootstrap(user string) bool {
	return c.cfg.AdminPassword != "" && user == c.cfg.AdminUser
}

// stored returns the stored entry for user.
func (c *credentials) stored(user string) (storedPassword, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sp, ok := c.users[user]
	return sp, ok
}

// exists reports whether user is defined anywhere.
func (c *credentials) exists(user string) bool {
	if user == "" {
		return false
	}
	if c.envCredential(user) != "" {
		return true
	}
	sp, ok := c.stored(user)
	return ok && sp.Managed
}

// managedRole returns the role of a user created in the admin.
func (c *credentials) managedRole(user string) (string, bool) {
	sp, ok := c.stored(user)
	if !ok || !sp.Managed {
		return "", false
	}
	return sp.Role, true
}

// check verifies a password. mustChange reports a temporary password (the
// bootstrap one, or one set by an admin) that may only be used to set a new
// password.
func (c *credentials) check(user, password string) (ok, mustChange bool) {
	if user == "" {
		return false, false
	}
	if sp, found := c.stored(user); found {
		if sp.Source != "" {
			return false, false // external: checked by the provider
		}
		return bcrypt.CompareHashAndPassword([]byte(sp.Hash), []byte(password)) == nil, sp.MustChange
	}
	if c.isBootstrap(user) {
		return subtle.ConstantTimeCompare([]byte(password), []byte(c.cfg.AdminPassword)) == 1, true
	}
	hash, known := c.cfg.Users[user]
	if !known {
		return false, false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, false
}

// change replaces user's password after verifying the current one.
func (c *credentials) change(user, current, next string) error {
	if ok, _ := c.check(user, current); !ok {
		return ErrInvalidCredentials
	}
	if len(next) < minPasswordLen {
		return ErrWeakPassword
	}
	if next == current || (c.isBootstrap(user) && next == c.cfg.AdminPassword) {
		return ErrSamePassword
	}
	return c.setPassword(user, next, false)
}

// setPassword stores a new password for an existing user. mustChange makes
// it temporary.
func (c *credentials) setPassword(user, password string, mustChange bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	sp, found := c.users[user]
	if found && sp.Source != "" {
		return ErrExternalUser
	}
	if !found || sp.Base != "" || !sp.Managed {
		// Env user: remember which env credential this password replaces.
		env := c.envCredential(user)
		if env == "" && !(found && sp.Managed) {
			return ErrUserNotFound
		}
		if env != "" {
			base, err := bcrypt.GenerateFromPassword([]byte(env), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			sp.Base = string(base)
		}
		// The first admin's account lives on in users.json once it has its
		// own password, independent of RGSTR_ADMIN_PASSWORD.
		if c.isBootstrap(user) {
			sp.Managed, sp.Role = true, RoleAdmin
		}
	}
	sp.Hash = string(hash)
	sp.MustChange = mustChange
	sp.ChangedAt = time.Now().UTC()
	c.users[user] = sp
	return c.saveLocked()
}

// createUser adds a user managed from the web admin.
func (c *credentials) createUser(user, role, password string, mustChange bool) error {
	if !userNameRe.MatchString(user) {
		return ErrInvalidName
	}
	if !validRole(role) {
		return ErrInvalidRole
	}
	if len(password) < minPasswordLen {
		return ErrWeakPassword
	}
	if c.exists(user) {
		return ErrUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, taken := c.users[user]; taken {
		return ErrUserExists
	}
	now := time.Now().UTC()
	c.users[user] = storedPassword{
		Hash: string(hash), Managed: true, Role: role, MustChange: mustChange,
		ChangedAt: now, CreatedAt: now,
	}
	return c.saveLocked()
}

// setRole changes the role of a managed user.
func (c *credentials) setRole(user, role string) error {
	if !validRole(role) {
		return ErrInvalidRole
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sp, ok := c.users[user]
	if !ok || !sp.Managed {
		if c.envCredential(user) != "" {
			return ErrEnvUser
		}
		return ErrUserNotFound
	}
	sp.Role = role
	c.users[user] = sp
	return c.saveLocked()
}

// deleteUser removes a managed user.
func (c *credentials) deleteUser(user string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	sp, ok := c.users[user]
	if !ok || !sp.Managed {
		if c.envCredential(user) != "" {
			return ErrEnvUser
		}
		return ErrUserNotFound
	}
	delete(c.users, user)
	return c.saveLocked()
}

// names returns every known user name, sorted.
func (c *credentials) names() []string {
	set := map[string]bool{}
	for u := range c.cfg.Users {
		set[u] = true
	}
	if c.cfg.AdminPassword != "" {
		set[c.cfg.AdminUser] = true
	}
	c.mu.RLock()
	for u, sp := range c.users {
		if sp.Managed {
			set[u] = true
		}
	}
	c.mu.RUnlock()
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func validRole(r string) bool { return r == RoleAdmin || r == RoleUser || r == RoleReadOnly }

// saveLocked writes users.json atomically. Caller holds c.mu (or owns c).
func (c *credentials) saveLocked() error {
	if c.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(usersFile{Users: c.users}, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
