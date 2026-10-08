package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rgstr/internal/config"
)

// Credential errors returned by Login and ChangePassword.
var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrPasswordChangeRequired = errors.New("password change required")
	ErrWeakPassword           = errors.New("password must be at least 8 characters")
	ErrSamePassword           = errors.New("new password must differ from the current one")
)

const minPasswordLen = 8

// credentials resolves passwords from three sources, in order:
//
//  1. Passwords changed through the web UI, stored as bcrypt hashes in
//     <storage>/users.json.
//  2. The bootstrap admin (RGSTR_ADMIN_USER / RGSTR_ADMIN_PASSWORD): a plain
//     password that only allows changing it.
//  3. RGSTR_USERS bcrypt hashes.
//
// A stored password remembers the env credential it replaced. When that env
// value changes (an operator resets a forgotten password, or rotates a hash),
// the stored password is discarded and the env value applies again.
type credentials struct {
	cfg  *config.Config
	path string // empty: keep changes in memory only

	mu        sync.RWMutex
	overrides map[string]storedPassword
}

type storedPassword struct {
	Hash      string    `json:"hash"`       // bcrypt of the new password
	Base      string    `json:"base"`       // bcrypt of the env credential it replaced
	ChangedAt time.Time `json:"changed_at"` // informational
}

type usersFile struct {
	Users map[string]storedPassword `json:"users"`
}

func loadCredentials(cfg *config.Config) (*credentials, error) {
	c := &credentials{cfg: cfg, overrides: make(map[string]storedPassword)}
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
		if env == "" || bcrypt.CompareHashAndPassword([]byte(sp.Base), []byte(env)) != nil {
			// User removed from env, or its env credential was reset.
			stale = true
			continue
		}
		c.overrides[user] = sp
	}
	if stale {
		if err := c.saveLocked(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// envCredential returns the credential env configures for user: the plain
// bootstrap password or the RGSTR_USERS hash. Empty if the user is unknown.
func (c *credentials) envCredential(user string) string {
	if c.isBootstrap(user) {
		return c.cfg.AdminPassword
	}
	return c.cfg.Users[user]
}

func (c *credentials) isBootstrap(user string) bool {
	return c.cfg.AdminPassword != "" && user == c.cfg.AdminUser
}

// check verifies a password. mustChange reports that the password is the
// bootstrap one, which may only be used to set a new password.
func (c *credentials) check(user, password string) (ok, mustChange bool) {
	if user == "" {
		return false, false
	}
	c.mu.RLock()
	sp, changed := c.overrides[user]
	c.mu.RUnlock()

	switch {
	case changed:
		return bcrypt.CompareHashAndPassword([]byte(sp.Hash), []byte(password)) == nil, false
	case c.isBootstrap(user):
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

	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	base, err := bcrypt.GenerateFromPassword([]byte(c.envCredential(user)), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.overrides[user] = storedPassword{Hash: string(hash), Base: string(base), ChangedAt: time.Now().UTC()}
	return c.saveLocked()
}

// saveLocked writes users.json atomically. Caller holds c.mu (or owns c).
func (c *credentials) saveLocked() error {
	if c.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(usersFile{Users: c.overrides}, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
