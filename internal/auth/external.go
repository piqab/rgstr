package auth

import (
	"crypto/subtle"
	"regexp"
	"strings"
	"time"

	"rgstr/internal/config"
)

// External users sign in through LDAP or an OIDC provider. They are created
// in users.json at their first sign-in (without a password) and keep their
// project memberships; their role follows their directory groups when
// group mappings are configured, otherwise it is set in the admin. They use
// docker login with their LDAP password or a CLI secret made in the admin.

// Providers of external users.
const (
	SourceLDAP = "ldap"
	SourceOIDC = "oidc"
)

// External names may be e-mail addresses. They are stored in lower case:
// directories compare names without case.
var externalNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._@+-]{0,127}$`)

// isLocal reports whether user is defined locally (env or created in the
// admin). Local users take precedence over directory users of the same name.
func (c *credentials) isLocal(user string) bool {
	if c.envCredential(user) != "" {
		return true
	}
	sp, ok := c.stored(user)
	return ok && sp.Managed && sp.Source == ""
}

// external returns the stored entry of an external user.
func (c *credentials) external(user string) (storedPassword, bool) {
	sp, ok := c.stored(user)
	return sp, ok && sp.Source != ""
}

// signInExternal creates or updates an external user after the provider
// accepted them. role is applied unless keepRole (no group mapping) and the
// user already exists.
func (c *credentials) signInExternal(user, source, role string, keepRole bool) error {
	if !externalNameRe.MatchString(user) {
		return ErrInvalidName
	}
	if c.isLocal(user) {
		return ErrLocalUser
	}
	now := time.Now().UTC()
	if sp, found := c.stored(user); found && sp.Source == source && (keepRole || sp.Role == role) &&
		now.Sub(sp.LastLogin) < time.Hour {
		return nil // nothing changed: spare the write on every docker login
	}
	return c.mutate(func(users map[string]storedPassword) error {
		sp, found := users[user]
		if found && sp.Source == "" {
			return ErrLocalUser
		}
		if !found {
			sp = storedPassword{Managed: true, Role: role, CreatedAt: now, ChangedAt: now}
		} else if !keepRole {
			sp.Role = role
		}
		sp.Source, sp.LastLogin = source, now
		users[user] = sp
		return nil
	})
}

// setCLISecret stores the hash of an external user's docker login secret.
func (c *credentials) setCLISecret(user, hash string) error {
	return c.mutate(func(users map[string]storedPassword) error {
		sp, ok := users[user]
		if !ok || sp.Source == "" {
			return ErrUserNotFound
		}
		sp.CLISecret = hash
		users[user] = sp
		return nil
	})
}

func (c *credentials) checkCLISecret(user, secret string) bool {
	sp, ok := c.external(user)
	return ok && sp.CLISecret != "" &&
		subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(sp.CLISecret)) == 1
}

// roleForGroups maps directory groups to a role. allowed is false when
// AllowedGroups (or any role group) restricts sign-in and the user is in
// none of them. keepRole means no role groups are configured: the role is
// managed in the admin.
func roleForGroups(groups []string, m config.GroupRoles) (role string, keepRole, allowed bool) {
	in := func(list []string) bool {
		for _, want := range list {
			for _, g := range groups {
				if groupMatches(g, want) {
					return true
				}
			}
		}
		return false
	}
	isAdmin, isRO := in(m.AdminGroups), in(m.ReadOnlyGroups)
	allowed = len(m.AllowedGroups) == 0 || in(m.AllowedGroups) || isAdmin || isRO
	role = m.DefaultRole
	if !validRole(role) {
		role = RoleUser
	}
	switch {
	case isAdmin:
		role = RoleAdmin
	case isRO:
		role = RoleReadOnly
	}
	keepRole = len(m.AdminGroups) == 0 && len(m.ReadOnlyGroups) == 0
	return role, keepRole, allowed
}

// groupMatches compares a group (a name, or a DN such as
// "CN=Devs,OU=Groups,DC=corp") with a configured one: equal ignoring case,
// or the DN's first CN equals it.
func groupMatches(group, want string) bool {
	if strings.EqualFold(group, want) {
		return true
	}
	first, _, _ := strings.Cut(group, ",")
	if k, v, ok := strings.Cut(first, "="); ok && strings.EqualFold(strings.TrimSpace(k), "cn") {
		return strings.EqualFold(strings.TrimSpace(v), want)
	}
	return false
}
