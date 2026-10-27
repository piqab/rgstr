package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"rgstr/internal/config"
)

// errLDAPDenied is a wrong password or an unknown user; other errors mean
// the directory could not be asked.
var errLDAPDenied = errors.New("ldap: invalid credentials")

// ldapChecker checks a directory password and returns the user's groups
// (replaced in tests).
type ldapChecker interface {
	authenticate(user, password string) ([]string, error)
}

// ldapAuth checks passwords against LDAP / Active Directory: it finds the
// user's entry (as the service account, or anonymously) and binds as the
// user with the password. Successful checks are cached for a minute:
// docker clients may send Basic credentials with every request.
type ldapAuth struct {
	cfg config.LDAPConfig
	tls *tls.Config

	mu    sync.Mutex
	cache map[[32]byte]ldapResult
}

type ldapResult struct {
	groups  []string
	expires time.Time
}

const ldapCacheTTL = time.Minute

func newLDAPAuth(cfg config.LDAPConfig) (*ldapAuth, error) {
	tc := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} // #nosec G402 -- opt-in via RGSTR_LDAP_INSECURE_SKIP_VERIFY
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("RGSTR_LDAP_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("RGSTR_LDAP_CA_FILE: no certificates in %s", cfg.CAFile)
		}
		tc.RootCAs = pool
	}
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, errors.New("RGSTR_LDAP_USER_FILTER must contain %s (the user name)")
	}
	return &ldapAuth{cfg: cfg, tls: tc, cache: map[[32]byte]ldapResult{}}, nil
}

// authenticate returns the user's groups if password is right.
func (l *ldapAuth) authenticate(user, password string) ([]string, error) {
	// An empty password would be an "unauthenticated bind", which many
	// servers accept for any DN.
	if user == "" || password == "" {
		return nil, errLDAPDenied
	}
	key := sha256.Sum256([]byte(user + "\x00" + password))
	l.mu.Lock()
	if r, ok := l.cache[key]; ok && time.Now().Before(r.expires) {
		l.mu.Unlock()
		return r.groups, nil
	}
	l.mu.Unlock()

	groups, err := l.query(user, password)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	now := time.Now()
	for k, r := range l.cache {
		if now.After(r.expires) {
			delete(l.cache, k)
		}
	}
	l.cache[key] = ldapResult{groups: groups, expires: now.Add(ldapCacheTTL)}
	l.mu.Unlock()
	return groups, nil
}

func (l *ldapAuth) query(user, password string) ([]string, error) {
	conn, err := ldap.DialURL(l.cfg.URL, ldap.DialWithTLSConfig(l.tls))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	if l.cfg.StartTLS {
		if err := conn.StartTLS(l.tls); err != nil {
			return nil, err
		}
	}
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("bind as RGSTR_LDAP_BIND_DN: %w", err)
		}
	}

	attr := l.cfg.GroupAttr
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 10, false, fmt.Sprintf(l.cfg.UserFilter, ldap.EscapeFilter(user)), []string{"dn", attr}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("user search: %w", err)
	}
	if res == nil || len(res.Entries) != 1 {
		return nil, errLDAPDenied // unknown, or ambiguous: never guess
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, errLDAPDenied
		}
		return nil, err
	}
	groups := entry.GetAttributeValues(attr)

	if l.cfg.GroupFilter != "" {
		// Directories without memberOf (plain OpenLDAP): search the groups
		// that list the user. Searched as the service account when set.
		if l.cfg.BindDN != "" {
			if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
				return nil, err
			}
		}
		base := l.cfg.GroupBaseDN
		if base == "" {
			base = l.cfg.BaseDN
		}
		gres, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 10, false, fmt.Sprintf(l.cfg.GroupFilter, ldap.EscapeFilter(entry.DN)), []string{"dn"}, nil))
		if err != nil {
			return nil, fmt.Errorf("group search: %w", err)
		}
		for _, g := range gres.Entries {
			groups = append(groups, g.DN)
		}
	}
	return groups, nil
}
