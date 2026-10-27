// Package meta persists registry metadata managed from the web admin —
// settings, GC history, policies — in <storage>/meta.json.
package meta

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Data is everything stored in meta.json.
type Data struct {
	Settings         Settings           `json:"settings"`
	GCHistory        []GCRun            `json:"gc_history,omitempty"`
	Retention        []RetentionRule    `json:"retention,omitempty"`
	RetentionHistory []RetentionRun     `json:"retention_history,omitempty"`
	Immutable        []ImmutableRule    `json:"immutable,omitempty"`
	Projects         map[string]Project `json:"projects,omitempty"`
	Robots           map[string]Robot   `json:"robots,omitempty"`
	Webhooks         []Webhook          `json:"webhooks,omitempty"`
	PendingFree      []PendingFree      `json:"pending_free,omitempty"`

	// Web admin sessions ended early: by sign-out (session ID → until when
	// to reject it) and by password changes (user → sessions started
	// before this time are rejected).
	RevokedSessions   map[string]time.Time `json:"revoked_sessions,omitempty"`
	SessionsNotBefore map[string]time.Time `json:"sessions_not_before,omitempty"`
}

// PendingFree is something deleted whose data GC has not removed yet.
type PendingFree struct {
	Ref       string    `json:"ref"`  // team/app, team/app:1, team/app@sha256:…
	Kind      string    `json:"kind"` // "repository", "tag" or "image"
	Repo      string    `json:"repo"`
	Manifests []string  `json:"manifests,omitempty"` // hex, for an immediate GC
	Blobs     []string  `json:"blobs"`               // hex
	User      string    `json:"user,omitempty"`
	Time      time.Time `json:"time"`
}

// MaxPendingFree caps the pending list; the oldest entries are dropped.
const MaxPendingFree = 500

// Webhook events.
const (
	EventPush          = "push"
	EventPull          = "pull"
	EventDelete        = "delete"
	EventQuotaExceeded = "quota_exceeded"
)

// Webhook notifies an HTTP endpoint about registry events.
type Webhook struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Project    string    `json:"project,omitempty"` // "" = every repository
	Events     []string  `json:"events"`
	Format     string    `json:"format"`                // "default" (JSON) or "slack"
	AuthHeader string    `json:"auth_header,omitempty"` // sent as Authorization
	SkipVerify bool      `json:"skip_verify,omitempty"` // accept any TLS certificate
	Disabled   bool      `json:"disabled,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
}

// RobotPrefix starts every robot account name.
const RobotPrefix = "robot$"

// Robot is a machine account for CI: a secret instead of a password and
// explicit per-project permissions.
type Robot struct {
	Name        string            `json:"name"` // full name, "robot$…"
	Description string            `json:"description,omitempty"`
	SecretHash  string            `json:"secret_hash"` // hex SHA-256 of the secret
	Permissions []RobotPermission `json:"permissions"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Disabled    bool              `json:"disabled,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
}

// RobotPermission grants actions in a project ("*" = every repository).
type RobotPermission struct {
	Project string   `json:"project"`
	Actions []string `json:"actions"`
}

// Active reports whether the robot may authenticate at time now.
func (r Robot) Active(now time.Time) bool {
	return !r.Disabled && (r.ExpiresAt == nil || now.Before(*r.ExpiresAt))
}

// Robot returns a copy of the named robot.
func (s *Store) Robot(name string) (Robot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.data.Robots[name]
	r.Permissions = append([]RobotPermission(nil), r.Permissions...)
	return r, ok
}

// Project roles.
const (
	ProjectAdmin      = "admin"      // everything, plus members and webhooks
	ProjectMaintainer = "maintainer" // pull, push, delete
	ProjectDeveloper  = "developer"  // pull, push
	ProjectGuest      = "guest"      // pull
)

// Project groups the repositories whose name starts with "<name>/".
type Project struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Public      bool              `json:"public"`            // anonymous pull
	Members     map[string]string `json:"members,omitempty"` // user → project role
	QuotaBytes  int64             `json:"quota_bytes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// ProjectOf returns the project name a repository belongs to: its first
// path segment, or "" for a repository without a slash.
func ProjectOf(repo string) string {
	if i := strings.IndexByte(repo, '/'); i > 0 {
		return repo[:i]
	}
	return ""
}

// Project returns a copy of the named project.
func (s *Store) Project(name string) (Project, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data.Projects[name]
	if ok {
		p.Members = copyMap(p.Members)
	}
	return p, ok
}

// Projects returns copies of all projects, sorted by name.
func (s *Store) Projects() []Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Project, 0, len(s.data.Projects))
	for _, p := range s.data.Projects {
		p.Members = copyMap(p.Members)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RetentionRule keeps some tags of matching repositories and deletes the
// others. A tag is deleted only if every enabled rule covering it lets it go.
type RetentionRule struct {
	Repos    string `json:"repos"`     // repository glob, e.g. "team/**"
	Tags     string `json:"tags"`      // tag glob, e.g. "*" or "dev-*"
	KeepLast int    `json:"keep_last"` // keep the N most recently pushed (0 = unused)
	KeepDays int    `json:"keep_days"` // keep tags pushed within N days (0 = unused)
	Disabled bool   `json:"disabled,omitempty"`
}

// RetentionRun records one application of the retention rules.
type RetentionRun struct {
	Start      time.Time `json:"start"`
	Trigger    string    `json:"trigger"` // "schedule" or "manual"
	User       string    `json:"user,omitempty"`
	DryRun     bool      `json:"dry_run"`
	TagsCount  int       `json:"tags_count"`
	Tags       []string  `json:"tags,omitempty"` // repo:tag, capped
	Error      string    `json:"error,omitempty"`
	DurationMs int64     `json:"duration_ms"`
}

// ImmutableRule protects matching tags from being overwritten or deleted.
type ImmutableRule struct {
	Repos    string `json:"repos"`
	Tags     string `json:"tags"`
	Disabled bool   `json:"disabled,omitempty"`
}

// Settings changed from the web admin. Zero values mean "use the env default".
type Settings struct {
	// GCInterval overrides RGSTR_GC_INTERVAL when set ("6h"; "0" = off).
	GCInterval string `json:"gc_interval,omitempty"`
}

// GCRun records one garbage collection run.
type GCRun struct {
	Start            time.Time `json:"start"`
	DurationMs       int64     `json:"duration_ms"`
	Trigger          string    `json:"trigger"` // "schedule" or "manual"
	User             string    `json:"user,omitempty"`
	DryRun           bool      `json:"dry_run"`
	IgnoreGrace      bool      `json:"ignore_grace"`
	BlobsRemoved     int       `json:"blobs_removed"`
	BytesFreed       int64     `json:"bytes_freed"`
	ManifestsRemoved int       `json:"manifests_removed"`
	UploadsRemoved   int       `json:"uploads_removed"`
	Manifests        []string  `json:"manifests,omitempty"` // repo@digest, capped
	Freed            []string  `json:"freed,omitempty"`     // deleted repos/tags/images whose data this run removed
	Error            string    `json:"error,omitempty"`
}

// MaxGCHistory is how many GC runs are kept.
const MaxGCHistory = 30

// Store guards Data and writes it to disk on every update.
type Store struct {
	path    string  // empty: in-memory only
	backend Backend // shared document instead of the file; nil: file
	mu      sync.RWMutex
	data    Data
}

// Backend keeps the data in a document shared by several rgstr processes
// (PostgreSQL): updates are atomic across processes, and Watch reports
// changes made by the others.
type Backend interface {
	Load() ([]byte, error)
	Update(fn func(old []byte) ([]byte, error)) error
	Watch(fn func())
}

// OpenShared loads the data from b and follows changes other processes
// make to it.
func OpenShared(b Backend) (*Store, error) {
	s := &Store{backend: b}
	if err := s.reload(); err != nil {
		return nil, err
	}
	b.Watch(func() {
		if err := s.reload(); err != nil {
			log.Printf("metadata: reload: %v", err)
		}
	})
	return s, nil
}

func (s *Store) reload() error {
	raw, err := s.backend.Load()
	if err != nil {
		return err
	}
	var d Data
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("metadata: %w", err)
		}
	}
	s.mu.Lock()
	s.data = d
	s.mu.Unlock()
	return nil
}

// Export returns the data as JSON (migration to a shared backend).
func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.data)
}

// Open loads <root>/meta.json, or starts empty. An empty root keeps data
// in memory only (tests).
func Open(root string) (*Store, error) {
	s := &Store{}
	if root == "" {
		return s, nil
	}
	s.path = filepath.Join(root, "meta.json")
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	return s, nil
}

// View calls fn with the data under a read lock. fn must not keep
// references to slices or maps beyond the call.
func (s *Store) View(fn func(d *Data)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.data)
}

// Update calls fn under the write lock and saves the result. If fn returns
// an error nothing is saved and in-memory changes are rolled back.
func (s *Store) Update(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend != nil {
		// Apply fn to the latest data, whichever process wrote it; the
		// cache takes the result once it is committed.
		var next Data
		err := s.backend.Update(func(old []byte) ([]byte, error) {
			next = Data{}
			if len(old) > 0 {
				if err := json.Unmarshal(old, &next); err != nil {
					return nil, err
				}
			}
			if err := fn(&next); err != nil {
				return nil, err
			}
			return json.Marshal(next)
		})
		if err == nil {
			s.data = next
		}
		return err
	}
	backup, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	if err := fn(&s.data); err != nil {
		json.Unmarshal(backup, &s.data)
		return err
	}
	if err := s.saveLocked(); err != nil {
		json.Unmarshal(backup, &s.data)
		return err
	}
	return nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
