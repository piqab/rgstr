// Package meta persists registry metadata managed from the web admin —
// settings, GC history, policies — in <storage>/meta.json.
package meta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Data is everything stored in meta.json.
type Data struct {
	Settings  Settings `json:"settings"`
	GCHistory []GCRun  `json:"gc_history,omitempty"`
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
	Error            string    `json:"error,omitempty"`
}

// MaxGCHistory is how many GC runs are kept.
const MaxGCHistory = 30

// Store guards Data and writes it to disk on every update.
type Store struct {
	path string // empty: in-memory only
	mu   sync.RWMutex
	data Data
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
