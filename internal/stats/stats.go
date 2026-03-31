// Package stats tracks per-repository pull counts and persists them to disk.
package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Counter tracks how many times each repository has been pulled.
// It is safe for concurrent use. Counts are persisted to stats.json in dataDir.
type Counter struct {
	mu      sync.Mutex
	pulls   map[string]int64
	dataDir string
}

// Snapshot is a point-in-time copy of all counters.
type Snapshot struct {
	Pulls map[string]int64 `json:"pulls"`
}

// New creates a Counter and loads any previously persisted counts from dataDir.
func New(dataDir string) *Counter {
	c := &Counter{
		pulls:   make(map[string]int64),
		dataDir: dataDir,
	}
	c.load()
	return c
}

// RecordPull increments the pull counter for repo and persists the new state.
func (c *Counter) RecordPull(repo string) {
	c.mu.Lock()
	c.pulls[repo]++
	snap := c.snapshot()
	c.mu.Unlock()
	c.persist(snap)
}

// Snapshot returns a copy of the current counters.
func (c *Counter) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshot()
}

func (c *Counter) snapshot() Snapshot {
	m := make(map[string]int64, len(c.pulls))
	for k, v := range c.pulls {
		m[k] = v
	}
	return Snapshot{Pulls: m}
}

func (c *Counter) filePath() string {
	return filepath.Join(c.dataDir, "stats.json")
}

func (c *Counter) load() {
	data, err := os.ReadFile(c.filePath())
	if err != nil {
		return // first run or missing file — start from zero
	}
	var snap Snapshot
	if json.Unmarshal(data, &snap) == nil && snap.Pulls != nil {
		c.pulls = snap.Pulls
	}
}

func (c *Counter) persist(snap Snapshot) {
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp := c.filePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	os.Rename(tmp, c.filePath()) // atomic on Linux
}
