// Package stats tracks per-repository pull counts and persists them to disk.
package stats

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Counter tracks how many times each repository has been pulled.
// It is safe for concurrent use. Counts are persisted to stats.json in dataDir.
type Counter struct {
	mu      sync.Mutex
	pulls   map[string]int64
	dataDir string

	shared  Shared           // counts kept by all processes; nil: stats.json
	pending map[string]int64 // pulls not yet added to shared
}

// Shared keeps counts for several rgstr processes (PostgreSQL).
type Shared interface {
	AddPulls(ctx context.Context, delta map[string]int64) error
	Pulls(ctx context.Context) (map[string]int64, error)
}

// flushInterval is how often pulls are added to the shared counts.
const flushInterval = 5 * time.Second

// NewShared creates a Counter on shared counts; pulls are added to them
// every few seconds, and the totals of all processes are read back.
func NewShared(s Shared) *Counter {
	c := &Counter{pulls: map[string]int64{}, shared: s, pending: map[string]int64{}}
	c.flush()
	go func() {
		for range time.Tick(flushInterval) {
			c.flush()
		}
	}()
	return c
}

func (c *Counter) flush() {
	c.mu.Lock()
	delta := c.pending
	c.pending = map[string]int64{}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if len(delta) > 0 {
		if err := c.shared.AddPulls(ctx, delta); err != nil {
			log.Printf("stats: %v", err)
			c.mu.Lock() // keep them for the next try
			for k, v := range delta {
				c.pending[k] += v
			}
			c.mu.Unlock()
			return
		}
	}
	totals, err := c.shared.Pulls(ctx)
	if err != nil {
		log.Printf("stats: %v", err)
		return
	}
	c.mu.Lock()
	for k, v := range c.pending { // pulls since the swap above
		totals[k] += v
	}
	c.pulls = totals
	c.mu.Unlock()
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
	if c.shared != nil {
		c.pending[repo]++
		c.mu.Unlock()
		return
	}
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
