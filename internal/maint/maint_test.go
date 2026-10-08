package maint

import (
	"testing"
	"time"

	"rgstr/internal/config"
	"rgstr/internal/meta"
	"rgstr/internal/storage"
)

func newRunner(t *testing.T) *Runner {
	t.Helper()
	cfg := &config.Config{StorageRoot: t.TempDir(), GCInterval: time.Hour, UploadTTL: time.Hour}
	store, err := storage.NewFilesystem(cfg.StorageRoot, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m, err := meta.Open(cfg.StorageRoot)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, store, m)
}

func TestIntervalOverride(t *testing.T) {
	r := newRunner(t)
	if d, fromUI := r.Interval(); d != time.Hour || fromUI {
		t.Errorf("default: got %v %v, want 1h from env", d, fromUI)
	}
	for _, bad := range []string{"soon", "10s"} {
		if err := r.SetInterval(bad); err == nil {
			t.Errorf("SetInterval(%q) accepted", bad)
		}
	}
	if err := r.SetInterval("6h"); err != nil {
		t.Fatal(err)
	}
	if d, fromUI := r.Interval(); d != 6*time.Hour || !fromUI {
		t.Errorf("override: got %v %v", d, fromUI)
	}
	r.SetInterval("0")
	if d, _ := r.Interval(); d != 0 {
		t.Errorf("off: got %v", d)
	}
	r.SetInterval("")
	if d, fromUI := r.Interval(); d != time.Hour || fromUI {
		t.Errorf("reset: got %v %v", d, fromUI)
	}

	// Persisted across restarts.
	r.SetInterval("12h")
	m, _ := meta.Open(r.cfg.StorageRoot)
	if d, _ := New(r.cfg, r.store, m).Interval(); d != 12*time.Hour {
		t.Errorf("after reopen: got %v", d)
	}
}

func TestRunHistoryAndBusy(t *testing.T) {
	r := newRunner(t)
	for i := 0; i < meta.MaxGCHistory+5; i++ {
		if _, err := r.Run("manual", "alice", storage.GCOptions{DryRun: i == 0}); err != nil {
			t.Fatal(err)
		}
	}
	h := r.History()
	if len(h) != meta.MaxGCHistory {
		t.Errorf("history length: got %d want %d", len(h), meta.MaxGCHistory)
	}
	if h[0].User != "alice" || h[0].Trigger != "manual" || h[0].DryRun {
		t.Errorf("newest run: %+v", h[0])
	}

	r.running.Lock()
	if _, err := r.Run("manual", "alice", storage.GCOptions{}); err != ErrBusy {
		t.Errorf("concurrent run: got %v want ErrBusy", err)
	}
	if !r.Running() {
		t.Error("Running() = false during a run")
	}
	r.running.Unlock()
}
