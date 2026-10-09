// Package maint runs scheduled maintenance — tag retention, then garbage
// collection — and records each run in the metadata store.
package maint

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/config"
	"rgstr/internal/meta"
	"rgstr/internal/ops"
	"rgstr/internal/storage"
)

// ErrBusy is returned when a run is already in progress.
var ErrBusy = errors.New("garbage collection is already running")

// Runner schedules and runs garbage collection.
type Runner struct {
	cfg   *config.Config
	store *storage.Filesystem
	meta  *meta.Store
	ops   *ops.Ops

	running sync.Mutex    // held while a run is in progress
	wake    chan struct{} // reschedule after a settings change

	mu      sync.Mutex
	nextRun time.Time
}

// New creates a Runner.
func New(cfg *config.Config, store *storage.Filesystem, m *meta.Store, o *ops.Ops) *Runner {
	return &Runner{cfg: cfg, store: store, meta: m, ops: o, wake: make(chan struct{}, 1)}
}

// Interval returns the effective GC interval (0 = scheduled runs off) and
// whether it was set from the web admin rather than RGSTR_GC_INTERVAL.
func (r *Runner) Interval() (time.Duration, bool) {
	var s string
	r.meta.View(func(d *meta.Data) { s = d.Settings.GCInterval })
	if s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d, true
		}
	}
	return r.cfg.GCInterval, false
}

// SetInterval stores a new GC interval ("" restores the env default) and
// reschedules the next run.
func (r *Runner) SetInterval(s string) error {
	if s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		if d != 0 && d < time.Minute {
			return errors.New("interval must be at least 1m, or 0 to disable")
		}
	}
	if err := r.meta.Update(func(d *meta.Data) error {
		d.Settings.GCInterval = s
		return nil
	}); err != nil {
		return err
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

// NextRun returns when the next scheduled run starts (zero if off).
func (r *Runner) NextRun() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nextRun
}

// Running reports whether a run is in progress.
func (r *Runner) Running() bool {
	if r.running.TryLock() {
		r.running.Unlock()
		return false
	}
	return true
}

// History returns past runs, newest first.
func (r *Runner) History() []meta.GCRun {
	var out []meta.GCRun
	r.meta.View(func(d *meta.Data) { out = append(out, d.GCHistory...) })
	return out
}

// Start runs GC on schedule until ctx is cancelled.
func (r *Runner) Start(ctx context.Context) {
	go func() {
		for {
			interval, _ := r.Interval()
			var timer <-chan time.Time
			r.mu.Lock()
			if interval > 0 {
				r.nextRun = time.Now().Add(interval)
				timer = time.After(interval)
			} else {
				r.nextRun = time.Time{}
			}
			r.mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-r.wake:
				// Interval changed: reschedule from now.
			case <-timer:
				// Retention first, so GC frees the space of expired tags.
				if _, err := r.RunRetention("schedule", "", false); err != nil {
					log.Printf("retention error: %v", err)
				}
				if _, err := r.Run("schedule", "", storage.GCOptions{}); err != nil && !errors.Is(err, ErrBusy) {
					log.Printf("gc error: %v", err)
				}
			}
		}
	}()
}

// Run collects garbage now and records the run. trigger is "schedule" or
// "manual"; user is who started a manual run.
func (r *Runner) Run(trigger, user string, opts storage.GCOptions) (meta.GCRun, error) {
	if !r.running.TryLock() {
		return meta.GCRun{}, ErrBusy
	}
	defer r.running.Unlock()

	run := meta.GCRun{
		Start:       time.Now().UTC(),
		Trigger:     trigger,
		User:        user,
		DryRun:      opts.DryRun,
		IgnoreGrace: opts.IgnoreGrace,
	}
	res, err := r.store.CollectGarbage(opts)
	run.DurationMs = time.Since(run.Start).Milliseconds()
	run.BlobsRemoved = res.BlobsRemoved
	run.BytesFreed = res.BytesFreed
	run.ManifestsRemoved = res.ManifestsRemoved
	run.UploadsRemoved = res.UploadsRemoved
	run.Manifests = res.Manifests
	if err != nil {
		run.Error = err.Error()
	}
	if !opts.DryRun && err == nil {
		run.Freed = r.reconcile()
	}

	r.ops.Audit(actor(user), audit.GCRun, "", gcDetail(run), err)
	if serr := r.meta.Update(func(d *meta.Data) error {
		d.GCHistory = append([]meta.GCRun{run}, d.GCHistory...)
		if len(d.GCHistory) > meta.MaxGCHistory {
			d.GCHistory = d.GCHistory[:meta.MaxGCHistory]
		}
		return nil
	}); serr != nil {
		log.Printf("gc: save history: %v", serr)
	}
	return run, err
}

// MaxRetentionListed caps RetentionRun.Tags.
const MaxRetentionListed = 500

// RunRetention applies the retention rules now and records the run. With no
// rules configured nothing is recorded.
func (r *Runner) RunRetention(trigger, user string, dryRun bool) (meta.RetentionRun, error) {
	run := meta.RetentionRun{Start: time.Now().UTC(), Trigger: trigger, User: user, DryRun: dryRun}
	var rules int
	r.meta.View(func(d *meta.Data) { rules = len(d.Retention) })
	if rules == 0 {
		return run, nil
	}
	tags, err := r.ops.ApplyRetention(actor(user), dryRun)
	detail := fmt.Sprintf("%d tag(s)", len(tags))
	if dryRun {
		detail += ", dry run"
	}
	r.ops.Audit(actor(user), audit.RetentionRun, "", detail, err)
	run.DurationMs = time.Since(run.Start).Milliseconds()
	run.TagsCount = len(tags)
	if len(tags) > MaxRetentionListed {
		tags = tags[:MaxRetentionListed]
	}
	run.Tags = tags
	if err != nil {
		run.Error = err.Error()
	}
	if serr := r.meta.Update(func(d *meta.Data) error {
		d.RetentionHistory = append([]meta.RetentionRun{run}, d.RetentionHistory...)
		if len(d.RetentionHistory) > meta.MaxGCHistory {
			d.RetentionHistory = d.RetentionHistory[:meta.MaxGCHistory]
		}
		return nil
	}); serr != nil {
		log.Printf("retention: save history: %v", serr)
	}
	return run, err
}

// actor is the user who started a run, or the system for scheduled runs.
func actor(user string) ops.Actor {
	if user == "" {
		return ops.System
	}
	return ops.Actor{Name: user}
}

func gcDetail(r meta.GCRun) string {
	d := fmt.Sprintf("freed %d bytes, %d blob(s), %d image(s)", r.BytesFreed, r.BlobsRemoved, r.ManifestsRemoved)
	if r.DryRun {
		d += ", dry run"
	}
	if r.IgnoreGrace {
		d += ", no grace period"
	}
	return d
}

// reconcile drops pending entries whose data is gone (returning them as
// freed) and entries older than the grace period plus a day whose data is
// still used by other images.
func (r *Runner) reconcile() []string {
	var pending []meta.PendingFree
	r.meta.View(func(d *meta.Data) { pending = append(pending, d.PendingFree...) })
	if len(pending) == 0 {
		return nil
	}
	var freed []string
	var keep []meta.PendingFree
	for _, p := range pending {
		_, present := r.store.BlobsSize(p.Blobs)
		switch {
		case present == 0:
			freed = append(freed, p.Kind+" "+p.Ref)
		case time.Since(p.Time) > r.cfg.UploadTTL+24*time.Hour:
			// Still on disk long after the grace period: shared with
			// images that are in use.
		default:
			keep = append(keep, p)
		}
	}
	r.meta.Update(func(d *meta.Data) error {
		// Keep entries added while GC ran.
		if len(d.PendingFree) >= len(pending) {
			keep = append(keep, d.PendingFree[len(pending):]...)
		}
		d.PendingFree = keep
		return nil
	})
	return freed
}

// Pending is deleted data still on disk.
type Pending struct {
	Ref   string    `json:"ref"`
	Kind  string    `json:"kind"`
	User  string    `json:"user,omitempty"`
	Time  time.Time `json:"time"`
	Bytes int64     `json:"bytes"` // of its blobs still on disk (may be shared)
}

// Pending lists deleted repositories, tags and images whose data GC has
// not removed yet, newest first.
func (r *Runner) Pending() []Pending {
	var list []meta.PendingFree
	r.meta.View(func(d *meta.Data) { list = append(list, d.PendingFree...) })
	out := []Pending{}
	for i := len(list) - 1; i >= 0; i-- {
		p := list[i]
		size, present := r.store.BlobsSize(p.Blobs)
		if present == 0 {
			continue
		}
		out = append(out, Pending{Ref: p.Ref, Kind: p.Kind, User: p.User, Time: p.Time, Bytes: size})
	}
	return out
}

// Estimate is what GC would free.
type Estimate struct {
	Next  int64 `json:"next"`  // at the next regular run
	Grace int64 `json:"grace"` // additionally, once the grace period ends
}

// Estimate runs two dry runs (regular and ignoring the grace period).
func (r *Runner) Estimate() (Estimate, error) {
	next, err := r.store.CollectGarbage(storage.GCOptions{DryRun: true})
	if err != nil {
		return Estimate{}, err
	}
	all, err := r.store.CollectGarbage(storage.GCOptions{DryRun: true, IgnoreGrace: true})
	if err != nil {
		return Estimate{}, err
	}
	grace := all.BytesFreed - next.BytesFreed
	if grace < 0 {
		grace = 0
	}
	return Estimate{Next: next.BytesFreed, Grace: grace}, nil
}

// FreeNow runs GC right after a deletion, lifting the grace period only for
// the data of the pending entries refs.
func (r *Runner) FreeNow(user string, refs []string) (meta.GCRun, error) {
	want := map[string]bool{}
	for _, ref := range refs {
		want[ref] = true
	}
	expire := map[string]storage.ExpireSet{}
	r.meta.View(func(d *meta.Data) {
		for _, p := range d.PendingFree {
			if want[p.Ref] {
				e := expire[p.Repo]
				e.Manifests = append(e.Manifests, p.Manifests...)
				e.Blobs = append(e.Blobs, p.Blobs...)
				expire[p.Repo] = e
			}
		}
	})
	return r.Run("manual", user, storage.GCOptions{Expire: expire})
}
