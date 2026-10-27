// Package db keeps the state rgstr processes share in PostgreSQL when they
// run as a cluster (RGSTR_DATABASE_URL): the metadata documents (users,
// projects, robots, policies, settings, sessions), the audit log, pull
// counters, the lock that keeps garbage collection away from writes, and
// claims of scheduled jobs so they run once per cluster, not once per
// process.
package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is a connection pool with rgstr's tables.
type DB struct {
	pool *pgxpool.Pool

	mu       sync.Mutex
	watchers map[string][]func()
	cancel   context.CancelFunc
	done     chan struct{}
}

const schema = `
CREATE TABLE IF NOT EXISTS rgstr_docs (
	name       text PRIMARY KEY,
	data       bytea NOT NULL,
	version    bigint NOT NULL DEFAULT 0,
	updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS rgstr_jobs (
	name     text PRIMARY KEY,
	next_run timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS rgstr_audit (
	id    bigserial PRIMARY KEY,
	time  timestamptz NOT NULL,
	entry jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS rgstr_audit_time ON rgstr_audit (time);
CREATE TABLE IF NOT EXISTS rgstr_pulls (
	repo  text PRIMARY KEY,
	pulls bigint NOT NULL
);
`

// Advisory lock keys (arbitrary, fixed).
const (
	keyMigrate int64 = 0x7267737472000001
	keyGC      int64 = 0x7267737472000002
)

const notifyChannel = "rgstr_docs"

// Open connects to url (postgres://user:pass@host/db) and creates the
// tables if needed.
func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("RGSTR_DATABASE_URL: %w", err)
	}
	if cfg.MaxConns < 16 {
		cfg.MaxConns = 16 // locks and the listener hold connections
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	d := &DB{pool: pool, watchers: map[string][]func(){}}
	if err := d.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	lctx, cancel := context.WithCancel(context.Background())
	d.cancel, d.done = cancel, make(chan struct{})
	go d.listen(lctx)
	return d, nil
}

// migrate creates the schema; processes starting together take turns.
func (d *DB) migrate(ctx context.Context) error {
	return pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", keyMigrate); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, schema)
		return err
	})
}

// Close stops the listener and closes the pool.
func (d *DB) Close() {
	d.cancel()
	<-d.done
	d.pool.Close()
}

// Ping checks the connection (readiness).
func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

// ─── GC lock ─────────────────────────────────────────────────────────────────

// Shared holds the GC lock shared (writes that make data reachable).
func (d *DB) Shared(ctx context.Context) (func(), error) {
	return d.advisory(ctx, "pg_advisory_lock_shared", "pg_advisory_unlock_shared")
}

// Exclusive holds the GC lock exclusively (a GC sweep).
func (d *DB) Exclusive(ctx context.Context) (func(), error) {
	return d.advisory(ctx, "pg_advisory_lock", "pg_advisory_unlock")
}

// advisory takes a session-level advisory lock on a dedicated connection,
// released by the returned function. If the process dies, PostgreSQL
// drops the connection and the lock with it.
func (d *DB) advisory(ctx context.Context, lock, unlock string) (func(), error) {
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "SELECT "+lock+"($1)", keyGC); err != nil {
		conn.Release()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			uctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := conn.Exec(uctx, "SELECT "+unlock+"($1)", keyGC); err != nil {
				// Closing the session releases the lock for sure.
				conn.Conn().Close(uctx)
			}
			conn.Release()
		})
	}, nil
}

// ─── Documents ───────────────────────────────────────────────────────────────

// Doc is one shared JSON document (meta, users).
type Doc struct {
	d    *DB
	name string
}

// Doc returns the document called name.
func (d *DB) Doc(name string) *Doc { return &Doc{d: d, name: name} }

// Load returns the document (nil if it does not exist yet).
func (doc *Doc) Load() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var data []byte
	err := doc.d.pool.QueryRow(ctx, "SELECT data FROM rgstr_docs WHERE name = $1", doc.name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return data, err
}

// Update replaces the document with fn(current) atomically across
// processes (the row is locked meanwhile) and tells the others. fn
// returning nil bytes leaves the document unchanged.
func (doc *Doc) Update(fn func(old []byte) ([]byte, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return pgx.BeginFunc(ctx, doc.d.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO rgstr_docs (name, data) VALUES ($1, '') ON CONFLICT DO NOTHING",
			doc.name); err != nil {
			return err
		}
		var old []byte
		if err := tx.QueryRow(ctx, "SELECT data FROM rgstr_docs WHERE name = $1 FOR UPDATE", doc.name).
			Scan(&old); err != nil {
			return err
		}
		next, err := fn(old)
		if err != nil || next == nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE rgstr_docs SET data = $2, version = version + 1, updated_at = now() WHERE name = $1",
			doc.name, next); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel, doc.name)
		return err
	})
}

// Watch calls fn after another process (or this one) changed the
// document, and after a lost connection to the database came back.
func (doc *Doc) Watch(fn func()) {
	doc.d.mu.Lock()
	defer doc.d.mu.Unlock()
	doc.d.watchers[doc.name] = append(doc.d.watchers[doc.name], fn)
}

func (d *DB) notify(name string) {
	d.mu.Lock()
	var fns []func()
	if name == "" {
		for _, w := range d.watchers {
			fns = append(fns, w...)
		}
	} else {
		fns = append(fns, d.watchers[name]...)
	}
	d.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// listen receives change notifications until ctx ends, reconnecting with
// backoff; after a reconnect every document is reloaded (changes may have
// been missed meanwhile).
func (d *DB) listen(ctx context.Context) {
	defer close(d.done)
	backoff := time.Second
	first := true
	for ctx.Err() == nil {
		conn, err := d.pool.Acquire(ctx)
		if err == nil {
			_, err = conn.Exec(ctx, "LISTEN "+notifyChannel)
			if err == nil {
				if !first {
					d.notify("")
				}
				first, backoff = false, time.Second
				for {
					n, werr := conn.Conn().WaitForNotification(ctx)
					if werr != nil {
						err = werr
						break
					}
					d.notify(n.Payload)
				}
			}
			conn.Conn().Close(context.Background()) // never reuse a LISTEN connection
			conn.Release()
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("database: change notifications: %v (retrying)", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

// ─── Scheduled jobs ──────────────────────────────────────────────────────────

// Claim reports whether this process should run job now: the first to ask
// once its time has come wins, and the next run is due after interval.
func (d *DB) Claim(ctx context.Context, job string, interval time.Duration) (bool, error) {
	if _, err := d.pool.Exec(ctx, "INSERT INTO rgstr_jobs (name, next_run) VALUES ($1, now()) ON CONFLICT DO NOTHING",
		job); err != nil {
		return false, err
	}
	tag, err := d.pool.Exec(ctx,
		"UPDATE rgstr_jobs SET next_run = now() + make_interval(secs => $2) WHERE name = $1 AND next_run <= now() + interval '5 seconds'",
		job, interval.Seconds())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ─── Audit log ───────────────────────────────────────────────────────────────

// AddAudit stores audit entries (JSON) with their times.
func (d *DB) AddAudit(ctx context.Context, times []time.Time, entries [][]byte) error {
	batch := &pgx.Batch{}
	for i := range entries {
		batch.Queue("INSERT INTO rgstr_audit (time, entry) VALUES ($1, $2)", times[i], entries[i])
	}
	return d.pool.SendBatch(ctx, batch).Close()
}

// RecentAudit returns up to limit entries before before (zero: now),
// newest first.
func (d *DB) RecentAudit(ctx context.Context, before time.Time, limit int) ([][]byte, error) {
	if before.IsZero() {
		before = time.Now().Add(time.Hour)
	}
	rows, err := d.pool.Query(ctx, "SELECT entry FROM rgstr_audit WHERE time < $1 ORDER BY time DESC, id DESC LIMIT $2",
		before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) ([]byte, error) {
		var b []byte
		err := r.Scan(&b)
		return b, err
	})
}

// PruneAudit drops entries older than before.
func (d *DB) PruneAudit(ctx context.Context, before time.Time) error {
	_, err := d.pool.Exec(ctx, "DELETE FROM rgstr_audit WHERE time < $1", before)
	return err
}

// ─── Pull counters ───────────────────────────────────────────────────────────

// AddPulls adds to the pull counters of repositories.
func (d *DB) AddPulls(ctx context.Context, delta map[string]int64) error {
	batch := &pgx.Batch{}
	for repo, n := range delta {
		batch.Queue("INSERT INTO rgstr_pulls (repo, pulls) VALUES ($1, $2) ON CONFLICT (repo) DO UPDATE SET pulls = rgstr_pulls.pulls + $2",
			repo, n)
	}
	return d.pool.SendBatch(ctx, batch).Close()
}

// Pulls returns every repository's pull count.
func (d *DB) Pulls(ctx context.Context) (map[string]int64, error) {
	rows, err := d.pool.Query(ctx, "SELECT repo, pulls FROM rgstr_pulls")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var repo string
		var n int64
		if err := rows.Scan(&repo, &n); err != nil {
			return nil, err
		}
		out[repo] = n
	}
	return out, rows.Err()
}

// SetPulls replaces the pull counters (migration).
func (d *DB) SetPulls(ctx context.Context, pulls map[string]int64) error {
	batch := &pgx.Batch{}
	for repo, n := range pulls {
		batch.Queue("INSERT INTO rgstr_pulls (repo, pulls) VALUES ($1, $2) ON CONFLICT (repo) DO UPDATE SET pulls = $2", repo, n)
	}
	return d.pool.SendBatch(ctx, batch).Close()
}
