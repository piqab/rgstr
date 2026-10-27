package db

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two DB values stand for two rgstr processes sharing the database.
// RGSTR_TEST_DATABASE_URL=postgres://postgres:pw@localhost:15432/rgstr?sslmode=disable
func open2(t *testing.T) (*DB, *DB) {
	url := os.Getenv("RGSTR_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RGSTR_TEST_DATABASE_URL not set")
	}
	var a, b *DB
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2) // both migrate at once, as pods starting together do
	go func() { defer wg.Done(); a, errA = Open(context.Background(), url) }()
	go func() { defer wg.Done(); b, errB = Open(context.Background(), url) }()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestDocUpdatesAreAtomicAcrossProcesses(t *testing.T) {
	a, b := open2(t)
	name := "test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var changed atomic.Int32
	b.Doc(name).Watch(func() { changed.Add(1) })

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		db := a
		if i%2 == 1 {
			db = b
		}
		go func() {
			defer wg.Done()
			err := db.Doc(name).Update(func(old []byte) ([]byte, error) {
				n, _ := strconv.Atoi(string(old))
				return []byte(strconv.Itoa(n + 1)), nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, _ := a.Doc(name).Load()
	if string(got) != "40" {
		t.Fatalf("counter %q, want 40 (lost updates)", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for changed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if changed.Load() == 0 {
		t.Error("no change notification")
	}
}

func TestGCLock(t *testing.T) {
	a, b := open2(t)
	ctx := context.Background()
	r1, err := a.Shared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := b.Shared(ctx) // shared locks coexist
	got := make(chan struct{})
	go func() {
		release, err := b.Exclusive(ctx)
		if err == nil {
			close(got)
			release()
		}
	}()
	select {
	case <-got:
		t.Fatal("exclusive lock granted while shared locks are held")
	case <-time.After(300 * time.Millisecond):
	}
	r1()
	r2()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive lock not granted after release")
	}
}

func TestClaimRunsOncePerInterval(t *testing.T) {
	a, b := open2(t)
	job := "job-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	ctx := context.Background()
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		db := a
		if i%2 == 1 {
			db = b
		}
		go func() {
			defer wg.Done()
			if ok, err := db.Claim(ctx, job, time.Hour); err == nil && ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Errorf("%d processes ran the job, want 1", won.Load())
	}
}

func TestAuditAndPulls(t *testing.T) {
	a, _ := open2(t)
	ctx := context.Background()
	now := time.Now()
	if err := a.AddAudit(ctx, []time.Time{now}, [][]byte{[]byte(`{"action":"test"}`)}); err != nil {
		t.Fatal(err)
	}
	recent, err := a.RecentAudit(ctx, time.Time{}, 1)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent: %v %v", recent, err)
	}
	repo := "r-" + strconv.FormatInt(now.UnixNano(), 36)
	a.AddPulls(ctx, map[string]int64{repo: 2})
	a.AddPulls(ctx, map[string]int64{repo: 3})
	if p, _ := a.Pulls(ctx); p[repo] != 5 {
		t.Errorf("pulls %d, want 5", p[repo])
	}
}
