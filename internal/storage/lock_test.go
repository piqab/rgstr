//go:build linux || darwin || freebsd

package storage

import (
	"strings"
	"testing"
)

func TestLockRefusesSecondProcess(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	// flock conflicts between open file descriptions, so a second Lock in
	// the same process behaves like another process.
	if _, err := Lock(dir); err == nil || !strings.Contains(err.Error(), "in use by another rgstr process") {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	unlock2, err := Lock(dir)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}
