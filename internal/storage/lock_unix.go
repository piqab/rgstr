//go:build linux || darwin || freebsd

package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// LockFile is the file in the storage root that one rgstr process holds
// locked while it runs.
const LockFile = ".rgstr.lock"

// Lock makes sure no other rgstr process uses the storage root: two
// processes on one data directory (two containers on a shared volume, NFS)
// would corrupt each other's state. The lock is held until the returned
// function is called or the process exits; the kernel releases it even
// after a crash, so a stale lock file never blocks a restart.
func Lock(root string) (unlock func(), err error) {
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(root, LockFile)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		b := make([]byte, 64)
		n, _ := f.ReadAt(b, 0)
		f.Close()
		if err == syscall.EWOULDBLOCK {
			holder := strings.TrimSpace(string(b[:n]))
			return nil, fmt.Errorf("%s is in use by another rgstr process (%s); "+
				"run one rgstr per data directory", root, holder)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	host, _ := os.Hostname()
	f.Truncate(0)
	f.WriteAt([]byte("pid "+strconv.Itoa(os.Getpid())+" on "+host+"\n"), 0)
	return func() { f.Close() }, nil
}
