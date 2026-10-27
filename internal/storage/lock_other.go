//go:build !(linux || darwin || freebsd)

package storage

// LockFile is the file in the storage root that one rgstr process holds
// locked while it runs.
const LockFile = ".rgstr.lock"

// Lock is not supported on this platform.
func Lock(root string) (unlock func(), err error) { return func() {}, nil }
