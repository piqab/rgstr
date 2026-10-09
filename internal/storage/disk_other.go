//go:build !(linux || darwin || freebsd)

package storage

// Disk is not supported on this platform.
func (fs *Filesystem) Disk() (DiskInfo, error) { return DiskInfo{}, nil }
