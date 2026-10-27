//go:build linux || darwin || freebsd

package storage

import "syscall"

// Disk reports the size of the filesystem holding the storage root
// (unsupported for object storage).
func (fs *Filesystem) Disk() (DiskInfo, error) {
	root := fs.localPath(".")
	if root == "" {
		return DiskInfo{}, nil
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(root, &st); err != nil {
		return DiskInfo{}, err
	}
	bs := uint64(st.Bsize)
	return DiskInfo{
		Total:     st.Blocks * bs,
		Free:      st.Bavail * bs,
		Supported: true,
	}, nil
}
