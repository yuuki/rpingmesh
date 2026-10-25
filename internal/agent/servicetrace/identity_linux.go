//go:build linux

package servicetrace

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// cgroupID reads the full kernfs ID, including its generation, rather than
// assuming a directory's inode number is the ID on every kernel.
func cgroupID(path string) (uint64, error) {
	// Other kernfs filesystems, including cgroup v1, use the same handle
	// format but allocate IDs independently of the BPF default hierarchy.
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0, fmt.Errorf("not a cgroup v2 filesystem")
	}
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0, err
	}
	if handle.Type() != 0xfe || len(handle.Bytes()) != 8 {
		return 0, fmt.Errorf("not a cgroup v2 file handle")
	}
	return binary.NativeEndian.Uint64(handle.Bytes()), nil
}
