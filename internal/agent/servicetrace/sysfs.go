package servicetrace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yuuki/rpingmesh/internal/probe"
)

// DefaultSysfsRoot is where sysfs is mounted.
const DefaultSysfsRoot = "/sys"

// MakeDev encodes a device number the way the kernel's struct inode stores
// it (new_encode_dev: 12-bit major above a 20-bit minor), which is the form
// the tracer reports in Event.Dev.
func MakeDev(major, minor uint32) uint32 {
	return major<<20 | minor
}

// UverbsDevices maps the device number of every uverbs node
// (/sys/class/infiniband_verbs/uverbsN) to the name of the RDMA device it
// belongs to, so that Event.Dev can be resolved to an RDMA device name.
func UverbsDevices(sysfsRoot string) (map[uint32]string, error) {
	if sysfsRoot == "" {
		sysfsRoot = DefaultSysfsRoot
	}
	classDir := filepath.Join(sysfsRoot, "class", "infiniband_verbs")
	entries, err := os.ReadDir(classDir)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]string, len(entries))
	for _, e := range entries {
		dir := filepath.Join(classDir, e.Name())
		devText, err := os.ReadFile(filepath.Join(dir, "dev"))
		if err != nil {
			continue
		}
		var major, minor uint32
		if _, err := fmt.Sscanf(strings.TrimSpace(string(devText)), "%d:%d", &major, &minor); err != nil {
			continue
		}
		ibdev, err := os.ReadFile(filepath.Join(dir, "ibdev"))
		if err != nil {
			continue
		}
		if name := strings.TrimSpace(string(ibdev)); name != "" {
			out[MakeDev(major, minor)] = name
		}
	}
	return out, nil
}

// PortGID reads the GID at index of an RDMA device port from sysfs
// (/sys/class/infiniband/<device>/ports/<port>/gids/<index>), the source GID
// a connection's sgid_index refers to.
func PortGID(sysfsRoot, device string, port, index uint8) ([16]byte, error) {
	if sysfsRoot == "" {
		sysfsRoot = DefaultSysfsRoot
	}
	path := filepath.Join(sysfsRoot, "class", "infiniband", device, "ports", fmt.Sprint(port), "gids", fmt.Sprint(index))
	b, err := os.ReadFile(path)
	if err != nil {
		return [16]byte{}, err
	}
	gid, err := probe.ParseGID(strings.TrimSpace(string(b)))
	if err != nil {
		return [16]byte{}, fmt.Errorf("%s: %w", path, err)
	}
	return gid, nil
}
