//go:build !linux

package servicetrace

import "context"

// SnapshotQPs is unavailable on platforms without RDMA netlink.
func SnapshotQPs(context.Context, map[uint32]string) ([]QPResource, error) {
	return nil, ErrUnsupported
}
