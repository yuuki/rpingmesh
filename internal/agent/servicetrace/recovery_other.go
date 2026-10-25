//go:build !linux

package servicetrace

import "context"

// RecoverQPs cannot recover driver state on platforms without RDMA netlink.
func RecoverQPs(_ context.Context, _ map[uint32]string, resources []QPResource) ([]QPResource, error) {
	return resources, ErrUnsupported
}
