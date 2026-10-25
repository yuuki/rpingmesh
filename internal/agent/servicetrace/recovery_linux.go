//go:build linux

package servicetrace

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// RecoverQPs attempts mlx5 address-vector recovery after generic enumeration.
// CAP_NET_ADMIN is required for raw queries. The caller waits at most thirty
// seconds; a stuck kernel query cannot accumulate workers across refreshes.
func RecoverQPs(ctx context.Context, devices map[uint32]string, resources []QPResource) ([]QPResource, error) {
	owned := append([]QPResource(nil), resources...)
	return boundedQPCollection(ctx, devices, 30*time.Second, func(ctx context.Context, devices map[uint32]string) ([]QPResource, error) {
		fd, err := openRDMASocket()
		if err != nil {
			return owned, err
		}
		defer unix.Close(fd)
		var seq uint32
		dump := func(ctx context.Context, cmd uint16, attrs []byte) ([][]byte, error) {
			seq++
			return requestRDMA(ctx, fd, seq, cmd, attrs, true)
		}
		query := func(ctx context.Context, cmd uint16, attrs []byte) ([][]byte, error) {
			seq++
			return requestRDMA(ctx, fd, seq, cmd, attrs, false)
		}
		return recoverQPs(ctx, devices, owned, dump, query, func(name string) string {
			path, err := os.Readlink(filepath.Join(DefaultSysfsRoot, "class", "infiniband", name, "device", "driver"))
			if err != nil {
				return ""
			}
			return filepath.Base(path)
		})
	})
}
