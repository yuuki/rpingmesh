package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// deviceWatchInterval is how often the agent checks that every opened
	// RDMA device is still registered. A removed device fails every probe
	// with send_error, so a few seconds of detection delay is cheap.
	deviceWatchInterval = 5 * time.Second

	// deviceLostStopTimeout bounds the shutdown after a device was lost.
	// Tearing down verbs resources on a device the kernel already removed
	// should not block, but if it did, the agent would never exit and
	// systemd would never restart it.
	deviceLostStopTimeout = 30 * time.Second
)

// watchedDevice is an opened RDMA device's uverbs node in sysfs
// (/sys/class/infiniband_verbs/uverbsN), recorded at startup.
//
// The uverbs node, not /sys/class/infiniband/<dev>, is what tells that the
// device is gone: on unregistration the kernel deletes the uverbs node
// first, and only then waits for open contexts to close (on drivers without
// disassociate_ucontext, such as rxe) before removing the IB device. A
// watch on the IB device would wait for the agent to close the device while
// the kernel waits for the agent. The node's inode changes when the device
// is re-registered, even under the same name and uverbs number, and its
// ibdev attribute follows a rename.
type watchedDevice struct {
	name   string
	netdev string
	uverbs string // path of the uverbs node under the sysfs root
	ino    uint64
}

// uverbsClassDir returns the sysfs directory listing the uverbs nodes.
func uverbsClassDir(sysfsRoot string) string {
	return filepath.Join(sysfsRoot, "class", "infiniband_verbs")
}

// findUverbsNode returns the path of the uverbs node whose ibdev attribute
// names device.
func findUverbsNode(sysfsRoot, device string) (string, error) {
	entries, err := os.ReadDir(uverbsClassDir(sysfsRoot))
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		path := filepath.Join(uverbsClassDir(sysfsRoot), e.Name())
		if ibdev, err := readIBDev(path); err == nil && ibdev == device {
			return path, nil
		}
	}
	return "", fmt.Errorf("no uverbs node for RDMA device %s", device)
}

// readIBDev reads the IB device name a uverbs node belongs to.
func readIBDev(uverbsPath string) (string, error) {
	b, err := os.ReadFile(filepath.Join(uverbsPath, "ibdev"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// inode returns the inode of path, following symlinks (the class entries are
// symlinks to the device directories).
func inode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("no inode for %s", path)
	}
	return uint64(st.Ino), nil
}

// recordWatchedDevices records the uverbs node of every opened device. A
// device whose node cannot be found (e.g. /sys/class/infiniband_verbs is not
// mounted in a container) is not watched, so a missing sysfs never makes a
// healthy agent exit.
func (a *Agent) recordWatchedDevices() {
	a.watchedDevices = nil
	for i, dev := range a.devices {
		path, err := findUverbsNode(a.sysfsRoot, dev.Info.DeviceName)
		var ino uint64
		if err == nil {
			ino, err = inode(path)
		}
		if err != nil {
			a.logger.Warn().Err(err).
				Str("device", dev.Info.DeviceName).
				Msg("Cannot find the device's uverbs node in sysfs; its removal will not be detected")
			continue
		}
		a.watchedDevices = append(a.watchedDevices, watchedDevice{
			name:   dev.Info.DeviceName,
			netdev: a.cachedNetdev(i),
			uverbs: path,
			ino:    ino,
		})
	}
}

// checkWatchedDevice returns a non-nil error when the device was
// unregistered, re-registered (its open context is dead either way), or
// renamed. A rename leaves the context working, but device_tor_ids,
// device_plane_ids, the device filters, and the source_rdma_device label
// are keyed by name, so the agent restarts to apply them to the new name.
// Any other read error is not treated as a loss.
func checkWatchedDevice(d watchedDevice) error {
	ino, err := inode(d.uverbs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("RDMA device %s (netdev %q) was unregistered by the kernel", d.name, d.netdev)
	case err != nil:
		return nil
	case ino != d.ino:
		return fmt.Errorf("RDMA device %s (netdev %q) was re-registered; its open context is no longer valid",
			d.name, d.netdev)
	}
	ibdev, err := readIBDev(d.uverbs)
	if err == nil && ibdev != d.name {
		return fmt.Errorf("RDMA device %s (netdev %q) was renamed to %s", d.name, d.netdev, ibdev)
	}
	return nil
}

// startDeviceWatch starts the goroutine that checks the watched devices
// every deviceWatchInterval. On the first lost device it logs the loss,
// sends it on a.deviceLost, and exits; Run then stops the agent and returns
// an error so that the process exits non-zero and systemd restarts it with
// the current device set. The agent keeps no handle on a removed device
// that could ever work again: a RoCE LAG change, NIC reset, driver reload,
// or hot unplug re-registers the device, often under another name.
func (a *Agent) startDeviceWatch(ctx context.Context) {
	if len(a.watchedDevices) == 0 {
		return
	}
	a.deviceWatchStopCh = make(chan struct{})
	a.deviceWatchWg.Add(1)
	go func() {
		defer a.deviceWatchWg.Done()
		ticker := time.NewTicker(a.watchInterval())
		defer ticker.Stop()
		for {
			select {
			case <-a.deviceWatchStopCh:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, d := range a.watchedDevices {
					if err := checkWatchedDevice(d); err != nil {
						a.logger.Warn().
							Str("device", d.name).
							Str("netdev", d.netdev).
							Err(err).
							Msg("Opened RDMA device was removed, re-registered, or renamed; stopping the agent so it restarts with the current devices")
						select {
						case a.deviceLost <- err:
						default:
						}
						return
					}
				}
			}
		}
	}()
}

// stopDeviceWatch stops the device watch goroutine and waits for it. It is a
// no-op if the watch was never started.
func (a *Agent) stopDeviceWatch() {
	if a.deviceWatchStopCh == nil {
		return
	}
	close(a.deviceWatchStopCh)
	a.deviceWatchWg.Wait()
	a.deviceWatchStopCh = nil
}

// watchInterval returns the device check period; tests shorten it.
func (a *Agent) watchInterval() time.Duration {
	if a.deviceWatchPeriod > 0 {
		return a.deviceWatchPeriod
	}
	return deviceWatchInterval
}
