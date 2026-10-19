package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// watchedDevice is an opened RDMA device's identity in sysfs, recorded at
// startup so a later check can tell that the device was unregistered, or
// that its name now belongs to a different device.
type watchedDevice struct {
	name     string
	netdev   string
	nodeGUID string
}

// nodeGUIDPath returns the sysfs node_guid file of an RDMA device.
func nodeGUIDPath(sysfsRoot, device string) string {
	return filepath.Join(sysfsRoot, "class", "infiniband", device, "node_guid")
}

// readNodeGUID reads an RDMA device's node GUID from sysfs.
func readNodeGUID(sysfsRoot, device string) (string, error) {
	b, err := os.ReadFile(nodeGUIDPath(sysfsRoot, device))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// recordWatchedDevices records the sysfs identity of every opened device.
// A device whose node GUID cannot be read (e.g. /sys/class/infiniband is not
// mounted in a container) is not watched, so a missing sysfs never makes a
// healthy agent exit.
func (a *Agent) recordWatchedDevices() {
	a.watchedDevices = nil
	for i, dev := range a.devices {
		guid, err := readNodeGUID(a.sysfsRoot, dev.Info.DeviceName)
		if err != nil || guid == "" {
			a.logger.Warn().Err(err).
				Str("device", dev.Info.DeviceName).
				Msg("Cannot read the device's node GUID from sysfs; its removal will not be detected")
			continue
		}
		a.watchedDevices = append(a.watchedDevices, watchedDevice{
			name:     dev.Info.DeviceName,
			netdev:   a.cachedNetdev(i),
			nodeGUID: guid,
		})
	}
}

// checkWatchedDevice returns a non-nil error when the device is no longer
// registered under its name, or its name now belongs to another device (a
// different node GUID). Any other read error is not treated as a removal.
func checkWatchedDevice(sysfsRoot string, d watchedDevice) error {
	guid, err := readNodeGUID(sysfsRoot, d.name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("RDMA device %s (netdev %q) was unregistered by the kernel", d.name, d.netdev)
	case err != nil:
		return nil
	case guid != d.nodeGUID:
		return fmt.Errorf("RDMA device name %s now belongs to another device (node GUID %s, was %s)",
			d.name, guid, d.nodeGUID)
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
					if err := checkWatchedDevice(a.sysfsRoot, d); err != nil {
						a.logger.Warn().
							Str("device", d.name).
							Str("netdev", d.netdev).
							Err(err).
							Msg("Opened RDMA device disappeared; stopping the agent so it restarts with the current devices")
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
