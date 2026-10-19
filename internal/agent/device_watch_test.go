package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

// writeNodeGUID creates sysfs/class/infiniband/<device>/node_guid.
func writeNodeGUID(t *testing.T, sysfs, device, guid string) {
	t.Helper()
	dir := filepath.Join(sysfs, "class", "infiniband", device)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_guid"), []byte(guid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDeviceSkipReason verifies the post-open filters: a GID in
// excluded_gid_cidrs is skipped, and with mapped_devices_only a device
// without a device_tor_ids entry is skipped.
func TestDeviceSkipReason(t *testing.T) {
	cfg := &config.AgentConfig{
		ExcludedGIDCIDRs:  []string{"10.0.0.0/24"},
		DeviceTorIDs:      map[string]string{"mlx5_0": "leaf-a", "mlx5_2": "leaf-b"},
		MappedDevicesOnly: true,
	}
	cases := []struct {
		name, ip, want string
	}{
		{"mlx5_0", "10.200.0.1", ""},
		{"MLX5_0", "10.200.0.1", ""},
		{"mlx5_1", "10.200.0.2", "mapped_devices_only"},
		// A mapped name on the management network is still skipped: the GID
		// is what tells the transient bond device apart from a fabric RNIC
		// that might later take over its name.
		{"mlx5_2", "10.0.0.5", "excluded_gid_cidrs:10.0.0.0/24"},
	}
	for _, c := range cases {
		info := rdmabridge.DeviceInfo{DeviceName: c.name, IPAddr: c.ip}
		if got := deviceSkipReason(cfg, info); got != c.want {
			t.Errorf("deviceSkipReason(%s, %s) = %q, want %q", c.name, c.ip, got, c.want)
		}
	}

	cfg.MappedDevicesOnly = false
	if got := deviceSkipReason(cfg, rdmabridge.DeviceInfo{DeviceName: "mlx5_1", IPAddr: "10.200.0.2"}); got != "" {
		t.Errorf("without mapped_devices_only an unmapped device is skipped: %q", got)
	}
}

// TestAgent_AdmitDeviceLogsSkip verifies that a skipped device is logged at
// the documented level with its name, netdev, and GID.
func TestAgent_AdmitDeviceLogsSkip(t *testing.T) {
	sysfs := t.TempDir()
	dir := filepath.Join(sysfs, "class", "infiniband", "mlx5_9", "ports", "1", "gid_attrs", "ndevs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "3"), []byte("bond0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAgent(&config.AgentConfig{
		AgentID:           "agent-1",
		DeviceTorIDs:      map[string]string{"mlx5_0": "leaf-a"},
		MappedDevicesOnly: true,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	var logs bytes.Buffer
	a.logger = zerolog.New(&logs)
	a.sysfsRoot = sysfs

	dev := fakeDevice("mlx5_9", "9")
	dev.Info.ActivePort, dev.Info.ActiveGIDIndex = 1, 3
	if a.admitDevice(dev) {
		t.Fatal("admitDevice admitted an unmapped device under mapped_devices_only")
	}
	for _, want := range []string{`"level":"warn"`, `"device_name":"mlx5_9"`, `"netdev":"bond0"`, `"gid":"9"`, `"reason":"mapped_devices_only"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("skip log lacks %s:\n%s", want, logs.String())
		}
	}

	if !a.admitDevice(fakeDevice("mlx5_0", "0")) {
		t.Error("admitDevice rejected a mapped device")
	}
}

// TestAgent_UnmappedDeviceFallbackWarns verifies that, with device_tor_ids
// set, a device resolved to the host-wide tor_id is warned about.
func TestAgent_UnmappedDeviceFallbackWarns(t *testing.T) {
	a, err := NewAgent(&config.AgentConfig{
		AgentID:      "agent-1",
		TorID:        "placeholder",
		DeviceTorIDs: map[string]string{"mlx5_0": "leaf-a"},
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	var logs bytes.Buffer
	a.logger = zerolog.New(&logs)
	a.devices = []*rdmabridge.Device{fakeDevice("mlx5_0", "0"), fakeDevice("mlx5_2", "2")}
	a.deviceNetdevs = []string{"enp1s0", "bond0"}

	a.resolveDeviceTorIDs(nil)

	var warned []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "falls back to tor_id") {
			warned = append(warned, line)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], `"device":"mlx5_2"`) ||
		!strings.Contains(warned[0], `"netdev":"bond0"`) || !strings.Contains(warned[0], `"level":"warn"`) {
		t.Errorf("fallback warnings = %v, want one warn for mlx5_2/bond0", warned)
	}

	// Without device_tor_ids the fallback is the normal case: no warning.
	b, _ := NewAgent(&config.AgentConfig{AgentID: "agent-1", TorID: "tor-1"})
	logs.Reset()
	b.logger = zerolog.New(&logs)
	b.devices = []*rdmabridge.Device{fakeDevice("mlx5_0", "0")}
	b.resolveDeviceTorIDs(nil)
	if strings.Contains(logs.String(), "falls back to tor_id") {
		t.Errorf("unexpected fallback warning without device_tor_ids:\n%s", logs.String())
	}
}

// TestCheckWatchedDevice covers the removal conditions: the device is
// gone, its name now belongs to another device, or it is unchanged.
func TestCheckWatchedDevice(t *testing.T) {
	sysfs := t.TempDir()
	writeNodeGUID(t, sysfs, "mlx5_0", "aaaa:bbbb:cccc:0001")
	writeNodeGUID(t, sysfs, "mlx5_1", "aaaa:bbbb:cccc:0099")

	if err := checkWatchedDevice(sysfs, watchedDevice{name: "mlx5_0", nodeGUID: "aaaa:bbbb:cccc:0001"}); err != nil {
		t.Errorf("present device reported lost: %v", err)
	}
	if err := checkWatchedDevice(sysfs, watchedDevice{name: "mlx5_1", nodeGUID: "aaaa:bbbb:cccc:0002"}); err == nil {
		t.Error("device name reused by another node GUID not reported")
	}
	if err := checkWatchedDevice(sysfs, watchedDevice{name: "mlx5_2", netdev: "bond0", nodeGUID: "x"}); err == nil ||
		!strings.Contains(err.Error(), "unregistered") {
		t.Errorf("removed device: err = %v, want an unregistered error", err)
	}
}

// TestAgent_RecordWatchedDevicesSkipsUnreadable verifies that a device whose
// node GUID cannot be read is not watched, so a missing sysfs can never make
// the agent exit.
func TestAgent_RecordWatchedDevicesSkipsUnreadable(t *testing.T) {
	sysfs := t.TempDir()
	writeNodeGUID(t, sysfs, "rxe0", "guid-0")

	a, err := NewAgent(&config.AgentConfig{AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	a.logger = zerolog.Nop()
	a.sysfsRoot = sysfs
	a.devices = []*rdmabridge.Device{fakeDevice("rxe0", "0"), fakeDevice("rxe1", "1")}
	a.deviceNetdevs = []string{"eth0", "eth1"}

	a.recordWatchedDevices()
	if len(a.watchedDevices) != 1 || a.watchedDevices[0] != (watchedDevice{name: "rxe0", netdev: "eth0", nodeGUID: "guid-0"}) {
		t.Errorf("watchedDevices = %+v, want only rxe0", a.watchedDevices)
	}
}

// TestAgent_DeviceWatchReportsLoss verifies that removing a watched device
// from sysfs delivers the loss on deviceLost, and that stopDeviceWatch
// returns once the watch goroutine has exited.
func TestAgent_DeviceWatchReportsLoss(t *testing.T) {
	sysfs := t.TempDir()
	writeNodeGUID(t, sysfs, "mlx5_0", "guid-0")
	writeNodeGUID(t, sysfs, "mlx5_2", "guid-2")

	a, err := NewAgent(&config.AgentConfig{AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	a.logger = zerolog.Nop()
	a.sysfsRoot = sysfs
	a.deviceWatchPeriod = 10 * time.Millisecond
	a.devices = []*rdmabridge.Device{fakeDevice("mlx5_0", "0"), fakeDevice("mlx5_2", "2")}
	a.deviceNetdevs = []string{"enp1s0", "bond0"}
	a.recordWatchedDevices()

	a.startDeviceWatch(context.Background())
	defer a.stopDeviceWatch()

	select {
	case err := <-a.deviceLost:
		t.Fatalf("loss reported while every device is present: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := os.RemoveAll(filepath.Join(sysfs, "class", "infiniband", "mlx5_2")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-a.deviceLost:
		if !strings.Contains(err.Error(), "mlx5_2") {
			t.Errorf("loss error = %v, want it to name mlx5_2", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("device removal was not reported")
	}
}

// TestAgent_StopAfterDeviceLossReturnsError verifies that a device loss ends
// Run's wait with an error (so the process exits non-zero) after stopping.
func TestAgent_StopAfterDeviceLossReturnsError(t *testing.T) {
	a, err := NewAgent(&config.AgentConfig{AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	a.logger = zerolog.Nop()
	err = a.stopAfterDeviceLoss(os.ErrNotExist)
	if err == nil || !strings.Contains(err.Error(), "RDMA device lost") {
		t.Errorf("stopAfterDeviceLoss = %v, want an RDMA device lost error", err)
	}
}
