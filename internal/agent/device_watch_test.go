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

// writeUverbsNode creates sysfs/class/infiniband_verbs/<node>/ibdev naming
// device, and returns the node's path.
func writeUverbsNode(t *testing.T, sysfs, node, device string) string {
	t.Helper()
	dir := filepath.Join(sysfs, "class", "infiniband_verbs", node)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ibdev"), []byte(device+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// recordOne records the watch identity of a single device.
func recordOne(t *testing.T, sysfs, device string) watchedDevice {
	t.Helper()
	a, err := NewAgent(&config.AgentConfig{AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	a.logger = zerolog.Nop()
	a.sysfsRoot = sysfs
	a.devices = []*rdmabridge.Device{fakeDevice(device, "0")}
	a.recordWatchedDevices()
	if len(a.watchedDevices) != 1 {
		t.Fatalf("watchedDevices = %+v, want one entry", a.watchedDevices)
	}
	return a.watchedDevices[0]
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

// TestCheckWatchedDevice covers the loss conditions: the uverbs node is
// gone, it was re-created (re-registration under the same name and number),
// or its device was renamed. An unchanged node is not a loss.
func TestCheckWatchedDevice(t *testing.T) {
	sysfs := t.TempDir()
	node := writeUverbsNode(t, sysfs, "uverbs2", "mlx5_2")
	writeUverbsNode(t, sysfs, "uverbs0", "mlx5_0")

	d := recordOne(t, sysfs, "mlx5_2")
	if d.uverbs != node {
		t.Fatalf("recorded uverbs node = %s, want %s", d.uverbs, node)
	}
	if err := checkWatchedDevice(d); err != nil {
		t.Errorf("present device reported lost: %v", err)
	}

	if err := os.WriteFile(filepath.Join(node, "ibdev"), []byte("mlx5_bond_0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkWatchedDevice(d); err == nil || !strings.Contains(err.Error(), "renamed to mlx5_bond_0") {
		t.Errorf("rename: err = %v, want a renamed error", err)
	}

	// Re-created with the same name and uverbs number. The replacement is
	// created before the original is removed so that the filesystem cannot
	// hand it the original's inode.
	if err := os.WriteFile(filepath.Join(node, "ibdev"), []byte("mlx5_2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh := writeUverbsNode(t, sysfs, "uverbs2.new", "mlx5_2")
	if err := os.RemoveAll(node); err != nil {
		t.Fatal(err)
	}
	if err := checkWatchedDevice(d); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Errorf("removed device: err = %v, want an unregistered error", err)
	}
	if err := os.Rename(fresh, node); err != nil {
		t.Fatal(err)
	}
	if err := checkWatchedDevice(d); err == nil || !strings.Contains(err.Error(), "re-registered") {
		t.Errorf("re-registered device: err = %v, want a re-registered error", err)
	}
}

// TestAgent_RecordWatchedDevicesSkipsUnknown verifies that a device without
// a uverbs node is not watched, so a missing sysfs can never make the agent
// exit.
func TestAgent_RecordWatchedDevicesSkipsUnknown(t *testing.T) {
	sysfs := t.TempDir()
	node := writeUverbsNode(t, sysfs, "uverbs0", "rxe0")

	a, err := NewAgent(&config.AgentConfig{AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	a.logger = zerolog.Nop()
	a.sysfsRoot = sysfs
	a.devices = []*rdmabridge.Device{fakeDevice("rxe0", "0"), fakeDevice("rxe1", "1")}
	a.deviceNetdevs = []string{"eth0", "eth1"}

	a.recordWatchedDevices()
	if len(a.watchedDevices) != 1 || a.watchedDevices[0].name != "rxe0" ||
		a.watchedDevices[0].netdev != "eth0" || a.watchedDevices[0].uverbs != node {
		t.Errorf("watchedDevices = %+v, want only rxe0", a.watchedDevices)
	}

	b, _ := NewAgent(&config.AgentConfig{AgentID: "agent-1"})
	b.logger = zerolog.Nop()
	b.sysfsRoot = filepath.Join(sysfs, "missing")
	b.devices = []*rdmabridge.Device{fakeDevice("rxe0", "0")}
	b.recordWatchedDevices()
	if len(b.watchedDevices) != 0 {
		t.Errorf("watchedDevices without sysfs = %+v, want none", b.watchedDevices)
	}
}

// TestAgent_DeviceWatchReportsLoss verifies that removing a watched device
// from sysfs delivers the loss on deviceLost, and that stopDeviceWatch
// returns once the watch goroutine has exited.
func TestAgent_DeviceWatchReportsLoss(t *testing.T) {
	sysfs := t.TempDir()
	writeUverbsNode(t, sysfs, "uverbs0", "mlx5_0")
	node := writeUverbsNode(t, sysfs, "uverbs2", "mlx5_2")

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

	if err := os.RemoveAll(node); err != nil {
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
