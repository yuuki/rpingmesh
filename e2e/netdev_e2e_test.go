package e2e_test

import (
	"os"
	"testing"

	"github.com/yuuki/rpingmesh/internal/lldp"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

// expectedNetdevs is the RDMA device -> netdev binding scripts/run-e2e.sh sets
// up ("rdma link add rxeN type rxe netdev vethN").
var expectedNetdevs = map[string]string{
	proberDeviceName:    "veth0",
	responderDeviceName: "veth1",
}

// TestNetdevResolution verifies, against a real sysfs, that the netdev bound
// to each opened soft-RoCE device's active port/GID is resolved exactly as the
// agent does at startup (lldp.NetdevForRDMAPort, used by resolveDeviceNetdevs).
// This is the value exported as the source_netdev metric attribute, so a
// regression here turns every series' source_netdev into "unspecified".
func TestNetdevResolution(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	for dev, want := range expectedNetdevs {
		d, err := rdmaCtx.OpenDeviceByName(dev, gidIndex, testServiceLevel, testTrafficClass)
		if err != nil {
			t.Fatalf("open device %q: %v", dev, err)
		}
		got, err := lldp.NetdevForRDMAPort(lldp.DefaultSysfsRoot, d.Info.DeviceName,
			d.Info.ActivePort, d.Info.ActiveGIDIndex)
		d.Close()
		if err != nil {
			t.Errorf("NetdevForRDMAPort(%s, port %d, gid %d): %v",
				dev, d.Info.ActivePort, d.Info.ActiveGIDIndex, err)
			continue
		}
		if got != want {
			t.Errorf("%s netdev = %q, want %q", dev, got, want)
		}
		t.Logf("%s (port %d, gid %d) -> %s", dev, d.Info.ActivePort, d.Info.ActiveGIDIndex, got)
	}
}
