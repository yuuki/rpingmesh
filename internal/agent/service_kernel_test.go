package agent

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func TestServiceMonitorKernelConnection(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{
		remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77},
	}}
	p := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, &fakeEventSource{}, p)
	m.loadDeviceNumbers()
	m.serviceMapping = map[string]string{"/": "worker-must-not-be-owner"}
	ev := connectTo(0x1234, 0, 202, 123, remoteGID, 3)
	ev.Source, ev.DeviceName = servicetrace.SourceKernel, "mlx5_0"
	ev.QPNum, ev.QPType, ev.IsGlobal = 101, servicetrace.QPTypeRC, 1
	ev.PID, ev.CgroupID = 7, 999
	m.handleEvent(ev)
	m.rebuild(context.Background(), false)
	targets, _ := p.last()
	if len(targets) != 1 || targets[0].GetFlowLabel() != 123 || targets[0].GetTargetGid() != remoteGIDStr ||
		targets[0].GetPinglistType() != controller_agent.PinglistType_SERVICE_TRACING {
		t.Fatalf("kernel connection did not become a probe target: %v", targets)
	}
	if labels := p.services[targets[0]]; len(labels) != 1 || labels[0] != "_unspecified" {
		t.Fatalf("kernel worker was attributed to a service: %v", labels)
	}
	if c := m.table.Connections()[0]; c.Dev != testUverbsDev || !c.Kernel {
		t.Fatalf("device not resolved from kernel name: %+v", c)
	}
	// A successful empty inventory repairs a lost kernel destroy event.
	m.refreshQPs(context.Background())
	m.rebuild(context.Background(), false)
	if targets, _ := p.last(); len(targets) != 0 {
		t.Fatalf("stale kernel probe targets survived reconciliation: %v", targets)
	}
	ev.DeviceName = "unknown"
	m.handleEvent(ev)
	if m.table.QPCount() != 0 {
		t.Fatal("unresolved device was assigned a guessed device number")
	}
}

func TestServiceMonitorKernelInventoryScope(t *testing.T) {
	m := newTestServiceMonitor(t, &fakeResolver{}, &fakeEventSource{}, &fakeServiceProber{})
	m.loadDeviceNumbers()
	ev := connectTo(0x1234, 0, 202, 123, remoteGID, 3)
	ev.Source, ev.DeviceName = servicetrace.SourceKernel, "mlx5_9"
	ev.QPNum, ev.QPType, ev.IsGlobal = 101, servicetrace.QPTypeRC, 1
	m.handleEvent(ev)
	// mlx5_9 exists in sysfs but only mlx5_0 is monitored and inventoried.
	m.refreshQPs(context.Background())
	_, other := m.connectionsByDevice()
	if other != 1 || m.table.QPCount() != 1 {
		t.Fatalf("unmonitored kernel connection disappeared: other=%d qps=%d", other, m.table.QPCount())
	}
}
