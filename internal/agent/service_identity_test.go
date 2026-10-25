package agent

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func TestServiceMonitorSharedFlowIdentity(t *testing.T) {
	resolver := &fakeResolver{targets: map[string]*controller_agent.PingTarget{remoteGIDStr: {TargetGid: remoteGIDStr, TargetQpn: 77}}}
	p := &fakeServiceProber{}
	m := newTestServiceMonitor(t, resolver, &fakeEventSource{}, p)
	m.loadDeviceNumbers()
	m.serviceMapping = map[string]string{"/a": "a", "/b": "b"}
	m.resolveServices = func(_ string, _ map[string]string, wanted map[uint64]bool) map[uint64]string {
		if len(wanted) == 0 {
			return nil
		}
		if len(wanted) != 3 {
			t.Errorf("wanted = %v", wanted)
		}
		return map[uint64]string{1: "a", 2: "b"}
	}
	for i, id := range []uint64{1, 1, 2, 3} {
		ev := createRC(100, testUverbsDev, uint32(i+1), uint32(i+10))
		ev.CgroupID = id
		m.handleEvent(ev)
		m.handleEvent(connectTo(100, uint32(i+1), 200, 7, remoteGID, 3))
	}
	m.rebuild(context.Background(), false)
	targets, _ := p.last()
	if len(targets) != 1 {
		t.Fatalf("shared flow produced %d probes", len(targets))
	}
	want := []string{"_unspecified", "a", "b"}
	if got := p.services[targets[0]]; !reflect.DeepEqual(got, want) {
		t.Fatalf("services=%v want %v", got, want)
	}
	s := m.Stats()
	if len(s.Devices) != 3 {
		t.Fatalf("stats=%+v", s.Devices)
	}
	for _, d := range s.Devices {
		want := 1
		if d.Service == "a" {
			want = 2
		}
		if d.Connections != want || d.FlowsProbed != 1 || d.FlowsUnresolved != 0 {
			t.Errorf("stats=%+v", d)
		}
	}
	// An unregistered remote still has per-service flow and connection counts.
	resolver.targets = nil
	m.rebuild(context.Background(), true)
	for _, d := range m.Stats().Devices {
		if d.FlowsProbed != 0 || d.FlowsUnresolved != 1 {
			t.Errorf("unresolved=%+v", d)
		}
	}
	// Removing connections removes their per-service series at the next rebuild.
	m.handleEvent(servicetrace.Event{Kind: servicetrace.KindContextClose, Context: 100})
	m.rebuild(context.Background(), false)
	if len(m.Stats().Devices) != 0 {
		t.Fatal("removed services still exported")
	}
}

func TestServiceIdentitySurvivesTargetRefresh(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		p := fakeProber(1)
		target := serviceTargets(1)[0]
		labels := map[*controller_agent.PingTarget][]string{target: {"training"}}
		p.UpdateServiceTargets([]*controller_agent.PingTarget{target}, labels)
		passes := []sendPass{{ptype: controller_agent.PinglistType_SERVICE_TRACING}}
		pass, _ := p.nextSend(passes, &seenGens{}, time.Now())
		if pass == nil {
			t.Fatal("no service pass")
		}
		pp := &pendingProbe{target: target, meas: probe.NewPendingMeasurement(), services: pass.services[target], createdAt: time.Now().Add(-2 * stalePendingTimeout)}
		p.pending[1] = pp
		p.UpdateServiceTargets(nil, nil)
		var result *probe.ProbeResult
		if timeout {
			p.cleanupStalePending()
			result = <-p.resultChan
		} else {
			pp.meas.ApplySend(1, 100)
			pp.meas.ApplyFirstAck(1000, 2400)
			pp.meas.ApplySecondAck(1000, 1300, 2500)
			result = p.finalizeIfCompleteLocked(1, pp)
		}
		if result == nil || !reflect.DeepEqual(result.Services, []string{"training"}) {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestServiceIdentitySendFailure(t *testing.T) {
	p := fakeProber(1)
	// A null bridge handle returns a send error without opening RDMA hardware.
	p.queue = &rdmabridge.Queue{}
	p.sendProbe(serviceTargets(1)[0], 0, []string{"training"})
	r := <-p.resultChan
	if r.FailureReason != probe.FailureSendError || !reflect.DeepEqual(r.Services, []string{"training"}) {
		t.Fatalf("result=%+v", r)
	}
}
