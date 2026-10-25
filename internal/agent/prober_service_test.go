// Tests for the service-tracing pass of the probe loop: SERVICE_TRACING
// targets live beside the pinglist targets, share one aggregate rate per
// prober, are spaced by their own interval and are visited in a fresh random
// order on every pass.
package agent

import (
	"fmt"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func serviceTargets(n int) []*controller_agent.PingTarget {
	out := make([]*controller_agent.PingTarget, n)
	for i := range out {
		out[i] = &controller_agent.PingTarget{
			TargetGid:      fmt.Sprintf("fe80::f%d", i),
			TargetQpn:      uint32(100 + i),
			FlowLabel:      uint32(0x1000 + i),
			FlowLabelCount: 1,
			PinglistType:   controller_agent.PinglistType_SERVICE_TRACING,
		}
	}
	return out
}

// assertServiceRate checks that the service targets together were probed at
// about aggregatePPS over dur, that no two service probes came closer than
// the aggregate interval, and that every target got about its fair share.
// Unlike assertRate it does not require even spacing per target: each pass
// visits the targets in a new random order, so one target's probes can sit
// at the end of one pass and the start of the next.
func assertServiceRate(t *testing.T, sends map[string][]time.Time, targets []*controller_agent.PingTarget, dur time.Duration, aggregatePPS float64) {
	t.Helper()
	var all []time.Time
	perTarget := aggregatePPS * dur.Seconds() / float64(len(targets))
	for _, tg := range targets {
		got := sends[tg.GetTargetGid()]
		if math.Abs(float64(len(got))-perTarget) > math.Max(2, perTarget*0.1) {
			t.Errorf("service target %s: %d probes in %v, want ~%.0f", tg.GetTargetGid(), len(got), dur, perTarget)
		}
		all = append(all, got...)
	}
	want := aggregatePPS * dur.Seconds()
	if math.Abs(float64(len(all))-want) > math.Max(2, want*0.05) {
		t.Errorf("service probes = %d in %v, want ~%.0f (%.0f probes/s)", len(all), dur, want, aggregatePPS)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Before(all[j]) })
	minGap := time.Duration(float64(time.Second) / aggregatePPS * 0.9)
	for i := 1; i < len(all); i++ {
		if gap := all[i].Sub(all[i-1]); gap < minGap {
			t.Errorf("service probes %d and %d only %v apart, want >= %v", i-1, i, gap, minGap)
			break
		}
	}
}

// TestServiceTracing_AggregateRate verifies that the service rate is an
// aggregate cap shared by every traced flow, while the pinglist targets keep
// their own per-target rate.
func TestServiceTracing_AggregateRate(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 2)
	svc := serviceTargets(5)
	p := newSimProber(500*time.Millisecond, tor, nil)
	p.SetPerTypeRateLimit(2, 1)
	p.SetServiceTracingRate(100, 10)
	p.UpdateServiceTargets(svc, nil)

	const dur = 10 * time.Second
	sends := simSchedule(t, p, dur, nil)

	// 100 pps shared by 5 flows: 20 pps each, 200 probes in 10 s.
	assertServiceRate(t, sends, svc, dur, 100)
	assertRate(t, sends, tor, dur, 2, "tor-mesh")
}

// TestServiceTracing_IntervalFloor verifies that with few flows the service
// interval, not the aggregate rate, paces each flow.
func TestServiceTracing_IntervalFloor(t *testing.T) {
	svc := serviceTargets(2)
	p := newSimProber(500*time.Millisecond, nil, nil)
	p.SetServiceTracingRate(1000, 10)
	p.UpdateServiceTargets(svc, nil)

	const dur = 5 * time.Second
	sends := simSchedule(t, p, dur, nil)
	// One pass every 10 ms: 100 probes/s per flow, far below the 1000 pps cap.
	assertRate(t, sends, svc, dur, 100, "service")
}

// TestServiceTracing_ThrottleScalesRate verifies that the self-protection
// multiplier scales the service rate like the pinglist rates.
func TestServiceTracing_ThrottleScalesRate(t *testing.T) {
	svc := serviceTargets(4)
	p := newSimProber(500*time.Millisecond, nil, nil)
	p.SetServiceTracingRate(100, 10)
	p.UpdateServiceTargets(svc, nil)
	p.SetRateMultiplier(0.5)

	const dur = 10 * time.Second
	sends := simSchedule(t, p, dur, nil)
	// 50 pps shared by 4 flows.
	assertServiceRate(t, sends, svc, dur, 50)
}

// TestServiceTracing_IndependentLists verifies that a pinglist refresh keeps
// the service targets and a service update keeps the pinglist, and that
// clearing the service targets stops service probing.
func TestServiceTracing_IndependentLists(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 2)
	svc := serviceTargets(3)
	p := newSimProber(500*time.Millisecond, tor, nil)
	p.SetServiceTracingRate(100, 10)
	p.UpdateServiceTargets(svc, nil)

	p.UpdateTargets(typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 3))
	p.targetsMu.RLock()
	nTor := len(p.targets)
	nSvc := len(p.serviceTargets)
	p.targetsMu.RUnlock()
	if nSvc != 3 || nTor != 3 {
		t.Fatalf("after pinglist refresh: %d service targets, %d pinglist targets; want 3 and 3", nSvc, nTor)
	}

	p.UpdateServiceTargets(nil, nil)
	p.targetsMu.RLock()
	nTor = len(p.targets)
	nSvc = len(p.serviceTargets)
	p.targetsMu.RUnlock()
	if nSvc != 0 || nTor != 3 {
		t.Fatalf("after clearing service targets: %d service targets, %d pinglist targets; want 0 and 3", nSvc, nTor)
	}

	sends := simSchedule(t, p, 2*time.Second, nil)
	for _, tg := range svc {
		if n := len(sends[tg.GetTargetGid()]); n != 0 {
			t.Errorf("cleared service target %s was probed %d times", tg.GetTargetGid(), n)
		}
	}
}

// TestServiceTracing_PassIsShuffled verifies that each pass visits the
// service targets in a new random order.
func TestServiceTracing_PassIsShuffled(t *testing.T) {
	svc := serviceTargets(16)
	p := newTestProber()
	p.UpdateServiceTargets(svc, nil)

	p.targetsMu.RLock()
	defer p.targetsMu.RUnlock()
	first := p.passTargetsLocked(controller_agent.PinglistType_SERVICE_TRACING)
	if len(first) != len(svc) {
		t.Fatalf("pass has %d targets, want %d", len(first), len(svc))
	}
	for attempt := 0; attempt < 10; attempt++ {
		next := p.passTargetsLocked(controller_agent.PinglistType_SERVICE_TRACING)
		for i := range next {
			if next[i] != first[i] {
				return
			}
		}
	}
	t.Fatal("ten passes visited the service targets in the same order")
}

// TestServiceTracing_EmptyPassDoesNotWake verifies that an empty service
// list adds no wake-ups to the scheduler while pinglist targets are active.
func TestServiceTracing_EmptyPassDoesNotWake(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 1)
	p := newSimProber(100*time.Millisecond, tor, nil)
	p.SetServiceTracingRate(100, 10)

	passes := [...]sendPass{
		{ptype: controller_agent.PinglistType_TOR_MESH},
		{ptype: controller_agent.PinglistType_INTER_TOR},
		{ptype: controller_agent.PinglistType_SERVICE_TRACING},
	}
	var seen seenGens
	now := time.Unix(1_000_000, 0)
	pass, wait := p.nextSend(passes[:], &seen, now)
	if pass == nil || wait != 0 {
		t.Fatalf("first call: pass=%v wait=%v, want the tor-mesh target now", pass, wait)
	}
	pass.next++
	p.reserveSend(pass.ptype, now)
	// The tor-mesh pass is done; the next event must be its restart after
	// probeInterval, not the empty service pass's 10 ms restart.
	pass, wait = p.nextSend(passes[:], &seen, now.Add(time.Millisecond))
	if pass != nil || wait < 90*time.Millisecond {
		t.Fatalf("second call: pass=%v wait=%v, want a sleep until the tor-mesh restart", pass, wait)
	}
}

// TestServiceTracing_UpdatesDoNotRestartPinglistPasses verifies that service
// target churn (connections appearing every second) leaves the pinglist
// passes alone: with a pass that takes longer than the churn period, every
// pinglist target still gets its share instead of only the first ones.
func TestServiceTracing_UpdatesDoNotRestartPinglistPasses(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 4)
	p := newSimProber(100*time.Millisecond, tor, nil)
	// 0.5 probes/s per target: a pass over 4 targets takes 2 s.
	p.SetPerTypeRateLimit(0.5, 0.5)
	p.SetServiceTracingRate(100, 10)

	const dur = 40 * time.Second
	var lastUpdate time.Time
	n := 0
	sends := simSchedule(t, p, dur, func(now time.Time) {
		if now.Sub(lastUpdate) >= time.Second {
			lastUpdate = now
			n++
			p.UpdateServiceTargets(serviceTargets(1+n%3), nil)
		}
	})
	assertRate(t, sends, tor, dur, 0.5, "tor-mesh")
}

// TestServiceTracing_DoesNotAdvancePinglistRotation verifies that a service
// probe to a remote RNIC does not advance the flow-label rotation of the
// pinglist target for the same GID, so the pinglist's ECMP coverage stays
// complete when the two interleave.
func TestServiceTracing_DoesNotAdvancePinglistRotation(t *testing.T) {
	p := newTestProber()
	const gid = "fe80::77"
	cluster := &controller_agent.PingTarget{TargetGid: gid, FlowLabelSeed: 0x1234, FlowLabelCount: 4}
	service := &controller_agent.PingTarget{TargetGid: gid, FlowLabel: 0x55, FlowLabelCount: 1,
		PinglistType: controller_agent.PinglistType_SERVICE_TRACING}
	want := probe.GenerateFlowLabels(0x1234, 4, 1)

	for i := 0; i < 8; i++ {
		if got := p.nextFlowLabel(cluster, 1); got != want[i%4] {
			t.Fatalf("pinglist probe %d got label %#x, want %#x", i, got, want[i%4])
		}
		if got := p.nextFlowLabel(service, 1); got != 0x55 {
			t.Fatalf("service probe %d got label %#x, want 0x55", i, got)
		}
	}
	if _, ok := p.labelRotation[gid]; !ok {
		t.Fatal("the pinglist target must own rotation state for its GID")
	}
}

// TestFillTargetMetadata_ServiceTracing verifies that results of
// SERVICE_TRACING targets are flagged for the service instruments.
func TestFillTargetMetadata_ServiceTracing(t *testing.T) {
	var result probe.ProbeResult
	fillTargetMetadata(&result, 1, 7, serviceTargets(1)[0])
	if !result.IsServiceTracing() || result.TargetSampled || result.FlowLabel != 7 {
		t.Errorf("service result: %+v", result)
	}
	var cluster probe.ProbeResult
	fillTargetMetadata(&cluster, 2, 8, typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 1)[0])
	if cluster.IsServiceTracing() || cluster.PinglistType != probe.PinglistTorMesh {
		t.Error("a ToR-mesh result must not be flagged as service tracing")
	}
}
