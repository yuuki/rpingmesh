// Tests for the probe loop's per-pinglist-type scheduling (issue #77): the two
// types are paced independently, so a binding inter-ToR cap no longer slows
// ToR-mesh probing; probe_interval_ms is a per-target ceiling; and the
// self-protection multiplier scales the rate that is actually achieved. The
// scheduler is driven on a virtual clock through nextSend/reserveSend, the
// same calls probeLoop makes, so no RDMA queue or real sleeping is needed.
package agent

import (
	"math"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// simSendCost is the virtual time one SendProbe takes in the simulation.
const simSendCost = 20 * time.Microsecond

// simSchedule runs the probe-loop scheduler for dur of virtual time and
// returns the send times of every target, keyed by GID. before, if non-nil, is
// called before each scheduling step with the current virtual time, so a test
// can change targets or rates mid-run.
func simSchedule(t *testing.T, p *Prober, dur time.Duration, before func(now time.Time)) map[string][]time.Time {
	t.Helper()
	passes := [...]sendPass{
		{ptype: controller_agent.PinglistType_TOR_MESH},
		{ptype: controller_agent.PinglistType_INTER_TOR},
	}
	var seenGen uint64
	sends := make(map[string][]time.Time)

	start := time.Unix(1_000_000, 0)
	end := start.Add(dur)
	for now := start; now.Before(end); {
		if before != nil {
			before(now)
		}
		pass, wait := p.nextSend(passes[:], &seenGen, now)
		if pass == nil || wait > 0 {
			if wait <= 0 {
				t.Fatalf("scheduler asked to sleep for %v at %v (busy loop)", wait, now.Sub(start))
			}
			now = now.Add(wait)
			continue
		}
		target := pass.targets[pass.next]
		pass.next++
		p.reserveSend(pass.ptype, now)
		sends[target.GetTargetGid()] = append(sends[target.GetTargetGid()], now)
		now = now.Add(simSendCost)
	}
	return sends
}

// assertRate checks that every target in targets was probed at about wantPPS
// over dur, and that no two probes to one target came closer than the
// interval the rate implies (minus a small tolerance for pass boundaries).
func assertRate(t *testing.T, sends map[string][]time.Time, targets []*controller_agent.PingTarget, dur time.Duration, wantPPS float64, label string) {
	t.Helper()
	want := wantPPS * dur.Seconds()
	minGap := time.Duration(float64(time.Second) / wantPPS * 0.9)
	for _, tg := range targets {
		got := sends[tg.GetTargetGid()]
		if math.Abs(float64(len(got))-want) > math.Max(2, want*0.05) {
			t.Errorf("%s target %s: %d probes in %v, want ~%.0f (%.1f probes/s)",
				label, tg.GetTargetGid(), len(got), dur, want, wantPPS)
		}
		for i := 1; i < len(got); i++ {
			if gap := got[i].Sub(got[i-1]); gap < minGap {
				t.Errorf("%s target %s: probes %d and %d only %v apart, want >= %v",
					label, tg.GetTargetGid(), i-1, i, gap, minGap)
				break
			}
		}
	}
}

func newSimProber(interval time.Duration, tor, inter []*controller_agent.PingTarget) *Prober {
	p := &Prober{logger: zerolog.Nop(), probeInterval: interval}
	p.UpdateTargets(append(append([]*controller_agent.PingTarget{}, tor...), inter...))
	return p
}

// TestSchedule_MixedTypesReachDifferentiatedRates is the #77 acceptance case:
// with a 100 ms interval (10 probes/s ceiling) and caps of 10 (ToR-mesh) and 1
// (inter-ToR), ToR-mesh targets get ~10 probes/s and inter-ToR targets ~1,
// instead of both being dragged to ~1 probe/s by the shared round.
func TestSchedule_MixedTypesReachDifferentiatedRates(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 6)
	inter := typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 4)
	p := newSimProber(100*time.Millisecond, tor, inter)
	p.SetPerTypeRateLimit(10, 1)

	const dur = 20 * time.Second
	sends := simSchedule(t, p, dur, nil)
	assertRate(t, sends, tor, dur, 10, "ToR-mesh")
	assertRate(t, sends, inter, dur, 1, "inter-ToR")
}

// TestSchedule_IntervalIsCeiling verifies the shipped interval (500 ms) caps
// every target at 2 probes/s, and that the binding 1 probe/s inter-ToR cap no
// longer slows ToR-mesh targets below that ceiling.
func TestSchedule_IntervalIsCeiling(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 5)
	inter := typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 3)
	p := newSimProber(500*time.Millisecond, tor, inter)
	p.SetPerTypeRateLimit(10, 1)

	const dur = 30 * time.Second
	sends := simSchedule(t, p, dur, nil)
	assertRate(t, sends, tor, dur, 2, "ToR-mesh")
	assertRate(t, sends, inter, dur, 1, "inter-ToR")
}

// TestSchedule_NoCapUsesInterval verifies that without any cap each target is
// probed once per interval, as before per-type caps existed.
func TestSchedule_NoCapUsesInterval(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 3)
	inter := typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 2)
	p := newSimProber(250*time.Millisecond, tor, inter)

	const dur = 20 * time.Second
	sends := simSchedule(t, p, dur, nil)
	assertRate(t, sends, tor, dur, 4, "ToR-mesh")
	assertRate(t, sends, inter, dur, 4, "inter-ToR")
}

// TestSchedule_MultiplierScalesAchievedRate verifies the self-protection
// multiplier slows the rate actually achieved. With a 10 probes/s cap above
// the 2 probes/s interval ceiling, scaling the raw cap by 0.5 would still
// leave 5 probes/s above the ceiling and change nothing; the multiplier must
// apply to min(cap, ceiling) instead.
func TestSchedule_MultiplierScalesAchievedRate(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 4)
	inter := typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 2)
	p := newSimProber(500*time.Millisecond, tor, inter)
	p.SetPerTypeRateLimit(10, 1)
	p.SetRateMultiplier(0.5)

	const dur = 40 * time.Second
	sends := simSchedule(t, p, dur, nil)
	assertRate(t, sends, tor, dur, 1, "ToR-mesh")
	assertRate(t, sends, inter, dur, 0.5, "inter-ToR")
}

// TestSchedule_FlowLabelsShareTargetBudget verifies a target's ECMP flow-label
// set does not multiply its probe rate: a target with many labels is probed at
// the same per-target rate as one with a single label.
func TestSchedule_FlowLabelsShareTargetBudget(t *testing.T) {
	tor := typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 3)
	tor[0].FlowLabelCount = 64
	tor[0].FlowLabelSeed = 7
	p := newSimProber(100*time.Millisecond, tor, nil)
	p.SetPerTypeRateLimit(10, 1)

	const dur = 10 * time.Second
	sends := simSchedule(t, p, dur, nil)
	assertRate(t, sends, tor, dur, 10, "ToR-mesh")
}

// TestSchedule_UpdateTargetsTakesEffect verifies a pinglist update mid-run
// stops probes to removed targets and reaches added targets promptly, rather
// than finishing a pass over the stale snapshot.
func TestSchedule_UpdateTargetsTakesEffect(t *testing.T) {
	oldTor := typedTargets(controller_agent.PinglistType_TOR_MESH, "old", 3)
	newTor := typedTargets(controller_agent.PinglistType_TOR_MESH, "new", 3)
	inter := typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 2)
	p := newSimProber(100*time.Millisecond, oldTor, inter)
	p.SetPerTypeRateLimit(10, 1)

	start := time.Unix(1_000_000, 0)
	switchAt := start.Add(5 * time.Second)
	switched := false
	sends := simSchedule(t, p, 10*time.Second, func(now time.Time) {
		if !switched && !now.Before(switchAt) {
			p.UpdateTargets(append(append([]*controller_agent.PingTarget{}, newTor...), inter...))
			switched = true
		}
	})

	for _, tg := range oldTor {
		for _, at := range sends[tg.GetTargetGid()] {
			if !at.Before(switchAt) {
				t.Errorf("removed target %s probed at +%v, after the update at +5s",
					tg.GetTargetGid(), at.Sub(start))
				break
			}
		}
	}
	for _, tg := range newTor {
		got := sends[tg.GetTargetGid()]
		if len(got) == 0 {
			t.Fatalf("added target %s never probed", tg.GetTargetGid())
		}
		if first := got[0].Sub(switchAt); first > 200*time.Millisecond {
			t.Errorf("added target %s first probed %v after the update, want <= 200ms",
				tg.GetTargetGid(), first)
		}
		if n := len(got); n < 45 || n > 52 {
			t.Errorf("added target %s: %d probes in 5s, want ~50", tg.GetTargetGid(), n)
		}
	}
	// The inter-ToR rate is unaffected by the ToR-mesh churn (within the
	// one-interval restart delay the update may cost).
	for _, tg := range inter {
		if n := len(sends[tg.GetTargetGid()]); n < 9 || n > 11 {
			t.Errorf("inter-ToR target %s: %d probes in 10s, want ~10", tg.GetTargetGid(), n)
		}
	}
}
