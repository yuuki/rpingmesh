// Tests for the prober's ECMP multi-flow-label probing: round-robin advance
// across a target's set, the per-target label cache, and the invariant that
// the per-target rate limit is independent of the label-set size. Label-set
// generation itself is tested in internal/probe.
package agent

import (
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// TestNextFlowLabel_RoundRobin verifies that successive probes to a target walk
// its flow-label set in order and wrap around (round-robin), so all paths are
// exercised over time.
func TestNextFlowLabel_RoundRobin(t *testing.T) {
	const (
		seed  = uint32(0xABCDEF)
		count = uint32(4)
		epoch = uint64(1000)
	)
	target := &controller_agent.PingTarget{
		TargetGid:      "fe80::abcd",
		FlowLabelSeed:  seed,
		FlowLabelCount: count,
	}
	want := probe.GenerateFlowLabels(seed, count, epoch)

	p := newTestProber()
	for i := 0; i < 3*int(count); i++ {
		got := p.nextFlowLabel(target, epoch)
		exp := want[uint32(i)%count]
		if got != exp {
			t.Fatalf("probe %d: flow label = %d, want %d (round-robin index %d)",
				i, got, exp, uint32(i)%count)
		}
	}
}

// TestCachedLabelsForTarget verifies the per-target label-set cache: within one
// rotation epoch (and unchanged seed/count) the identical set is returned
// without regenerating, while an epoch change or a seed/count change forces
// regeneration. This keeps generateFlowLabels off the per-probe-tick hot path.
func TestCachedLabelsForTarget(t *testing.T) {
	target := &controller_agent.PingTarget{
		TargetGid:      "fe80::cafe",
		FlowLabelSeed:  0x1234,
		FlowLabelCount: 8,
	}
	p := newTestProber()

	a := p.cachedLabelsForTarget(target, 100)
	b := p.cachedLabelsForTarget(target, 100)
	// Same epoch/seed/count: the cache must return the SAME backing slice, not
	// a freshly generated one.
	if &a[0] != &b[0] {
		t.Errorf("same epoch returned a regenerated set; cache not hit")
	}
	if len(a) != 8 {
		t.Fatalf("cached set length = %d, want 8", len(a))
	}

	// Epoch change: must regenerate (new backing slice).
	c := p.cachedLabelsForTarget(target, 101)
	if &a[0] == &c[0] {
		t.Errorf("epoch change did not regenerate the label set")
	}

	// Count change at the same epoch: must regenerate with the new size.
	target.FlowLabelCount = 16
	d := p.cachedLabelsForTarget(target, 101)
	if &c[0] == &d[0] || len(d) != 16 {
		t.Errorf("count change did not regenerate (len=%d, want 16)", len(d))
	}
}

// TestLabelsForTarget_LegacySingleLabel verifies that FlowLabelCount <= 1
// preserves exact legacy behavior: the single controller-provided FlowLabel is
// used verbatim, ignoring seed and epoch.
func TestLabelsForTarget_LegacySingleLabel(t *testing.T) {
	target := &controller_agent.PingTarget{
		FlowLabel:      0xBEEF,
		FlowLabelSeed:  0x9999,
		FlowLabelCount: 1,
	}
	got := labelsForTarget(target, 12345)
	if len(got) != 1 || got[0] != 0xBEEF {
		t.Errorf("legacy path = %v, want [0xBEEF]", got)
	}

	// Count 0 (unset by an older controller) is also legacy single-label.
	target.FlowLabelCount = 0
	got = labelsForTarget(target, 999)
	if len(got) != 1 || got[0] != 0xBEEF {
		t.Errorf("count=0 path = %v, want [0xBEEF]", got)
	}
}

// TestPerTargetRateLimit_IndependentOfFlowLabelCount verifies that the
// aggregate send-rate limit is per TARGET (pps * number of targets) and does
// not scale with each target's flow-label count. This guards the deliberate
// choice that a target's labels share its probe budget (bounded amplification).
func TestPerTargetRateLimit_IndependentOfFlowLabelCount(t *testing.T) {
	const pps = 10.0

	// Two targets, each with a large flow-label set.
	targets := []*controller_agent.PingTarget{
		{TargetGid: "fe80::1", FlowLabelSeed: 1, FlowLabelCount: 64},
		{TargetGid: "fe80::2", FlowLabelSeed: 2, FlowLabelCount: 64},
	}

	p := newTestProber()
	p.UpdateTargets(targets)
	p.SetPerTargetRateLimit(pps)

	// Aggregate rate must be pps * len(targets) = 20 pps regardless of the
	// per-target flow-label count, i.e. a 50ms minimum spacing.
	wantInterval := time.Duration(float64(time.Second) / (pps * float64(len(targets))))

	// Both targets carry the proto3-default PinglistType (TOR_MESH), so their
	// aggregate rate lands on the ToR-mesh limiter.
	base := time.Now()
	if w := p.torMeshRate.limiter.Reserve(base); w != 0 {
		t.Fatalf("first Reserve wait = %v, want 0", w)
	}
	// The next send, requested at the same instant, must wait exactly one
	// aggregate interval -- proving n (=64) did not inflate the rate.
	if w := p.torMeshRate.limiter.Reserve(base); w != wantInterval {
		t.Fatalf("second Reserve wait = %v, want %v (rate independent of flow_label_count)", w, wantInterval)
	}
}
