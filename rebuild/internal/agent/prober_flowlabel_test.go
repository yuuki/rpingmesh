// Tests for the prober's ECMP multi-flow-label probing: deterministic
// label-set expansion, round-robin advance across a target's set, time-based
// rotation of the ~20% rotating subset, and the invariant that the per-target
// rate limit is independent of the label-set size (probe amplification is
// bounded, not multiplied by n).
package agent

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// TestGenerateFlowLabels_Deterministic verifies that the same (seed, count,
// epoch) always yields the same set and that the set is distinct and within
// the 20-bit flow-label field.
func TestGenerateFlowLabels_Deterministic(t *testing.T) {
	const (
		seed  = uint32(0x12345678)
		count = uint32(16)
		epoch = uint64(42)
	)

	a := generateFlowLabels(seed, count, epoch)
	b := generateFlowLabels(seed, count, epoch)

	if len(a) != int(count) {
		t.Fatalf("len = %d, want %d", len(a), count)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at %d: %d != %d", i, a[i], b[i])
		}
	}

	seen := make(map[uint32]struct{}, count)
	for i, v := range a {
		if v > 0xFFFFF {
			t.Errorf("label[%d] = %#x exceeds 20-bit flow-label width", i, v)
		}
		if _, dup := seen[v]; dup {
			t.Errorf("label[%d] = %#x is a duplicate; set is not distinct", i, v)
		}
		seen[v] = struct{}{}
	}
	if len(seen) != int(count) {
		t.Errorf("distinct labels = %d, want %d", len(seen), count)
	}
}

// TestGenerateFlowLabels_ZeroCount ensures a count of 0 still yields one label,
// so every target is probed at least once.
func TestGenerateFlowLabels_ZeroCount(t *testing.T) {
	if got := generateFlowLabels(1, 0, 0); len(got) != 1 {
		t.Errorf("count=0 produced %d labels, want 1", len(got))
	}
}

// TestGenerateFlowLabels_DistinctUnderCollision verifies that a (seed, count)
// pair whose raw 20-bit hashes collide still yields exactly count distinct
// labels. seed=593, count=64, epoch=0 is a known collision (indices 5 and 37
// both hash to 0xfda4b without dedup); Eq.(1) sizing assumes distinct labels,
// so the set-guarded loop must resolve the collision. A broad sweep guards the
// invariant across many seeds at the controller's maximum cap (64).
func TestGenerateFlowLabels_DistinctUnderCollision(t *testing.T) {
	got := generateFlowLabels(593, 64, 0)
	seen := make(map[uint32]struct{}, len(got))
	for i, v := range got {
		if v > 0xFFFFF {
			t.Errorf("label[%d] = %#x exceeds 20-bit width", i, v)
		}
		if _, dup := seen[v]; dup {
			t.Errorf("label[%d] = %#x is a duplicate; collision not resolved", i, v)
		}
		seen[v] = struct{}{}
	}
	if len(seen) != 64 {
		t.Fatalf("seed=593 count=64: got %d distinct labels, want 64", len(seen))
	}

	// The dedup must hold for every seed at the maximum label count.
	for seed := uint32(0); seed < 4096; seed++ {
		labels := generateFlowLabels(seed, 64, 0)
		u := make(map[uint32]struct{}, 64)
		for _, v := range labels {
			u[v] = struct{}{}
		}
		if len(u) != 64 {
			t.Fatalf("seed=%d count=64: got %d distinct labels, want 64", seed, len(u))
		}
	}
}

// TestFlowLabelRotation_FractionAcrossEpoch verifies that exactly the rotating
// subset (~20%, every flowLabelRotateStride-th index) changes across an epoch
// boundary while the rest stay stable for time-series continuity.
func TestFlowLabelRotation_FractionAcrossEpoch(t *testing.T) {
	const (
		seed  = uint32(0xABCDEF01)
		count = uint32(20)
	)
	before := generateFlowLabels(seed, count, 1000)
	after := generateFlowLabels(seed, count, 1001)

	rotating := 0
	changed := 0
	for i := uint32(0); i < count; i++ {
		if i%flowLabelRotateStride == 0 {
			rotating++
		} else if before[i] != after[i] {
			t.Errorf("stable index %d changed across epoch: %d -> %d", i, before[i], after[i])
		}
		if before[i] != after[i] {
			changed++
		}
	}

	// With stride 5 over 20 labels, indices 0,5,10,15 rotate -> 20%.
	if wantRotating := int(count) / flowLabelRotateStride; rotating != wantRotating {
		t.Errorf("rotating index count = %d, want %d (~20%%)", rotating, wantRotating)
	}
	// Changed labels can never exceed the rotating count, and (barring an
	// astronomically unlikely hash collision) at least one must actually move.
	if changed > rotating {
		t.Errorf("changed %d > rotating %d: a stable label moved", changed, rotating)
	}
	if changed == 0 {
		t.Error("no labels changed across the epoch boundary; rotation is not taking effect")
	}
}

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
	want := generateFlowLabels(seed, count, epoch)

	p := &Prober{logger: zerolog.Nop()}
	for i := 0; i < 3*int(count); i++ {
		got := p.nextFlowLabel(target, epoch)
		exp := want[uint32(i)%count]
		if got != exp {
			t.Fatalf("probe %d: flow label = %d, want %d (round-robin index %d)",
				i, got, exp, uint32(i)%count)
		}
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

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(targets)
	p.SetPerTargetRateLimit(pps)

	// Aggregate rate must be pps * len(targets) = 20 pps regardless of the
	// per-target flow-label count, i.e. a 50ms minimum spacing.
	wantInterval := time.Duration(float64(time.Second) / (pps * float64(len(targets))))

	base := time.Now()
	if w := p.limiter.Reserve(base); w != 0 {
		t.Fatalf("first Reserve wait = %v, want 0", w)
	}
	// The next send, requested at the same instant, must wait exactly one
	// aggregate interval -- proving n (=64) did not inflate the rate.
	if w := p.limiter.Reserve(base); w != wantInterval {
		t.Fatalf("second Reserve wait = %v, want %v (rate independent of flow_label_count)", w, wantInterval)
	}
}
