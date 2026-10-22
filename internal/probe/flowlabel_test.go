package probe

import "testing"

func assertDistinct20Bit(t *testing.T, labels []uint32, want int) {
	t.Helper()
	seen := make(map[uint32]struct{}, len(labels))
	for i, v := range labels {
		if v > FlowLabelMask {
			t.Errorf("label[%d] = %#x exceeds 20-bit flow-label width", i, v)
		}
		if _, dup := seen[v]; dup {
			t.Errorf("label[%d] = %#x is a duplicate; set is not distinct", i, v)
		}
		seen[v] = struct{}{}
	}
	if len(seen) != want {
		t.Errorf("distinct labels = %d, want %d", len(seen), want)
	}
}

func TestGenerateFlowLabels_Deterministic(t *testing.T) {
	const (
		seed  = uint32(0x12345678)
		count = uint32(16)
		epoch = uint64(42)
	)
	a := GenerateFlowLabels(seed, count, epoch)
	b := GenerateFlowLabels(seed, count, epoch)
	if len(a) != int(count) {
		t.Fatalf("len = %d, want %d", len(a), count)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at %d: %d != %d", i, a[i], b[i])
		}
	}
	assertDistinct20Bit(t, a, int(count))
}

func TestGenerateFlowLabels_ZeroCount(t *testing.T) {
	if got := GenerateFlowLabels(1, 0, 0); len(got) != 1 {
		t.Errorf("count=0 produced %d labels, want 1", len(got))
	}
}

// seed=593, count=64, epoch=0 is a known collision (indices 5 and 37 both
// hash to 0xfda4b without dedup); the set-guarded loop must resolve it. The
// sweep guards the invariant across many seeds at the controller's default
// maximum cap (64).
func TestGenerateFlowLabels_DistinctUnderCollision(t *testing.T) {
	assertDistinct20Bit(t, GenerateFlowLabels(593, 64, 0), 64)
	for seed := uint32(0); seed < 4096; seed++ {
		labels := GenerateFlowLabels(seed, 64, 0)
		u := make(map[uint32]struct{}, 64)
		for _, v := range labels {
			u[v] = struct{}{}
		}
		if len(u) != 64 {
			t.Fatalf("seed=%d count=64: got %d distinct labels, want 64", seed, len(u))
		}
	}
}

func TestClampDistinctFlowLabelCount(t *testing.T) {
	tests := []struct{ in, want uint32 }{
		{0, 0},
		{5, 5},
		{MaxDistinctFlowLabels - 1, MaxDistinctFlowLabels - 1},
		{MaxDistinctFlowLabels, MaxDistinctFlowLabels},
		{MaxDistinctFlowLabels + 1, MaxDistinctFlowLabels},
		{^uint32(0), MaxDistinctFlowLabels},
	}
	for _, tc := range tests {
		if got := ClampDistinctFlowLabelCount(tc.in); got != tc.want {
			t.Errorf("ClampDistinctFlowLabelCount(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Exactly the rotating subset (every FlowLabelRotateStride-th index) may
// change across an epoch boundary; the rest must stay stable.
func TestFlowLabelRotation_FractionAcrossEpoch(t *testing.T) {
	const (
		seed  = uint32(0xABCDEF01)
		count = uint32(20)
	)
	before := GenerateFlowLabels(seed, count, 1000)
	after := GenerateFlowLabels(seed, count, 1001)

	rotating, changed := 0, 0
	for i := uint32(0); i < count; i++ {
		if i%FlowLabelRotateStride == 0 {
			rotating++
		} else if before[i] != after[i] {
			t.Errorf("stable index %d changed across epoch: %d -> %d", i, before[i], after[i])
		}
		if before[i] != after[i] {
			changed++
		}
	}
	if wantRotating := int(count) / FlowLabelRotateStride; rotating != wantRotating {
		t.Errorf("rotating index count = %d, want %d (~20%%)", rotating, wantRotating)
	}
	if changed > rotating {
		t.Errorf("changed %d > rotating %d: a stable label moved", changed, rotating)
	}
	if changed == 0 {
		t.Error("no labels changed across the epoch boundary; rotation is not taking effect")
	}
}
