package pinglist

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// TestComputeFlowLabelCount verifies Eq.(1) sizing for representative (m, p)
// pairs, plus the hard cap and the degenerate edge cases. Expected values were
// computed independently from n = ceil(ln(1 - p^(1/m)) / ln((m-1)/m)).
func TestComputeFlowLabelCount(t *testing.T) {
	tests := []struct {
		name string
		m    int
		p    float64
		maxN int
		want uint32
	}{
		{"m2_p0.9", 2, 0.9, 64, 5},
		{"m4_p0.9", 4, 0.9, 64, 13},
		{"m8_p0.9", 8, 0.9, 64, 33},
		{"m16_p0.9_capped", 16, 0.9, 64, 64},    // uncapped 78 -> cap 64
		{"m16_p0.9_uncapped", 16, 0.9, 256, 78}, // cap high enough to see raw n
		{"m32_p0.9_capped", 32, 0.9, 64, 64},
		{"m32_p0.9_uncapped", 32, 0.9, 256, 181},
		{"m16_p0.5", 16, 0.5, 64, 49},
		{"m16_p0.99_capped", 16, 0.99, 64, 64},
		// Degenerate / boundary cases.
		{"single_path", 1, 0.9, 64, 1},
		{"cap_dominates", 16, 0.9, 1, 1},
		{"zero_probability", 16, 0.0, 64, 1},
		{"certainty_falls_back_to_cap", 16, 1.0, 64, 64},
		{"zero_cap_clamped_to_one", 16, 0.9, 0, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeFlowLabelCount(tc.m, tc.p, tc.maxN)
			if got != tc.want {
				t.Errorf("ComputeFlowLabelCount(%d, %v, %d) = %d, want %d",
					tc.m, tc.p, tc.maxN, got, tc.want)
			}
			// The result must always be a usable, capped label count.
			if got < 1 {
				t.Errorf("result %d < 1", got)
			}
			if tc.maxN >= 1 && got > uint32(tc.maxN) {
				t.Errorf("result %d exceeds cap %d", got, tc.maxN)
			}
		})
	}
}

// TestComputeFlowLabelCount_MonotonicInProbability checks that requiring higher
// coverage never asks for fewer labels (sanity property of Eq.(1)).
func TestComputeFlowLabelCount_MonotonicInProbability(t *testing.T) {
	prev := uint32(0)
	for _, p := range []float64{0.5, 0.7, 0.9, 0.95} {
		got := ComputeFlowLabelCount(8, p, 1000)
		if got < prev {
			t.Errorf("n decreased as p rose: p=%v got %d, previous %d", p, got, prev)
		}
		prev = got
	}
}

// fakeRnicSource is a minimal RnicSource returning a fixed set of RNICs so the
// generator's PingTarget construction (seed/count stamping) and its same-host /
// same-family filtering can be tested without a real registry.
type fakeRnicSource struct {
	torMesh  []*controller_agent.RnicInfo
	interTor []*controller_agent.RnicInfo
	// hostnameByGID maps a requester GID to the hostname it is registered
	// under. A GID absent from the map resolves to "" (unregistered), which
	// exercises the GID self-exclusion fallback.
	hostnameByGID map[string]string
	// resolveErr, if set, is returned by ResolveHostnameByGID to exercise the
	// graceful-degradation path.
	resolveErr error
}

func (f *fakeRnicSource) GetRNICsByToR(_ context.Context, _ string) ([]*controller_agent.RnicInfo, error) {
	return f.torMesh, nil
}

func (f *fakeRnicSource) GetActiveRNICsInOtherToRs(_ context.Context, _ string) ([]*controller_agent.RnicInfo, error) {
	return f.interTor, nil
}

func (f *fakeRnicSource) ResolveHostnameByGID(_ context.Context, gid string) (string, error) {
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return f.hostnameByGID[gid], nil
}

// TestPinglistCarriesSeedAndCount verifies that generated PingTargets carry the
// Eq.(1) flow-label count and a non-zero seed whose low 20 bits equal the
// legacy flow label, so an agent can expand the label set.
func TestPinglistCarriesSeedAndCount(t *testing.T) {
	src := &fakeRnicSource{
		torMesh: []*controller_agent.RnicInfo{
			{Gid: "fe80::1"}, // requester (self) -- excluded
			{Gid: "fe80::2", Qpn: 100, TorId: "tor-1"},
			{Gid: "fe80::3", Qpn: 101, TorId: "tor-1"},
		},
	}
	wantCount := ComputeFlowLabelCount(16, 0.9, 64)
	gen := NewPinglistGenerator(src, ECMPConfig{
		PathsAssumed:        16,
		CoverageProbability: 0.9,
		MaxFlowLabels:       64,
	}, DefaultInterTorSampleSize)

	targets, err := gen.GenerateTorMeshPinglist(context.Background(), "fe80::1", "tor-1")
	if err != nil {
		t.Fatalf("GenerateTorMeshPinglist: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (requester excluded)", len(targets))
	}

	for _, tgt := range targets {
		if tgt.GetFlowLabelCount() != wantCount {
			t.Errorf("target %s: FlowLabelCount = %d, want %d",
				tgt.GetTargetGid(), tgt.GetFlowLabelCount(), wantCount)
		}
		if tgt.GetFlowLabelSeed() == 0 {
			t.Errorf("target %s: FlowLabelSeed = 0, want non-zero", tgt.GetTargetGid())
		}
		// The legacy flow label must remain the low 20 bits of the seed for
		// backward compatibility.
		if tgt.GetFlowLabel() != tgt.GetFlowLabelSeed()&0xFFFFF {
			t.Errorf("target %s: FlowLabel %#x != seed&0xFFFFF %#x",
				tgt.GetTargetGid(), tgt.GetFlowLabel(), tgt.GetFlowLabelSeed()&0xFFFFF)
		}
	}
}
