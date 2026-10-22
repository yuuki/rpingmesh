package pinglist

import (
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// hashPairs are requester/target GID pairs covering realistic, empty and
// single-byte inputs for the deterministic 5-tuple helpers.
var hashPairs = [][2]string{
	{"fe80::1", "fe80::2"},
	{"fe80::aaaa", "fe80::bbbb"},
	{"", ""},
	{"a", "b"},
}

// TestGidPairHash_Deterministic verifies that the same requester/target GID
// pair always produces the same hash, and that swapping the pair (or changing
// either GID) changes the result.
func TestGidPairHash_Deterministic(t *testing.T) {
	requesterGID := "fe80::1"
	targetGID := "fe80::2"

	got1 := gidPairHash(requesterGID, "", targetGID)
	got2 := gidPairHash(requesterGID, "", targetGID)
	if got1 != got2 {
		t.Fatalf("gidPairHash is not deterministic: %d != %d", got1, got2)
	}

	if reversed := gidPairHash(targetGID, "", requesterGID); reversed == got1 {
		t.Errorf("gidPairHash(target, requester) = %d, expected different value than gidPairHash(requester, target) = %d", reversed, got1)
	}

	if other := gidPairHash(requesterGID, "", "fe80::3"); other == got1 {
		t.Errorf("gidPairHash with a different targetGID unexpectedly matched: %d", other)
	}
}

// TestGidPairHash_SaltDifferentiates verifies that the salts used for the
// source port and priority keep those hashes independent of the flow-label
// seed, so the three 5-tuple values do not move in lockstep.
func TestGidPairHash_SaltDifferentiates(t *testing.T) {
	for _, p := range hashPairs {
		seed := gidPairHash(p[0], "", p[1])
		port := gidPairHash(p[0], "port", p[1])
		prio := gidPairHash(p[0], "prio", p[1])
		if seed == port || seed == prio || port == prio {
			t.Errorf("gidPairHash(%q, salt, %q): seed=%#x port=%#x prio=%#x, want all distinct", p[0], p[1], seed, port, prio)
		}
	}
}

// TestBuildPingTarget_FlowLabelIsMaskedSeed verifies that the legacy flow
// label stamped on a PingTarget is the low 20 bits of flowLabelSeed (the width
// of ibv_ah_attr.grh.flow_label), for every pair.
func TestBuildPingTarget_FlowLabelIsMaskedSeed(t *testing.T) {
	g := &PinglistGenerator{flowLabelCount: 1}
	for _, p := range hashPairs {
		tgt := g.buildPingTarget(p[0], &controller_agent.RnicInfo{Gid: p[1]}, controller_agent.PinglistType_TOR_MESH)
		seed := flowLabelSeed(p[0], p[1])
		if tgt.GetFlowLabelSeed() != seed {
			t.Errorf("buildPingTarget(%q, %q).FlowLabelSeed = %#x, want %#x", p[0], p[1], tgt.GetFlowLabelSeed(), seed)
		}
		if tgt.GetFlowLabel() > flowLabelMask {
			t.Errorf("buildPingTarget(%q, %q).FlowLabel = %#x, want <= %#x", p[0], p[1], tgt.GetFlowLabel(), flowLabelMask)
		}
		if tgt.GetFlowLabel() != seed&flowLabelMask {
			t.Errorf("buildPingTarget(%q, %q).FlowLabel = %#x, want seed&mask %#x", p[0], p[1], tgt.GetFlowLabel(), seed&flowLabelMask)
		}
	}
}

// TestDeterministicSourcePort verifies determinism and that the source port
// falls within the ephemeral port range 49152-65535.
func TestDeterministicSourcePort(t *testing.T) {
	for _, p := range hashPairs {
		got := deterministicSourcePort(p[0], p[1])
		if again := deterministicSourcePort(p[0], p[1]); again != got {
			t.Errorf("deterministicSourcePort(%q, %q) is not deterministic: %d != %d", p[0], p[1], got, again)
		}
		if got < 49152 || got > 65535 {
			t.Errorf("deterministicSourcePort(%q, %q) = %d, want in range [49152, 65535]", p[0], p[1], got)
		}
	}
}

// TestDeterministicPriority verifies determinism and that the priority is
// always in 0-7.
func TestDeterministicPriority(t *testing.T) {
	for _, p := range hashPairs {
		got := deterministicPriority(p[0], p[1])
		if again := deterministicPriority(p[0], p[1]); again != got {
			t.Errorf("deterministicPriority(%q, %q) is not deterministic: %d != %d", p[0], p[1], got, again)
		}
		if got > 7 {
			t.Errorf("deterministicPriority(%q, %q) = %d, want in range [0, 7]", p[0], p[1], got)
		}
	}
}
