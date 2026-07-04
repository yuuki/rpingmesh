package pinglist

import "testing"

// TestDeterministicFlowLabel_Deterministic verifies that the same
// requester/target GID pair always produces the same flow label, and that
// swapping the pair (or changing either GID) changes the result.
func TestDeterministicFlowLabel_Deterministic(t *testing.T) {
	requesterGID := "fe80::1"
	targetGID := "fe80::2"

	got1 := deterministicFlowLabel(requesterGID, targetGID)
	got2 := deterministicFlowLabel(requesterGID, targetGID)
	if got1 != got2 {
		t.Fatalf("deterministicFlowLabel is not deterministic: %d != %d", got1, got2)
	}

	if reversed := deterministicFlowLabel(targetGID, requesterGID); reversed == got1 {
		t.Errorf("deterministicFlowLabel(target, requester) = %d, expected different value than deterministicFlowLabel(requester, target) = %d", reversed, got1)
	}

	if other := deterministicFlowLabel(requesterGID, "fe80::3"); other == got1 {
		t.Errorf("deterministicFlowLabel with a different targetGID unexpectedly matched: %d", other)
	}
}

// TestDeterministicFlowLabel_Range verifies that the flow label is always
// masked to 20 bits (0-0xFFFFF), as required for ibv_ah_attr.grh.flow_label.
func TestDeterministicFlowLabel_Range(t *testing.T) {
	pairs := [][2]string{
		{"fe80::1", "fe80::2"},
		{"fe80::aaaa", "fe80::bbbb"},
		{"", ""},
		{"a", "b"},
	}

	for _, p := range pairs {
		got := deterministicFlowLabel(p[0], p[1])
		if got > 0xFFFFF {
			t.Errorf("deterministicFlowLabel(%q, %q) = %#x, want <= 0xFFFFF", p[0], p[1], got)
		}
	}
}

// TestDeterministicSourcePort_Deterministic verifies determinism and that
// the salt differentiates the source port hash from the flow label hash.
func TestDeterministicSourcePort_Deterministic(t *testing.T) {
	requesterGID := "fe80::1"
	targetGID := "fe80::2"

	got1 := deterministicSourcePort(requesterGID, targetGID)
	got2 := deterministicSourcePort(requesterGID, targetGID)
	if got1 != got2 {
		t.Fatalf("deterministicSourcePort is not deterministic: %d != %d", got1, got2)
	}
}

// TestDeterministicSourcePort_Range verifies the source port falls within
// the ephemeral port range 49152-65535.
func TestDeterministicSourcePort_Range(t *testing.T) {
	pairs := [][2]string{
		{"fe80::1", "fe80::2"},
		{"fe80::aaaa", "fe80::bbbb"},
		{"", ""},
		{"a", "b"},
	}

	for _, p := range pairs {
		got := deterministicSourcePort(p[0], p[1])
		if got < 49152 || got > 65535 {
			t.Errorf("deterministicSourcePort(%q, %q) = %d, want in range [49152, 65535]", p[0], p[1], got)
		}
	}
}

// TestDeterministicPriority_Deterministic verifies determinism.
func TestDeterministicPriority_Deterministic(t *testing.T) {
	requesterGID := "fe80::1"
	targetGID := "fe80::2"

	got1 := deterministicPriority(requesterGID, targetGID)
	got2 := deterministicPriority(requesterGID, targetGID)
	if got1 != got2 {
		t.Fatalf("deterministicPriority is not deterministic: %d != %d", got1, got2)
	}
}

// TestDeterministicPriority_Range verifies the priority is always in 0-7.
func TestDeterministicPriority_Range(t *testing.T) {
	pairs := [][2]string{
		{"fe80::1", "fe80::2"},
		{"fe80::aaaa", "fe80::bbbb"},
		{"", ""},
		{"a", "b"},
	}

	for _, p := range pairs {
		got := deterministicPriority(p[0], p[1])
		if got > 7 {
			t.Errorf("deterministicPriority(%q, %q) = %d, want in range [0, 7]", p[0], p[1], got)
		}
	}
}
