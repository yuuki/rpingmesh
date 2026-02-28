package probe

import (
	"testing"
	"time"
)

func TestCalculateRTT_ValidResult(t *testing.T) {
	// Simulate a valid probe with realistic nanosecond timestamps.
	// T1=100us, T2=101us, T3=200us, T4=202us, T5=301us, T6=302us
	result := &ProbeResult{
		T1: 100_000, // 100us prober send
		T2: 101_000, // 101us NIC send completion
		T3: 200_000, // 200us responder recv
		T4: 202_000, // 202us responder ACK send completion
		T5: 301_000, // 301us prober first ACK recv
		T6: 302_000, // 302us prober second ACK recv
	}

	rtt := CalculateRTT(result)
	if !rtt.Valid {
		t.Fatalf("expected valid RTT result, got validation error: %s", rtt.ValidationError)
	}

	// ResponderDelay = T4 - T3 = 202000 - 200000 = 2000 ns
	expectedResponderDelay := int64(2_000)
	if rtt.ResponderDelay != expectedResponderDelay {
		t.Errorf("ResponderDelay: got %d ns, want %d ns", rtt.ResponderDelay, expectedResponderDelay)
	}

	// NetworkRTT = (T5-T2) - (T4-T3) = (301000-101000) - (202000-200000) = 200000 - 2000 = 198000 ns
	expectedNetworkRTT := int64(198_000)
	if rtt.NetworkRTT != expectedNetworkRTT {
		t.Errorf("NetworkRTT: got %d ns, want %d ns", rtt.NetworkRTT, expectedNetworkRTT)
	}

	// ProberDelay = (T6-T1) - (T5-T2) = (302000-100000) - (301000-101000) = 202000 - 200000 = 2000 ns
	expectedProberDelay := int64(2_000)
	if rtt.ProberDelay != expectedProberDelay {
		t.Errorf("ProberDelay: got %d ns, want %d ns", rtt.ProberDelay, expectedProberDelay)
	}
}

func TestCalculateRTT_NilProbeResult(t *testing.T) {
	rtt := CalculateRTT(nil)
	if rtt.Valid {
		t.Fatal("expected invalid RTT result for nil input")
	}
	if rtt.ValidationError != "nil ProbeResult" {
		t.Errorf("unexpected validation error: %s", rtt.ValidationError)
	}
}

func TestCalculateRTT_ZeroTimestamps(t *testing.T) {
	tests := []struct {
		name   string
		result ProbeResult
		errMsg string
	}{
		{"zero T1", ProbeResult{T1: 0, T2: 1, T3: 1, T4: 1, T5: 1, T6: 1}, "T1"},
		{"zero T2", ProbeResult{T1: 1, T2: 0, T3: 1, T4: 1, T5: 1, T6: 1}, "T2"},
		{"zero T3", ProbeResult{T1: 1, T2: 1, T3: 0, T4: 1, T5: 1, T6: 1}, "T3"},
		{"zero T4", ProbeResult{T1: 1, T2: 1, T3: 1, T4: 0, T5: 1, T6: 1}, "T4"},
		{"zero T5", ProbeResult{T1: 1, T2: 1, T3: 1, T4: 1, T5: 0, T6: 1}, "T5"},
		{"zero T6", ProbeResult{T1: 1, T2: 1, T3: 1, T4: 1, T5: 1, T6: 0}, "T6"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rtt := CalculateRTT(&tc.result)
			if rtt.Valid {
				t.Fatal("expected invalid RTT result for zero timestamp")
			}
			if len(rtt.ValidationError) == 0 {
				t.Fatal("expected non-empty validation error")
			}
		})
	}
}

func TestCalculateRTT_NegativeNetworkRTT(t *testing.T) {
	// Clock skew scenario: T5-T2 is less than T4-T3, making NetworkRTT negative.
	result := &ProbeResult{
		T1: 100_000,
		T2: 101_000,
		T3: 200_000,
		T4: 300_000, // Large responder delay
		T5: 150_000, // Prober first ACK recv is before responder ACK send due to clock skew
		T6: 160_000,
	}

	rtt := CalculateRTT(result)
	if rtt.Valid {
		t.Fatal("expected invalid RTT result for negative NetworkRTT")
	}
	if rtt.NetworkRTT >= 0 {
		t.Errorf("expected negative NetworkRTT, got %d", rtt.NetworkRTT)
	}
}

func TestCalculateRTT_ExceedsMaxSaneRTT(t *testing.T) {
	// NetworkRTT exceeds 10s bound.
	result := &ProbeResult{
		T1: 1_000_000_000,
		T2: 1_000_000_000,
		T3: 2_000_000_000,
		T4: 2_000_000_001,                        // Tiny responder delay
		T5: 1_000_000_000 + uint64(11*time.Second), // 11s round trip
		T6: 1_000_000_000 + uint64(12*time.Second),
	}

	rtt := CalculateRTT(result)
	if rtt.Valid {
		t.Fatal("expected invalid RTT result when NetworkRTT exceeds max sane bound")
	}
}

func TestCalculateRTT_NegativeResponderDelay(t *testing.T) {
	// T4 < T3: responder timestamp ordering issue.
	result := &ProbeResult{
		T1: 100_000,
		T2: 101_000,
		T3: 200_000,
		T4: 199_000, // T4 before T3
		T5: 301_000,
		T6: 302_000,
	}

	rtt := CalculateRTT(result)
	if rtt.Valid {
		t.Fatal("expected invalid RTT result for negative ResponderDelay")
	}
}

func TestCalculateRTT_ExceedsMaxSaneDelay(t *testing.T) {
	// ResponderDelay exceeds 1s bound.
	result := &ProbeResult{
		T1: 1_000_000_000,
		T2: 1_000_000_001,
		T3: 2_000_000_000,
		T4: 2_000_000_000 + uint64(2*time.Second), // 2s responder delay
		T5: 3_000_000_000 + uint64(2*time.Second),
		T6: 3_000_000_001 + uint64(2*time.Second),
	}

	rtt := CalculateRTT(result)
	if rtt.Valid {
		t.Fatal("expected invalid RTT result when ResponderDelay exceeds max sane bound")
	}
}

func TestFormatGID(t *testing.T) {
	tests := []struct {
		name     string
		gid      [16]byte
		expected string
	}{
		{
			"all zeros",
			[16]byte{},
			"0000:0000:0000:0000:0000:0000:0000:0000",
		},
		{
			"link-local fe80",
			[16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0, 0x03, 0, 0x04},
			"fe80:0000:0000:0000:0001:0002:0003:0004",
		},
		{
			"IPv4-mapped",
			[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
			"0000:0000:0000:0000:0000:ffff:c0a8:0101",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatGID(tc.gid)
			if got != tc.expected {
				t.Errorf("FormatGID: got %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestParseGID_LongForm(t *testing.T) {
	input := "fe80:0000:0000:0000:0001:0002:0003:0004"
	expected := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0, 0x03, 0, 0x04}

	gid, err := ParseGID(input)
	if err != nil {
		t.Fatalf("ParseGID(%q): unexpected error: %v", input, err)
	}
	if gid != expected {
		t.Errorf("ParseGID(%q): got %v, want %v", input, gid, expected)
	}
}

func TestParseGID_ShortForm(t *testing.T) {
	input := "fe80::1"
	expected := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	gid, err := ParseGID(input)
	if err != nil {
		t.Fatalf("ParseGID(%q): unexpected error: %v", input, err)
	}
	if gid != expected {
		t.Errorf("ParseGID(%q): got %v, want %v", input, gid, expected)
	}
}

func TestParseGID_AllZeros(t *testing.T) {
	input := "::"
	expected := [16]byte{}

	gid, err := ParseGID(input)
	if err != nil {
		t.Fatalf("ParseGID(%q): unexpected error: %v", input, err)
	}
	if gid != expected {
		t.Errorf("ParseGID(%q): got %v, want %v", input, gid, expected)
	}
}

func TestParseGID_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too few groups", "fe80:0000:0000"},
		{"empty string", ""},
		{"invalid hex", "gggg:0000:0000:0000:0000:0000:0000:0000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseGID(tc.input)
			if err == nil {
				t.Errorf("ParseGID(%q): expected error, got nil", tc.input)
			}
		})
	}
}

func TestFormatGID_ParseGID_Roundtrip(t *testing.T) {
	original := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0, 0x03, 0, 0x04}

	formatted := FormatGID(original)
	parsed, err := ParseGID(formatted)
	if err != nil {
		t.Fatalf("roundtrip ParseGID failed: %v", err)
	}
	if parsed != original {
		t.Errorf("roundtrip failed: got %v, want %v", parsed, original)
	}
}

func TestGIDToIPv4_MappedAddress(t *testing.T) {
	// IPv4-mapped: ::ffff:192.168.1.1
	gid := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1}
	got := GIDToIPv4(gid)
	expected := "192.168.1.1"
	if got != expected {
		t.Errorf("GIDToIPv4 (mapped): got %q, want %q", got, expected)
	}
}

func TestGIDToIPv4_NonMappedAddress(t *testing.T) {
	// Link-local GID: not IPv4-mapped, should return full hex.
	gid := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0, 0x03, 0, 0x04}
	got := GIDToIPv4(gid)
	expected := "fe80:0000:0000:0000:0001:0002:0003:0004"
	if got != expected {
		t.Errorf("GIDToIPv4 (non-mapped): got %q, want %q", got, expected)
	}
}

func TestGIDToIPv4_AllZeros(t *testing.T) {
	// All zeros is not IPv4-mapped (bytes 10-11 are not 0xFF).
	gid := [16]byte{}
	got := GIDToIPv4(gid)
	expected := "0000:0000:0000:0000:0000:0000:0000:0000"
	if got != expected {
		t.Errorf("GIDToIPv4 (all zeros): got %q, want %q", got, expected)
	}
}

func TestGIDToIPv4_LoopbackMapped(t *testing.T) {
	// ::ffff:127.0.0.1
	gid := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}
	got := GIDToIPv4(gid)
	expected := "127.0.0.1"
	if got != expected {
		t.Errorf("GIDToIPv4 (loopback): got %q, want %q", got, expected)
	}
}

func TestCalculateRTT_RealisticTimestamps(t *testing.T) {
	// Simulate a realistic datacenter probe with ~50us RTT.
	baseNS := uint64(1_000_000_000_000) // 1000 seconds in nanoseconds

	result := &ProbeResult{
		T1: baseNS,                  // Prober starts sending
		T2: baseNS + 1_000,         // 1us later: NIC send completion
		T3: baseNS + 25_000,        // 25us later: responder receives
		T4: baseNS + 26_000,        // 1us responder processing
		T5: baseNS + 51_000,        // 51us from T1: first ACK arrives at prober
		T6: baseNS + 52_000,        // 1us later: second ACK arrives
	}

	rtt := CalculateRTT(result)
	if !rtt.Valid {
		t.Fatalf("expected valid RTT, got: %s", rtt.ValidationError)
	}

	// ResponderDelay = T4 - T3 = 1000 ns = 1us
	if rtt.ResponderDelay != 1_000 {
		t.Errorf("ResponderDelay: got %d ns, want 1000 ns", rtt.ResponderDelay)
	}

	// NetworkRTT = (T5-T2) - (T4-T3) = 50000 - 1000 = 49000 ns = 49us
	if rtt.NetworkRTT != 49_000 {
		t.Errorf("NetworkRTT: got %d ns, want 49000 ns", rtt.NetworkRTT)
	}

	// ProberDelay = (T6-T1) - (T5-T2) = 52000 - 50000 = 2000 ns = 2us
	if rtt.ProberDelay != 2_000 {
		t.Errorf("ProberDelay: got %d ns, want 2000 ns", rtt.ProberDelay)
	}
}
