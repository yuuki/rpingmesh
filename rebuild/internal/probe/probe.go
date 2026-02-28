// Package probe provides Go-native probe result types and RTT calculation
// logic for the R-Pingmesh 6-timestamp probing protocol.
//
// The protocol works as follows:
//
//	Prober                     Responder
//	  |                           |
//	  |-- T1: send probe -------> |
//	  |         T2: probe arrives |
//	  |                           |-- T3: recv timestamp
//	  |         T4: send first ACK|
//	  |<-- first ACK (T1,T3) ----|
//	  |  T5: first ACK arrives    |
//	  |                           |
//	  |<-- second ACK (T1,T3,T4) -|
//	  |  T6: second ACK arrives   |
//
// RTT calculations:
//
//	NetworkRTT     = (T5 - T2) - (T4 - T3)   // Pure network round-trip
//	ProberDelay    = (T6 - T1) - (T5 - T2)   // Prober-side processing overhead
//	ResponderDelay = T4 - T3                  // Responder-side processing time
package probe

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Sanity bounds for RTT validation. Values exceeding these thresholds
// indicate clock skew, misconfiguration, or corrupted timestamps.
const (
	MaxSaneRTT   = int64(10 * time.Second) // 10s upper bound for network RTT
	MaxSaneDelay = int64(1 * time.Second)  // 1s upper bound for processing delays
)

// ProbeResult contains the complete 6-timestamp probe measurement.
// Timestamps are in nanoseconds (CLOCK_MONOTONIC or HW timestamps).
type ProbeResult struct {
	SequenceNum    uint64
	TargetGID      [16]byte
	TargetQPN      uint32
	FlowLabel      uint32
	T1             uint64 // Prober send time (CLOCK_MONOTONIC via Zig)
	T2             uint64 // NIC HW timestamp of probe send completion (or SW fallback)
	T3             uint64 // Responder recv timestamp (NIC HW or SW)
	T4             uint64 // Responder first ACK send completion timestamp
	T5             uint64 // Prober first ACK recv timestamp (NIC HW or SW)
	T6             uint64 // Prober second ACK recv time (Go MONOTONIC)
	Success        bool
	ErrorMessage   string
	TargetIP       string
	TargetHostname string
	TargetTorID    string
	SourceTorID    string
}

// RTTResult contains calculated RTT metrics from a probe.
// All durations are in nanoseconds.
type RTTResult struct {
	NetworkRTT      int64  // nanoseconds: (T5-T2) - (T4-T3)
	ProberDelay     int64  // nanoseconds: (T6-T1) - (T5-T2)
	ResponderDelay  int64  // nanoseconds: T4-T3
	Valid           bool   // Whether all timestamps are present and calculation is sane
	ValidationError string // Reason if not valid
}

// CalculateRTT computes RTT metrics from a 6-timestamp probe result.
// It validates that all timestamps are non-zero, computes the three
// RTT components, and performs sanity checks on the results.
//
// A result with Valid=false indicates either missing timestamps or
// values outside acceptable bounds (e.g., negative NetworkRTT from
// clock skew, or unreasonably large delays).
func CalculateRTT(result *ProbeResult) *RTTResult {
	if result == nil {
		return &RTTResult{
			Valid:           false,
			ValidationError: "nil ProbeResult",
		}
	}

	// Validate all timestamps are non-zero (present).
	if result.T1 == 0 {
		return &RTTResult{
			Valid:           false,
			ValidationError: "T1 (prober send time) is zero",
		}
	}
	if result.T2 == 0 {
		return &RTTResult{
			Valid:           false,
			ValidationError: "T2 (probe send completion timestamp) is zero",
		}
	}
	if result.T3 == 0 {
		return &RTTResult{
			Valid:           false,
			ValidationError: "T3 (responder recv timestamp) is zero",
		}
	}
	if result.T4 == 0 {
		return &RTTResult{
			Valid:           false,
			ValidationError: "T4 (responder ACK send completion timestamp) is zero",
		}
	}
	if result.T5 == 0 {
		return &RTTResult{
			Valid:           false,
			ValidationError: "T5 (prober first ACK recv timestamp) is zero",
		}
	}
	if result.T6 == 0 {
		return &RTTResult{
			Valid:           false,
			ValidationError: "T6 (prober second ACK recv time) is zero",
		}
	}

	// Calculate RTT components using signed arithmetic to detect
	// negative values caused by clock skew.
	responderDelay := int64(result.T4) - int64(result.T3)
	networkRTT := (int64(result.T5) - int64(result.T2)) - responderDelay
	proberDelay := (int64(result.T6) - int64(result.T1)) - (int64(result.T5) - int64(result.T2))

	// Validate: NetworkRTT must be positive. A negative value indicates
	// clock skew between the prober and responder hardware timestamps.
	if networkRTT < 0 {
		return &RTTResult{
			NetworkRTT:      networkRTT,
			ProberDelay:     proberDelay,
			ResponderDelay:  responderDelay,
			Valid:           false,
			ValidationError: fmt.Sprintf("negative NetworkRTT (%d ns) indicates clock skew", networkRTT),
		}
	}

	// Validate: NetworkRTT should not exceed the sanity bound.
	if networkRTT > MaxSaneRTT {
		return &RTTResult{
			NetworkRTT:      networkRTT,
			ProberDelay:     proberDelay,
			ResponderDelay:  responderDelay,
			Valid:           false,
			ValidationError: fmt.Sprintf("NetworkRTT (%d ns) exceeds max sane bound (%d ns)", networkRTT, MaxSaneRTT),
		}
	}

	// Validate: ResponderDelay must be positive. A negative value indicates
	// a timestamp ordering issue on the responder side.
	if responderDelay < 0 {
		return &RTTResult{
			NetworkRTT:      networkRTT,
			ProberDelay:     proberDelay,
			ResponderDelay:  responderDelay,
			Valid:           false,
			ValidationError: fmt.Sprintf("negative ResponderDelay (%d ns) indicates timestamp ordering issue", responderDelay),
		}
	}

	// Validate: ResponderDelay should not exceed the sanity bound.
	if responderDelay > MaxSaneDelay {
		return &RTTResult{
			NetworkRTT:      networkRTT,
			ProberDelay:     proberDelay,
			ResponderDelay:  responderDelay,
			Valid:           false,
			ValidationError: fmt.Sprintf("ResponderDelay (%d ns) exceeds max sane bound (%d ns)", responderDelay, MaxSaneDelay),
		}
	}

	return &RTTResult{
		NetworkRTT:     networkRTT,
		ProberDelay:    proberDelay,
		ResponderDelay: responderDelay,
		Valid:          true,
	}
}

// FormatGID formats a 16-byte GID as a colon-separated hex string in
// RoCEv2 GID notation, e.g., "fe80:0000:0000:0000:0001:0002:0003:0004".
// Each group represents 2 bytes (4 hex digits).
func FormatGID(gid [16]byte) string {
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		groups[i] = fmt.Sprintf("%02x%02x", gid[i*2], gid[i*2+1])
	}
	return strings.Join(groups, ":")
}

// ParseGID parses a colon-separated hex GID string into a [16]byte.
// It supports both the full form ("fe80:0000:0000:0000:0001:0002:0003:0004")
// and the abbreviated form ("fe80::1") by delegating to the standard
// net.ParseIP function for IPv6 address parsing.
func ParseGID(s string) ([16]byte, error) {
	var gid [16]byte

	// Try parsing as a standard IPv6 address first. This handles both
	// the abbreviated (fe80::1) and full (fe80:0000:...) forms. The
	// net.ParseIP function returns a 16-byte IPv6 representation.
	ip := net.ParseIP(s)
	if ip != nil {
		ip6 := ip.To16()
		if ip6 != nil {
			copy(gid[:], ip6)
			return gid, nil
		}
	}

	// Fallback: try parsing as raw colon-separated hex without abbreviation.
	// This handles GID formats that may not be valid IPv6 but are valid
	// InfiniBand GID notation.
	parts := strings.Split(s, ":")
	if len(parts) != 8 {
		return gid, fmt.Errorf("invalid GID format: expected 8 colon-separated groups, got %d in %q", len(parts), s)
	}

	for i, part := range parts {
		// Pad short groups to 4 hex characters.
		for len(part) < 4 {
			part = "0" + part
		}
		if len(part) != 4 {
			return gid, fmt.Errorf("invalid GID group %d: expected up to 4 hex chars, got %q", i, parts[i])
		}
		b, err := hex.DecodeString(part)
		if err != nil {
			return gid, fmt.Errorf("invalid hex in GID group %d: %w", i, err)
		}
		gid[i*2] = b[0]
		gid[i*2+1] = b[1]
	}

	return gid, nil
}

// GIDToIPv4 converts a 16-byte GID to a human-readable IP string.
// If the GID is an IPv4-mapped address (bytes 0-9 are zero, bytes 10-11
// are 0xFFFF), it returns dotted-decimal notation (e.g., "192.168.1.1").
// Otherwise, it returns the full colon-separated GID hex notation.
func GIDToIPv4(gid [16]byte) string {
	// Check for IPv4-mapped IPv6 address:
	// bytes 0-9 must be zero, bytes 10-11 must be 0xFF.
	isIPv4Mapped := true
	for i := 0; i < 10; i++ {
		if gid[i] != 0 {
			isIPv4Mapped = false
			break
		}
	}
	if isIPv4Mapped && gid[10] == 0xff && gid[11] == 0xff {
		return fmt.Sprintf("%d.%d.%d.%d", gid[12], gid[13], gid[14], gid[15])
	}

	// Not IPv4-mapped, return full GID hex notation.
	return FormatGID(gid)
}
