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
	MaxSaneRTT   = int64(10 * time.Second) // network RTT
	MaxSaneDelay = int64(1 * time.Second)  // prober and responder processing delays
)

// ProbeResult contains the complete 6-timestamp probe measurement.
// Timestamps are in nanoseconds (CLOCK_MONOTONIC or HW timestamps).
type ProbeResult struct {
	SequenceNum uint64
	// SourceGID is the GID of the local RNIC that sent this probe. It is set
	// by the Prober from its bound device so that downstream consumers (in
	// particular the per-path PathAggregator) can key results by
	// (source, target) even after every device's results are merged into one
	// fan-in stream. Zero when the emitting Prober has no bound device (test
	// fakes), which is harmless: such results are never aggregated.
	SourceGID    [16]byte
	TargetGID    [16]byte
	TargetQPN    uint32
	FlowLabel    uint32
	T1           uint64 // Prober send time (CLOCK_MONOTONIC via Zig)
	T2           uint64 // NIC HW timestamp of probe send completion (or SW fallback)
	T3           uint64 // Responder recv timestamp (NIC HW or SW)
	T4           uint64 // Responder first ACK send completion timestamp
	T5           uint64 // Prober first ACK recv timestamp (NIC HW or SW)
	T6           uint64 // Prober second ACK recv time (CLOCK_MONOTONIC, same domain as T1)
	Success      bool
	ErrorMessage string
	// FailureReason classifies a failed probe (Success == false) for the
	// "reason" metric attribute; empty for a successful probe.
	FailureReason  FailureReason
	TargetIP       string
	TargetHostname string
	TargetTorID    string
	SourceTorID    string
	// SourceRdmaDevice and SourceNetdev name the local RNIC that sent this
	// probe: its RDMA device (e.g. "mlx5_0") and the netdev bound to the
	// probing port/GID (e.g. "ens1f0"). Both are stamped by the Prober so they
	// survive the fan-in of every device's results, and become the
	// source_rdma_device / source_netdev metric attributes. Empty when
	// unknown (test fakes, or a netdev that could not be resolved).
	SourceRdmaDevice string
	SourceNetdev     string
	// TargetRdmaDevice and TargetNetdev name the target RNIC, copied from
	// the PingTarget (empty when the controller or target agent does not
	// know them). TargetSampled reports that the controller picked the
	// target by sampling that changes across pinglist refreshes (inter-ToR,
	// or a capped untagged ToR-mesh). All three exist only for the optional
	// destination-RNIC metrics.
	TargetRdmaDevice string
	TargetNetdev     string
	TargetSampled    bool
	// PinglistType is the pinglist the probe's target came from. A
	// PinglistServiceTracing result was sent along a traced service flow (a
	// SERVICE_TRACING target, see internal/agent/servicetrace) rather than
	// to a controller pinglist target: it measures the service network, is
	// recorded on the rpingmesh.service.* instruments (never on the
	// cluster-monitoring ones) and is summarized apart from the cluster
	// paths of the same target by the PathAggregator.
	PinglistType PinglistType
}

// PinglistType identifies the pinglist a probe target belongs to. The values
// equal those of the controller_agent.PinglistType proto enum, which this
// RDMA- and proto-independent package cannot import; the agent converts
// between the two by value (and tests pin the equality).
type PinglistType int32

const (
	// PinglistTorMesh: a target in the same ToR, from the controller's
	// ToR-mesh pinglist.
	PinglistTorMesh PinglistType = 0
	// PinglistInterTor: a sampled target in another ToR, from the
	// controller's inter-ToR pinglist.
	PinglistInterTor PinglistType = 1
	// PinglistServiceTracing: the remote RNIC of a traced application flow,
	// probed with the flow's own flow label.
	PinglistServiceTracing PinglistType = 2
)

// String returns the lower-case name used in logs and findings.
func (t PinglistType) String() string {
	switch t {
	case PinglistTorMesh:
		return "tor_mesh"
	case PinglistInterTor:
		return "inter_tor"
	case PinglistServiceTracing:
		return "service_tracing"
	default:
		return "unknown"
	}
}

// IsServiceTracing reports whether the probe was sent along a traced service
// flow rather than to a controller pinglist target.
func (r *ProbeResult) IsServiceTracing() bool {
	return r.PinglistType == PinglistServiceTracing
}

// InvalidKind classifies why CalculateRTT rejected a measurement. The values
// form a small fixed set so they can be used as a metric attribute; the
// detailed, value-bearing message stays in RTTResult.ValidationError.
type InvalidKind string

// InvalidKind values. InvalidKindNone is the kind of a valid result.
const (
	InvalidKindNone InvalidKind = ""
	// InvalidKindMissingTimestamp: one of T1-T6 is zero (or the result is nil).
	InvalidKindMissingTimestamp InvalidKind = "missing_timestamp"
	// InvalidKindNegativeNetworkRTT: (T5-T2) < (T4-T3), e.g. timestamp
	// jitter or skew between the prober's and responder's NIC clocks.
	InvalidKindNegativeNetworkRTT InvalidKind = "negative_network_rtt"
	// InvalidKindNetworkRTTTooLarge: NetworkRTT above MaxSaneRTT.
	InvalidKindNetworkRTTTooLarge InvalidKind = "network_rtt_too_large"
	// InvalidKindNegativeResponderDelay: T4 < T3 on the responder.
	InvalidKindNegativeResponderDelay InvalidKind = "negative_responder_delay"
	// InvalidKindResponderDelayTooLarge: T4-T3 above MaxSaneDelay. The usual
	// cause is a responder that fell behind its inbound probes (a backlog of
	// more than MaxSaneDelay before the first ACK was posted), not the
	// network.
	InvalidKindResponderDelayTooLarge InvalidKind = "responder_delay_too_large"
	// InvalidKindNegativeProberDelay: (T6-T1) < (T5-T2) on the prober.
	InvalidKindNegativeProberDelay InvalidKind = "negative_prober_delay"
	// InvalidKindProberDelayTooLarge: ProberDelay above MaxSaneDelay.
	InvalidKindProberDelayTooLarge InvalidKind = "prober_delay_too_large"
)

// FailureReason is the agent's classification of why a probe failed. The
// values are the "reason" attribute of rpingmesh.probe_failed_total.
type FailureReason string

const (
	// FailureTimeout: the probe's ACKs never completed the measurement.
	FailureTimeout FailureReason = "timeout"
	// FailureSendError: posting the probe failed before any ACK could be
	// expected.
	FailureSendError FailureReason = "send_error"
)

// RTTResult contains calculated RTT metrics from a probe.
// All durations are in nanoseconds.
type RTTResult struct {
	NetworkRTT      int64       // nanoseconds: (T5-T2) - (T4-T3)
	ProberDelay     int64       // nanoseconds: (T6-T1) - (T5-T2)
	ResponderDelay  int64       // nanoseconds: T4-T3
	Valid           bool        // Whether all timestamps are present and calculation is sane
	ValidationError string      // Reason if not valid
	InvalidKind     InvalidKind // Classification of ValidationError; InvalidKindNone if valid
}

// CalculateRTT computes RTT metrics from a 6-timestamp probe result. It
// rejects a result with a missing (zero) timestamp, then computes the three
// components with signed arithmetic and rejects a negative or implausibly
// large one (see InvalidKind for the causes of each).
func CalculateRTT(result *ProbeResult) *RTTResult {
	rtt := &RTTResult{}
	invalid := func(kind InvalidKind, msg string) *RTTResult {
		rtt.Valid, rtt.InvalidKind, rtt.ValidationError = false, kind, msg
		return rtt
	}
	if result == nil {
		return invalid(InvalidKindMissingTimestamp, "nil ProbeResult")
	}
	for _, ts := range [...]struct {
		value uint64
		name  string
	}{
		{result.T1, "T1 (prober send time)"},
		{result.T2, "T2 (probe send completion timestamp)"},
		{result.T3, "T3 (responder recv timestamp)"},
		{result.T4, "T4 (responder ACK send completion timestamp)"},
		{result.T5, "T5 (prober first ACK recv timestamp)"},
		{result.T6, "T6 (prober second ACK recv time)"},
	} {
		if ts.value == 0 {
			return invalid(InvalidKindMissingTimestamp, ts.name+" is zero")
		}
	}

	rtt.ResponderDelay = int64(result.T4) - int64(result.T3)
	rtt.NetworkRTT = (int64(result.T5) - int64(result.T2)) - rtt.ResponderDelay
	rtt.ProberDelay = (int64(result.T6) - int64(result.T1)) - (int64(result.T5) - int64(result.T2))

	// The ProberDelay term is only meaningful when T1 and T6 are both
	// CLOCK_MONOTONIC on the prober host; its bound check mirrors the
	// ResponderDelay one so a corrupted or wall-clock-contaminated T6 cannot
	// slip through as a valid measurement.
	switch {
	case rtt.NetworkRTT < 0:
		return invalid(InvalidKindNegativeNetworkRTT,
			fmt.Sprintf("negative NetworkRTT (%d ns) indicates clock skew", rtt.NetworkRTT))
	case rtt.NetworkRTT > MaxSaneRTT:
		return invalid(InvalidKindNetworkRTTTooLarge,
			fmt.Sprintf("NetworkRTT (%d ns) exceeds max sane bound (%d ns)", rtt.NetworkRTT, MaxSaneRTT))
	case rtt.ResponderDelay < 0:
		return invalid(InvalidKindNegativeResponderDelay,
			fmt.Sprintf("negative ResponderDelay (%d ns) indicates timestamp ordering issue", rtt.ResponderDelay))
	case rtt.ResponderDelay > MaxSaneDelay:
		return invalid(InvalidKindResponderDelayTooLarge,
			fmt.Sprintf("ResponderDelay (%d ns) exceeds max sane bound (%d ns)", rtt.ResponderDelay, MaxSaneDelay))
	case rtt.ProberDelay < 0:
		return invalid(InvalidKindNegativeProberDelay,
			fmt.Sprintf("negative ProberDelay (%d ns) indicates clock skew or T1/T6 clock-domain mismatch", rtt.ProberDelay))
	case rtt.ProberDelay > MaxSaneDelay:
		return invalid(InvalidKindProberDelayTooLarge,
			fmt.Sprintf("ProberDelay (%d ns) exceeds max sane bound (%d ns)", rtt.ProberDelay, MaxSaneDelay))
	}
	rtt.Valid = true
	return rtt
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

	// net.ParseIP handles both the abbreviated (fe80::1) and the full
	// (fe80:0000:...) form.
	if ip6 := net.ParseIP(s).To16(); ip6 != nil {
		copy(gid[:], ip6)
		return gid, nil
	}

	// Fallback for colon-separated hex that is valid InfiniBand GID notation
	// but not a valid IPv6 address.
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

// isIPv4MappedGID reports whether gid is an IPv4-mapped IPv6 address
// (::ffff:a.b.c.d: bytes 0-9 zero, bytes 10-11 0xff), the form a RoCE GID
// takes on an IPv4-addressed port. It is the single prefix test behind
// GIDToIPv4 and GIDFamily.
func isIPv4MappedGID(gid [16]byte) bool {
	return net.IP(gid[:]).To4() != nil
}

// GIDToIPv4 renders a 16-byte GID for display: an IPv4-mapped GID as
// dotted-decimal (e.g. "192.168.1.1"), any other GID in FormatGID's
// colon-separated hex notation.
func GIDToIPv4(gid [16]byte) string {
	if isIPv4MappedGID(gid) {
		return fmt.Sprintf("%d.%d.%d.%d", gid[12], gid[13], gid[14], gid[15])
	}
	return FormatGID(gid)
}

// GID address-family classifications returned by GIDFamily. The controller's
// pinglist generators use them to avoid pairing a native-IPv6 GID with an
// IPv4-mapped one: ibv_create_ah() resolves the destination via a route lookup
// that fails when the source and destination GID families differ, so a
// cross-family probe can never leave the source host and every such pair would
// retry-and-fail forever (see issue #41).
const (
	// GIDFamilyIPv4Mapped is an IPv4-mapped IPv6 GID (::ffff:a.b.c.d): bytes
	// 0-9 are zero and bytes 10-11 are 0xff. These typically live on
	// RoCE-capable management NICs.
	GIDFamilyIPv4Mapped = "ipv4-mapped"
	// GIDFamilyIPv6 is a native IPv6 GID (e.g. a fabric-rail link-local GID).
	GIDFamilyIPv6 = "ipv6"
	// GIDFamilyUnknown is returned when the GID string cannot be parsed. It is
	// treated as its own family, so an unparseable GID never pairs with a
	// parseable one while two unparseable GIDs still pair (see GIDFamily).
	GIDFamilyUnknown = "unknown"
)

// GIDFamily classifies a textual GID into its address family so the controller
// can skip cross-address-family probe pairs that ibv_create_ah() would reject.
//
// Why parse rather than string-match: GIDs travel in several textual forms. The
// Zig bridge emits the full 8-group hex form (an IPv4-mapped address becomes
// "0000:0000:0000:0000:0000:ffff:c0a8:0101"), while abbreviated inputs and
// tests use "::ffff:a.b.c.d" or "fe80::1". Parsing to the 16-byte form and
// inspecting the IPv4-mapped prefix classifies all of these consistently,
// whereas a SQL/string `LIKE '::ffff:%'` would miss the full-hex form entirely.
//
// Why unparseable is its own family and not force-matched: we cannot know
// whether a probe to an unparseable GID would succeed, so it only ever pairs
// with another equally-unparseable GID. That keeps a parser quirk from silently
// force-pairing (and log-spamming) against the parseable majority, while never
// emitting a pair we already know ibv_create_ah() would reject. In practice all
// production GIDs originate from the Zig bridge's canonical hex form and always
// parse, so this branch is purely defensive.
func GIDFamily(gid string) string {
	parsed, err := ParseGID(gid)
	if err != nil {
		return GIDFamilyUnknown
	}
	if isIPv4MappedGID(parsed) {
		return GIDFamilyIPv4Mapped
	}
	return GIDFamilyIPv6
}
