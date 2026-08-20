package probe

import "strings"

// UnspecifiedTorLabel is the OTel / PathSummary display value for an unset
// ToR ID. It is reserved: agents must not register it as a real tor_id, so
// untagged metrics cannot collide with a named ToR.
const UnspecifiedTorLabel = "unspecified"

// CanonicalTorID trims surrounding whitespace from a ToR identifier. A
// whitespace-only value is treated as unset (empty string), which is the
// registry storage key for untagged agents.
func CanonicalTorID(torID string) string {
	return strings.TrimSpace(torID)
}

// TorMetricLabel returns the low-cardinality ToR label used on OTel metrics
// and PathSummary fields. Unset (empty or whitespace-only) IDs map to
// UnspecifiedTorLabel so Prometheus/Grafana see a nonempty series key.
func TorMetricLabel(torID string) string {
	if id := CanonicalTorID(torID); id != "" {
		return id
	}
	return UnspecifiedTorLabel
}

// IsReservedTorID reports whether torID, after canonicalization, equals the
// display label reserved for unset ToRs.
func IsReservedTorID(torID string) bool {
	return CanonicalTorID(torID) == UnspecifiedTorLabel
}
