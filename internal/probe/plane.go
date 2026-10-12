package probe

import "strings"

// CanonicalPlaneID trims surrounding whitespace from a network plane (rail)
// identifier. A whitespace-only value is treated as unset (empty string),
// which means "plane unknown": such RNICs are paired without any plane
// restriction, as before plane support existed.
func CanonicalPlaneID(planeID string) string {
	return strings.TrimSpace(planeID)
}
