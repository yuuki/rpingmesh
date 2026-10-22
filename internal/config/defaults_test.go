package config

import (
	"testing"

	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
)

// TestDefaultsMatchControllerPackages pins the config defaults to the
// fallbacks the controller packages apply when they are handed a non-positive
// value, so the documented default and the effective default cannot drift.
// The constants are duplicated rather than imported because config must not
// depend on the controller packages.
func TestDefaultsMatchControllerPackages(t *testing.T) {
	if DefaultActiveThresholdSec != registry.DefaultActiveThresholdSec {
		t.Errorf("DefaultActiveThresholdSec = %d, registry has %d", DefaultActiveThresholdSec, registry.DefaultActiveThresholdSec)
	}
	if DefaultStaleThresholdSec != registry.DefaultStaleThresholdSec {
		t.Errorf("DefaultStaleThresholdSec = %d, registry has %d", DefaultStaleThresholdSec, registry.DefaultStaleThresholdSec)
	}
	if DefaultInterTorSampleSize != pinglist.DefaultInterTorSampleSize {
		t.Errorf("DefaultInterTorSampleSize = %d, pinglist has %d", DefaultInterTorSampleSize, pinglist.DefaultInterTorSampleSize)
	}
	if DefaultUnspecifiedMeshMaxTargets != pinglist.DefaultUnspecifiedMeshMaxTargets {
		t.Errorf("DefaultUnspecifiedMeshMaxTargets = %d, pinglist has %d", DefaultUnspecifiedMeshMaxTargets, pinglist.DefaultUnspecifiedMeshMaxTargets)
	}
}
