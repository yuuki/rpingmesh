package config

import (
	"testing"

	"github.com/yuuki/rpingmesh/internal/controller/analyzer"
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
	if DefaultAnalyzerLocalizationWindows != analyzer.DefaultLocalizationWindows {
		t.Errorf("DefaultAnalyzerLocalizationWindows = %d, analyzer has %d", DefaultAnalyzerLocalizationWindows, analyzer.DefaultLocalizationWindows)
	}
	if MaxAnalyzerLocalizationWindows != analyzer.MaxLocalizationWindows {
		t.Errorf("MaxAnalyzerLocalizationWindows = %d, analyzer has %d", MaxAnalyzerLocalizationWindows, analyzer.MaxLocalizationWindows)
	}
	if DefaultAnalyzerLocalizationBaselineLossRatio != analyzer.DefaultLocalizationBaselineLossRatio {
		t.Errorf("DefaultAnalyzerLocalizationBaselineLossRatio = %v, analyzer has %v", DefaultAnalyzerLocalizationBaselineLossRatio, analyzer.DefaultLocalizationBaselineLossRatio)
	}
	if DefaultAnalyzerLocalizationMinConfidence != analyzer.DefaultLocalizationMinConfidence {
		t.Errorf("DefaultAnalyzerLocalizationMinConfidence = %v, analyzer has %v", DefaultAnalyzerLocalizationMinConfidence, analyzer.DefaultLocalizationMinConfidence)
	}
	if DefaultAnalyzerLocalizationMaxPathsPerWindow != analyzer.DefaultLocalizationMaxPathsPerWindow {
		t.Errorf("DefaultAnalyzerLocalizationMaxPathsPerWindow = %d, analyzer has %d", DefaultAnalyzerLocalizationMaxPathsPerWindow, analyzer.DefaultLocalizationMaxPathsPerWindow)
	}
}
