package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/controller"
	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
)

// localizationTestConfig is a controller configuration with the analyzer
// and fault localization on, and no metrics export.
func localizationTestConfig() *config.ControllerConfig {
	return &config.ControllerConfig{
		AnalyzerEnabled:                       true,
		AnalyzerWindowRetention:               config.DefaultAnalyzerWindowRetention,
		AnalyzerLocalizationEnabled:           true,
		AnalyzerLocalizationWindows:           config.DefaultAnalyzerLocalizationWindows,
		AnalyzerLocalizationBaselineLossRatio: config.DefaultAnalyzerLocalizationBaselineLossRatio,
		AnalyzerLocalizationMinConfidence:     config.DefaultAnalyzerLocalizationMinConfidence,
		AnalyzerLocalizationMaxPathsPerWindow: config.DefaultAnalyzerLocalizationMaxPathsPerWindow,
	}
}

func testControllerService() *controller.ControllerService {
	return controller.NewControllerService(nil, pinglist.ECMPConfig{
		PathsAssumed:        config.DefaultEcmpPathsAssumed,
		CoverageProbability: config.DefaultEcmpCoverageProbability,
		MaxFlowLabels:       config.DefaultEcmpMaxFlowLabels,
	}, config.DefaultInterTorSampleSize, config.DefaultUnspecifiedMeshMaxTargets)
}

// TestLocalizationConfig verifies how the controller configuration becomes
// the analyzer's localization settings: nil when disabled, no topology
// without a file, and the parsed topology with one.
func TestLocalizationConfig(t *testing.T) {
	cfg := localizationTestConfig()
	cfg.AnalyzerLocalizationEnabled = false
	loc, err := localizationConfig(cfg)
	if err != nil || loc != nil {
		t.Fatalf("disabled: got %+v, %v; want nil, nil", loc, err)
	}

	cfg = localizationTestConfig()
	cfg.AnalyzerLocalizationWindows = 8
	cfg.AnalyzerLocalizationBaselineLossRatio = 0.0005
	cfg.AnalyzerLocalizationMinConfidence = 0.99
	cfg.AnalyzerLocalizationMaxPathsPerWindow = 1234
	loc, err = localizationConfig(cfg)
	if err != nil {
		t.Fatalf("without a topology file: %v", err)
	}
	if loc.Topology != nil {
		t.Error("Topology is set without a topology file")
	}
	if loc.Windows != 8 || loc.BaselineLossRatio != 0.0005 || loc.MinConfidence != 0.99 || loc.MaxPathsPerWindow != 1234 {
		t.Errorf("settings = %+v, want those of the configuration", loc)
	}

	path := filepath.Join(t.TempDir(), "topology.yaml")
	topology := "version: 1\ntors:\n  leaf-a: {rail: rail0, spine_group: pod-a}\n  leaf-b: {rail: rail0, spine_group: pod-a}\n"
	if err := os.WriteFile(path, []byte(topology), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.AnalyzerLocalizationTopologyFile = path
	loc, err = localizationConfig(cfg)
	if err != nil {
		t.Fatalf("with a topology file: %v", err)
	}
	if loc.Topology.Tors() != 2 || loc.Topology.SpineGroups() != 1 || loc.Topology.Rails() != 1 {
		t.Errorf("topology = %d ToRs, %d spine groups, %d rails; want 2, 1, 1",
			loc.Topology.Tors(), loc.Topology.SpineGroups(), loc.Topology.Rails())
	}
}

// TestSetupAnalyzer_InvalidTopologyFileFails verifies that the controller
// refuses to start on a topology file it cannot interpret in full, and that
// the error names the configuration key and the file.
func TestSetupAnalyzer_InvalidTopologyFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ntors: {leaf-a: {rial: rail0}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := localizationTestConfig()
	cfg.AnalyzerLocalizationTopologyFile = path

	az, provider, err := setupAnalyzer(cfg, testControllerService())
	if err == nil {
		t.Fatal("setupAnalyzer accepted an invalid topology file")
	}
	if az != nil || provider != nil {
		t.Error("setupAnalyzer returned an analyzer or a provider with an error")
	}
	for _, want := range []string{"analyzer_localization_topology_file", path, `unknown key "rial"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// TestSetupAnalyzer_LocalizationRunsAndStops verifies that the analyzer
// built with localization on has a localization loop that stops with its
// context, and that the one built without returns at once.
func TestSetupAnalyzer_LocalizationRunsAndStops(t *testing.T) {
	cfg := localizationTestConfig()
	az, _, err := setupAnalyzer(cfg, testControllerService())
	if err != nil || az == nil {
		t.Fatalf("setupAnalyzer: %v, %v", az, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		az.RunLocalization(ctx)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("RunLocalization returned before its context was cancelled")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunLocalization did not stop when its context was cancelled")
	}

	cfg.AnalyzerLocalizationEnabled = false
	az, _, err = setupAnalyzer(cfg, testControllerService())
	if err != nil || az == nil {
		t.Fatalf("setupAnalyzer without localization: %v, %v", az, err)
	}
	returned := make(chan struct{})
	go func() {
		az.RunLocalization(context.Background())
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("RunLocalization did not return at once with localization disabled")
	}

	// A disabled analyzer is no analyzer at all.
	cfg.AnalyzerEnabled = false
	az, provider, err := setupAnalyzer(cfg, testControllerService())
	if az != nil || provider != nil || err != nil {
		t.Errorf("analyzer disabled: got %v, %v, %v; want nil, nil, nil", az, provider, err)
	}
}
