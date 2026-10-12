package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/logging"
)

// writeYAML writes content to a temp file named name inside t.TempDir() and
// returns its path.
func writeYAML(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}
	return path
}

// --- ControllerConfig ---

func TestLoadControllerConfig_Defaults(t *testing.T) {
	cfg, err := LoadControllerConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != ":50051" {
		t.Errorf("ListenAddr = %q, want :50051", cfg.ListenAddr)
	}
	if cfg.DatabaseURI != "http://localhost:4001" {
		t.Errorf("DatabaseURI = %q, want http://localhost:4001", cfg.DatabaseURI)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.ActiveThresholdSec != DefaultActiveThresholdSec {
		t.Errorf("ActiveThresholdSec = %d, want %d", cfg.ActiveThresholdSec, DefaultActiveThresholdSec)
	}
	if cfg.StaleThresholdSec != DefaultStaleThresholdSec {
		t.Errorf("StaleThresholdSec = %d, want %d", cfg.StaleThresholdSec, DefaultStaleThresholdSec)
	}
	if cfg.InterTorSampleSize != DefaultInterTorSampleSize {
		t.Errorf("InterTorSampleSize = %d, want %d", cfg.InterTorSampleSize, DefaultInterTorSampleSize)
	}
	if cfg.UnspecifiedMeshMaxTargets != DefaultUnspecifiedMeshMaxTargets {
		t.Errorf("UnspecifiedMeshMaxTargets = %d, want %d", cfg.UnspecifiedMeshMaxTargets, DefaultUnspecifiedMeshMaxTargets)
	}
	if cfg.TLSMode != TLSModeDisabled {
		t.Errorf("TLSMode = %q, want %q (backward-compatible default)", cfg.TLSMode, TLSModeDisabled)
	}
}

func TestLoadControllerConfig_FileOverridesDefault(t *testing.T) {
	path := writeYAML(t, "controller.yaml", "listen_addr: \":9000\"\n")

	cfg, err := LoadControllerConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":9000" {
		t.Errorf("ListenAddr = %q, want :9000 (from file)", cfg.ListenAddr)
	}
	// Untouched keys still fall back to defaults.
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info (default)", cfg.LogLevel)
	}
}

func TestLoadControllerConfig_ExplicitMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	_, err := LoadControllerConfig(path, nil)
	if err == nil {
		t.Fatal("expected error for missing explicit --config path")
	}
}

func TestLoadControllerConfig_SearchPathMissingOK(t *testing.T) {
	// Empty path uses the search list; a miss is not an error.
	if _, err := LoadControllerConfig("", nil); err != nil {
		t.Fatalf("search-path miss should be OK: %v", err)
	}
}

func TestLoadControllerConfig_EnvOverridesFile(t *testing.T) {
	path := writeYAML(t, "controller.yaml", "listen_addr: \":9000\"\n")
	t.Setenv("RPINGMESH_LISTEN_ADDR", ":9100")

	cfg, err := LoadControllerConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":9100" {
		t.Errorf("ListenAddr = %q, want :9100 (env overrides file)", cfg.ListenAddr)
	}
}

func TestLoadControllerConfig_FlagOverridesEnvAndFile(t *testing.T) {
	path := writeYAML(t, "controller.yaml", "listen_addr: \":9000\"\n")
	t.Setenv("RPINGMESH_LISTEN_ADDR", ":9100")

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindControllerFlags(flags)
	if err := flags.Set("listen-addr", ":9200"); err != nil {
		t.Fatalf("failed to set flag: %v", err)
	}

	cfg, err := LoadControllerConfig(path, flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":9200" {
		t.Errorf("ListenAddr = %q, want :9200 (flag overrides env and file)", cfg.ListenAddr)
	}
}

func TestLoadControllerConfig_UnsetFlagDoesNotOverrideEnv(t *testing.T) {
	t.Setenv("RPINGMESH_LISTEN_ADDR", ":9100")

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindControllerFlags(flags)
	// Do not call flags.Set: the flag keeps its unset default value and
	// must not shadow the environment variable.

	cfg, err := LoadControllerConfig("", flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":9100" {
		t.Errorf("ListenAddr = %q, want :9100 (unset flag must not override env)", cfg.ListenAddr)
	}
}

func TestLoadControllerConfig_OTLPAddrWithSchemeRejected(t *testing.T) {
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_ADDR", "http://collector:4317")

	if _, err := LoadControllerConfig("", nil); err == nil {
		t.Fatal("expected an error for an otel_collector_addr with a URL scheme, got nil")
	}
}

func TestLoadControllerConfig_InvalidLogLevel(t *testing.T) {
	t.Setenv("RPINGMESH_LOG_LEVEL", "not-a-level")

	if _, err := LoadControllerConfig("", nil); err == nil {
		t.Fatal("expected an error for an invalid log_level, got nil")
	}
}

func TestLoadControllerConfig_InvalidDatabaseURI(t *testing.T) {
	t.Setenv("RPINGMESH_DATABASE_URI", "not a url")

	if _, err := LoadControllerConfig("", nil); err == nil {
		t.Fatal("expected an error for an invalid database_uri, got nil")
	}
}

func TestLoadControllerConfig_EmptyListenAddr(t *testing.T) {
	// Note: an empty *environment variable* is treated by viper as unset
	// (see Viper's getEnv, which only honors env vars with a non-empty
	// value unless AllowEmptyEnv is set), so an explicit empty value must
	// come from the config file to exercise this validation path.
	path := writeYAML(t, "controller.yaml", "listen_addr: \"\"\n")

	if _, err := LoadControllerConfig(path, nil); err == nil {
		t.Fatal("expected an error for an empty listen_addr, got nil")
	}
}

func TestControllerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ControllerConfig
		wantErr bool
	}{
		{
			name: "valid",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
			},
			wantErr: false,
		},
		{
			name: "zero ecmp paths assumed",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 0, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
			},
			wantErr: true,
		},
		{
			name: "coverage probability out of range",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 1.0, EcmpMaxFlowLabels: 64,
			},
			wantErr: true,
		},
		{
			name: "zero ecmp max flow labels",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 0,
			},
			wantErr: true,
		},
		{
			// A cap above the 20-bit flow-label space (2^20) could reach a
			// PingTarget and hang the agent's distinct-label generation.
			name: "ecmp max flow labels exceeds 20-bit space",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: MaxEcmpFlowLabels + 1,
			},
			wantErr: true,
		},
		{
			name: "ecmp max flow labels at 20-bit boundary",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: MaxEcmpFlowLabels,
			},
			wantErr: false,
		},
		{
			name: "invalid listen addr",
			cfg: ControllerConfig{
				ListenAddr: "not-a-valid-addr-no-colon", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
			},
			wantErr: true,
		},
		{
			name: "non-positive active threshold",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 0, StaleThresholdSec: 900, InterTorSampleSize: 5,
			},
			wantErr: true,
		},
		{
			name: "non-positive stale threshold",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: -1, InterTorSampleSize: 5,
			},
			wantErr: true,
		},
		{
			name: "stale threshold below active threshold",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 60, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
			},
			wantErr: true,
		},
		{
			name: "stale threshold equals active threshold",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 300, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
			},
			wantErr: false,
		},
		{
			name: "non-positive inter-tor sample size",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 0,
			},
			wantErr: true,
		},
		{
			name: "negative unspecified mesh max",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				UnspecifiedMeshMaxTargets: -1,
				EcmpPathsAssumed:          16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
			},
			wantErr: true,
		},
		{
			name: "zero unspecified mesh max is unlimited",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				UnspecifiedMeshMaxTargets: 0,
				EcmpPathsAssumed:          16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
			},
			wantErr: false,
		},
		{
			name: "tls_mode disabled requires no certificate files",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
				TLSMode: TLSModeDisabled,
			},
			wantErr: false,
		},
		{
			name: "unknown tls_mode is rejected",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
				TLSMode: "bogus",
			},
			wantErr: true,
		},
		{
			name: "tls_mode=tls without server cert/key is rejected",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
				TLSMode: TLSModeTLS,
			},
			wantErr: true,
		},
		{
			name: "tls_mode=mtls without ca/cert/key is rejected",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
				EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
				TLSMode: TLSModeMTLS,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// --- AgentConfig ---

func TestLoadAgentConfig_Defaults(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ControllerAddr != "localhost:50051" {
		t.Errorf("ControllerAddr = %q, want localhost:50051", cfg.ControllerAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.ProbeIntervalMS != 500 {
		t.Errorf("ProbeIntervalMS = %d, want 500", cfg.ProbeIntervalMS)
	}
	if !cfg.MetricsEnabled {
		t.Error("MetricsEnabled = false, want true")
	}
	// The default must be a bare host:port: the OTLP gRPC exporter's
	// WithEndpoint cannot dial a "grpc://" URL.
	if cfg.OtelCollectorAddr != "localhost:4317" {
		t.Errorf("OtelCollectorAddr = %q, want localhost:4317", cfg.OtelCollectorAddr)
	}
	if cfg.TargetProbeRatePerSecond != DefaultTargetProbeRatePerSecond {
		t.Errorf("TargetProbeRatePerSecond = %d, want %d", cfg.TargetProbeRatePerSecond, DefaultTargetProbeRatePerSecond)
	}
	// AgentID and HostName fall back to the OS hostname when unset.
	if cfg.AgentID == "" {
		t.Error("AgentID should fall back to hostname, got empty string")
	}
	if cfg.HostName == "" {
		t.Error("HostName should be auto-detected, got empty string")
	}
	if cfg.TLSMode != TLSModeDisabled {
		t.Errorf("TLSMode = %q, want %q (backward-compatible default)", cfg.TLSMode, TLSModeDisabled)
	}
	// Self-protection is opt-in: disabled by default, with sane threshold
	// defaults so that merely enabling it needs no other settings.
	if cfg.SelfProtectionEnabled != DefaultSelfProtectionEnabled {
		t.Errorf("SelfProtectionEnabled = %v, want %v", cfg.SelfProtectionEnabled, DefaultSelfProtectionEnabled)
	}
	if cfg.WatchdogIntervalSec != DefaultWatchdogIntervalSec {
		t.Errorf("WatchdogIntervalSec = %d, want %d", cfg.WatchdogIntervalSec, DefaultWatchdogIntervalSec)
	}
	if cfg.MaxMemoryMB != 0 {
		t.Errorf("MaxMemoryMB = %d, want 0 (disabled)", cfg.MaxMemoryMB)
	}
	if cfg.MaxProcs != 0 {
		t.Errorf("MaxProcs = %d, want 0 (Go default)", cfg.MaxProcs)
	}
	if cfg.ThrottleMemoryRatio != DefaultThrottleMemoryRatio {
		t.Errorf("ThrottleMemoryRatio = %g, want %g", cfg.ThrottleMemoryRatio, DefaultThrottleMemoryRatio)
	}
	if cfg.ThrottleCPUPercent != DefaultThrottleCPUPercent {
		t.Errorf("ThrottleCPUPercent = %g, want %g", cfg.ThrottleCPUPercent, float64(DefaultThrottleCPUPercent))
	}
}

func TestLoadAgentConfig_ExplicitMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	_, err := LoadAgentConfig(path, nil)
	if err == nil {
		t.Fatal("expected error for missing explicit --config path")
	}
}

// TestEffectiveProbeRates verifies the per-pinglist-type rate resolution,
// including the backward-compatible fallback: when a type-specific rate is 0
// (unset) it inherits the legacy target_probe_rate_per_second.
func TestEffectiveProbeRates(t *testing.T) {
	cases := []struct {
		name         string
		target       int
		torMesh      int
		interTor     int
		wantTorMesh  int
		wantInterTor int
	}{
		{
			name:         "both_unset_falls_back_to_target",
			target:       10,
			torMesh:      0,
			interTor:     0,
			wantTorMesh:  10,
			wantInterTor: 10,
		},
		{
			name:         "differentiated_paper_rates",
			target:       10,
			torMesh:      10,
			interTor:     1,
			wantTorMesh:  10,
			wantInterTor: 1,
		},
		{
			name:         "only_inter_tor_set_tor_mesh_inherits",
			target:       8,
			torMesh:      0,
			interTor:     5,
			wantTorMesh:  8,
			wantInterTor: 5,
		},
		{
			name:         "only_tor_mesh_set_inter_tor_inherits",
			target:       7,
			torMesh:      12,
			interTor:     0,
			wantTorMesh:  12,
			wantInterTor: 7,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &AgentConfig{
				TargetProbeRatePerSecond:   tc.target,
				TorMeshProbeRatePerSecond:  tc.torMesh,
				InterTorProbeRatePerSecond: tc.interTor,
			}
			if got := cfg.EffectiveTorMeshProbeRate(); got != tc.wantTorMesh {
				t.Errorf("EffectiveTorMeshProbeRate() = %d, want %d", got, tc.wantTorMesh)
			}
			if got := cfg.EffectiveInterTorProbeRate(); got != tc.wantInterTor {
				t.Errorf("EffectiveInterTorProbeRate() = %d, want %d", got, tc.wantInterTor)
			}
		})
	}
}

// TestValidate_RejectsNegativePerTypeProbeRates verifies that a negative
// per-type probe rate is rejected (a negative rate would be silently read as
// "disabled" by the limiter, defeating the intended cap).
func TestValidate_RejectsNegativePerTypeProbeRates(t *testing.T) {
	base := func() *AgentConfig {
		return &AgentConfig{
			ProbeIntervalMS:            500,
			FlowLabelRotationPeriodSec: 3600,
			TLSMode:                    TLSModeDisabled,
		}
	}

	neg := base()
	neg.TorMeshProbeRatePerSecond = -1
	if err := neg.Validate(); err == nil {
		t.Error("Validate() accepted negative tor_mesh_probe_rate_per_second, want error")
	}

	neg = base()
	neg.InterTorProbeRatePerSecond = -1
	if err := neg.Validate(); err == nil {
		t.Error("Validate() accepted negative inter_tor_probe_rate_per_second, want error")
	}

	ok := base()
	ok.TorMeshProbeRatePerSecond = 10
	ok.InterTorProbeRatePerSecond = 1
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate() rejected valid per-type rates: %v", err)
	}
}

func TestLoadAgentConfig_FlagOverridesEnvAndFile(t *testing.T) {
	path := writeYAML(t, "agent.yaml", "controller_addr: \"file-addr:1\"\n")
	t.Setenv("RPINGMESH_CONTROLLER_ADDR", "env-addr:2")

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindAgentFlags(flags)
	if err := flags.Set("controller-addr", "flag-addr:3"); err != nil {
		t.Fatalf("failed to set flag: %v", err)
	}

	cfg, err := LoadAgentConfig(path, flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControllerAddr != "flag-addr:3" {
		t.Errorf("ControllerAddr = %q, want flag-addr:3 (flag overrides env and file)", cfg.ControllerAddr)
	}
}

func TestLoadAgentConfig_EnvOverridesFile(t *testing.T) {
	path := writeYAML(t, "agent.yaml", "controller_addr: \"file-addr:1\"\n")
	t.Setenv("RPINGMESH_CONTROLLER_ADDR", "env-addr:2")

	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControllerAddr != "env-addr:2" {
		t.Errorf("ControllerAddr = %q, want env-addr:2 (env overrides file)", cfg.ControllerAddr)
	}
}

func TestLoadAgentConfig_OTLPAddrWithSchemeRejected(t *testing.T) {
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_ADDR", "grpc://collector:4317")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for an otel_collector_addr with a URL scheme, got nil")
	}
}

func TestLoadAgentConfig_NegativeGIDIndex(t *testing.T) {
	t.Setenv("RPINGMESH_GID_INDEX", "-1")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for a negative gid_index, got nil")
	}
}

func TestLoadAgentConfig_GIDIndexExceedsMax(t *testing.T) {
	t.Setenv("RPINGMESH_GID_INDEX", "256")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for gid_index=256 (max is 255), got nil")
	}
}

func TestLoadAgentConfig_GIDIndexAtMax(t *testing.T) {
	t.Setenv("RPINGMESH_GID_INDEX", "255")

	if _, err := LoadAgentConfig("", nil); err != nil {
		t.Fatalf("unexpected error for gid_index=255 (max allowed): %v", err)
	}
}

func TestLoadAgentConfig_ServiceLevelAndTrafficClassDefaults(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServiceLevel != 0 {
		t.Errorf("ServiceLevel = %d, want 0", cfg.ServiceLevel)
	}
	if cfg.TrafficClass != 0 {
		t.Errorf("TrafficClass = %d, want 0", cfg.TrafficClass)
	}
}

func TestLoadAgentConfig_CQPollModeDefaultIsAuto(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CQPollMode != CQPollModeAuto {
		t.Errorf("CQPollMode = %q, want %q", cfg.CQPollMode, CQPollModeAuto)
	}
}

func TestLoadAgentConfig_CQPollModeFromEnv(t *testing.T) {
	for _, mode := range []string{CQPollModeAuto, CQPollModeEvent, CQPollModeBusy} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("RPINGMESH_CQ_POLL_MODE", mode)
			cfg, err := LoadAgentConfig("", nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.CQPollMode != mode {
				t.Errorf("CQPollMode = %q, want %q", cfg.CQPollMode, mode)
			}
		})
	}
}

func TestLoadAgentConfig_InvalidCQPollMode(t *testing.T) {
	t.Setenv("RPINGMESH_CQ_POLL_MODE", "spin")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for cq_poll_mode=spin, got nil")
	}
}

func TestLoadAgentConfig_NegativeServiceLevel(t *testing.T) {
	t.Setenv("RPINGMESH_SERVICE_LEVEL", "-1")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for a negative service_level, got nil")
	}
}

func TestLoadAgentConfig_ServiceLevelExceedsMax(t *testing.T) {
	t.Setenv("RPINGMESH_SERVICE_LEVEL", "8")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for service_level=8 (max is 7), got nil")
	}
}

func TestLoadAgentConfig_NegativeTrafficClass(t *testing.T) {
	t.Setenv("RPINGMESH_TRAFFIC_CLASS", "-1")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for a negative traffic_class, got nil")
	}
}

func TestLoadAgentConfig_TrafficClassExceedsMax(t *testing.T) {
	t.Setenv("RPINGMESH_TRAFFIC_CLASS", "256")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for traffic_class=256 (max is 255), got nil")
	}
}

func TestLoadAgentConfig_ZeroProbeInterval(t *testing.T) {
	t.Setenv("RPINGMESH_PROBE_INTERVAL_MS", "0")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for probe_interval_ms=0 (would panic time.NewTicker), got nil")
	}
}

func TestLoadAgentConfig_MTLSMissingFiles(t *testing.T) {
	t.Setenv("RPINGMESH_TLS_MODE", TLSModeMTLS)

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for tls_mode=mtls with no cert/key/ca configured, got nil")
	}
}

func TestLoadAgentConfig_InvalidTLSMode(t *testing.T) {
	t.Setenv("RPINGMESH_TLS_MODE", "bogus")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for an unknown tls_mode, got nil")
	}
}

func TestAgentConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AgentConfig
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     AgentConfig{GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600},
			wantErr: false,
		},
		{
			name: "reserved tor_id",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TorID: "unspecified",
			},
			wantErr: true,
		},
		{
			name: "reserved tor_id with surrounding whitespace",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TorID: " unspecified ",
			},
			wantErr: true,
		},
		{
			name: "unknown is a valid named ToR",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TorID: "unknown",
			},
			wantErr: false,
		},
		{
			name:    "negative gid index",
			cfg:     AgentConfig{GIDIndex: -1, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600},
			wantErr: true,
		},
		{
			name:    "gid index at max is valid",
			cfg:     AgentConfig{GIDIndex: MaxGIDIndex, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600},
			wantErr: false,
		},
		{
			name:    "gid index exceeds max",
			cfg:     AgentConfig{GIDIndex: MaxGIDIndex + 1, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600},
			wantErr: true,
		},
		{
			name:    "zero probe interval",
			cfg:     AgentConfig{GIDIndex: 0, ProbeIntervalMS: 0, FlowLabelRotationPeriodSec: 3600},
			wantErr: true,
		},
		{
			name:    "zero flow label rotation period",
			cfg:     AgentConfig{GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 0},
			wantErr: true,
		},
		{
			name: "valid service level and traffic class at bounds",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				ServiceLevel: 7, TrafficClass: 255,
			},
			wantErr: false,
		},
		{
			name: "invalid cq poll mode",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				CQPollMode: "spin",
			},
			wantErr: true,
		},
		{
			name: "busy cq poll mode",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				CQPollMode: CQPollModeBusy,
			},
			wantErr: false,
		},
		{
			name: "negative service level",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				ServiceLevel: -1,
			},
			wantErr: true,
		},
		{
			name: "service level exceeds max",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				ServiceLevel: 8,
			},
			wantErr: true,
		},
		{
			name: "negative traffic class",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TrafficClass: -1,
			},
			wantErr: true,
		},
		{
			name: "traffic class exceeds max",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TrafficClass: 256,
			},
			wantErr: true,
		},
		{
			name: "tls_mode disabled requires no certificate files",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TLSMode: TLSModeDisabled,
			},
			wantErr: false,
		},
		{
			name: "unknown tls_mode is rejected",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TLSMode: "bogus",
			},
			wantErr: true,
		},
		{
			name: "tls_mode=tls without ca file is rejected",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TLSMode: TLSModeTLS,
			},
			wantErr: true,
		},
		{
			name: "tls_mode=mtls without ca/cert/key is rejected",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				TLSMode: TLSModeMTLS,
			},
			wantErr: true,
		},
		{
			name: "self-protection enabled with valid thresholds",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: true, WatchdogIntervalSec: 5,
				ThrottleMemoryRatio: 0.9, ThrottleCPUPercent: 90,
			},
			wantErr: false,
		},
		{
			name: "self-protection enabled rejects zero watchdog interval",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: true, WatchdogIntervalSec: 0,
				ThrottleMemoryRatio: 0.9, ThrottleCPUPercent: 90,
			},
			wantErr: true,
		},
		{
			name: "self-protection enabled rejects memory ratio of zero",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: true, WatchdogIntervalSec: 5,
				ThrottleMemoryRatio: 0, ThrottleCPUPercent: 90,
			},
			wantErr: true,
		},
		{
			name: "self-protection enabled rejects memory ratio above one",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: true, WatchdogIntervalSec: 5,
				ThrottleMemoryRatio: 1.5, ThrottleCPUPercent: 90,
			},
			wantErr: true,
		},
		{
			name: "self-protection enabled rejects cpu percent of zero",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: true, WatchdogIntervalSec: 5,
				ThrottleMemoryRatio: 0.9, ThrottleCPUPercent: 0,
			},
			wantErr: true,
		},
		{
			name: "self-protection enabled rejects cpu percent above 100",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: true, WatchdogIntervalSec: 5,
				ThrottleMemoryRatio: 0.9, ThrottleCPUPercent: 101,
			},
			wantErr: true,
		},
		{
			name: "self-protection disabled ignores throttle knobs",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				SelfProtectionEnabled: false, WatchdogIntervalSec: 0,
				ThrottleMemoryRatio: 0, ThrottleCPUPercent: 0,
			},
			wantErr: false,
		},
		{
			name: "negative max_memory_mb rejected regardless of self-protection",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				MaxMemoryMB: -1,
			},
			wantErr: true,
		},
		{
			name: "negative max_procs rejected regardless of self-protection",
			cfg: AgentConfig{
				GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
				MaxProcs: -1,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestAgentConfig_Validate_MTLSWithRealFiles verifies that tls_mode=mtls
// passes Validate() once all three certificate files actually exist on
// disk, using freshly generated test certificates rather than a hard-coded
// stub path (real existence checking is the behavior under test).
func TestAgentConfig_Validate_MTLSWithRealFiles(t *testing.T) {
	certs := newTestCertSet(t)

	cfg := AgentConfig{
		GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600,
		TLSMode:     TLSModeMTLS,
		TLSCertFile: certs.clientCertFile,
		TLSKeyFile:  certs.clientKeyFile,
		TLSCAFile:   certs.caFile,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil when all tls files exist", err)
	}
}

func TestLoadAgentConfig_DeviceTorIDs(t *testing.T) {
	path := writeYAML(t, "agent.yaml", `tor_id: "host-tor"
device_tor_ids:
  mlx5_0: "leaf-a"
  MLX5_1: " leaf-b "
`)
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cases := map[string]string{
		"mlx5_0": "leaf-a",
		"mlx5_1": "leaf-b",   // key case and value whitespace are normalized
		"MLX5_0": "leaf-a",   // device names match case-insensitively
		"mlx5_2": "host-tor", // unlisted devices use tor_id
	}
	for dev, want := range cases {
		if got := cfg.TorIDForDevice(dev); got != want {
			t.Errorf("TorIDForDevice(%q) = %q, want %q", dev, got, want)
		}
	}
}

func TestLoadAgentConfig_DeviceTorIDsDefaultEmpty(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DeviceTorIDs) != 0 {
		t.Errorf("DeviceTorIDs = %v, want empty", cfg.DeviceTorIDs)
	}
	if got := cfg.TorIDForDevice("mlx5_0"); got != "" {
		t.Errorf("TorIDForDevice = %q, want empty (untagged)", got)
	}
}

func TestLoadAgentConfig_DeviceTorIDsRejectsInvalid(t *testing.T) {
	for name, content := range map[string]string{
		"empty value":    "device_tor_ids:\n  mlx5_0: \"  \"\n",
		"reserved value": "device_tor_ids:\n  mlx5_0: \"unspecified\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadAgentConfig(writeYAML(t, "agent.yaml", content), nil); err == nil {
				t.Error("expected a validation error, got nil")
			}
		})
	}
}

func TestLoadAgentConfig_ExcludedDeviceNames(t *testing.T) {
	path := writeYAML(t, "agent.yaml", `excluded_device_names:
  - mlx5_2
  - " MLX5_3 "
`)
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cases := map[string]bool{
		"mlx5_2": true,
		"MLX5_2": true, // device names match case-insensitively
		"mlx5_3": true, // list entries are trimmed and case-folded
		"mlx5_0": false,
		"":       false,
	}
	for dev, want := range cases {
		if got := cfg.IsDeviceExcluded(dev); got != want {
			t.Errorf("IsDeviceExcluded(%q) = %v, want %v", dev, got, want)
		}
	}
}

func TestLoadAgentConfig_ExcludedDeviceNamesDefaultEmpty(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ExcludedDeviceNames) != 0 {
		t.Errorf("ExcludedDeviceNames = %v, want empty", cfg.ExcludedDeviceNames)
	}
	if cfg.IsDeviceExcluded("mlx5_0") {
		t.Error("IsDeviceExcluded should be false with no exclusions")
	}
}

func TestLoadAgentConfig_ExcludedDeviceNamesEnv(t *testing.T) {
	t.Setenv("RPINGMESH_EXCLUDED_DEVICE_NAMES", "mlx5_4 mlx5_5")
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsDeviceExcluded("mlx5_4") || !cfg.IsDeviceExcluded("mlx5_5") {
		t.Errorf("ExcludedDeviceNames = %v, want mlx5_4 and mlx5_5", cfg.ExcludedDeviceNames)
	}
}

func TestLoadAgentConfig_ExcludedDeviceNamesRejectsInvalid(t *testing.T) {
	for name, content := range map[string]string{
		"empty name": "excluded_device_names: [\"  \"]\n",
		"overlap with allowed": "allowed_device_names: [mlx5_0, mlx5_1]\n" +
			"excluded_device_names: [MLX5_1]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadAgentConfig(writeYAML(t, "agent.yaml", content), nil); err == nil {
				t.Error("expected a validation error, got nil")
			}
		})
	}
}

func TestLoadAgentConfig_LLDPDefaults(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LLDPTorDiscovery {
		t.Error("LLDPTorDiscovery should default to false")
	}
	if cfg.LLDPTorIDField != "system_name" || cfg.LLDPCLIPath != "lldpcli" ||
		cfg.LLDPDiscoveryTimeoutSec != DefaultLLDPDiscoveryTimeoutSec {
		t.Errorf("unexpected LLDP defaults: field=%q path=%q timeout=%d",
			cfg.LLDPTorIDField, cfg.LLDPCLIPath, cfg.LLDPDiscoveryTimeoutSec)
	}
}

func TestLoadAgentConfig_LLDPSettings(t *testing.T) {
	path := writeYAML(t, "agent.yaml", `lldp_tor_discovery: true
lldp_tor_id_field: chassis_id
lldpcli_path: /usr/sbin/lldpcli
lldp_discovery_timeout_sec: 0
`)
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.LLDPTorDiscovery || cfg.LLDPTorIDField != "chassis_id" ||
		cfg.LLDPCLIPath != "/usr/sbin/lldpcli" || cfg.LLDPDiscoveryTimeoutSec != 0 {
		t.Errorf("unexpected LLDP settings: %+v", cfg)
	}
	if _, ok := cfg.DeviceTorID("mlx5_0"); ok {
		t.Error("DeviceTorID should report no entry without device_tor_ids")
	}
}

func TestLoadAgentConfig_LLDPFieldRejectsInvalid(t *testing.T) {
	path := writeYAML(t, "agent.yaml", "lldp_tor_id_field: port_id\n")
	if _, err := LoadAgentConfig(path, nil); err == nil {
		t.Error("expected a validation error, got nil")
	}
}

// --- log_format ---

func TestLoadConfig_LogFormatDefaultIsConsole(t *testing.T) {
	agentCfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if agentCfg.LogFormat != logging.FormatConsole {
		t.Errorf("agent LogFormat = %q, want %q", agentCfg.LogFormat, logging.FormatConsole)
	}
	ctrlCfg, err := LoadControllerConfig("", nil)
	if err != nil {
		t.Fatalf("LoadControllerConfig: %v", err)
	}
	if ctrlCfg.LogFormat != logging.FormatConsole {
		t.Errorf("controller LogFormat = %q, want %q", ctrlCfg.LogFormat, logging.FormatConsole)
	}
}

// TestLoadConfig_LogFormatPrecedence checks flag > env > YAML > default for
// log_format on both binaries.
func TestLoadConfig_LogFormatPrecedence(t *testing.T) {
	type loader func(path string, flags *pflag.FlagSet) (string, error)
	loaders := map[string]struct {
		bind func(*pflag.FlagSet)
		load loader
	}{
		"agent": {BindAgentFlags, func(p string, f *pflag.FlagSet) (string, error) {
			c, err := LoadAgentConfig(p, f)
			if err != nil {
				return "", err
			}
			return c.LogFormat, nil
		}},
		"controller": {BindControllerFlags, func(p string, f *pflag.FlagSet) (string, error) {
			c, err := LoadControllerConfig(p, f)
			if err != nil {
				return "", err
			}
			return c.LogFormat, nil
		}},
	}
	for name, l := range loaders {
		t.Run(name, func(t *testing.T) {
			path := writeYAML(t, "cfg.yaml", "log_format: json\n")
			if got, err := l.load(path, nil); err != nil || got != "json" {
				t.Fatalf("YAML: got %q, %v; want json", got, err)
			}

			t.Setenv("RPINGMESH_LOG_FORMAT", "console")
			if got, err := l.load(path, nil); err != nil || got != "console" {
				t.Fatalf("env over YAML: got %q, %v; want console", got, err)
			}

			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			l.bind(flags)
			if got, err := l.load(path, flags); err != nil || got != "console" {
				t.Fatalf("unset flag must not override env: got %q, %v", got, err)
			}
			if err := flags.Set("log-format", "json"); err != nil {
				t.Fatalf("flags.Set: %v", err)
			}
			if got, err := l.load(path, flags); err != nil || got != "json" {
				t.Fatalf("flag over env: got %q, %v; want json", got, err)
			}
		})
	}
}

func TestLoadConfig_LogFormatRejectsInvalid(t *testing.T) {
	t.Setenv("RPINGMESH_LOG_FORMAT", "logfmt")
	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Error("LoadAgentConfig: expected an error for log_format=logfmt, got nil")
	}
	if _, err := LoadControllerConfig("", nil); err == nil {
		t.Error("LoadControllerConfig: expected an error for log_format=logfmt, got nil")
	}
}

// --- plane_id / device_plane_ids ---

func TestLoadAgentConfig_PlaneDefaultsEmpty(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PlaneID != "" || len(cfg.DevicePlaneIDs) != 0 {
		t.Errorf("PlaneID = %q, DevicePlaneIDs = %v; want empty", cfg.PlaneID, cfg.DevicePlaneIDs)
	}
	if got := cfg.PlaneIDForDevice("mlx5_0"); got != "" {
		t.Errorf("PlaneIDForDevice = %q, want empty (no plane restriction)", got)
	}
}

func TestLoadAgentConfig_DevicePlaneIDs(t *testing.T) {
	path := writeYAML(t, "agent.yaml", `plane_id: " host-plane "
device_plane_ids:
  mlx5_0: "rail0"
  MLX5_1: " rail1 "
`)
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PlaneID != "host-plane" {
		t.Errorf("PlaneID = %q, want host-plane (trimmed)", cfg.PlaneID)
	}
	cases := map[string]string{
		"mlx5_0": "rail0",
		"mlx5_1": "rail1",      // key case and value whitespace are normalized
		"MLX5_0": "rail0",      // device names match case-insensitively
		"mlx5_2": "host-plane", // unlisted devices use plane_id
	}
	for dev, want := range cases {
		if got := cfg.PlaneIDForDevice(dev); got != want {
			t.Errorf("PlaneIDForDevice(%q) = %q, want %q", dev, got, want)
		}
	}
}

func TestLoadAgentConfig_PlaneIDPrecedence(t *testing.T) {
	path := writeYAML(t, "agent.yaml", "plane_id: file-plane\n")
	t.Setenv("RPINGMESH_PLANE_ID", "env-plane")

	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PlaneID != "env-plane" {
		t.Errorf("PlaneID = %q, want env-plane (env overrides file)", cfg.PlaneID)
	}

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindAgentFlags(flags)
	if err := flags.Set("plane-id", "flag-plane"); err != nil {
		t.Fatalf("flags.Set: %v", err)
	}
	cfg, err = LoadAgentConfig(path, flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PlaneID != "flag-plane" {
		t.Errorf("PlaneID = %q, want flag-plane (flag overrides env)", cfg.PlaneID)
	}
}

func TestLoadAgentConfig_DevicePlaneIDsRejectsInvalid(t *testing.T) {
	if _, err := LoadAgentConfig(writeYAML(t, "agent.yaml", "device_plane_ids:\n  mlx5_0: \"  \"\n"), nil); err == nil {
		t.Error("expected a validation error for an empty device_plane_ids value, got nil")
	}
	cfg := &AgentConfig{
		ProbeIntervalMS:            1,
		FlowLabelRotationPeriodSec: 1,
		DevicePlaneIDs:             map[string]string{" ": "rail0"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected a validation error for an empty device_plane_ids key, got nil")
	}
}

// TestLoadAgentConfig_DevicePlaneIDsToleratesExcludedDevices checks that a
// fleet-wide device_plane_ids map naming a device this host excludes (or does
// not allow) still loads; the agent only warns about such entries.
func TestLoadAgentConfig_DevicePlaneIDsToleratesExcludedDevices(t *testing.T) {
	path := writeYAML(t, "agent.yaml", `allowed_device_names: [mlx5_0]
excluded_device_names: [mlx5_1]
device_plane_ids:
  mlx5_0: rail0
  mlx5_1: rail1
  mlx5_2: rail2
`)
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsDeviceAllowed("MLX5_0") || cfg.IsDeviceAllowed("mlx5_2") {
		t.Errorf("IsDeviceAllowed: mlx5_0=%v mlx5_2=%v, want true/false",
			cfg.IsDeviceAllowed("MLX5_0"), cfg.IsDeviceAllowed("mlx5_2"))
	}
	if !(&AgentConfig{}).IsDeviceAllowed("anything") {
		t.Error("IsDeviceAllowed with no allowed_device_names should be true")
	}
}
