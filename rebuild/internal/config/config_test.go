package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
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
			name: "non-positive inter-tor sample size",
			cfg: ControllerConfig{
				ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
				ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 0,
			},
			wantErr: true,
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
