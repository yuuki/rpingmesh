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

func TestLoadAgentConfig_ZeroProbeInterval(t *testing.T) {
	t.Setenv("RPINGMESH_PROBE_INTERVAL_MS", "0")

	if _, err := LoadAgentConfig("", nil); err == nil {
		t.Fatal("expected an error for probe_interval_ms=0 (would panic time.NewTicker), got nil")
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
			name:    "zero probe interval",
			cfg:     AgentConfig{GIDIndex: 0, ProbeIntervalMS: 0, FlowLabelRotationPeriodSec: 3600},
			wantErr: true,
		},
		{
			name:    "zero flow label rotation period",
			cfg:     AgentConfig{GIDIndex: 0, ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 0},
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
