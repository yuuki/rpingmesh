package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/logging"
	"github.com/yuuki/rpingmesh/internal/testutil/tlscerts"
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

// validControllerConfig is the smallest ControllerConfig literal that passes
// Validate; Validate tables mutate one field of it per case.
func validControllerConfig() ControllerConfig {
	return ControllerConfig{
		ListenAddr: ":50051", DatabaseURI: "http://localhost:4001", LogLevel: "info",
		ActiveThresholdSec: 300, StaleThresholdSec: 900, InterTorSampleSize: 5,
		EcmpPathsAssumed: 16, EcmpCoverageProbability: 0.9, EcmpMaxFlowLabels: 64,
	}
}

// validAgentConfig is the smallest AgentConfig literal that passes Validate
// (the zero value fails only on the two fields that must be positive).
func validAgentConfig() AgentConfig {
	return AgentConfig{ProbeIntervalMS: 500, FlowLabelRotationPeriodSec: 3600}
}

// checkErr asserts that err is nil when want is empty and otherwise contains
// want, so a table case pins which validation rule fired first.
func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Errorf("unexpected error: %v", err)
	case want != "" && err == nil:
		t.Errorf("got nil error, want one containing %q", want)
	case want != "" && !strings.Contains(err.Error(), want):
		t.Errorf("error %q does not contain %q", err, want)
	}
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
	if cfg.LogFormat != logging.FormatConsole {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, logging.FormatConsole)
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
	if cfg.AnalyzerSLANetworkRTTP99Ns != DefaultAnalyzerSLANetworkRTTP99Ns {
		t.Errorf("AnalyzerSLANetworkRTTP99Ns = %d, want %d", cfg.AnalyzerSLANetworkRTTP99Ns, DefaultAnalyzerSLANetworkRTTP99Ns)
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
	if _, err := LoadControllerConfig(path, nil); err == nil {
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

// TestLoadControllerConfig_EnvValidation feeds single RPINGMESH_* values
// through the whole load path (env parsing, struct assembly, Validate).
func TestLoadControllerConfig_EnvValidation(t *testing.T) {
	for _, tc := range []struct {
		env, value string
		wantErr    string
	}{
		{"RPINGMESH_OTEL_COLLECTOR_ADDR", "http://collector:4317", "otel_collector_addr"},
		{"RPINGMESH_LOG_LEVEL", "not-a-level", "log_level"},
		{"RPINGMESH_LOG_FORMAT", "logfmt", "log_format"},
		{"RPINGMESH_DATABASE_URI", "not a url", "database_uri"},
		{"RPINGMESH_ECMP_MAX_FLOW_LABELS", "4096", ""},
	} {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)
			_, err := LoadControllerConfig("", nil)
			checkErr(t, err, tc.wantErr)
		})
	}
}

func TestLoadControllerConfig_EmptyListenAddr(t *testing.T) {
	// Note: an empty *environment variable* is treated by viper as unset
	// (see Viper's getEnv, which only honors env vars with a non-empty
	// value unless AllowEmptyEnv is set), so an explicit empty value must
	// come from the config file to exercise this validation path.
	path := writeYAML(t, "controller.yaml", "listen_addr: \"\"\n")

	_, err := LoadControllerConfig(path, nil)
	checkErr(t, err, "listen_addr must not be empty")
}

func TestControllerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *ControllerConfig)
		wantErr string
	}{
		{"valid", func(c *ControllerConfig) {}, ""},
		{"empty listen addr", func(c *ControllerConfig) { c.ListenAddr = " " }, "listen_addr must not be empty"},
		{"invalid listen addr", func(c *ControllerConfig) { c.ListenAddr = "not-a-valid-addr-no-colon" }, "listen_addr"},
		{"empty database uri", func(c *ControllerConfig) { c.DatabaseURI = "" }, "database_uri must not be empty"},
		{"database uri without scheme", func(c *ControllerConfig) { c.DatabaseURI = "localhost:4001" }, "database_uri"},
		{"zero database connect timeout disables retries", func(c *ControllerConfig) { c.DatabaseConnectTimeoutSec = 0 }, ""},
		{"negative database connect timeout", func(c *ControllerConfig) { c.DatabaseConnectTimeoutSec = -1 }, "database_connect_timeout_sec"},
		{"unknown log level", func(c *ControllerConfig) { c.LogLevel = "loud" }, "log_level"},
		{"unknown log format", func(c *ControllerConfig) { c.LogFormat = "logfmt" }, "log_format"},
		{"non-positive active threshold", func(c *ControllerConfig) { c.ActiveThresholdSec = 0 }, "active_threshold_sec"},
		{"non-positive stale threshold", func(c *ControllerConfig) { c.StaleThresholdSec = -1 }, "stale_threshold_sec must be > 0"},
		{"stale threshold below active threshold", func(c *ControllerConfig) { c.StaleThresholdSec = 60 }, "must be >= active_threshold_sec"},
		{"stale threshold equals active threshold", func(c *ControllerConfig) { c.StaleThresholdSec = 300 }, ""},
		{"non-positive inter-tor sample size", func(c *ControllerConfig) { c.InterTorSampleSize = 0 }, "inter_tor_sample_size"},
		{"negative unspecified mesh max", func(c *ControllerConfig) { c.UnspecifiedMeshMaxTargets = -1 }, "unspecified_mesh_max_targets"},
		{"zero unspecified mesh max is unlimited", func(c *ControllerConfig) { c.UnspecifiedMeshMaxTargets = 0 }, ""},
		{"zero ecmp paths assumed", func(c *ControllerConfig) { c.EcmpPathsAssumed = 0 }, "ecmp_paths_assumed"},
		{"coverage probability out of range", func(c *ControllerConfig) { c.EcmpCoverageProbability = 1.0 }, "ecmp_coverage_probability"},
		{"zero ecmp max flow labels", func(c *ControllerConfig) { c.EcmpMaxFlowLabels = 0 }, "ecmp_max_flow_labels must be >= 1"},
		{
			// A cap above the operational ceiling could reach a PingTarget
			// and stall the agent's distinct-label generation.
			"ecmp max flow labels exceeds ceiling",
			func(c *ControllerConfig) { c.EcmpMaxFlowLabels = MaxEcmpFlowLabels + 1 },
			"ecmp_max_flow_labels must be <=",
		},
		{"ecmp max flow labels at ceiling", func(c *ControllerConfig) { c.EcmpMaxFlowLabels = MaxEcmpFlowLabels }, ""},
		{
			"analyzer enabled rejects loss ratio above one",
			func(c *ControllerConfig) {
				c.AnalyzerEnabled = true
				c.AnalyzerSLALossRatio = 1.5
				c.AnalyzerWindowRetention = 20
			},
			"analyzer_sla_loss_ratio",
		},
		{
			"analyzer enabled rejects zero window retention",
			func(c *ControllerConfig) { c.AnalyzerEnabled = true; c.AnalyzerSLALossRatio = 0.02 },
			"analyzer_window_retention",
		},
		{
			"analyzer disabled ignores its thresholds",
			func(c *ControllerConfig) { c.AnalyzerEnabled = false; c.AnalyzerSLALossRatio = -1 },
			"",
		},
		{"otel collector addr with scheme", func(c *ControllerConfig) { c.OtelCollectorAddr = "grpc://collector:4317" }, "otel_collector_addr"},
		{"tls_mode disabled requires no certificate files", func(c *ControllerConfig) { c.TLSMode = TLSModeDisabled }, ""},
		{"unknown tls_mode is rejected", func(c *ControllerConfig) { c.TLSMode = "bogus" }, "tls_mode must be one of"},
		{"tls_mode=tls without server cert/key is rejected", func(c *ControllerConfig) { c.TLSMode = TLSModeTLS }, "tls_cert_file is required"},
		{"tls_mode=mtls without ca/cert/key is rejected", func(c *ControllerConfig) { c.TLSMode = TLSModeMTLS }, "tls_ca_file is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validControllerConfig()
			tc.mutate(&cfg)
			checkErr(t, cfg.Validate(), tc.wantErr)
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
	if cfg.LogFormat != logging.FormatConsole {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, logging.FormatConsole)
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
	if cfg.ServiceLevel != 0 || cfg.TrafficClass != 0 || cfg.GIDIndex != 0 {
		t.Errorf("ServiceLevel/TrafficClass/GIDIndex = %d/%d/%d, want 0/0/0", cfg.ServiceLevel, cfg.TrafficClass, cfg.GIDIndex)
	}
	if cfg.CQPollMode != CQPollModeAuto {
		t.Errorf("CQPollMode = %q, want %q", cfg.CQPollMode, CQPollModeAuto)
	}
	if cfg.EventRingCapacity != DefaultEventRingCapacity {
		t.Errorf("EventRingCapacity = %d, want %d", cfg.EventRingCapacity, DefaultEventRingCapacity)
	}

	// Metrics labels default to the ToR-level-only shape (see CLAUDE.md on
	// attribute cardinality).
	if cfg.MetricsTargetRnicLabels != MetricsTargetRnicLabelsOff {
		t.Errorf("MetricsTargetRnicLabels = %q, want %q", cfg.MetricsTargetRnicLabels, MetricsTargetRnicLabelsOff)
	}
	if cfg.MetricsTargetRnicLabelsScope != MetricsTargetRnicLabelsScopeStable {
		t.Errorf("MetricsTargetRnicLabelsScope = %q, want %q",
			cfg.MetricsTargetRnicLabelsScope, MetricsTargetRnicLabelsScopeStable)
	}
	if cfg.MetricsCardinalityLimit != 0 {
		t.Errorf("MetricsCardinalityLimit = %d, want 0", cfg.MetricsCardinalityLimit)
	}
	if cfg.MetricsProberDelayTargetTor {
		t.Error("MetricsProberDelayTargetTor = true, want false")
	}
	if !cfg.MetricsResponderDelayTargetTor {
		t.Error("MetricsResponderDelayTargetTor = false, want true")
	}

	// Device selection and topology default to "every device, untagged".
	if len(cfg.DeviceTorIDs) != 0 || len(cfg.DevicePlaneIDs) != 0 || len(cfg.ExcludedDeviceNames) != 0 {
		t.Errorf("DeviceTorIDs=%v DevicePlaneIDs=%v ExcludedDeviceNames=%v, want all empty",
			cfg.DeviceTorIDs, cfg.DevicePlaneIDs, cfg.ExcludedDeviceNames)
	}
	if got := cfg.TorIDForDevice("mlx5_0"); got != "" {
		t.Errorf("TorIDForDevice = %q, want empty (untagged)", got)
	}
	if cfg.PlaneID != "" || cfg.PlaneIDForDevice("mlx5_0") != "" {
		t.Errorf("PlaneID = %q, PlaneIDForDevice = %q; want empty (no plane restriction)", cfg.PlaneID, cfg.PlaneIDForDevice("mlx5_0"))
	}
	if cfg.IsDeviceExcluded("mlx5_0") {
		t.Error("IsDeviceExcluded should be false with no exclusions")
	}
	if cfg.MappedDevicesOnly {
		t.Error("MappedDevicesOnly should default to false")
	}
	if cfg.LLDPTorDiscovery {
		t.Error("LLDPTorDiscovery should default to false")
	}
	if cfg.LLDPTorIDField != "system_name" || cfg.LLDPCLIPath != "lldpcli" ||
		cfg.LLDPDiscoveryTimeoutSec != DefaultLLDPDiscoveryTimeoutSec {
		t.Errorf("unexpected LLDP defaults: field=%q path=%q timeout=%d",
			cfg.LLDPTorIDField, cfg.LLDPCLIPath, cfg.LLDPDiscoveryTimeoutSec)
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
	if _, err := LoadAgentConfig(path, nil); err == nil {
		t.Fatal("expected error for missing explicit --config path")
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

// TestLoadAgentConfig_EnvValidation feeds single RPINGMESH_* values through
// the whole load path (env parsing, struct assembly, Validate). Boundary
// values that must be accepted sit next to the values just past them.
func TestLoadAgentConfig_EnvValidation(t *testing.T) {
	for _, tc := range []struct {
		env, value string
		wantErr    string
	}{
		{"RPINGMESH_OTEL_COLLECTOR_ADDR", "grpc://collector:4317", "otel_collector_addr"},
		{"RPINGMESH_LOG_FORMAT", "logfmt", "log_format"},
		{"RPINGMESH_GID_INDEX", "-1", "gid_index"},
		{"RPINGMESH_GID_INDEX", "255", ""},
		{"RPINGMESH_GID_INDEX", "256", "gid_index"},
		{"RPINGMESH_SERVICE_LEVEL", "-1", "service_level"},
		{"RPINGMESH_SERVICE_LEVEL", "8", "service_level"},
		{"RPINGMESH_TRAFFIC_CLASS", "-1", "traffic_class"},
		{"RPINGMESH_TRAFFIC_CLASS", "256", "traffic_class"},
		{"RPINGMESH_CQ_POLL_MODE", "spin", "cq_poll_mode"},
		{"RPINGMESH_EVENT_RING_CAPACITY", "8192", ""},
		{"RPINGMESH_EVENT_RING_CAPACITY", "3000", "event_ring_capacity"},
		{"RPINGMESH_METRICS_TARGET_RNIC_LABELS", "histograms", "metrics_target_rnic_labels"},
		{"RPINGMESH_METRICS_TARGET_RNIC_LABELS_SCOPE", "inter_tor", "metrics_target_rnic_labels_scope"},
		// A limit below the SDK default would also cap the default
		// instruments; only 0 or a raised limit is accepted.
		{"RPINGMESH_METRICS_CARDINALITY_LIMIT", "-1", "metrics_cardinality_limit"},
		{"RPINGMESH_METRICS_CARDINALITY_LIMIT", "1", "metrics_cardinality_limit"},
		{"RPINGMESH_METRICS_CARDINALITY_LIMIT", "1999", "metrics_cardinality_limit"},
		{"RPINGMESH_METRICS_CARDINALITY_LIMIT", "2000", ""},
		// probe_interval_ms=0 would panic time.NewTicker.
		{"RPINGMESH_PROBE_INTERVAL_MS", "0", "probe_interval_ms"},
		{"RPINGMESH_TLS_MODE", TLSModeMTLS, "tls_ca_file is required"},
		{"RPINGMESH_TLS_MODE", "bogus", "tls_mode must be one of"},
	} {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)
			_, err := LoadAgentConfig("", nil)
			checkErr(t, err, tc.wantErr)
		})
	}
}

// TestLoadAgentConfig_YAMLValidation covers rules on list and map keys,
// which environment variables cannot express.
func TestLoadAgentConfig_YAMLValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml, wantErr string
	}{
		"device_tor_ids empty value":    {"device_tor_ids:\n  mlx5_0: \"  \"\n", "device_tor_ids[mlx5_0] must not be empty"},
		"device_tor_ids reserved value": {"device_tor_ids:\n  mlx5_0: \"unspecified\"\n", "is reserved for untagged agents"},
		"device_plane_ids empty value":  {"device_plane_ids:\n  mlx5_0: \"  \"\n", "device_plane_ids[mlx5_0] must not be empty"},
		"excluded_device_names empty":   {"excluded_device_names: [\"  \"]\n", "excluded_device_names has an empty device name"},
		"device both allowed and excluded": {
			"allowed_device_names: [mlx5_0, mlx5_1]\nexcluded_device_names: [MLX5_1]\n",
			"listed in both allowed_device_names and excluded_device_names",
		},
		"excluded_gid_cidrs bare address": {"excluded_gid_cidrs: [10.0.0.1]\n", "excluded_gid_cidrs"},
		"excluded_gid_cidrs garbage":      {"excluded_gid_cidrs: [mgmt]\n", "excluded_gid_cidrs"},
		"mapped_devices_only without map": {"mapped_devices_only: true\n", "mapped_devices_only requires"},
		"lldp_tor_id_field unknown":       {"lldp_tor_id_field: port_id\n", "lldp_tor_id_field"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadAgentConfig(writeYAML(t, "agent.yaml", tc.yaml), nil)
			checkErr(t, err, tc.wantErr)
		})
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

func TestLoadAgentConfig_MetricsTargetRnicLabelsFromEnv(t *testing.T) {
	t.Setenv("RPINGMESH_METRICS_TARGET_RNIC_LABELS", MetricsTargetRnicLabelsAll)
	t.Setenv("RPINGMESH_METRICS_TARGET_RNIC_LABELS_SCOPE", MetricsTargetRnicLabelsScopeAll)
	t.Setenv("RPINGMESH_METRICS_CARDINALITY_LIMIT", "10000")
	t.Setenv("RPINGMESH_METRICS_PROBER_DELAY_TARGET_TOR", "true")
	t.Setenv("RPINGMESH_METRICS_RESPONDER_DELAY_TARGET_TOR", "false")

	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MetricsTargetRnicLabels != MetricsTargetRnicLabelsAll {
		t.Errorf("MetricsTargetRnicLabels = %q, want %q", cfg.MetricsTargetRnicLabels, MetricsTargetRnicLabelsAll)
	}
	if cfg.MetricsTargetRnicLabelsScope != MetricsTargetRnicLabelsScopeAll {
		t.Errorf("MetricsTargetRnicLabelsScope = %q, want %q",
			cfg.MetricsTargetRnicLabelsScope, MetricsTargetRnicLabelsScopeAll)
	}
	if cfg.MetricsCardinalityLimit != 10000 {
		t.Errorf("MetricsCardinalityLimit = %d, want 10000", cfg.MetricsCardinalityLimit)
	}
	if !cfg.MetricsProberDelayTargetTor {
		t.Error("MetricsProberDelayTargetTor = false, want true")
	}
	if cfg.MetricsResponderDelayTargetTor {
		t.Error("MetricsResponderDelayTargetTor = true, want false")
	}
}

func TestLoadAgentConfig_EventRingCapacityFromEnv(t *testing.T) {
	t.Setenv("RPINGMESH_EVENT_RING_CAPACITY", "8192")
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.EffectiveEventRingCapacity(); got != 8192 {
		t.Errorf("EffectiveEventRingCapacity = %d, want 8192", got)
	}
	if got := (&AgentConfig{}).EffectiveEventRingCapacity(); got != DefaultEventRingCapacity {
		t.Errorf("EffectiveEventRingCapacity of a zero value = %d, want %d", got, DefaultEventRingCapacity)
	}
}

// TestEffectiveProbeRates verifies the per-pinglist-type rate resolution,
// including the backward-compatible fallback: when a type-specific rate is 0
// (unset) it inherits the legacy target_probe_rate_per_second.
func TestEffectiveProbeRates(t *testing.T) {
	cases := []struct {
		name                      string
		target, torMesh, interTor int
		wantTorMesh, wantInterTor int
	}{
		{"both_unset_falls_back_to_target", 10, 0, 0, 10, 10},
		{"differentiated_paper_rates", 10, 10, 1, 10, 1},
		{"only_inter_tor_set_tor_mesh_inherits", 8, 0, 5, 8, 5},
		{"only_tor_mesh_set_inter_tor_inherits", 7, 12, 0, 12, 7},
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

func TestAgentConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *AgentConfig)
		wantErr string
	}{
		{"valid", func(c *AgentConfig) {}, ""},
		{"reserved tor_id", func(c *AgentConfig) { c.TorID = "unspecified" }, "tor_id"},
		{"reserved tor_id with surrounding whitespace", func(c *AgentConfig) { c.TorID = " unspecified " }, "tor_id"},
		{"unknown is a valid named ToR", func(c *AgentConfig) { c.TorID = "unknown" }, ""},
		{
			"device_tor_ids empty device name",
			func(c *AgentConfig) { c.DeviceTorIDs = map[string]string{" ": "leaf-a"} },
			"device_tor_ids has an empty device name",
		},
		{
			"device_plane_ids empty device name",
			func(c *AgentConfig) { c.DevicePlaneIDs = map[string]string{" ": "rail0"} },
			"device_plane_ids has an empty device name",
		},
		{"negative gid index", func(c *AgentConfig) { c.GIDIndex = -1 }, "gid_index"},
		{"gid index at max is valid", func(c *AgentConfig) { c.GIDIndex = MaxGIDIndex }, ""},
		{"gid index exceeds max", func(c *AgentConfig) { c.GIDIndex = MaxGIDIndex + 1 }, "gid_index"},
		{"valid service level and traffic class at bounds", func(c *AgentConfig) { c.ServiceLevel = 7; c.TrafficClass = 255 }, ""},
		{"negative service level", func(c *AgentConfig) { c.ServiceLevel = -1 }, "service_level"},
		{"service level exceeds max", func(c *AgentConfig) { c.ServiceLevel = 8 }, "service_level"},
		{"negative traffic class", func(c *AgentConfig) { c.TrafficClass = -1 }, "traffic_class"},
		{"traffic class exceeds max", func(c *AgentConfig) { c.TrafficClass = 256 }, "traffic_class"},
		{"invalid cq poll mode", func(c *AgentConfig) { c.CQPollMode = "spin" }, "cq_poll_mode"},
		{"busy cq poll mode", func(c *AgentConfig) { c.CQPollMode = CQPollModeBusy }, ""},
		{"event ring capacity at min", func(c *AgentConfig) { c.EventRingCapacity = MinEventRingCapacity }, ""},
		{"event ring capacity at max", func(c *AgentConfig) { c.EventRingCapacity = MaxEventRingCapacity }, ""},
		{"event ring capacity below min", func(c *AgentConfig) { c.EventRingCapacity = MinEventRingCapacity / 2 }, "event_ring_capacity"},
		{"event ring capacity above max", func(c *AgentConfig) { c.EventRingCapacity = MaxEventRingCapacity * 2 }, "event_ring_capacity"},
		{"event ring capacity not a power of two", func(c *AgentConfig) { c.EventRingCapacity = 3000 }, "event_ring_capacity"},
		{"zero probe interval", func(c *AgentConfig) { c.ProbeIntervalMS = 0 }, "probe_interval_ms"},
		{"zero flow label rotation period", func(c *AgentConfig) { c.FlowLabelRotationPeriodSec = 0 }, "flow_label_rotation_period_sec"},
		// A negative per-type rate would be silently read as "disabled" by
		// the limiter, defeating the intended cap.
		{"negative tor-mesh probe rate", func(c *AgentConfig) { c.TorMeshProbeRatePerSecond = -1 }, "tor_mesh_probe_rate_per_second"},
		{"negative inter-tor probe rate", func(c *AgentConfig) { c.InterTorProbeRatePerSecond = -1 }, "inter_tor_probe_rate_per_second"},
		{"differentiated probe rates", func(c *AgentConfig) { c.TorMeshProbeRatePerSecond = 10; c.InterTorProbeRatePerSecond = 1 }, ""},
		{"analysis reporting needs a window", func(c *AgentConfig) { c.AnalysisReportEnabled = true }, "analysis_window_sec"},
		{"analysis reporting with a window", func(c *AgentConfig) { c.AnalysisReportEnabled = true; c.AnalysisWindowSec = 30 }, ""},
		{"tls_mode disabled requires no certificate files", func(c *AgentConfig) { c.TLSMode = TLSModeDisabled }, ""},
		{"unknown tls_mode is rejected", func(c *AgentConfig) { c.TLSMode = "bogus" }, "tls_mode must be one of"},
		{"tls_mode=tls without ca file is rejected", func(c *AgentConfig) { c.TLSMode = TLSModeTLS }, "tls_ca_file is required"},
		{"tls_mode=mtls without ca/cert/key is rejected", func(c *AgentConfig) { c.TLSMode = TLSModeMTLS }, "tls_ca_file is required"},
		{
			"self-protection enabled with valid thresholds",
			func(c *AgentConfig) { enableSelfProtection(c) },
			"",
		},
		{
			"self-protection enabled rejects zero watchdog interval",
			func(c *AgentConfig) { enableSelfProtection(c); c.WatchdogIntervalSec = 0 },
			"watchdog_interval_sec",
		},
		{
			"self-protection enabled rejects memory ratio of zero",
			func(c *AgentConfig) { enableSelfProtection(c); c.ThrottleMemoryRatio = 0 },
			"throttle_memory_ratio",
		},
		{
			"self-protection enabled rejects memory ratio above one",
			func(c *AgentConfig) { enableSelfProtection(c); c.ThrottleMemoryRatio = 1.5 },
			"throttle_memory_ratio",
		},
		{
			"self-protection enabled rejects cpu percent of zero",
			func(c *AgentConfig) { enableSelfProtection(c); c.ThrottleCPUPercent = 0 },
			"throttle_cpu_percent",
		},
		{
			"self-protection enabled rejects cpu percent above 100",
			func(c *AgentConfig) { enableSelfProtection(c); c.ThrottleCPUPercent = 101 },
			"throttle_cpu_percent",
		},
		{"self-protection disabled ignores throttle knobs", func(c *AgentConfig) { c.SelfProtectionEnabled = false }, ""},
		{"negative max_memory_mb rejected regardless of self-protection", func(c *AgentConfig) { c.MaxMemoryMB = -1 }, "max_memory_mb"},
		{"negative max_procs rejected regardless of self-protection", func(c *AgentConfig) { c.MaxProcs = -1 }, "max_procs"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfig()
			tc.mutate(&cfg)
			checkErr(t, cfg.Validate(), tc.wantErr)
		})
	}
}

// enableSelfProtection turns the watchdog on with thresholds that pass
// Validate; cases then break one of them.
func enableSelfProtection(c *AgentConfig) {
	c.SelfProtectionEnabled = true
	c.WatchdogIntervalSec = 5
	c.ThrottleMemoryRatio = 0.9
	c.ThrottleCPUPercent = 90
}

// TestAgentConfig_Validate_MTLSWithRealFiles verifies that tls_mode=mtls
// passes Validate() once all three certificate files actually exist on
// disk, using freshly generated test certificates rather than a hard-coded
// stub path (real existence checking is the behavior under test).
func TestAgentConfig_Validate_MTLSWithRealFiles(t *testing.T) {
	certs := tlscerts.WriteFileSet(t)

	cfg := validAgentConfig()
	cfg.TLSMode = TLSModeMTLS
	cfg.TLSCertFile = certs.ClientCertFile
	cfg.TLSKeyFile = certs.ClientKeyFile
	cfg.TLSCAFile = certs.CAFile
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil when all tls files exist", err)
	}
}

// --- device selection and topology ---

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

// Whitespace-separated env lists are a Viper convention this package relies
// on for every []string key.
func TestLoadAgentConfig_ListsFromEnv(t *testing.T) {
	t.Setenv("RPINGMESH_EXCLUDED_DEVICE_NAMES", "mlx5_4 mlx5_5")
	t.Setenv("RPINGMESH_EXCLUDED_GID_CIDRS", "10.0.0.0/24 192.168.0.0/16")
	cfg, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsDeviceExcluded("mlx5_4") || !cfg.IsDeviceExcluded("mlx5_5") {
		t.Errorf("ExcludedDeviceNames = %v, want mlx5_4 and mlx5_5", cfg.ExcludedDeviceNames)
	}
	if _, ok := cfg.ExcludedGIDCIDR("192.168.3.4"); !ok {
		t.Errorf("ExcludedGIDCIDRs = %v, want 192.168.0.0/16 included", cfg.ExcludedGIDCIDRs)
	}
}

func TestLoadAgentConfig_ExcludedGIDCIDRs(t *testing.T) {
	path := writeYAML(t, "agent.yaml", `excluded_gid_cidrs:
  - 10.0.0.0/24
  - " fd00:1::/64 "
`)
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cases := map[string]string{
		"10.0.0.7":        "10.0.0.0/24",
		"::ffff:10.0.0.7": "10.0.0.0/24", // IPv4-mapped form matches IPv4 networks
		"10.0.1.7":        "",
		"fd00:0001:0000:0000:0000:0000:0000:0005": "fd00:1::/64", // full-width GID text
		"fe80::1":   "",
		"":          "",
		"not-an-ip": "",
	}
	for ip, want := range cases {
		got, ok := cfg.ExcludedGIDCIDR(ip)
		if got != want || ok != (want != "") {
			t.Errorf("ExcludedGIDCIDR(%q) = (%q, %v), want %q", ip, got, ok, want)
		}
	}
}

func TestLoadAgentConfig_MappedDevicesOnly(t *testing.T) {
	path := writeYAML(t, "agent.yaml", "mapped_devices_only: true\ndevice_tor_ids:\n  mlx5_0: leaf-a\n")
	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.MappedDevicesOnly {
		t.Error("MappedDevicesOnly = false, want true")
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

// --- log_format ---

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
