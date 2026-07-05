package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// DefaultTargetProbeRatePerSecond is the default number of probes per second per target.
const DefaultTargetProbeRatePerSecond = 10

// DefaultFlowLabelRotationPeriodSec is the default period (seconds) over which
// the rotating subset (~20%) of a target's ECMP flow-label set is refreshed,
// shifting a fraction of probed paths over time while most labels stay stable
// for time-series continuity. 3600s (1h) matches the R-Pingmesh paper.
const DefaultFlowLabelRotationPeriodSec = 3600

// DefaultAnalysisWindowSec is the default aggregation window (seconds) over
// which the agent's PathAggregator groups per-path probe results before
// reporting a summary to the controller's analyzer. 30s balances reporting
// volume against detection latency.
const DefaultAnalysisWindowSec = 30

// MaxGIDIndex is a coarse sanity upper bound for gid_index. Real ibv GID
// tables are small (rdma_rxe typically exposes a handful of entries; mlx5
// rarely exceeds a few dozen), so a huge value can never be valid on any
// device and is rejected at config-validation time rather than surfacing
// only as a device-open failure later. Exact per-device range/existence
// validation still happens in the Zig bridge at device-open time (see
// findActivePortAndGid() in zig/src/device.zig), since that is the only
// place the real GID table size is known.
const MaxGIDIndex = 255

// AgentConfig holds all configuration for the agent.
type AgentConfig struct {
	AgentID            string   `mapstructure:"agent_id"`
	HostName           string   `mapstructure:"hostname"`
	TorID              string   `mapstructure:"tor_id"`
	ControllerAddr     string   `mapstructure:"controller_addr"`
	LogLevel           string   `mapstructure:"log_level"`
	ProbeIntervalMS    uint32   `mapstructure:"probe_interval_ms"`
	OtelCollectorAddr  string   `mapstructure:"otel_collector_addr"`
	MetricsEnabled     bool     `mapstructure:"metrics_enabled"`
	AllowedDeviceNames []string `mapstructure:"allowed_device_names"`
	GIDIndex           int      `mapstructure:"gid_index"`
	// ServiceLevel is the Service Level (SL, PFC priority) applied to every
	// Address Handle the agent's RDMA devices create (0-7; see Validate()).
	ServiceLevel int `mapstructure:"service_level"`
	// TrafficClass is the IPv6/GRH traffic class octet applied to every
	// Address Handle the agent's RDMA devices create (0-255; see
	// Validate()). RoCEv2 DSCP occupies the upper 6 bits of this octet: a
	// target DSCP value D maps to traffic_class = D << 2.
	TrafficClass              int    `mapstructure:"traffic_class"`
	PinglistUpdateIntervalSec uint32 `mapstructure:"pinglist_update_interval_sec"`
	TargetProbeRatePerSecond  int    `mapstructure:"target_probe_rate_per_second"`
	// FlowLabelRotationPeriodSec is the period over which the rotating subset
	// of each target's ECMP flow-label set is refreshed (time-based ECMP path
	// rotation). See DefaultFlowLabelRotationPeriodSec.
	FlowLabelRotationPeriodSec uint32 `mapstructure:"flow_label_rotation_period_sec"`

	// AnalysisReportEnabled turns on per-path window aggregation and reporting
	// of PathSummary batches to the controller's analyzer via
	// ReportProbeAnalysis. Reporting is best-effort and never blocks probing.
	AnalysisReportEnabled bool `mapstructure:"analysis_report_enabled"`
	// AnalysisWindowSec is the aggregation window length in seconds. See
	// DefaultAnalysisWindowSec.
	AnalysisWindowSec uint32 `mapstructure:"analysis_window_sec"`
	// TLS settings for the gRPC connection to the controller. See
	// internal/config/tls.go for mode semantics. TLSMode defaults to
	// TLSModeDisabled, preserving plaintext gRPC for backward compatibility.
	TLSMode     string `mapstructure:"tls_mode"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
	TLSCAFile   string `mapstructure:"tls_ca_file"`
	// TLSServerName overrides the name used for TLS SNI/verification against
	// the controller; useful when controller_addr is an IP literal that
	// doesn't match the server certificate's subject.
	TLSServerName string `mapstructure:"tls_server_name"`
}

// LoadAgentConfig loads agent configuration from a YAML file, environment
// variables, CLI flags, and applies defaults. Precedence (highest to
// lowest) is: CLI flag > environment variable > YAML file > default.
// Environment variables use the prefix RPINGMESH_ and replace hyphens with
// underscores (e.g., RPINGMESH_CONTROLLER_ADDR). If flags is non-nil, it is
// bound to viper so that explicitly-set flags take priority; pass the same
// FlagSet given to BindAgentFlags.
func LoadAgentConfig(configPath string, flags *pflag.FlagSet) (*AgentConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("agent_id", "")
	v.SetDefault("hostname", "")
	v.SetDefault("tor_id", "")
	v.SetDefault("controller_addr", "localhost:50051")
	v.SetDefault("log_level", "info")
	v.SetDefault("probe_interval_ms", 500)
	v.SetDefault("otel_collector_addr", "grpc://localhost:4317")
	v.SetDefault("metrics_enabled", true)
	v.SetDefault("allowed_device_names", []string{})
	v.SetDefault("gid_index", 0)
	v.SetDefault("service_level", 0)
	v.SetDefault("traffic_class", 0)
	v.SetDefault("pinglist_update_interval_sec", 300)
	v.SetDefault("target_probe_rate_per_second", DefaultTargetProbeRatePerSecond)
	v.SetDefault("flow_label_rotation_period_sec", DefaultFlowLabelRotationPeriodSec)
	v.SetDefault("analysis_report_enabled", true)
	v.SetDefault("analysis_window_sec", DefaultAnalysisWindowSec)
	v.SetDefault("tls_mode", TLSModeDisabled)
	v.SetDefault("tls_cert_file", "")
	v.SetDefault("tls_key_file", "")
	v.SetDefault("tls_ca_file", "")
	v.SetDefault("tls_server_name", "")

	// Enable environment variable override with RPINGMESH_ prefix.
	// Underscores in env var names map to underscores in config keys.
	v.SetEnvPrefix("RPINGMESH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind CLI flags so that explicitly-set flags take precedence over
	// environment variables, config file values, and defaults.
	if flags != nil {
		if err := bindPFlags(v, flags); err != nil {
			return nil, err
		}
	}

	// Load config file if a path was provided
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Search default locations when no explicit path is given
		v.SetConfigName("agent")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.rpingmesh")
		v.AddConfigPath("/etc/rpingmesh")
	}

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is acceptable; other read errors are not
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Auto-detect hostname if not explicitly configured
	hostname := v.GetString("hostname")
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to auto-detect hostname: %w", err)
		}
		hostname = h
	}

	// Fall back to hostname if agent_id is not set
	agentID := v.GetString("agent_id")
	if agentID == "" {
		agentID = hostname
	}

	config := &AgentConfig{
		AgentID:                    agentID,
		HostName:                   hostname,
		TorID:                      v.GetString("tor_id"),
		ControllerAddr:             v.GetString("controller_addr"),
		LogLevel:                   v.GetString("log_level"),
		ProbeIntervalMS:            v.GetUint32("probe_interval_ms"),
		OtelCollectorAddr:          v.GetString("otel_collector_addr"),
		MetricsEnabled:             v.GetBool("metrics_enabled"),
		AllowedDeviceNames:         v.GetStringSlice("allowed_device_names"),
		GIDIndex:                   v.GetInt("gid_index"),
		ServiceLevel:               v.GetInt("service_level"),
		TrafficClass:               v.GetInt("traffic_class"),
		PinglistUpdateIntervalSec:  v.GetUint32("pinglist_update_interval_sec"),
		TargetProbeRatePerSecond:   v.GetInt("target_probe_rate_per_second"),
		FlowLabelRotationPeriodSec: v.GetUint32("flow_label_rotation_period_sec"),
		AnalysisReportEnabled:      v.GetBool("analysis_report_enabled"),
		AnalysisWindowSec:          v.GetUint32("analysis_window_sec"),
		TLSMode:                    v.GetString("tls_mode"),
		TLSCertFile:                v.GetString("tls_cert_file"),
		TLSKeyFile:                 v.GetString("tls_key_file"),
		TLSCAFile:                  v.GetString("tls_ca_file"),
		TLSServerName:              v.GetString("tls_server_name"),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks that the agent configuration is well-formed. It returns
// an error describing the first invalid field encountered.
func (c *AgentConfig) Validate() error {
	// GID index must be non-negative; it indexes into the RNIC's GID table.
	// The upper bound is a coarse sanity check, not the real device limit
	// (which is only known at device-open time): it exists purely to reject
	// obviously-bogus values (e.g. a typo like 100000) before they reach the
	// RDMA bridge. See MaxGIDIndex.
	if c.GIDIndex < 0 || c.GIDIndex > MaxGIDIndex {
		return fmt.Errorf("gid_index must be between 0 and %d, got: %d", MaxGIDIndex, c.GIDIndex)
	}

	// Service Level maps directly to ibv_ah_attr.sl, a 4-bit verbs field of
	// which only the low 3 bits (0-7) are meaningful as PFC priority.
	if c.ServiceLevel < 0 || c.ServiceLevel > 7 {
		return fmt.Errorf("service_level must be between 0 and 7, got: %d", c.ServiceLevel)
	}

	// Traffic class maps directly to the one-byte GRH traffic_class field
	// (ibv_ah_attr.grh.traffic_class).
	if c.TrafficClass < 0 || c.TrafficClass > 255 {
		return fmt.Errorf("traffic_class must be between 0 and 255, got: %d", c.TrafficClass)
	}

	// A zero or negative probe interval would make time.NewTicker panic at
	// runtime, so reject it up front instead of failing deep in the prober.
	if c.ProbeIntervalMS == 0 {
		return fmt.Errorf("probe_interval_ms must be > 0, got: %d", c.ProbeIntervalMS)
	}

	// A zero rotation period would make the epoch computation divide by zero.
	if c.FlowLabelRotationPeriodSec == 0 {
		return fmt.Errorf("flow_label_rotation_period_sec must be > 0, got: %d", c.FlowLabelRotationPeriodSec)
	}

	// When analysis reporting is on, the window drives a time.Ticker and the
	// aggregator's window alignment, both of which require a positive length.
	if c.AnalysisReportEnabled && c.AnalysisWindowSec == 0 {
		return fmt.Errorf("analysis_window_sec must be > 0 when analysis_report_enabled, got: %d", c.AnalysisWindowSec)
	}

	// The agent is the gRPC client of the controller connection: fail fast
	// if the certificate files required by tls_mode are missing, rather
	// than at the first dial attempt.
	if err := validateTLSFiles(tlsRoleClient, c.TLSMode, c.TLSCertFile, c.TLSKeyFile, c.TLSCAFile); err != nil {
		return err
	}

	return nil
}

// BindAgentFlags binds common agent CLI flags to a pflag.FlagSet.
// These flags can later be bound to a viper instance for unified config resolution.
func BindAgentFlags(flags *pflag.FlagSet) {
	flags.String("agent-id", "", "Agent ID (defaults to hostname if empty)")
	flags.String("tor-id", "", "Top-of-Rack switch identifier")
	flags.String("controller-addr", "localhost:50051", "Controller gRPC address")
	flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	flags.Uint32("probe-interval-ms", 500, "Probe interval in milliseconds")
	flags.String("otel-collector-addr", "grpc://localhost:4317", "OpenTelemetry collector address")
	flags.Bool("metrics-enabled", true, "Enable OpenTelemetry metrics export")
	flags.StringSlice("allowed-device-names", []string{}, "List of allowed RDMA device names (empty = all)")
	flags.Int("gid-index", 0, "GID index to use for RDMA devices (0-255)")
	flags.Int("service-level", 0, "Service Level (SL, PFC priority) for Address Handles (0-7)")
	flags.Int("traffic-class", 0, "GRH traffic class (DSCP << 2) for Address Handles (0-255)")
	flags.Uint32("pinglist-update-interval-sec", 300, "Pinglist update interval in seconds")
	flags.Int("target-probe-rate-per-second", DefaultTargetProbeRatePerSecond, "Probe rate per second per target")
	flags.Uint32("flow-label-rotation-period-sec", DefaultFlowLabelRotationPeriodSec, "Period (seconds) over which the rotating ~20% of each target's ECMP flow-label set is refreshed")
	flags.Bool("analysis-report-enabled", true, "Enable per-path window aggregation and SLA reporting to the controller")
	flags.Uint32("analysis-window-sec", DefaultAnalysisWindowSec, "Per-path aggregation window length in seconds")
	flags.String("tls-mode", TLSModeDisabled, "gRPC transport security mode for the controller connection (disabled|tls|mtls)")
	flags.String("tls-cert-file", "", "Client certificate file (required when tls-mode=mtls)")
	flags.String("tls-key-file", "", "Client private key file (required when tls-mode=mtls)")
	flags.String("tls-ca-file", "", "CA file used to verify the controller's certificate (required when tls-mode is tls or mtls)")
	flags.String("tls-server-name", "", "Server name for TLS SNI/verification (optional; defaults to the name derived from controller-addr)")
}
