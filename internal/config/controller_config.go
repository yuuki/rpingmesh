package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/logging"
	"github.com/yuuki/rpingmesh/internal/probe"
)

// Default threshold values for the controller's RNIC registry. These mirror
// registry.Default{Active,Stale}ThresholdSec, pinglist.DefaultInterTorSampleSize
// and pinglist.DefaultUnspecifiedMeshMaxTargets so that config defaults and
// the packages' own fallbacks stay in sync without the config package
// importing the controller packages; TestDefaultsMatchControllerPackages pins
// them equal.
const (
	// DefaultActiveThresholdSec is the window (seconds) within which an
	// RNIC entry is considered "active" for pinglist generation.
	DefaultActiveThresholdSec = 300
	// DefaultStaleThresholdSec is the window (seconds) after which an RNIC
	// entry is considered stale and removed.
	DefaultStaleThresholdSec = 900
	// DefaultInterTorSampleSize is the default number of distinct ToRs
	// sampled for inter-ToR pinglist generation.
	DefaultInterTorSampleSize = 5
	// DefaultUnspecifiedMeshMaxTargets caps ToR-mesh pinglist size for
	// agents that omit tor_id. 0 means unlimited.
	DefaultUnspecifiedMeshMaxTargets = 32
	// DefaultDatabaseConnectTimeoutSec is how long (seconds) the controller
	// keeps retrying its rqlite connection and schema initialization at
	// startup before exiting. 0 disables retries (a single attempt).
	DefaultDatabaseConnectTimeoutSec = 120

	// DefaultEcmpPathsAssumed is the assumed ECMP fabric width (m) used by
	// Eq.(1) to size the per-target flow-label set. It cannot be measured
	// from the agent, so it is an operator assumption.
	DefaultEcmpPathsAssumed = 16
	// DefaultEcmpCoverageProbability is the target probability (p) that the
	// generated flow-label set exercises all m ECMP paths.
	DefaultEcmpCoverageProbability = 0.9
	// DefaultEcmpMaxFlowLabels caps the computed label count (n) to bound
	// probe amplification.
	DefaultEcmpMaxFlowLabels = 64

	// MaxEcmpFlowLabels is the operational ceiling on ecmp_max_flow_labels;
	// see probe.MaxDistinctFlowLabels, which the agent also clamps to.
	MaxEcmpFlowLabels = probe.MaxDistinctFlowLabels

	// DefaultAnalyzerSLALossRatio is the default per-path loss ratio
	// (probe_failed / probe_total) above which the analyzer flags a window as
	// a loss SLA violation.
	DefaultAnalyzerSLALossRatio = 0.02
	// DefaultAnalyzerSLANetworkRTTP99Ns is the default per-path p99 network-RTT
	// threshold (ns) above which the analyzer flags an RTT SLA violation.
	DefaultAnalyzerSLANetworkRTTP99Ns = 500_000
	// DefaultAnalyzerWindowRetention is the default number of distinct windows
	// the analyzer retains in its in-memory ring.
	DefaultAnalyzerWindowRetention = 20
	// DefaultAnalyzerMetricsCardinalityLimit is the default cap on attribute
	// sets per analyzer instrument. rpingmesh.analyzer.sla_violations_total
	// has one series per (network, source_tor, target_tor, kind): at most
	// 4 x T x (T-1) for T ToRs, all of which can appear at once in a wide
	// outage, when the labels matter most. 20000 covers about 70 ToRs; the
	// OTel SDK default of 2000 would fold the series of a 23-ToR fabric into
	// one overflow series. The analyzer is a single process, so the memory
	// is bounded fleet-wide.
	DefaultAnalyzerMetricsCardinalityLimit = 20000
	// DefaultControllerOtelCollectorAddr is the default OTLP gRPC collector
	// endpoint the analyzer exports its metrics to.
	DefaultControllerOtelCollectorAddr = "localhost:4317"
)

// ControllerConfig holds all configuration for the controller.
type ControllerConfig struct {
	ListenAddr  string `mapstructure:"listen_addr"`
	DatabaseURI string `mapstructure:"database_uri"`
	// DatabaseConnectTimeoutSec bounds the startup retry of the rqlite
	// connection (exponential backoff, 1s to 30s). 0 makes a single attempt.
	DatabaseConnectTimeoutSec int    `mapstructure:"database_connect_timeout_sec"`
	LogLevel                  string `mapstructure:"log_level"`
	// LogFormat selects the log output format: "console" (default,
	// human-readable) or "json" (one zerolog JSON object per line on stderr).
	LogFormat                 string `mapstructure:"log_format"`
	ActiveThresholdSec        int    `mapstructure:"active_threshold_sec"`
	StaleThresholdSec         int    `mapstructure:"stale_threshold_sec"`
	InterTorSampleSize        int    `mapstructure:"inter_tor_sample_size"`
	UnspecifiedMeshMaxTargets int    `mapstructure:"unspecified_mesh_max_targets"`
	// EcmpPathsAssumed (m), EcmpCoverageProbability (p), and EcmpMaxFlowLabels
	// (cap on n) drive R-Pingmesh Eq.(1) sizing of the per-target flow-label
	// set for probabilistic ECMP path coverage.
	EcmpPathsAssumed        int     `mapstructure:"ecmp_paths_assumed"`
	EcmpCoverageProbability float64 `mapstructure:"ecmp_coverage_probability"`
	EcmpMaxFlowLabels       int     `mapstructure:"ecmp_max_flow_labels"`

	// Analyzer (Phase 1) settings. AnalyzerEnabled turns on ingestion of
	// agent-reported per-path summaries and SLA-violation detection.
	AnalyzerEnabled            bool    `mapstructure:"analyzer_enabled"`
	AnalyzerSLALossRatio       float64 `mapstructure:"analyzer_sla_loss_ratio"`
	AnalyzerSLANetworkRTTP99Ns uint64  `mapstructure:"analyzer_sla_network_rtt_p99_ns"`
	// AnalyzerServiceSLOLossRatio and AnalyzerServiceSLONetworkRTTP99Ns are
	// the SLO thresholds for the service network: path summaries of probes
	// sent along traced application flows (pinglist_type SERVICE_TRACING),
	// which the analyzer evaluates apart from the cluster paths. They default
	// to the cluster thresholds' defaults but are independent settings.
	AnalyzerServiceSLOLossRatio       float64 `mapstructure:"analyzer_service_slo_loss_ratio"`
	AnalyzerServiceSLONetworkRTTP99Ns uint64  `mapstructure:"analyzer_service_slo_network_rtt_p99_ns"`
	AnalyzerWindowRetention           int     `mapstructure:"analyzer_window_retention"`
	// AnalyzerMetricsCardinalityLimit caps the attribute sets each analyzer
	// instrument keeps; extra sets fold into one otel.metric.overflow
	// series. 0 keeps the OTel SDK default (2000); otherwise it must be at
	// least MinMetricsCardinalityLimit, as for the agent's
	// metrics_cardinality_limit. See DefaultAnalyzerMetricsCardinalityLimit
	// for the sizing.
	AnalyzerMetricsCardinalityLimit int `mapstructure:"analyzer_metrics_cardinality_limit"`
	// OtelCollectorAddr is the OTLP gRPC endpoint the analyzer exports its
	// metrics to (service.name=rpingmesh-analyzer). Only used when the analyzer
	// is enabled; export is best-effort.
	OtelCollectorAddr string `mapstructure:"otel_collector_addr"`
	// TLS settings for the gRPC server. See internal/config/tls.go for mode
	// semantics. TLSMode defaults to TLSModeDisabled, preserving plaintext
	// gRPC for backward compatibility. These keys are symmetric with
	// AgentConfig's; TLSServerName is not used by the controller (server)
	// role but is kept for config-key symmetry across agent.yaml/controller.yaml.
	TLSMode       string `mapstructure:"tls_mode"`
	TLSCertFile   string `mapstructure:"tls_cert_file"`
	TLSKeyFile    string `mapstructure:"tls_key_file"`
	TLSCAFile     string `mapstructure:"tls_ca_file"`
	TLSServerName string `mapstructure:"tls_server_name"`
}

// controllerKeys is the single source of controller config keys, defaults
// and flag help. Order matches the ControllerConfig field order; it does not
// affect --help, which pflag sorts by name.
var controllerKeys = []keySpec{
	{key: "listen_addr", def: ":50051", help: "Address to listen on for gRPC connections"},
	{key: "database_uri", def: "http://localhost:4001", help: "rqlite database connection URI"},
	{key: "database_connect_timeout_sec", def: DefaultDatabaseConnectTimeoutSec, help: "Seconds to keep retrying the rqlite connection at startup (0 = single attempt)"},
	{key: "log_level", def: "info", help: "Log level (debug, info, warn, error)"},
	{key: "log_format", def: logging.DefaultFormat, help: "Log output format: console or json"},
	{key: "active_threshold_sec", def: DefaultActiveThresholdSec, help: "Window (seconds) within which an RNIC is considered active"},
	{key: "stale_threshold_sec", def: DefaultStaleThresholdSec, help: "Window (seconds) after which an inactive RNIC is removed"},
	{key: "inter_tor_sample_size", def: DefaultInterTorSampleSize, help: "Number of distinct ToRs sampled for inter-ToR pinglists"},
	{key: "unspecified_mesh_max_targets", def: DefaultUnspecifiedMeshMaxTargets, help: "Cap on ToR-mesh targets for agents with unset tor_id (0 = unlimited)"},
	{key: "ecmp_paths_assumed", def: DefaultEcmpPathsAssumed, help: "Assumed ECMP fabric width (m) for Eq.(1) flow-label coverage sizing"},
	{key: "ecmp_coverage_probability", def: DefaultEcmpCoverageProbability, help: "Target probability (p, in (0,1)) that generated flow labels cover all ECMP paths"},
	{key: "ecmp_max_flow_labels", def: DefaultEcmpMaxFlowLabels, help: "Hard cap on the number of flow labels per target (bounds probe amplification)"},
	{key: "analyzer_enabled", def: true, help: "Enable the Phase 1 analyzer (ingest agent summaries, detect SLA violations)"},
	{key: "analyzer_sla_loss_ratio", def: DefaultAnalyzerSLALossRatio, help: "Per-path loss ratio (0..1) above which a window is an SLA violation"},
	{key: "analyzer_sla_network_rtt_p99_ns", def: uint64(DefaultAnalyzerSLANetworkRTTP99Ns), help: "Per-path p99 network-RTT threshold (ns) above which a window is an SLA violation (0 disables)"},
	{key: "analyzer_service_slo_loss_ratio", def: DefaultAnalyzerSLALossRatio, help: "Service-network (service tracing) per-path loss ratio (0..1) above which a window is an SLO violation"},
	{key: "analyzer_service_slo_network_rtt_p99_ns", def: uint64(DefaultAnalyzerSLANetworkRTTP99Ns), help: "Service-network (service tracing) per-path p99 network-RTT threshold (ns) above which a window is an SLO violation (0 disables)"},
	{key: "analyzer_window_retention", def: DefaultAnalyzerWindowRetention, help: "Number of recent windows the analyzer retains in memory"},
	{key: "analyzer_metrics_cardinality_limit", def: DefaultAnalyzerMetricsCardinalityLimit, help: "Maximum attribute sets per analyzer metric instrument (0 = OTel SDK default 2000, otherwise >= 2000)"},
	{key: "otel_collector_addr", def: DefaultControllerOtelCollectorAddr, help: "OTLP gRPC collector endpoint for analyzer metrics"},
	{key: "tls_mode", def: TLSModeDisabled, help: "gRPC transport security mode (disabled|tls|mtls)"},
	{key: "tls_cert_file", def: "", help: "Server certificate file (required when tls-mode is tls or mtls)"},
	{key: "tls_key_file", def: "", help: "Server private key file (required when tls-mode is tls or mtls)"},
	{key: "tls_ca_file", def: "", help: "CA file used to verify client certificates (required when tls-mode=mtls)"},
	{key: "tls_server_name", def: "", help: "Reserved for config-key symmetry with the agent; unused by the controller (server) role"},
}

// LoadControllerConfig loads controller configuration from a YAML file,
// environment variables, CLI flags, and applies defaults. Precedence
// (highest to lowest) is: CLI flag > environment variable > YAML file >
// default. Environment variables are RPINGMESH_ plus the upper-cased config
// key (e.g., RPINGMESH_LISTEN_ADDR). If flags is non-nil, it is bound to
// viper so that explicitly-set flags take priority; pass the same FlagSet
// given to BindControllerFlags.
func LoadControllerConfig(configPath string, flags *pflag.FlagSet) (*ControllerConfig, error) {
	v, err := newViper("controller", configPath, flags, controllerKeys)
	if err != nil {
		return nil, err
	}

	config := &ControllerConfig{
		ListenAddr:                v.GetString("listen_addr"),
		DatabaseURI:               v.GetString("database_uri"),
		DatabaseConnectTimeoutSec: v.GetInt("database_connect_timeout_sec"),
		LogLevel:                  v.GetString("log_level"),
		LogFormat:                 v.GetString("log_format"),
		ActiveThresholdSec:        v.GetInt("active_threshold_sec"),
		StaleThresholdSec:         v.GetInt("stale_threshold_sec"),
		InterTorSampleSize:        v.GetInt("inter_tor_sample_size"),
		UnspecifiedMeshMaxTargets: v.GetInt("unspecified_mesh_max_targets"),
		EcmpPathsAssumed:          v.GetInt("ecmp_paths_assumed"),
		EcmpCoverageProbability:   v.GetFloat64("ecmp_coverage_probability"),
		EcmpMaxFlowLabels:         v.GetInt("ecmp_max_flow_labels"),

		AnalyzerEnabled:                   v.GetBool("analyzer_enabled"),
		AnalyzerSLALossRatio:              v.GetFloat64("analyzer_sla_loss_ratio"),
		AnalyzerSLANetworkRTTP99Ns:        v.GetUint64("analyzer_sla_network_rtt_p99_ns"),
		AnalyzerServiceSLOLossRatio:       v.GetFloat64("analyzer_service_slo_loss_ratio"),
		AnalyzerServiceSLONetworkRTTP99Ns: v.GetUint64("analyzer_service_slo_network_rtt_p99_ns"),
		AnalyzerWindowRetention:           v.GetInt("analyzer_window_retention"),
		AnalyzerMetricsCardinalityLimit:   v.GetInt("analyzer_metrics_cardinality_limit"),
		OtelCollectorAddr:                 v.GetString("otel_collector_addr"),
		TLSMode:                           v.GetString("tls_mode"),
		TLSCertFile:                       v.GetString("tls_cert_file"),
		TLSKeyFile:                        v.GetString("tls_key_file"),
		TLSCAFile:                         v.GetString("tls_ca_file"),
		TLSServerName:                     v.GetString("tls_server_name"),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// BindControllerFlags binds common controller CLI flags to a pflag.FlagSet.
// These flags can later be bound to a viper instance for unified config resolution.
func BindControllerFlags(flags *pflag.FlagSet) {
	registerFlags(flags, controllerKeys)
}

// Validate checks that the controller configuration is well-formed. It
// returns an error describing the first invalid field encountered. The
// helpers run in a fixed order so that the first error for a given input is
// stable.
func (c *ControllerConfig) Validate() error {
	if err := c.validateEndpoints(); err != nil {
		return err
	}
	if err := c.validateLogging(); err != nil {
		return err
	}
	if err := c.validateRegistry(); err != nil {
		return err
	}
	if err := c.validateECMP(); err != nil {
		return err
	}
	if err := c.validateAnalyzer(); err != nil {
		return err
	}
	if err := validateOTLPEndpoint(c.OtelCollectorAddr); err != nil {
		return err
	}
	// The controller is the gRPC server of the controller-agent connection:
	// fail fast if the certificate files required by tls_mode are missing,
	// rather than at the first client handshake.
	return validateTLSFiles(tlsRoleServer, c.TLSMode, c.TLSCertFile, c.TLSKeyFile, c.TLSCAFile)
}

// validateEndpoints checks listen_addr and the database settings.
func (c *ControllerConfig) validateEndpoints() error {
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("listen_addr must not be empty")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr %q is not a valid address: %w", c.ListenAddr, err)
	}

	if strings.TrimSpace(c.DatabaseURI) == "" {
		return fmt.Errorf("database_uri must not be empty")
	}
	u, err := url.Parse(c.DatabaseURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("database_uri %q is not a valid URL", c.DatabaseURI)
	}
	if c.DatabaseConnectTimeoutSec < 0 {
		return fmt.Errorf("database_connect_timeout_sec must be >= 0, got: %d", c.DatabaseConnectTimeoutSec)
	}
	return nil
}

// validateLogging checks log_level and log_format.
func (c *ControllerConfig) validateLogging() error {
	if _, err := zerolog.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("log_level %q is not a known level: %w", c.LogLevel, err)
	}
	return logging.ValidateFormat(c.LogFormat)
}

// validateRegistry checks the RNIC registry thresholds and pinglist sizing.
func (c *ControllerConfig) validateRegistry() error {
	if c.ActiveThresholdSec <= 0 {
		return fmt.Errorf("active_threshold_sec must be > 0, got: %d", c.ActiveThresholdSec)
	}
	if c.StaleThresholdSec <= 0 {
		return fmt.Errorf("stale_threshold_sec must be > 0, got: %d", c.StaleThresholdSec)
	}
	if c.StaleThresholdSec < c.ActiveThresholdSec {
		return fmt.Errorf("stale_threshold_sec (%d) must be >= active_threshold_sec (%d)", c.StaleThresholdSec, c.ActiveThresholdSec)
	}
	if c.InterTorSampleSize <= 0 {
		return fmt.Errorf("inter_tor_sample_size must be > 0, got: %d", c.InterTorSampleSize)
	}
	if c.UnspecifiedMeshMaxTargets < 0 {
		return fmt.Errorf("unspecified_mesh_max_targets must be >= 0, got: %d", c.UnspecifiedMeshMaxTargets)
	}
	return nil
}

// validateECMP checks the Eq.(1) flow-label sizing inputs.
func (c *ControllerConfig) validateECMP() error {
	if c.EcmpPathsAssumed < 1 {
		return fmt.Errorf("ecmp_paths_assumed must be >= 1, got: %d", c.EcmpPathsAssumed)
	}
	// p must be a strict probability: 0 and 1 are degenerate for Eq.(1)
	// (0 needs no coverage; 1 is unreachable by random sampling).
	if c.EcmpCoverageProbability <= 0 || c.EcmpCoverageProbability >= 1 {
		return fmt.Errorf("ecmp_coverage_probability must be in (0, 1), got: %v", c.EcmpCoverageProbability)
	}
	if c.EcmpMaxFlowLabels < 1 {
		return fmt.Errorf("ecmp_max_flow_labels must be >= 1, got: %d", c.EcmpMaxFlowLabels)
	}
	// Bound per-target probe amplification and agent memory: an operational cap
	// far below the 20-bit flow-label space (see MaxEcmpFlowLabels).
	if c.EcmpMaxFlowLabels > MaxEcmpFlowLabels {
		return fmt.Errorf("ecmp_max_flow_labels must be <= %d, got: %d", MaxEcmpFlowLabels, c.EcmpMaxFlowLabels)
	}
	return nil
}

// validateAnalyzer checks the analyzer thresholds, which are only enforced
// when the analyzer is enabled.
func (c *ControllerConfig) validateAnalyzer() error {
	if !c.AnalyzerEnabled {
		return nil
	}
	// A loss ratio is a probability in [0, 1]; outside that range the
	// threshold is meaningless (a negative ratio flags everything, > 1
	// flags nothing).
	if c.AnalyzerSLALossRatio < 0 || c.AnalyzerSLALossRatio > 1 {
		return fmt.Errorf("analyzer_sla_loss_ratio must be in [0, 1], got: %v", c.AnalyzerSLALossRatio)
	}
	if c.AnalyzerServiceSLOLossRatio < 0 || c.AnalyzerServiceSLOLossRatio > 1 {
		return fmt.Errorf("analyzer_service_slo_loss_ratio must be in [0, 1], got: %v", c.AnalyzerServiceSLOLossRatio)
	}
	// The window ring must retain at least one window.
	if c.AnalyzerWindowRetention < 1 {
		return fmt.Errorf("analyzer_window_retention must be >= 1, got: %d", c.AnalyzerWindowRetention)
	}
	// As for the agent: a negative limit would disable the SDK's cap and a
	// limit below the SDK default would cap every instrument harder than
	// the default does.
	if c.AnalyzerMetricsCardinalityLimit != 0 && c.AnalyzerMetricsCardinalityLimit < MinMetricsCardinalityLimit {
		return fmt.Errorf("analyzer_metrics_cardinality_limit must be 0 (OTel SDK default) or >= %d, got: %d",
			MinMetricsCardinalityLimit, c.AnalyzerMetricsCardinalityLimit)
	}
	return nil
}
