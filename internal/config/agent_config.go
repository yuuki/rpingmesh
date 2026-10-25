package config

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"net"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/lldp"
	"github.com/yuuki/rpingmesh/internal/logging"
	"github.com/yuuki/rpingmesh/internal/probe"
)

// DefaultTargetProbeRatePerSecond is the default number of probes per second
// per target. It is the backward-compatible uniform rate: when neither
// tor_mesh_probe_rate_per_second nor inter_tor_probe_rate_per_second is set
// (both 0), this rate applies to targets of both pinglist types, reproducing
// the pre-differentiation single-rate behavior.
const DefaultTargetProbeRatePerSecond = 10

// DefaultTorMeshProbeRatePerSecond and DefaultInterTorProbeRatePerSecond are
// the defaults for the per-pinglist-type probe rates. They are 0, meaning
// "inherit target_probe_rate_per_second" so that a deployment which only ever
// set the legacy single rate keeps its uniform behavior after upgrading. Set
// them to positive values (see the recommended configs/agent.yaml: ToR-mesh
// 10pps, inter-ToR 1pps) to get the paper's differentiated per-type rates.
const (
	DefaultTorMeshProbeRatePerSecond  = 0
	DefaultInterTorProbeRatePerSecond = 0
)

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

// Defaults for agent self-protection (P2-G). The feature is opt-in
// (SelfProtectionEnabled defaults to false), so an untouched config behaves
// exactly as before. When enabled, the watchdog samples this process's
// CPU/memory usage every WatchdogIntervalSec seconds and, on threshold breach,
// steps the probe-rate multiplier down (fail-slow) rather than stopping.
const (
	DefaultSelfProtectionEnabled = false
	DefaultWatchdogIntervalSec   = 5
	// DefaultThrottleMemoryRatio triggers throttling once runtime-managed
	// memory reaches this fraction of max_memory_mb (the GOMEMLIMIT budget).
	// Memory throttling is inactive unless max_memory_mb > 0.
	DefaultThrottleMemoryRatio = 0.9
	// DefaultThrottleCPUPercent triggers throttling once the process's CPU use
	// reaches this percentage of its available capacity (GOMAXPROCS cores).
	DefaultThrottleCPUPercent = 90
)

// Defaults for service tracing (R-Pingmesh paper section 4.2.2). The feature
// is opt-in: it loads eBPF programs, which needs CAP_BPF and CAP_PERFMON (see
// packaging/systemd/rpingmesh-agent.service.d/10-service-tracing.conf). The
// probe rate is an aggregate cap per RNIC shared by every traced flow, and
// the interval is the minimum spacing between two passes over the flows; the
// paper probes service flows every 10 ms.
const (
	DefaultServiceTracingEnabled            = false
	DefaultServiceTracingProbeRatePerSecond = 100
	DefaultServiceTracingProbeIntervalMS    = 10
)

// MaxGIDIndex is a coarse sanity upper bound for gid_index. Real ibv GID
// tables are small (rdma_rxe typically exposes a handful of entries; mlx5
// rarely exceeds a few dozen), so a huge value can never be valid on any
// device and is rejected at config-validation time rather than surfacing
// only as a device-open failure later. Exact per-device range/existence
// validation still happens in the Zig bridge at device-open time (see
// findActivePortAndGid() in zig/src/device.zig), since that is the only
// place the real GID table size is known.
const MaxGIDIndex = 255

// MinMetricsCardinalityLimit is the smallest non-zero
// metrics_cardinality_limit, equal to the OTel SDK default. The SDK (v1.47)
// cannot scope the limit to the rpingmesh.target_rnic.* instruments: it
// applies to every instrument, so a lower value would fold the default
// ToR-level series that dashboards and alerts use into the overflow series.
const MinMetricsCardinalityLimit = 2000

// Values accepted by metrics_target_rnic_labels (see
// AgentConfig.MetricsTargetRnicLabels).
const (
	MetricsTargetRnicLabelsOff      = "off"
	MetricsTargetRnicLabelsCounters = "counters"
	MetricsTargetRnicLabelsAll      = "all"
	DefaultMetricsTargetRnicLabels  = MetricsTargetRnicLabelsOff
)

// Values accepted by metrics_target_rnic_labels_scope (see
// AgentConfig.MetricsTargetRnicLabelsScope).
const (
	MetricsTargetRnicLabelsScopeStable  = "stable"
	MetricsTargetRnicLabelsScopeAll     = "all"
	DefaultMetricsTargetRnicLabelsScope = MetricsTargetRnicLabelsScopeStable
)

// CQ poll modes accepted by cq_poll_mode (see AgentConfig.CQPollMode).
const (
	CQPollModeAuto    = "auto"
	CQPollModeEvent   = "event"
	CQPollModeBusy    = "busy"
	DefaultCQPollMode = CQPollModeAuto
)

// Bounds and default of event_ring_capacity (see
// AgentConfig.EventRingCapacity).
const (
	DefaultEventRingCapacity = 1024
	MinEventRingCapacity     = 64
	MaxEventRingCapacity     = 65536
)

// DefaultLLDPDiscoveryTimeoutSec is how long the agent waits at startup for
// lldpd to report a neighbor on every RDMA device's netdev. lldpd learns a
// neighbor only from the switch's next LLDP frame (sent every 30 s by
// default), so right after boot the first query can come back empty.
const DefaultLLDPDiscoveryTimeoutSec = 60

// AgentConfig holds all configuration for the agent.
type AgentConfig struct {
	AgentID  string `mapstructure:"agent_id"`
	HostName string `mapstructure:"hostname"`
	TorID    string `mapstructure:"tor_id"`
	// DeviceTorIDs optionally assigns a ToR per RDMA device (device name ->
	// ToR ID). It exists for rail-optimized multi-rail hosts, where each RNIC
	// is cabled to a different leaf switch, so a single host-wide TorID
	// misplaces every RNIC but one. Devices not listed use TorID. Keys are
	// lower-cased at load time (Viper lower-cases map keys anyway) and device
	// names are matched case-insensitively; values are canonicalized like
	// TorID and must be non-empty (proto3 cannot tell an explicitly empty
	// per-RNIC ToR from an unset one, so the controller would fall back to
	// tor_id). To leave a device untagged, leave tor_id empty and do not list
	// the device.
	DeviceTorIDs map[string]string `mapstructure:"device_tor_ids"`
	// PlaneID names the isolated network plane (rail) this host's RNICs are
	// attached to; DevicePlaneIDs overrides it per RDMA device (device name ->
	// plane), which is what rail-optimized multi-rail hosts need. On fabrics
	// whose rails are not routed to each other, the controller then pairs an
	// RNIC only with RNICs of the same plane in inter-ToR and untagged
	// pinglists, since cross-plane probes can never succeed. Empty (the
	// default) means unknown and keeps the plane-agnostic behavior.
	// DevicePlaneIDs follows the device_tor_ids rules: keys are lower-cased
	// and matched case-insensitively, values are trimmed and must be
	// non-empty (omit a device to use PlaneID).
	PlaneID        string            `mapstructure:"plane_id"`
	DevicePlaneIDs map[string]string `mapstructure:"device_plane_ids"`
	// LLDPTorDiscovery derives each RDMA device's ToR from the LLDP neighbor
	// of its netdev (via lldpd's lldpcli) at startup, so rail-optimized hosts
	// need no device_tor_ids map. Precedence per device: device_tor_ids entry,
	// then the LLDP neighbor, then tor_id. Discovery runs once; restart the
	// agent after re-cabling.
	LLDPTorDiscovery bool `mapstructure:"lldp_tor_discovery"`
	// LLDPTorIDField selects the neighbor attribute used as the ToR ID:
	// "system_name" (default, the switch hostname) or "chassis_id".
	LLDPTorIDField string `mapstructure:"lldp_tor_id_field"`
	// LLDPCLIPath is the lldpcli binary to run (default "lldpcli" on PATH).
	LLDPCLIPath string `mapstructure:"lldpcli_path"`
	// LLDPDiscoveryTimeoutSec bounds the startup wait for every device to see
	// a neighbor; 0 queries once. See DefaultLLDPDiscoveryTimeoutSec.
	LLDPDiscoveryTimeoutSec uint32 `mapstructure:"lldp_discovery_timeout_sec"`

	ControllerAddr string `mapstructure:"controller_addr"`
	LogLevel       string `mapstructure:"log_level"`
	// LogFormat selects the log output format: "console" (default,
	// human-readable) or "json" (one zerolog JSON object per line on stderr).
	LogFormat         string `mapstructure:"log_format"`
	ProbeIntervalMS   uint32 `mapstructure:"probe_interval_ms"`
	OtelCollectorAddr string `mapstructure:"otel_collector_addr"`
	MetricsEnabled    bool   `mapstructure:"metrics_enabled"`
	// MetricsTargetRnicLabels adds destination-RNIC attributes
	// (target_hostname, target_rdma_device, target_netdev) to probe metrics:
	// "off" (default) adds none, "counters" adds them to the probe counters
	// only, "all" also to the RTT histograms.
	MetricsTargetRnicLabels string `mapstructure:"metrics_target_rnic_labels"`
	// MetricsTargetRnicLabelsScope limits which targets get their real
	// identity: "stable" (default) labels only targets whose set is stable
	// across pinglist refreshes and gives sampled targets (inter-ToR, capped
	// untagged ToR-mesh) a fixed "_sampled" value; "all" labels them too.
	MetricsTargetRnicLabelsScope string `mapstructure:"metrics_target_rnic_labels_scope"`
	// MetricsCardinalityLimit caps the attribute sets each metric instrument
	// keeps; extra sets fold into one otel.metric.overflow series. 0 keeps
	// the OTel SDK default (2000). The SDK applies one limit to every
	// instrument, so only raising it is allowed (see
	// MinMetricsCardinalityLimit).
	MetricsCardinalityLimit int `mapstructure:"metrics_cardinality_limit"`
	// MetricsProberDelayTargetTor attaches target_tor to
	// rpingmesh.prober_delay_ns. Off by default: the prober delay is time
	// spent on the probing host, so target_tor only multiplies its series by
	// the number of ToRs probed.
	MetricsProberDelayTargetTor bool `mapstructure:"metrics_prober_delay_target_tor"`
	// MetricsResponderDelayTargetTor attaches target_tor to
	// rpingmesh.responder_delay_ns. On by default: it is the only default
	// metric that localizes slow responders, because network RTT subtracts
	// the responder delay.
	MetricsResponderDelayTargetTor bool     `mapstructure:"metrics_responder_delay_target_tor"`
	AllowedDeviceNames             []string `mapstructure:"allowed_device_names"`
	// ExcludedDeviceNames lists RDMA devices the agent never opens, matched
	// case-insensitively. It applies on top of AllowedDeviceNames; naming a
	// device in both lists is rejected by Validate().
	ExcludedDeviceNames []string `mapstructure:"excluded_device_names"`
	// ExcludedGIDCIDRs lists networks (CIDRs) whose RDMA devices the agent
	// never uses: a device whose GID at gid_index (as an IP address; RoCE v2
	// IPv4-mapped GIDs match IPv4 networks) lies in one of them is closed
	// right after it is opened, before any queue is created. Unlike device
	// names, a host's management or service network does not change when
	// the kernel renames or re-registers an RDMA device.
	ExcludedGIDCIDRs []string `mapstructure:"excluded_gid_cidrs"`
	// MappedDevicesOnly makes the agent use only the devices listed in
	// device_tor_ids. Any other device is closed right after it is opened
	// and logged at warn level, instead of silently falling back to the
	// host-wide tor_id. Requires a non-empty device_tor_ids.
	MappedDevicesOnly bool `mapstructure:"mapped_devices_only"`
	GIDIndex          int  `mapstructure:"gid_index"`
	// ServiceLevel is the Service Level (SL, PFC priority) applied to every
	// Address Handle the agent's RDMA devices create (0-7; see Validate()).
	ServiceLevel int `mapstructure:"service_level"`
	// TrafficClass is the IPv6/GRH traffic class octet applied to every
	// Address Handle the agent's RDMA devices create (0-255; see
	// Validate()). RoCEv2 DSCP occupies the upper 6 bits of this octet: a
	// target DSCP value D maps to traffic_class = D << 2.
	TrafficClass int `mapstructure:"traffic_class"`
	// CQPollMode selects how completions are awaited, by both the Zig CQ
	// poller thread and the Go event-ring consumer of each queue: "event"
	// sleeps on a completion channel and an eventfd (no CPU while idle),
	// "busy" polls (the CQ every ~50us, the ring every 100us), and "auto"
	// (default) uses event with hardware timestamps and busy with software
	// timestamps, whose accuracy depends on prompt polling.
	CQPollMode string `mapstructure:"cq_poll_mode"`
	// EventRingCapacity is the number of completion events each prober and
	// responder event ring holds (a power of two between
	// MinEventRingCapacity and MaxEventRingCapacity; 0 means
	// DefaultEventRingCapacity). Each event takes 80 bytes, and there are
	// two rings per RDMA device. A responder ring has to absorb the inbound
	// probes that arrive while its consumer goroutine is descheduled. Sizing
	// it beyond about one second of inbound probes buys little: a probe
	// answered more than probe.MaxSaneDelay (1 s) after it arrived is
	// rejected as invalid_rtt (kind responder_delay_too_large) instead of
	// timing out.
	EventRingCapacity         uint32 `mapstructure:"event_ring_capacity"`
	PinglistUpdateIntervalSec uint32 `mapstructure:"pinglist_update_interval_sec"`
	// TargetProbeRatePerSecond is the legacy uniform per-target probe rate. It
	// is the fallback for whichever per-pinglist-type rate below is left unset
	// (0). See EffectiveTorMeshProbeRate / EffectiveInterTorProbeRate.
	TargetProbeRatePerSecond int `mapstructure:"target_probe_rate_per_second"`
	// TorMeshProbeRatePerSecond and InterTorProbeRatePerSecond are the
	// differentiated per-target probe rates for ToR-mesh and inter-ToR targets
	// respectively (R-Pingmesh probes ToR-mesh more aggressively than inter-ToR).
	// A value of 0 means "inherit TargetProbeRatePerSecond" for backward
	// compatibility; a positive value overrides it for that pinglist type.
	TorMeshProbeRatePerSecond  int `mapstructure:"tor_mesh_probe_rate_per_second"`
	InterTorProbeRatePerSecond int `mapstructure:"inter_tor_probe_rate_per_second"`
	// FlowLabelRotationPeriodSec is the period over which the rotating subset
	// of each target's ECMP flow-label set is refreshed (time-based ECMP path
	// rotation). See DefaultFlowLabelRotationPeriodSec.
	FlowLabelRotationPeriodSec uint32 `mapstructure:"flow_label_rotation_period_sec"`

	// ServiceTracingEnabled traces the application RDMA connections on this
	// host with eBPF and probes each traced flow with the flow's own flow
	// label, so the probes follow the service traffic's ECMP paths (paper
	// section 4.2.2). Linux only; the agent needs CAP_BPF and CAP_PERFMON
	// and a kernel with BTF, and continues without service tracing when
	// the tracer cannot start.
	ServiceTracingEnabled bool `mapstructure:"service_tracing_enabled"`
	// ServiceTracingProbeRatePerSecond caps the aggregate service-tracing
	// probe rate of each RNIC (probes per second shared by all of its traced
	// flows, visited in random order). It bounds the probe load whatever
	// the number of flows the applications open.
	ServiceTracingProbeRatePerSecond int `mapstructure:"service_tracing_probe_rate_per_second"`
	// ServiceTracingProbeIntervalMS is the minimum interval between two
	// passes over an RNIC's traced flows, i.e. the per-flow probe interval
	// when the rate cap does not bind.
	ServiceTracingProbeIntervalMS uint32 `mapstructure:"service_tracing_probe_interval_ms"`
	// ServiceTracingServiceLabels is an opt-in allow-list of cgroup v2 path
	// prefixes and their service metric labels. Empty disables attribution.
	ServiceTracingServiceLabels []ServiceLabelMapping `mapstructure:"service_tracing_service_labels"`

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

	// SelfProtectionEnabled turns on the resource watchdog (P2-G): a background
	// goroutine that samples this process's CPU/memory every
	// WatchdogIntervalSec and, on threshold breach, steps the probe-rate
	// multiplier down (fail-slow) to shed load, restoring it on recovery. It
	// defaults to false, so the agent's behavior is unchanged unless opted in.
	SelfProtectionEnabled bool `mapstructure:"self_protection_enabled"`
	// WatchdogIntervalSec is how often the watchdog samples resource usage.
	WatchdogIntervalSec uint32 `mapstructure:"watchdog_interval_sec"`
	// MaxMemoryMB sets a soft runtime memory limit via debug.SetMemoryLimit
	// (GOMEMLIMIT equivalent) at startup; 0 disables it. It is also the
	// reference budget for memory-based throttling (see ThrottleMemoryRatio):
	// memory throttling is inactive when this is 0. Applied whenever > 0,
	// independent of SelfProtectionEnabled, so it can be used as a plain
	// runtime knob.
	MaxMemoryMB int `mapstructure:"max_memory_mb"`
	// MaxProcs caps runtime.GOMAXPROCS at startup; 0 leaves the Go default
	// (all cores). Applied whenever > 0, independent of SelfProtectionEnabled.
	MaxProcs int `mapstructure:"max_procs"`
	// ThrottleMemoryRatio is the fraction of MaxMemoryMB at which memory-based
	// throttling engages (e.g. 0.9 = 90%). Only meaningful when MaxMemoryMB > 0.
	ThrottleMemoryRatio float64 `mapstructure:"throttle_memory_ratio"`
	// ThrottleCPUPercent is the percentage of available CPU capacity (GOMAXPROCS
	// cores) at which CPU-based throttling engages (e.g. 90 = 90%).
	ThrottleCPUPercent float64 `mapstructure:"throttle_cpu_percent"`
}

// agentKeys is the single source of agent config keys, defaults and flag
// help. Order matches the AgentConfig field order; it does not affect
// --help, which pflag sorts by name.
var agentKeys = []keySpec{
	{key: "agent_id", def: "", help: "Agent ID (defaults to hostname if empty)"},
	{key: "hostname", def: "", noFlag: true},
	{key: "tor_id", def: "", help: "Top-of-Rack switch identifier"},
	{key: "device_tor_ids", def: map[string]string{}, noFlag: true},
	{key: "plane_id", def: "", help: "Network plane (rail) of this host's RNICs; restricts inter-ToR and untagged pinglists to the same plane (empty = no restriction)"},
	{key: "device_plane_ids", def: map[string]string{}, noFlag: true},
	{key: "lldp_tor_discovery", def: false, help: "Derive each RDMA device's ToR ID from its LLDP neighbor (lldpd) at startup"},
	{key: "lldp_tor_id_field", def: lldp.FieldSystemName, help: "LLDP neighbor attribute used as the ToR ID: system_name or chassis_id"},
	{key: "lldpcli_path", def: lldp.DefaultCLIPath, help: "Path to the lldpd client used for LLDP ToR discovery"},
	{key: "lldp_discovery_timeout_sec", def: uint32(DefaultLLDPDiscoveryTimeoutSec), help: "Max startup wait for LLDP neighbors on every RDMA device (0 = query once)"},
	{key: "controller_addr", def: "localhost:50051", help: "Controller gRPC address"},
	{key: "log_level", def: "info", help: "Log level (debug, info, warn, error)"},
	{key: "log_format", def: logging.DefaultFormat, help: "Log output format: console or json"},
	{key: "probe_interval_ms", def: uint32(500), help: "Minimum interval in milliseconds between two probes to the same target (per-target rate ceiling)"},
	{key: "otel_collector_addr", def: "localhost:4317", help: "OpenTelemetry collector address"},
	{key: "metrics_enabled", def: true, help: "Enable OpenTelemetry metrics export"},
	{key: "metrics_target_rnic_labels", def: DefaultMetricsTargetRnicLabels, noFlag: true},
	{key: "metrics_target_rnic_labels_scope", def: DefaultMetricsTargetRnicLabelsScope, noFlag: true},
	{key: "metrics_cardinality_limit", def: 0, noFlag: true},
	{key: "metrics_prober_delay_target_tor", def: false, noFlag: true},
	{key: "metrics_responder_delay_target_tor", def: true, noFlag: true},
	{key: "allowed_device_names", def: []string{}, help: "List of allowed RDMA device names (empty = all)"},
	{key: "excluded_device_names", def: []string{}, help: "List of RDMA device names never to open (applied after allowed-device-names)"},
	{key: "excluded_gid_cidrs", def: []string{}, help: "Networks (CIDRs) whose RDMA devices are never used, matched against each device's GID at gid-index"},
	{key: "mapped_devices_only", def: false, help: "Use only the RDMA devices listed in device_tor_ids (requires a non-empty device_tor_ids)"},
	{key: "gid_index", def: 0, help: "GID index to use for RDMA devices (0-255)"},
	{key: "service_level", def: 0, help: "Service Level (SL, PFC priority) for Address Handles (0-7)"},
	{key: "traffic_class", def: 0, help: "GRH traffic class (DSCP << 2) for Address Handles (0-255)"},
	{key: "cq_poll_mode", def: DefaultCQPollMode, help: "CQ poller wait mode: auto, event or busy"},
	{key: "event_ring_capacity", def: uint32(DefaultEventRingCapacity), help: "Completion events each prober/responder event ring holds (power of two, 64-65536)"},
	{key: "pinglist_update_interval_sec", def: uint32(300), help: "Pinglist update interval in seconds"},
	{key: "target_probe_rate_per_second", def: DefaultTargetProbeRatePerSecond, help: "Legacy uniform probe rate per second per target (fallback for the per-type rates below when they are 0)"},
	{key: "tor_mesh_probe_rate_per_second", def: DefaultTorMeshProbeRatePerSecond, help: "Probe rate per second per ToR-mesh target (0 = inherit target-probe-rate-per-second)"},
	{key: "inter_tor_probe_rate_per_second", def: DefaultInterTorProbeRatePerSecond, help: "Probe rate per second per inter-ToR target (0 = inherit target-probe-rate-per-second)"},
	{key: "flow_label_rotation_period_sec", def: uint32(DefaultFlowLabelRotationPeriodSec), help: "Period (seconds) over which the rotating ~20% of each target's ECMP flow-label set is refreshed"},
	{key: "service_tracing_enabled", def: DefaultServiceTracingEnabled, help: "Trace application RDMA connections with eBPF and probe their flows (Linux; needs CAP_BPF and CAP_PERFMON)"},
	{key: "service_tracing_probe_rate_per_second", def: DefaultServiceTracingProbeRatePerSecond, help: "Aggregate service-tracing probe rate per RNIC, shared by all of its traced flows"},
	{key: "service_tracing_probe_interval_ms", def: uint32(DefaultServiceTracingProbeIntervalMS), help: "Minimum interval in milliseconds between two passes over an RNIC's traced flows"},
	{key: "service_tracing_service_labels", def: []ServiceLabelMapping{}, noFlag: true},
	{key: "analysis_report_enabled", def: true, help: "Enable per-path window aggregation and SLO reporting to the controller"},
	{key: "analysis_window_sec", def: uint32(DefaultAnalysisWindowSec), help: "Per-path aggregation window length in seconds"},
	{key: "tls_mode", def: TLSModeDisabled, help: "gRPC transport security mode for the controller connection (disabled|tls|mtls)"},
	{key: "tls_cert_file", def: "", help: "Client certificate file (required when tls-mode=mtls)"},
	{key: "tls_key_file", def: "", help: "Client private key file (required when tls-mode=mtls)"},
	{key: "tls_ca_file", def: "", help: "CA file used to verify the controller's certificate (required when tls-mode is tls or mtls)"},
	{key: "tls_server_name", def: "", help: "Server name for TLS SNI/verification (optional; defaults to the name derived from controller-addr)"},
	{key: "self_protection_enabled", def: DefaultSelfProtectionEnabled, help: "Enable the resource watchdog that throttles probing (fail-slow) under local CPU/memory pressure"},
	{key: "watchdog_interval_sec", def: uint32(DefaultWatchdogIntervalSec), help: "How often the self-protection watchdog samples resource usage (seconds)"},
	{key: "max_memory_mb", def: 0, help: "Soft runtime memory limit in MiB (GOMEMLIMIT via debug.SetMemoryLimit; 0 = disabled). Also the reference budget for memory throttling"},
	{key: "max_procs", def: 0, help: "Cap runtime.GOMAXPROCS to this many cores (0 = Go default: all cores)"},
	{key: "throttle_memory_ratio", def: DefaultThrottleMemoryRatio, help: "Fraction of max-memory-mb at which memory throttling engages (0-1; only when max-memory-mb > 0)"},
	{key: "throttle_cpu_percent", def: float64(DefaultThrottleCPUPercent), help: "Percentage of available CPU capacity (GOMAXPROCS cores) at which CPU throttling engages (0-100)"},
}

// LoadAgentConfig loads agent configuration from a YAML file, environment
// variables, CLI flags, and applies defaults. Precedence (highest to
// lowest) is: CLI flag > environment variable > YAML file > default.
// Environment variables are RPINGMESH_ plus the upper-cased config key
// (e.g., RPINGMESH_CONTROLLER_ADDR). If flags is non-nil, it is bound to
// viper so that explicitly-set flags take priority; pass the same FlagSet
// given to BindAgentFlags.
func LoadAgentConfig(configPath string, flags *pflag.FlagSet) (*AgentConfig, error) {
	v, err := newViper("agent", configPath, flags, agentKeys)
	if err != nil {
		return nil, err
	}

	hostname := v.GetString("hostname")
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to auto-detect hostname: %w", err)
		}
		hostname = h
	}

	agentID := v.GetString("agent_id")
	if agentID == "" {
		agentID = hostname
	}

	config := &AgentConfig{
		AgentID:                          agentID,
		HostName:                         hostname,
		TorID:                            v.GetString("tor_id"),
		DeviceTorIDs:                     canonicalDeviceMap(v.GetStringMapString("device_tor_ids"), probe.CanonicalTorID),
		PlaneID:                          probe.CanonicalPlaneID(v.GetString("plane_id")),
		DevicePlaneIDs:                   canonicalDeviceMap(v.GetStringMapString("device_plane_ids"), probe.CanonicalPlaneID),
		LLDPTorDiscovery:                 v.GetBool("lldp_tor_discovery"),
		LLDPTorIDField:                   v.GetString("lldp_tor_id_field"),
		LLDPCLIPath:                      v.GetString("lldpcli_path"),
		LLDPDiscoveryTimeoutSec:          v.GetUint32("lldp_discovery_timeout_sec"),
		ControllerAddr:                   v.GetString("controller_addr"),
		LogLevel:                         v.GetString("log_level"),
		LogFormat:                        v.GetString("log_format"),
		ProbeIntervalMS:                  v.GetUint32("probe_interval_ms"),
		OtelCollectorAddr:                v.GetString("otel_collector_addr"),
		MetricsEnabled:                   v.GetBool("metrics_enabled"),
		MetricsTargetRnicLabels:          v.GetString("metrics_target_rnic_labels"),
		MetricsTargetRnicLabelsScope:     v.GetString("metrics_target_rnic_labels_scope"),
		MetricsCardinalityLimit:          v.GetInt("metrics_cardinality_limit"),
		MetricsProberDelayTargetTor:      v.GetBool("metrics_prober_delay_target_tor"),
		MetricsResponderDelayTargetTor:   v.GetBool("metrics_responder_delay_target_tor"),
		AllowedDeviceNames:               v.GetStringSlice("allowed_device_names"),
		ExcludedDeviceNames:              v.GetStringSlice("excluded_device_names"),
		ExcludedGIDCIDRs:                 v.GetStringSlice("excluded_gid_cidrs"),
		MappedDevicesOnly:                v.GetBool("mapped_devices_only"),
		GIDIndex:                         v.GetInt("gid_index"),
		ServiceLevel:                     v.GetInt("service_level"),
		TrafficClass:                     v.GetInt("traffic_class"),
		CQPollMode:                       v.GetString("cq_poll_mode"),
		EventRingCapacity:                v.GetUint32("event_ring_capacity"),
		PinglistUpdateIntervalSec:        v.GetUint32("pinglist_update_interval_sec"),
		TargetProbeRatePerSecond:         v.GetInt("target_probe_rate_per_second"),
		TorMeshProbeRatePerSecond:        v.GetInt("tor_mesh_probe_rate_per_second"),
		InterTorProbeRatePerSecond:       v.GetInt("inter_tor_probe_rate_per_second"),
		FlowLabelRotationPeriodSec:       v.GetUint32("flow_label_rotation_period_sec"),
		ServiceTracingEnabled:            v.GetBool("service_tracing_enabled"),
		ServiceTracingProbeRatePerSecond: v.GetInt("service_tracing_probe_rate_per_second"),
		ServiceTracingProbeIntervalMS:    v.GetUint32("service_tracing_probe_interval_ms"),
		AnalysisReportEnabled:            v.GetBool("analysis_report_enabled"),
		AnalysisWindowSec:                v.GetUint32("analysis_window_sec"),
		TLSMode:                          v.GetString("tls_mode"),
		TLSCertFile:                      v.GetString("tls_cert_file"),
		TLSKeyFile:                       v.GetString("tls_key_file"),
		TLSCAFile:                        v.GetString("tls_ca_file"),
		TLSServerName:                    v.GetString("tls_server_name"),
		SelfProtectionEnabled:            v.GetBool("self_protection_enabled"),
		WatchdogIntervalSec:              v.GetUint32("watchdog_interval_sec"),
		MaxMemoryMB:                      v.GetInt("max_memory_mb"),
		MaxProcs:                         v.GetInt("max_procs"),
		ThrottleMemoryRatio:              v.GetFloat64("throttle_memory_ratio"),
		ThrottleCPUPercent:               v.GetFloat64("throttle_cpu_percent"),
	}

	if raw, ok := v.Get("service_tracing_service_labels").(string); ok {
		// Environment variables are strings; Viper cannot decode a JSON
		// array of mappings through UnmarshalKey's slice conversion hook.
		err = json.Unmarshal([]byte(raw), &config.ServiceTracingServiceLabels)
	} else {
		err = v.UnmarshalKey("service_tracing_service_labels", &config.ServiceTracingServiceLabels)
	}
	if err != nil {
		return nil, fmt.Errorf("service_tracing_service_labels: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// BindAgentFlags binds common agent CLI flags to a pflag.FlagSet.
// These flags can later be bound to a viper instance for unified config resolution.
func BindAgentFlags(flags *pflag.FlagSet) {
	registerFlags(flags, agentKeys)
}

// Validate checks that the agent configuration is well-formed. It returns
// an error describing the first invalid field encountered. The helpers run
// in a fixed order so that the first error for a given input is stable.
func (c *AgentConfig) Validate() error {
	// Reject an unknown level at load, as the controller does, instead of
	// silently running at info.
	if _, err := zerolog.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("log_level %q is not a known level: %w", c.LogLevel, err)
	}
	if err := c.validateTorAndPlaneIDs(); err != nil {
		return err
	}
	if err := c.validateDeviceSelection(); err != nil {
		return err
	}
	if err := c.validateRDMAAddressing(); err != nil {
		return err
	}
	if err := logging.ValidateFormat(c.LogFormat); err != nil {
		return err
	}
	if err := c.validateCompletionPolling(); err != nil {
		return err
	}
	if err := c.validateMetrics(); err != nil {
		return err
	}
	if err := c.validateProbing(); err != nil {
		return err
	}
	if err := c.validateServiceTracing(); err != nil {
		return err
	}
	if err := c.validateSelfProtection(); err != nil {
		return err
	}
	if err := validateOTLPEndpoint(c.OtelCollectorAddr); err != nil {
		return err
	}
	// The agent is the gRPC client of the controller connection: fail fast
	// if the certificate files required by tls_mode are missing, rather
	// than at the first dial attempt.
	return validateTLSFiles(tlsRoleClient, c.TLSMode, c.TLSCertFile, c.TLSKeyFile, c.TLSCAFile)
}

// validateTorAndPlaneIDs checks tor_id, device_tor_ids and device_plane_ids.
func (c *AgentConfig) validateTorAndPlaneIDs() error {
	// The display label for unset ToRs must not be used as a real rack name:
	// an older controller would persist it as a named ToR and collide with
	// untagged metric series after upgrade.
	if probe.IsReservedTorID(c.TorID) {
		return fmt.Errorf("tor_id %q is reserved for untagged agents", probe.UnspecifiedTorLabel)
	}
	for dev, tor := range c.DeviceTorIDs {
		if strings.TrimSpace(dev) == "" {
			return fmt.Errorf("device_tor_ids has an empty device name")
		}
		if probe.CanonicalTorID(tor) == "" {
			return fmt.Errorf("device_tor_ids[%s] must not be empty; omit the device to use tor_id", dev)
		}
		if probe.IsReservedTorID(tor) {
			return fmt.Errorf("device_tor_ids[%s] %q is reserved for untagged agents", dev, probe.UnspecifiedTorLabel)
		}
	}

	// Entries naming an excluded or not-allowed device are not errors (a
	// fleet-wide map commonly meets a per-host exclusion); the agent warns
	// about them at startup instead (see resolveDevicePlaneIDs).
	for dev, plane := range c.DevicePlaneIDs {
		if strings.TrimSpace(dev) == "" {
			return fmt.Errorf("device_plane_ids has an empty device name")
		}
		if probe.CanonicalPlaneID(plane) == "" {
			return fmt.Errorf("device_plane_ids[%s] must not be empty; omit the device to use plane_id", dev)
		}
	}
	return nil
}

// validateDeviceSelection checks the device allow/exclude lists,
// excluded_gid_cidrs, mapped_devices_only and the LLDP ToR-discovery field.
func (c *AgentConfig) validateDeviceSelection() error {
	for _, dev := range c.ExcludedDeviceNames {
		if strings.TrimSpace(dev) == "" {
			return fmt.Errorf("excluded_device_names has an empty device name")
		}
	}
	// A device both allowed and excluded is almost certainly a typo or a
	// stale list; fail fast instead of silently picking one.
	for _, dev := range c.AllowedDeviceNames {
		if c.IsDeviceExcluded(dev) {
			return fmt.Errorf("device %q is listed in both allowed_device_names and excluded_device_names", dev)
		}
	}
	for _, cidr := range c.ExcludedGIDCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("excluded_gid_cidrs entry %q is not a CIDR: %w", cidr, err)
		}
	}
	// With nothing mapped, mapped_devices_only would leave no device to open.
	if c.MappedDevicesOnly && len(c.DeviceTorIDs) == 0 {
		return fmt.Errorf("mapped_devices_only requires a non-empty device_tor_ids")
	}

	// An empty field (a zero-value AgentConfig) means the default, system_name.
	if c.LLDPTorIDField != "" && !lldp.ValidField(c.LLDPTorIDField) {
		return fmt.Errorf("lldp_tor_id_field must be %q or %q, got: %q",
			lldp.FieldSystemName, lldp.FieldChassisID, c.LLDPTorIDField)
	}
	return nil
}

// validateRDMAAddressing checks gid_index, service_level and traffic_class,
// the values the agent puts into every Address Handle.
func (c *AgentConfig) validateRDMAAddressing() error {
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
	return nil
}

// validateCompletionPolling checks cq_poll_mode and event_ring_capacity.
func (c *AgentConfig) validateCompletionPolling() error {
	// An empty mode (a zero-value AgentConfig) means the default, auto.
	switch c.CQPollMode {
	case "", CQPollModeAuto, CQPollModeEvent, CQPollModeBusy:
	default:
		return fmt.Errorf("cq_poll_mode must be %q, %q or %q, got: %q",
			CQPollModeAuto, CQPollModeEvent, CQPollModeBusy, c.CQPollMode)
	}

	// Zero (a zero-value AgentConfig) means the default.
	if n := c.EventRingCapacity; n != 0 &&
		(n < MinEventRingCapacity || n > MaxEventRingCapacity || n&(n-1) != 0) {
		return fmt.Errorf("event_ring_capacity must be a power of two between %d and %d, got: %d",
			MinEventRingCapacity, MaxEventRingCapacity, n)
	}
	return nil
}

// validateMetrics checks the metrics_target_rnic_labels* and
// metrics_cardinality_limit knobs.
func (c *AgentConfig) validateMetrics() error {
	// Empty values (a zero-value AgentConfig) mean the defaults, off and
	// stable.
	switch c.MetricsTargetRnicLabels {
	case "", MetricsTargetRnicLabelsOff, MetricsTargetRnicLabelsCounters, MetricsTargetRnicLabelsAll:
	default:
		return fmt.Errorf("metrics_target_rnic_labels must be %q, %q or %q, got: %q",
			MetricsTargetRnicLabelsOff, MetricsTargetRnicLabelsCounters, MetricsTargetRnicLabelsAll,
			c.MetricsTargetRnicLabels)
	}
	switch c.MetricsTargetRnicLabelsScope {
	case "", MetricsTargetRnicLabelsScopeStable, MetricsTargetRnicLabelsScopeAll:
	default:
		return fmt.Errorf("metrics_target_rnic_labels_scope must be %q or %q, got: %q",
			MetricsTargetRnicLabelsScopeStable, MetricsTargetRnicLabelsScopeAll,
			c.MetricsTargetRnicLabelsScope)
	}
	// A negative limit would disable the OTel SDK's cardinality cap entirely,
	// and a limit below the SDK default would also cap the default ToR-level
	// instruments, so only 0 (SDK default) or a raised limit is accepted.
	if c.MetricsCardinalityLimit != 0 && c.MetricsCardinalityLimit < MinMetricsCardinalityLimit {
		return fmt.Errorf("metrics_cardinality_limit must be 0 (OTel SDK default) or >= %d, got: %d",
			MinMetricsCardinalityLimit, c.MetricsCardinalityLimit)
	}
	return nil
}

// validateProbing checks the probe interval, flow-label rotation, per-type
// probe rates and the analysis window.
func (c *AgentConfig) validateProbing() error {
	// A zero probe interval would make time.NewTicker panic at runtime, so
	// reject it up front instead of failing deep in the prober.
	if c.ProbeIntervalMS == 0 {
		return fmt.Errorf("probe_interval_ms must be > 0, got: %d", c.ProbeIntervalMS)
	}

	// A zero rotation period would make the epoch computation divide by zero.
	if c.FlowLabelRotationPeriodSec == 0 {
		return fmt.Errorf("flow_label_rotation_period_sec must be > 0, got: %d", c.FlowLabelRotationPeriodSec)
	}

	// 0 selects the backward-compatible fallback to
	// target_probe_rate_per_second. A negative value is meaningless (the
	// limiter treats <=0 as "disabled", which would silently defeat the
	// intended cap), so reject it up front.
	if c.TorMeshProbeRatePerSecond < 0 {
		return fmt.Errorf("tor_mesh_probe_rate_per_second must be >= 0, got: %d", c.TorMeshProbeRatePerSecond)
	}
	if c.InterTorProbeRatePerSecond < 0 {
		return fmt.Errorf("inter_tor_probe_rate_per_second must be >= 0, got: %d", c.InterTorProbeRatePerSecond)
	}

	// When analysis reporting is on, the window drives a time.Ticker and the
	// aggregator's window alignment, both of which require a positive length.
	if c.AnalysisReportEnabled && c.AnalysisWindowSec == 0 {
		return fmt.Errorf("analysis_window_sec must be > 0 when analysis_report_enabled, got: %d", c.AnalysisWindowSec)
	}
	return nil
}

// validateServiceTracing checks the service-tracing rate and interval. A
// negative rate is always rejected; the positive-value requirements apply
// only when the feature is enabled, so a disabled feature never blocks
// startup over a knob it does not use.
func (c *AgentConfig) validateServiceTracing() error {
	if err := validateServiceLabels(c.ServiceTracingServiceLabels); err != nil {
		return err
	}
	if c.ServiceTracingProbeRatePerSecond < 0 {
		return fmt.Errorf("service_tracing_probe_rate_per_second must be >= 0, got: %d", c.ServiceTracingProbeRatePerSecond)
	}
	if !c.ServiceTracingEnabled {
		return nil
	}
	// Without a cap the prober would send every traced flow back-to-back
	// each pass, and applications, not the controller, set the flow count.
	if c.ServiceTracingProbeRatePerSecond == 0 {
		return fmt.Errorf("service_tracing_probe_rate_per_second must be > 0 when service_tracing_enabled")
	}
	// A zero interval would make the service pass restart without pause.
	if c.ServiceTracingProbeIntervalMS == 0 {
		return fmt.Errorf("service_tracing_probe_interval_ms must be > 0 when service_tracing_enabled")
	}
	return nil
}

// validateSelfProtection checks the runtime limits and, only when the
// watchdog is enabled, its thresholds.
func (c *AgentConfig) validateSelfProtection() error {
	// Hard runtime limits are honored regardless of self-protection, so range
	// checks always apply. Negative values are meaningless (the runtime APIs
	// take non-negative sizes/counts), so reject them up front.
	if c.MaxMemoryMB < 0 {
		return fmt.Errorf("max_memory_mb must be >= 0, got: %d", c.MaxMemoryMB)
	}
	if c.MaxProcs < 0 {
		return fmt.Errorf("max_procs must be >= 0, got: %d", c.MaxProcs)
	}

	// The throttle thresholds only drive behavior when self-protection is
	// enabled; validate them only then so a disabled feature never blocks
	// startup over a knob it does not use.
	if !c.SelfProtectionEnabled {
		return nil
	}
	// The interval drives a time.Ticker, which panics on a non-positive
	// period.
	if c.WatchdogIntervalSec == 0 {
		return fmt.Errorf("watchdog_interval_sec must be > 0 when self_protection_enabled, got: %d", c.WatchdogIntervalSec)
	}
	// The memory ratio is a fraction of the limit; a value outside (0, 1]
	// would trigger either never or only after exceeding the limit.
	if c.ThrottleMemoryRatio <= 0 || c.ThrottleMemoryRatio > 1 {
		return fmt.Errorf("throttle_memory_ratio must be in (0, 1] when self_protection_enabled, got: %g", c.ThrottleMemoryRatio)
	}
	// CPU is measured as a percentage of GOMAXPROCS-core capacity, so the
	// threshold lives in (0, 100].
	if c.ThrottleCPUPercent <= 0 || c.ThrottleCPUPercent > 100 {
		return fmt.Errorf("throttle_cpu_percent must be in (0, 100] when self_protection_enabled, got: %g", c.ThrottleCPUPercent)
	}
	return nil
}

// EffectiveTorMeshProbeRate returns the per-target probe rate (probes/sec) to
// apply to ToR-mesh targets. TorMeshProbeRatePerSecond takes effect when it is
// positive; otherwise it falls back to TargetProbeRatePerSecond so a deployment
// that only set the legacy uniform rate keeps its behavior unchanged.
func (c *AgentConfig) EffectiveTorMeshProbeRate() int {
	if c.TorMeshProbeRatePerSecond > 0 {
		return c.TorMeshProbeRatePerSecond
	}
	return c.TargetProbeRatePerSecond
}

// EffectiveInterTorProbeRate returns the per-target probe rate (probes/sec) to
// apply to inter-ToR targets, using the same fallback rule as
// EffectiveTorMeshProbeRate.
func (c *AgentConfig) EffectiveInterTorProbeRate() int {
	if c.InterTorProbeRatePerSecond > 0 {
		return c.InterTorProbeRatePerSecond
	}
	return c.TargetProbeRatePerSecond
}

// deviceNameMatches reports whether a configured device name refers to
// deviceName. Both sides are trimmed and compared case-insensitively, so
// YAML spacing and the casing of a kernel device name never cause a miss.
func deviceNameMatches(configured, deviceName string) bool {
	return strings.EqualFold(strings.TrimSpace(configured), strings.TrimSpace(deviceName))
}

// containsDeviceName reports whether names lists deviceName (see
// deviceNameMatches).
func containsDeviceName(names []string, deviceName string) bool {
	for _, n := range names {
		if deviceNameMatches(n, deviceName) {
			return true
		}
	}
	return false
}

// lookupDeviceName returns the value keyed by deviceName in a device map
// (see deviceNameMatches) and whether one exists. It scans rather than
// indexing so that maps built by hand (not through canonicalDeviceMap)
// still match case-insensitively.
func lookupDeviceName(m map[string]string, deviceName string) (string, bool) {
	for dev, val := range m {
		if deviceNameMatches(dev, deviceName) {
			return val, true
		}
	}
	return "", false
}

// canonicalDeviceMap lower-cases device-name keys and canonicalizes values
// with canon (probe.CanonicalTorID or probe.CanonicalPlaneID). An empty
// input yields nil.
func canonicalDeviceMap(in map[string]string, canon func(string) string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for dev, val := range in {
		out[strings.ToLower(strings.TrimSpace(dev))] = canon(val)
	}
	return out
}

// IsDeviceAllowed reports whether an RDMA device passes allowed_device_names
// (an empty list allows every device). Device names match case-insensitively.
func (c *AgentConfig) IsDeviceAllowed(deviceName string) bool {
	if len(c.AllowedDeviceNames) == 0 {
		return true
	}
	return containsDeviceName(c.AllowedDeviceNames, deviceName)
}

// IsDeviceExcluded reports whether an RDMA device is listed in
// excluded_device_names. Device names match case-insensitively.
func (c *AgentConfig) IsDeviceExcluded(deviceName string) bool {
	return containsDeviceName(c.ExcludedDeviceNames, deviceName)
}

// ExcludedGIDCIDR returns the excluded_gid_cidrs entry that contains ip (a
// device's GID formatted as an IP address) and whether one does. An IPv4
// address matches IPv4 networks whether it is written dotted or
// IPv4-mapped. Entries are assumed valid (see Validate).
func (c *AgentConfig) ExcludedGIDCIDR(ip string) (string, bool) {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return "", false
	}
	for _, cidr := range c.ExcludedGIDCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && network.Contains(addr) {
			return strings.TrimSpace(cidr), true
		}
	}
	return "", false
}

// DeviceTorID returns the canonical device_tor_ids entry for an RDMA device
// and whether one exists. Device names match case-insensitively.
func (c *AgentConfig) DeviceTorID(deviceName string) (string, bool) {
	tor, ok := lookupDeviceName(c.DeviceTorIDs, deviceName)
	if !ok {
		return "", false
	}
	return probe.CanonicalTorID(tor), true
}

// TorIDForDevice returns the canonical ToR ID for an RDMA device: its
// device_tor_ids entry when present, otherwise the host-wide tor_id.
func (c *AgentConfig) TorIDForDevice(deviceName string) string {
	if tor, ok := c.DeviceTorID(deviceName); ok {
		return tor
	}
	return probe.CanonicalTorID(c.TorID)
}

// DevicePlaneID returns the canonical device_plane_ids entry for an RDMA
// device and whether one exists. Device names match case-insensitively.
func (c *AgentConfig) DevicePlaneID(deviceName string) (string, bool) {
	plane, ok := lookupDeviceName(c.DevicePlaneIDs, deviceName)
	if !ok {
		return "", false
	}
	return probe.CanonicalPlaneID(plane), true
}

// PlaneIDForDevice returns the canonical plane of an RDMA device: its
// device_plane_ids entry when present, otherwise the host-wide plane_id.
func (c *AgentConfig) PlaneIDForDevice(deviceName string) string {
	if plane, ok := c.DevicePlaneID(deviceName); ok {
		return plane
	}
	return probe.CanonicalPlaneID(c.PlaneID)
}

// EffectiveEventRingCapacity returns EventRingCapacity, or
// DefaultEventRingCapacity when it is unset (0).
func (c *AgentConfig) EffectiveEventRingCapacity() int {
	if c.EventRingCapacity == 0 {
		return DefaultEventRingCapacity
	}
	return int(c.EventRingCapacity)
}
