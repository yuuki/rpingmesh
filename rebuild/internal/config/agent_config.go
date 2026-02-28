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

// AgentConfig holds all configuration for the agent.
type AgentConfig struct {
	AgentID                   string   `mapstructure:"agent_id"`
	HostName                  string   `mapstructure:"hostname"`
	TorID                     string   `mapstructure:"tor_id"`
	ControllerAddr            string   `mapstructure:"controller_addr"`
	LogLevel                  string   `mapstructure:"log_level"`
	ProbeIntervalMS           uint32   `mapstructure:"probe_interval_ms"`
	OtelCollectorAddr         string   `mapstructure:"otel_collector_addr"`
	MetricsEnabled            bool     `mapstructure:"metrics_enabled"`
	AllowedDeviceNames        []string `mapstructure:"allowed_device_names"`
	GIDIndex                  int      `mapstructure:"gid_index"`
	PinglistUpdateIntervalSec uint32   `mapstructure:"pinglist_update_interval_sec"`
	TargetProbeRatePerSecond  int      `mapstructure:"target_probe_rate_per_second"`
}

// LoadAgentConfig loads agent configuration from a YAML file, environment variables,
// and applies defaults. Environment variables use the prefix RPINGMESH_ and replace
// hyphens with underscores (e.g., RPINGMESH_CONTROLLER_ADDR).
func LoadAgentConfig(configPath string) (*AgentConfig, error) {
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
	v.SetDefault("pinglist_update_interval_sec", 300)
	v.SetDefault("target_probe_rate_per_second", DefaultTargetProbeRatePerSecond)

	// Enable environment variable override with RPINGMESH_ prefix.
	// Underscores in env var names map to underscores in config keys.
	v.SetEnvPrefix("RPINGMESH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

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
		AgentID:                   agentID,
		HostName:                  hostname,
		TorID:                     v.GetString("tor_id"),
		ControllerAddr:            v.GetString("controller_addr"),
		LogLevel:                  v.GetString("log_level"),
		ProbeIntervalMS:           v.GetUint32("probe_interval_ms"),
		OtelCollectorAddr:         v.GetString("otel_collector_addr"),
		MetricsEnabled:            v.GetBool("metrics_enabled"),
		AllowedDeviceNames:        v.GetStringSlice("allowed_device_names"),
		GIDIndex:                  v.GetInt("gid_index"),
		PinglistUpdateIntervalSec: v.GetUint32("pinglist_update_interval_sec"),
		TargetProbeRatePerSecond:  v.GetInt("target_probe_rate_per_second"),
	}

	// Validate GID index is non-negative
	if config.GIDIndex < 0 {
		return nil, fmt.Errorf("gid_index must be >= 0, got: %d", config.GIDIndex)
	}

	return config, nil
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
	flags.Int("gid-index", 0, "GID index to use for RDMA devices (must be >= 0)")
	flags.Uint32("pinglist-update-interval-sec", 300, "Pinglist update interval in seconds")
	flags.Int("target-probe-rate-per-second", DefaultTargetProbeRatePerSecond, "Probe rate per second per target")
}
