package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// AgentConfig holds configuration for the agent
type AgentConfig struct {
	AgentID              string
	ControllerAddr       string
	AnalyzerAddr         string
	LogLevel             string
	ProbeIntervalMS      uint32
	TimeoutMS            uint32
	DataUploadIntervalMS uint32
	TracerouteIntervalMS uint32
	TracerouteOnTimeout  bool
	EBPFEnabled          bool
	OtelCollectorAddr    string
	MetricsEnabled       bool
	AnalyzerEnabled      bool
	TracerEnabled        bool
	AllowedDeviceNames   []string
	GIDIndex             int
}

// SetupAgentFlags sets up the command line flags for the agent
func SetupAgentFlags(flagSet *pflag.FlagSet) {
	flagSet.String("config", "", "Path to configuration file")
	flagSet.Bool("create-config", false, "Create a default configuration file")
	flagSet.String("config-output", "agent.yaml", "Path where to write the default configuration")
	flagSet.Bool("version", false, "Show version information")
	flagSet.String("agent-id", "", "Agent ID (defaults to hostname if empty)")
	flagSet.String("controller-addr", "localhost:50051", "Controller address")
	flagSet.String("analyzer-addr", "localhost:50052", "Analyzer address")
	flagSet.String("log-level", "info", "Log level (debug, info, warn, error)")
	flagSet.Uint32("probe-interval-ms", 500, "Probe interval in milliseconds")
	flagSet.Uint32("timeout-ms", 500, "Timeout in milliseconds")
	flagSet.Uint32("data-upload-interval-ms", 10000, "Data upload interval in milliseconds")
	flagSet.Uint32("traceroute-interval-ms", 300000, "Traceroute interval in milliseconds")
	flagSet.Bool("traceroute-on-timeout", true, "Run traceroute on probe timeout")
	flagSet.Bool("ebpf-enabled", true, "Enable eBPF monitoring")
	flagSet.String("otel-collector-addr", "grpc://localhost:4317", "OpenTelemetry collector address (e.g., grpc://localhost:4317, grpcs://localhost:4317, http://localhost:4318, https://localhost:4318)")
	flagSet.Bool("metrics-enabled", true, "Enable OpenTelemetry metrics")
	flagSet.Bool("analyzer-enabled", false, "Enable data upload to Analyzer")
	flagSet.Bool("tracer-enabled", false, "Enable traceroute functionality")
	flagSet.StringSlice("allowed-device-names", []string{}, "List of allowed device names for pinglist filtering (whitelist)")
	flagSet.Int("gid-index", 0, "GID Index to use for RDMA devices (default: 0). Must be >= 0.")
}

// LoadAgentConfig loads the configuration for an agent from a file or environment variables
func LoadAgentConfig(flagSet *pflag.FlagSet) (*AgentConfig, error) {
	// Create a new viper instance
	v := viper.New()

	// Set environment variable prefix
	v.SetEnvPrefix("RPINGMESH")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	// Bind flags to viper
	if err := v.BindPFlags(flagSet); err != nil {
		return nil, fmt.Errorf("failed to bind flags: %w", err)
	}

	// Check if a config file was specified
	if configFile := v.GetString("config"); configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Create config
	config := &AgentConfig{
		AgentID:              v.GetString("agent-id"),
		ControllerAddr:       v.GetString("controller-addr"),
		AnalyzerAddr:         v.GetString("analyzer-addr"),
		LogLevel:             v.GetString("log-level"),
		ProbeIntervalMS:      v.GetUint32("probe-interval-ms"),
		TimeoutMS:            v.GetUint32("timeout-ms"),
		DataUploadIntervalMS: v.GetUint32("data-upload-interval-ms"),
		TracerouteIntervalMS: v.GetUint32("traceroute-interval-ms"),
		TracerouteOnTimeout:  v.GetBool("traceroute-on-timeout"),
		EBPFEnabled:          v.GetBool("ebpf-enabled"),
		OtelCollectorAddr:    v.GetString("otel-collector-addr"),
		MetricsEnabled:       v.GetBool("metrics-enabled"),
		AnalyzerEnabled:      v.GetBool("analyzer-enabled"),
		TracerEnabled:        v.GetBool("tracer-enabled"),
		AllowedDeviceNames:   v.GetStringSlice("allowed-device-names"),
		GIDIndex:             v.GetInt("gid-index"),
	}

	if config.GIDIndex < 0 {
		return nil, fmt.Errorf("gid-index must be greater than or equal to 0, got: %d", config.GIDIndex)
	}

	return config, nil
}

// WriteDefaultConfig writes a default configuration file
func WriteDefaultConfig(path string) error {
	v := viper.New()
	v.SetConfigFile(path)

	// Set default values
	v.Set("agent-id", "")
	v.Set("controller-addr", "localhost:50051")
	v.Set("analyzer-addr", "localhost:50052")
	v.Set("log-level", "info")
	v.Set("probe-interval-ms", 1000)
	v.Set("timeout-ms", 500)
	v.Set("data-upload-interval-ms", 10000)
	v.Set("traceroute-interval-ms", 300000)
	v.Set("traceroute-on-timeout", true)
	v.Set("ebpf-enabled", true)
	v.Set("otel-collector-addr", "grpc://localhost:4317")
	v.Set("metrics-enabled", true)
	v.Set("analyzer-enabled", false)
	v.Set("tracer-enabled", false)
	v.Set("allowed-device-names", []string{})
	v.Set("gid-index", 0)

	// Write the config file
	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
