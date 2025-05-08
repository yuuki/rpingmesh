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
	flagSet.Uint32("probe-interval-ms", 1000, "Probe interval in milliseconds")
	flagSet.Uint32("timeout-ms", 500, "Timeout in milliseconds")
	flagSet.Uint32("data-upload-interval-ms", 10000, "Data upload interval in milliseconds")
	flagSet.Uint32("traceroute-interval-ms", 300000, "Traceroute interval in milliseconds")
	flagSet.Bool("traceroute-on-timeout", true, "Run traceroute on probe timeout")
	flagSet.Bool("ebpf-enabled", true, "Enable eBPF monitoring")
}

// LoadAgentConfig loads the configuration for an agent from a file or environment variables
func LoadAgentConfig(configPath string) (*AgentConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("agent_id", getSystemHostname())
	v.SetDefault("controller_addr", "localhost:50051")
	v.SetDefault("analyzer_addr", "localhost:50052")
	v.SetDefault("log_level", "info")
	v.SetDefault("probe_interval_ms", 1000)        // 1 second default
	v.SetDefault("timeout_ms", 500)                // 500 ms default
	v.SetDefault("data_upload_interval_ms", 10000) // 10 seconds
	v.SetDefault("traceroute_interval_ms", 300000) // 5 minutes
	v.SetDefault("traceroute_on_timeout", true)
	v.SetDefault("ebpf_enabled", true)

	// Environment variables
	v.SetEnvPrefix("RPINGMESH_AGENT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config in default locations
		v.SetConfigName("agent")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.rpingmesh")
		v.AddConfigPath("/etc/rpingmesh")
	}

	if err := v.ReadInConfig(); err != nil {
		// It's okay if config file is not found, but other errors should be handled
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config AgentConfig
	config.AgentID = v.GetString("agent_id")
	config.ControllerAddr = v.GetString("controller_addr")
	config.AnalyzerAddr = v.GetString("analyzer_addr")
	config.LogLevel = v.GetString("log_level")
	config.ProbeIntervalMS = v.GetUint32("probe_interval_ms")
	config.TimeoutMS = v.GetUint32("timeout_ms")
	config.DataUploadIntervalMS = v.GetUint32("data_upload_interval_ms")
	config.TracerouteIntervalMS = v.GetUint32("traceroute_interval_ms")
	config.TracerouteOnTimeout = v.GetBool("traceroute_on_timeout")
	config.EBPFEnabled = v.GetBool("ebpf_enabled")

	return &config, nil
}

// LoadAgentConfigWithFlags loads the configuration for an agent using viper and flags
func LoadAgentConfigWithFlags() (*AgentConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("agent-id", getSystemHostname())
	v.SetDefault("controller-addr", "localhost:50051")
	v.SetDefault("analyzer-addr", "localhost:50052")
	v.SetDefault("log-level", "info")
	v.SetDefault("probe-interval-ms", 1000)        // 1 second default
	v.SetDefault("timeout-ms", 500)                // 500 ms default
	v.SetDefault("data-upload-interval-ms", 10000) // 10 seconds
	v.SetDefault("traceroute-interval-ms", 300000) // 5 minutes
	v.SetDefault("traceroute-on-timeout", true)
	v.SetDefault("ebpf-enabled", true)

	// Setup for environment variables
	v.SetEnvPrefix("RPINGMESH_AGENT")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Bind command line flags
	v.BindPFlags(pflag.CommandLine)

	// Try to load config file if provided
	configPath := v.GetString("config")
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		// Look for config in default locations if no explicit path provided
		v.SetConfigName("agent")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.rpingmesh")
		v.AddConfigPath("/etc/rpingmesh")

		// Try to read config, but don't error if not found
		if err := v.ReadInConfig(); err != nil {
			// It's okay if config file is not found, but other errors should be handled
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("error reading config file: %w", err)
			}
		}
	}

	// Create config from viper values
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
	}

	return config, nil
}

// CreateDefaultAgentConfig creates a default configuration file for an agent
func CreateDefaultAgentConfig(path string) error {
	// Default config content
	configContent := `# RPingMesh Agent Configuration
agent_id: "" # Leave empty to use hostname
controller_addr: "localhost:50051"
analyzer_addr: "localhost:50052"
log_level: "info" # debug, info, warn, error
probe_interval_ms: 1000 # 1 second
timeout_ms: 500 # 500 milliseconds
data_upload_interval_ms: 10000 # 10 seconds
traceroute_interval_ms: 300000 # 5 minutes
traceroute_on_timeout: true
ebpf_enabled: true
`

	return writeConfigFile(path, configContent)
}
