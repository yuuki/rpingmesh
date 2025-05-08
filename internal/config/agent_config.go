package config

import (
	"fmt"
	"strings"

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
