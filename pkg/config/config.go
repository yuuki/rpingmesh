package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for the agent
type Config struct {
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

// LoadConfig loads the configuration from a file or environment variables
func LoadConfig(configPath string) (*Config, error) {
	// Set defaults
	viper.SetDefault("agent_id", getHostname())
	viper.SetDefault("controller_addr", "localhost:50051")
	viper.SetDefault("analyzer_addr", "localhost:50052")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("probe_interval_ms", 1000)        // 1 second default
	viper.SetDefault("timeout_ms", 500)                // 500 ms default
	viper.SetDefault("data_upload_interval_ms", 10000) // 10 seconds
	viper.SetDefault("traceroute_interval_ms", 300000) // 5 minutes
	viper.SetDefault("traceroute_on_timeout", true)
	viper.SetDefault("ebpf_enabled", true)

	// Environment variables
	viper.SetEnvPrefix("RPINGMESH")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Config file
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		// Look for config in default locations
		viper.SetConfigName("agent")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.rpingmesh")
		viper.AddConfigPath("/etc/rpingmesh")
	}

	if err := viper.ReadInConfig(); err != nil {
		// It's okay if config file is not found, but other errors should be handled
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	config.AgentID = viper.GetString("agent_id")
	config.ControllerAddr = viper.GetString("controller_addr")
	config.AnalyzerAddr = viper.GetString("analyzer_addr")
	config.LogLevel = viper.GetString("log_level")
	config.ProbeIntervalMS = viper.GetUint32("probe_interval_ms")
	config.TimeoutMS = viper.GetUint32("timeout_ms")
	config.DataUploadIntervalMS = viper.GetUint32("data_upload_interval_ms")
	config.TracerouteIntervalMS = viper.GetUint32("traceroute_interval_ms")
	config.TracerouteOnTimeout = viper.GetBool("traceroute_on_timeout")
	config.EBPFEnabled = viper.GetBool("ebpf_enabled")

	return &config, nil
}

// getHostname returns the system hostname or a fallback string
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		// Fallback to a random identifier
		return fmt.Sprintf("agent-%d", os.Getpid())
	}
	return hostname
}

// CreateDefaultConfig creates a default configuration file
func CreateDefaultConfig(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating config directory: %w", err)
		}
	}

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

	// Write the config file
	if err := os.WriteFile(path, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
