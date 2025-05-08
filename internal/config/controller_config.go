package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// ControllerConfig holds configuration for the controller
type ControllerConfig struct {
	ListenAddr  string
	DatabaseURI string
	LogLevel    string
}

// LoadControllerConfig loads the configuration for a controller from a file or environment variables
func LoadControllerConfig(configPath string) (*ControllerConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("listen_addr", "0.0.0.0:50051")
	v.SetDefault("database_uri", "http://localhost:4001")
	v.SetDefault("log_level", "info")

	// Environment variables
	v.SetEnvPrefix("RPINGMESH_CONTROLLER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config in default locations
		v.SetConfigName("controller")
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

	var config ControllerConfig
	config.ListenAddr = v.GetString("listen_addr")
	config.DatabaseURI = v.GetString("database_uri")
	config.LogLevel = v.GetString("log_level")

	return &config, nil
}

// CreateDefaultControllerConfig creates a default configuration file for a controller
func CreateDefaultControllerConfig(path string) error {
	// Default config content
	configContent := `# RPingMesh Controller Configuration
listen_addr: "0.0.0.0:50051"
database_uri: "http://localhost:4001"
log_level: "info" # debug, info, warn, error
`

	return writeConfigFile(path, configContent)
}
