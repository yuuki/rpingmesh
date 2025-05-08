package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// ControllerConfig holds configuration for the controller
type ControllerConfig struct {
	ListenAddr  string
	DatabaseURI string
	LogLevel    string
}

// SetupControllerFlags sets up the command line flags for the controller
func SetupControllerFlags(flagSet *pflag.FlagSet) {
	flagSet.String("config", "", "Path to configuration file")
	flagSet.Bool("create-config", false, "Create a default configuration file")
	flagSet.String("config-output", "controller.yaml", "Path where to write the default configuration")
	flagSet.Bool("version", false, "Show version information")
	flagSet.String("listen-addr", "0.0.0.0:50051", "Address to listen on for gRPC connections")
	flagSet.String("database-uri", "http://localhost:4001", "URI for the database connection")
	flagSet.String("log-level", "info", "Log level (debug, info, warn, error)")
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

// LoadControllerConfigWithFlags loads the configuration for a controller using viper and flags
func LoadControllerConfigWithFlags() (*ControllerConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("listen-addr", "0.0.0.0:50051")
	v.SetDefault("database-uri", "http://localhost:4001")
	v.SetDefault("log-level", "info")

	// Setup for environment variables
	v.SetEnvPrefix("RPINGMESH_CONTROLLER")
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
		v.SetConfigName("controller")
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
	config := &ControllerConfig{
		ListenAddr:  v.GetString("listen-addr"),
		DatabaseURI: v.GetString("database-uri"),
		LogLevel:    v.GetString("log-level"),
	}

	return config, nil
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
