package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// AnalyzerConfig holds configuration for the analyzer
type AnalyzerConfig struct {
	ListenAddr  string
	DatabaseURI string
	LogLevel    string
}

// SetupAnalyzerFlags sets up the command line flags for the analyzer
func SetupAnalyzerFlags(flagSet *pflag.FlagSet) {
	flagSet.String("config", "", "Path to configuration file")
	flagSet.Bool("create-config", false, "Create a default configuration file")
	flagSet.String("config-output", "analyzer.yaml", "Path where to write the default configuration")
	flagSet.Bool("version", false, "Show version information")
	flagSet.String("listen-addr", "0.0.0.0:50052", "Address to listen on for gRPC connections")
	flagSet.String("database-uri", "http://localhost:4001", "URI for the database connection")
	flagSet.String("log-level", "info", "Log level (debug, info, warn, error)")
}

// LoadAnalyzerConfig loads the configuration for an analyzer from a file or environment variables
func LoadAnalyzerConfig(flagSet *pflag.FlagSet) (*AnalyzerConfig, error) {
	v := viper.New()

	// Set environment variable prefix
	v.SetEnvPrefix("RPINGMESH_ANALYZER")
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
	config := &AnalyzerConfig{
		ListenAddr:  v.GetString("listen-addr"),
		DatabaseURI: v.GetString("database-uri"),
		LogLevel:    v.GetString("log-level"),
	}

	return config, nil
}

// CreateDefaultAnalyzerConfig creates a default configuration file for an analyzer
func CreateDefaultAnalyzerConfig(path string) error {
	v := viper.New()
	v.SetConfigFile(path)

	// Set default values
	v.Set("listen-addr", "0.0.0.0:50052")
	v.Set("database-uri", "http://localhost:4001")
	v.Set("log-level", "info")

	// Write the config file
	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
