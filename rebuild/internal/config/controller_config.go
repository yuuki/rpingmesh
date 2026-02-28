package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// ControllerConfig holds all configuration for the controller.
type ControllerConfig struct {
	ListenAddr  string `mapstructure:"listen_addr"`
	DatabaseURI string `mapstructure:"database_uri"`
	LogLevel    string `mapstructure:"log_level"`
}

// LoadControllerConfig loads controller configuration from a YAML file, environment
// variables, and applies defaults. Environment variables use the prefix RPINGMESH_
// and replace dots with underscores (e.g., RPINGMESH_LISTEN_ADDR).
func LoadControllerConfig(configPath string) (*ControllerConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("listen_addr", ":50051")
	v.SetDefault("database_uri", "http://localhost:4001")
	v.SetDefault("log_level", "info")

	// Enable environment variable override with RPINGMESH_ prefix
	v.SetEnvPrefix("RPINGMESH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Load config file if a path was provided
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Search default locations when no explicit path is given
		v.SetConfigName("controller")
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

	config := &ControllerConfig{
		ListenAddr:  v.GetString("listen_addr"),
		DatabaseURI: v.GetString("database_uri"),
		LogLevel:    v.GetString("log_level"),
	}

	return config, nil
}

// BindControllerFlags binds common controller CLI flags to a pflag.FlagSet.
// These flags can later be bound to a viper instance for unified config resolution.
func BindControllerFlags(flags *pflag.FlagSet) {
	flags.String("listen-addr", ":50051", "Address to listen on for gRPC connections")
	flags.String("database-uri", "http://localhost:4001", "rqlite database connection URI")
	flags.String("log-level", "info", "Log level (debug, info, warn, error)")
}
