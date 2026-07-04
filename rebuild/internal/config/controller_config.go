package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Default threshold values for the controller's RNIC registry. These mirror
// registry.Default{Active,Stale}ThresholdSec / DefaultInterTorSampleSize so
// that config defaults and registry defaults stay in sync without the
// config package importing the controller/registry package.
const (
	// DefaultActiveThresholdSec is the window (seconds) within which an
	// RNIC entry is considered "active" for pinglist generation.
	DefaultActiveThresholdSec = 300
	// DefaultStaleThresholdSec is the window (seconds) after which an RNIC
	// entry is considered stale and removed.
	DefaultStaleThresholdSec = 900
	// DefaultInterTorSampleSize is the default number of distinct ToRs
	// sampled for inter-ToR pinglist generation.
	DefaultInterTorSampleSize = 5
)

// ControllerConfig holds all configuration for the controller.
type ControllerConfig struct {
	ListenAddr         string `mapstructure:"listen_addr"`
	DatabaseURI        string `mapstructure:"database_uri"`
	LogLevel           string `mapstructure:"log_level"`
	ActiveThresholdSec int    `mapstructure:"active_threshold_sec"`
	StaleThresholdSec  int    `mapstructure:"stale_threshold_sec"`
	InterTorSampleSize int    `mapstructure:"inter_tor_sample_size"`
}

// LoadControllerConfig loads controller configuration from a YAML file,
// environment variables, CLI flags, and applies defaults. Precedence
// (highest to lowest) is: CLI flag > environment variable > YAML file >
// default. Environment variables use the prefix RPINGMESH_ and replace dots
// with underscores (e.g., RPINGMESH_LISTEN_ADDR). If flags is non-nil, it is
// bound to viper via BindPFlags so that explicitly-set flags take priority;
// pass the same FlagSet given to BindControllerFlags.
func LoadControllerConfig(configPath string, flags *pflag.FlagSet) (*ControllerConfig, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("listen_addr", ":50051")
	v.SetDefault("database_uri", "http://localhost:4001")
	v.SetDefault("log_level", "info")
	v.SetDefault("active_threshold_sec", DefaultActiveThresholdSec)
	v.SetDefault("stale_threshold_sec", DefaultStaleThresholdSec)
	v.SetDefault("inter_tor_sample_size", DefaultInterTorSampleSize)

	// Enable environment variable override with RPINGMESH_ prefix
	v.SetEnvPrefix("RPINGMESH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind CLI flags so that explicitly-set flags take precedence over
	// environment variables, config file values, and defaults.
	if flags != nil {
		if err := bindPFlags(v, flags); err != nil {
			return nil, err
		}
	}

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
		ListenAddr:         v.GetString("listen_addr"),
		DatabaseURI:        v.GetString("database_uri"),
		LogLevel:           v.GetString("log_level"),
		ActiveThresholdSec: v.GetInt("active_threshold_sec"),
		StaleThresholdSec:  v.GetInt("stale_threshold_sec"),
		InterTorSampleSize: v.GetInt("inter_tor_sample_size"),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// bindPFlags binds each flag in flags to v under a key with hyphens
// replaced by underscores (e.g. "listen-addr" -> "listen_addr"), so that CLI
// flag names resolve to the same viper key used by the YAML config,
// environment variables (via SetEnvKeyReplacer), and struct mapstructure
// tags. viper.BindPFlags alone would bind flags under their literal
// hyphenated names, which would never match a "_"-separated lookup key and
// would silently make flags dead weight.
func bindPFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	var bindErr error
	flags.VisitAll(func(f *pflag.Flag) {
		if bindErr != nil {
			return
		}
		key := strings.ReplaceAll(f.Name, "-", "_")
		if err := v.BindPFlag(key, f); err != nil {
			bindErr = fmt.Errorf("failed to bind flag %q: %w", f.Name, err)
		}
	})
	return bindErr
}

// Validate checks that the controller configuration is well-formed. It
// returns an error describing the first invalid field encountered.
func (c *ControllerConfig) Validate() error {
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("listen_addr must not be empty")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr %q is not a valid address: %w", c.ListenAddr, err)
	}

	if strings.TrimSpace(c.DatabaseURI) == "" {
		return fmt.Errorf("database_uri must not be empty")
	}
	u, err := url.Parse(c.DatabaseURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("database_uri %q is not a valid URL", c.DatabaseURI)
	}

	if _, err := zerolog.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("log_level %q is not a known level: %w", c.LogLevel, err)
	}

	if c.ActiveThresholdSec <= 0 {
		return fmt.Errorf("active_threshold_sec must be > 0, got: %d", c.ActiveThresholdSec)
	}
	if c.StaleThresholdSec <= 0 {
		return fmt.Errorf("stale_threshold_sec must be > 0, got: %d", c.StaleThresholdSec)
	}
	if c.InterTorSampleSize <= 0 {
		return fmt.Errorf("inter_tor_sample_size must be > 0, got: %d", c.InterTorSampleSize)
	}

	return nil
}

// BindControllerFlags binds common controller CLI flags to a pflag.FlagSet.
// These flags can later be bound to a viper instance for unified config resolution.
func BindControllerFlags(flags *pflag.FlagSet) {
	flags.String("listen-addr", ":50051", "Address to listen on for gRPC connections")
	flags.String("database-uri", "http://localhost:4001", "rqlite database connection URI")
	flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	flags.Int("active-threshold-sec", DefaultActiveThresholdSec, "Window (seconds) within which an RNIC is considered active")
	flags.Int("stale-threshold-sec", DefaultStaleThresholdSec, "Window (seconds) after which an inactive RNIC is removed")
	flags.Int("inter-tor-sample-size", DefaultInterTorSampleSize, "Number of distinct ToRs sampled for inter-ToR pinglists")
}
