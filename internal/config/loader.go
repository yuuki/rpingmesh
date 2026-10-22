package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// keySpec describes one configuration key of a binary: its Viper key (the
// snake_case YAML key), its default, and the help text of its CLI flag. One
// table per binary drives both v.SetDefault and the flag registration, so a
// default literal exists exactly once and a flag can never drift from its
// key's default.
//
// The dynamic type of def selects the pflag type (string, bool, int,
// uint32, uint64, float64 or []string), so a default must carry the Go type
// of the struct field it feeds (e.g. uint32(500), not 500, for a Uint32
// flag). The flag name is the key with "_" replaced by "-", the inverse of
// bindPFlags.
type keySpec struct {
	key  string
	def  any
	help string
	// noFlag marks keys that are deliberately file/env-only: hostname (the
	// OS hostname is the intended source), the device maps (not expressible
	// as a flag) and the metrics cardinality knobs.
	noFlag bool
}

// flagName returns the CLI flag name of a key ("probe_interval_ms" ->
// "probe-interval-ms").
func (s keySpec) flagName() string {
	return strings.ReplaceAll(s.key, "_", "-")
}

// setDefaults registers every key's default on v.
func setDefaults(v *viper.Viper, specs []keySpec) {
	for _, s := range specs {
		v.SetDefault(s.key, s.def)
	}
}

// registerFlags defines a CLI flag for every key in specs that has one.
// It panics on an unsupported default type: the tables are static, so that
// is a programming error caught by the package tests, not an input error.
func registerFlags(flags *pflag.FlagSet, specs []keySpec) {
	for _, s := range specs {
		if s.noFlag {
			continue
		}
		name := s.flagName()
		switch d := s.def.(type) {
		case string:
			flags.String(name, d, s.help)
		case bool:
			flags.Bool(name, d, s.help)
		case int:
			flags.Int(name, d, s.help)
		case uint32:
			flags.Uint32(name, d, s.help)
		case uint64:
			flags.Uint64(name, d, s.help)
		case float64:
			flags.Float64(name, d, s.help)
		case []string:
			flags.StringSlice(name, d, s.help)
		default:
			panic(fmt.Sprintf("config: key %q has unsupported default type %T", s.key, s.def))
		}
	}
}

// newViper builds the Viper instance both loaders share, in precedence
// order (highest first): CLI flags (when flags is non-nil), environment
// variables, the config file, and the defaults from specs.
//
// Environment variables are RPINGMESH_ plus the upper-cased key
// (RPINGMESH_CONTROLLER_ADDR); the replacer only maps the dots of nested
// Viper keys to underscores. An explicit configPath is read as given; an
// empty one searches ".", "$HOME/.rpingmesh" and "/etc/rpingmesh" for
// configName.yaml, and a miss there is not an error.
func newViper(configName, configPath string, flags *pflag.FlagSet, specs []keySpec) (*viper.Viper, error) {
	v := viper.New()
	setDefaults(v, specs)

	v.SetEnvPrefix("RPINGMESH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if flags != nil {
		if err := bindPFlags(v, flags); err != nil {
			return nil, err
		}
	}

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName(configName)
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.rpingmesh")
		v.AddConfigPath("/etc/rpingmesh")
	}

	if err := readConfigFile(v, configPath); err != nil {
		return nil, err
	}
	return v, nil
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

// readConfigFile loads the file already configured on v. An explicit
// configPath that does not exist is an error (the operator asked for that
// file). A search-path miss (empty configPath) is not: defaults, env, and
// flags still apply.
func readConfigFile(v *viper.Viper, configPath string) error {
	if err := v.ReadInConfig(); err != nil {
		if configPath == "" {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				return nil
			}
			if os.IsNotExist(err) {
				return nil
			}
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}
	return nil
}
