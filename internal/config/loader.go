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

	v.SetEnvPrefix(envPrefix)
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

// envPrefix is the prefix of the environment variables both binaries read:
// the key listen_addr is set by RPINGMESH_LISTEN_ADDR.
const envPrefix = "RPINGMESH"

// envName returns the environment variable that sets key, as AutomaticEnv
// derives it: the prefix, an underscore and the upper-cased key.
func envName(key string) string {
	return envPrefix + "_" + strings.ToUpper(key)
}

// renamedKey records a configuration key that was renamed. The old key stays
// usable as a deprecated alias: a value set under it in the config file, its
// environment variable or its hidden CLI flag feeds the new key when the new
// key itself is not set explicitly, and the loader reports the use so the
// binary can log a deprecation warning once logging is configured (the log
// format and level are themselves configuration, so the loader cannot log).
type renamedKey struct {
	old, new string
}

// specByKey returns the spec of key in specs.
func specByKey(specs []keySpec, key string) (keySpec, bool) {
	for _, s := range specs {
		if s.key == key {
			return s, true
		}
	}
	return keySpec{}, false
}

// registerDeprecatedFlags defines, for every renamed key, a CLI flag under
// the old name with the type and default of the new key's spec, and marks it
// deprecated: pflag hides it from --help and prints a notice when it is
// used. bindPFlags later binds it to the old key, where applyRenamedKeys
// picks it up like a value from the config file or the environment. It
// panics when a new key has no spec: the tables are static, so that is a
// programming error caught by the package tests.
func registerDeprecatedFlags(flags *pflag.FlagSet, specs []keySpec, renamed []renamedKey) {
	for _, r := range renamed {
		spec, ok := specByKey(specs, r.new)
		if !ok {
			panic(fmt.Sprintf("config: renamed key %q has no spec for its new name %q", r.old, r.new))
		}
		old := keySpec{key: r.old, def: spec.def, help: "Deprecated alias of --" + spec.flagName()}
		registerFlags(flags, []keySpec{old})
		if err := flags.MarkDeprecated(old.flagName(), "use --"+spec.flagName()); err != nil {
			panic(fmt.Sprintf("config: mark flag --%s deprecated: %v", old.flagName(), err))
		}
	}
}

// explicitlySet reports whether key has a value from a source the operator
// controls: a changed CLI flag, a non-empty environment variable or the
// config file. Viper's IsSet also counts the key's default, so it cannot
// tell an explicit value from the default. The environment check mirrors
// AutomaticEnv: an empty variable counts as unset.
func explicitlySet(v *viper.Viper, flags *pflag.FlagSet, key string) bool {
	if flags != nil {
		if f := flags.Lookup(keySpec{key: key}.flagName()); f != nil && f.Changed {
			return true
		}
	}
	if val, ok := os.LookupEnv(envName(key)); ok && val != "" {
		return true
	}
	return v.InConfig(key)
}

// applyRenamedKeys resolves the deprecated aliases in renamed on v and
// returns one warning per alias in use, for the binary to log. An alias
// whose new key is also set explicitly is ignored, whatever the sources: an
// operator who has already migrated can leave the old key in place until
// the next config edit, and the new key never changes meaning depending on
// which source set it.
func applyRenamedKeys(v *viper.Viper, flags *pflag.FlagSet, renamed []renamedKey) []string {
	var warnings []string
	for _, r := range renamed {
		if !explicitlySet(v, flags, r.old) {
			continue
		}
		oldSpec, newSpec := keySpec{key: r.old}, keySpec{key: r.new}
		if explicitlySet(v, flags, r.new) {
			warnings = append(warnings, fmt.Sprintf(
				"config key %q (--%s, %s) is deprecated and ignored because %q is also set; remove it",
				r.old, oldSpec.flagName(), envName(r.old), r.new))
			continue
		}
		v.Set(r.new, v.Get(r.old))
		warnings = append(warnings, fmt.Sprintf(
			"config key %q (--%s, %s) is deprecated and will be removed in the next minor release; rename it to %q (--%s, %s), which takes the same value",
			r.old, oldSpec.flagName(), envName(r.old), r.new, newSpec.flagName(), envName(r.new)))
	}
	return warnings
}
