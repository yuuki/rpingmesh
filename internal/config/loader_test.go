package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TestKeyTablesMatchFlags checks, for each binary, that the key table and
// the registered flags describe the same configuration: every flag maps to
// a table key with the same default, every table key that is not noFlag has
// a flag, every table key has a Viper default, and no key is listed twice.
func TestKeyTablesMatchFlags(t *testing.T) {
	for name, tc := range map[string]struct {
		bind  func(*pflag.FlagSet)
		specs []keySpec
	}{
		"agent":      {BindAgentFlags, agentKeys},
		"controller": {BindControllerFlags, controllerKeys},
	} {
		t.Run(name, func(t *testing.T) {
			byFlag := make(map[string]keySpec, len(tc.specs))
			for _, s := range tc.specs {
				if _, dup := byFlag[s.flagName()]; dup {
					t.Errorf("key %q is listed twice", s.key)
				}
				byFlag[s.flagName()] = s
			}

			flags := pflag.NewFlagSet(name, pflag.ContinueOnError)
			tc.bind(flags)

			seen := make(map[string]bool)
			flags.VisitAll(func(f *pflag.Flag) {
				seen[f.Name] = true
				s, ok := byFlag[f.Name]
				if !ok {
					t.Errorf("flag --%s has no key table entry", f.Name)
					return
				}
				if s.noFlag {
					t.Errorf("flag --%s is registered but key %q is marked noFlag", f.Name, s.key)
				}
				// pflag renders every supported default type the way
				// fmt.Sprint does ("[]" for an empty slice, "0.9" for a
				// float64), so a mismatch here means the flag default
				// diverged from the Viper default.
				if want := fmt.Sprint(s.def); f.DefValue != want {
					t.Errorf("flag --%s default = %q, want %q (key %q)", f.Name, f.DefValue, want, s.key)
				}
			})
			for _, s := range tc.specs {
				if !s.noFlag && !seen[s.flagName()] {
					t.Errorf("key %q has no registered flag --%s", s.key, s.flagName())
				}
			}

			v := viper.New()
			setDefaults(v, tc.specs)
			defaults := make(map[string]bool)
			for _, k := range v.AllKeys() {
				defaults[k] = true
			}
			if len(defaults) != len(tc.specs) {
				t.Errorf("viper has %d default keys, table has %d entries", len(defaults), len(tc.specs))
			}
			for _, s := range tc.specs {
				if !defaults[s.key] {
					t.Errorf("key %q has no viper default", s.key)
				}
			}
		})
	}
}

// TestKeySpec_FlagName pins the key -> flag naming rule, which must stay the
// inverse of bindPFlags for flags to reach their Viper keys.
func TestKeySpec_FlagName(t *testing.T) {
	if got := (keySpec{key: "tor_mesh_probe_rate_per_second"}).flagName(); got != "tor-mesh-probe-rate-per-second" {
		t.Errorf("flagName() = %q", got)
	}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindAgentFlags(flags)
	flags.VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "_") {
			t.Errorf("flag --%s contains an underscore", f.Name)
		}
	})
}

func TestRegisterFlags_UnsupportedDefaultTypePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registerFlags accepted an int64 default, want panic")
		}
	}()
	registerFlags(pflag.NewFlagSet("test", pflag.ContinueOnError), []keySpec{{key: "bad", def: int64(1)}})
}
