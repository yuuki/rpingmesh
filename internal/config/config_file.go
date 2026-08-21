package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

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
