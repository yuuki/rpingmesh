package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/controller"
)

func main() {
	// Setup command line flags
	config.SetupControllerFlags(pflag.CommandLine)

	// Parse flags
	pflag.Parse()

	// Setup viper for the main application flags (create-config, version, etc.)
	v := viper.New()
	v.BindPFlags(pflag.CommandLine)

	// Get flag values
	createConfig := v.GetBool("create-config")
	configOutput := v.GetString("config-output")
	showVersion := v.GetBool("version")

	// Show version information
	if showVersion {
		fmt.Println("RPingMesh Controller")
		fmt.Println("Version: 0.1.0")
		return
	}

	// Create default configuration file if requested
	if createConfig {
		if err := config.CreateDefaultControllerConfig(configOutput); err != nil {
			log.Fatal().Err(err).Str("path", configOutput).Msg("Failed to create default configuration")
		}
		fmt.Printf("Default configuration written to %s\n", configOutput)
		return
	}

	// Load configuration from viper (flags, env vars, and config file)
	cfg, err := config.LoadControllerConfigWithFlags()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Create and run controller with the loaded config
	controller, err := controller.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create controller")
	}

	// Run the controller with signal handling
	if err := controller.Run(); err != nil {
		log.Fatal().Err(err).Msg("Controller failed")
	}

	// Exit normally
	os.Exit(0)
}
