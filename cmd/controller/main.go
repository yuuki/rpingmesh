package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/controller"
)

func main() {
	// Parse command line flags
	var (
		configPath   string
		createConfig bool
		configOutput string
		showVersion  bool
	)

	flag.StringVar(&configPath, "config", "", "Path to configuration file")
	flag.BoolVar(&createConfig, "create-config", false, "Create a default configuration file")
	flag.StringVar(&configOutput, "config-output", "controller.yaml", "Path where to write the default configuration")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.Parse()

	// Show version information
	if showVersion {
		fmt.Println("RPingMesh Controller")
		fmt.Println("Version: 0.1.0")
		return
	}

	// Create default configuration file if requested
	if createConfig {
		if err := config.CreateDefaultConfig(configOutput); err != nil {
			log.Fatal().Err(err).Str("path", configOutput).Msg("Failed to create default configuration")
		}
		fmt.Printf("Default configuration written to %s\n", configOutput)
		return
	}

	// Create and run controller
	controller, err := controller.New(configPath)
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
