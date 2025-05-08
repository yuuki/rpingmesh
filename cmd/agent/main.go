package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/agent"
	"github.com/yuuki/rpingmesh/pkg/config"
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
	flag.StringVar(&configOutput, "config-output", "agent.yaml", "Path where to write the default configuration")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.Parse()

	// Show version information
	if showVersion {
		fmt.Println("RPingMesh Agent")
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

	// Create and run agent
	agent, err := agent.New(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create agent")
	}

	// Run the agent with signal handling
	if err := agent.Run(); err != nil {
		log.Fatal().Err(err).Msg("Agent failed")
	}

	// Exit normally
	os.Exit(0)
}
