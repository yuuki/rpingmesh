package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/agent"
	"github.com/yuuki/rpingmesh/internal/config"
)

func main() {
	// Set up command line flags
	flagSet := pflag.NewFlagSet("agent", pflag.ExitOnError)
	config.SetupAgentFlags(flagSet)

	// Parse flags
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Handle version flag
	version, _ := flagSet.GetBool("version")
	if version {
		fmt.Println("RPingMesh Agent v0.1.0")
		os.Exit(0)
	}

	// Handle create-config flag
	createConfig, _ := flagSet.GetBool("create-config")
	if createConfig {
		configOutput, _ := flagSet.GetString("config-output")
		if err := config.WriteDefaultConfig(configOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating default config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created default configuration at %s\n", configOutput)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadAgentConfig(flagSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Create and run agent
	a, err := agent.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create agent")
	}

	if err := a.Run(); err != nil {
		log.Fatal().Err(err).Msg("Agent failed")
	}
}
