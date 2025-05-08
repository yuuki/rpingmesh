package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/yuuki/rpingmesh/internal/agent"
	"github.com/yuuki/rpingmesh/internal/config"
)

func main() {
	// Setup command line flags
	config.SetupAgentFlags(pflag.CommandLine)

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
		fmt.Println("RPingMesh Agent")
		fmt.Println("Version: 0.1.0")
		return
	}

	// Create default configuration file if requested
	if createConfig {
		if err := config.CreateDefaultAgentConfig(configOutput); err != nil {
			log.Fatal().Err(err).Str("path", configOutput).Msg("Failed to create default configuration")
		}
		fmt.Printf("Default configuration written to %s\n", configOutput)
		return
	}

	// Load configuration from viper (flags, env vars, and config file)
	cfg, err := config.LoadAgentConfigWithFlags()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Create and run agent with the loaded config
	agent, err := agent.New(cfg)
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
