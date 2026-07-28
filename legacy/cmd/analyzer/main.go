package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/analyzer"
	"github.com/yuuki/rpingmesh/internal/config"
)

func main() {
	// Parse command line flags
	flags := pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
	var configOutput string

	config.SetupAnalyzerFlags(flags)
	flags.StringVar(&configOutput, "config-output", "analyzer.yaml", "Path where to write the default configuration")

	// Version flag is handled in the config package, so no version logic here

	// Parse flags
	flags.Parse(os.Args[1:])

	// Create default configuration file if requested
	createConfigFlag, err := flags.GetBool("create-config")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get create-config flag value")
	}
	if createConfigFlag {
		if err := config.CreateDefaultAnalyzerConfig(configOutput); err != nil {
			log.Fatal().Err(err).Str("path", configOutput).Msg("Failed to create default configuration")
		}
		fmt.Printf("Default configuration written to %s\n", configOutput)
		return
	}

	// Load configuration
	cfg, err := config.LoadAnalyzerConfig(flags)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load analyzer config")
	}

	// Convert to analyzer package's AnalyzerConfig type
	analyzerCfg := &analyzer.AnalyzerConfig{
		ListenAddr:  cfg.ListenAddr,
		DatabaseURI: cfg.DatabaseURI,
		LogLevel:    cfg.LogLevel,
	}

	// Create and run analyzer
	analyzer, err := analyzer.New(analyzerCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create analyzer")
	}

	// Run the analyzer with signal handling
	if err := analyzer.Run(); err != nil {
		log.Fatal().Err(err).Msg("Analyzer failed")
	}

	// Exit normally
	os.Exit(0)
}
