// Command rpingmesh-agent is the entry point for the R-Pingmesh agent process.
// It initializes configuration from a YAML file, environment variables, and CLI
// flags, sets up structured logging, and runs the agent lifecycle until a
// shutdown signal (SIGINT or SIGTERM) is received.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/yuuki/rpingmesh/rebuild/internal/agent"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
)

// configPath holds the path to the agent configuration file, set via the
// --config CLI flag.
var configPath string

func main() {
	rootCmd := &cobra.Command{
		Use:   "rpingmesh-agent",
		Short: "R-Pingmesh agent service",
		Long: "RDMA network monitoring agent that performs end-to-end probing " +
			"using the R-Pingmesh 6-timestamp protocol. The agent registers " +
			"with a controller, receives probe targets, and exports RTT metrics " +
			"via OpenTelemetry.",
		RunE: run,
	}

	// Bind the --config flag for specifying the configuration file path.
	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to agent configuration file (YAML)")

	// Bind all agent-specific CLI flags (--agent-id, --tor-id, etc.).
	config.BindAgentFlags(rootCmd.Flags())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// run is the main entry point for the agent. It loads configuration, configures
// logging, creates the agent, sets up signal handling, and runs the agent
// lifecycle until a termination signal is received.
func run(cmd *cobra.Command, args []string) error {
	// Load configuration from file, environment variables, and CLI flags.
	cfg, err := config.LoadAgentConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load agent configuration: %w", err)
	}

	// Set up structured logging with console writer for human-readable output.
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Logger()

	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Warn().
			Str("configured_level", cfg.LogLevel).
			Msg("Invalid log level, defaulting to info")
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	log.Info().
		Str("agent_id", cfg.AgentID).
		Str("hostname", cfg.HostName).
		Str("tor_id", cfg.TorID).
		Str("controller_addr", cfg.ControllerAddr).
		Str("log_level", cfg.LogLevel).
		Uint32("probe_interval_ms", cfg.ProbeIntervalMS).
		Bool("metrics_enabled", cfg.MetricsEnabled).
		Strs("allowed_devices", cfg.AllowedDeviceNames).
		Int("gid_index", cfg.GIDIndex).
		Msg("Starting rpingmesh-agent")

	// Create the agent instance.
	a, err := agent.NewAgent(cfg)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	// Set up a context that is cancelled on SIGINT or SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Cancel the context when a shutdown signal is received.
	go func() {
		sig := <-sigCh
		log.Info().
			Str("signal", sig.String()).
			Msg("Received shutdown signal, initiating graceful shutdown")
		cancel()

		// A second signal forces immediate exit.
		sig = <-sigCh
		log.Warn().
			Str("signal", sig.String()).
			Msg("Received second signal, forcing immediate exit")
		os.Exit(1)
	}()

	// Run the agent lifecycle. This blocks until the context is cancelled.
	if err := a.Run(ctx); err != nil {
		log.Error().Err(err).Msg("Agent exited with error")
		return err
	}

	log.Info().Msg("Agent exited cleanly")
	return nil
}
