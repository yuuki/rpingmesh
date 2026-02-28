package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller/registry"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

var configPath string

func main() {
	rootCmd := &cobra.Command{
		Use:   "rpingmesh-controller",
		Short: "R-Pingmesh controller service",
		Long:  "Central coordination service that manages agent registration and distributes pinglists for RDMA network monitoring.",
		RunE:  run,
	}

	// Bind CLI flags.
	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to configuration file")
	config.BindControllerFlags(rootCmd.Flags())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// run is the main entry point for the controller. It loads configuration,
// starts the gRPC server, and blocks until a shutdown signal is received.
func run(cmd *cobra.Command, args []string) error {
	// Load configuration from file, env vars, and flags.
	cfg, err := config.LoadControllerConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Set up structured logging with console writer and configured level.
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Logger()

	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Warn().Str("logLevel", cfg.LogLevel).Msg("Invalid log level, defaulting to info")
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	log.Info().
		Str("listenAddr", cfg.ListenAddr).
		Str("databaseURI", cfg.DatabaseURI).
		Str("logLevel", cfg.LogLevel).
		Msg("Starting rpingmesh-controller")

	// Initialize RNIC registry backed by rqlite.
	reg, err := registry.NewRnicRegistry(cfg.DatabaseURI)
	if err != nil {
		return fmt.Errorf("failed to initialize registry: %w", err)
	}
	defer func() {
		if err := reg.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close registry")
		}
	}()

	// Create the controller gRPC service.
	svc := controller.NewControllerService(reg)

	// Create and configure the gRPC server.
	grpcServer := grpc.NewServer()
	controller_agent.RegisterControllerServiceServer(grpcServer, svc)

	// Start listening on the configured address.
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddr, err)
	}

	log.Info().Str("addr", cfg.ListenAddr).Msg("gRPC server listening")

	// Serve gRPC in a background goroutine.
	errCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			errCh <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Set up a cancellable context for background tasks.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start periodic cleanup of stale RNIC entries (every 5 minutes).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := reg.CleanupStaleEntries(ctx); err != nil {
					log.Error().Err(err).Msg("Failed to cleanup stale entries")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for shutdown signal (SIGINT or SIGTERM).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
	case err := <-errCh:
		log.Error().Err(err).Msg("gRPC server failed")
		return err
	}

	// Gracefully stop the gRPC server to drain in-flight requests.
	log.Info().Msg("Shutting down gRPC server gracefully")
	grpcServer.GracefulStop()

	log.Info().Msg("Controller stopped")
	return nil
}
