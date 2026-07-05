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
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller/analyzer"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller/registry"
	"github.com/yuuki/rpingmesh/rebuild/internal/telemetry"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// analyzerServiceName is the OTel service.name reported by the controller-side
// analyzer's metrics, distinguishing them from agent metrics in the collector.
const analyzerServiceName = "rpingmesh-analyzer"

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
	cfg, err := config.LoadControllerConfig(configPath, cmd.Flags())
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
		Int("activeThresholdSec", cfg.ActiveThresholdSec).
		Int("staleThresholdSec", cfg.StaleThresholdSec).
		Int("interTorSampleSize", cfg.InterTorSampleSize).
		Int("ecmpPathsAssumed", cfg.EcmpPathsAssumed).
		Float64("ecmpCoverageProbability", cfg.EcmpCoverageProbability).
		Int("ecmpMaxFlowLabels", cfg.EcmpMaxFlowLabels).
		Str("tlsMode", cfg.TLSMode).
		Msg("Starting rpingmesh-controller")

	// Initialize RNIC registry backed by rqlite.
	reg, err := registry.NewRnicRegistry(
		cfg.DatabaseURI,
		cfg.ActiveThresholdSec,
		cfg.StaleThresholdSec,
		cfg.InterTorSampleSize,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize registry: %w", err)
	}
	defer func() {
		if err := reg.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close registry")
		}
	}()

	// Create the controller gRPC service. The ECMP config sizes the per-target
	// flow-label set (Eq.(1) coverage) each pinglist entry carries.
	svc := controller.NewControllerService(reg, pinglist.ECMPConfig{
		PathsAssumed:        cfg.EcmpPathsAssumed,
		CoverageProbability: cfg.EcmpCoverageProbability,
		MaxFlowLabels:       cfg.EcmpMaxFlowLabels,
	})

	// Set up the Phase 1 analyzer if enabled: it ingests agent-reported
	// per-path summaries and flags SLA violations. Its OTLP metrics are
	// best-effort (service.name=rpingmesh-analyzer); a failure to build the
	// meter provider degrades to log-only findings rather than failing startup.
	// The provider is returned so it can be flushed on shutdown.
	analyzerProvider := setupAnalyzer(cfg, svc)
	if analyzerProvider != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := analyzerProvider.Shutdown(shutdownCtx); err != nil {
				log.Error().Err(err).Msg("Failed to shut down analyzer metrics provider")
			}
		}()
	}

	// Configure gRPC server transport security from tls_mode. disabled (the
	// default) preserves the original plaintext behavior for backward
	// compatibility.
	var serverOpts []grpc.ServerOption
	switch cfg.TLSMode {
	case config.TLSModeDisabled, "":
		log.Warn().Msg("gRPC server starting with tls_mode=disabled: controller-agent traffic is plaintext and unauthenticated; set tls_mode to tls or mtls for production deployments")
	default:
		tlsConfig, err := config.ServerTLSConfig(cfg.TLSMode, cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
		if err != nil {
			return fmt.Errorf("failed to build server TLS configuration: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		log.Info().Str("tlsMode", cfg.TLSMode).Msg("gRPC server TLS enabled")
	}

	// Create and configure the gRPC server.
	grpcServer := grpc.NewServer(serverOpts...)
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

// setupAnalyzer builds the Phase 1 analyzer (when enabled) and wires it into
// svc. It attempts to create an OTLP meter provider tagged
// service.name=rpingmesh-analyzer for the analyzer's metrics; if that fails,
// the analyzer still runs with log-only findings. It returns the meter provider
// (or nil) so the caller can flush it on shutdown.
func setupAnalyzer(cfg *config.ControllerConfig, svc *controller.ControllerService) *sdkmetric.MeterProvider {
	if !cfg.AnalyzerEnabled {
		log.Info().Msg("Analyzer disabled")
		return nil
	}

	var provider *sdkmetric.MeterProvider
	var metrics *analyzer.Metrics
	if cfg.OtelCollectorAddr != "" {
		p, err := telemetry.NewMeterProvider(context.Background(), cfg.OtelCollectorAddr, analyzerServiceName)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create analyzer meter provider; continuing with log-only findings")
		} else {
			m, err := analyzer.NewMetrics(p.Meter("rpingmesh.analyzer"))
			if err != nil {
				log.Warn().Err(err).Msg("Failed to register analyzer metrics; continuing with log-only findings")
				_ = p.Shutdown(context.Background())
			} else {
				provider = p
				metrics = m
			}
		}
	}

	az := analyzer.New(analyzer.Config{
		SLALossRatio:       cfg.AnalyzerSLALossRatio,
		SLANetworkRTTP99Ns: cfg.AnalyzerSLANetworkRTTP99Ns,
		WindowRetention:    cfg.AnalyzerWindowRetention,
	}, metrics)
	svc.SetAnalyzer(az)

	log.Info().
		Float64("slaLossRatio", cfg.AnalyzerSLALossRatio).
		Uint64("slaNetworkRttP99Ns", cfg.AnalyzerSLANetworkRTTP99Ns).
		Int("windowRetention", cfg.AnalyzerWindowRetention).
		Bool("metricsEnabled", metrics != nil).
		Msg("Analyzer enabled")

	return provider
}
