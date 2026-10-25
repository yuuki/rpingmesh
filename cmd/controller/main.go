package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yuuki/rpingmesh/internal/buildinfo"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/controller"
	"github.com/yuuki/rpingmesh/internal/controller/analyzer"
	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/internal/logging"
	"github.com/yuuki/rpingmesh/internal/telemetry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// analyzerServiceName is the OTel service.name reported by the controller-side
// analyzer's metrics, distinguishing them from agent metrics in the collector.
const analyzerServiceName = "rpingmesh-analyzer"

var configPath string

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "rpingmesh-controller",
		Short:   "R-Pingmesh controller service",
		Long:    "Central coordination service that manages agent registration and distributes pinglists for RDMA network monitoring.",
		Version: buildinfo.Version,
		RunE:    run,
	}

	// Bind CLI flags.
	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to configuration file")
	config.BindControllerFlags(rootCmd.Flags())

	return rootCmd
}

// run is the main entry point for the controller. It loads configuration,
// starts the gRPC server, and blocks until a shutdown signal is received.
func run(cmd *cobra.Command, args []string) error {
	// Flags parsed successfully, so any error from here on is a runtime
	// failure: print it without the flag usage, which cobra would otherwise
	// append and make it look like CLI misuse.
	cmd.SilenceUsage = true

	// Anything logged before the configuration is resolved uses the default
	// (console) format.
	logging.SetupBootstrap()

	// Load configuration from file, env vars, and flags.
	cfg, err := config.LoadControllerConfig(configPath, cmd.Flags())
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Switch to the configured log format (console or json) and level. The
	// level cannot be invalid here: LoadControllerConfig already rejects
	// unknown levels.
	if _, err := logging.Setup(cfg.LogFormat, cfg.LogLevel); err != nil {
		return fmt.Errorf("failed to set up logging: %w", err)
	}

	log.Info().
		Str("listenAddr", cfg.ListenAddr).
		Str("databaseURI", cfg.DatabaseURI).
		Int("databaseConnectTimeoutSec", cfg.DatabaseConnectTimeoutSec).
		Str("logLevel", cfg.LogLevel).
		Str("logFormat", cfg.LogFormat).
		Int("activeThresholdSec", cfg.ActiveThresholdSec).
		Int("staleThresholdSec", cfg.StaleThresholdSec).
		Int("interTorSampleSize", cfg.InterTorSampleSize).
		Int("unspecifiedMeshMaxTargets", cfg.UnspecifiedMeshMaxTargets).
		Int("ecmpPathsAssumed", cfg.EcmpPathsAssumed).
		Float64("ecmpCoverageProbability", cfg.EcmpCoverageProbability).
		Int("ecmpMaxFlowLabels", cfg.EcmpMaxFlowLabels).
		Str("tlsMode", cfg.TLSMode).
		Msg("Starting rpingmesh-controller")

	reg, err := openRegistry(cfg)
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
	}, cfg.InterTorSampleSize, cfg.UnspecifiedMeshMaxTargets)

	// Set up the Phase 1 analyzer if enabled. Its meter provider (nil when
	// metrics are unavailable) is flushed on shutdown.
	if analyzerProvider := setupAnalyzer(cfg, svc); analyzerProvider != nil {
		defer shutdownMeterProvider(analyzerProvider)
	}

	serverOpts, err := buildServerOptions(cfg)
	if err != nil {
		return err
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

	// Background tasks run until run returns.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runStaleEntryCleanup(ctx, reg, 5*time.Minute)

	if err := waitForShutdown(grpcServer, errCh); err != nil {
		return err
	}

	log.Info().Msg("Controller stopped")
	return nil
}

// openRegistry connects the RNIC registry to rqlite. The connection is retried
// until database_connect_timeout_sec elapses, so the controller tolerates an
// rqlite node that is still starting; a shutdown signal aborts the wait.
func openRegistry(cfg *config.ControllerConfig) (*registry.RnicRegistry, error) {
	connectCtx, stopConnect := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopConnect()
	return registry.NewRnicRegistry(
		connectCtx,
		cfg.DatabaseURI,
		cfg.ActiveThresholdSec,
		cfg.StaleThresholdSec,
		time.Duration(cfg.DatabaseConnectTimeoutSec)*time.Second,
	)
}

// shutdownMeterProvider flushes and shuts down the analyzer's meter provider,
// bounded by a 5s timeout.
func shutdownMeterProvider(provider *sdkmetric.MeterProvider) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := provider.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Failed to shut down analyzer metrics provider")
	}
}

// buildServerOptions configures gRPC server transport security from tls_mode.
// disabled (the default) preserves the original plaintext behavior for
// backward compatibility and yields no options.
func buildServerOptions(cfg *config.ControllerConfig) ([]grpc.ServerOption, error) {
	switch cfg.TLSMode {
	case config.TLSModeDisabled, "":
		log.Warn().Msg("gRPC server starting with tls_mode=disabled: controller-agent traffic is plaintext and unauthenticated; set tls_mode to tls or mtls for production deployments")
		return nil, nil
	default:
		tlsConfig, err := config.ServerTLSConfig(cfg.TLSMode, cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to build server TLS configuration: %w", err)
		}
		log.Info().Str("tlsMode", cfg.TLSMode).Msg("gRPC server TLS enabled")
		return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
	}
}

// staleCleaner is the part of the registry the cleanup loop uses.
type staleCleaner interface {
	CleanupStaleEntries(ctx context.Context) error
}

// runStaleEntryCleanup removes stale RNIC entries every interval until ctx is
// cancelled.
func runStaleEntryCleanup(ctx context.Context, reg staleCleaner, interval time.Duration) {
	ticker := time.NewTicker(interval)
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
}

// waitForShutdown blocks until SIGINT/SIGTERM arrives or the gRPC server
// reports a serve error on errCh. On a signal it drains in-flight requests
// with GracefulStop and returns nil; a serve error is returned as is.
func waitForShutdown(grpcServer *grpc.Server, errCh <-chan error) error {
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
		var providerOpts []sdkmetric.Option
		if cfg.AnalyzerMetricsCardinalityLimit > 0 {
			providerOpts = append(providerOpts, sdkmetric.WithCardinalityLimit(cfg.AnalyzerMetricsCardinalityLimit))
		}
		p, err := telemetry.NewMeterProvider(context.Background(), cfg.OtelCollectorAddr, analyzerServiceName, providerOpts...)
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
		Cluster: analyzer.Thresholds{
			LossRatio:       cfg.AnalyzerSLALossRatio,
			NetworkRTTP99Ns: cfg.AnalyzerSLANetworkRTTP99Ns,
		},
		Service: analyzer.Thresholds{
			LossRatio:       cfg.AnalyzerServiceSLOLossRatio,
			NetworkRTTP99Ns: cfg.AnalyzerServiceSLONetworkRTTP99Ns,
		},
		WindowRetention: cfg.AnalyzerWindowRetention,
	}, metrics)
	svc.SetAnalyzer(az)

	// Dashboards read the fraction of probes above the RTT threshold off the
	// agents' rpingmesh.network_rtt_ns (or rpingmesh.service.network_rtt_ns)
	// bucket at that boundary, which only exists when the threshold is one of
	// the agent's default boundaries.
	for _, t := range []struct {
		key string
		ns  uint64
	}{
		{"analyzer_sla_network_rtt_p99_ns", cfg.AnalyzerSLANetworkRTTP99Ns},
		{"analyzer_service_slo_network_rtt_p99_ns", cfg.AnalyzerServiceSLONetworkRTTP99Ns},
	} {
		if t.ns != 0 && !telemetry.IsNetworkRTTBucketBoundary(t.ns) {
			log.Warn().
				Str("key", t.key).
				Uint64("networkRttP99Ns", t.ns).
				Msg("threshold is not a bucket boundary of the agents' network_rtt_ns histograms; dashboards can only approximate the share of probes above it")
		}
	}

	log.Info().
		Float64("slaLossRatio", cfg.AnalyzerSLALossRatio).
		Uint64("slaNetworkRttP99Ns", cfg.AnalyzerSLANetworkRTTP99Ns).
		Float64("serviceSloLossRatio", cfg.AnalyzerServiceSLOLossRatio).
		Uint64("serviceSloNetworkRttP99Ns", cfg.AnalyzerServiceSLONetworkRTTP99Ns).
		Int("windowRetention", cfg.AnalyzerWindowRetention).
		Int("metricsCardinalityLimit", cfg.AnalyzerMetricsCardinalityLimit).
		Bool("metricsEnabled", metrics != nil).
		Msg("Analyzer enabled")

	return provider
}
