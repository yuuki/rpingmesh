package agent

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/internal/agent/telemetry"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/monitor"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/state"
	"github.com/yuuki/rpingmesh/internal/tracer"
	"github.com/yuuki/rpingmesh/internal/upload"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Agent represents the RPingMesh agent
type Agent struct {
	ctx              context.Context
	cancel           context.CancelFunc
	config           *config.AgentConfig
	agentState       *state.AgentState
	controllerClient *controller_client.ControllerClient
	prober           *probe.Prober
	clusterMonitor   *monitor.ClusterMonitor
	tracer           *tracer.Tracer
	uploader         *upload.Uploader
	metrics          *telemetry.Metrics
	wg               sync.WaitGroup
}

// New creates a new agent instance
func New(cfg *config.AgentConfig) (*Agent, error) {
	// Initialize logging
	initLogging(cfg.LogLevel)

	log.Debug().Msg("Creating new agent instance")

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create agent state
	agentState := state.NewAgentState(cfg.AgentID, "")

	// Initialize controller client
	controllerClient := controller_client.NewControllerClient(cfg.ControllerAddr)

	// Create new agent
	agent := &Agent{
		ctx:              ctx,
		cancel:           cancel,
		config:           cfg,
		agentState:       agentState,
		controllerClient: controllerClient,
	}

	// Initialize tracer if enabled
	if cfg.TracerEnabled {
		agent.tracer = tracer.NewTracer()
		log.Debug().Msg("Tracer created and enabled")
	} else {
		log.Info().Msg("Tracer is disabled via configuration")
	}

	log.Debug().Str("agent_id", cfg.AgentID).Str("controller_addr", cfg.ControllerAddr).Msg("Agent instance created")
	return agent, nil
}

// Start starts the agent
func (a *Agent) Start() error {
	log.Debug().Msg("Starting agent")

	// Initialize agent state
	if err := a.agentState.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize agent state: %w", err)
	}
	log.Debug().Msg("Agent state initialized")

	// Connect to controller
	if err := a.controllerClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to controller: %w", err)
	}
	log.Debug().Msg("Connected to controller")

	// Register with controller
	if err := a.controllerClient.RegisterAgent(
		a.agentState.GetAgentID(),
		a.agentState.GetAgentIP(),
		a.agentState.GetDetectedRNICs(),
	); err != nil {
		return fmt.Errorf("failed to register agent with controller: %w", err)
	}
	log.Info().Msg("Registered agent with controller")

	primaryRnic := a.agentState.GetPrimaryRNIC()
	if primaryRnic == nil {
		return fmt.Errorf("no RDMA devices available")
	}

	udQueue := a.agentState.GetUDQueue(primaryRnic.GID)
	if udQueue == nil {
		return fmt.Errorf("no UD queue available for RNIC %s", primaryRnic.GID)
	}
	log.Debug().Str("primary_rnic_gid", primaryRnic.GID).Msg("Got primary RNIC and UD queue")

	// Initialize metrics if enabled
	if a.config.MetricsEnabled {
		metricsInstance, err := telemetry.NewMetrics(a.ctx, a.agentState.GetAgentID(), a.config.OtelCollectorAddr)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize metrics, continuing without metrics")
		} else {
			a.metrics = metricsInstance
			log.Info().
				Str("agent_id", a.agentState.GetAgentID()).
				Str("collector_addr", a.config.OtelCollectorAddr).
				Msg("OpenTelemetry metrics initialized")
		}
	}

	// Create prober
	a.prober = probe.NewProber(a.agentState.GetRDMAManager(), a.agentState, a.config.TimeoutMS)
	if err := a.prober.Start(); err != nil {
		return fmt.Errorf("failed to start prober: %w", err)
	}
	log.Debug().Msg("Prober started")

	// Create cluster monitor
	a.clusterMonitor = monitor.NewClusterMonitor(
		a.agentState,
		a.prober,
		a.config.ProbeIntervalMS,
	)
	if err := a.clusterMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start cluster monitor: %w", err)
	}
	log.Debug().Uint32("probe_interval_ms", a.config.ProbeIntervalMS).Msg("Cluster monitor started")

	// Set context for tracer
	if a.tracer != nil {
		a.tracer.SetContext(a.ctx)
	}

	// Start periodic traceroute if interval is set
	if a.config.TracerouteIntervalMS > 0 {
		// Get primary RNIC for periodic traceroute
		primaryRnic := a.agentState.GetPrimaryRNIC()
		if primaryRnic != nil {
			// Get a pinglist from the controller to use as traceroute targets
			targets, _, _, err := a.controllerClient.GetPinglist(
				primaryRnic,
				controller_agent.PinglistRequest_TOR_MESH,
			)

			if err != nil {
				log.Warn().Err(err).Msg("Failed to get pinglist for traceroute targets, will use localhost")
				// Fallback to localhost if we can't get targets
				if a.tracer != nil {
					a.tracer.StartPeriodicTracingToLocalhost(a.ctx, primaryRnic.GID, a.config.TracerouteIntervalMS)
				}
			} else {
				// Start periodic tracing to targets
				if a.tracer != nil {
					a.tracer.StartPeriodicTracing(a.ctx, primaryRnic.GID, targets, a.config.TracerouteIntervalMS, 3)
				}
			}
		}
	}

	// Create uploader
	a.uploader = upload.NewUploader(
		a.config.AnalyzerAddr,
		a.agentState.GetAgentID(),
		a.config.DataUploadIntervalMS,
		1000,  // Batch size
		10000, // Max queue size
	)
	log.Debug().Msg("Uploader created")

	// Start uploader only if enabled
	if a.config.AnalyzerEnabled {
		if err := a.uploader.Start(); err != nil {
			log.Warn().Err(err).Str("analyzer_addr", a.config.AnalyzerAddr).Msg("Failed to start uploader, will retry later. Agent will continue without analyzer connection")
		} else {
			log.Info().Str("analyzer_addr", a.config.AnalyzerAddr).Uint32("upload_interval_ms", a.config.DataUploadIntervalMS).Msg("Uploader started")
		}
	} else {
		log.Info().Msg("Analyzer data upload is disabled")
	}

	// Start background goroutines
	a.wg.Add(2)
	go a.resultHandler()
	go a.pinglistUpdater()
	log.Debug().Msg("Background goroutines started")

	log.Info().Msg("Agent started successfully")
	return nil
}

// resultHandler collects and forwards results from components
func (a *Agent) resultHandler() {
	defer a.wg.Done()
	log.Debug().Msg("Result handler started")

	// Handle probe results
	probeResults := a.prober.GetProbeResults()

	// Handle trace results only if tracer is enabled
	var traceResults <-chan *agent_analyzer.PathInfo
	if a.tracer != nil {
		traceResults = a.tracer.GetTraceResults()
	} else {
		log.Debug().Msg("Tracer is disabled, trace results will not be processed.")
	}

	for {
		select {
		case <-a.ctx.Done():
			log.Debug().Msg("Result handler stopping due to context cancellation")
			return
		case result, ok := <-probeResults:
			if !ok {
				log.Debug().Msg("Probe results channel closed")
				// If probe results channel is closed, we might want to stop the handler.
				// However, if traceResults is still open (and tracer enabled), we might want to continue.
				// For now, let's assume closing probeResults means we should stop.
				return
			}
			log.Debug().
				Str("src_gid", result.FiveTuple.SrcGid).
				Str("dst_gid", result.FiveTuple.DstGid).
				Int32("status", int32(result.Status)).
				Float64("rtt_ms", float64(result.NetworkRtt)/1000000.0).
				Msg("Received probe result")

			// Record metrics if enabled
			if a.metrics != nil {
				// Create common attributes
				commonAttrs := attribute.NewSet(
					attribute.String("src_gid", result.FiveTuple.SrcGid),
					attribute.String("dst_gid", result.FiveTuple.DstGid),
					attribute.String("probe_type", result.ProbeType),
				)

				// Record metrics based on probe status
				if result.Status == agent_analyzer.ProbeResult_OK {
					// Record RTT with RecordOption
					a.metrics.RecordRTT(a.ctx, result.NetworkRtt, metric.WithAttributeSet(commonAttrs))

					// Record processing delays with RecordOption
					a.metrics.RecordProberDelay(a.ctx, result.ProberDelay, metric.WithAttributeSet(commonAttrs))
					a.metrics.RecordResponderDelay(a.ctx, result.ResponderDelay, metric.WithAttributeSet(commonAttrs))
					log.Debug().
						Str("src_gid", result.FiveTuple.SrcGid).
						Str("dst_gid", result.FiveTuple.DstGid).
						Int32("status", int32(result.Status)).
						Float64("rtt_ms", float64(result.NetworkRtt)/1000000.0).
						Msg("Recorded RTT metrics")
				} else if result.Status == agent_analyzer.ProbeResult_TIMEOUT {
					// Record timeout with AddOption
					a.metrics.RecordTimeout(a.ctx, metric.WithAttributeSet(commonAttrs))
					log.Debug().
						Str("src_gid", result.FiveTuple.SrcGid).
						Str("dst_gid", result.FiveTuple.DstGid).
						Int32("status", int32(result.Status)).
						Msg("Recorded timeout metrics")
				}
			}

			// Forward to uploader
			if a.uploader != nil && a.config.AnalyzerEnabled {
				a.uploader.AddProbeResult(result)
			} else {
				log.Debug().Msg("Uploader not available or disabled, probe result discarded")
			}

			// If it's a timeout, maybe run a traceroute
			if result.Status == agent_analyzer.ProbeResult_TIMEOUT && a.config.TracerouteOnTimeout {
				if a.tracer != nil {
					log.Debug().
						Str("dst_gid", result.FiveTuple.DstGid).
						Msg("Timeout detected, initiating traceroute")

					go func(fiveTuple *agent_analyzer.ProbeFiveTuple) {
						if err := a.tracer.Trace(a.ctx, fiveTuple); err != nil {
							log.Error().Err(err).Msg("Failed to run traceroute")
						}
					}(result.FiveTuple)
				} else {
					log.Debug().Msg("Traceroute on timeout is configured, but tracer is disabled. Skipping traceroute.")
				}
			}
		case traceInfo, ok := <-traceResults:
			if !ok {
				log.Debug().Msg("Trace results channel closed")
				// If tracer was enabled, this means its channel closed, so we might want to stop or handle.
				// If tracer was disabled, traceResults is nil, so this case should not be hit often,
				// but if it is (e.g., if a nil channel somehow becomes readable as closed),
				// we simply continue the loop or return if probeResults is also closed.
				// For safety, if traceResults is nil and this case is hit, we log and continue.
				if a.tracer == nil {
					log.Warn().Msg("Trace results channel (which should be nil as tracer is disabled) reported as closed. Continuing.")
					// Make sure we don't get stuck in a loop if a nil channel somehow repeatedly signals closed.
					// Setting it to a new nil should prevent this, though select on nil chan should block.
					traceResults = nil
					continue
				}
				// If tracer was active and channel is now closed, we might stop this handler
				// if probe channel is also expected to close or already closed.
				// For now, just log and treat as if this source is done.
				// If probeResults is still active, the loop will continue for that.
				// If we want to exit when EITHER is done, more complex logic is needed or
				// we rely on context cancellation.
				log.Debug().Msg("Trace results channel from active tracer closed. Will no longer process trace results.")
				// To prevent this case from being selected again after closure:
				traceResults = nil // Set to nil so select doesn't pick it.
				continue
			}
			log.Debug().
				Str("src_gid", traceInfo.FiveTuple.SrcGid).
				Str("dst_gid", traceInfo.FiveTuple.DstGid).
				Int("hop_count", len(traceInfo.Hops)).
				Msg("Received trace result")

			// Forward to uploader
			if a.uploader != nil && a.config.AnalyzerEnabled {
				a.uploader.AddPathInfo(traceInfo)
			} else {
				log.Debug().Msg("Uploader not available or disabled, path info discarded")
			}
		}
	}
}

// pinglistUpdater periodically updates the pinglist from the controller
func (a *Agent) pinglistUpdater() {
	defer a.wg.Done()
	log.Debug().Msg("Pinglist updater started")

	// Initial update
	a.updatePinglist()

	// Set up periodic update
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			log.Debug().Msg("Pinglist updater stopping due to context cancellation")
			return
		case <-ticker.C:
			log.Debug().Msg("Periodic pinglist update triggered")
			a.updatePinglist()
		}
	}
}

// updatePinglist gets a fresh pinglist from the controller
func (a *Agent) updatePinglist() {
	log.Debug().Msg("Updating pinglist from controller")

	primaryRnic := a.agentState.GetPrimaryRNIC()
	if primaryRnic == nil {
		log.Error().Msg("No primary RNIC available")
		return
	}
	log.Debug().Str("primary_rnic_gid", primaryRnic.GID).Msg("Retrieved primary RNIC for pinglist request")

	// Get ToR-mesh pinglist
	torTargets, intervalMs, timeoutMs, err := a.controllerClient.GetPinglist(
		primaryRnic,
		controller_agent.PinglistRequest_TOR_MESH,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ToR-mesh pinglist")
		return
	}
	log.Debug().Int("target_count", len(torTargets)).Msg("Received ToR-mesh pinglist")

	// Update probe timeout if controller specified it
	if timeoutMs > 0 && timeoutMs != a.config.TimeoutMS {
		log.Debug().Uint32("old_timeout_ms", a.config.TimeoutMS).Uint32("new_timeout_ms", timeoutMs).Msg("Updating probe timeout")
		a.config.TimeoutMS = timeoutMs
		log.Info().Uint32("timeout_ms", timeoutMs).Msg("Updated probe timeout from controller")
	}

	// Update probe interval if controller specified it
	if intervalMs > 0 && intervalMs != a.config.ProbeIntervalMS {
		log.Debug().Uint32("old_interval_ms", a.config.ProbeIntervalMS).Uint32("new_interval_ms", intervalMs).Msg("Updating probe interval")
		a.config.ProbeIntervalMS = intervalMs
		log.Info().Uint32("interval_ms", intervalMs).Msg("Updated probe interval from controller")
	}

	// Update cluster monitor's pinglist
	a.clusterMonitor.UpdatePinglist(torTargets)
	log.Debug().Msg("Updated cluster monitor pinglist")

	// Also get Inter-ToR pinglist
	interTorTargets, _, _, err := a.controllerClient.GetPinglist(
		primaryRnic,
		controller_agent.PinglistRequest_INTER_TOR,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get Inter-ToR pinglist")
		return
	}
	log.Debug().Int("target_count", len(interTorTargets)).Msg("Received Inter-ToR pinglist")

	// Combine the pinglists (in a real implementation, you might want to keep them separate)
	log.Info().Int("torTargets", len(torTargets)).Int("interTorTargets", len(interTorTargets)).Msg("Updated pinglists")
}

// Stop stops the agent
func (a *Agent) Stop() {
	log.Debug().Msg("Stopping agent")
	a.cancel()

	// Stop components in reverse order
	if a.uploader != nil && a.config.AnalyzerEnabled {
		log.Debug().Msg("Closing uploader")
		if err := a.uploader.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close uploader")
		}
	}

	if a.tracer != nil {
		log.Debug().Msg("Closing tracer")
		if err := a.tracer.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close tracer")
		}
	}

	if a.clusterMonitor != nil {
		log.Debug().Msg("Stopping cluster monitor")
		a.clusterMonitor.Stop()
	}

	if a.prober != nil {
		log.Debug().Msg("Closing prober")
		if err := a.prober.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close prober")
		}
	}

	if a.controllerClient != nil {
		log.Debug().Msg("Closing controller client")
		if err := a.controllerClient.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close controller client")
		}
	}

	// Shutdown metrics if enabled
	if a.metrics != nil {
		log.Debug().Msg("Shutting down metrics")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := a.metrics.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown metrics properly")
		}
	}

	if a.agentState != nil {
		log.Debug().Msg("Closing agent state")
		a.agentState.Close()
	}

	// Wait for goroutines to complete
	log.Debug().Msg("Waiting for background goroutines to complete")
	a.wg.Wait()
	log.Info().Msg("Agent stopped")
}

// Run runs the agent with signal handling for graceful shutdown
func (a *Agent) Run() error {
	log.Debug().Msg("Running agent")

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	log.Debug().Msg("Signal handlers set up")

	// Start the agent
	go func() {
		if err := a.Start(); err != nil {
			log.Error().Err(err).Msg("Failed to start agent")
		}
	}()

	// Wait for the first signal
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("Received signal, shutting down gracefully...")

	// Create a new channel for the second signal
	forceQuitCh := make(chan os.Signal, 1)
	signal.Notify(forceQuitCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for the second signal in a separate goroutine
	go func() {
		<-forceQuitCh
		log.Warn().Msg("Received second signal, forcing immediate exit...")
		os.Exit(1)
	}()

	// Normal shutdown process
	a.Stop()

	// This won't be reached if forceQuit is called
	log.Info().Msg("Agent shut down gracefully")
	return nil
}

// initLogging initializes the logging configuration
func initLogging(level string) {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Set log level based on config
	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Configure pretty logging for development
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}
