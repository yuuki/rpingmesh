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
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/monitor"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/state"
	"github.com/yuuki/rpingmesh/internal/tracer"
	"github.com/yuuki/rpingmesh/internal/upload"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
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

	// Create prober
	a.prober = probe.NewProber(a.agentState.GetRDMAManager(), udQueue, a.config.TimeoutMS)
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

	// Create tracer
	a.tracer = tracer.NewTracer()
	log.Debug().Msg("Tracer created")

	// Create uploader
	a.uploader = upload.NewUploader(
		a.config.AnalyzerAddr,
		a.agentState.GetAgentID(),
		a.config.DataUploadIntervalMS,
		1000,  // Batch size
		10000, // Max queue size
	)
	log.Debug().Msg("Uploader created")
	if err := a.uploader.Start(); err != nil {
		log.Warn().Err(err).Str("analyzer_addr", a.config.AnalyzerAddr).Msg("Failed to start uploader, will retry later. Agent will continue without analyzer connection")
	} else {
		log.Debug().Str("analyzer_addr", a.config.AnalyzerAddr).Uint32("upload_interval_ms", a.config.DataUploadIntervalMS).Msg("Uploader started")
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
	// Handle trace results
	traceResults := a.tracer.GetTraceResults()

	for {
		select {
		case <-a.ctx.Done():
			log.Debug().Msg("Result handler stopping due to context cancellation")
			return
		case result, ok := <-probeResults:
			if !ok {
				log.Debug().Msg("Probe results channel closed")
				return
			}
			log.Debug().
				Str("src_gid", result.FiveTuple.SrcGid).
				Str("dst_gid", result.FiveTuple.DstGid).
				Int32("status", int32(result.Status)).
				Float64("rtt_ms", float64(result.NetworkRtt)/1000000.0).
				Msg("Received probe result")

			// Forward to uploader
			if a.uploader != nil {
				a.uploader.AddProbeResult(result)
			} else {
				log.Debug().Msg("Uploader not available, probe result discarded")
			}

			// If it's a timeout, maybe run a traceroute
			if result.Status == 1 && a.config.TracerouteOnTimeout {
				log.Debug().
					Str("dst_gid", result.FiveTuple.DstGid).
					Msg("Timeout detected, initiating traceroute")

				go func(fiveTuple *agent_analyzer.ProbeFiveTuple) {
					if err := a.tracer.Trace(a.ctx, fiveTuple); err != nil {
						log.Error().Err(err).Msg("Failed to run traceroute")
					}
				}(result.FiveTuple)
			}
		case traceInfo, ok := <-traceResults:
			if !ok {
				log.Debug().Msg("Trace results channel closed")
				return
			}
			log.Debug().
				Str("src_gid", traceInfo.FiveTuple.SrcGid).
				Str("dst_gid", traceInfo.FiveTuple.DstGid).
				Int("hop_count", len(traceInfo.Hops)).
				Msg("Received trace result")

			// Forward to uploader
			if a.uploader != nil {
				a.uploader.AddPathInfo(traceInfo)
			} else {
				log.Debug().Msg("Uploader not available, path info discarded")
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
	if a.uploader != nil {
		log.Debug().Msg("Closing uploader")
		_ = a.uploader.Close()
	}

	if a.tracer != nil {
		log.Debug().Msg("Closing tracer")
		_ = a.tracer.Close()
	}

	if a.clusterMonitor != nil {
		log.Debug().Msg("Stopping cluster monitor")
		a.clusterMonitor.Stop()
	}

	if a.prober != nil {
		log.Debug().Msg("Closing prober")
		a.prober.Close()
	}

	if a.controllerClient != nil {
		log.Debug().Msg("Closing controller client")
		_ = a.controllerClient.Close()
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

	// Wait for a signal
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("Received signal, shutting down...")

	// Stop the agent
	a.Stop()
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
