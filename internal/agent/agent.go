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
func New(configPath string) (*Agent, error) {
	// Load configuration
	cfg, err := config.LoadAgentConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logging
	initLogging(cfg.LogLevel)

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

	return agent, nil
}

// Start starts the agent
func (a *Agent) Start() error {
	// Initialize agent state
	if err := a.agentState.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize agent state: %w", err)
	}

	// Connect to controller
	if err := a.controllerClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to controller: %w", err)
	}

	// Register with controller
	primaryRnic := a.agentState.GetPrimaryRNIC()
	if primaryRnic == nil {
		return fmt.Errorf("no RDMA devices available")
	}

	udQueue := a.agentState.GetUDQueue(primaryRnic.GID)
	if udQueue == nil {
		return fmt.Errorf("no UD queue available for RNIC %s", primaryRnic.GID)
	}

	// Create prober
	a.prober = probe.NewProber(a.agentState.GetRDMAManager(), udQueue, a.config.TimeoutMS)
	if err := a.prober.Start(); err != nil {
		return fmt.Errorf("failed to start prober: %w", err)
	}

	// Create cluster monitor
	a.clusterMonitor = monitor.NewClusterMonitor(
		a.agentState,
		a.prober,
		a.config.ProbeIntervalMS,
	)
	if err := a.clusterMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start cluster monitor: %w", err)
	}

	// Create tracer
	a.tracer = tracer.NewTracer()

	// Create uploader
	a.uploader = upload.NewUploader(
		a.config.AnalyzerAddr,
		a.agentState.GetAgentID(),
		a.config.DataUploadIntervalMS,
		1000,  // Batch size
		10000, // Max queue size
	)
	if err := a.uploader.Start(); err != nil {
		return fmt.Errorf("failed to start uploader: %w", err)
	}

	// Start background goroutines
	a.wg.Add(2)
	go a.resultHandler()
	go a.pinglistUpdater()

	log.Info().Msg("Agent started successfully")
	return nil
}

// resultHandler collects and forwards results from components
func (a *Agent) resultHandler() {
	defer a.wg.Done()

	// Handle probe results
	probeResults := a.prober.GetProbeResults()
	// Handle trace results
	traceResults := a.tracer.GetTraceResults()

	for {
		select {
		case <-a.ctx.Done():
			return
		case result, ok := <-probeResults:
			if !ok {
				return
			}
			// Forward to uploader
			a.uploader.AddProbeResult(result)

			// If it's a timeout, maybe run a traceroute
			if result.Status == 1 && a.config.TracerouteOnTimeout {
				go func(fiveTuple *agent_analyzer.ProbeFiveTuple) {
					if err := a.tracer.Trace(a.ctx, fiveTuple); err != nil {
						log.Error().Err(err).Msg("Failed to run traceroute")
					}
				}(result.FiveTuple)
			}
		case traceInfo, ok := <-traceResults:
			if !ok {
				return
			}
			// Forward to uploader
			a.uploader.AddPathInfo(traceInfo)
		}
	}
}

// pinglistUpdater periodically updates the pinglist from the controller
func (a *Agent) pinglistUpdater() {
	defer a.wg.Done()

	// Initial update
	a.updatePinglist()

	// Set up periodic update
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.updatePinglist()
		}
	}
}

// updatePinglist gets a fresh pinglist from the controller
func (a *Agent) updatePinglist() {
	primaryRnic := a.agentState.GetPrimaryRNIC()
	if primaryRnic == nil {
		log.Error().Msg("No primary RNIC available")
		return
	}

	// Get ToR-mesh pinglist
	torTargets, intervalMs, timeoutMs, err := a.controllerClient.GetPinglist(
		primaryRnic,
		controller_agent.PinglistRequest_TOR_MESH,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ToR-mesh pinglist")
		return
	}

	// Update probe timeout if controller specified it
	if timeoutMs > 0 && timeoutMs != a.config.TimeoutMS {
		a.config.TimeoutMS = timeoutMs
		log.Info().Uint32("timeout_ms", timeoutMs).Msg("Updated probe timeout from controller")
	}

	// Update probe interval if controller specified it
	if intervalMs > 0 && intervalMs != a.config.ProbeIntervalMS {
		a.config.ProbeIntervalMS = intervalMs
		log.Info().Uint32("interval_ms", intervalMs).Msg("Updated probe interval from controller")
	}

	// Update cluster monitor's pinglist
	a.clusterMonitor.UpdatePinglist(torTargets)

	// Also get Inter-ToR pinglist
	interTorTargets, _, _, err := a.controllerClient.GetPinglist(
		primaryRnic,
		controller_agent.PinglistRequest_INTER_TOR,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get Inter-ToR pinglist")
		return
	}

	// Combine the pinglists (in a real implementation, you might want to keep them separate)
	log.Info().Int("torTargets", len(torTargets)).Int("interTorTargets", len(interTorTargets)).Msg("Updated pinglists")
}

// Stop stops the agent
func (a *Agent) Stop() {
	a.cancel()

	// Stop components in reverse order
	if a.uploader != nil {
		_ = a.uploader.Close()
	}

	if a.tracer != nil {
		_ = a.tracer.Close()
	}

	if a.clusterMonitor != nil {
		a.clusterMonitor.Stop()
	}

	if a.prober != nil {
		a.prober.Close()
	}

	if a.controllerClient != nil {
		_ = a.controllerClient.Close()
	}

	if a.agentState != nil {
		a.agentState.Close()
	}

	// Wait for goroutines to complete
	a.wg.Wait()
	log.Info().Msg("Agent stopped")
}

// Run runs the agent with signal handling for graceful shutdown
func (a *Agent) Run() error {
	// Start the agent
	if err := a.Start(); err != nil {
		return err
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for a signal
	<-sigCh
	log.Info().Msg("Received signal, shutting down...")

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
