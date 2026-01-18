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
	"github.com/yuuki/rpingmesh/internal/agent/serviceflowmonitor"
	"github.com/yuuki/rpingmesh/internal/agent/telemetry"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/ebpf"
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

// Constants
const (
	// Uploader constants
	UploaderBatchSize    = 1000
	UploaderMaxQueueSize = 10000

	// Goroutine counts
	NumBackgroundGoroutines = 2

	// Timing constants
	MetricsShutdownTimeout = 3 * time.Second

	// Tracer constants
	PeriodicTraceHopLimit = 3

	// Signal constants
	ShutdownSignals = "SIGINT, SIGTERM"
)

// Log levels
const (
	LogLevelTrace = "trace"
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// Agent represents the RPingMesh agent
type Agent struct {
	ctx                context.Context
	cancel             context.CancelFunc
	config             *config.AgentConfig
	agentState         *state.AgentState
	controllerClient   *controller_client.ControllerClient
	prober             *probe.Prober
	clusterMonitor     *monitor.ClusterMonitor
	tracer             *tracer.Tracer
	uploader           *upload.Uploader
	metrics            *telemetry.Metrics
	serviceTracer      *ebpf.ServiceTracer
	serviceFlowMonitor *serviceflowmonitor.ServiceFlowMonitor
	wg                 sync.WaitGroup
}

// New creates a new agent instance
func New(cfg *config.AgentConfig) (*Agent, error) {
	// Initialize logging
	initLogging(cfg.LogLevel)

	log.Debug().Msg("Creating new agent instance")

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create agent state
	agentState := state.NewAgentState(cfg.AgentID, cfg.HostName, "", cfg.GIDIndex)

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

	// Initialize eBPF ServiceTracer if eBPF is generally enabled
	if cfg.EBPFEnabled {
		st, err := ebpf.NewServiceTracer()
		if err != nil {
			// If eBPF is required but fails, we might want to error out,
			// especially if ServiceFlowMonitor is also enabled.
			log.Error().Err(err).Msg("Failed to initialize eBPF ServiceTracer")
			// Depending on strictness, could return an error here:
			// return nil, fmt.Errorf("failed to initialize eBPF ServiceTracer: %w", err)
			// For now, log and continue, ServiceFlowMonitor init will then also likely fail or be skipped.
		} else {
			agent.serviceTracer = st
			log.Info().Msg("eBPF ServiceTracer initialized.")
		}
	} else {
		log.Info().Msg("eBPF is disabled. ServiceFlowMonitor will not be available.")
	}

	log.Debug().Str("agent_id", cfg.AgentID).Str("controller_addr", cfg.ControllerAddr).Msg("Agent instance partially created, prober and SFM to be initialized in Start")
	return agent, nil
}

// Start starts the agent
func (a *Agent) Start() error {
	log.Debug().Msg("Starting agent")

	// Initialize agent state's RDMA infrastructure first.
	if err := a.agentState.InitializeRDMAInfrastructure(a.config.AllowedDeviceNames); err != nil {
		return fmt.Errorf("failed to initialize agent RDMA infrastructure: %w", err)
	}
	log.Debug().Msg("Agent RDMA infrastructure initialized")

	// After RDMA infra is up, check if any RNICs are available before proceeding.
	if len(a.agentState.GetDetectedRNICs()) == 0 {
		var errStr string
		if len(a.config.AllowedDeviceNames) > 0 {
			errStr = fmt.Sprintf("No RNIC devices available after RDMA infra initialization and filtering by AllowedDeviceNames: %v. Agent cannot start.", a.config.AllowedDeviceNames)
		} else {
			errStr = "No RNIC devices detected or initialized successfully in RDMA infra. Agent cannot start."
		}
		return fmt.Errorf("%s", errStr)
	}

	// Create prober - Prober itself does not start its loops yet.
	a.prober = probe.NewProber(a.agentState.GetRDMAManager(), a.agentState)
	log.Debug().Msg("Prober instance created")

	// Set the ACK handler in AgentState now that prober is created.
	a.agentState.SetAckHandler(a.prober.HandleIncomingRDMAPacket)
	log.Debug().Msg("ACK handler set in AgentState")

	// Now initialize UD Queues in AgentState, it will use the handler set above.
	if err := a.agentState.InitializeUDQueues(); err != nil {
		return fmt.Errorf("failed to initialize agent UD queues: %w", err)
	}
	log.Debug().Msg("Agent UD queues initialized with ACK handler")

	// Now that UD queues are ready (including those for the prober), start the prober's internal loops.
	if err := a.prober.Start(); err != nil {
		return fmt.Errorf("failed to start prober: %w", err)
	}
	log.Debug().Msg("Prober started")

	// Initialize and start ServiceFlowMonitor if enabled
	if a.config.ServiceFlowMonitorEnabled {
		if !a.config.EBPFEnabled || a.serviceTracer == nil {
			log.Warn().Msg("ServiceFlowMonitor is enabled in config, but eBPF is disabled or eBPF ServiceTracer failed to initialize. ServiceFlowMonitor will NOT start.")
		} else {
			sfm, err := serviceflowmonitor.NewServiceFlowMonitor(a.ctx, a.serviceTracer, a.controllerClient, a.prober, a.agentState)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create ServiceFlowMonitor")
				// Potentially return error, or continue without it
			} else {
				a.serviceFlowMonitor = sfm
				if err := a.serviceTracer.Start(); err != nil { // Start the eBPF tracer itself
					log.Error().Err(err).Msg("Failed to start eBPF ServiceTracer for ServiceFlowMonitor")
					// SFM might not work correctly, decide if this is fatal
				} else {
					a.serviceFlowMonitor.Start() // Start the monitor component that uses the tracer
					log.Info().Msg("ServiceFlowMonitor started.")
				}
			}
		}
	} else {
		log.Info().Msg("ServiceFlowMonitor is disabled via configuration.")
	}

	// Connect to controller
	if err := a.controllerClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to controller: %w", err)
	}
	log.Debug().Msg("Connected to controller")

	// Register with controller
	if err := a.controllerClient.RegisterAgent(
		a.agentState.GetAgentID(),
		a.agentState.GetHostName(),
		a.agentState.GetAgentIP(),
		a.agentState.GetDetectedRNICs(),
	); err != nil {
		return fmt.Errorf("failed to register agent with controller: %w", err)
	}
	log.Info().Msg("Registered agent with controller")

	primaryRnic := a.agentState.GetPrimaryRNIC()
	if primaryRnic == nil {
		// This case should ideally be caught after filtering if AllowedDeviceNames is used.
		// If AllowedDeviceNames is empty, this means no devices were found or initialized properly.
		var errMsg string
		if len(a.config.AllowedDeviceNames) > 0 {
			errMsg = fmt.Sprintf("no primary RDMA device available after filtering with allowed names: %v", a.config.AllowedDeviceNames)
		} else {
			errMsg = "no primary RDMA device available or none initialized successfully"
		}
		log.Error().Msg(errMsg)
		return fmt.Errorf("%s", errMsg)
	}

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

	// Create cluster monitor
	// Use ProbeIntervalMS as initial timeout (will be updated from controller)
	a.clusterMonitor = monitor.NewClusterMonitor(
		a.agentState,
		a.prober,
		a.config.ProbeIntervalMS,
		a.config.ProbeIntervalMS, // Initial timeout, will be updated from controller
		a.config.TargetProbeRatePerSecond,
	)
	if err := a.clusterMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start cluster monitor: %w", err)
	}
	log.Debug().
		Uint32("probe_interval_ms", a.config.ProbeIntervalMS).
		Int("target_probe_rate_per_second", a.config.TargetProbeRatePerSecond).
		Msg("Cluster monitor started")

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
				a.agentState.GetHostName(),
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
					a.tracer.StartPeriodicTracing(a.ctx, primaryRnic.GID, targets, a.config.TracerouteIntervalMS, PeriodicTraceHopLimit)
				}
			}
		}
	}

	// Create uploader
	a.uploader = upload.NewUploader(
		a.config.AnalyzerAddr,
		a.agentState.GetAgentID(),
		a.config.DataUploadIntervalMS,
		UploaderBatchSize,    // Batch size
		UploaderMaxQueueSize, // Max queue size
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
	a.wg.Add(NumBackgroundGoroutines)
	go a.resultHandler()
	go a.runPinglistUpdater()
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
				Float64("rtt_us", float64(result.NetworkRtt)/1000000.0).
				Msg("Received probe result")

			// Record metrics if enabled
			if a.metrics != nil {
				// Get device names and agent IDs from RNIC identifiers
				var srcDeviceName, dstDeviceName, dstAgentID, dstHostname string

				// Get source device name from probe result's source RNIC
				if result.SourceRnic != nil {
					srcDeviceName = result.SourceRnic.DeviceName
				}

				// Get destination device name and agent ID from destination RNIC
				if result.DestinationRnic != nil {
					dstAgentID = result.DestinationRnic.HostName
					dstDeviceName = result.DestinationRnic.DeviceName
					dstHostname = result.DestinationRnic.HostName
				}

				// Create common attributes
				commonAttrs := attribute.NewSet(
					attribute.String("src_agent_id", a.agentState.GetAgentID()),
					attribute.String("dst_agent_id", dstAgentID),
					attribute.String("src_hostname", a.agentState.GetHostName()),
					attribute.String("dst_hostname", dstHostname),
					attribute.String("src_gid", result.FiveTuple.SrcGid),
					attribute.String("dst_gid", result.FiveTuple.DstGid),
					attribute.String("src_device_name", srcDeviceName),
					attribute.String("dst_device_name", dstDeviceName),
					attribute.String("probe_type", result.ProbeType),
				)

				// Record metrics based on probe status
				if result.Status == agent_analyzer.ProbeResult_OK {
					// Record RTT with RecordOption
					a.metrics.RecordRTT(a.ctx, result.NetworkRtt, metric.WithAttributeSet(commonAttrs))

					// Record processing delays with RecordOption
					a.metrics.RecordProberDelay(a.ctx, result.ProberDelay, metric.WithAttributeSet(commonAttrs))
					a.metrics.RecordResponderDelay(a.ctx, result.ResponderDelay, metric.WithAttributeSet(commonAttrs))
				} else if result.Status == agent_analyzer.ProbeResult_TIMEOUT {
					// Record timeout with AddOption
					a.metrics.RecordTimeout(a.ctx, metric.WithAttributeSet(commonAttrs))
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

// runPinglistUpdater periodically updates the pinglist from the controller
func (a *Agent) runPinglistUpdater() {
	log.Info().Msg("Starting pinglist updater loop")
	a.updatePinglist()

	// Set up periodic update
	ticker := time.NewTicker(time.Duration(a.config.PinglistUpdateIntervalSec) * time.Second)
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

// updatePinglist gets a fresh pinglist from the controller for all local RNICs
func (a *Agent) updatePinglist() {
	log.Debug().Msg("Updating pinglist from controller")

	// Get all detected RNICs instead of just the primary one
	localRnics := a.agentState.GetDetectedRNICs()
	if len(localRnics) == 0 {
		log.Error().Msg("No local RNICs available")
		return
	}
	log.Debug().Int("local_rnic_count", len(localRnics)).Msg("Retrieved local RNICs for pinglist requests")

	// Collect all targets from all RNICs to avoid duplicates and ensure proper flow label distribution
	allTorTargets := make([]*controller_agent.PingTarget, 0)
	allInterTorTargets := make([]*controller_agent.PingTarget, 0)

	var lastIntervalMs uint32
	var lastTimeoutMs uint32

	// Get pinglist for each local RNIC to ensure unique flow labels
	for _, localRnic := range localRnics {
		if localRnic == nil || localRnic.GID == "" {
			log.Warn().Msg("Skipping invalid local RNIC")
			continue
		}

		log.Debug().Str("local_rnic_gid", localRnic.GID).Msg("Getting pinglist for local RNIC")

		// Get ToR-mesh pinglist for this RNIC
		torTargets, intervalMs, timeoutMs, err := a.controllerClient.GetPinglist(
			localRnic,
			a.agentState.GetHostName(),
			controller_agent.PinglistRequest_TOR_MESH,
		)
		if err != nil {
			log.Error().Err(err).Str("rnic_gid", localRnic.GID).Msg("Failed to get ToR-mesh pinglist for RNIC")
			continue
		}
		log.Debug().Str("rnic_gid", localRnic.GID).Int("target_count", len(torTargets)).Msg("Received ToR-mesh pinglist data for RNIC")

		// Add targets to the combined list
		allTorTargets = append(allTorTargets, torTargets...)

		// Get Inter-ToR pinglist for this RNIC
		interTorTargets, _, _, err := a.controllerClient.GetPinglist(
			localRnic,
			a.agentState.GetHostName(),
			controller_agent.PinglistRequest_INTER_TOR,
		)
		if err != nil {
			log.Error().Err(err).Str("rnic_gid", localRnic.GID).Msg("Failed to get Inter-ToR pinglist for RNIC")
			continue
		}
		log.Debug().Str("rnic_gid", localRnic.GID).Int("target_count", len(interTorTargets)).Msg("Received Inter-ToR pinglist data for RNIC")

		// Add targets to the combined list
		allInterTorTargets = append(allInterTorTargets, interTorTargets...)

		// Store the last valid interval and timeout values
		if intervalMs > 0 {
			lastIntervalMs = intervalMs
		}
		if timeoutMs > 0 {
			lastTimeoutMs = timeoutMs
		}
	}

	// Log combined ToR-mesh targets grouped by AgentID
	torTargetsByAgent := make(map[string][]*controller_agent.RnicInfo)
	for _, target := range allTorTargets {
		if target.TargetRnic != nil {
			torTargetsByAgent[target.TargetRnic.HostName] = append(torTargetsByAgent[target.TargetRnic.HostName], target.TargetRnic)
		}
	}
	log.Debug().Interface("tor_targets_by_hostname", torTargetsByAgent).Msg("Combined ToR-mesh pinglist targets grouped by hostname")

	// Log combined Inter-ToR targets grouped by AgentID
	interTorTargetsByAgent := make(map[string][]string)
	for _, target := range allInterTorTargets {
		if target.TargetRnic != nil {
			interTorTargetsByAgent[target.TargetRnic.HostName] = append(interTorTargetsByAgent[target.TargetRnic.HostName], target.TargetRnic.Gid)
		}
	}
	log.Debug().Interface("inter_tor_targets_by_hostname", interTorTargetsByAgent).Msg("Combined Inter-ToR pinglist targets grouped by hostname")

	// Update probe interval if controller specified it
	if lastIntervalMs > 0 && lastIntervalMs != a.config.ProbeIntervalMS {
		log.Debug().Uint32("old_interval_ms", a.config.ProbeIntervalMS).Uint32("new_interval_ms", lastIntervalMs).Msg("Updating probe interval")
		a.config.ProbeIntervalMS = lastIntervalMs
		log.Info().Uint32("interval_ms", lastIntervalMs).Msg("Updated probe interval from controller")
	}

	// Update probe timeout if controller specified it
	if lastTimeoutMs > 0 {
		a.clusterMonitor.UpdateTimeout(lastTimeoutMs)
		log.Info().Uint32("timeout_ms", lastTimeoutMs).Msg("Updated probe timeout from controller")
	}

	// Update cluster monitor's pinglist with combined targets
	a.clusterMonitor.UpdatePinglist(allTorTargets)
	log.Debug().Msg("Updated cluster monitor pinglist with combined targets")

	// Log summary
	log.Info().
		Int("total_tor_targets", len(allTorTargets)).
		Int("total_inter_tor_targets", len(allInterTorTargets)).
		Int("local_rnics", len(localRnics)).
		Msg("Updated pinglists for all local RNICs")
}

// Stop stops the agent
func (a *Agent) Stop() {
	log.Info().Msg("Stopping agent")
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

	if a.serviceFlowMonitor != nil {
		log.Debug().Msg("Stopping ServiceFlowMonitor")
		a.serviceFlowMonitor.Stop()
	}

	if a.serviceTracer != nil { // Should be stopped after ServiceFlowMonitor uses it
		log.Debug().Msg("Stopping eBPF ServiceTracer")
		if err := a.serviceTracer.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop eBPF ServiceTracer")
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), MetricsShutdownTimeout)
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
	defer signal.Stop(sigCh)
	log.Debug().Msg("Signal handlers set up")

	// Start the agent and surface startup failures
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- a.Start()
	}()

	// Wait for startup to finish or for an early signal
	select {
	case err := <-startErrCh:
		if err != nil {
			log.Error().Err(err).Msg("Failed to start agent")
			a.Stop()
			return err
		}
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("Received signal during startup, shutting down gracefully...")
		a.Stop()
		return nil
	}

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
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMicro
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Set log level based on config
	switch level {
	case LogLevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case LogLevelInfo:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case LogLevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case LogLevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case LogLevelTrace:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Configure pretty logging for development
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}
