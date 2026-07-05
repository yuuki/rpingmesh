// Package agent implements the R-Pingmesh agent lifecycle, orchestrating RDMA
// device management, probe responders, active probing, controller registration,
// cluster monitoring, and telemetry collection.
package agent

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/internal/telemetry"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// Timing constants for shutdown operations.
const (
	metricsShutdownTimeout = 5 * time.Second
	eventRingCapacity      = 1024 // Power of 2 for optimal SPSC ring performance.

	// heartbeatInterval is the period between periodic re-registration
	// heartbeats sent to the controller. The controller's liveness check
	// considers an agent dead once last_updated_epoch is older than 300s,
	// so this must be well under that threshold.
	heartbeatInterval = 60 * time.Second

	// heartbeatFailureEscalationThreshold is the number of consecutive
	// heartbeat failures after which log severity is escalated from Warn
	// to Error, to surface sustained controller unreachability without
	// being noisy about single transient failures.
	heartbeatFailureEscalationThreshold = 3

	// Initial registration retry parameters: exponential backoff starting
	// at registerRetryInitialBackoff, doubling up to registerRetryMaxBackoff,
	// for up to registerRetryMaxAttempts total attempts.
	registerRetryInitialBackoff = 1 * time.Second
	registerRetryMaxBackoff     = 30 * time.Second
	registerRetryMaxAttempts    = 6
)

// Agent orchestrates all R-Pingmesh agent components: RDMA context, devices,
// responders, probers, cluster monitors, and telemetry. It handles
// initialization, registration with the controller, and graceful shutdown.
//
// One Prober, one ClusterMonitor, and one prober EventRing are created per
// opened RDMA device so that every RNIC on a multi-rail host actively probes
// (not just the first device), matching the fact that every device is
// registered with the controller and can be targeted by other agents'
// pinglists.
type Agent struct {
	cfg         *config.AgentConfig
	rdmaCtx     *rdmabridge.Context
	devices     []*rdmabridge.Device
	responders  []*Responder
	probers     []*Prober
	monitors    []*ClusterMonitor
	grpcClient  *controller_client.GRPCControllerClient
	metrics     *telemetry.MetricsCollector
	proberRings []*rdmabridge.EventRing
	respRings   []*rdmabridge.EventRing
	logger      zerolog.Logger

	// results is the fan-in destination for every prober's Results()
	// channel (see createResultsFanIn), consumed by the metrics result
	// consumer as a single stream.
	results   chan *probe.ProbeResult
	resultsWg sync.WaitGroup

	// resultsDone is closed by stopResultsFanIn (called from Stop) to tell
	// every fan-in goroutine to stop forwarding immediately, even if it is
	// currently blocked trying to send on a full results channel. Without
	// this, a fan-in goroutine has no way to unblock when nothing drains
	// a.results (e.g. metrics disabled, or MetricsCollector creation
	// failed), which would leak the goroutine and any buffered results
	// forever instead of letting Stop complete deterministically.
	resultsDone chan struct{}

	// analysisResults is the secondary fan-out branch of the results fan-in,
	// feeding the AnalysisReporter (per-path window aggregation). It is nil
	// when analysis reporting is disabled. The fan-in tees onto it with a
	// non-blocking send so a backed-up aggregator can never stall the primary
	// metrics path; it is closed by stopResultsFanIn after every fan-in
	// goroutine has exited (so no send races the close).
	analysisResults chan *probe.ProbeResult

	// analysisReporter drives the PathAggregator and ships completed window
	// summaries to the controller via ReportProbeAnalysis. nil when analysis
	// reporting is disabled.
	analysisReporter *AnalysisReporter

	// watchdog samples this process's CPU/memory and throttles every prober's
	// send rate (fail-slow) under pressure. nil when self-protection is
	// disabled (the default).
	watchdog *Watchdog

	// metricsResultsActive records whether a metrics result consumer will drain
	// a.results (i.e. a.metrics != nil). It is decided before createResultsFanIn
	// and read by each fan-in goroutine: when false, the fan-in does NOT send on
	// a.results at all. Otherwise a full a.results (which nobody drains when
	// metrics are disabled or MetricsCollector creation failed) would block the
	// fan-in, stopping it reading from the probers and starving the independent
	// analysis tee. Analysis reporting can be enabled without metrics, so the
	// two branches must not be coupled.
	metricsResultsActive bool

	// agentIP is the host's outbound IP toward the controller, reported in the
	// registration request's agent_ip field. Best-effort: empty if it cannot be
	// determined, which never blocks registration.
	agentIP string

	// heartbeatStopCh and heartbeatWg control the lifecycle of the
	// background heartbeat goroutine that periodically re-registers with
	// the controller to keep the agent's registry entry alive.
	heartbeatStopCh chan struct{}
	heartbeatWg     sync.WaitGroup
}

// NewAgent creates a new Agent instance with the given configuration.
// The agent is not started until Initialize and Start are called.
func NewAgent(cfg *config.AgentConfig) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("agent config must not be nil")
	}

	a := &Agent{
		cfg:    cfg,
		logger: log.With().Str("component", "agent").Logger(),
	}

	// Apply optional hard runtime caps as early as possible (before any heavy
	// allocation) so a soft memory limit governs the whole process lifetime.
	applyRuntimeLimits(cfg, a.logger)

	return a, nil
}

// applyRuntimeLimits applies the optional hard runtime caps from config: a soft
// memory limit (GOMEMLIMIT, via debug.SetMemoryLimit) and a GOMAXPROCS cap.
// Both are opt-in (0 leaves the Go default) and applied independently of
// self_protection_enabled, so they can serve as plain runtime tuning knobs. The
// memory limit also acts as the reference budget the watchdog throttles against.
func applyRuntimeLimits(cfg *config.AgentConfig, logger zerolog.Logger) {
	if cfg.MaxMemoryMB > 0 {
		limit := int64(cfg.MaxMemoryMB) * bytesPerMiB
		debug.SetMemoryLimit(limit)
		logger.Info().
			Int("max_memory_mb", cfg.MaxMemoryMB).
			Int64("gomemlimit_bytes", limit).
			Msg("Applied soft memory limit (GOMEMLIMIT)")
	}
	if cfg.MaxProcs > 0 {
		prev := runtime.GOMAXPROCS(cfg.MaxProcs)
		logger.Info().
			Int("max_procs", cfg.MaxProcs).
			Int("previous_gomaxprocs", prev).
			Msg("Capped GOMAXPROCS")
	}
}

// Initialize performs all setup steps required before the agent can be started.
// It initializes the RDMA subsystem, opens devices, creates the gRPC client,
// builds event rings for the prober and responders, registers with the controller,
// and creates the cluster monitor.
func (a *Agent) Initialize(ctx context.Context) error {
	// Step 1: Initialize RDMA context.
	a.logger.Info().Msg("Initializing RDMA context")
	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize RDMA context: %w", err)
	}
	a.rdmaCtx = rdmaCtx

	// Step 2: Open RDMA devices.
	a.logger.Info().Msg("Opening RDMA devices")
	if err := a.openDevices(); err != nil {
		return fmt.Errorf("failed to open RDMA devices: %w", err)
	}
	if len(a.devices) == 0 {
		return fmt.Errorf("no RDMA devices available")
	}
	a.logger.Info().Int("device_count", len(a.devices)).Msg("RDMA devices opened")

	// Step 3: Create gRPC client for controller communication.
	a.logger.Info().
		Str("controller_addr", a.cfg.ControllerAddr).
		Msg("Creating gRPC controller client")
	grpcClient, err := controller_client.NewGRPCControllerClient(a.cfg.ControllerAddr, &config.TLSClientConfig{
		Mode:       a.cfg.TLSMode,
		CertFile:   a.cfg.TLSCertFile,
		KeyFile:    a.cfg.TLSKeyFile,
		CAFile:     a.cfg.TLSCAFile,
		ServerName: a.cfg.TLSServerName,
	})
	if err != nil {
		return fmt.Errorf("failed to create gRPC controller client: %w", err)
	}
	a.grpcClient = grpcClient

	// Step 4: Create event rings (one prober ring and one responder ring per device).
	a.logger.Info().Msg("Creating event rings")
	if err := a.createEventRings(); err != nil {
		return fmt.Errorf("failed to create event rings: %w", err)
	}

	// Step 5: Create one prober per device, so every RNIC actively probes
	// instead of only the first one. This closes the multi-rail monitoring
	// blind spot where every device is registered and probed BY other agents
	// but only devices[0] ever probed anyone.
	a.logger.Info().Int("device_count", len(a.devices)).Msg("Creating probers")
	for i, dev := range a.devices {
		prober, err := NewProber(dev, a.proberRings[i], a.cfg.ProbeIntervalMS)
		if err != nil {
			return fmt.Errorf("failed to create prober for device %s: %w",
				dev.Info.DeviceName, err)
		}
		torMeshRate := a.cfg.EffectiveTorMeshProbeRate()
		interTorRate := a.cfg.EffectiveInterTorProbeRate()
		if torMeshRate > 0 || interTorRate > 0 {
			// Per-target rate caps, differentiated by pinglist type (the prober
			// scales each type's aggregate limit with that type's target count).
			// When both per-type keys are unset they inherit the legacy
			// target_probe_rate_per_second, reproducing a single uniform cap.
			// Note the cap is per TARGET, not per flow label: a target's ECMP
			// label set shares this budget, bounding probe amplification.
			prober.SetPerTypeRateLimit(float64(torMeshRate), float64(interTorRate))
		}
		// Configure the ECMP flow-label rotation period (time-based rotation of
		// the rotating ~20% of each target's label set).
		prober.SetFlowLabelRotationPeriod(a.cfg.FlowLabelRotationPeriodSec)
		a.probers = append(a.probers, prober)
		a.logger.Info().
			Str("device", dev.Info.DeviceName).
			Uint32("qpn", prober.GetQueueInfo().QPN).
			Msg("Prober created")
	}

	// Create the metrics collector (if enabled) BEFORE the results fan-in, so
	// the fan-in knows whether a metrics result consumer will actually drain
	// a.results. If none will (metrics disabled, or MetricsCollector creation
	// failed), the fan-in must not send on a.results -- once its buffer filled,
	// the fan-in would block, stop reading from the probers, and starve the
	// independent analysis tee too.
	a.createMetricsCollector(ctx)
	a.metricsResultsActive = a.metrics != nil

	// Fan-in every prober's Results() channel into a single stream so the
	// rest of Initialize/Start can keep treating "the" probe result stream
	// as one channel, as before. When analysis reporting is enabled this also
	// creates the secondary analysis branch that the fan-in tees onto.
	a.createResultsFanIn()

	// Create the analysis reporter (per-path window aggregation + SLA
	// reporting to the controller) if enabled. It consumes the analysis branch
	// created by createResultsFanIn and reports on this agent's behalf.
	if a.cfg.AnalysisReportEnabled {
		a.analysisReporter = NewAnalysisReporter(
			a.grpcClient,
			a.cfg.AgentID,
			a.cfg.TorID,
			a.cfg.AnalysisWindowSec,
			a.analysisResults,
		)
		a.logger.Info().
			Uint32("window_sec", a.cfg.AnalysisWindowSec).
			Msg("Analysis reporter created")
	}

	// Create the resource watchdog (self-protection) if enabled. It throttles
	// every prober's send rate (fail-slow) when this process's CPU/memory
	// crosses the configured thresholds. Created after the probers (which it
	// drives) and the metrics collector (whose self_throttle gauge reads its
	// live multiplier).
	if a.cfg.SelfProtectionEnabled {
		throttlers := make([]rateThrottler, 0, len(a.probers))
		for _, p := range a.probers {
			throttlers = append(throttlers, p)
		}
		a.watchdog = NewWatchdog(a.cfg, throttlers)
		if a.metrics != nil {
			if err := a.metrics.RegisterSelfThrottleCallback(a.watchdog.CurrentMultiplier); err != nil {
				a.logger.Warn().Err(err).
					Msg("Failed to register self-throttle metric callback")
			}
		}
		a.logger.Info().
			Int("prober_count", len(a.probers)).
			Msg("Self-protection watchdog created")
	}

	// Step 6: Create one responder per device.
	a.logger.Info().Int("device_count", len(a.devices)).Msg("Creating responders")
	for i, dev := range a.devices {
		resp, err := NewResponder(dev, a.respRings[i])
		if err != nil {
			return fmt.Errorf("failed to create responder for device %s: %w",
				dev.Info.DeviceName, err)
		}
		a.responders = append(a.responders, resp)
		a.logger.Info().
			Str("device", dev.Info.DeviceName).
			Uint32("qpn", resp.GetQueueInfo().QPN).
			Msg("Responder created")
	}

	// (The metrics collector is created earlier, before the results fan-in; see
	// createMetricsCollector above.)

	// Determine the host's outbound IP toward the controller so it can be
	// reported in the registration. Best-effort: on failure agentIP stays
	// empty and registration proceeds unaffected.
	a.agentIP = outboundIP(a.cfg.ControllerAddr)
	if a.agentIP != "" {
		a.logger.Info().Str("agent_ip", a.agentIP).Msg("Determined agent outbound IP")
	} else {
		a.logger.Warn().
			Str("controller_addr", a.cfg.ControllerAddr).
			Msg("Could not determine agent outbound IP; registering without agent_ip")
	}

	// Step 8: Register with the controller.
	a.logger.Info().Msg("Registering with controller")
	if err := a.registerWithController(ctx); err != nil {
		return fmt.Errorf("failed to register with controller: %w", err)
	}

	// Step 9: Create one cluster monitor per device for periodic pinglist
	// updates, each requesting its pinglist with that device's own GID as
	// requester_gid and feeding targets to that device's prober.
	a.createClusterMonitors()

	a.logger.Info().Msg("Agent initialization complete")
	return nil
}

// createClusterMonitors creates one ClusterMonitor per device, each
// requesting its pinglist with that device's own GID as requester_gid and
// feeding fetched targets to that device's prober (a.probers[i]). This keeps
// each RNIC's probe targets scoped to requests made on its own behalf,
// matching how the controller's registry associates pinglists with GIDs, and
// closes the multi-rail blind spot where only devices[0] ever requested a
// pinglist. Requires a.probers to already be populated one-to-one with
// a.devices.
func (a *Agent) createClusterMonitors() {
	a.logger.Info().Int("device_count", len(a.devices)).Msg("Creating cluster monitors")
	for i, dev := range a.devices {
		requesterGID := dev.Info.GID
		a.logger.Info().
			Str("device", dev.Info.DeviceName).
			Str("requester_gid", requesterGID).
			Uint32("update_interval_sec", a.cfg.PinglistUpdateIntervalSec).
			Msg("Creating cluster monitor")
		monitor := NewClusterMonitor(
			a.grpcClient,
			a.probers[i],
			a.cfg.AgentID,
			a.cfg.TorID,
			requesterGID,
			a.cfg.PinglistUpdateIntervalSec,
		)
		a.monitors = append(a.monitors, monitor)
	}
}

// buildRegistrationRequest builds a registration request from the agent's
// configuration and device/responder state. It is used both for the initial
// registration and for periodic heartbeat re-registrations.
func (a *Agent) buildRegistrationRequest() *controller_agent.AgentRegistrationRequest {
	rnics := make([]*controller_agent.RnicInfo, 0, len(a.responders))

	for i, resp := range a.responders {
		dev := a.devices[i]
		queueInfo := resp.GetQueueInfo()

		rnic := &controller_agent.RnicInfo{
			Gid:        dev.Info.GID,
			Qpn:        queueInfo.QPN,
			IpAddress:  dev.Info.IPAddr,
			HostName:   a.cfg.HostName,
			TorId:      a.cfg.TorID,
			DeviceName: dev.Info.DeviceName,
		}
		rnics = append(rnics, rnic)

		a.logger.Debug().
			Str("gid", rnic.Gid).
			Uint32("qpn", rnic.Qpn).
			Str("ip", rnic.IpAddress).
			Str("device", rnic.DeviceName).
			Msg("Prepared RNIC info for registration")
	}

	return &controller_agent.AgentRegistrationRequest{
		AgentId:  a.cfg.AgentID,
		AgentIp:  a.agentIP,
		Hostname: a.cfg.HostName,
		TorId:    a.cfg.TorID,
		Rnics:    rnics,
	}
}

// outboundIP returns the local source IP the kernel would use to reach
// controllerAddr, via the classic connectionless UDP-dial trick: dialing a UDP
// address performs a route lookup and binds a local address but sends no
// packets, so LocalAddr() reveals the outbound interface IP. It is best-effort
// and returns "" on any error (e.g. an addr with no host such as ":50051").
func outboundIP(controllerAddr string) string {
	conn, err := net.Dial("udp", controllerAddr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() {
		return udpAddr.IP.String()
	}
	return ""
}

// registerAttemptErr builds an error describing why a single registration
// attempt was considered a failure, checking both the RPC error and the
// resp.Success field. The controller contract allows it to signal failure
// via either channel (a gRPC error, e.g. codes.Internal, or a false Success
// with a populated Message), so both must be checked.
func registerAttemptErr(resp *controller_agent.AgentRegistrationResponse, err error) error {
	if err != nil {
		return fmt.Errorf("RegisterAgent failed: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("agent registration rejected by controller: %s", resp.GetMessage())
	}
	return nil
}

// registerWithController sends the agent's registration request to the
// controller, retrying with exponential backoff on failure. A failure is
// anything that fails either the err or the resp.Success check, since the
// controller may report a rejected registration via a gRPC error, a
// Success=false response, or both. It returns an error only if every
// attempt fails.
func (a *Agent) registerWithController(ctx context.Context) error {
	req := a.buildRegistrationRequest()

	backoff := registerRetryInitialBackoff
	var lastErr error

	for attempt := 1; attempt <= registerRetryMaxAttempts; attempt++ {
		resp, err := a.grpcClient.RegisterAgent(ctx, req)
		attemptErr := registerAttemptErr(resp, err)
		if attemptErr == nil {
			a.logger.Info().
				Str("agent_id", a.cfg.AgentID).
				Int("rnic_count", len(req.GetRnics())).
				Str("message", resp.GetMessage()).
				Msg("Agent registered with controller")
			return nil
		}
		lastErr = attemptErr

		if attempt == registerRetryMaxAttempts {
			break
		}

		a.logger.Warn().Err(lastErr).
			Int("attempt", attempt).
			Int("max_attempts", registerRetryMaxAttempts).
			Dur("backoff", backoff).
			Msg("Agent registration attempt failed, retrying")

		select {
		case <-ctx.Done():
			return fmt.Errorf("registration cancelled: %w", ctx.Err())
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > registerRetryMaxBackoff {
			backoff = registerRetryMaxBackoff
		}
	}

	return fmt.Errorf("agent registration failed after %d attempts: %w", registerRetryMaxAttempts, lastErr)
}

// Start begins all agent components: responders, probers, cluster monitors,
// and the metrics result consumer. All components must be initialized via
// Initialize() before calling Start().
func (a *Agent) Start(ctx context.Context) error {
	// Start all responders.
	for i, resp := range a.responders {
		if err := resp.Start(ctx); err != nil {
			return fmt.Errorf("failed to start responder %d: %w", i, err)
		}
	}

	// Start all probers (one per device).
	for i, prober := range a.probers {
		if err := prober.Start(ctx); err != nil {
			return fmt.Errorf("failed to start prober %d: %w", i, err)
		}
	}

	// Start all cluster monitors for periodic pinglist updates.
	for i, monitor := range a.monitors {
		if err := monitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start cluster monitor %d: %w", i, err)
		}
	}

	// Start the heartbeat goroutine to periodically re-register with the
	// controller, keeping the agent's registry entry alive.
	a.startHeartbeat(ctx)

	// Start the metrics result consumer if metrics are enabled. It reads from
	// the fan-in channel that merges every prober's results (see
	// createResultsFanIn), so results from every device are recorded.
	if a.metrics != nil {
		a.metrics.StartResultConsumer(ctx, a.results, a.cfg.TorID)
		a.logger.Info().Msg("Metrics result consumer started")
	}

	// Start the analysis reporter if enabled. It consumes the secondary
	// analysis branch of the fan-in independently of the metrics consumer.
	if a.analysisReporter != nil {
		a.analysisReporter.Start(ctx)
	}

	// Start the resource watchdog if enabled. It runs independently, sampling
	// on its own interval and throttling the probers under load.
	if a.watchdog != nil {
		a.watchdog.Start(ctx)
	}

	a.logger.Info().Msg("Agent started")
	return nil
}

// Stop gracefully shuts down all agent components in reverse order of startup.
// It stops the cluster monitors, probers, and responders, then tears down
// infrastructure resources (metrics, gRPC, queues, devices, RDMA context,
// and event rings).
func (a *Agent) Stop(ctx context.Context) {
	a.logger.Info().Msg("Stopping agent")

	// Stop all cluster monitors first to prevent new pinglist updates.
	for _, monitor := range a.monitors {
		if monitor != nil {
			monitor.Stop()
		}
	}

	// Stop the heartbeat goroutine before closing the gRPC client, since
	// both it and the cluster monitors depend on grpcClient being open.
	a.stopHeartbeat()

	// Stop the resource watchdog before tearing down the probers, since it
	// calls SetRateMultiplier on them.
	if a.watchdog != nil {
		a.watchdog.Stop()
	}

	// Stop all probers to cease outgoing probes. Destroy() closes each
	// prober's own Results() channel, letting each fan-in goroutine's range
	// loop finish once it has drained any buffered values.
	for _, prober := range a.probers {
		if prober != nil {
			prober.Destroy()
		}
	}

	// Deterministically wind down the results fan-in: signal every fan-in
	// goroutine to stop forwarding, wait for all of them to exit, and close
	// the shared results channel exactly once. This must happen here in
	// Stop (not a fire-and-forget background goroutine) so shutdown never
	// leaves a fan-in goroutine blocked forever on a full a.results with
	// nothing draining it (e.g. metrics disabled), which in turn lets the
	// metrics result consumer's range loop finish.
	a.stopResultsFanIn()

	// Wait for the analysis reporter to drain the now-closed analysis branch
	// and ship its final window summary. This must happen before the gRPC
	// client is closed below, since the final flush is sent over it.
	if a.analysisReporter != nil {
		a.analysisReporter.Wait()
	}

	// Stop all responders.
	for _, resp := range a.responders {
		resp.Destroy()
	}

	// Shutdown metrics collector, flushing any buffered data.
	if a.metrics != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, metricsShutdownTimeout)
		defer cancel()
		if err := a.metrics.Shutdown(shutdownCtx); err != nil {
			a.logger.Error().Err(err).Msg("Failed to shutdown metrics collector")
		}
	}

	// Close the gRPC client connection.
	if a.grpcClient != nil {
		if err := a.grpcClient.Close(); err != nil {
			a.logger.Error().Err(err).Msg("Failed to close gRPC controller client")
		}
	}

	// Close all RDMA devices.
	for _, dev := range a.devices {
		dev.Close()
	}
	a.devices = nil

	// Destroy the RDMA context.
	if a.rdmaCtx != nil {
		a.rdmaCtx.Destroy()
		a.rdmaCtx = nil
	}

	// Destroy event rings.
	for _, ring := range a.proberRings {
		ring.Destroy()
	}
	a.proberRings = nil
	for _, ring := range a.respRings {
		ring.Destroy()
	}
	a.respRings = nil

	a.logger.Info().Msg("Agent stopped")
}

// startHeartbeat launches the background goroutine that periodically
// re-sends the agent's registration to the controller. This refreshes the
// controller's last_updated_epoch liveness field, without which the
// controller's registry considers the agent dead ~5 minutes after startup
// and drops it from distributed pinglists (and evicts it entirely after
// ~15 minutes).
func (a *Agent) startHeartbeat(ctx context.Context) {
	a.heartbeatStopCh = make(chan struct{})
	a.heartbeatWg.Add(1)
	go a.heartbeatLoop(ctx)
}

// stopHeartbeat signals the heartbeat goroutine to exit and waits for it to
// finish. It is a no-op if the heartbeat was never started.
func (a *Agent) stopHeartbeat() {
	if a.heartbeatStopCh == nil {
		return
	}
	close(a.heartbeatStopCh)
	a.heartbeatWg.Wait()
}

// heartbeatLoop periodically re-sends the agent's registration to the
// controller until the context is cancelled or stopHeartbeat is called.
// Failures are logged but never terminate the process: a transient
// controller outage should not bring down an otherwise healthy agent, and
// the next tick will simply retry.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.heartbeatWg.Done()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	consecutiveFailures := 0

	for {
		select {
		case <-a.heartbeatStopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			req := a.buildRegistrationRequest()
			resp, err := a.grpcClient.RegisterAgent(ctx, req)
			if attemptErr := registerAttemptErr(resp, err); attemptErr != nil {
				consecutiveFailures++
				a.logHeartbeatFailure(consecutiveFailures, attemptErr)
				continue
			}
			consecutiveFailures = 0
			a.logger.Debug().
				Str("agent_id", a.cfg.AgentID).
				Msg("Heartbeat re-registration succeeded")
		}
	}
}

// logHeartbeatFailure logs a heartbeat failure, escalating the log level
// from Warn to Error once consecutive failures reach the escalation
// threshold, to surface sustained controller unreachability.
func (a *Agent) logHeartbeatFailure(consecutiveFailures int, err error) {
	event := a.logger.Warn()
	if consecutiveFailures >= heartbeatFailureEscalationThreshold {
		event = a.logger.Error()
	}
	event.Err(err).
		Int("consecutive_failures", consecutiveFailures).
		Msg("Heartbeat re-registration failed, agent continues running")
}

// Run is the main lifecycle method. It initializes the agent, starts all
// components, blocks until the context is cancelled (e.g., by a signal),
// and then performs a graceful shutdown.
//
// Stop is always called after a successful (even partial) Initialize so that
// any resources allocated before a failure are released.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Initialize(ctx); err != nil {
		// Stop is safe to call with partially initialised state because
		// every resource field in Stop is guarded by a nil check.
		a.Stop(ctx)
		return fmt.Errorf("agent initialization failed: %w", err)
	}

	if err := a.Start(ctx); err != nil {
		// Clean up partially started components.
		a.Stop(ctx)
		return fmt.Errorf("agent start failed: %w", err)
	}

	// Block until the context is cancelled (signal handler, etc.).
	<-ctx.Done()
	a.logger.Info().Msg("Context cancelled, initiating shutdown")

	// Use a fresh context for shutdown operations since the parent is cancelled.
	shutdownCtx := context.Background()
	a.Stop(shutdownCtx)

	return nil
}

// openDevices opens RDMA devices based on configuration. If AllowedDeviceNames
// is configured, only those devices are opened by name. Otherwise, all available
// devices are opened by index.
func (a *Agent) openDevices() error {
	gidIndex := a.cfg.GIDIndex
	// Config.Validate() guarantees ServiceLevel is in [0,7] and TrafficClass
	// is in [0,255], so both narrow to uint8 without loss.
	sl := uint8(a.cfg.ServiceLevel)
	tc := uint8(a.cfg.TrafficClass)

	if len(a.cfg.AllowedDeviceNames) > 0 {
		// Open only the explicitly allowed devices by name.
		for _, name := range a.cfg.AllowedDeviceNames {
			dev, err := a.rdmaCtx.OpenDeviceByName(name, gidIndex, sl, tc)
			if err != nil {
				a.logger.Warn().Err(err).
					Str("device_name", name).
					Msg("Failed to open allowed RDMA device, skipping")
				continue
			}
			a.devices = append(a.devices, dev)
			a.logger.Info().
				Str("device_name", dev.Info.DeviceName).
				Str("gid", dev.Info.GID).
				Str("ip", dev.Info.IPAddr).
				Msg("Opened RDMA device by name")
		}
	} else {
		// Open all available devices by index.
		count := a.rdmaCtx.GetDeviceCount()
		if count == 0 {
			return fmt.Errorf("no RDMA devices found on this host")
		}

		for i := 0; i < count; i++ {
			dev, err := a.rdmaCtx.OpenDevice(i, gidIndex, sl, tc)
			if err != nil {
				a.logger.Warn().Err(err).
					Int("index", i).
					Msg("Failed to open RDMA device by index, skipping")
				continue
			}
			a.devices = append(a.devices, dev)
			a.logger.Info().
				Str("device_name", dev.Info.DeviceName).
				Str("gid", dev.Info.GID).
				Str("ip", dev.Info.IPAddr).
				Int("index", i).
				Msg("Opened RDMA device by index")
		}
	}

	return nil
}

// createEventRings creates one prober event ring and one responder event
// ring per device. Each ring is a lock-free SPSC buffer used to deliver CQ
// completion events from the Zig poller thread to Go.
func (a *Agent) createEventRings() error {
	for i, dev := range a.devices {
		proberRing, err := rdmabridge.NewEventRing(eventRingCapacity)
		if err != nil {
			return fmt.Errorf("failed to create prober event ring for device %d (%s): %w",
				i, dev.Info.DeviceName, err)
		}
		a.proberRings = append(a.proberRings, proberRing)

		respRing, err := rdmabridge.NewEventRing(eventRingCapacity)
		if err != nil {
			return fmt.Errorf("failed to create responder event ring for device %d (%s): %w",
				i, dev.Info.DeviceName, err)
		}
		a.respRings = append(a.respRings, respRing)
	}

	a.logger.Info().
		Int("prober_rings", len(a.proberRings)).
		Int("responder_rings", len(a.respRings)).
		Msg("Event rings created")
	return nil
}

// createMetricsCollector creates the OTel MetricsCollector when metrics are
// enabled, leaving a.metrics nil (and logging) if metrics are disabled or if
// creation fails. It is called before createResultsFanIn so the fan-in can
// tell, via a.metrics != nil, whether a metrics result consumer will run.
func (a *Agent) createMetricsCollector(ctx context.Context) {
	if !a.cfg.MetricsEnabled {
		a.logger.Info().Msg("Metrics collection is disabled")
		return
	}

	a.logger.Info().
		Str("collector_addr", a.cfg.OtelCollectorAddr).
		Msg("Creating metrics collector")
	mc, err := telemetry.NewMetricsCollector(ctx, a.cfg.OtelCollectorAddr)
	if err != nil {
		a.logger.Warn().Err(err).
			Msg("Failed to create metrics collector, continuing without metrics")
		return
	}
	a.metrics = mc

	// Surface event-ring drop counts (rings were created earlier) as an OTel
	// observable counter. A growing count means the Go poller goroutine is not
	// draining rdma_event_ring_poll fast enough and completion events are being
	// silently discarded. Both readers aggregate across all per-device rings
	// under a single label ("prober"/"responder") to keep metric cardinality
	// low (matching the source_tor/target_tor-only convention used elsewhere),
	// rather than reporting one data point per device.
	if err := a.metrics.RegisterEventRingDropCallback(map[string]func() uint64{
		"prober":    a.proberRingDropCount,
		"responder": a.responderRingDropCount,
	}); err != nil {
		a.logger.Warn().Err(err).
			Msg("Failed to register event ring drop count callback")
	}
}

// createResultsFanIn creates the shared results channel and starts one
// fan-in goroutine per prober that forwards its Results() into the shared
// channel. This lets Start() and the metrics result consumer keep treating
// "the" probe result stream as a single channel even though every device now
// has its own Prober.
//
// When a.metricsResultsActive is true, each fan-in goroutine selects between
// sending on a.results and reading from resultsDone, so it can always return
// promptly once Stop calls stopResultsFanIn -- whether or not anything is (or
// ever was) draining a.results (e.g. metrics active but the consumer has
// already stopped during shutdown). When it is false (no metrics consumer will
// run), the fan-in skips the a.results send entirely: sending on a channel
// nobody drains would, once full, block the goroutine, stop it reading from the
// prober, and starve the independent analysis tee. Analysis can be enabled
// without metrics, so the two branches must stay decoupled.
func (a *Agent) createResultsFanIn() {
	a.results = make(chan *probe.ProbeResult, resultChanSize)
	a.resultsDone = make(chan struct{})
	if a.cfg.AnalysisReportEnabled {
		a.analysisResults = make(chan *probe.ProbeResult, resultChanSize)
	}

	for _, prober := range a.probers {
		a.resultsWg.Add(1)
		go func(p *Prober) {
			defer a.resultsWg.Done()
			for result := range p.Results() {
				// Secondary, best-effort tee to the analysis path. The send is
				// non-blocking (dropped if the analysis buffer is full) so a
				// slow or backed-up aggregator/reporter can never stall the
				// primary metrics path below. Done first so a full a.results
				// (e.g. metrics slow) does not also starve analysis of this
				// result.
				if a.analysisResults != nil {
					select {
					case a.analysisResults <- result:
					default:
					}
				}
				// Primary metrics path. Skipped entirely when no metrics
				// consumer will drain a.results, so a slow/absent metrics
				// consumer cannot stall the fan-in (and thus the analysis tee).
				if !a.metricsResultsActive {
					continue
				}
				select {
				case a.results <- result:
				case <-a.resultsDone:
					// Stop is shutting down and nothing is guaranteed to
					// drain a.results; stop forwarding immediately instead
					// of risking a permanent block. Any results not yet
					// forwarded (this one, and anything still buffered in
					// p.Results()) are dropped.
					return
				}
			}
		}(prober)
	}
}

// stopResultsFanIn signals every fan-in goroutine started by
// createResultsFanIn to stop forwarding, waits for all of them to exit, and
// then closes the shared results channel exactly once. It is a no-op if
// createResultsFanIn was never called (e.g. Initialize failed before
// reaching it), matching the nil-guard pattern used throughout Stop.
//
// Closing resultsDone before waiting is what makes this deterministic: it
// guarantees every fan-in goroutine can return -- even one currently blocked
// trying to send on a full a.results -- regardless of whether the metrics
// result consumer (or anything else) is draining it. Callers must invoke
// this only after every prober has been destroyed (which closes that
// prober's own Results() channel), so fan-in goroutines waiting for the
// *next* value (rather than blocked on the send) also observe closure and
// exit their range loop.
func (a *Agent) stopResultsFanIn() {
	if a.resultsDone == nil {
		return
	}
	close(a.resultsDone)
	a.resultsWg.Wait()
	close(a.results)
	// Close the analysis branch too (only after every fan-in goroutine has
	// exited, so no tee send can race this close). This is what ends the
	// AnalysisReporter's run loop and triggers its final-window flush.
	if a.analysisResults != nil {
		close(a.analysisResults)
	}
}

// proberRingDropCount sums EventRing.DropCount() across every prober ring
// (one per device). Used as the "prober" reader for
// telemetry.MetricsCollector.RegisterEventRingDropCallback; see
// responderRingDropCount for why this aggregates rather than reporting per
// device.
func (a *Agent) proberRingDropCount() uint64 {
	var total uint64
	for _, ring := range a.proberRings {
		total += ring.DropCount()
	}
	return total
}

// responderRingDropCount sums EventRing.DropCount() across every responder
// ring (one per device). Used as the "responder" reader for
// telemetry.MetricsCollector.RegisterEventRingDropCallback, which reports a
// single ring="responder" data point rather than one per device to keep
// metric cardinality low (matching the source_tor/target_tor-only
// convention used elsewhere in this package).
func (a *Agent) responderRingDropCount() uint64 {
	var total uint64
	for _, ring := range a.respRings {
		total += ring.DropCount()
	}
	return total
}
