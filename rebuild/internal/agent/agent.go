// Package agent implements the R-Pingmesh agent lifecycle, orchestrating RDMA
// device management, probe responders, active probing, controller registration,
// cluster monitoring, and telemetry collection.
package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/internal/telemetry"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// Timing constants for shutdown operations.
const (
	metricsShutdownTimeout = 5 * time.Second
	eventRingCapacity      = 1024 // Power of 2 for optimal SPSC ring performance.
)

// Agent orchestrates all R-Pingmesh agent components: RDMA context, devices,
// responders, prober, cluster monitor, and telemetry. It handles initialization,
// registration with the controller, and graceful shutdown.
type Agent struct {
	cfg        *config.AgentConfig
	rdmaCtx    *rdmabridge.Context
	devices    []*rdmabridge.Device
	responders []*Responder
	prober     *Prober
	monitor    *ClusterMonitor
	grpcClient *controller_client.GRPCControllerClient
	metrics    *telemetry.MetricsCollector
	proberRing *rdmabridge.EventRing
	respRings  []*rdmabridge.EventRing
	logger     zerolog.Logger
}

// NewAgent creates a new Agent instance with the given configuration.
// The agent is not started until Initialize and Start are called.
func NewAgent(cfg *config.AgentConfig) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("agent config must not be nil")
	}

	return &Agent{
		cfg:    cfg,
		logger: log.With().Str("component", "agent").Logger(),
	}, nil
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
	grpcClient, err := controller_client.NewGRPCControllerClient(a.cfg.ControllerAddr)
	if err != nil {
		return fmt.Errorf("failed to create gRPC controller client: %w", err)
	}
	a.grpcClient = grpcClient

	// Step 4: Create event rings (one for the prober, one per responder).
	a.logger.Info().Msg("Creating event rings")
	if err := a.createEventRings(); err != nil {
		return fmt.Errorf("failed to create event rings: %w", err)
	}

	// Step 5: Create prober using the first device.
	a.logger.Info().
		Str("device", a.devices[0].Info.DeviceName).
		Uint32("probe_interval_ms", a.cfg.ProbeIntervalMS).
		Msg("Creating prober")
	prober, err := NewProber(a.devices[0], a.proberRing, a.cfg.ProbeIntervalMS)
	if err != nil {
		return fmt.Errorf("failed to create prober: %w", err)
	}
	a.prober = prober

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

	// Step 7: Create metrics collector if enabled.
	if a.cfg.MetricsEnabled {
		a.logger.Info().
			Str("collector_addr", a.cfg.OtelCollectorAddr).
			Msg("Creating metrics collector")
		mc, err := telemetry.NewMetricsCollector(ctx, a.cfg.OtelCollectorAddr)
		if err != nil {
			a.logger.Warn().Err(err).
				Msg("Failed to create metrics collector, continuing without metrics")
		} else {
			a.metrics = mc
		}
	} else {
		a.logger.Info().Msg("Metrics collection is disabled")
	}

	// Step 8: Register with the controller.
	a.logger.Info().Msg("Registering with controller")
	if err := a.registerWithController(ctx); err != nil {
		return fmt.Errorf("failed to register with controller: %w", err)
	}

	// Step 9: Create cluster monitor for periodic pinglist updates.
	// Use the first device's GID as the requester GID for pinglist requests.
	requesterGID := a.devices[0].Info.GID
	a.logger.Info().
		Str("requester_gid", requesterGID).
		Uint32("update_interval_sec", a.cfg.PinglistUpdateIntervalSec).
		Msg("Creating cluster monitor")
	a.monitor = NewClusterMonitor(
		a.grpcClient,
		a.prober,
		a.cfg.AgentID,
		a.cfg.TorID,
		requesterGID,
		a.cfg.PinglistUpdateIntervalSec,
	)

	a.logger.Info().Msg("Agent initialization complete")
	return nil
}

// registerWithController builds a registration request from the agent's
// configuration and device/responder state, then sends it to the controller.
func (a *Agent) registerWithController(ctx context.Context) error {
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

	req := &controller_agent.AgentRegistrationRequest{
		AgentId:  a.cfg.AgentID,
		Hostname: a.cfg.HostName,
		TorId:    a.cfg.TorID,
		Rnics:    rnics,
	}

	_, err := a.grpcClient.RegisterAgent(ctx, req)
	if err != nil {
		return fmt.Errorf("RegisterAgent failed: %w", err)
	}

	a.logger.Info().
		Str("agent_id", a.cfg.AgentID).
		Int("rnic_count", len(rnics)).
		Msg("Agent registered with controller")
	return nil
}

// Start begins all agent components: responders, prober, cluster monitor,
// and the metrics result consumer. All components must be initialized via
// Initialize() before calling Start().
func (a *Agent) Start(ctx context.Context) error {
	// Start all responders.
	for i, resp := range a.responders {
		if err := resp.Start(ctx); err != nil {
			return fmt.Errorf("failed to start responder %d: %w", i, err)
		}
	}

	// Start the prober.
	if err := a.prober.Start(ctx); err != nil {
		return fmt.Errorf("failed to start prober: %w", err)
	}

	// Start the cluster monitor for periodic pinglist updates.
	if err := a.monitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start cluster monitor: %w", err)
	}

	// Start the metrics result consumer if metrics are enabled.
	if a.metrics != nil {
		a.metrics.StartResultConsumer(ctx, a.prober.Results(), a.cfg.TorID)
		a.logger.Info().Msg("Metrics result consumer started")
	}

	a.logger.Info().Msg("Agent started")
	return nil
}

// Stop gracefully shuts down all agent components in reverse order of startup.
// It stops the cluster monitor, prober, and responders, then tears down
// infrastructure resources (metrics, gRPC, queues, devices, RDMA context,
// and event rings).
func (a *Agent) Stop(ctx context.Context) {
	a.logger.Info().Msg("Stopping agent")

	// Stop cluster monitor first to prevent new pinglist updates.
	if a.monitor != nil {
		a.monitor.Stop()
	}

	// Stop the prober to cease outgoing probes.
	if a.prober != nil {
		a.prober.Destroy()
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
	if a.proberRing != nil {
		a.proberRing.Destroy()
		a.proberRing = nil
	}
	for _, ring := range a.respRings {
		ring.Destroy()
	}
	a.respRings = nil

	a.logger.Info().Msg("Agent stopped")
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

	if len(a.cfg.AllowedDeviceNames) > 0 {
		// Open only the explicitly allowed devices by name.
		for _, name := range a.cfg.AllowedDeviceNames {
			dev, err := a.rdmaCtx.OpenDeviceByName(name, gidIndex)
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
			dev, err := a.rdmaCtx.OpenDevice(i, gidIndex)
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

// createEventRings creates one event ring for the prober and one per device
// (for responders). Each ring is a lock-free SPSC buffer used to deliver
// CQ completion events from the Zig poller thread to Go.
func (a *Agent) createEventRings() error {
	// Prober ring.
	proberRing, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		return fmt.Errorf("failed to create prober event ring: %w", err)
	}
	a.proberRing = proberRing

	// One responder ring per device.
	for i, dev := range a.devices {
		ring, err := rdmabridge.NewEventRing(eventRingCapacity)
		if err != nil {
			return fmt.Errorf("failed to create responder event ring for device %d (%s): %w",
				i, dev.Info.DeviceName, err)
		}
		a.respRings = append(a.respRings, ring)
	}

	a.logger.Info().
		Int("responder_rings", len(a.respRings)).
		Msg("Event rings created")
	return nil
}
