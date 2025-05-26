package monitor

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdma"
	"github.com/yuuki/rpingmesh/internal/state"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"go.uber.org/ratelimit"
)

// ClusterMonitor monitors all RDMA devices in the cluster
type ClusterMonitor struct {
	agentState         *state.AgentState
	prober             *probe.Prober
	intervalMs         uint32
	probeRatePerSecond int
	pinglist           []probe.PingTarget // Changed to probe.PingTarget
	stopCh             chan struct{}
	wg                 sync.WaitGroup
	running            bool

	// For rate limiting and controlling goroutines
	targetChans map[string]chan struct{}
}

// NewClusterMonitor creates a new ClusterMonitor
func NewClusterMonitor(
	agentState *state.AgentState,
	prober *probe.Prober,
	intervalMs uint32,
	probeRatePerSecond int,
) *ClusterMonitor {
	return &ClusterMonitor{
		agentState:         agentState,
		prober:             prober,
		intervalMs:         intervalMs,
		probeRatePerSecond: probeRatePerSecond,
		pinglist:           make([]probe.PingTarget, 0), // Changed to probe.PingTarget
		stopCh:             make(chan struct{}),
		running:            false,
		targetChans:        make(map[string]chan struct{}),
	}
}

// Start starts the cluster monitor
func (c *ClusterMonitor) Start() error {
	if c.running {
		return nil
	}

	c.running = true
	c.stopCh = make(chan struct{})

	// Start the monitor goroutine
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		// Start probe workers for each target
		c.runAllProbeWorkers()

		// Wait for stop signal
		<-c.stopCh

		// Stop all target goroutines
		for _, stopCh := range c.targetChans {
			close(stopCh)
		}
		c.targetChans = make(map[string]chan struct{})
	}()

	log.Info().Msg("Cluster monitor started")
	return nil
}

// Stop stops the cluster monitor
func (c *ClusterMonitor) Stop() {
	if !c.running {
		return
	}

	close(c.stopCh)
	c.wg.Wait()
	c.running = false
	log.Info().Msg("Cluster monitor stopped")
}

// UpdatePinglist updates the list of targets to ping using source-destination mapping from controller
func (c *ClusterMonitor) UpdatePinglist(pinglist []*controller_agent.PingTarget) {
	// Stop existing probe workers
	for _, stopCh := range c.targetChans {
		close(stopCh)
	}
	c.targetChans = make(map[string]chan struct{})

	// Convert controller targets to probe targets using explicit source-destination mapping
	c.pinglist = make([]probe.PingTarget, 0, len(pinglist))

	for _, target := range pinglist {
		// Skip targets without proper source or destination information
		if target.TargetRnic == nil || target.SourceRnic == nil {
			log.Warn().Msg("Skipping target with missing source or destination RNIC information")
			continue
		}

		// Create probe target with explicit source-destination mapping from controller
		probeTarget := probe.PingTarget{
			// Destination RNIC information
			GID:        target.TargetRnic.Gid,
			QPN:        target.TargetRnic.Qpn,
			IPAddress:  target.TargetRnic.IpAddress,
			HostName:   target.TargetRnic.HostName,
			TorID:      target.TargetRnic.TorId,
			DeviceName: target.TargetRnic.DeviceName,

			// Source RNIC information (from controller's explicit mapping)
			SourceRnicGID:    target.SourceRnic.Gid,
			SourceRnicQPN:    target.SourceRnic.Qpn,
			SourceRnicIP:     target.SourceRnic.IpAddress,
			SourceHostName:   target.SourceRnic.HostName,
			SourceTorID:      target.SourceRnic.TorId,
			SourceDeviceName: target.SourceRnic.DeviceName,

			// 5-tuple details from controller
			SourcePort: target.SourcePort,
			FlowLabel:  target.FlowLabel,
			Priority:   target.Priority,
			// ProbeType will be set in probeTargetWithRateLimit based on TOR relationship
		}

		c.pinglist = append(c.pinglist, probeTarget)
	}

	// If the monitor is running, start new probe workers
	if c.running {
		c.runAllProbeWorkers()
	}

	log.Info().
		Int("controller_targets", len(pinglist)).
		Int("probe_targets", len(c.pinglist)).
		Msg("Updated cluster monitoring pinglist using controller's source-destination mapping")
}

// runAllProbeWorkers starts goroutines for each target in the pinglist
func (c *ClusterMonitor) runAllProbeWorkers() {
	// Get local RNICs for validation
	localRnics := c.agentState.GetDetectedRNICs()
	if len(localRnics) == 0 {
		log.Error().Msg("No local RNICs available for probing")
		return
	}

	// Create a map of local RNICs by GID for quick lookup
	localRnicsByGID := make(map[string]*rdma.RNIC)
	for _, rnic := range localRnics {
		if rnic != nil && rnic.GID != "" {
			localRnicsByGID[rnic.GID] = rnic
		}
	}

	// For each target in the pinglist, create a goroutine using the specified source RNIC
	for _, target := range c.pinglist {
		// Find the source RNIC specified in the target
		sourceRnic, exists := localRnicsByGID[target.SourceRnicGID]
		if !exists || sourceRnic == nil {
			log.Warn().
				Str("target_source_gid", target.SourceRnicGID).
				Str("target_dest_gid", target.GID).
				Msg("Source RNIC specified in target not found in local RNICs, skipping")
			continue
		}

		// Skip probing ourselves (should not happen with proper pinglist generation)
		if target.GID == target.SourceRnicGID {
			log.Debug().
				Str("target_gid", target.GID).
				Str("source_gid", target.SourceRnicGID).
				Msg("Skipping self-probe target")
			continue
		}

		// Create a unique key for this source-target pair
		key := target.SourceRnicGID + "_" + target.GID

		// Check if this probe worker is already running
		if _, exists := c.targetChans[key]; exists {
			log.Debug().
				Str("key", key).
				Msg("Probe worker already running for this source-target pair")
			continue
		}

		// Create a stop channel for this target
		stopCh := make(chan struct{})
		c.targetChans[key] = stopCh

		// Start a goroutine for this specific source-target pair
		c.wg.Add(1)
		go c.probeTargetWithRateLimit(sourceRnic, target, stopCh)

		log.Debug().
			Str("source_gid", target.SourceRnicGID).
			Str("target_gid", target.GID).
			Uint32("flow_label", target.FlowLabel).
			Msg("Started probe worker for source-target pair")
	}

	log.Info().
		Int("total_targets", len(c.pinglist)).
		Int("active_workers", len(c.targetChans)).
		Msg("Started probe workers with explicit source-destination mapping")
}

// probeTargetWithRateLimit continuously probes a target with rate limiting
func (c *ClusterMonitor) probeTargetWithRateLimit(localRnic *rdma.RNIC, target probe.PingTarget, stopCh chan struct{}) { // Changed to probe.PingTarget
	defer c.wg.Done()

	// Determine probe type based on TOR relationship
	probeType := probe.ProbeTypeInterTor              // Changed to probe.ProbeTypeInterTor
	if target.TorID == c.agentState.GetLocalTorID() { // agentState.GetLocalTorID() needs to be checked for existence
		probeType = probe.ProbeTypeTorMesh // Changed to probe.ProbeTypeTorMesh
	}

	// Create a mutable copy of the target to set the ProbeType for this specific probe instance.
	// This is important if the original `target` from `c.pinglist` should remain unchanged
	// or if multiple goroutines might operate on slightly different versions of it.
	// However, given the current structure where `target` is a copy from the `c.pinglist` loop,
	// modifying it directly here for `ProbeType` is acceptable if `c.pinglist` elements are not meant
	// to store this dynamic probe type.
	// For clarity and safety, let's create a PingTarget specifically for the prober call.
	probeDetails := probe.PingTarget{
		GID:              target.GID, // This might need to be actualTargetGID later
		QPN:              target.QPN,
		IPAddress:        target.IPAddress,
		HostName:         target.HostName,
		TorID:            target.TorID,
		SourcePort:       target.SourcePort,
		FlowLabel:        target.FlowLabel,
		Priority:         target.Priority,
		ServiceFlowTuple: target.ServiceFlowTuple, // Pass along if present
		ProbeType:        probeType,               // Set the determined probe type
	}

	// Create target RNIC info for the result (used for logging/reporting, not directly for probing logic with ProbeTarget)
	// agent_analyzer.RnicIdentifier remains the same
	/* targetRnicInfo := &agent_analyzer.RnicIdentifier{
		Gid:       target.GID,
		Qpn:       target.QPN,
		IpAddress: target.IPAddress,
		HostName:  target.HostName,
		TorId:     target.TorID,
	} */

	// Resolve the actual GID to use for the target
	actualTargetGID := c.resolveTargetGID(target) // Pass probe.PingTarget

	// Final check to skip probing ourselves after GID resolution
	if actualTargetGID == localRnic.GID {
		log.Debug().
			Str("actualTargetGID", actualTargetGID).
			Str("localRnic.GID", localRnic.GID).
			Msg("Skipping probe to self (after GID resolution)")
		return
	}

	// Update probeDetails with the resolved GID if it's different and relevant for ProbeTarget
	// The prober.ProbeTarget function signature expects a *probe.PingTarget.
	// Let's ensure the GID in probeDetails is the one to be probed.
	probeDetails.GID = actualTargetGID

	// Verify that a sender UDQueue is available for this RNIC
	senderUDQueue := c.agentState.GetSenderUDQueue(localRnic.GID) // agentState.GetSenderUDQueue needs to be checked
	if senderUDQueue == nil {
		log.Error().
			Str("localRnic.GID", localRnic.GID).
			Str("localRnic.DeviceName", localRnic.DeviceName).
			Msg("No sender UDQueue available for this RNIC, cannot probe target")
		// TODO: Consider how to report this failure, e.g., via a ProbeResult with an error status.
		// For now, just returning as the original code did.
		return
	}

	// Create rate limiter for this target using configured rate
	limiter := ratelimit.New(c.probeRatePerSecond, ratelimit.WithoutSlack)

	// Main probing loop with rate limiting
	for {
		select {
		case <-stopCh:
			return
		default:
			// Take a token from the rate limiter (this blocks until the rate limit allows)
			limiter.Take()

			// Send probe with a timeout context
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.intervalMs)*time.Millisecond)
			// Ensure cancel is called to free resources, even if ProbeTarget panics or returns early.
			// However, ProbeTarget itself might handle the context cancellation if it's long-running.
			// The prober.ProbeTarget call needs to be updated to accept *probe.PingTarget
			c.prober.ProbeTarget(
				ctx,
				localRnic,
				&probeDetails, // Pass the address of probeDetails, which is *probe.PingTarget
			)
			cancel() // Call cancel after the probe is done or times out.
		}
	}
}

// resolveTargetGID resolves the GID to use for the target.
// Currently, it just returns target.GID, but could involve more complex logic.
func (c *ClusterMonitor) resolveTargetGID(target probe.PingTarget) string { // Changed to probe.PingTarget
	// Placeholder for more complex GID resolution if needed (e.g., based on IP, hostname)
	// For now, assume target.GID is the correct one to use for probing.
	if target.IPAddress != probe.EmptyIPString && net.ParseIP(target.IPAddress) == nil { // Changed to probe.EmptyIPString
		log.Warn().Str("ip", target.IPAddress).Str("gid", target.GID).Msg("Target has an invalid IP address, using GID for probing.")
	}
	// Potentially, if GID is empty but IP is present, query controller for GID by IP.
	// For now, we rely on the Pinglist providing a valid GID for the target.
	return target.GID
}
