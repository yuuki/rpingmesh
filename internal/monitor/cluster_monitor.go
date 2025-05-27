package monitor

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/state"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// ProbeScheduler manages sequential probe execution with per-target rate limiting
type ProbeScheduler struct {
	targets            []probe.PingTarget
	targetLastProbe    map[string]time.Time // Key: target GID, Value: last probe time
	probeRatePerSecond int
	currentIndex       int
	mutex              sync.RWMutex
}

// NewProbeScheduler creates a new ProbeScheduler
func NewProbeScheduler() *ProbeScheduler {
	return &ProbeScheduler{
		targets:         make([]probe.PingTarget, 0),
		targetLastProbe: make(map[string]time.Time),
		currentIndex:    0,
	}
}

// UpdateTargets updates the target list and recreates rate limiters
func (ps *ProbeScheduler) UpdateTargets(targets []probe.PingTarget, probeRatePerSecond int) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	ps.targets = make([]probe.PingTarget, len(targets))
	copy(ps.targets, targets)
	ps.currentIndex = 0
	ps.probeRatePerSecond = probeRatePerSecond

	// Clear existing last probe times
	ps.targetLastProbe = make(map[string]time.Time)

	log.Info().
		Int("targets", len(targets)).
		Int("rate_per_second", probeRatePerSecond).
		Msg("ProbeScheduler targets updated")
}

// GetNextTarget returns the next target to probe, applying rate limiting
// Returns nil if no target is ready to be probed
func (ps *ProbeScheduler) GetNextTarget() *probe.PingTarget {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if len(ps.targets) == 0 {
		return nil
	}

	// If rate limiting is disabled (rate <= 0) or very high rate (>= 100),
	// return targets in round-robin fashion without rate limiting
	if ps.probeRatePerSecond <= 0 || ps.probeRatePerSecond >= 100 {
		target := &ps.targets[ps.currentIndex]
		ps.currentIndex = (ps.currentIndex + 1) % len(ps.targets)
		return target
	}

	// Calculate minimum interval between probes for the same target
	minInterval := time.Second / time.Duration(ps.probeRatePerSecond)

	// Try to find a target that's ready to be probed (not rate limited)
	startIndex := ps.currentIndex
	for {
		target := &ps.targets[ps.currentIndex]

		// Move to next target for next call
		ps.currentIndex = (ps.currentIndex + 1) % len(ps.targets)

		// Check if enough time has passed since the last probe to this target
		lastProbe, exists := ps.targetLastProbe[target.GID]
		now := time.Now()

		if !exists || now.Sub(lastProbe) >= minInterval {
			// Update last probe time for this target
			ps.targetLastProbe[target.GID] = now
			return target
		}

		// If we've checked all targets and none are ready, return nil
		if ps.currentIndex == startIndex {
			return nil
		}
	}
}

// GetTargetCount returns the number of targets
func (ps *ProbeScheduler) GetTargetCount() int {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return len(ps.targets)
}

// ClusterMonitor monitors all RDMA devices in the cluster
type ClusterMonitor struct {
	agentState         *state.AgentState
	prober             *probe.Prober
	intervalMs         uint32
	probeRatePerSecond int
	scheduler          *ProbeScheduler
	stopCh             chan struct{}
	wg                 sync.WaitGroup
	running            bool
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
		scheduler:          NewProbeScheduler(),
		stopCh:             make(chan struct{}),
		running:            false,
	}
}

// Start starts the cluster monitor
func (c *ClusterMonitor) Start() error {
	if c.running {
		return nil
	}

	c.running = true
	c.stopCh = make(chan struct{})

	// Start the sequential probe worker
	c.wg.Add(1)
	go c.runSequentialProbeWorker()

	log.Info().Msg("Cluster monitor started with sequential probe worker")
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
	// Convert controller targets to probe targets using explicit source-destination mapping
	probeTargets := make([]probe.PingTarget, 0, len(pinglist))
	localHostName := c.agentState.GetHostName()
	skippedCount := 0

	for _, target := range pinglist {
		// Skip targets without proper source or destination information
		if target.TargetRnic == nil || target.SourceRnic == nil {
			log.Warn().Msg("Skipping target with missing source or destination RNIC information")
			skippedCount++
			continue
		}

		// Skip targets on the same host to avoid RDMA CM address resolution issues
		if target.TargetRnic.HostName == localHostName {
			log.Debug().
				Str("target_hostname", target.TargetRnic.HostName).
				Str("local_hostname", localHostName).
				Str("target_gid", target.TargetRnic.Gid).
				Msg("Skipping target on same host during pinglist update")
			skippedCount++
			continue
		}

		// TEMPORARY FIX: Skip targets that would fail due to link-local GID constraints
		// Link-local GIDs (fe80::) can only communicate within the same physical port/L2 segment

		// Get the actual source device name from local RNIC information
		sourceDeviceName := target.SourceRnic.DeviceName
		if sourceDeviceName == "" {
			// If source device name is not provided by controller, look it up locally
			sourceRnic := c.agentState.GetRnicByGID(target.SourceRnic.Gid)
			if sourceRnic != nil {
				sourceDeviceName = sourceRnic.DeviceName
			}
		}

		if c.shouldSkipLinkLocalTarget(target.SourceRnic.Gid, target.TargetRnic.Gid, sourceDeviceName, target.TargetRnic.DeviceName) {
			log.Debug().
				Str("source_gid", target.SourceRnic.Gid).
				Str("target_gid", target.TargetRnic.Gid).
				Str("source_device", sourceDeviceName).
				Str("target_device", target.TargetRnic.DeviceName).
				Msg("Skipping target due to link-local GID cross-port communication constraint")
			skippedCount++
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
		}

		probeTargets = append(probeTargets, probeTarget)
	}

	// Update the scheduler with new targets
	c.scheduler.UpdateTargets(probeTargets, c.probeRatePerSecond)

	log.Info().
		Int("controller_targets", len(pinglist)).
		Int("probe_targets", len(probeTargets)).
		Int("skipped_targets", skippedCount).
		Msg("Updated cluster monitoring pinglist for sequential processing")
}

// shouldSkipLinkLocalTarget determines if a target should be skipped due to link-local GID constraints
// Link-local GIDs (fe80::) can only communicate within the same physical port/L2 segment
func (c *ClusterMonitor) shouldSkipLinkLocalTarget(sourceGID, targetGID, sourceDevice, targetDevice string) bool {
	// Check if both GIDs are link-local (fe80::)
	sourceIsLinkLocal := c.isLinkLocalGID(sourceGID)
	targetIsLinkLocal := c.isLinkLocalGID(targetGID)

	// If neither is link-local, no constraint applies
	if !sourceIsLinkLocal && !targetIsLinkLocal {
		return false
	}

	// If both are link-local, check if they are on different devices
	// Different devices typically mean different physical ports/L2 segments
	if sourceIsLinkLocal && targetIsLinkLocal {
		// For cross-device communication with link-local GIDs, we need to be more careful
		// In the current setup, different devices (mlx5_0 vs mlx5_1) are on different networks
		// So cross-device link-local communication will likely fail
		if sourceDevice != targetDevice {
			return true // Skip cross-device link-local communication
		}
	}

	// If only one is link-local, it might still work depending on routing
	// For now, allow mixed link-local/global communication
	return false
}

// isLinkLocalGID checks if a GID is a link-local IPv6 address (fe80::)
func (c *ClusterMonitor) isLinkLocalGID(gid string) bool {
	if len(gid) < 4 {
		return false
	}
	// Check if GID starts with "fe80:" (case-insensitive)
	prefix := gid[:5]
	return prefix == "fe80:" || prefix == "FE80:"
}

// runSequentialProbeWorker runs the main sequential probe loop
func (c *ClusterMonitor) runSequentialProbeWorker() {
	defer c.wg.Done()

	// Calculate minimum interval between probe attempts
	minInterval := time.Duration(c.intervalMs) * time.Millisecond
	if minInterval <= 0 {
		minInterval = 10 * time.Millisecond // Default minimum interval
	}

	ticker := time.NewTicker(minInterval)
	defer ticker.Stop()

	log.Info().
		Dur("min_interval", minInterval).
		Int("rate_per_second", c.probeRatePerSecond).
		Msg("Sequential probe worker started")

	for {
		select {
		case <-c.stopCh:
			log.Info().Msg("Sequential probe worker stopping")
			return
		case <-ticker.C:
			c.processNextProbe()
		}
	}
}

// processNextProbe processes the next available probe target
func (c *ClusterMonitor) processNextProbe() {
	// Get the next target that's ready to be probed
	target := c.scheduler.GetNextTarget()
	if target == nil {
		// No targets ready to be probed (either empty list or all rate limited)
		return
	}

	// Find the source RNIC specified in the target
	sourceRnic := c.agentState.GetRnicByGID(target.SourceRnicGID)
	if sourceRnic == nil {
		log.Warn().
			Str("target_source_gid", target.SourceRnicGID).
			Str("target_dest_gid", target.GID).
			Msg("Source RNIC specified in target not found in local RNICs, skipping")
		return
	}

	// Skip probing ourselves (should not happen with proper pinglist generation)
	if target.GID == target.SourceRnicGID {
		log.Debug().
			Str("target_gid", target.GID).
			Str("source_gid", target.SourceRnicGID).
			Msg("Skipping self-probe target")
		return
	}

	// Skip probing targets on the same host to avoid RDMA CM address resolution issues
	localHostName := c.agentState.GetHostName()
	if target.HostName == localHostName {
		log.Debug().
			Str("target_hostname", target.HostName).
			Str("local_hostname", localHostName).
			Str("target_gid", target.GID).
			Str("source_gid", target.SourceRnicGID).
			Msg("Skipping probe to target on same host to avoid RDMA CM address resolution issues")
		return
	}

	// Determine probe type based on TOR relationship
	probeType := probe.ProbeTypeInterTor
	if target.TorID == c.agentState.GetLocalTorID() {
		probeType = probe.ProbeTypeTorMesh
	}

	// Create probe details with the determined probe type
	probeDetails := probe.PingTarget{
		GID:              c.resolveTargetGID(*target),
		QPN:              target.QPN,
		IPAddress:        target.IPAddress,
		HostName:         target.HostName,
		DeviceName:       target.DeviceName,
		TorID:            target.TorID,
		SourcePort:       target.SourcePort,
		FlowLabel:        target.FlowLabel,
		Priority:         target.Priority,
		ServiceFlowTuple: target.ServiceFlowTuple,
		ProbeType:        probeType,
	}

	// Verify that a sender UDQueue is available for this RNIC
	senderUDQueue := c.agentState.GetSenderUDQueue(sourceRnic.GID)
	if senderUDQueue == nil {
		log.Error().
			Str("localRnic.GID", sourceRnic.GID).
			Str("localRnic.DeviceName", sourceRnic.DeviceName).
			Msg("No sender UDQueue available for this RNIC, cannot probe target")
		return
	}

	// Send probe with a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.intervalMs)*time.Millisecond)
	defer cancel()

	// Execute the probe
	c.prober.ProbeTarget(ctx, sourceRnic, &probeDetails)

	log.Trace().
		Str("source_gid", target.SourceRnicGID).
		Str("target_gid", probeDetails.GID).
		Str("probe_type", probeType).
		Msg("Executed probe in sequential worker")
}

// resolveTargetGID resolves the GID to use for the target.
// Currently, it just returns target.GID, but could involve more complex logic.
func (c *ClusterMonitor) resolveTargetGID(target probe.PingTarget) string {
	// Placeholder for more complex GID resolution if needed (e.g., based on IP, hostname)
	// For now, assume target.GID is the correct one to use for probing.
	if target.IPAddress != probe.EmptyIPString && net.ParseIP(target.IPAddress) == nil {
		log.Warn().Str("ip", target.IPAddress).Str("gid", target.GID).Msg("Target has an invalid IP address, using GID for probing.")
	}
	// Potentially, if GID is empty but IP is present, query controller for GID by IP.
	// For now, we rely on the Pinglist providing a valid GID for the target.
	return target.GID
}
