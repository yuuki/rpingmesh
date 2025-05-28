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
	"go.uber.org/ratelimit"
)

// ProbeScheduler manages sequential probe execution with per-target rate limiting using ratelimit
type ProbeScheduler struct {
	targets               []probe.PingTarget
	targetLimiters        map[string]ratelimit.Limiter // Key: target GID, Value: rate limiter
	currentIndex          int
	mutex                 sync.RWMutex
	targetProbeRatePerSec int
}

// NewProbeScheduler creates a new ProbeScheduler
func NewProbeScheduler() *ProbeScheduler {
	return &ProbeScheduler{
		targets:               make([]probe.PingTarget, 0),
		targetLimiters:        make(map[string]ratelimit.Limiter),
		currentIndex:          0,
		targetProbeRatePerSec: 10,
	}
}

// UpdateTargets updates the target list and recreates rate limiters
func (ps *ProbeScheduler) UpdateTargets(targets []probe.PingTarget, targetProbeRatePerSecond int) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	ps.targets = make([]probe.PingTarget, len(targets))
	copy(ps.targets, targets)
	ps.currentIndex = 0
	ps.targetProbeRatePerSec = targetProbeRatePerSecond

	// Create new rate limiters for each unique target GID
	ps.targetLimiters = make(map[string]ratelimit.Limiter)

	for _, target := range targets {
		if _, exists := ps.targetLimiters[target.GID]; !exists {
			if targetProbeRatePerSecond <= 0 {
				ps.targetLimiters[target.GID] = ratelimit.NewUnlimited()
			} else {
				ps.targetLimiters[target.GID] = ratelimit.New(targetProbeRatePerSecond, ratelimit.WithoutSlack)
			}
		}
	}

	log.Debug().
		Int("targets", len(targets)).
		Int("unique_target_gids", len(ps.targetLimiters)).
		Int("target_rate_per_second", targetProbeRatePerSecond).
		Msg("ProbeScheduler targets updated with per-target rate limiting using ratelimit")
}

// GetNextTarget returns the next target to probe, applying per-target rate limiting
// This method blocks until a target is available according to the rate limiter
func (ps *ProbeScheduler) GetNextTarget() *probe.PingTarget {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if len(ps.targets) == 0 {
		return nil
	}

	// Get the next target in round-robin fashion
	target := &ps.targets[ps.currentIndex]
	ps.currentIndex = (ps.currentIndex + 1) % len(ps.targets)

	// Get the rate limiter for this target
	limiter, exists := ps.targetLimiters[target.GID]
	if !exists {
		// This shouldn't happen if UpdateTargets was called properly
		log.Warn().Str("target_gid", target.GID).Msg("No rate limiter found for target GID")
		return target // Return anyway to avoid infinite loop
	}

	// Take from the rate limiter (this will block until allowed)
	limiter.Take()
	return target
}

// GetTargetCount returns the number of targets
func (ps *ProbeScheduler) GetTargetCount() int {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return len(ps.targets)
}

// GetRateInfo returns current rate limiting information
func (ps *ProbeScheduler) GetRateInfo() (targetRate int, uniqueTargets int) {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return ps.targetProbeRatePerSec, len(ps.targetLimiters)
}

// ClusterMonitor monitors all RDMA devices in the cluster
type ClusterMonitor struct {
	agentState            *state.AgentState
	prober                *probe.Prober
	intervalMs            uint32
	targetProbeRatePerSec int
	scheduler             *ProbeScheduler
	stopCh                chan struct{}
	wg                    sync.WaitGroup
	running               bool
}

// NewClusterMonitor creates a new ClusterMonitor
func NewClusterMonitor(
	agentState *state.AgentState,
	prober *probe.Prober,
	intervalMs uint32,
	targetProbeRatePerSec int,
) *ClusterMonitor {
	return &ClusterMonitor{
		agentState:            agentState,
		prober:                prober,
		intervalMs:            intervalMs,
		targetProbeRatePerSec: targetProbeRatePerSec,
		scheduler:             NewProbeScheduler(),
		stopCh:                make(chan struct{}),
		running:               false,
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
	c.scheduler.UpdateTargets(probeTargets, c.targetProbeRatePerSec)

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

	log.Info().
		Int("target_rate_per_second", c.targetProbeRatePerSec).
		Msg("Sequential probe worker started with per-target rate limiting")

	for {
		select {
		case <-c.stopCh:
			log.Info().Msg("Sequential probe worker stopping")
			return
		default:
			c.processNextProbe()
		}
	}
}

// processNextProbe processes the next available probe target
func (c *ClusterMonitor) processNextProbe() {
	// Get the next target - this will block until a target is available according to rate limiting
	target := c.scheduler.GetNextTarget()
	if target == nil {
		// No targets configured, return immediately
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
