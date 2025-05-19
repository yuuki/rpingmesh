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
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"go.uber.org/ratelimit"
)

// Constants
const (
	// Probe Types
	ProbeTypeTorMesh  = "TOR_MESH"
	ProbeTypeInterTor = "INTER_TOR"

	// Default Values
	DefaultFlowLabel = 0  // Default flow label for ACK packets
	EmptyIPString    = "" // Empty string for IP address checks

	// Rate limit configuration
	ProbeRatePerSecond = 10 // Probes per second per target
)

// PingTarget represents a target for probing
type PingTarget struct {
	GID        string
	QPN        uint32
	IPAddress  string
	HostName   string
	TorID      string
	SourcePort uint32
	FlowLabel  uint32
	Priority   uint32
}

// ClusterMonitor monitors all RDMA devices in the cluster
type ClusterMonitor struct {
	agentState *state.AgentState
	prober     *probe.Prober
	intervalMs uint32
	pinglist   []PingTarget
	stopCh     chan struct{}
	wg         sync.WaitGroup
	running    bool

	// For rate limiting and controlling goroutines
	targetChans map[string]chan struct{}
}

// NewClusterMonitor creates a new ClusterMonitor
func NewClusterMonitor(
	agentState *state.AgentState,
	prober *probe.Prober,
	intervalMs uint32,
) *ClusterMonitor {
	return &ClusterMonitor{
		agentState:  agentState,
		prober:      prober,
		intervalMs:  intervalMs,
		pinglist:    make([]PingTarget, 0),
		stopCh:      make(chan struct{}),
		running:     false,
		targetChans: make(map[string]chan struct{}),
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

// UpdatePinglist updates the list of targets to ping
func (c *ClusterMonitor) UpdatePinglist(pinglist []*controller_agent.PingTarget) {
	// Stop existing probe workers
	for _, stopCh := range c.targetChans {
		close(stopCh)
	}
	c.targetChans = make(map[string]chan struct{})

	// Update pinglist
	c.pinglist = make([]PingTarget, 0, len(pinglist))
	for _, target := range pinglist {
		c.pinglist = append(c.pinglist, PingTarget{
			GID:        target.TargetRnic.Gid,
			QPN:        target.TargetRnic.Qpn,
			IPAddress:  target.TargetRnic.IpAddress,
			HostName:   target.TargetRnic.HostName,
			TorID:      target.TargetRnic.TorId,
			SourcePort: target.SourcePort,
			FlowLabel:  target.FlowLabel,
			Priority:   target.Priority,
		})
	}

	// If the monitor is running, start new probe workers
	if c.running {
		c.runAllProbeWorkers()
	}

	log.Info().Int("targets", len(c.pinglist)).Msg("Updated cluster monitoring pinglist")
}

// runAllProbeWorkers starts goroutines for each target in the pinglist
func (c *ClusterMonitor) runAllProbeWorkers() {
	// Get local RNICs
	localRnics := c.agentState.GetDetectedRNICs()
	if len(localRnics) == 0 {
		log.Error().Msg("No local RNICs available for probing")
		return
	}

	// For each target in the pinglist, create a goroutine
	for _, target := range c.pinglist {
		for _, localRnic := range localRnics {
			// Skip if the RNIC is nil or doesn't have a valid GID
			if localRnic == nil || localRnic.GID == "" {
				continue
			}

			// Skip probing ourselves (initial check)
			if target.GID == localRnic.GID {
				log.Debug().Str("target.GID", target.GID).Str("localRnic.GID", localRnic.GID).Msg("Skipping probe to self (initial check)")
				continue
			}

			// Create a unique key for this source-target pair
			key := localRnic.GID + "_" + target.GID

			// Create a stop channel for this target
			stopCh := make(chan struct{})
			c.targetChans[key] = stopCh

			// Start a goroutine for this target
			c.wg.Add(1)
			go c.probeTargetWithRateLimit(localRnic, target, stopCh)
		}
	}
}

// probeTargetWithRateLimit continuously probes a target with rate limiting
func (c *ClusterMonitor) probeTargetWithRateLimit(localRnic *rdma.RNIC, target PingTarget, stopCh chan struct{}) {
	defer c.wg.Done()

	// Determine probe type based on TOR relationship
	probeType := ProbeTypeInterTor
	if target.TorID == c.agentState.GetLocalTorID() {
		probeType = ProbeTypeTorMesh
	}

	// Create target RNIC info for the result
	targetRnicInfo := &agent_analyzer.RnicIdentifier{
		Gid:       target.GID,
		Qpn:       target.QPN,
		IpAddress: target.IPAddress,
		HostName:  target.HostName,
		TorId:     target.TorID,
	}

	// Resolve the actual GID to use for the target
	actualTargetGID := c.resolveTargetGID(target)

	// Final check to skip probing ourselves after GID resolution
	if actualTargetGID == localRnic.GID {
		log.Debug().
			Str("actualTargetGID", actualTargetGID).
			Str("localRnic.GID", localRnic.GID).
			Msg("Skipping probe to self (after GID resolution)")
		return
	}

	// Verify that a sender UDQueue is available for this RNIC
	senderUDQueue := c.agentState.GetSenderUDQueue(localRnic.GID)
	if senderUDQueue == nil {
		log.Error().
			Str("localRnic.GID", localRnic.GID).
			Str("localRnic.DeviceName", localRnic.DeviceName).
			Msg("No sender UDQueue available for this RNIC, cannot probe target")
		return
	}

	// Create rate limiter for this target
	limiter := ratelimit.New(ProbeRatePerSecond)

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
			c.prober.ProbeTarget(
				ctx,
				localRnic,
				actualTargetGID,
				target.QPN,
				target.SourcePort,
				target.FlowLabel,
				probeType,
				targetRnicInfo,
			)
			cancel()
		}
	}
}

// resolveTargetGID resolves the actual GID to use for a target
// It handles cases where the target.GID might be an IP address
func (c *ClusterMonitor) resolveTargetGID(target PingTarget) string {
	actualTargetGID := target.GID

	// Check if target.GID is a valid IP address
	ipFromGID := net.ParseIP(target.GID)
	if ipFromGID == nil {
		// Not an IP address, use as is
		log.Debug().
			Str("targetGID", target.GID).
			Msg("Target GID does not look like an IP address, using as is")
		return actualTargetGID
	}

	// It's an IP address, try to find corresponding GID
	lookupIP := target.IPAddress
	if lookupIP == EmptyIPString || net.ParseIP(lookupIP) == nil {
		// If target.IPAddress is not valid, fallback to GID
		lookupIP = target.GID
	}

	foundRnic := c.agentState.FindRNICByIP(lookupIP)
	if foundRnic == nil {
		log.Debug().
			Str("lookupIP", lookupIP).
			Msg("Could not find matching RNIC for target IP. Using original GID/IP in registry.")
		return actualTargetGID
	}
	return foundRnic.GID
}
