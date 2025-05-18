package monitor

import (
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/state"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
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
	mutex      sync.Mutex
}

// NewClusterMonitor creates a new ClusterMonitor
func NewClusterMonitor(
	agentState *state.AgentState,
	prober *probe.Prober,
	intervalMs uint32,
) *ClusterMonitor {
	return &ClusterMonitor{
		agentState: agentState,
		prober:     prober,
		intervalMs: intervalMs,
		pinglist:   make([]PingTarget, 0),
		stopCh:     make(chan struct{}),
		running:    false,
	}
}

// Start starts the cluster monitor
func (c *ClusterMonitor) Start() error {
	if c.running {
		return nil
	}

	c.running = true
	c.stopCh = make(chan struct{})

	// Start probing goroutine
	c.wg.Add(1)
	go c.monitorLoop()

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
	c.mutex.Lock()
	defer c.mutex.Unlock()

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

	log.Info().Int("targets", len(c.pinglist)).Msg("Updated cluster monitoring pinglist")
}

// monitorLoop is the main loop for cluster monitoring
func (c *ClusterMonitor) monitorLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Duration(c.intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.probeAllTargets()
		}
	}
}

// probeAllTargets sends probes to all targets in the pinglist
func (c *ClusterMonitor) probeAllTargets() {
	// Make a copy of the pinglist to avoid holding the mutex during probing
	c.mutex.Lock()
	pinglist := make([]PingTarget, len(c.pinglist))
	copy(pinglist, c.pinglist)
	c.mutex.Unlock()

	if len(pinglist) == 0 {
		// No targets to probe
		return
	}

	// Get local RNIC
	localRnic := c.agentState.GetPrimaryRNIC()
	if localRnic == nil {
		log.Error().Msg("No local RNIC available for probing")
		return
	}

	// Probe each target
	for _, target := range pinglist {
		// Skip probing ourselves
		if target.GID == localRnic.GID { // Initial check, might be comparing IP string to GID string
			log.Debug().Str("target.GID", target.GID).Str("localRnic.GID", localRnic.GID).Msg("Skipping probe to self (initial check)")
			continue
		}

		// Determine probe type based on TOR relationship
		var probeType string
		if target.TorID == c.agentState.GetLocalTorID() {
			probeType = "TOR_MESH"
		} else {
			probeType = "INTER_TOR"
		}

		// Create target RNIC info for the result
		targetRnicInfo := &agent_analyzer.RnicIdentifier{
			Gid:       target.GID,
			Qpn:       target.QPN,
			IpAddress: target.IPAddress,
			HostName:  target.HostName,
			TorId:     target.TorID,
		}

		// Attempt to use the GID from the target first.
		// If it looks like an IP address, try to find the corresponding RNIC GID from local state.
		actualTargetGID := target.GID
		// Check if target.GID is a valid IP address. If so, it might be an IPv4 representation.
		ipFromGID := net.ParseIP(target.GID)
		if ipFromGID != nil {
			// If target.GID is an IP, prefer looking up by target.IPAddress first as it's more explicit.
			// If target.IPAddress is empty or also an IP, then use target.GID (which is an IP) for lookup if different.
			lookupIP := target.IPAddress
			if lookupIP == "" || net.ParseIP(lookupIP) == nil { // If target.IPAddress is not a valid IP, fallback to GID if it's an IP
				lookupIP = target.GID
			}

			log.Debug().Str("originalGID", target.GID).Str("lookupIPForGIDResolution", lookupIP).Msg("Target GID might be an IP address, attempting to find IPv6 GID from local RNICs by IP.")
			foundRnic := c.agentState.FindRNICByIP(lookupIP)
			if foundRnic != nil && foundRnic.GID != "" && net.ParseIP(foundRnic.GID) != nil && net.ParseIP(foundRnic.GID).To16() != nil && net.ParseIP(foundRnic.GID).To4() == nil {
				actualTargetGID = foundRnic.GID
				log.Debug().Str("originalGIDOrIP", target.GID).Str("resolvedIPv6GID", actualTargetGID).Msg("Found matching IPv6 GID for target IP.")
			} else {
				log.Warn().Str("originalGIDOrIP", target.GID).Str("lookupIP", lookupIP).Msg("Could not find matching IPv6 GID for target IP, or found GID is not IPv6. Using original GID/IP. This might fail.")
			}
		} else {
			// target.GID is not a parseable IP, assume it's a proper GID (hopefully IPv6)
			log.Debug().Str("targetGID", target.GID).Msg("Target GID does not look like an IP address, using as is.")
		}

		// Final check to skip probing ourselves after GID resolution
		if actualTargetGID == localRnic.GID {
			log.Debug().Str("actualTargetGID", actualTargetGID).Str("localRnic.GID", localRnic.GID).Msg("Skipping probe to self (after GID resolution)")
			continue
		}

		// Send probe
		c.prober.ProbeTarget(
			localRnic,
			actualTargetGID, // Use the potentially resolved GID
			target.QPN,
			target.SourcePort,
			target.FlowLabel,
			probeType,
			targetRnicInfo,
		)
	}
}
