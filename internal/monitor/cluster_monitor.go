package monitor

import (
	"context"
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
	ctx        context.Context
	cancel     context.CancelFunc
	running    bool
	mutex      sync.Mutex
}

// NewClusterMonitor creates a new ClusterMonitor
func NewClusterMonitor(
	agentState *state.AgentState,
	prober *probe.Prober,
	intervalMs uint32,
) *ClusterMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ClusterMonitor{
		agentState: agentState,
		prober:     prober,
		intervalMs: intervalMs,
		pinglist:   make([]PingTarget, 0),
		stopCh:     make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		running:    false,
	}
}

// Start starts the cluster monitor
func (c *ClusterMonitor) Start() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

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

	c.cancel()
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
		if target.GID == localRnic.GID {
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

		// Send probe
		c.prober.ProbeTarget(
			localRnic,
			target.GID,
			target.QPN,
			target.SourcePort,
			target.FlowLabel,
			probeType,
			targetRnicInfo,
		)
	}
}
