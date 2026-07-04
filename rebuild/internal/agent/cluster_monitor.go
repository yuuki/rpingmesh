// Package agent implements the R-Pingmesh agent. ClusterMonitor periodically
// fetches pinglists from the controller and distributes probe targets to the
// Prober for continuous network quality measurement.
package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// ControllerClient defines the interface for communicating with the controller.
// This interface allows the monitor to be tested with a mock client.
type ControllerClient interface {
	GetPinglist(ctx context.Context, agentID, torID, requesterGID string, ptype controller_agent.PinglistType) ([]*controller_agent.PingTarget, error)
}

// ClusterMonitor periodically fetches pinglists from the controller
// and distributes targets to the prober. It fetches both ToR-mesh and
// inter-ToR pinglists, combines them, and updates the prober's target
// list atomically.
type ClusterMonitor struct {
	client         ControllerClient
	prober         *Prober
	agentID        string
	torID          string
	requesterGID   string
	updateInterval time.Duration
	running        atomic.Bool
	stopMu         sync.Mutex // guards stopCh (re)creation across Start/Stop
	stopCh         chan struct{}
	wg             sync.WaitGroup
	logger         zerolog.Logger

	// lastTorMeshTargets and lastInterTorTargets cache the most recently
	// fetched successful pinglist for each type. When a fetch for one
	// pinglist type fails while the other succeeds, the cached value for
	// the failed type is reused instead of treating it as empty. This
	// prevents a transient failure of a single pinglist type from wiping
	// out the other type's live, healthy targets. These fields are only
	// ever touched from the single monitor loop goroutine (Start ensures
	// at most one is running), so no additional synchronization is needed.
	lastTorMeshTargets  []*controller_agent.PingTarget
	lastInterTorTargets []*controller_agent.PingTarget
}

// NewClusterMonitor creates a new ClusterMonitor that will poll the controller
// for pinglists every updateIntervalSec seconds and push the combined target
// list to the given prober.
func NewClusterMonitor(
	client ControllerClient,
	prober *Prober,
	agentID, torID, requesterGID string,
	updateIntervalSec uint32,
) *ClusterMonitor {
	interval := time.Duration(updateIntervalSec) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}

	return &ClusterMonitor{
		client:         client,
		prober:         prober,
		agentID:        agentID,
		torID:          torID,
		requesterGID:   requesterGID,
		updateInterval: interval,
		stopCh:         make(chan struct{}),
		logger:         log.With().Str("component", "cluster_monitor").Logger(),
	}
}

// Start launches the background goroutine that periodically fetches pinglists
// from the controller. The first fetch is performed immediately without
// waiting for the first tick. It returns nil if already running.
func (m *ClusterMonitor) Start(ctx context.Context) error {
	if !m.running.CompareAndSwap(false, true) {
		return nil // already running
	}

	// Recreate stopCh so the monitor can be started again after a previous
	// Stop() closed it. Stop() has already waited for the old goroutine to exit
	// (running is false here), so nothing references the old channel. Without
	// this, a Stop->Start cycle would leave monitorLoop reading an
	// already-closed stopCh and returning immediately, leaving the loop dead.
	m.stopMu.Lock()
	m.stopCh = make(chan struct{})
	m.stopMu.Unlock()

	m.wg.Add(1)
	go m.monitorLoop(ctx)

	m.logger.Info().
		Str("agent_id", m.agentID).
		Str("tor_id", m.torID).
		Str("requester_gid", m.requesterGID).
		Dur("update_interval", m.updateInterval).
		Msg("ClusterMonitor started")

	return nil
}

// Stop signals the monitor goroutine to exit and waits for it to finish.
// Closing stopCh wakes the goroutine immediately without waiting for the
// next ticker interval. It is safe to call Stop multiple times.
func (m *ClusterMonitor) Stop() {
	if !m.running.CompareAndSwap(true, false) {
		return // not running
	}
	m.stopMu.Lock()
	close(m.stopCh)
	m.stopMu.Unlock()
	m.wg.Wait()
	m.logger.Info().Msg("ClusterMonitor stopped")
}

// monitorLoop is the main background loop. It fetches pinglists once
// immediately on start, then on every tick of the update interval.
// The loop exits when the context is cancelled or Stop closes stopCh.
// Using stopCh ensures the goroutine exits immediately on Stop rather
// than blocking until the next ticker interval (up to 30 s).
func (m *ClusterMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	// Fetch immediately on start so the prober has targets without
	// waiting for the first tick.
	m.updateTargets(ctx)

	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.updateTargets(ctx)
		}
	}
}

// updateTargets fetches the combined pinglist and pushes targets to the
// prober. fetchPinglists always returns a usable list (falling back to
// per-type cached values on failure), so the result is always pushed.
func (m *ClusterMonitor) updateTargets(ctx context.Context) {
	targets := m.fetchPinglists(ctx)
	m.prober.UpdateTargets(targets)
}

// fetchPinglists requests both TOR_MESH and INTER_TOR pinglists from the
// controller and merges the results.
//
// Each pinglist type is handled independently: on success its result
// replaces the cached value for that type; on failure the previously
// cached value for that type is reused. This prevents a failure in one
// pinglist type (e.g. INTER_TOR) from wiping out live, healthy targets of
// the other type (e.g. TOR_MESH) that were just fetched successfully, and
// still gracefully degrades to the last known-good targets if a fetch
// keeps failing repeatedly.
func (m *ClusterMonitor) fetchPinglists(ctx context.Context) []*controller_agent.PingTarget {
	// Fetch ToR-mesh pinglist (targets within the same ToR).
	torMeshTargets, torMeshErr := m.client.GetPinglist(
		ctx, m.agentID, m.torID, m.requesterGID,
		controller_agent.PinglistType_TOR_MESH,
	)
	if torMeshErr != nil {
		m.logger.Error().Err(torMeshErr).
			Int("cached_count", len(m.lastTorMeshTargets)).
			Msg("Failed to fetch TOR_MESH pinglist, reusing cached targets")
		torMeshTargets = m.lastTorMeshTargets
	} else {
		m.lastTorMeshTargets = torMeshTargets
	}

	// Fetch inter-ToR pinglist (targets across different ToRs).
	interTorTargets, interTorErr := m.client.GetPinglist(
		ctx, m.agentID, m.torID, m.requesterGID,
		controller_agent.PinglistType_INTER_TOR,
	)
	if interTorErr != nil {
		m.logger.Error().Err(interTorErr).
			Int("cached_count", len(m.lastInterTorTargets)).
			Msg("Failed to fetch INTER_TOR pinglist, reusing cached targets")
		interTorTargets = m.lastInterTorTargets
	} else {
		m.lastInterTorTargets = interTorTargets
	}

	if torMeshErr != nil && interTorErr != nil {
		m.logger.Warn().Msg("Both pinglist fetches failed, falling back to cached targets")
	}

	// Combine the results from both pinglist types.
	combined := make([]*controller_agent.PingTarget, 0, len(torMeshTargets)+len(interTorTargets))
	combined = append(combined, torMeshTargets...)
	combined = append(combined, interTorTargets...)

	m.logger.Info().
		Int("tor_mesh_count", len(torMeshTargets)).
		Int("inter_tor_count", len(interTorTargets)).
		Int("total_count", len(combined)).
		Msg("Fetched pinglists from controller")

	return combined
}
