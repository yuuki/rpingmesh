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
	wg             sync.WaitGroup
	logger         zerolog.Logger
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
// It is safe to call Stop multiple times.
func (m *ClusterMonitor) Stop() {
	if !m.running.CompareAndSwap(true, false) {
		return // not running
	}
	m.wg.Wait()
	m.logger.Info().Msg("ClusterMonitor stopped")
}

// monitorLoop is the main background loop. It fetches pinglists once
// immediately on start, then on every tick of the update interval.
// If the context is cancelled or running is set to false, the loop exits.
func (m *ClusterMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	// Fetch immediately on start so the prober has targets without
	// waiting for the first tick.
	m.updateTargets(ctx)

	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for m.running.Load() {
		select {
		case <-ctx.Done():
			m.running.Store(false)
			return
		case <-ticker.C:
			if !m.running.Load() {
				return
			}
			m.updateTargets(ctx)
		}
	}
}

// updateTargets fetches the combined pinglist and pushes targets to the prober.
// If the fetch returns a non-empty list, the prober's targets are replaced.
// If both fetches fail, the prober keeps its previous targets to avoid
// clearing healthy targets on a transient controller failure.
func (m *ClusterMonitor) updateTargets(ctx context.Context) {
	targets := m.fetchPinglists(ctx)
	if targets != nil {
		m.prober.UpdateTargets(targets)
	}
}

// fetchPinglists requests both TOR_MESH and INTER_TOR pinglists from the
// controller, merges the results, and returns the combined list.
//
// If both fetches fail, nil is returned so the caller knows not to update
// the prober (preserving previous targets). If at least one succeeds, the
// successfully fetched targets are returned (which may be empty if the
// controller has no targets for that type).
func (m *ClusterMonitor) fetchPinglists(ctx context.Context) []*controller_agent.PingTarget {
	var (
		torMeshTargets  []*controller_agent.PingTarget
		interTorTargets []*controller_agent.PingTarget
		torMeshErr      error
		interTorErr     error
	)

	// Fetch ToR-mesh pinglist (targets within the same ToR).
	torMeshTargets, torMeshErr = m.client.GetPinglist(
		ctx, m.agentID, m.torID, m.requesterGID,
		controller_agent.PinglistType_TOR_MESH,
	)
	if torMeshErr != nil {
		m.logger.Error().Err(torMeshErr).
			Msg("Failed to fetch TOR_MESH pinglist")
	}

	// Fetch inter-ToR pinglist (targets across different ToRs).
	interTorTargets, interTorErr = m.client.GetPinglist(
		ctx, m.agentID, m.torID, m.requesterGID,
		controller_agent.PinglistType_INTER_TOR,
	)
	if interTorErr != nil {
		m.logger.Error().Err(interTorErr).
			Msg("Failed to fetch INTER_TOR pinglist")
	}

	// If both fetches failed, return nil to signal the caller that the
	// prober should keep its existing targets.
	if torMeshErr != nil && interTorErr != nil {
		m.logger.Warn().Msg("Both pinglist fetches failed, keeping previous targets")
		return nil
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
