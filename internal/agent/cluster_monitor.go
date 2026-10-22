// Package agent implements the R-Pingmesh agent. ClusterMonitor periodically
// fetches pinglists from the controller and distributes probe targets to the
// Prober for continuous network quality measurement.
package agent

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// ControllerClient defines the interface for communicating with the controller.
// This interface allows the monitor to be tested with a mock client.
type ControllerClient interface {
	GetPinglist(ctx context.Context, agentID, torID, requesterGID, planeID string, ptype controller_agent.PinglistType) ([]*controller_agent.PingTarget, error)
}

// ClusterMonitor periodically fetches the ToR-mesh and inter-ToR pinglists
// of one RNIC from the controller and pushes the combined targets to that
// RNIC's prober.
type ClusterMonitor struct {
	lifecycle
	client       ControllerClient
	prober       *Prober
	agentID      string
	torID        string
	requesterGID string
	// planeID is the requesting RNIC's plane sent with every pinglist
	// request (empty = no plane restriction). Set via SetPlaneID.
	planeID        string
	updateInterval time.Duration
	logger         zerolog.Logger

	// lastTorMeshTargets and lastInterTorTargets cache the last successful
	// pinglist of each type so a failed fetch of one type reuses its cached
	// value instead of wiping out the other type's live targets. Owned by
	// the monitor loop goroutine.
	lastTorMeshTargets  []*controller_agent.PingTarget
	lastInterTorTargets []*controller_agent.PingTarget

	// minEarlyRefresh is the base delay of early (out-of-schedule) pinglist
	// refreshes: those requested by the prober on a target timeout streak
	// and the retry after an empty pinglist. See earlyRefreshBackoff.
	minEarlyRefresh time.Duration
}

// defaultMinEarlyRefresh is the base delay between early pinglist refreshes.
// It bounds controller load when many agents see timeouts at once (e.g. a
// ToR outage) while still recovering from a restarted peer's QPN change in
// well under the default 300s update interval.
const defaultMinEarlyRefresh = 30 * time.Second

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

	m := &ClusterMonitor{
		client:          client,
		prober:          prober,
		agentID:         agentID,
		torID:           torID,
		requesterGID:    requesterGID,
		updateInterval:  interval,
		minEarlyRefresh: min(defaultMinEarlyRefresh, interval),
		logger:          log.With().Str("component", "cluster_monitor").Logger(),
	}
	m.stopCh = make(chan struct{})
	return m
}

// SetPlaneID sets the plane (rail) of the requesting RNIC, sent with every
// pinglist request so the controller can restrict targets to that plane even
// before the RNIC's registration is visible. Call it before Start.
func (m *ClusterMonitor) SetPlaneID(planeID string) {
	m.planeID = planeID
}

// Start launches the background goroutine that fetches pinglists: once
// immediately, then every update interval. It returns nil if already running.
func (m *ClusterMonitor) Start(ctx context.Context) error {
	if !m.lifecycle.start() {
		return nil
	}
	m.wg.Add(1)
	go m.monitorLoop(ctx)

	m.logger.Info().
		Str("agent_id", m.agentID).
		Str("tor_id", m.torID).
		Str("requester_gid", m.requesterGID).
		Str("plane_id", m.planeID).
		Dur("update_interval", m.updateInterval).
		Msg("ClusterMonitor started")

	return nil
}

// Stop signals the monitor goroutine to exit and waits for it. Safe to call
// more than once.
func (m *ClusterMonitor) Stop() {
	if m.lifecycle.stop() {
		m.logger.Info().Msg("ClusterMonitor stopped")
	}
}

// monitorLoop fetches pinglists once on start and then on every tick until
// ctx is cancelled or Stop closes stopCh.
//
// Between ticks it also performs early refreshes, paced by
// earlyRefreshBackoff:
//   - when the prober reports a target timeout streak (RefreshHint). The
//     usual cause is a peer agent that restarted and re-registered its RNIC
//     under a new QPN, which the cached pinglist does not know yet; without
//     an early refresh every probe to it times out (and is reported as loss)
//     until the next tick.
//   - after a fetch that returned no targets at all, typically because this
//     agent registered before its peers, so it does not sit idle for a
//     whole update interval.
func (m *ClusterMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	var hint <-chan struct{}
	if m.prober != nil {
		hint = m.prober.RefreshHint()
	}
	backoff := newEarlyRefreshBackoff(m.minEarlyRefresh, m.updateInterval)

	// Fetch immediately on start so the prober has targets without
	// waiting for the first tick.
	snap := m.updateTargets(ctx)
	lastFetch := time.Now()

	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	// emptyRetry fires an early refresh after a fetch returned no targets.
	emptyRetry := time.NewTimer(backoff.delay())
	defer emptyRetry.Stop()
	armEmptyRetry := func() {
		emptyRetry.Stop()
		if len(snap) == 0 {
			emptyRetry.Reset(backoff.delay())
		}
	}
	armEmptyRetry()

	earlyRefresh := func(reason string) {
		prev := snap
		snap = m.updateTargets(ctx)
		lastFetch = time.Now()
		// Progress means a stale QPN was replaced, or an empty pinglist
		// gained targets; anything else backs off further.
		progressed := qpnChanged(prev, snap) || (len(prev) == 0 && len(snap) > 0)
		backoff.observe(progressed)
		m.logger.Info().
			Str("reason", reason).
			Bool("progressed", progressed).
			Int("target_count", len(snap)).
			Dur("next_min_delay", backoff.delay()).
			Msg("Early pinglist refresh")
		armEmptyRetry()
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap = m.updateTargets(ctx)
			lastFetch = time.Now()
			armEmptyRetry()
		case <-hint:
			// Rate-limit: a hint arriving too soon after the last fetch is
			// dropped; the prober re-requests after another timeout streak
			// if the target is still failing.
			if time.Since(lastFetch) < backoff.delay() {
				continue
			}
			earlyRefresh("target_timeouts")
		case <-emptyRetry.C:
			earlyRefresh("empty_pinglist")
		}
	}
}

// earlyRefreshBackoff paces early pinglist refreshes. The delay starts at
// base and doubles (capped at max, the regular update interval) every time an
// early refresh makes no progress -- the failing target is really down rather
// than stale, so refetching sooner cannot help -- and resets to base as soon
// as a refresh does (see monitorLoop's earlyRefresh).
type earlyRefreshBackoff struct {
	base, max, cur time.Duration
}

func newEarlyRefreshBackoff(base, max time.Duration) *earlyRefreshBackoff {
	if base <= 0 || base > max {
		base = max
	}
	return &earlyRefreshBackoff{base: base, max: max, cur: base}
}

func (b *earlyRefreshBackoff) delay() time.Duration { return b.cur }

func (b *earlyRefreshBackoff) observe(changed bool) {
	if changed {
		b.cur = b.base
		return
	}
	b.cur = min(b.cur*2, b.max)
}

// updateTargets fetches the combined pinglist and pushes targets to the
// prober. fetchPinglists always returns a usable list (falling back to
// per-type cached values on failure), so the result is always pushed. It
// returns the pushed list's GID -> QPN snapshot (see qpnsByGID).
func (m *ClusterMonitor) updateTargets(ctx context.Context) map[string]uint32 {
	targets := m.fetchPinglists(ctx)
	m.prober.UpdateTargets(targets)
	return qpnsByGID(targets)
}

// qpnsByGID maps each target GID in a pinglist to its responder QPN.
func qpnsByGID(targets []*controller_agent.PingTarget) map[string]uint32 {
	qpns := make(map[string]uint32, len(targets))
	for _, t := range targets {
		if t != nil {
			qpns[t.GetTargetGid()] = t.GetTargetQpn()
		}
	}
	return qpns
}

// qpnChanged reports whether any GID present in both snapshots changed QPN,
// i.e. a refresh replaced a stale QPN of a re-registered peer. Membership
// changes alone do not count: inter-ToR representatives are re-sampled on
// every fetch, so the GID set differs between refreshes even when nothing
// was stale.
func qpnChanged(prev, cur map[string]uint32) bool {
	for gid, qpn := range cur {
		if old, ok := prev[gid]; ok && old != qpn {
			return true
		}
	}
	return false
}

// fetchPinglists requests the TOR_MESH and INTER_TOR pinglists and merges
// them. Each type is handled independently: on success its result replaces
// the cached value for that type, on failure the cached value is reused.
func (m *ClusterMonitor) fetchPinglists(ctx context.Context) []*controller_agent.PingTarget {
	torMeshTargets, torMeshErr := m.client.GetPinglist(
		ctx, m.agentID, m.torID, m.requesterGID, m.planeID,
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

	interTorTargets, interTorErr := m.client.GetPinglist(
		ctx, m.agentID, m.torID, m.requesterGID, m.planeID,
		controller_agent.PinglistType_INTER_TOR,
	)
	if interTorErr != nil {
		m.logger.Error().Err(interTorErr).
			Int("cached_count", len(m.lastInterTorTargets)).
			Msg("Failed to fetch INTER_TOR pinglist, reusing cached targets")
		interTorTargets = m.lastInterTorTargets
	} else {
		// An older controller never sets pinglist_type, so its inter-ToR
		// targets arrive as the proto3-default TOR_MESH and would be
		// rate-limited as ToR-mesh. The agent knows they came from an
		// INTER_TOR request, so stamp the type where it is unset.
		stampUnsetPinglistType(interTorTargets, controller_agent.PinglistType_INTER_TOR)
		m.lastInterTorTargets = interTorTargets
	}

	if torMeshErr != nil && interTorErr != nil {
		m.logger.Warn().Msg("Both pinglist fetches failed, falling back to cached targets")
	}

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

// stampUnsetPinglistType sets ptype on every target whose pinglist_type is
// still the proto3 default (TOR_MESH / 0). The targets are freshly
// deserialized and owned by this agent, so mutating them in place is safe.
func stampUnsetPinglistType(targets []*controller_agent.PingTarget, ptype controller_agent.PinglistType) {
	for _, t := range targets {
		if t != nil && t.GetPinglistType() == controller_agent.PinglistType_TOR_MESH {
			t.PinglistType = ptype
		}
	}
}
