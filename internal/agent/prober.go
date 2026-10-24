package agent

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"golang.org/x/sys/unix"
)

const (
	// probeSendTimeoutMS bounds one probe send and its send completion.
	probeSendTimeoutMS = 1000

	// resultChanSize is the buffer size of the probe results channel.
	resultChanSize = 1024

	// stalePendingTimeout is how long a probe may wait for its ACKs before
	// it is reported as timed out.
	stalePendingTimeout = 30 * time.Second

	// staleTargetTimeoutStreak is the number of consecutive ACK timeouts to
	// one target (GID + QPN) after which the prober asks its ClusterMonitor
	// for an early pinglist refresh. A restarted peer re-registers its RNIC
	// under a new responder QPN, so probes to the old QPN time out until the
	// pinglist is refreshed; the streak bounds that window by the
	// stale-pending timeout rather than the much longer update interval.
	staleTargetTimeoutStreak = 3

	// stalePendingCleanupPeriod is the wall-clock interval between
	// stale-pending sweeps, independent of the probe rate.
	stalePendingCleanupPeriod = 10 * time.Second
)

// labelsForTarget returns the flow-label set the prober cycles through for a
// target: the single controller-provided FlowLabel when FlowLabelCount <= 1
// (legacy controllers), else the set expanded from FlowLabelSeed and
// FlowLabelCount for the given rotation epoch.
func labelsForTarget(target *controller_agent.PingTarget, rotationEpoch uint64) []uint32 {
	if target.GetFlowLabelCount() <= 1 {
		return []uint32{target.GetFlowLabel()}
	}
	return probe.GenerateFlowLabels(target.GetFlowLabelSeed(), target.GetFlowLabelCount(), rotationEpoch)
}

// pendingProbe is the in-flight state of a probe awaiting its ACKs. The
// embedded PendingMeasurement accepts the two ACKs in either order.
type pendingProbe struct {
	target    *controller_agent.PingTarget
	meas      *probe.PendingMeasurement
	createdAt time.Time
	// flowLabel is the ECMP flow label this probe was sent with (one of the
	// target's rotating set), so the result reports the path exercised.
	flowLabel uint32
}

// Prober sends probe packets to its targets, matches the ACK completions
// read from its event ring against the pending probes, and emits completed
// 6-timestamp ProbeResults on a buffered channel.
type Prober struct {
	lifecycle
	queueHandle
	ring   *rdmabridge.EventRing
	device *rdmabridge.Device

	// Identity of the bound RNIC stamped onto every emitted ProbeResult.
	// sourceGID is zero when the device GID is unparseable (results are then
	// not path-aggregated). sourceTorLabel and sourceNetdev are set once via
	// SetSourceTorID / SetSourceNetdev before Start; empty means unknown.
	sourceGID        [16]byte
	sourceTorLabel   string
	sourceRdmaDevice string
	sourceNetdev     string

	// targets are the controller's pinglist targets (ToR-mesh and
	// inter-ToR); serviceTargets are the SERVICE_TRACING targets built from
	// the traced service flows (see UpdateServiceTargets). They are kept
	// apart so a pinglist refresh never drops the service targets and vice
	// versa, and each list has its own generation (targetsGen, serviceGen)
	// so an update of one list restarts only that list's passes: service
	// connections can churn every second, and restarting the pinglist
	// passes on every churn would starve the targets at their end. Both
	// generations are guarded by targetsMu.
	targets        []*controller_agent.PingTarget
	serviceTargets []*controller_agent.PingTarget
	targetsGen     uint64
	serviceGen     uint64
	targetsMu      sync.RWMutex

	pending   map[uint64]*pendingProbe // sequence_num -> pending probe
	pendingMu sync.Mutex

	// Sequence numbers are high 32 bits = agentEpoch (random per process, so
	// ACKs from a previous agent lifetime cannot match) | low 32 bits =
	// seqCounter.
	seqCounter atomic.Uint64
	agentEpoch uint32

	resultChan chan *probe.ProbeResult

	// destroyOnce makes Destroy idempotent: resultChan is closed exactly once
	// even if Agent.Stop destroys the prober after a partial start.
	destroyOnce sync.Once

	probeInterval time.Duration
	probeTimeout  uint32 // ms

	// Per-pinglist-type send-rate limiters, so ToR-mesh and inter-ToR
	// targets can be capped at independent per-target rates. Each limiter's
	// aggregate rate is pps * (targets of that type) * rateMultiplier,
	// recomputed on every UpdateTargets so the per-target cadence survives
	// pinglist churn. rateMultiplier in (0, 1] is the self-protection
	// throttle set by the Watchdog; it never reaches 0, so probing degrades
	// but never stops. Lock order: targetsMu -> rateMu.
	rateMu         sync.Mutex
	torMeshRate    perTypeRate
	interTorRate   perTypeRate
	rateMultiplier float64

	// serviceRate paces the service-tracing pass. Unlike the two pinglist
	// rates, its pps is an AGGREGATE cap per prober (RNIC), not a per-target
	// one: the number of traced flows is set by the applications, not by the
	// controller, so a per-target rate could not bound the probe load. The
	// flows share the budget, and each pass visits them in a fresh random
	// order (the paper's "shuffle the pinglist in each round"). Guarded by
	// rateMu like the other rates.
	serviceRate perTypeRate
	// serviceInterval is the minimum spacing between two passes over the
	// service targets (the paper's 10 ms service-tracing interval); 0 means
	// probeInterval. Read only by the probe-loop goroutine; set before Start.
	serviceInterval time.Duration

	// flowLabelRotationPeriodSec is the period over which the rotating subset
	// of each target's flow-label set is refreshed. Read only by the
	// probe-loop goroutine; set before Start.
	flowLabelRotationPeriodSec uint32

	// labelRotation (next label index per target GID) and labelCache (the
	// generated label set per target GID) are owned by the probe-loop
	// goroutine and pruned when the pinglist changes.
	labelRotation map[string]uint32
	labelCache    map[string]*labelSet

	// timeoutStreak counts consecutive ACK timeouts per target key (see
	// targetKey); any completed probe resets it and UpdateTargets clears it.
	// currentKeys is the current pinglist's key set: timeouts of probes sent
	// to a key no longer in it are not counted, so they cannot re-trigger a
	// refresh that already happened. Written from both the probe loop and
	// the ACK loop, hence streakMu.
	streakMu      sync.Mutex
	timeoutStreak map[string]int
	currentKeys   map[string]struct{}

	// refreshHint carries an early-refresh request to the ClusterMonitor
	// (see staleTargetTimeoutStreak). Capacity 1 and written non-blockingly,
	// so repeated requests coalesce.
	refreshHint chan struct{}

	logger zerolog.Logger
}

// perTypeRate couples the configured per-target probe rate (pps) of one
// pinglist type with the aggregate RateLimiter enforcing it. pps is retained
// so UpdateTargets can recompute the aggregate when the pinglist size changes.
type perTypeRate struct {
	pps     float64
	limiter probe.RateLimiter
}

// labelSet is a cached flow-label set plus the inputs that produced it.
type labelSet struct {
	epoch  uint64
	seed   uint32
	count  uint32
	labels []uint32
}

// newProberCore builds a Prober with every map, channel and default
// initialized but no RDMA queue. NewProber binds the queue and device; tests
// use it directly to exercise scheduling and rate logic without RDMA.
func newProberCore(probeInterval time.Duration) *Prober {
	p := &Prober{
		pending:                    make(map[uint64]*pendingProbe),
		agentEpoch:                 rand.Uint32(),
		resultChan:                 make(chan *probe.ProbeResult, resultChanSize),
		refreshHint:                make(chan struct{}, 1),
		probeInterval:              probeInterval,
		probeTimeout:               probeSendTimeoutMS,
		rateMultiplier:             1.0,
		flowLabelRotationPeriodSec: config.DefaultFlowLabelRotationPeriodSec,
		labelRotation:              make(map[string]uint32),
		labelCache:                 make(map[string]*labelSet),
		logger:                     log.With().Str("component", "prober").Logger(),
	}
	p.stopCh = make(chan struct{})
	return p
}

// NewProber creates a Prober with a sender-type RDMA queue bound to device and
// ring. probeIntervalMS is how often every target is probed.
func NewProber(device *rdmabridge.Device, ring *rdmabridge.EventRing, probeIntervalMS uint32) (*Prober, error) {
	// A zero interval would make probeLoop's ticker panic; fail at
	// construction instead.
	if probeIntervalMS == 0 {
		return nil, fmt.Errorf("probeIntervalMS must be greater than 0")
	}

	queue, err := device.CreateQueue(rdmabridge.QueueTypeSender, ring)
	if err != nil {
		return nil, err
	}

	p := newProberCore(time.Duration(probeIntervalMS) * time.Millisecond)
	p.queue = queue
	p.ring = ring
	p.device = device
	p.sourceRdmaDevice = device.Info.DeviceName
	// Best-effort: an unparseable GID only means results are not
	// path-aggregated.
	if gid, err := probe.ParseGID(device.Info.GID); err == nil {
		p.sourceGID = gid
	}

	p.logger.Info().
		Uint32("qpn", queue.Info.QPN).
		Uint32("agent_epoch", p.agentEpoch).
		Uint32("probe_interval_ms", probeIntervalMS).
		Msg("Prober created")
	return p, nil
}

// Start launches the probe loop (sends, pacing each pinglist type
// independently) and the ACK loop (drains the event ring). Both run until
// Stop is called or ctx is cancelled.
func (p *Prober) Start(ctx context.Context) error {
	if !p.lifecycle.start() {
		return nil
	}
	p.wg.Add(2)
	go p.probeLoop(ctx)
	go p.ackProcessLoop(ctx)

	p.logger.Info().
		Str("device", p.sourceRdmaDevice).
		Uint32("qpn", p.queue.Info.QPN).
		Bool("cq_events", p.queue.Info.UsesCQEvents).
		Bool("hw_timestamps", !p.queue.Info.UsesSWTimestamps).
		Msg("Prober started")
	return nil
}

// Stop signals both loops to exit and waits for them. Safe to call more
// than once.
func (p *Prober) Stop() {
	if p.lifecycle.stop() {
		p.logger.Info().Msg("Prober stopped")
	}
}

// SetPerTargetRateLimit applies the same per-target cap (packets per second)
// to both pinglist types. A non-positive pps disables the cap.
func (p *Prober) SetPerTargetRateLimit(pps float64) {
	p.SetPerTypeRateLimit(pps, pps)
}

// SetPerTypeRateLimit caps the per-target send rate at torMeshPPS for
// ToR-mesh targets and interTorPPS for inter-ToR targets. A non-positive pps
// disables the cap for that type. Safe to call while running.
func (p *Prober) SetPerTypeRateLimit(torMeshPPS, interTorPPS float64) {
	// targetsMu is held across the whole update (lock order targetsMu ->
	// rateMu) so the target counts and the recomputed rates cannot
	// interleave with a concurrent UpdateTargets.
	p.targetsMu.RLock()
	defer p.targetsMu.RUnlock()
	nTorMesh, nInterTor := countTargetsByType(p.targets)

	p.rateMu.Lock()
	p.torMeshRate.pps = torMeshPPS
	p.interTorRate.pps = interTorPPS
	p.applyRatesLocked(nTorMesh, nInterTor)
	p.rateMu.Unlock()

	p.logger.Info().
		Float64("tor_mesh_pps", torMeshPPS).
		Int("tor_mesh_targets", nTorMesh).
		Float64("inter_tor_pps", interTorPPS).
		Int("inter_tor_targets", nInterTor).
		Msg("Probe send rate limits updated")
}

// SetRateMultiplier scales both per-type aggregate rates by mult, the
// self-protection throttle factor the Watchdog drives. mult is clamped to
// (0, 1] (anything else means unthrottled), so it can only slow probing. The
// stored multiplier is applied by later UpdateTargets/SetPerTypeRateLimit
// calls too, so a pinglist change while throttled preserves the throttle.
func (p *Prober) SetRateMultiplier(mult float64) {
	mult = clampRateMultiplier(mult)

	p.targetsMu.RLock()
	defer p.targetsMu.RUnlock()
	nTorMesh, nInterTor := countTargetsByType(p.targets)

	p.rateMu.Lock()
	p.rateMultiplier = mult
	p.applyRatesLocked(nTorMesh, nInterTor)
	p.rateMu.Unlock()

	p.logger.Debug().
		Float64("rate_multiplier", mult).
		Msg("Probe send rate multiplier updated")
}

// applyRatesLocked recomputes the limiters from the stored rates, the given
// pinglist target counts and the throttle multiplier. Caller holds rateMu.
func (p *Prober) applyRatesLocked(nTorMesh, nInterTor int) {
	p.torMeshRate.limiter.SetRate(scaledRate(p.torMeshRate.pps, nTorMesh, p.rateMultiplier, p.probeInterval))
	p.interTorRate.limiter.SetRate(scaledRate(p.interTorRate.pps, nInterTor, p.rateMultiplier, p.probeInterval))
	p.serviceRate.limiter.SetRate(serviceAggregateRate(p.serviceRate.pps, p.rateMultiplier))
}

// serviceAggregateRate is the service-tracing limiter rate: the configured
// aggregate pps scaled by the throttle multiplier. A non-positive pps
// disables the cap (0 is read by RateLimiter.SetRate as disabled); the
// service pass interval then paces the sends alone, so config validation
// requires a positive rate whenever service tracing is enabled.
func serviceAggregateRate(pps, mult float64) float64 {
	if pps <= 0 {
		return 0
	}
	if mult <= 0 || mult > 1 {
		mult = 1.0
	}
	return pps * mult
}

// SetServiceTracingRate caps the aggregate service-tracing send rate of this
// prober at pps probes per second and spaces passes over the service targets
// by at least intervalMS milliseconds (0 keeps probeInterval). Call it before
// Start; the rate is applied on the next rate recomputation.
func (p *Prober) SetServiceTracingRate(pps float64, intervalMS uint32) {
	p.rateMu.Lock()
	p.serviceRate.pps = pps
	p.serviceRate.limiter.SetRate(serviceAggregateRate(pps, p.rateMultiplier))
	p.rateMu.Unlock()
	p.serviceInterval = time.Duration(intervalMS) * time.Millisecond
	p.logger.Info().
		Float64("service_pps", pps).
		Uint32("service_interval_ms", intervalMS).
		Msg("Service tracing probe rate updated")
}

// UpdateServiceTargets replaces the SERVICE_TRACING targets, one per traced
// service flow, each carrying that flow's own flow label. The pinglist
// targets and their passes are untouched; only the service pass restarts.
func (p *Prober) UpdateServiceTargets(targets []*controller_agent.PingTarget) {
	p.targetsMu.Lock()
	defer p.targetsMu.Unlock()
	p.serviceTargets = targets
	p.serviceGen++
	p.logger.Info().
		Int("count", len(targets)).
		Msg("Service tracing targets updated")
}

// passInterval is the minimum spacing between two passes of a pinglist
// type: the service interval for service tracing, probeInterval otherwise.
func (p *Prober) passInterval(ptype controller_agent.PinglistType) time.Duration {
	if ptype == controller_agent.PinglistType_SERVICE_TRACING && p.serviceInterval > 0 {
		return p.serviceInterval
	}
	return p.probeInterval
}

// passTargetsLocked returns the targets of one pass of ptype: the pinglist
// targets of that type, or a freshly shuffled copy of the service targets.
// Caller holds targetsMu (read).
func (p *Prober) passTargetsLocked(ptype controller_agent.PinglistType) []*controller_agent.PingTarget {
	if ptype != controller_agent.PinglistType_SERVICE_TRACING {
		return targetsOfType(p.targets, ptype)
	}
	if len(p.serviceTargets) == 0 {
		return nil
	}
	out := make([]*controller_agent.PingTarget, 0, len(p.serviceTargets))
	for _, t := range p.serviceTargets {
		if t != nil {
			out = append(out, t)
		}
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// seenGens records the generations of the two target lists that the probe
// loop's passes reflect (see nextSend). Owned by the probe-loop goroutine.
type seenGens struct {
	targets uint64
	service uint64
}

// clampRateMultiplier maps any value outside (0, 1] to 1.0 (unthrottled).
func clampRateMultiplier(mult float64) float64 {
	if mult <= 0 || mult > 1 {
		return 1.0
	}
	return mult
}

// scaledRate computes a pinglist type's aggregate limiter rate: the
// effective per-target rate times the number of targets, scaled by the
// throttle multiplier.
//
// The effective per-target rate is min(pps, 1s/interval): the probe loop
// never sends a target more than once per interval, so a higher cap cannot
// be reached, and clamping makes the multiplier scale the rate actually
// achieved. A non-positive pps means "no cap", so the ceiling alone applies;
// a non-positive interval has no ceiling. A non-positive multiplier counts
// as 1.0. A result of 0 is read by RateLimiter.SetRate as disabled.
func scaledRate(pps float64, n int, mult float64, interval time.Duration) float64 {
	if mult <= 0 {
		mult = 1.0
	}
	if interval > 0 {
		ceiling := float64(time.Second) / float64(interval)
		if pps <= 0 || pps > ceiling {
			pps = ceiling
		}
	}
	if pps <= 0 {
		return 0
	}
	return pps * float64(n) * mult
}

// isInterTor reports whether a target belongs to the inter-ToR pinglist.
// Anything else, including the proto3-default zero value from a controller
// that never stamped the field, is ToR-mesh.
func isInterTor(t *controller_agent.PingTarget) bool {
	return t.GetPinglistType() == controller_agent.PinglistType_INTER_TOR
}

// countTargetsByType counts the non-nil targets of each pinglist type.
func countTargetsByType(targets []*controller_agent.PingTarget) (nTorMesh, nInterTor int) {
	for _, t := range targets {
		switch {
		case t == nil:
		case isInterTor(t):
			nInterTor++
		default:
			nTorMesh++
		}
	}
	return nTorMesh, nInterTor
}

// rateForType returns the limiter governing ptype. Caller holds rateMu.
func (p *Prober) rateForType(ptype controller_agent.PinglistType) *perTypeRate {
	switch ptype {
	case controller_agent.PinglistType_INTER_TOR:
		return &p.interTorRate
	case controller_agent.PinglistType_SERVICE_TRACING:
		return &p.serviceRate
	}
	return &p.torMeshRate
}

// SetFlowLabelRotationPeriod sets the period over which the rotating subset of
// each target's flow-label set is refreshed; 0 keeps the default. Call it
// before Start.
func (p *Prober) SetFlowLabelRotationPeriod(sec uint32) {
	if sec == 0 {
		sec = config.DefaultFlowLabelRotationPeriodSec
	}
	p.flowLabelRotationPeriodSec = sec
	p.logger.Info().
		Uint32("rotation_period_sec", sec).
		Msg("Flow-label rotation period updated")
}

// flowLabelRotationEpoch maps a wall-clock instant to the rotation epoch
// floor(unixTime / period). Wall-clock is fine here: the epoch only selects
// labels, never a measurement timestamp.
func (p *Prober) flowLabelRotationEpoch(now time.Time) uint64 {
	period := p.flowLabelRotationPeriodSec
	if period == 0 {
		period = config.DefaultFlowLabelRotationPeriodSec
	}
	return uint64(now.Unix()) / uint64(period)
}

// nowMonotonicNS returns CLOCK_MONOTONIC in nanoseconds. T6 must come from
// this clock rather than time.Now().UnixNano() so that ProberDelay =
// (T6-T1) - (T5-T2) is sound: T1 is CLOCK_MONOTONIC on this host (Zig side),
// and (T5-T2) is a same-clock difference whichever clock the NIC used.
func nowMonotonicNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Does not fail in practice on Linux; avoid returning zero, which
		// the RTT validator would reject.
		return uint64(time.Now().UnixNano())
	}
	return uint64(ts.Nano())
}

// UpdateTargets replaces the probe targets with a new pinglist.
func (p *Prober) UpdateTargets(targets []*controller_agent.PingTarget) {
	p.targetsMu.Lock()
	defer p.targetsMu.Unlock()
	p.targets = targets
	p.targetsGen++

	// A new pinglist may carry fresh QPNs for previously failing targets, so
	// timeout streaks restart against the new list.
	keys := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t != nil {
			keys[targetKey(t)] = struct{}{}
		}
	}
	p.streakMu.Lock()
	p.timeoutStreak = nil
	p.currentKeys = keys
	p.streakMu.Unlock()

	nTorMesh, nInterTor := countTargetsByType(targets)
	p.rateMu.Lock()
	p.applyRatesLocked(nTorMesh, nInterTor)
	p.rateMu.Unlock()

	p.logger.Info().
		Int("count", len(targets)).
		Int("tor_mesh_count", nTorMesh).
		Int("inter_tor_count", nInterTor).
		Msg("Probe targets updated")
}

// Results returns the channel of completed probe results.
func (p *Prober) Results() <-chan *probe.ProbeResult {
	return p.resultChan
}

// RefreshHint returns the channel that receives a value when some target has
// hit staleTargetTimeoutStreak consecutive ACK timeouts and the pinglist
// should be refreshed early.
func (p *Prober) RefreshHint() <-chan struct{} {
	return p.refreshHint
}

// targetKey identifies a target by GID and responder QPN, so a target that
// re-registered under a new QPN starts a fresh timeout streak.
func targetKey(target *controller_agent.PingTarget) string {
	return fmt.Sprintf("%s/%d", target.GetTargetGid(), target.GetTargetQpn())
}

// recordTargetOutcome updates the consecutive-timeout streak of target and
// requests an early pinglist refresh when it reaches staleTargetTimeoutStreak.
// The streak restarts after each request, so a target that stays unreachable
// re-requests at most once per streak; the ClusterMonitor rate-limits the
// resulting fetches.
func (p *Prober) recordTargetOutcome(target *controller_agent.PingTarget, timedOut bool) {
	if target == nil {
		return
	}
	key := targetKey(target)

	p.streakMu.Lock()
	if !timedOut {
		delete(p.timeoutStreak, key)
		p.streakMu.Unlock()
		return
	}
	if _, current := p.currentKeys[key]; !current {
		p.streakMu.Unlock()
		return
	}
	if p.timeoutStreak == nil {
		p.timeoutStreak = make(map[string]int)
	}
	p.timeoutStreak[key]++
	fire := p.timeoutStreak[key] >= staleTargetTimeoutStreak
	if fire {
		delete(p.timeoutStreak, key)
	}
	p.streakMu.Unlock()

	if fire && p.refreshHint != nil {
		select {
		case p.refreshHint <- struct{}{}:
		default: // a request is already pending
		}
	}
}

// sendPass is the probe loop's progress through one pinglist type's targets:
// a snapshot of that type's targets, the index of the next one to probe, and
// the earliest time the following pass may start.
type sendPass struct {
	ptype     controller_agent.PinglistType
	targets   []*controller_agent.PingTarget
	next      int
	notBefore time.Time
}

func (ps *sendPass) active() bool { return ps.next < len(ps.targets) }

// probeLoop sends one probe to every target per pass, with one pass per
// pinglist type, and periodically expires pending probes whose ACKs never
// came.
//
// The types are scheduled independently from this single goroutine: each
// iteration sends the probe whose type limiter is ready soonest, so a type
// whose cap binds delays only its own sends. The sends must stay on one
// goroutine: the Zig send path waits for its completion through a single
// per-queue slot, so concurrent SendProbe calls would steal each other's
// completions. A pass starts at most once per passInterval, which keeps the
// one-probe-per-target-per-interval ceiling even when a limiter is disabled.
func (p *Prober) probeLoop(ctx context.Context) {
	defer p.wg.Done()

	passes := [...]sendPass{
		{ptype: controller_agent.PinglistType_TOR_MESH},
		{ptype: controller_agent.PinglistType_INTER_TOR},
		{ptype: controller_agent.PinglistType_SERVICE_TRACING},
	}
	var seen seenGens

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	lastCleanup := time.Now()

	p.logger.Info().
		Dur("interval", p.probeInterval).
		Msg("Probe loop started")

	for p.running.Load() {
		// Do not clear running here: Stop is its only writer, and it must
		// Wait after the CAS so Destroy cannot race a sibling in SendProbe.
		if p.stopping(ctx) {
			return
		}

		now := time.Now()
		if now.Sub(lastCleanup) >= stalePendingCleanupPeriod {
			p.cleanupStalePending()
			lastCleanup = now
		}

		pass, wait := p.nextSend(passes[:], &seen, now)
		if pass == nil || wait > 0 {
			// Sleep until the next send is due, waking for shutdown. The
			// sleep is bounded so the stale-pending sweep keeps its cadence
			// under a heavy throttle.
			timer.Reset(min(wait, stalePendingCleanupPeriod))
			select {
			case <-ctx.Done():
				return
			case <-p.stopCh:
				return
			case <-timer.C:
			}
			continue
		}

		target := pass.targets[pass.next]
		pass.next++
		p.reserveSend(pass.ptype, now)
		if target == nil {
			continue
		}
		p.sendProbe(target, p.flowLabelRotationEpoch(now))
	}
}

// nextSend returns the pass whose next probe may be sent soonest and how long
// until then. A zero wait means pass.targets[pass.next] may be sent now; a
// positive wait means sleep and ask again (rates and targets may change
// meanwhile). It returns a nil pass when neither type has a pass that can
// start, with wait set to when one can.
//
// A finished pass whose notBefore has passed is restarted with a fresh
// snapshot of its type's targets. After UpdateTargets the pinglist passes
// are abandoned, and after UpdateServiceTargets the service pass is, so
// probes are not sent to targets that were just removed and new targets are
// reached without waiting for a stale pass to finish; an update of one list
// never restarts the other's passes. Called only from the probe-loop
// goroutine, which owns passes and seen.
func (p *Prober) nextSend(passes []sendPass, seen *seenGens, now time.Time) (*sendPass, time.Duration) {
	p.targetsMu.RLock()
	targetsChanged := p.targetsGen != seen.targets
	serviceChanged := p.serviceGen != seen.service
	var pinglist []*controller_agent.PingTarget
	if targetsChanged {
		pinglist = p.targets
	}
	for i := range passes {
		ps := &passes[i]
		isService := ps.ptype == controller_agent.PinglistType_SERVICE_TRACING
		if (isService && serviceChanged) || (!isService && targetsChanged) {
			ps.targets, ps.next = nil, 0
		}
		if !ps.active() && !now.Before(ps.notBefore) {
			ps.targets = p.passTargetsLocked(ps.ptype)
			ps.next = 0
			ps.notBefore = now.Add(p.passInterval(ps.ptype))
		}
	}
	seen.targets, seen.service = p.targetsGen, p.serviceGen
	p.targetsMu.RUnlock()

	if targetsChanged {
		// Service targets never own rotation state (see nextFlowLabel), so
		// the pinglist alone decides what to keep.
		p.pruneLabelRotation(pinglist)
	}

	var best *sendPass
	bestWait := time.Duration(-1)
	// soonestStart is the next restart of a finished pass that has targets;
	// soonestAny also counts passes without targets (an empty pinglist
	// type), which only need a wake-up when nothing else is scheduled.
	soonestStart := time.Duration(-1)
	soonestAny := time.Duration(-1)
	for i := range passes {
		ps := &passes[i]
		if !ps.active() {
			w := ps.notBefore.Sub(now)
			if soonestAny < 0 || w < soonestAny {
				soonestAny = w
			}
			if len(ps.targets) > 0 && (soonestStart < 0 || w < soonestStart) {
				soonestStart = w
			}
			continue
		}
		w := p.sendDelay(ps.ptype, now)
		if best == nil || w < bestWait {
			best, bestWait = ps, w
		}
	}
	if best == nil {
		if soonestStart >= 0 {
			return nil, soonestStart
		}
		return nil, soonestAny
	}
	if soonestStart >= 0 && soonestStart < bestWait {
		// A finished pass restarts before the active pass's next slot; wake
		// up for it so its first probe is not delayed.
		return nil, soonestStart
	}
	return best, bestWait
}

// targetsOfType returns the non-nil targets of the given pinglist type.
func targetsOfType(targets []*controller_agent.PingTarget, ptype controller_agent.PinglistType) []*controller_agent.PingTarget {
	wantInter := ptype == controller_agent.PinglistType_INTER_TOR
	var out []*controller_agent.PingTarget
	for _, t := range targets {
		if t != nil && isInterTor(t) == wantInter {
			out = append(out, t)
		}
	}
	return out
}

// sendProbe sends one probe to target, registering its pending entry, and
// emits a failed result if the send fails.
func (p *Prober) sendProbe(target *controller_agent.PingTarget, rotationEpoch uint64) {
	counter := p.seqCounter.Add(1)
	seqNum := (uint64(p.agentEpoch) << 32) | (counter & 0xFFFFFFFF)

	// Parse before registering the pending entry so a malformed target never
	// leaves an orphan behind.
	targetGID, err := probe.ParseGID(target.GetTargetGid())
	if err != nil {
		p.logger.Error().Err(err).
			Str("target_gid", target.GetTargetGid()).
			Uint64("seq", seqNum).
			Msg("Failed to parse target GID, skipping target")
		return
	}

	// Round-robin across the target's ECMP label set. Labels share the
	// target's probe budget (the rate limit is per target), so a larger set
	// trades coverage speed for bounded probe amplification.
	flowLabel := p.nextFlowLabel(target, rotationEpoch)

	// Register the pending entry BEFORE sending: SendProbe blocks until the
	// send completion (T2), and on a low-latency RNIC an ACK can reach the
	// ACK loop before it returns. Complete() requires the send-side
	// timestamps applied below, so the ACK handlers cannot finalize the
	// entry before this path records T1/T2.
	pp := &pendingProbe{
		target:    target,
		meas:      probe.NewPendingMeasurement(),
		createdAt: time.Now(),
		flowLabel: flowLabel,
	}
	p.pendingMu.Lock()
	p.pending[seqNum] = pp
	p.pendingMu.Unlock()

	// The per-send flow label reaches ibv_ah_attr.grh.flow_label through a
	// fresh AH created in the Zig bridge.
	result := p.queue.SendProbe(targetGID, target.GetTargetQpn(), seqNum, flowLabel, p.probeTimeout)
	if result.Error != nil {
		// No ACK will ever complete this probe: drop the entry and count the
		// loss in probe_failed_total now rather than at the stale sweep.
		p.pendingMu.Lock()
		delete(p.pending, seqNum)
		p.pendingMu.Unlock()

		p.logger.Error().Err(result.Error).
			Str("target_gid", target.GetTargetGid()).
			Uint32("target_qpn", target.GetTargetQpn()).
			Uint64("seq", seqNum).
			Uint32("flow_label", flowLabel).
			Msg("Failed to send probe packet")
		p.emitResult(newFailedResult(seqNum, target, flowLabel, probe.FailureSendError, fmt.Sprintf("probe send failed: %v", result.Error)))
		return
	}

	// Apply T1/T2. If both ACKs already arrived while the send was in
	// progress, this completes the measurement.
	p.pendingMu.Lock()
	var finalized *probe.ProbeResult
	if cur, ok := p.pending[seqNum]; ok {
		cur.meas.ApplySend(result.T1NS, result.T2NS)
		finalized = p.finalizeIfCompleteLocked(seqNum, cur)
	}
	p.pendingMu.Unlock()
	if finalized != nil {
		p.deliverResult(seqNum, target, finalized)
	}

	p.logger.Debug().
		Str("target_gid", target.GetTargetGid()).
		Uint32("target_qpn", target.GetTargetQpn()).
		Uint64("seq", seqNum).
		Uint32("flow_label", flowLabel).
		Uint64("t1_ns", result.T1NS).
		Uint64("t2_ns", result.T2NS).
		Msg("Probe sent, awaiting ACKs")
}

// nextFlowLabel returns the flow label for the next probe to target and
// advances the target's round-robin index. A target with a single label (a
// service flow, or a legacy single-label pinglist target) returns it without
// touching the round-robin state: that state is keyed by GID and shared with
// the pinglist target of the same remote RNIC, whose ECMP coverage would
// otherwise skip labels every time a service probe went to the same GID.
// Probe-loop goroutine only.
func (p *Prober) nextFlowLabel(target *controller_agent.PingTarget, rotationEpoch uint64) uint32 {
	labels := p.cachedLabelsForTarget(target, rotationEpoch)
	if len(labels) == 1 {
		return labels[0]
	}
	gid := target.GetTargetGid()
	idx := p.labelRotation[gid]
	p.labelRotation[gid] = idx + 1
	return labels[idx%uint32(len(labels))]
}

// cachedLabelsForTarget returns the target's flow-label set, regenerating it
// only when the rotation epoch or the target's seed/count changed, so a
// large set is not rebuilt on every probe. The single-label legacy case is
// trivial and bypasses the cache. Probe-loop goroutine only.
func (p *Prober) cachedLabelsForTarget(target *controller_agent.PingTarget, rotationEpoch uint64) []uint32 {
	count := target.GetFlowLabelCount()
	if count <= 1 {
		return labelsForTarget(target, rotationEpoch)
	}
	gid := target.GetTargetGid()
	seed := target.GetFlowLabelSeed()
	if e, ok := p.labelCache[gid]; ok && e.epoch == rotationEpoch && e.seed == seed && e.count == count {
		return e.labels
	}
	labels := probe.GenerateFlowLabels(seed, count, rotationEpoch)
	p.labelCache[gid] = &labelSet{epoch: rotationEpoch, seed: seed, count: count, labels: labels}
	return labels
}

// pruneLabelRotation drops round-robin and label-cache entries for targets
// absent from the current pinglist. Probe-loop goroutine only.
func (p *Prober) pruneLabelRotation(targets []*controller_agent.PingTarget) {
	if len(p.labelRotation) == 0 && len(p.labelCache) == 0 {
		return
	}
	live := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t != nil {
			live[t.GetTargetGid()] = struct{}{}
		}
	}
	for gid := range p.labelRotation {
		if _, ok := live[gid]; !ok {
			delete(p.labelRotation, gid)
		}
	}
	for gid := range p.labelCache {
		if _, ok := live[gid]; !ok {
			delete(p.labelCache, gid)
		}
	}
}

// sendDelay reports how long until ptype's limiter allows the next send,
// without reserving it. Zero means now (or the limiter is disabled).
func (p *Prober) sendDelay(ptype controller_agent.PinglistType, now time.Time) time.Duration {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	return p.rateForType(ptype).limiter.Delay(now)
}

// reserveSend books a send slot on ptype's limiter; called only once
// sendDelay reported zero.
func (p *Prober) reserveSend(ptype controller_agent.PinglistType, now time.Time) {
	p.rateMu.Lock()
	p.rateForType(ptype).limiter.Reserve(now)
	p.rateMu.Unlock()
}

// ackProcessLoop drains the event ring and matches ACK completions against
// pending probes: first ACKs supply T3 and T5, second ACKs T3, T4 and T6.
func (p *Prober) ackProcessLoop(ctx context.Context) {
	defer p.wg.Done()
	p.logger.Info().Msg("ACK process loop started")
	runRingLoop(ctx, &p.lifecycle, p.ring, p.queue.Info.UsesCQEvents, p.logger, p.handleACKEvent)
}

// handleACKEvent processes one completion event. Only successful ACK recv
// completions matter to the prober.
func (p *Prober) handleACKEvent(event *rdmabridge.CompletionEvent) {
	if event.IsSend || !event.IsAck {
		return
	}
	if event.Status != 0 {
		p.logger.Warn().
			Int32("status", event.Status).
			Uint64("seq", event.SequenceNum).
			Msg("ACK recv completion with non-zero status, skipping")
		return
	}

	switch event.AckType {
	case rdmabridge.AckTypeFirst:
		// T5 is this completion's timestamp (prober NIC recv of the first
		// ACK); T3 is the responder recv timestamp carried in the payload.
		p.applyAck(event.SequenceNum, "first", func(m *probe.PendingMeasurement) {
			m.ApplyFirstAck(event.T3, event.TimestampNS)
		}, func(e *zerolog.Event) *zerolog.Event {
			return e.Uint64("t3_ns", event.T3).Uint64("t5_ns", event.TimestampNS)
		})
	case rdmabridge.AckTypeSecond:
		// T6 is taken on this host, in the same CLOCK_MONOTONIC domain as
		// T1, as soon as the second ACK is processed; the ring event carries
		// no host-side timestamp for it.
		t6 := nowMonotonicNS()
		p.applyAck(event.SequenceNum, "second", func(m *probe.PendingMeasurement) {
			m.ApplySecondAck(event.T3, event.T4, t6)
		}, func(e *zerolog.Event) *zerolog.Event {
			return e.Uint64("t4_ns", event.T4).Uint64("t6_ns", t6)
		})
	default:
		p.logger.Warn().
			Uint8("ack_type", event.AckType).
			Uint64("seq", event.SequenceNum).
			Msg("Received ACK with unknown type")
	}
}

// applyAck records one ACK on the pending probe seqNum via apply and, when
// the measurement is then complete, delivers the result. ACKs may arrive in
// either order. fields adds the ACK's timestamps to the debug log.
func (p *Prober) applyAck(seqNum uint64, which string, apply func(*probe.PendingMeasurement), fields func(*zerolog.Event) *zerolog.Event) {
	p.pendingMu.Lock()
	pp, ok := p.pending[seqNum]
	if !ok {
		p.pendingMu.Unlock()
		p.logger.Warn().
			Uint64("seq", seqNum).
			Msgf("Received %s ACK for unknown sequence number", which)
		return
	}
	apply(pp.meas)
	result := p.finalizeIfCompleteLocked(seqNum, pp)
	p.pendingMu.Unlock()

	fields(p.logger.Debug().Uint64("seq", seqNum)).Msgf("%s ACK received", which)

	if result != nil {
		p.deliverResult(seqNum, pp.target, result)
	}
}

// finalizeIfCompleteLocked builds the ProbeResult and removes the pending
// entry once both ACKs have arrived; nil while still waiting. Caller holds
// pendingMu.
func (p *Prober) finalizeIfCompleteLocked(seqNum uint64, pp *pendingProbe) *probe.ProbeResult {
	if !pp.meas.Complete() {
		return nil
	}
	result := pp.meas.Result()
	fillTargetMetadata(&result, seqNum, pp.flowLabel, pp.target)
	result.Success = true
	delete(p.pending, seqNum)
	return &result
}

// fillTargetMetadata copies the sequence number, the flow label actually
// used, and the target's identity into result. Shared by the success,
// send-failure and timeout paths so they carry the same fields.
func fillTargetMetadata(result *probe.ProbeResult, seqNum uint64, flowLabel uint32, target *controller_agent.PingTarget) {
	result.SequenceNum = seqNum
	result.TargetQPN = target.GetTargetQpn()
	result.FlowLabel = flowLabel
	result.TargetIP = target.GetTargetIp()
	result.TargetHostname = target.GetTargetHostname()
	result.TargetTorID = target.GetTargetTorId()
	result.TargetRdmaDevice = target.GetTargetDeviceName()
	result.TargetNetdev = target.GetTargetNetdev()
	// An older controller never sets Sampled, but every inter-ToR target is
	// sampled.
	result.TargetSampled = target.GetSampled() || isInterTor(target)
	result.ServiceTracing = target.GetPinglistType() == controller_agent.PinglistType_SERVICE_TRACING
	if parsedGID, err := probe.ParseGID(target.GetTargetGid()); err == nil {
		result.TargetGID = parsedGID
	}
}

// newFailedResult builds a Success=false ProbeResult for a probe whose send
// failed outright.
func newFailedResult(seqNum uint64, target *controller_agent.PingTarget, flowLabel uint32, reason probe.FailureReason, errMsg string) *probe.ProbeResult {
	result := &probe.ProbeResult{}
	fillTargetMetadata(result, seqNum, flowLabel, target)
	result.FailureReason = reason
	result.ErrorMessage = errMsg
	return result
}

// SetSourceTorID records the ToR of the prober's device (canonical form;
// empty means untagged). Call it before Start.
func (p *Prober) SetSourceTorID(torID string) {
	p.sourceTorLabel = probe.TorMetricLabel(torID)
}

// SetSourceNetdev records the netdev bound to the prober's device port/GID
// (empty when unresolved). Call it before Start.
func (p *Prober) SetSourceNetdev(netdev string) {
	p.sourceNetdev = netdev
}

// emitResult stamps the source RNIC onto result and delivers it without
// blocking: a full channel drops the result with a warning, so a slow
// consumer cannot stall the probe or ACK loops.
func (p *Prober) emitResult(result *probe.ProbeResult) {
	result.SourceGID = p.sourceGID
	if p.sourceTorLabel != "" {
		result.SourceTorID = p.sourceTorLabel
	}
	result.SourceRdmaDevice = p.sourceRdmaDevice
	result.SourceNetdev = p.sourceNetdev
	select {
	case p.resultChan <- result:
	default:
		p.logger.Warn().
			Uint64("seq", result.SequenceNum).
			Msg("Result channel full, dropping probe result")
	}
}

// deliverResult logs a completed probe and emits it. Called without
// pendingMu so a slow consumer cannot stall ACK processing under the lock.
func (p *Prober) deliverResult(seqNum uint64, target *controller_agent.PingTarget, result *probe.ProbeResult) {
	// Both ACKs arrived, so the target's QPN is live whether or not the RTT
	// validates.
	p.recordTargetOutcome(target, false)

	if e := p.logger.Debug(); e.Enabled() {
		rtt := probe.CalculateRTT(result)
		e.Uint64("seq", seqNum).
			Str("target_gid", target.GetTargetGid()).
			Uint64("t1", result.T1).
			Uint64("t2", result.T2).
			Uint64("t3", result.T3).
			Uint64("t4", result.T4).
			Uint64("t5", result.T5).
			Uint64("t6", result.T6).
			Bool("rtt_valid", rtt.Valid).
			Int64("network_rtt_ns", rtt.NetworkRTT).
			Int64("responder_delay_ns", rtt.ResponderDelay).
			Int64("prober_delay_ns", rtt.ProberDelay).
			Msg("Probe completed with all 6 timestamps")
	}

	p.emitResult(result)
}

// cleanupStalePending expires pending probes older than stalePendingTimeout,
// emitting each as a failed result so lost ACKs show up in probe_failed_total
// instead of vanishing.
func (p *Prober) cleanupStalePending() {
	now := time.Now()
	var stale []*probe.ProbeResult
	var staleTargets []*controller_agent.PingTarget

	p.pendingMu.Lock()
	for seqNum, pp := range p.pending {
		if now.Sub(pp.createdAt) > stalePendingTimeout {
			// Keep any partial timestamps the measurement collected.
			result := pp.meas.Result()
			fillTargetMetadata(&result, seqNum, pp.flowLabel, pp.target)
			result.FailureReason = probe.FailureTimeout
			result.ErrorMessage = "timed out waiting for ACKs"
			stale = append(stale, &result)
			staleTargets = append(staleTargets, pp.target)
			delete(p.pending, seqNum)
		}
	}
	p.pendingMu.Unlock()

	for _, result := range stale {
		p.emitResult(result)
	}
	for _, target := range staleTargets {
		p.recordTargetOutcome(target, true)
	}
	if len(stale) > 0 {
		p.logger.Info().
			Int("cleaned", len(stale)).
			Msg("Expired stale pending probes emitted as failures")
	}
}

// Destroy stops the prober and destroys its RDMA queue. resultChan is closed
// once every producer goroutine has exited, so range loops over Results()
// finish cleanly.
func (p *Prober) Destroy() {
	p.Stop()
	p.destroyOnce.Do(func() {
		close(p.resultChan)
		p.destroyQueue()
		p.logger.Info().Msg("Prober destroyed")
	})
}
