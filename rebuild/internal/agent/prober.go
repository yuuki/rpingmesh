// Package agent implements the R-Pingmesh agent, including the Prober
// that sends probe packets to targets and processes ACK responses to
// compute 6-timestamp RTT measurements.
package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"golang.org/x/sys/unix"
)

// Default constants for the Prober.
const (
	// probeSendTimeoutMS is the timeout in milliseconds for sending a single
	// probe packet and waiting for its send completion.
	probeSendTimeoutMS = 1000

	// resultChanSize is the buffer size for the probe results channel.
	resultChanSize = 1024

	// stalePendingTimeout is the duration after which a pending probe entry
	// is considered stale and eligible for cleanup.
	stalePendingTimeout = 30 * time.Second

	// stalePendingCleanupPeriod is the wall-clock interval between stale-pending
	// sweeps. Using elapsed time (rather than a tick count) decouples cleanup
	// cadence from the probe interval, so the sweep runs at a predictable rate
	// regardless of how frequently probes are sent.
	stalePendingCleanupPeriod = 10 * time.Second

	// defaultFlowLabelRotationPeriodSec is the fallback rotation period used
	// when SetFlowLabelRotationPeriod has not been called (or is set to 0). It
	// mirrors config.DefaultFlowLabelRotationPeriodSec without importing the
	// config package.
	defaultFlowLabelRotationPeriodSec = 3600

	// flowLabelRotateStride controls which flow-label indices rotate with the
	// epoch: every flowLabelRotateStride-th label (indices 0, 5, 10, ...) mixes
	// the rotation epoch into its hash, so ~1/5 (20%) of a target's label set
	// shifts each rotation period while the remaining ~80% stay stable for
	// time-series continuity. This matches the R-Pingmesh paper's ~20%
	// 5-tuple rotation.
	flowLabelRotateStride = 5

	// flowLabelMask is the 20-bit IPv6 flow-label field width; generated labels
	// are masked to it before reaching ibv_ah_attr.grh.flow_label.
	flowLabelMask = 0xFFFFF

	// maxDistinctFlowLabels is the operational hard clamp on how many labels a
	// target's set may contain. generateFlowLabels clamps FlowLabelCount to it
	// so a bad or malicious controller value can never make the agent build a
	// huge label set/map (stalling the send loop or OOMing) nor spin the dedup
	// loop forever. 4096 is ~16KB per target and covers even extreme Eq.(1)
	// configs; it mirrors config.MaxEcmpFlowLabels (defense in depth). The
	// 20-bit flow-label field's 2^20 distinct-value ceiling is the secondary,
	// far higher bound this stays well under.
	maxDistinctFlowLabels = 4096
)

// clampDistinctFlowLabelCount bounds a requested flow-label count to the number
// of distinct 20-bit labels that can exist (maxDistinctFlowLabels). Extracted
// so the clamp decision is unit-testable without generating a huge label set.
func clampDistinctFlowLabelCount(count uint32) uint32 {
	if count > maxDistinctFlowLabels {
		return maxDistinctFlowLabels
	}
	return count
}

// flowLabelAt deterministically derives a candidate ECMP flow label for label
// index within a target's set, from the controller-provided seed and (for the
// rotating subset of indices) the current rotationEpoch. It is pure: the same
// (seed, index, rotationEpoch, attempt) always yields the same 20-bit label,
// which is what makes the set reproducible across agents and testable.
//
// Only indices that are multiples of flowLabelRotateStride fold in the epoch;
// all other indices ignore it and are therefore stable across epochs. The
// attempt parameter is a collision-resolution nonce: attempt 0 is the primary
// candidate (its bytes are omitted so the value is unchanged from a plain
// hash), and generateFlowLabels advances it only when a candidate collides
// with an already-chosen label.
func flowLabelAt(seed, index uint32, rotationEpoch uint64, attempt uint32) uint32 {
	h := fnv.New32a()
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[0:4], seed)
	binary.BigEndian.PutUint32(buf[4:8], index)
	n := 8
	if index%flowLabelRotateStride == 0 {
		binary.BigEndian.PutUint64(buf[8:16], rotationEpoch)
		n = 16
	}
	_, _ = h.Write(buf[:n])
	if attempt > 0 {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], attempt)
		_, _ = h.Write(a[:])
	}
	return h.Sum32() & flowLabelMask
}

// generateFlowLabels expands a (seed, count) pair into exactly count DISTINCT
// deterministic 20-bit flow labels for the given rotationEpoch. A count of 0 is
// treated as 1 so every target yields at least one label.
//
// Distinctness matters: the controller sizes count via Eq.(1) assuming n
// distinct labels, so a duplicate would silently explore fewer ECMP 5-tuples
// than the configured coverage probability requires. Masking a 32-bit hash to
// 20 bits can collide, so each label is chosen by a set-guarded loop that
// advances a collision nonce (flowLabelAt's attempt) until the candidate is
// new. Termination is fast and guaranteed: the controller caps count well
// below the 2^20 label space (default cap 64), so collisions are rare and each
// slot resolves in ~1 attempt.
//
// Slots are resolved in two passes -- stable slots (index % stride != 0)
// first, then rotating slots -- so a stable slot's dedup never depends on the
// epoch-varying rotating slots. This keeps the ~80% stable subset byte-for-byte
// identical across epochs (exact time-series continuity, not merely likely)
// while the rotating subset still shifts each epoch. Dedup is applied after the
// epoch is mixed in, so the final set is distinct for every epoch.
func generateFlowLabels(seed, count uint32, rotationEpoch uint64) []uint32 {
	if count == 0 {
		count = 1
	}
	// Never ask for more distinct labels than the 20-bit space can hold, or the
	// dedup loop below could never satisfy the request and would spin forever.
	count = clampDistinctFlowLabelCount(count)
	labels := make([]uint32, count)
	used := make(map[uint32]struct{}, count)

	assign := func(i uint32) {
		for attempt := uint32(0); ; attempt++ {
			v := flowLabelAt(seed, i, rotationEpoch, attempt)
			if _, dup := used[v]; !dup {
				used[v] = struct{}{}
				labels[i] = v
				return
			}
		}
	}

	// Pass 1: stable slots (epoch-independent dedup domain).
	for i := uint32(0); i < count; i++ {
		if i%flowLabelRotateStride != 0 {
			assign(i)
		}
	}
	// Pass 2: rotating slots (epoch-mixed, dedup against the full set).
	for i := uint32(0); i < count; i++ {
		if i%flowLabelRotateStride == 0 {
			assign(i)
		}
	}
	return labels
}

// labelsForTarget returns the flow-label set the prober cycles through for a
// target. When FlowLabelCount <= 1 it preserves exact legacy behavior by
// returning the single controller-provided FlowLabel; otherwise it expands
// FlowLabelSeed + FlowLabelCount for the given epoch.
func labelsForTarget(target *controller_agent.PingTarget, rotationEpoch uint64) []uint32 {
	if target.GetFlowLabelCount() <= 1 {
		return []uint32{target.GetFlowLabel()}
	}
	return generateFlowLabels(target.GetFlowLabelSeed(), target.GetFlowLabelCount(), rotationEpoch)
}

// pendingProbe holds the in-flight state for a single probe awaiting ACKs.
// The 6-timestamp bookkeeping lives in the embedded PendingMeasurement, which
// accepts the two ACKs in either arrival order.
type pendingProbe struct {
	target    *controller_agent.PingTarget
	meas      *probe.PendingMeasurement
	createdAt time.Time
	// flowLabel is the concrete ECMP flow label this probe was actually sent
	// with (one of the target's rotating set), recorded so the resulting
	// ProbeResult and debug logs report the path actually exercised rather
	// than the target's base label.
	flowLabel uint32
}

// Prober sends probe packets to targets on a configurable interval,
// processes first and second ACK responses via its event ring, and
// produces ProbeResult values on a buffered channel.
type Prober struct {
	queue  *rdmabridge.Queue
	ring   *rdmabridge.EventRing
	device *rdmabridge.Device
	// sourceGID is the parsed 16-byte GID of the bound device, stamped onto
	// every emitted ProbeResult so the per-path aggregator can key results by
	// (source, target). Parsed once at construction; zero if the device GID is
	// unparseable or the Prober was built without a device (test fakes).
	sourceGID     [16]byte
	targets       []*controller_agent.PingTarget
	targetsMu     sync.RWMutex
	pending       map[uint64]*pendingProbe // sequence_num -> pending probe info
	pendingMu     sync.Mutex
	seqCounter    atomic.Uint64
	agentEpoch    uint32 // Random epoch prefix for sequence number collision prevention
	resultChan    chan *probe.ProbeResult
	running       atomic.Bool
	stopMu        sync.Mutex    // guards stopCh (re)creation across Start/Stop
	stopCh        chan struct{} // closed by Stop() to wake goroutines immediately
	wg            sync.WaitGroup
	probeInterval time.Duration
	probeTimeout  uint32 // ms

	// queueMu guards access to the queue pointer so that GetQueueInfo cannot
	// race with Destroy() setting queue to nil.
	queueMu sync.RWMutex

	// destroyOnce makes Destroy() idempotent: closing resultChan and tearing
	// down the queue must happen exactly once even if Destroy is called
	// multiple times (e.g. Agent.Stop after a partial start), otherwise the
	// second close(resultChan) panics.
	destroyOnce sync.Once

	// rateMu guards the per-pinglist-type send-rate limiters, which
	// SetPerTypeRateLimit / SetPerTargetRateLimit may update from a different
	// goroutine than the probe loop. Lock order: targetsMu -> rateMu.
	//
	// There is one limiter per pinglist type (ToR-mesh, inter-ToR) so the two
	// types can be capped at independent per-target rates (R-Pingmesh probes
	// ToR-mesh more aggressively than inter-ToR). Each limiter's aggregate rate
	// is pps * (number of targets of that type), recomputed on every
	// UpdateTargets so the configured per-target cadence survives pinglist
	// churn -- exactly as the single aggregate limiter did before, but scoped
	// per type. sendProbes selects the limiter matching each target's
	// PinglistType.
	rateMu       sync.Mutex
	torMeshRate  perTypeRate
	interTorRate perTypeRate

	// rateMultiplier is the self-protection throttle factor in (0, 1] applied
	// on top of both per-type aggregate rates: the effective limiter rate is
	// pps * (targets of that type) * rateMultiplier. It is guarded by rateMu
	// and set by the Watchdog via SetRateMultiplier when local CPU/memory
	// pressure warrants slowing probing (fail-slow), and restored toward 1.0 on
	// recovery. A non-positive value (the zero value of a struct-literal Prober,
	// or an unset throttle) is treated as 1.0 by scaledRate, so throttling is
	// strictly opt-in and can never silently disable a limiter. It never reaches
	// 0: the Watchdog floors it at minThrottleMultiplier so probing degrades but
	// never stops (no fail-closed monitoring hole).
	rateMultiplier float64

	// flowLabelRotationPeriodSec is the period over which the rotating subset
	// of each target's flow-label set is refreshed. Read only by the probe-loop
	// goroutine via flowLabelRotationEpoch; set once at construction and
	// optionally via SetFlowLabelRotationPeriod before Start.
	flowLabelRotationPeriodSec uint32

	// labelRotation tracks the next flow-label index for each target, keyed by
	// target GID string, so successive probes to a target use successive labels
	// (round-robin over its set). It is accessed ONLY from the probe-loop
	// goroutine (sendProbes), so it needs no lock; stale keys are pruned there.
	labelRotation map[string]uint32

	// labelCache memoizes each target's generated flow-label set so it is built
	// once per (epoch, seed, count) rather than on every probe tick. Same GID
	// key, same goroutine confinement, and pruned alongside labelRotation.
	labelCache map[string]*labelSet

	logger zerolog.Logger
}

// perTypeRate couples the configured per-target probe rate (pps) for one
// pinglist type with the aggregate RateLimiter that enforces it. The limiter's
// rate is pps * (number of targets of that type); pps is retained so
// UpdateTargets can recompute the aggregate rate when the pinglist size
// changes. The zero value is a disabled limiter (pps 0), which is what a
// struct-literal Prober in tests starts with.
type perTypeRate struct {
	pps     float64
	limiter probe.RateLimiter
}

// labelSet is a cached flow-label set plus the inputs that produced it, so the
// prober can detect when a rotation-epoch or target seed/count change makes the
// cached labels stale and must be regenerated.
type labelSet struct {
	epoch  uint64
	seed   uint32
	count  uint32
	labels []uint32
}

// NewProber creates a new Prober with a sender-type RDMA queue bound to the
// given device and event ring. The probeIntervalMS parameter controls how
// frequently probe packets are sent to all targets.
//
// A random agentEpoch is generated so that sequence numbers from different
// agent lifetimes do not collide: the high 32 bits of each sequence number
// contain the epoch, and the low 32 bits are a monotonic counter.
func NewProber(device *rdmabridge.Device, ring *rdmabridge.EventRing, probeIntervalMS uint32) (*Prober, error) {
	// A zero interval would make probeLoop call time.NewTicker(0), which panics.
	// Reject it here rather than at Start time so the misconfiguration surfaces
	// during construction. (The signature already returns an error.)
	if probeIntervalMS == 0 {
		return nil, fmt.Errorf("probeIntervalMS must be greater than 0")
	}

	queue, err := device.CreateQueue(rdmabridge.QueueTypeSender, ring)
	if err != nil {
		return nil, err
	}

	// Parse the device GID once so every emitted result can carry its source
	// without re-parsing. Best-effort: a parse failure leaves sourceGID zero,
	// which only means such results are not path-aggregated.
	var sourceGID [16]byte
	if gid, err := probe.ParseGID(device.Info.GID); err == nil {
		sourceGID = gid
	}

	p := &Prober{
		queue:                      queue,
		ring:                       ring,
		device:                     device,
		sourceGID:                  sourceGID,
		pending:                    make(map[uint64]*pendingProbe),
		agentEpoch:                 rand.Uint32(),
		resultChan:                 make(chan *probe.ProbeResult, resultChanSize),
		stopCh:                     make(chan struct{}),
		rateMultiplier:             1.0, // unthrottled until the Watchdog engages
		probeInterval:              time.Duration(probeIntervalMS) * time.Millisecond,
		probeTimeout:               probeSendTimeoutMS,
		flowLabelRotationPeriodSec: defaultFlowLabelRotationPeriodSec,
		labelRotation:              make(map[string]uint32),
		labelCache:                 make(map[string]*labelSet),
		logger:                     log.With().Str("component", "prober").Logger(),
	}

	p.logger.Info().
		Uint32("qpn", queue.Info.QPN).
		Uint32("agent_epoch", p.agentEpoch).
		Uint32("probe_interval_ms", probeIntervalMS).
		Msg("Prober created")

	return p, nil
}

// Start begins the prober's two background goroutines:
//   - probeLoop: sends probes to all targets on the configured interval
//   - ackProcessLoop: polls the event ring for ACK completions
//
// Both goroutines run until Stop() is called or the context is cancelled.
func (p *Prober) Start(ctx context.Context) error {
	if !p.running.CompareAndSwap(false, true) {
		return nil // already running
	}

	// Recreate stopCh so a prober can be started again after a previous Stop()
	// closed it. Stop() has already waited for the old goroutines to exit
	// (running is false here), so no goroutine references the old channel.
	p.stopMu.Lock()
	p.stopCh = make(chan struct{})
	p.stopMu.Unlock()

	p.wg.Add(2)
	go p.probeLoop(ctx)
	go p.ackProcessLoop(ctx)

	p.logger.Info().
		Uint32("qpn", p.queue.Info.QPN).
		Msg("Prober started")
	return nil
}

// Stop signals both background goroutines to exit and waits for them
// to finish. It is safe to call Stop multiple times. Closing stopCh
// wakes goroutines immediately instead of waiting for the next ticker
// or sleep to fire.
func (p *Prober) Stop() {
	if !p.running.CompareAndSwap(true, false) {
		return // not running
	}
	p.stopMu.Lock()
	close(p.stopCh)
	p.stopMu.Unlock()
	p.wg.Wait()
	p.logger.Info().Msg("Prober stopped")
}

// SetPerTargetRateLimit caps the probe send rate to at most pps packets per
// second per target, applying the SAME cap to both pinglist types. It is the
// backward-compatible single-rate entry point (differentiated rates go through
// SetPerTypeRateLimit). Each type's aggregate limiter rate is recomputed as
// pps * (targets of that type) here and on every UpdateTargets call, so the
// configured per-target cadence is preserved as the pinglist grows or shrinks.
// A non-positive pps disables rate limiting. Safe to call while running.
func (p *Prober) SetPerTargetRateLimit(pps float64) {
	p.SetPerTypeRateLimit(pps, pps)
}

// SetPerTypeRateLimit caps the probe send rate per target at torMeshPPS for
// ToR-mesh targets and interTorPPS for inter-ToR targets, independently. Each
// type's aggregate limiter is set to pps * (number of targets of that type) so
// the per-target cadence is preserved as the pinglist changes; a non-positive
// pps disables limiting for that type. Safe to call while running.
func (p *Prober) SetPerTypeRateLimit(torMeshPPS, interTorPPS float64) {
	// Hold targetsMu across the whole rate update, taking rateMu nested. This
	// matches UpdateTargets' lock order (targetsMu -> rateMu) and closes a
	// TOCTOU window: reading the per-type target counts and recomputing the
	// aggregate rates must be atomic w.r.t. a concurrent UpdateTargets,
	// otherwise the two could interleave and leave a limiter with a rate
	// computed from a stale count.
	p.targetsMu.RLock()
	defer p.targetsMu.RUnlock()
	nTorMesh, nInterTor := countTargetsByType(p.targets)

	p.rateMu.Lock()
	p.torMeshRate.pps = torMeshPPS
	p.torMeshRate.limiter.SetRate(scaledRate(torMeshPPS, nTorMesh, p.rateMultiplier))
	p.interTorRate.pps = interTorPPS
	p.interTorRate.limiter.SetRate(scaledRate(interTorPPS, nInterTor, p.rateMultiplier))
	p.rateMu.Unlock()

	p.logger.Info().
		Float64("tor_mesh_pps", torMeshPPS).
		Int("tor_mesh_targets", nTorMesh).
		Float64("inter_tor_pps", interTorPPS).
		Int("inter_tor_targets", nInterTor).
		Msg("Probe send rate limits updated")
}

// SetRateMultiplier scales BOTH per-type aggregate send rates by mult, the
// self-protection throttle factor. It is the single integration point between
// the Watchdog and the send path: the Watchdog calls it to slow probing when
// local CPU/memory pressure rises (fail-slow) and to restore it on recovery.
// mult is clamped to (0, 1] (out-of-range values map to 1.0 = unthrottled), so
// the multiplier can only reduce, never amplify, the configured per-target
// cadence, and can never fully stop probing.
//
// It intentionally reuses the SetPerTypeRateLimit lock order (targetsMu ->
// rateMu): the per-type target counts are read under targetsMu and the limiter
// rates recomputed under rateMu, so a concurrent UpdateTargets or
// SetPerTypeRateLimit can neither race the read nor leave a limiter scaled from
// a stale count. Because the stored multiplier is applied by every subsequent
// UpdateTargets/SetPerTypeRateLimit too, a pinglist change while throttled
// preserves the throttle. Safe to call while running.
func (p *Prober) SetRateMultiplier(mult float64) {
	mult = clampRateMultiplier(mult)

	p.targetsMu.RLock()
	defer p.targetsMu.RUnlock()
	nTorMesh, nInterTor := countTargetsByType(p.targets)

	p.rateMu.Lock()
	p.rateMultiplier = mult
	p.torMeshRate.limiter.SetRate(scaledRate(p.torMeshRate.pps, nTorMesh, mult))
	p.interTorRate.limiter.SetRate(scaledRate(p.interTorRate.pps, nInterTor, mult))
	p.rateMu.Unlock()

	p.logger.Debug().
		Float64("rate_multiplier", mult).
		Msg("Probe send rate multiplier updated")
}

// clampRateMultiplier bounds a throttle multiplier to (0, 1]. Any value <= 0 or
// > 1 is nonsensical for a factor that may only slow probing, so it maps to 1.0
// (unthrottled) -- the safe default that keeps monitoring at full rate rather
// than risking a stall from a bad input.
func clampRateMultiplier(mult float64) float64 {
	if mult <= 0 || mult > 1 {
		return 1.0
	}
	return mult
}

// scaledRate computes a pinglist type's aggregate limiter rate: the per-target
// pps times the number of targets of that type, scaled by the self-protection
// throttle multiplier. A non-positive multiplier (the zero value of a
// struct-literal Prober, or an unset throttle) is treated as 1.0 so throttling
// is opt-in and never silently disables the limiter; multiplying by an exact
// 1.0 is bit-identical to the un-throttled pps*n, so unthrottled behavior is
// unchanged. A pps of 0 yields 0, which RateLimiter.SetRate reads as disabled.
func scaledRate(pps float64, n int, mult float64) float64 {
	if mult <= 0 {
		mult = 1.0
	}
	return pps * float64(n) * mult
}

// countTargetsByType counts how many targets belong to each pinglist type. A
// nil target and any type other than INTER_TOR count as ToR-mesh, which also
// makes the (proto3-default) zero PinglistType read as TOR_MESH -- the
// backward-compatible reading of targets from a controller that never stamped
// the field.
func countTargetsByType(targets []*controller_agent.PingTarget) (nTorMesh, nInterTor int) {
	for _, t := range targets {
		if t == nil {
			continue
		}
		if t.GetPinglistType() == controller_agent.PinglistType_INTER_TOR {
			nInterTor++
		} else {
			nTorMesh++
		}
	}
	return nTorMesh, nInterTor
}

// rateForType returns the limiter state governing the given pinglist type.
// INTER_TOR maps to the inter-ToR limiter; everything else (TOR_MESH and the
// proto3 default) maps to the ToR-mesh limiter. Callers must hold rateMu.
func (p *Prober) rateForType(ptype controller_agent.PinglistType) *perTypeRate {
	if ptype == controller_agent.PinglistType_INTER_TOR {
		return &p.interTorRate
	}
	return &p.torMeshRate
}

// SetFlowLabelRotationPeriod sets the period over which the rotating subset of
// each target's ECMP flow-label set is refreshed. A non-positive value keeps
// the default (defaultFlowLabelRotationPeriodSec). It should be called before
// Start; the field is read only by the single probe-loop goroutine.
func (p *Prober) SetFlowLabelRotationPeriod(sec uint32) {
	if sec == 0 {
		sec = defaultFlowLabelRotationPeriodSec
	}
	p.flowLabelRotationPeriodSec = sec
	p.logger.Info().
		Uint32("rotation_period_sec", sec).
		Msg("Flow-label rotation period updated")
}

// flowLabelRotationEpoch maps a wall-clock instant to the current rotation
// epoch = floor(unixTime / period). Wall-clock is acceptable here because the
// epoch only selects which flow labels are used, never a measurement timestamp.
func (p *Prober) flowLabelRotationEpoch(now time.Time) uint64 {
	period := p.flowLabelRotationPeriodSec
	if period == 0 {
		period = defaultFlowLabelRotationPeriodSec
	}
	return uint64(now.Unix()) / uint64(period)
}

// nowMonotonicNS returns the current CLOCK_MONOTONIC time in nanoseconds. It
// must be used for T6 instead of time.Now().UnixNano() (a wall-clock reading)
// so that ProberDelay = (T6-T1) - (T5-T2) is arithmetically sound in both
// timestamp modes:
//
//   - SW fallback: T1, T2, T5 are all CLOCK_MONOTONIC on the prober host, and
//     T6 now matches that domain, so every term shares one clock.
//   - HW timestamps: T2 and T5 are NIC wall-clock timestamps, but only their
//     difference (T5-T2) is used, which is self-consistent within the NIC
//     clock. T1 and T6 are the host CLOCK_MONOTONIC pair whose difference
//     (T6-T1) is likewise self-consistent. Subtracting the two durations is
//     valid because both clocks advance at ~1 ns/ns. Using a wall-clock T6
//     here would instead make (T6-T1) a cross-domain difference and corrupt
//     ProberDelay.
func nowMonotonicNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// clock_gettime(CLOCK_MONOTONIC) does not fail in practice on Linux;
		// fall back to the process-monotonic reading embedded in time.Now to
		// avoid returning zero, which the RTT validator would reject.
		return uint64(time.Now().UnixNano())
	}
	return uint64(ts.Nano())
}

// UpdateTargets replaces the current list of probe targets. This is called
// when the agent receives an updated pinglist from the controller.
func (p *Prober) UpdateTargets(targets []*controller_agent.PingTarget) {
	p.targetsMu.Lock()
	defer p.targetsMu.Unlock()
	p.targets = targets

	// Keep each type's aggregate limiter in sync with its per-target rate so the
	// per-target cadence survives pinglist size changes (a type whose count
	// shrinks must slow its aggregate, and vice versa). Lock order is always
	// targetsMu -> rateMu.
	nTorMesh, nInterTor := countTargetsByType(targets)
	p.rateMu.Lock()
	if p.torMeshRate.pps > 0 {
		p.torMeshRate.limiter.SetRate(scaledRate(p.torMeshRate.pps, nTorMesh, p.rateMultiplier))
	}
	if p.interTorRate.pps > 0 {
		p.interTorRate.limiter.SetRate(scaledRate(p.interTorRate.pps, nInterTor, p.rateMultiplier))
	}
	p.rateMu.Unlock()

	p.logger.Info().
		Int("count", len(targets)).
		Int("tor_mesh_count", nTorMesh).
		Int("inter_tor_count", nInterTor).
		Msg("Probe targets updated")
}

// Results returns a read-only channel that delivers completed probe results
// for consumption by the telemetry/metrics layer.
func (p *Prober) Results() <-chan *probe.ProbeResult {
	return p.resultChan
}

// probeLoop runs on a ticker at probeInterval, sending one probe packet
// to each target on every tick. It also periodically cleans up stale
// pending probes that never received their ACK responses.
func (p *Prober) probeLoop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.probeInterval)
	defer ticker.Stop()

	lastCleanup := time.Now()

	p.logger.Info().
		Dur("interval", p.probeInterval).
		Msg("Probe loop started")

	for p.running.Load() {
		select {
		case <-ctx.Done():
			p.running.Store(false)
			return
		case <-p.stopCh:
			// Stop() was called; exit immediately without waiting for
			// the next ticker fire, which could be up to probeInterval away.
			return
		case <-ticker.C:
			p.sendProbes(ctx)

			// Clean up stale pending probes on a wall-clock cadence so the
			// sweep frequency does not depend on the probe interval.
			if time.Since(lastCleanup) >= stalePendingCleanupPeriod {
				p.cleanupStalePending()
				lastCleanup = time.Now()
			}
		}
	}
}

// sendProbes reads the current target list and sends one probe to each target.
// It checks for shutdown (ctx cancellation or Stop) before each target so that
// Stop() is not blocked for up to probeSendTimeoutMS * len(targets); each
// SendProbe can block for up to probeSendTimeoutMS, so without these checks a
// large target list could delay shutdown by many seconds.
func (p *Prober) sendProbes(ctx context.Context) {
	p.targetsMu.RLock()
	targets := make([]*controller_agent.PingTarget, len(p.targets))
	copy(targets, p.targets)
	p.targetsMu.RUnlock()

	if len(targets) == 0 {
		return
	}

	// The rotation epoch selects which of each target's rotating labels are in
	// effect this round; computed once per round so all targets share it.
	rotationEpoch := p.flowLabelRotationEpoch(time.Now())

	// Prune round-robin state for targets no longer in the pinglist so the map
	// cannot grow without bound as targets churn. Confined to this goroutine.
	p.pruneLabelRotation(targets)

	for _, target := range targets {
		// Abort the batch promptly on shutdown instead of walking the entire
		// target list while blocking on SendProbe for each one.
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
		}

		if target == nil {
			continue
		}

		// Apply the optional send-rate limit for this target's pinglist type,
		// spacing sends across targets of the same type. The wait is
		// interruptible so Stop() is not delayed by the limiter.
		if !p.rateLimitWait(ctx, target.GetPinglistType()) {
			return
		}

		// Generate a globally-unique sequence number:
		// high 32 bits = random agent epoch, low 32 bits = monotonic counter.
		counter := uint64(p.seqCounter.Add(1))
		seqNum := (uint64(p.agentEpoch) << 32) | (counter & 0xFFFFFFFF)

		// Parse the target GID string into a [16]byte for the RDMA layer. Do
		// this BEFORE registering the pending entry so a malformed target never
		// leaves an orphaned entry behind.
		targetGID, err := probe.ParseGID(target.GetTargetGid())
		if err != nil {
			p.logger.Error().Err(err).
				Str("target_gid", target.GetTargetGid()).
				Uint64("seq", seqNum).
				Msg("Failed to parse target GID, skipping target")
			continue
		}

		// Pick the flow label for this probe: round-robin across the target's
		// ECMP label set so successive probes to a target exercise successive
		// paths. Labels share the target's probe budget (the rate limiter is
		// per-target, unaffected by the set size), trading coverage speed for
		// bounded probe amplification.
		flowLabel := p.nextFlowLabel(target, rotationEpoch)

		// Register the pending entry BEFORE sending. SendProbe blocks until the
		// send completion (T2), and on a low-latency RNIC an ACK can reach
		// ackProcessLoop before SendProbe returns. Registering first guarantees
		// the ACK handlers find the entry instead of dropping the ACK as an
		// "unknown sequence number" and letting the probe falsely time out. The
		// send-side timestamps are applied after the send via ApplySend, and
		// Complete() requires them, so the ACK handlers cannot finalize (and
		// delete) the entry before this send path records T1/T2.
		pp := &pendingProbe{
			target:    target,
			meas:      probe.NewPendingMeasurement(),
			createdAt: time.Now(),
			flowLabel: flowLabel,
		}
		p.pendingMu.Lock()
		p.pending[seqNum] = pp
		p.pendingMu.Unlock()

		// Send the probe packet. SendProbe is synchronous: it posts the
		// packet and waits for the send completion within the timeout. The
		// per-send flow label reaches ibv_ah_attr.grh.flow_label via a fresh
		// AH created in the Zig bridge, so no per-QP/AH state needs updating.
		result := p.queue.SendProbe(
			targetGID,
			target.GetTargetQpn(),
			seqNum,
			flowLabel,
			p.probeTimeout,
		)

		if result.Error != nil {
			// The send failed, so no ACK will ever complete this probe. Remove
			// the pending entry and emit a failed result so the loss is counted
			// in probe_failed_total rather than vanishing until the stale sweep.
			p.pendingMu.Lock()
			delete(p.pending, seqNum)
			p.pendingMu.Unlock()

			p.logger.Error().Err(result.Error).
				Str("target_gid", target.GetTargetGid()).
				Uint32("target_qpn", target.GetTargetQpn()).
				Uint64("seq", seqNum).
				Uint32("flow_label", flowLabel).
				Msg("Failed to send probe packet")
			p.emitResult(newFailedResult(seqNum, target, flowLabel, fmt.Sprintf("probe send failed: %v", result.Error)))
			continue
		}

		// Apply the send-side timestamps T1/T2 now that the send completed. If
		// both ACKs already arrived while the send was in progress, this is the
		// call that finally completes the measurement; finalize it here rather
		// than losing it.
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
}

// nextFlowLabel returns the flow label to use for the next probe to target and
// advances that target's round-robin index. It is called only from the
// probe-loop goroutine, so the unsynchronized map accesses are safe.
func (p *Prober) nextFlowLabel(target *controller_agent.PingTarget, rotationEpoch uint64) uint32 {
	if p.labelRotation == nil {
		// Defensive: a Prober built via a struct literal (test helpers) rather
		// than NewProber may have nil maps. Lazily initialize so the single
		// probe-loop goroutine never panics writing to them.
		p.labelRotation = make(map[string]uint32)
	}
	labels := p.cachedLabelsForTarget(target, rotationEpoch)
	gid := target.GetTargetGid()
	idx := p.labelRotation[gid]
	p.labelRotation[gid] = idx + 1
	return labels[idx%uint32(len(labels))]
}

// cachedLabelsForTarget returns the target's flow-label set, regenerating it
// only when the rotation epoch or the target's seed/count changes. Without this
// cache, generateFlowLabels would rebuild a (potentially thousands-entry) set
// on every probe tick for every target, stalling the send loop. The multi-label
// set is expensive to build; the legacy single-label case is trivial and
// bypasses the cache. Called only from the probe-loop goroutine, so the
// unsynchronized map access is safe.
func (p *Prober) cachedLabelsForTarget(target *controller_agent.PingTarget, rotationEpoch uint64) []uint32 {
	count := target.GetFlowLabelCount()
	if count <= 1 {
		// Trivial single-label (legacy) path; no set to cache.
		return labelsForTarget(target, rotationEpoch)
	}

	gid := target.GetTargetGid()
	seed := target.GetFlowLabelSeed()
	if p.labelCache == nil {
		p.labelCache = make(map[string]*labelSet)
	}
	if e, ok := p.labelCache[gid]; ok && e.epoch == rotationEpoch && e.seed == seed && e.count == count {
		return e.labels
	}
	labels := generateFlowLabels(seed, count, rotationEpoch)
	p.labelCache[gid] = &labelSet{epoch: rotationEpoch, seed: seed, count: count, labels: labels}
	return labels
}

// pruneLabelRotation drops per-target round-robin and label-cache entries for
// targets absent from the current pinglist, bounding both maps' sizes as
// targets churn. Called only from the probe-loop goroutine.
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

// rateLimitWait blocks for the duration required by the configured send-rate
// limit for the given pinglist type before the next probe of that type may be
// sent. It returns false if the wait was interrupted by ctx cancellation or
// Stop(), in which case the caller should abandon the current send batch. When
// rate limiting is disabled for the type it returns true immediately.
func (p *Prober) rateLimitWait(ctx context.Context, ptype controller_agent.PinglistType) bool {
	p.rateMu.Lock()
	wait := p.rateForType(ptype).limiter.Reserve(time.Now())
	p.rateMu.Unlock()

	if wait <= 0 {
		return true
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-p.stopCh:
		return false
	case <-timer.C:
		return true
	}
}

// ackProcessLoop continuously polls the event ring for ACK completion
// events and matches them against pending probes. First ACKs provide T3
// and T5; second ACKs provide T3, T4, and T6, completing the 6-timestamp
// measurement and emitting a ProbeResult.
func (p *Prober) ackProcessLoop(ctx context.Context) {
	defer p.wg.Done()

	const (
		maxBatch  = 32
		idleSleep = 100 * time.Microsecond
	)

	p.logger.Info().Msg("ACK process loop started")

	// idleTimer is reused on each empty-poll iteration to avoid allocating
	// a new timer on every spin. Reset is safe here because we always drain
	// it before calling Reset (see time.Timer documentation).
	idleTimer := time.NewTimer(idleSleep)
	defer idleTimer.Stop()

	for p.running.Load() {
		// Check for shutdown or context cancellation on every iteration,
		// even when the ring is continuously delivering events.
		select {
		case <-ctx.Done():
			p.running.Store(false)
			return
		case <-p.stopCh:
			return
		default:
		}

		events := p.ring.Poll(maxBatch)
		if len(events) == 0 {
			// No events yet; wait briefly before polling again.
			// Select on stopCh and ctx.Done() so we exit immediately
			// when Stop() is called rather than finishing the sleep.
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleSleep)
			select {
			case <-ctx.Done():
				p.running.Store(false)
				return
			case <-p.stopCh:
				// Stop() was called; exit without waiting for the idle sleep.
				return
			case <-idleTimer.C:
			}
			continue
		}

		for i := range events {
			p.handleACKEvent(&events[i])
		}
	}
}

// handleACKEvent processes a single completion event from the ring buffer.
// Only recv events that are ACKs are relevant to the prober; all other
// event types (send completions, non-ACK receives) are ignored.
func (p *Prober) handleACKEvent(event *rdmabridge.CompletionEvent) {
	// Only process recv completions that are ACKs.
	// Skip send completions and non-ACK receives.
	if event.IsSend || !event.IsAck {
		return
	}

	// Check for completion errors from the hardware.
	if event.Status != 0 {
		p.logger.Warn().
			Int32("status", event.Status).
			Uint64("seq", event.SequenceNum).
			Msg("ACK recv completion with non-zero status, skipping")
		return
	}

	seqNum := event.SequenceNum

	switch event.AckType {
	case rdmabridge.AckTypeFirst:
		p.handleFirstACK(seqNum, event)

	case rdmabridge.AckTypeSecond:
		p.handleSecondACK(seqNum, event)

	default:
		p.logger.Warn().
			Uint8("ack_type", event.AckType).
			Uint64("seq", seqNum).
			Msg("Received ACK with unknown type")
	}
}

// handleFirstACK processes a first ACK event. It records T3 (responder recv
// timestamp, authoritative from the first ACK) and T5 (prober recv timestamp
// from the NIC HW or SW timestamp on this completion). If the second ACK has
// already arrived, this completes the measurement.
func (p *Prober) handleFirstACK(seqNum uint64, event *rdmabridge.CompletionEvent) {
	p.pendingMu.Lock()
	pp, ok := p.pending[seqNum]
	if !ok {
		p.pendingMu.Unlock()
		p.logger.Warn().
			Uint64("seq", seqNum).
			Msg("Received first ACK for unknown sequence number")
		return
	}

	// T5 is the prober's recv timestamp for the first ACK, taken from the NIC
	// completion event (HW or SW timestamp). T3 is the responder recv timestamp
	// carried in the ACK payload.
	pp.meas.ApplyFirstAck(event.T3, event.TimestampNS)
	result := p.finalizeIfCompleteLocked(seqNum, pp)
	p.pendingMu.Unlock()

	p.logger.Debug().
		Uint64("seq", seqNum).
		Uint64("t3_ns", event.T3).
		Uint64("t5_ns", event.TimestampNS).
		Msg("First ACK received")

	if result != nil {
		p.deliverResult(seqNum, pp.target, result)
	}
}

// handleSecondACK processes a second ACK event, which carries T3 and T4
// (responder-side timestamps). T6 is captured on the prober host from
// CLOCK_MONOTONIC (the same clock domain as T1) because the ring buffer
// completion event does not carry a host-side timestamp for the second ACK
// arrival. If the first ACK has already arrived, this completes the
// measurement; otherwise the pending entry waits for it (out-of-order ACKs are
// supported).
func (p *Prober) handleSecondACK(seqNum uint64, event *rdmabridge.CompletionEvent) {
	// Capture T6 immediately upon processing the second ACK, using the same
	// CLOCK_MONOTONIC domain as T1 so that (T6 - T1) in ProberDelay is a valid
	// same-domain difference.
	t6 := nowMonotonicNS()

	p.pendingMu.Lock()
	pp, ok := p.pending[seqNum]
	if !ok {
		p.pendingMu.Unlock()
		p.logger.Warn().
			Uint64("seq", seqNum).
			Msg("Received second ACK for unknown sequence number")
		return
	}

	// The second ACK carries T3 and T4 in the event payload. T3 here is only
	// used if the first ACK has not yet supplied it (see PendingMeasurement).
	pp.meas.ApplySecondAck(event.T3, event.T4, t6)
	result := p.finalizeIfCompleteLocked(seqNum, pp)
	p.pendingMu.Unlock()

	p.logger.Debug().
		Uint64("seq", seqNum).
		Uint64("t4_ns", event.T4).
		Uint64("t6_ns", t6).
		Msg("Second ACK received")

	if result != nil {
		p.deliverResult(seqNum, pp.target, result)
	}
}

// finalizeIfCompleteLocked builds a ProbeResult and removes the pending entry
// once both ACKs have arrived. It returns nil while the measurement is still
// waiting for the other ACK. The caller must hold pendingMu.
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

// fillTargetMetadata copies the sequence number, the flow label actually used
// for the probe, and per-target metadata into a ProbeResult. Shared by the
// success, send-failure, and stale-timeout paths so they cannot diverge on
// which fields a result carries. The flow label is passed explicitly (rather
// than read from target.GetFlowLabel()) so the result reports the specific
// ECMP path this probe exercised out of the target's rotating set.
func fillTargetMetadata(result *probe.ProbeResult, seqNum uint64, flowLabel uint32, target *controller_agent.PingTarget) {
	result.SequenceNum = seqNum
	result.TargetQPN = target.GetTargetQpn()
	result.FlowLabel = flowLabel
	result.TargetIP = target.GetTargetIp()
	result.TargetHostname = target.GetTargetHostname()
	result.TargetTorID = target.GetTargetTorId()
	if parsedGID, err := probe.ParseGID(target.GetTargetGid()); err == nil {
		result.TargetGID = parsedGID
	}
}

// newFailedResult builds a Success=false ProbeResult carrying the target
// metadata, the flow label the failed send used, and an error message, used
// when a probe send fails outright.
func newFailedResult(seqNum uint64, target *controller_agent.PingTarget, flowLabel uint32, errMsg string) *probe.ProbeResult {
	result := &probe.ProbeResult{}
	fillTargetMetadata(result, seqNum, flowLabel, target)
	result.Success = false
	result.ErrorMessage = errMsg
	return result
}

// emitResult delivers a result on resultChan without blocking. A non-blocking
// send keeps a slow consumer from stalling the probe or ACK loops (which may
// hold pendingMu at the call site's caller); a full channel drops the result
// with a warning.
func (p *Prober) emitResult(result *probe.ProbeResult) {
	// Stamp the source RNIC GID so downstream per-path aggregation can key by
	// (source, target). Single-writer point: the result is still owned by the
	// prober here, before any consumer sees it.
	result.SourceGID = p.sourceGID
	select {
	case p.resultChan <- result:
	default:
		p.logger.Warn().
			Uint64("seq", result.SequenceNum).
			Msg("Result channel full, dropping probe result")
	}
}

// deliverResult computes RTT metrics for a completed probe and emits it on the
// results channel. It is called without holding pendingMu so a slow consumer
// cannot stall ACK processing under the lock.
func (p *Prober) deliverResult(seqNum uint64, target *controller_agent.PingTarget, result *probe.ProbeResult) {
	rtt := probe.CalculateRTT(result)

	p.logger.Debug().
		Uint64("seq", seqNum).
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

	p.emitResult(result)
}

// cleanupStalePending removes entries from the pending map that are older
// than stalePendingTimeout. This prevents memory leaks from probes whose
// ACK responses were lost or never arrived. Each expired probe is emitted as
// a failed ProbeResult so packet loss / timeouts are visible in the
// probe_failed_total metric instead of vanishing silently.
func (p *Prober) cleanupStalePending() {
	now := time.Now()
	var stale []*probe.ProbeResult

	p.pendingMu.Lock()
	for seqNum, pp := range p.pending {
		if now.Sub(pp.createdAt) > stalePendingTimeout {
			// Preserve any partial timestamps the measurement collected, then
			// overlay the target metadata and failure state.
			result := pp.meas.Result()
			fillTargetMetadata(&result, seqNum, pp.flowLabel, pp.target)
			result.Success = false
			result.ErrorMessage = "timed out waiting for ACKs"
			stale = append(stale, &result)
			delete(p.pending, seqNum)
		}
	}
	p.pendingMu.Unlock()

	// Emit outside pendingMu; non-blocking like deliverResult so a slow
	// consumer cannot stall the probe loop.
	for _, result := range stale {
		p.emitResult(result)
	}

	if len(stale) > 0 {
		p.logger.Info().
			Int("cleaned", len(stale)).
			Msg("Expired stale pending probes emitted as failures")
	}
}

// GetQueueInfo returns the queue metadata (QPN, timestamp mode) for this
// prober's sender queue. This can be used for logging and diagnostics. It is
// safe to call after Destroy(): a zero-valued QueueInfo is returned once the
// queue has been torn down.
func (p *Prober) GetQueueInfo() rdmabridge.QueueInfo {
	p.queueMu.RLock()
	defer p.queueMu.RUnlock()
	if p.queue == nil {
		return rdmabridge.QueueInfo{}
	}
	return p.queue.Info
}

// Destroy stops the prober if it is running and destroys the underlying
// RDMA queue, freeing all associated resources (QP, CQ, MRs).
//
// After Stop() returns all producer goroutines have exited, so closing
// resultChan here is safe. Consumers using "for range" will exit cleanly
// when the channel is closed.
func (p *Prober) Destroy() {
	p.Stop()
	p.destroyOnce.Do(func() {
		close(p.resultChan)
		p.queueMu.Lock()
		if p.queue != nil {
			p.queue.Destroy()
			p.queue = nil
		}
		p.queueMu.Unlock()
		p.logger.Info().Msg("Prober destroyed")
	})
}
