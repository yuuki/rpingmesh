package agent

import (
	"context"
	"math"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"golang.org/x/sys/unix"
)

// Watchdog constants.
const (
	// defaultWatchdogIntervalSec is the fallback sampling period used when the
	// configured watchdog_interval_sec is 0 (which Validate rejects while the
	// feature is enabled, so this only guards direct/test construction).
	defaultWatchdogIntervalSec = 5

	// throttleRecoveryRatio is the hysteresis band. Throttling engages when a
	// resource reaches its threshold, but the watchdog only steps the rate
	// multiplier back UP once usage falls to this fraction of that threshold.
	// The gap between the engage point (threshold) and the release point
	// (threshold * ratio) is what keeps the multiplier from flapping when usage
	// hovers right at the threshold; 0.75 leaves a 25% margin.
	throttleRecoveryRatio = 0.75

	// bytesPerMiB converts the config's max_memory_mb into the byte-domain
	// reading the runtime/metrics sampler returns.
	bytesPerMiB = 1 << 20

	// runtime/metrics keys for GOMEMLIMIT-style memory accounting: all
	// runtime-managed memory (total) minus what has been returned to the OS
	// (released). Their difference is directly comparable to the max_memory_mb
	// budget, which uses the same accounting as debug.SetMemoryLimit.
	metricMemTotal    = "/memory/classes/total:bytes"
	metricMemReleased = "/memory/classes/heap/released:bytes"
)

// throttleLadder is the discrete set of rate multipliers the watchdog steps
// through, from unthrottled (index 0) down to the fail-slow floor (last index).
// The watchdog moves at most one step per sample, so a sustained overload ramps
// down over several intervals and recovery climbs back just as gradually; that
// gradualness, together with throttleRecoveryRatio, is what prevents abrupt
// oscillation. The floor is deliberately greater than 0: self-protection slows
// probing but must never stop it, since a silent agent is a monitoring blind
// spot (fail-slow, never fail-closed).
var throttleLadder = []float64{1.0, 0.5, 0.25, 0.1}

// minThrottleMultiplier is the fail-slow floor (the last ladder entry), named
// so logs and the prober's contract can refer to the guaranteed lower bound.
var minThrottleMultiplier = throttleLadder[len(throttleLadder)-1]

// resourceSample is a point-in-time reading of this process's resource usage.
// Kept small and free of any RDMA/cgo dependency so the watchdog logic can be
// unit-tested with an injected sampler.
type resourceSample struct {
	// memInUseBytes is runtime-managed memory currently in use, using the same
	// accounting as GOMEMLIMIT (total classes minus released-to-OS), so it is
	// directly comparable to the max_memory_mb budget.
	memInUseBytes uint64
	// cpuNanos is cumulative process CPU time (user+system) in nanoseconds. The
	// watchdog derives a utilization percentage from its delta between samples.
	cpuNanos uint64
	// gomaxprocs is the CPU capacity (number of cores the process may use) at
	// sample time; utilization is measured relative to this so a max_procs cap
	// is respected automatically.
	gomaxprocs int
}

// resourceSampler produces a resourceSample. Injected into the Watchdog so
// tests can feed deterministic readings without touching real process state.
type resourceSampler interface {
	sample() resourceSample
}

// rateThrottler is the subset of *Prober the watchdog drives: scaling the
// prober's aggregate send rate by a multiplier in (0, 1]. Declared here (at the
// point of use) so the watchdog can be tested against a fake.
type rateThrottler interface {
	SetRateMultiplier(mult float64)
}

// runtimeSampler is the production resourceSampler. Memory comes from
// runtime/metrics (GOMEMLIMIT accounting); CPU comes from getrusage.
type runtimeSampler struct{}

// sample reads current memory and CPU usage.
//
// Memory uses runtime/metrics so the reading matches the debug.SetMemoryLimit
// budget. CPU uses getrusage rather than runtime/metrics /cpu/classes because
// those CPU counters only advance during a GC cycle: a low-allocation agent
// would report stale (often zero) CPU for long stretches unless the watchdog
// forced a disruptive GC every tick. getrusage returns real cumulative process
// CPU time on every call and is available on both linux and darwin via
// golang.org/x/sys/unix (already a dependency) -- the only platforms this agent
// builds for -- so it adds no new dependency.
func (runtimeSampler) sample() resourceSample {
	samples := []metrics.Sample{
		{Name: metricMemTotal},
		{Name: metricMemReleased},
	}
	metrics.Read(samples)
	var total, released uint64
	if samples[0].Value.Kind() == metrics.KindUint64 {
		total = samples[0].Value.Uint64()
	}
	if samples[1].Value.Kind() == metrics.KindUint64 {
		released = samples[1].Value.Uint64()
	}
	var memInUse uint64
	if total > released {
		memInUse = total - released
	}

	var cpuNanos uint64
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err == nil {
		cpuNanos = uint64(ru.Utime.Nano() + ru.Stime.Nano())
	}

	return resourceSample{
		memInUseBytes: memInUse,
		cpuNanos:      cpuNanos,
		gomaxprocs:    runtime.GOMAXPROCS(0),
	}
}

// Watchdog periodically samples this agent process's CPU and memory usage and,
// on threshold breach, steps every prober's send-rate multiplier down the
// throttleLadder (fail-slow), restoring it as usage recovers. It never stops
// probing outright. All mutable state except the published multiplier is owned
// by the single run goroutine (tick is not called concurrently); the multiplier
// is published via an atomic for the OTLP gauge callback.
type Watchdog struct {
	interval   time.Duration
	sampler    resourceSampler
	throttlers []rateThrottler

	// Thresholds precomputed from config. A zero threshold disables that
	// resource's contribution (memory throttling is off when no max_memory_mb
	// budget is set).
	memHighBytes float64 // 0 => memory throttling disabled
	cpuHighPct   float64 // 0 => CPU throttling disabled

	// State owned by the run goroutine (and tick, called only from it).
	levelIdx int
	prev     resourceSample
	prevTime time.Time
	havePrev bool

	// multiplierBits is math.Float64bits of the current multiplier, published
	// for CurrentMultiplier (read from the metrics callback goroutine).
	multiplierBits atomic.Uint64

	nowFn  func() time.Time
	logger zerolog.Logger

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewWatchdog builds a Watchdog from config that drives the given throttlers
// (one per prober). It reads the production runtimeSampler; tests construct a
// Watchdog directly to inject a fake sampler and clock.
func NewWatchdog(cfg *config.AgentConfig, throttlers []rateThrottler) *Watchdog {
	interval := time.Duration(cfg.WatchdogIntervalSec) * time.Second
	if interval <= 0 {
		interval = defaultWatchdogIntervalSec * time.Second
	}

	// Memory throttling references the max_memory_mb budget; with no budget it
	// stays disabled and only CPU is watched.
	var memHigh float64
	if cfg.MaxMemoryMB > 0 {
		memHigh = float64(cfg.MaxMemoryMB) * bytesPerMiB * cfg.ThrottleMemoryRatio
	}

	w := &Watchdog{
		interval:     interval,
		sampler:      runtimeSampler{},
		throttlers:   throttlers,
		memHighBytes: memHigh,
		cpuHighPct:   cfg.ThrottleCPUPercent,
		nowFn:        time.Now,
		logger:       log.With().Str("component", "watchdog").Logger(),
	}
	w.setMultiplier(throttleLadder[0])
	return w
}

// Start launches the watchdog goroutine. It returns immediately; the goroutine
// runs until Stop is called or ctx is cancelled.
func (w *Watchdog) Start(ctx context.Context) {
	w.stopCh = make(chan struct{})
	w.wg.Add(1)
	go w.run(ctx)
	w.logger.Info().
		Dur("interval", w.interval).
		Float64("mem_high_bytes", w.memHighBytes).
		Float64("cpu_high_percent", w.cpuHighPct).
		Float64("floor_multiplier", minThrottleMultiplier).
		Msg("Self-protection watchdog started")
}

// Stop signals the watchdog goroutine to exit and waits for it. It is a no-op
// if Start was never called, matching the nil-guard pattern used in Agent.Stop.
func (w *Watchdog) Stop() {
	if w.stopCh == nil {
		return
	}
	close(w.stopCh)
	w.wg.Wait()
	w.logger.Info().Msg("Self-protection watchdog stopped")
}

// CurrentMultiplier returns the watchdog's current rate multiplier (1.0 =
// unthrottled, down to minThrottleMultiplier). Safe to call from any goroutine;
// used by the rpingmesh.agent.self_throttle gauge callback.
func (w *Watchdog) CurrentMultiplier() float64 {
	return math.Float64frombits(w.multiplierBits.Load())
}

func (w *Watchdog) setMultiplier(m float64) {
	w.multiplierBits.Store(math.Float64bits(m))
}

// run is the watchdog loop: sample, evaluate, apply, on each interval tick.
func (w *Watchdog) run(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.tick(w.sampler.sample(), w.nowFn())
		}
	}
}

// tick evaluates one sample and, if the throttle level changes, applies the new
// multiplier to every prober and logs the transition. It is called only from
// the run goroutine, so its state mutations need no lock. Extracted from run so
// tests can drive it directly with injected samples and timestamps for
// deterministic threshold/hysteresis verification.
func (w *Watchdog) tick(cur resourceSample, now time.Time) {
	cpuUtil := -1.0 // negative => no CPU reading yet (need a prior sample)
	if w.havePrev {
		cpuUtil = cpuUtilization(w.prev, cur, w.prevTime, now)
	}
	w.prev = cur
	w.prevTime = now
	w.havePrev = true

	over, clear := w.assess(cur.memInUseBytes, cpuUtil)
	newIdx := nextLevel(w.levelIdx, over, clear)
	if newIdx == w.levelIdx {
		return
	}

	oldMult := throttleLadder[w.levelIdx]
	newMult := throttleLadder[newIdx]
	w.levelIdx = newIdx
	w.setMultiplier(newMult)
	for _, t := range w.throttlers {
		t.SetRateMultiplier(newMult)
	}
	w.logThrottleChange(oldMult, newMult, cur.memInUseBytes, cpuUtil)
}

// assess reports whether the current reading is OVER any enabled threshold
// (=> throttle down) and whether it is CLEAR of ALL enabled thresholds by the
// hysteresis margin (=> recover up). A disabled resource (or a CPU reading not
// yet available, cpuUtil < 0) counts as clear and never over, so it neither
// triggers nor blocks throttling. over and clear are mutually exclusive
// (threshold > threshold*ratio), so a reading in the deadband between the
// release and engage points yields neither, holding the current level.
func (w *Watchdog) assess(memBytes uint64, cpuUtil float64) (over, clear bool) {
	over = false
	clear = true

	if w.memHighBytes > 0 {
		high := w.memHighBytes
		low := high * throttleRecoveryRatio
		m := float64(memBytes)
		if m >= high {
			over = true
		}
		if m > low {
			clear = false
		}
	}

	if w.cpuHighPct > 0 && cpuUtil >= 0 {
		high := w.cpuHighPct
		low := high * throttleRecoveryRatio
		if cpuUtil >= high {
			over = true
		}
		if cpuUtil > low {
			clear = false
		}
	}

	return over, clear
}

// nextLevel returns the throttle-ladder index for the next tick: one step down
// (more throttle) when over, one step up (less throttle) when clear, otherwise
// unchanged. Clamped to the ladder bounds. Pure, so the ladder walk is
// trivially unit-testable.
func nextLevel(cur int, over, clear bool) int {
	switch {
	case over:
		if cur < len(throttleLadder)-1 {
			return cur + 1
		}
		return cur
	case clear:
		if cur > 0 {
			return cur - 1
		}
		return cur
	default:
		return cur
	}
}

// cpuUtilization returns process CPU utilization between two samples as a
// percentage of the available CPU capacity (GOMAXPROCS cores) over the wall
// interval, using the current sample's core count as capacity. It returns 0 for
// a non-positive interval or a counter that went backwards, guarding against a
// clock that did not advance or a rusage anomaly.
func cpuUtilization(prev, cur resourceSample, prevTime, curTime time.Time) float64 {
	wall := curTime.Sub(prevTime).Nanoseconds()
	if wall <= 0 {
		return 0
	}
	if cur.cpuNanos < prev.cpuNanos {
		return 0
	}
	cores := cur.gomaxprocs
	if cores <= 0 {
		cores = 1
	}
	busy := float64(cur.cpuNanos - prev.cpuNanos)
	capacity := float64(wall) * float64(cores)
	return busy / capacity * 100
}

// logThrottleChange records a throttle-level transition. Engaging throttle
// (leaving the unthrottled top of the ladder) and fully recovering (returning
// to it) are logged at Warn since they mark a change in monitoring fidelity;
// intermediate steps are Info to avoid noise.
func (w *Watchdog) logThrottleChange(oldMult, newMult float64, memBytes uint64, cpuUtil float64) {
	unthrottled := throttleLadder[0]
	var event *zerolog.Event
	switch {
	case oldMult == unthrottled && newMult < unthrottled:
		event = w.logger.Warn()
	case newMult == unthrottled:
		event = w.logger.Warn()
	default:
		event = w.logger.Info()
	}
	event.
		Float64("old_multiplier", oldMult).
		Float64("new_multiplier", newMult).
		Float64("floor_multiplier", minThrottleMultiplier).
		Uint64("mem_in_use_bytes", memBytes).
		Float64("cpu_util_percent", cpuUtil).
		Msg("Self-protection throttle level changed")
}
