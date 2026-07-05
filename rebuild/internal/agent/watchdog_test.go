// Tests for the self-protection watchdog's throttle state machine: threshold
// breach steps the rate multiplier down the ladder, recovery steps it back up,
// a hysteresis deadband holds it steady near the threshold, and the floor is
// never breached (fail-slow, never fail-closed). Samples and timestamps are
// injected so every case is deterministic without real resource pressure.
package agent

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// fakeThrottler records every multiplier the watchdog applies, standing in for
// a *Prober so the watchdog can be tested without RDMA.
type fakeThrottler struct{ mults []float64 }

func (f *fakeThrottler) SetRateMultiplier(m float64) { f.mults = append(f.mults, m) }

// newTestWatchdog builds a Watchdog with the given thresholds and a fake
// throttler, bypassing NewWatchdog so tests drive tick() directly with injected
// samples instead of the sampler/goroutine.
func newTestWatchdog(memHigh, cpuHigh float64) (*Watchdog, *fakeThrottler) {
	ft := &fakeThrottler{}
	w := &Watchdog{
		memHighBytes: memHigh,
		cpuHighPct:   cpuHigh,
		throttlers:   []rateThrottler{ft},
		logger:       zerolog.Nop(),
	}
	w.setMultiplier(throttleLadder[0])
	return w, ft
}

// memSample builds a sample carrying only a memory reading.
func memSample(bytes uint64) resourceSample {
	return resourceSample{memInUseBytes: bytes, gomaxprocs: 1}
}

func TestNextLevel(t *testing.T) {
	last := len(throttleLadder) - 1
	cases := []struct {
		name       string
		cur        int
		over, clr  bool
		wantResult int
	}{
		{"over steps down from top", 0, true, false, 1},
		{"over steps down mid", 1, true, false, 2},
		{"over clamps at floor", last, true, false, last},
		{"clear steps up", 2, false, true, 1},
		{"clear clamps at top", 0, false, true, 0},
		{"deadband holds mid", 2, false, false, 2},
		{"over wins over clear (mutually exclusive guard)", 1, true, true, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextLevel(c.cur, c.over, c.clr); got != c.wantResult {
				t.Errorf("nextLevel(%d, over=%v, clear=%v) = %d, want %d", c.cur, c.over, c.clr, got, c.wantResult)
			}
		})
	}
}

func TestAssess_MemoryThresholdsAndHysteresis(t *testing.T) {
	// high=100 => low = 100 * 0.75 = 75. CPU disabled.
	w, _ := newTestWatchdog(100, 0)
	cases := []struct {
		mem              uint64
		wantOver, wantCl bool
	}{
		{100, true, false}, // exactly at high engages
		{101, true, false}, // above high
		{99, false, false}, // deadband (below high, above low)
		{76, false, false}, // deadband just above low
		{75, false, true},  // exactly at low recovers (not > low)
		{74, false, true},  // below low
		{0, false, true},   // idle
	}
	for _, c := range cases {
		over, clr := w.assess(c.mem, -1)
		if over != c.wantOver || clr != c.wantCl {
			t.Errorf("assess(mem=%d) = (over=%v, clear=%v), want (over=%v, clear=%v)", c.mem, over, clr, c.wantOver, c.wantCl)
		}
	}
}

func TestAssess_CPUThresholdsAndUnavailable(t *testing.T) {
	// high=90 => low = 67.5. Memory disabled.
	w, _ := newTestWatchdog(0, 90)
	cases := []struct {
		util             float64
		wantOver, wantCl bool
	}{
		{-1, false, true},   // no reading yet: clear, never over
		{90, true, false},   // at threshold engages
		{95, true, false},   // above
		{80, false, false},  // deadband
		{68, false, false},  // deadband just above low
		{67.5, false, true}, // at low recovers
		{10, false, true},   // idle
	}
	for _, c := range cases {
		over, clr := w.assess(0, c.util)
		if over != c.wantOver || clr != c.wantCl {
			t.Errorf("assess(cpu=%g) = (over=%v, clear=%v), want (over=%v, clear=%v)", c.util, over, clr, c.wantOver, c.wantCl)
		}
	}
}

func TestAssess_EitherResourceTriggers_BothRequiredToClear(t *testing.T) {
	// Both enabled: mem high=100 (low 75), cpu high=90 (low 67.5).
	w, _ := newTestWatchdog(100, 90)

	// Memory over, CPU idle => over (any resource triggers).
	if over, clr := w.assess(120, 10); !over || clr {
		t.Errorf("mem-over: got (over=%v, clear=%v), want (true, false)", over, clr)
	}
	// CPU over, memory idle => over.
	if over, clr := w.assess(10, 95); !over || clr {
		t.Errorf("cpu-over: got (over=%v, clear=%v), want (true, false)", over, clr)
	}
	// Memory clear but CPU still in deadband => not clear (both must clear).
	if over, clr := w.assess(10, 80); over || clr {
		t.Errorf("cpu-deadband: got (over=%v, clear=%v), want (false, false)", over, clr)
	}
	// Both clear => clear.
	if over, clr := w.assess(10, 10); over || !clr {
		t.Errorf("both-clear: got (over=%v, clear=%v), want (false, true)", over, clr)
	}
}

// TestTick_MemoryRampDownAndRecover drives the full ladder: sustained overload
// steps down one level per tick to the floor (and no further), then sustained
// idle steps back up to unthrottled, each step applied to the throttler exactly
// once.
func TestTick_MemoryRampDownAndRecover(t *testing.T) {
	w, ft := newTestWatchdog(100, 0)
	base := time.Unix(0, 0)
	step := time.Second

	over := memSample(150) // above high=100
	idle := memSample(50)  // below low=75

	// Ramp down: 0->0.5->0.25->0.1, then hold at floor.
	seq := []resourceSample{over, over, over, over}
	for i, s := range seq {
		w.tick(s, base.Add(time.Duration(i)*step))
	}
	// Then recover: 0.1->0.25->0.5->1.0, then hold at top.
	for i, s := range []resourceSample{idle, idle, idle, idle} {
		w.tick(s, base.Add(time.Duration(len(seq)+i)*step))
	}

	want := []float64{0.5, 0.25, 0.1, 0.25, 0.5, 1.0}
	assertMults(t, ft.mults, want)
	if got := w.CurrentMultiplier(); got != 1.0 {
		t.Errorf("CurrentMultiplier() = %g, want 1.0 after recovery", got)
	}
}

// TestTick_HysteresisHoldsInDeadband verifies that once throttled, a reading in
// the deadband (below the engage threshold but above the recovery threshold)
// neither throttles further nor recovers -- the multiplier holds until usage
// clears the recovery threshold.
func TestTick_HysteresisHoldsInDeadband(t *testing.T) {
	w, ft := newTestWatchdog(100, 0) // low=75
	base := time.Unix(0, 0)

	w.tick(memSample(150), base)                   // over -> 0.5
	w.tick(memSample(80), base.Add(1*time.Second)) // deadband -> hold
	w.tick(memSample(80), base.Add(2*time.Second)) // deadband -> hold
	w.tick(memSample(70), base.Add(3*time.Second)) // clear -> 1.0

	assertMults(t, ft.mults, []float64{0.5, 1.0})
}

// TestTick_CPURampNeedsPriorSample verifies the first tick cannot throttle on
// CPU (no delta yet), and that a subsequent high-CPU delta throttles while a
// low delta recovers.
func TestTick_CPURampNeedsPriorSample(t *testing.T) {
	w, ft := newTestWatchdog(0, 90) // cpu low = 67.5, 1 core
	base := time.Unix(0, 0)
	sec := int64(time.Second)

	// First sample: no prior => cpuUtil unavailable => no throttle.
	w.tick(resourceSample{cpuNanos: 0, gomaxprocs: 1}, base)
	// +1s, +0.95s CPU on 1 core => 95% => over.
	w.tick(resourceSample{cpuNanos: uint64(0.95 * float64(sec)), gomaxprocs: 1}, base.Add(time.Second))
	// +1s, +0.95s CPU => 95% => over again.
	w.tick(resourceSample{cpuNanos: uint64(1.90 * float64(sec)), gomaxprocs: 1}, base.Add(2*time.Second))
	// +1s, +0.10s CPU => 10% < low => clear.
	w.tick(resourceSample{cpuNanos: uint64(2.00 * float64(sec)), gomaxprocs: 1}, base.Add(3*time.Second))

	assertMults(t, ft.mults, []float64{0.5, 0.25, 0.5})
}

func TestCPUUtilization_Guards(t *testing.T) {
	base := time.Unix(0, 0)
	prev := resourceSample{cpuNanos: 1_000, gomaxprocs: 4}
	// Non-positive interval => 0.
	if got := cpuUtilization(prev, resourceSample{cpuNanos: 2_000, gomaxprocs: 4}, base, base); got != 0 {
		t.Errorf("zero interval util = %g, want 0", got)
	}
	// Counter went backwards => 0.
	if got := cpuUtilization(prev, resourceSample{cpuNanos: 500, gomaxprocs: 4}, base, base.Add(time.Second)); got != 0 {
		t.Errorf("backwards counter util = %g, want 0", got)
	}
	// 2 cores, 1s wall, 1s CPU => 50% of capacity.
	got := cpuUtilization(
		resourceSample{cpuNanos: 0, gomaxprocs: 2},
		resourceSample{cpuNanos: uint64(time.Second), gomaxprocs: 2},
		base, base.Add(time.Second),
	)
	if got < 49.9 || got > 50.1 {
		t.Errorf("util = %g, want ~50", got)
	}
}

func assertMults(t *testing.T, got, want []float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("multiplier sequence = %v, want %v (length %d != %d)", got, want, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("multiplier sequence = %v, want %v (index %d)", got, want, i)
		}
	}
}
