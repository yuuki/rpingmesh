// Tests for the self-protection rate multiplier applied on top of the
// per-pinglist-type send-rate limiters: the multiplier scales both types'
// aggregate rates, unity (and out-of-range clamped) multipliers are a no-op,
// the multiplier survives a pinglist resize, and SetRateMultiplier obeys the
// targetsMu -> rateMu lock order under concurrency. These reuse the helpers in
// prober_ratelimit_test.go (same package).
package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// wantScaledInterval mirrors SetRate(scaledRate(pps, n, mult)) exactly: the
// aggregate rate is pps*n*mult and the reported minimum inter-send interval is
// its reciprocal, using the same operand order so the float result is
// bit-identical to the limiter's.
func wantScaledInterval(pps float64, n int, mult float64) time.Duration {
	return time.Duration(float64(time.Second) / (pps * float64(n) * mult))
}

func mixedTargets(nTor, nInter int) []*controller_agent.PingTarget {
	return append(
		typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", nTor),
		typedTargets(controller_agent.PinglistType_INTER_TOR, "int", nInter)...,
	)
}

// TestSetRateMultiplier_ScalesBothTypes verifies a 0.5 multiplier halves each
// type's aggregate rate (doubling its inter-send interval), independently.
func TestSetRateMultiplier_ScalesBothTypes(t *testing.T) {
	const (
		torPPS   = 10.0
		interPPS = 2.0
		nTor     = 4
		nInter   = 2
		mult     = 0.5
	)

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(mixedTargets(nTor, nInter))
	p.SetPerTypeRateLimit(torPPS, interPPS)
	p.SetRateMultiplier(mult)

	if got, want := reserveInterval(&p.torMeshRate.limiter), wantScaledInterval(torPPS, nTor, mult); got != want {
		t.Errorf("ToR-mesh interval @ mult %.2f = %v, want %v", mult, got, want)
	}
	if got, want := reserveInterval(&p.interTorRate.limiter), wantScaledInterval(interPPS, nInter, mult); got != want {
		t.Errorf("inter-ToR interval @ mult %.2f = %v, want %v", mult, got, want)
	}
}

// TestSetRateMultiplier_UnityAndClampAreNoops verifies that a unity multiplier,
// and any out-of-range value (<=0 or >1, which clamp to 1.0), leave both rates
// exactly at their unthrottled values.
func TestSetRateMultiplier_UnityAndClampAreNoops(t *testing.T) {
	const (
		torPPS   = 10.0
		interPPS = 2.0
		nTor     = 3
		nInter   = 2
	)

	for _, mult := range []float64{1.0, 0.0, -0.5, 1.5} {
		p := &Prober{logger: zerolog.Nop()}
		p.UpdateTargets(mixedTargets(nTor, nInter))
		p.SetPerTypeRateLimit(torPPS, interPPS)
		p.SetRateMultiplier(mult)

		if got, want := reserveInterval(&p.torMeshRate.limiter), wantScaledInterval(torPPS, nTor, 1.0); got != want {
			t.Errorf("ToR-mesh interval @ mult %.2f = %v, want unthrottled %v", mult, got, want)
		}
		if got, want := reserveInterval(&p.interTorRate.limiter), wantScaledInterval(interPPS, nInter, 1.0); got != want {
			t.Errorf("inter-ToR interval @ mult %.2f = %v, want unthrottled %v", mult, got, want)
		}
	}
}

// TestSetRateMultiplier_SurvivesUpdateTargets verifies that an active multiplier
// keeps applying after a pinglist resize: UpdateTargets recomputes each rate
// from the new target count but still folds in the stored multiplier.
func TestSetRateMultiplier_SurvivesUpdateTargets(t *testing.T) {
	const (
		torPPS   = 10.0
		interPPS = 4.0
		mult     = 0.25
	)

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(mixedTargets(2, 3))
	p.SetPerTypeRateLimit(torPPS, interPPS)
	p.SetRateMultiplier(mult)

	// Resize both types; the multiplier must persist through UpdateTargets.
	p.UpdateTargets(mixedTargets(4, 1))

	if got, want := reserveInterval(&p.torMeshRate.limiter), wantScaledInterval(torPPS, 4, mult); got != want {
		t.Errorf("ToR-mesh interval after resize = %v, want %v (multiplier not preserved)", got, want)
	}
	if got, want := reserveInterval(&p.interTorRate.limiter), wantScaledInterval(interPPS, 1, mult); got != want {
		t.Errorf("inter-ToR interval after resize = %v, want %v (multiplier not preserved)", got, want)
	}
}

// TestSetRateMultiplier_LockOrderRace hammers UpdateTargets, SetPerTypeRateLimit,
// SetRateMultiplier, and the rateMu-guarded read path concurrently. Under -race
// it guards against a data race or a lock-order regression: every writer,
// including the new SetRateMultiplier, must take targetsMu -> rateMu, while the
// reader takes only rateMu.
func TestSetRateMultiplier_LockOrderRace(t *testing.T) {
	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 4))
	p.SetPerTypeRateLimit(10, 2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled so rateLimitWait returns immediately

	var wg sync.WaitGroup
	const iters = 500
	mults := []float64{1.0, 0.5, 0.25, 0.1}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			p.UpdateTargets(mixedTargets(1+i%6, 1+i%3))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			p.SetPerTypeRateLimit(float64(1+i%10), float64(1+i%4))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			p.SetRateMultiplier(mults[i%len(mults)])
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			p.rateLimitWait(ctx, controller_agent.PinglistType_TOR_MESH)
			p.rateLimitWait(ctx, controller_agent.PinglistType_INTER_TOR)
		}
	}()

	wg.Wait()
}
