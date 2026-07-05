// Tests for the prober's differentiated, per-pinglist-type send-rate limiting:
// each pinglist type (ToR-mesh, inter-ToR) is capped at its own per-target rate
// by an independent limiter whose aggregate rate tracks that type's target
// count, the legacy single-rate entry point applies one rate to both types, and
// the targetsMu -> rateMu lock order holds under concurrent updates.
package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// typedTargets builds n targets of the given pinglist type. GIDs are unique
// across a call so the prober's per-target maps do not collide, but the tests
// here only exercise counting and rate resolution.
func typedTargets(ptype controller_agent.PinglistType, prefix string, n int) []*controller_agent.PingTarget {
	targets := make([]*controller_agent.PingTarget, 0, n)
	for i := 0; i < n; i++ {
		targets = append(targets, &controller_agent.PingTarget{
			TargetGid:    prefix + string(rune('a'+i)),
			PinglistType: ptype,
		})
	}
	return targets
}

// wantInterval computes the minimum inter-send interval a limiter set to
// pps*n aggregate pps reports. It mirrors RateLimiter.SetRate's own
// computation (including its truncation to time.Duration) exactly, and takes n
// as a runtime int so the division is not a constant expression (a constant
// non-integer conversion to time.Duration is a compile error).
func wantInterval(pps float64, n int) time.Duration {
	return time.Duration(float64(time.Second) / (pps * float64(n)))
}

// reserveInterval returns the spacing a fresh limiter reports: the second
// Reserve at the same instant is the configured minimum inter-send interval,
// which encodes the limiter's rate (interval = 1 / rate).
func reserveInterval(rl interface {
	Reserve(time.Time) time.Duration
}) time.Duration {
	now := time.Now()
	_ = rl.Reserve(now) // first send: no prior schedule, no wait
	return rl.Reserve(now)
}

// TestPerTypeRateLimit_Independent verifies that a pinglist with many ToR-mesh
// targets and few inter-ToR targets yields two independent aggregate rates:
// each type's limiter is torPPS*nTor / interPPS*nInter, and neither type's
// count or rate leaks into the other's limiter.
func TestPerTypeRateLimit_Independent(t *testing.T) {
	const (
		torPPS   = 10.0
		interPPS = 1.0
		nTor     = 5
		nInter   = 2
	)

	targets := append(
		typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", nTor),
		typedTargets(controller_agent.PinglistType_INTER_TOR, "int", nInter)...,
	)

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(targets)
	p.SetPerTypeRateLimit(torPPS, interPPS)

	wantTor := wantInterval(torPPS, nTor)       // 20ms
	wantInter := wantInterval(interPPS, nInter) // 500ms

	if got := reserveInterval(&p.torMeshRate.limiter); got != wantTor {
		t.Errorf("ToR-mesh limiter interval = %v, want %v (%d targets @ %.0f pps)", got, wantTor, nTor, torPPS)
	}
	if got := reserveInterval(&p.interTorRate.limiter); got != wantInter {
		t.Errorf("inter-ToR limiter interval = %v, want %v (%d targets @ %.0f pps)", got, wantInter, nInter, interPPS)
	}
}

// TestPerTypeRateLimit_FollowsPinglistSize verifies that each type's aggregate
// rate is recomputed on UpdateTargets, so a change in one type's target count
// re-scales only that type's limiter while the other stays put.
func TestPerTypeRateLimit_FollowsPinglistSize(t *testing.T) {
	const (
		torPPS   = 10.0
		interPPS = 2.0
	)

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(append(
		typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 2),
		typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 3)...,
	))
	p.SetPerTypeRateLimit(torPPS, interPPS)

	// Grow ToR-mesh to 4, shrink inter-ToR to 1; the limiters must follow.
	p.UpdateTargets(append(
		typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 4),
		typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 1)...,
	))

	wantTor := wantInterval(torPPS, 4)
	wantInter := wantInterval(interPPS, 1)

	if got := reserveInterval(&p.torMeshRate.limiter); got != wantTor {
		t.Errorf("ToR-mesh limiter interval after resize = %v, want %v", got, wantTor)
	}
	if got := reserveInterval(&p.interTorRate.limiter); got != wantInter {
		t.Errorf("inter-ToR limiter interval after resize = %v, want %v", got, wantInter)
	}
}

// TestSetPerTargetRateLimit_Fallback verifies the backward-compatible entry
// point applies one uniform rate to both pinglist types, each scaled by that
// type's own target count -- the single-rate behavior deployments had before
// differentiated rates existed.
func TestSetPerTargetRateLimit_Fallback(t *testing.T) {
	const pps = 10.0
	const nTor = 3
	const nInter = 2

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(append(
		typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", nTor),
		typedTargets(controller_agent.PinglistType_INTER_TOR, "int", nInter)...,
	))
	p.SetPerTargetRateLimit(pps)

	wantTor := wantInterval(pps, nTor)
	wantInter := wantInterval(pps, nInter)

	if got := reserveInterval(&p.torMeshRate.limiter); got != wantTor {
		t.Errorf("ToR-mesh limiter interval = %v, want %v", got, wantTor)
	}
	if got := reserveInterval(&p.interTorRate.limiter); got != wantInter {
		t.Errorf("inter-ToR limiter interval = %v, want %v", got, wantInter)
	}
}

// TestPerTypeRateLimit_UnstampedTargetsAreTorMesh verifies that targets with
// the proto3-default PinglistType (0 = TOR_MESH), as an older controller would
// send, all count toward the ToR-mesh limiter -- the backward-compatible
// classification.
func TestPerTypeRateLimit_UnstampedTargetsAreTorMesh(t *testing.T) {
	const pps = 4.0
	// Targets built without setting PinglistType default to TOR_MESH.
	targets := []*controller_agent.PingTarget{
		{TargetGid: "fe80::1"},
		{TargetGid: "fe80::2"},
	}

	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(targets)
	p.SetPerTypeRateLimit(pps, pps)

	wantTor := wantInterval(pps, 2)
	if got := reserveInterval(&p.torMeshRate.limiter); got != wantTor {
		t.Errorf("ToR-mesh limiter interval = %v, want %v (unstamped targets)", got, wantTor)
	}
	// No inter-ToR targets, so its limiter stays disabled (Reserve == 0).
	if p.interTorRate.limiter.Enabled() {
		t.Error("inter-ToR limiter should be disabled with zero inter-ToR targets")
	}
}

// TestPerTypeRateLimit_LockOrderRace hammers UpdateTargets, SetPerTypeRateLimit,
// and the rateMu-guarded limiter read path concurrently. Run under -race, it
// guards against a data race or a lock-order regression (all writers take
// targetsMu -> rateMu; the reader takes only rateMu) that would deadlock.
func TestPerTypeRateLimit_LockOrderRace(t *testing.T) {
	p := &Prober{logger: zerolog.Nop()}
	p.UpdateTargets(typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 4))

	// A pre-cancelled context makes rateLimitWait return immediately on any
	// non-zero reservation instead of sleeping, so the reader still hits the
	// rateMu-guarded Reserve every iteration without slowing the test.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var wg sync.WaitGroup
	const iters = 500

	// Writer 1: resize the pinglist (targetsMu -> rateMu).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			p.UpdateTargets(append(
				typedTargets(controller_agent.PinglistType_TOR_MESH, "tor", 1+i%6),
				typedTargets(controller_agent.PinglistType_INTER_TOR, "int", 1+i%3)...,
			))
		}
	}()

	// Writer 2: change the per-type rates (targetsMu -> rateMu).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			p.SetPerTypeRateLimit(float64(1+i%10), float64(1+i%4))
		}
	}()

	// Reader: the send path's rate check (rateMu only). A cancelled context
	// makes any non-zero wait return immediately without a real sleep.
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
