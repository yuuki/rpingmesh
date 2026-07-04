package probe

import (
	"testing"
	"time"
)

// TestRateLimiter_Disabled verifies that a limiter with no rate set never asks
// the caller to wait.
func TestRateLimiter_Disabled(t *testing.T) {
	var r RateLimiter
	if r.Enabled() {
		t.Fatal("limiter should be disabled by default")
	}
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		if w := r.Reserve(now); w != 0 {
			t.Fatalf("disabled limiter returned non-zero wait %v", w)
		}
	}
}

// TestRateLimiter_ZeroOrNegativeDisables verifies that a non-positive rate
// disables limiting.
func TestRateLimiter_ZeroOrNegativeDisables(t *testing.T) {
	var r RateLimiter
	r.SetRate(1000)
	if !r.Enabled() {
		t.Fatal("limiter should be enabled after SetRate(1000)")
	}
	r.SetRate(0)
	if r.Enabled() {
		t.Fatal("SetRate(0) should disable the limiter")
	}
	r.SetRate(-5)
	if r.Enabled() {
		t.Fatal("SetRate(-5) should disable the limiter")
	}
}

// TestRateLimiter_SpacingWhenCallerKeepsUp verifies that when the caller sends
// as fast as allowed, each successive Reserve returns the full inter-send
// interval.
func TestRateLimiter_SpacingWhenCallerKeepsUp(t *testing.T) {
	var r RateLimiter
	r.SetRate(1000) // 1ms between sends
	interval := time.Millisecond

	now := time.Unix(100, 0)

	// First send: no prior schedule, so no wait.
	if w := r.Reserve(now); w != 0 {
		t.Fatalf("first Reserve wait = %v, want 0", w)
	}

	// Immediately reserving again (no time elapsed) must wait one interval.
	if w := r.Reserve(now); w != interval {
		t.Fatalf("second Reserve wait = %v, want %v", w, interval)
	}

	// Advancing exactly to the reserved slot and reserving again waits another
	// full interval.
	now = now.Add(interval)
	if w := r.Reserve(now); w != interval {
		t.Fatalf("third Reserve wait = %v, want %v", w, interval)
	}
}

// TestRateLimiter_NoCreditAccumulation verifies that when the caller falls
// behind (long gaps between Reserve calls), the limiter does not accumulate
// credit that would permit a later unbounded burst.
func TestRateLimiter_NoCreditAccumulation(t *testing.T) {
	var r RateLimiter
	r.SetRate(1000) // 1ms interval

	now := time.Unix(100, 0)
	_ = r.Reserve(now) // establishes schedule at now+1ms

	// Caller returns much later than the reserved slot.
	now = now.Add(1 * time.Second)
	if w := r.Reserve(now); w != 0 {
		t.Fatalf("late Reserve wait = %v, want 0 (slot already elapsed)", w)
	}

	// The very next reservation must still be spaced by one interval; the long
	// idle gap must not grant a free burst.
	if w := r.Reserve(now); w != time.Millisecond {
		t.Fatalf("post-idle Reserve wait = %v, want 1ms", w)
	}
}
