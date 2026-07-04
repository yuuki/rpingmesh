package probe

import "time"

// RateLimiter is a simple send-spacing rate limiter. It enforces a minimum
// interval between successive events so that the average rate does not exceed
// a configured packets-per-second (pps) target.
//
// RateLimiter is NOT safe for concurrent use; callers must provide their own
// synchronization. It is kept free of any RDMA/cgo dependency so it can be
// unit-tested on any platform. The actual (interruptible) waiting is performed
// by the caller based on the duration returned by Reserve.
type RateLimiter struct {
	minInterval time.Duration
	next        time.Time // earliest time the next send is allowed
}

// SetRate configures the limiter to allow at most pps sends per second. A
// non-positive pps disables rate limiting (Reserve always returns 0).
func (r *RateLimiter) SetRate(pps float64) {
	if pps <= 0 {
		r.minInterval = 0
		return
	}
	r.minInterval = time.Duration(float64(time.Second) / pps)
}

// Enabled reports whether rate limiting is currently active.
func (r *RateLimiter) Enabled() bool {
	return r.minInterval > 0
}

// Reserve returns how long the caller should wait, relative to now, before
// performing the next send, and advances the internal schedule so that the
// following Reserve accounts for this send. When rate limiting is disabled it
// always returns 0.
//
// The schedule is advanced from the later of now and the previously reserved
// slot, so bursts that fall behind the target rate do not accumulate credit
// that would later allow an unbounded burst.
func (r *RateLimiter) Reserve(now time.Time) time.Duration {
	if r.minInterval <= 0 {
		return 0
	}

	var wait time.Duration
	if now.Before(r.next) {
		wait = r.next.Sub(now)
	}
	// The send happens at now+wait; the next one is allowed one interval later.
	r.next = now.Add(wait).Add(r.minInterval)
	return wait
}
