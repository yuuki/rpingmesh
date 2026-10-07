package agent

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

// ringPollFallbackInterval is how long an event-ring consumer sleeps between
// polls in busy mode, or in event mode when the ring has no notification
// eventfd. Otherwise the consumer blocks until the CQ poller pushes events.
const ringPollFallbackInterval = 100 * time.Microsecond

// newRingIdleWait prepares the idle wait of an event-ring consumer loop.
//
// The returned wait function is called after ring.Poll returned no events.
// It returns true when the ring may have new events, or false once ctx is
// done or stopCh is closed. release must be called when the loop exits.
//
// eventDriven should be the queue's QueueInfo.UsesCQEvents, so the consumer
// follows the same mode as the Zig CQ poller feeding the ring:
//
//   - Event mode: wait blocks until the poller signals new events through
//     the ring's eventfd (via the Go netpoller). Blocking instead of polling
//     on a 100us timer is what keeps an idle agent cheap: with 2 consumers
//     per RDMA device, timer polling woke the Go runtime tens of thousands
//     of times per second on multi-rail hosts.
//   - Busy mode: wait sleeps ringPollFallbackInterval. Busy mode is chosen
//     for software timestamps, which absorb wakeup latency; keeping the
//     consumer polling too keeps that path identical to the poll-based
//     design (an otherwise idle process lets CPUs enter deeper idle states,
//     which delays the completions the software timestamps are taken at).
//
// Event mode also falls back to the timer if the ring has no eventfd.
func newRingIdleWait(ctx context.Context, stopCh <-chan struct{}, ring *rdmabridge.EventRing, eventDriven bool, logger zerolog.Logger) (wait func() bool, release func()) {
	if !eventDriven {
		return newRingTimerWait(ctx, stopCh)
	}
	waiter, err := ring.NewWaiter()
	if err != nil {
		logger.Warn().Err(err).
			Dur("interval", ringPollFallbackInterval).
			Msg("Event ring notification unavailable; polling the ring on a timer")
		return newRingTimerWait(ctx, stopCh)
	}

	// Close the waiter on shutdown so a blocked Wait returns immediately.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopCh:
		case <-done:
		}
		_ = waiter.Close()
	}()

	wait = func() bool {
		return waiter.Wait() == nil
	}
	release = func() {
		close(done)
		_ = waiter.Close()
	}
	return wait, release
}

// newRingTimerWait is the busy-mode idle wait: sleep ringPollFallbackInterval,
// waking early (and returning false) on ctx cancellation or stopCh.
func newRingTimerWait(ctx context.Context, stopCh <-chan struct{}) (wait func() bool, release func()) {
	// The timer is reused across waits to avoid allocating one per empty
	// poll. Reset is safe because every wait drains it before resetting.
	timer := time.NewTimer(ringPollFallbackInterval)
	wait = func() bool {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(ringPollFallbackInterval)
		select {
		case <-ctx.Done():
			return false
		case <-stopCh:
			return false
		case <-timer.C:
			return true
		}
	}
	release = func() { timer.Stop() }
	return wait, release
}
