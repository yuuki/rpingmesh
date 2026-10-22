package e2e_test

import (
	"context"
	"time"

	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

// startEventPoller drains ring in a goroutine and hands every completion event
// to handler until ctx is cancelled. It is the test-only counterpart of the
// agent's prober/responder loops: it blocks on the ring's eventfd when the
// queue's CQ poller is in event mode and polls on a short timer otherwise.
func startEventPoller(ctx context.Context, q *rdmabridge.Queue, ring *rdmabridge.EventRing, handler func(rdmabridge.CompletionEvent)) {
	go func() {
		const (
			maxBatch  = 32
			idleSleep = 100 * time.Microsecond
		)
		var waiter *rdmabridge.RingWaiter
		if q.Info.UsesCQEvents {
			if w, err := ring.NewWaiter(); err == nil {
				waiter = w
			}
		}
		if waiter != nil {
			defer waiter.Close()
			stop := context.AfterFunc(ctx, func() { _ = waiter.Close() })
			defer stop()
		}
		for ctx.Err() == nil {
			events := ring.Poll(maxBatch)
			if len(events) == 0 {
				if waiter == nil {
					time.Sleep(idleSleep)
				} else if waiter.Wait() != nil {
					return
				}
				continue
			}
			for _, ev := range events {
				handler(ev)
			}
		}
	}()
}
