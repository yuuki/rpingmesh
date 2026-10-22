package agent

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

// lifecycle is the start/stop state shared by the agent's goroutine-owning
// components (Prober, Responder, ClusterMonitor): a running flag, a stop
// channel that is recreated on every start so a component can be restarted,
// and a WaitGroup that stop always joins.
type lifecycle struct {
	running atomic.Bool
	stopMu  sync.Mutex    // guards stopCh (re)creation across start/stop
	stopCh  chan struct{} // closed by stop to wake the goroutines immediately
	wg      sync.WaitGroup
}

// start flips the component to running and returns false if it already was.
// The stop channel is recreated because a previous stop closed it; stop has
// already joined the old goroutines, so nothing references the old channel.
func (l *lifecycle) start() bool {
	if !l.running.CompareAndSwap(false, true) {
		return false
	}
	l.stopMu.Lock()
	l.stopCh = make(chan struct{})
	l.stopMu.Unlock()
	return true
}

// stop clears running, closes the stop channel (only the CAS winner does, so
// a second stop cannot double-close) and waits for the goroutines. It always
// waits, even when running was already false: a loop that observed ctx.Done
// may still be unwinding, and the caller typically tears down the resources
// those goroutines use right after stop returns. It reports whether this call
// was the one that stopped the component.
func (l *lifecycle) stop() bool {
	signaled := l.running.CompareAndSwap(true, false)
	if signaled {
		l.stopMu.Lock()
		close(l.stopCh)
		l.stopMu.Unlock()
	}
	l.wg.Wait()
	return signaled
}

// stopping reports whether ctx is done or stop has been called.
func (l *lifecycle) stopping(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	case <-l.stopCh:
		return true
	default:
		return false
	}
}

// queueHandle guards a component's RDMA queue so GetQueueInfo cannot race
// with destroy setting the queue to nil.
type queueHandle struct {
	queueMu sync.RWMutex
	queue   *rdmabridge.Queue
}

// GetQueueInfo returns the queue metadata (QPN, timestamp mode). It is safe
// to call after destroy: a zero-valued QueueInfo is returned once the queue
// has been torn down.
func (h *queueHandle) GetQueueInfo() rdmabridge.QueueInfo {
	h.queueMu.RLock()
	defer h.queueMu.RUnlock()
	if h.queue == nil {
		return rdmabridge.QueueInfo{}
	}
	return h.queue.Info
}

// destroyQueue destroys the RDMA queue (QP, CQ, MRs) once.
func (h *queueHandle) destroyQueue() {
	h.queueMu.Lock()
	if h.queue != nil {
		h.queue.Destroy()
		h.queue = nil
	}
	h.queueMu.Unlock()
}

// ringEventBatch is the maximum number of completion events a consumer takes
// from its ring per poll.
const ringEventBatch = 32

// runRingLoop drains ring until ctx is done or lc is stopped, calling handle
// for every completion event. While the ring is empty it sleeps until the CQ
// poller signals new events (see newRingIdleWait). Shutdown is checked before
// every event, so a handler that may block (the responder waiting for a send
// slot) does not delay stop.
func runRingLoop(ctx context.Context, lc *lifecycle, ring *rdmabridge.EventRing, eventDriven bool, logger zerolog.Logger, handle func(*rdmabridge.CompletionEvent)) {
	wait, release := newRingIdleWait(ctx, lc.stopCh, ring, eventDriven, logger)
	defer release()

	for lc.running.Load() {
		if lc.stopping(ctx) {
			return
		}
		events := ring.Poll(ringEventBatch)
		if len(events) == 0 {
			if !wait() {
				return
			}
			continue
		}
		for i := range events {
			if lc.stopping(ctx) {
				return
			}
			handle(&events[i])
		}
	}
}
