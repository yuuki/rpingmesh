package rdmabridge

/*
#include "rdma_bridge.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrRingNotifyUnavailable is returned by EventRing.NewWaiter when the ring
// has no notification eventfd. Consumers should then fall back to polling
// the ring on a timer.
var ErrRingNotifyUnavailable = errors.New("event ring has no notification fd")

// RingWaiter lets the single consumer of an EventRing sleep until the Zig
// CQ poller signals that it pushed new events, instead of polling the ring
// on a timer. It wraps a dup of the ring's eventfd in an *os.File, which the
// Go runtime registers with its netpoller: a blocked Wait parks only the
// goroutine, not an OS thread, and costs no CPU while the ring is idle.
//
// The producer increments the eventfd after pushing events, and Wait resets
// it. Because the counter persists until read, the consumer pattern
//
//	for {
//		events := ring.Poll(n)
//		if len(events) == 0 {
//			if err := waiter.Wait(); err != nil { return }
//			continue
//		}
//		...
//	}
//
// never sleeps through an event: a push that races with an empty Poll leaves
// the counter non-zero, so the following Wait returns immediately.
type RingWaiter struct {
	f   *os.File
	buf [8]byte
}

// NewWaiter returns a RingWaiter for this ring. It returns
// ErrRingNotifyUnavailable (wrapped) when the ring has no eventfd. The
// waiter owns its own fd and stays valid after the ring is destroyed (Wait
// then simply never returns until Close).
func (ring *EventRing) NewWaiter() (*RingWaiter, error) {
	if ring.handle == nil {
		return nil, fmt.Errorf("event ring destroyed: %w", ErrRingNotifyUnavailable)
	}
	fd := ring.notifyFD()
	if fd < 0 {
		return nil, ErrRingNotifyUnavailable
	}
	// Dup so that closing the waiter never closes the ring's fd (and vice
	// versa). The eventfd was created with EFD_NONBLOCK; that status flag is
	// shared by the dup, which is what makes os.NewFile use the netpoller.
	dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dup event ring notify fd: %w", err)
	}
	return &RingWaiter{f: os.NewFile(uintptr(dupFD), "rdma-event-ring")}, nil
}

// notifyFD returns the ring-owned eventfd, or -1 if there is none.
func (ring *EventRing) notifyFD() int {
	return int(C.rdma_event_ring_notify_fd(ring.handle))
}

// Wait blocks until the producer has signalled at least once since the
// previous Wait returned, then returns nil. After Close it returns a
// non-nil error (os.ErrClosed), including for a Wait already blocked when
// Close was called. Wait must not be called concurrently with itself.
func (w *RingWaiter) Wait() error {
	_, err := w.f.Read(w.buf[:])
	return err
}

// Close releases the waiter's fd and unblocks a pending Wait. It is safe to
// call concurrently with Wait and more than once.
func (w *RingWaiter) Close() error {
	return w.f.Close()
}
