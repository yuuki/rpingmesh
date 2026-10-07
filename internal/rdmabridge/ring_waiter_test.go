package rdmabridge

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// signalRing plays the Zig producer's notify(): it adds 1 to the ring's
// eventfd counter.
func signalRing(t *testing.T, ring *EventRing) {
	t.Helper()
	fd := ring.notifyFD()
	if fd < 0 {
		t.Fatal("ring has no notify fd")
	}
	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	if _, err := unix.Write(fd, one[:]); err != nil {
		t.Fatalf("write eventfd: %v", err)
	}
}

func newTestRingWaiter(t *testing.T) (*EventRing, *RingWaiter) {
	t.Helper()
	ring, err := NewEventRing(16)
	if err != nil {
		t.Fatalf("NewEventRing: %v", err)
	}
	t.Cleanup(ring.Destroy)
	w, err := ring.NewWaiter()
	if err != nil {
		t.Fatalf("NewWaiter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return ring, w
}

func TestRingWaiterWakesOnSignal(t *testing.T) {
	ring, w := newTestRingWaiter(t)

	done := make(chan error, 1)
	go func() { done <- w.Wait() }()

	select {
	case err := <-done:
		t.Fatalf("Wait returned before any signal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	signalRing(t, ring)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after signal")
	}
}

func TestRingWaiterSignalBeforeWaitIsNotLost(t *testing.T) {
	ring, w := newTestRingWaiter(t)

	// Several notifications before the consumer waits coalesce into one
	// pending wakeup, and Wait consumes it without blocking.
	signalRing(t, ring)
	signalRing(t, ring)
	done := make(chan error, 1)
	go func() { done <- w.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending signal was lost")
	}

	// The read reset the counter: the next Wait blocks again.
	go func() { done <- w.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("Wait returned without a new signal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = w.Close()
	<-done
}

func TestRingWaiterCloseUnblocksWait(t *testing.T) {
	_, w := newTestRingWaiter(t)

	done := make(chan error, 1)
	go func() { done <- w.Wait() }()
	time.Sleep(20 * time.Millisecond)

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Wait after Close = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Wait")
	}
	// A second Close is harmless.
	_ = w.Close()
}

func TestRingWaiterOutlivesRing(t *testing.T) {
	ring, err := NewEventRing(16)
	if err != nil {
		t.Fatalf("NewEventRing: %v", err)
	}
	w, err := ring.NewWaiter()
	if err != nil {
		t.Fatalf("NewWaiter: %v", err)
	}
	ring.Destroy()

	if _, err := ring.NewWaiter(); !errors.Is(err, ErrRingNotifyUnavailable) {
		t.Fatalf("NewWaiter on destroyed ring = %v, want ErrRingNotifyUnavailable", err)
	}
	// The waiter's dup keeps its fd valid; Close still unblocks it.
	done := make(chan error, 1)
	go func() { done <- w.Wait() }()
	_ = w.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Wait after ring destroy")
	}
}
