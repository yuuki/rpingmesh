package agent

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestProber_StopWaitsAfterRunningCleared reproduces the shutdown race where
// a loop observes ctx.Done, stores running=false, and returns while a sibling
// goroutine is still in-flight. Stop used to CAS-fail and skip wg.Wait, so
// Destroy could free the queue under that sibling. Stop must join remaining
// goroutines even when running is already false.
func TestProber_StopWaitsAfterRunningCleared(t *testing.T) {
	p := &Prober{
		logger: zerolog.Nop(),
		stopCh: make(chan struct{}),
	}
	p.running.Store(true)
	p.wg.Add(1)

	var siblingExited atomic.Bool
	go func() {
		defer p.wg.Done()
		// Simulate ctx.Done in one loop: drop the running flag before the
		// sibling has finished (the other loop is this goroutine).
		p.running.Store(false)
		time.Sleep(150 * time.Millisecond)
		siblingExited.Store(true)
	}()

	// Let the goroutine store running=false before Stop runs.
	time.Sleep(30 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()

	select {
	case <-done:
		if !siblingExited.Load() {
			t.Fatal("Stop returned before the remaining goroutine finished")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return")
	}
}

// TestResponder_StopWaitsAfterRunningCleared is the same contract for the
// responder: ctx.Done may clear running while processLoop is still unwinding
// an in-flight ACK send.
func TestResponder_StopWaitsAfterRunningCleared(t *testing.T) {
	r := &Responder{
		logger: zerolog.Nop(),
		stopCh: make(chan struct{}),
	}
	r.running.Store(true)
	r.wg.Add(1)

	var siblingExited atomic.Bool
	go func() {
		defer r.wg.Done()
		r.running.Store(false)
		time.Sleep(150 * time.Millisecond)
		siblingExited.Store(true)
	}()

	time.Sleep(30 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		r.Stop()
		close(done)
	}()

	select {
	case <-done:
		if !siblingExited.Load() {
			t.Fatal("Stop returned before the remaining goroutine finished")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return")
	}
}
