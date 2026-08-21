package agent

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitStopAfterRunningCleared is the shared Stop contract: a sibling has
// already stored running=false (as ctx.Done used to) and is still in-flight.
// Stop must join that sibling even though CAS on running fails. The barrier
// makes the "running already false" precondition deterministic; a sleep
// before Stop would let the old CAS-skip-Wait implementation pass when the
// scheduler delayed the sibling's Store(false).
func waitStopAfterRunningCleared(t *testing.T, running *atomic.Bool, wg *sync.WaitGroup, stop func()) {
	t.Helper()

	cleared := make(chan struct{})
	var siblingExited atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		running.Store(false)
		close(cleared)
		time.Sleep(150 * time.Millisecond)
		siblingExited.Store(true)
	}()
	<-cleared

	done := make(chan struct{})
	go func() {
		stop()
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

// TestProber_StopWaitsAfterRunningCleared reproduces the shutdown race where
// a loop observes ctx.Done, stores running=false, and returns while a sibling
// goroutine is still in-flight. Stop used to CAS-fail and skip wg.Wait, so
// Destroy could free the queue under that sibling. Stop must join remaining
// goroutines even when running is already false.
func TestProber_StopWaitsAfterRunningCleared(t *testing.T) {
	p := &Prober{
		stopCh: make(chan struct{}),
	}
	p.running.Store(true)
	waitStopAfterRunningCleared(t, &p.running, &p.wg, p.Stop)
}

// TestResponder_StopWaitsAfterRunningCleared is the same contract for the
// responder: ctx.Done may clear running while processLoop is still unwinding
// an in-flight ACK send.
func TestResponder_StopWaitsAfterRunningCleared(t *testing.T) {
	r := &Responder{
		stopCh: make(chan struct{}),
	}
	r.running.Store(true)
	waitStopAfterRunningCleared(t, &r.running, &r.wg, r.Stop)
}
