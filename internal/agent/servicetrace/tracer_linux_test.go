//go:build linux

package servicetrace

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestTracerOpenClose loads the embedded eBPF objects into the running
// kernel, attaches them to the uverbs entry points, reads nothing and tears
// everything down. It needs root (CAP_BPF, CAP_PERFMON), kernel BTF and the
// ib_uverbs module, so it skips on an ordinary developer host and runs in
// the privileged e2e container and in CI under sudo.
func TestTracerOpenClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
	if _, err := os.Stat(vmlinuxBTF); err != nil {
		t.Skip("kernel BTF is not available")
	}

	tr, err := Open()
	if errors.Is(err, ErrNoUverbs) {
		t.Skipf("ib_uverbs is not loaded: %v", err)
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr.Start(ctx, func(Event) {})

	if s := tr.Stats(); s.Events != 0 || s.RingBufferDropped != 0 || s.ParseErrors != 0 {
		t.Errorf("fresh tracer stats = %+v, want zeros", s)
	}

	// Close must unblock the reader and be idempotent.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := tr.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if err := tr.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return within 10s")
	}
}
