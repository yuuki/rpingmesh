package main

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/yuuki/rpingmesh/internal/buildinfo"
	"github.com/yuuki/rpingmesh/internal/config"
)

func TestRootCommandVersion(t *testing.T) {
	cmd := newRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, want := buf.String(), "rpingmesh-controller version "+buildinfo.Version+"\n"; got != want {
		t.Fatalf("--version output = %q, want %q", got, want)
	}
}

// TestBuildServerOptions_PlaintextByDefault verifies that tls_mode disabled
// (explicit or empty) yields a plaintext server with no options.
func TestBuildServerOptions_PlaintextByDefault(t *testing.T) {
	for _, mode := range []string{"", config.TLSModeDisabled} {
		opts, err := buildServerOptions(&config.ControllerConfig{TLSMode: mode})
		if err != nil {
			t.Errorf("tls_mode=%q: unexpected error: %v", mode, err)
		}
		if len(opts) != 0 {
			t.Errorf("tls_mode=%q: got %d server options, want 0", mode, len(opts))
		}
	}
}

// TestBuildServerOptions_TLSWithoutCertFails verifies that a TLS mode without
// usable certificate files is reported as an error rather than ignored.
func TestBuildServerOptions_TLSWithoutCertFails(t *testing.T) {
	_, err := buildServerOptions(&config.ControllerConfig{TLSMode: config.TLSModeTLS})
	if err == nil {
		t.Fatal("expected an error for tls_mode=tls without certificate files")
	}
}

type fakeCleaner struct {
	calls atomic.Int32
	done  chan struct{}
}

func (f *fakeCleaner) CleanupStaleEntries(context.Context) error {
	if f.calls.Add(1) == 1 {
		close(f.done)
	}
	return errors.New("cleanup failed") // logged, must not stop the loop
}

// TestRunStaleEntryCleanup verifies the loop ticks, survives a cleanup error
// and exits when its context is cancelled.
func TestRunStaleEntryCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleaner := &fakeCleaner{done: make(chan struct{})}
	stopped := make(chan struct{})
	go func() {
		runStaleEntryCleanup(ctx, cleaner, time.Millisecond)
		close(stopped)
	}()

	select {
	case <-cleaner.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup was not invoked")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup loop did not stop after cancel")
	}
}

// TestWaitForShutdown_ServeErrorReturned verifies that a gRPC serve error ends
// the wait and is returned unchanged.
func TestWaitForShutdown_ServeErrorReturned(t *testing.T) {
	want := errors.New("serve failed")
	errCh := make(chan error, 1)
	errCh <- want

	if got := waitForShutdown(grpc.NewServer(), errCh); !errors.Is(got, want) {
		t.Fatalf("waitForShutdown() = %v, want %v", got, want)
	}
}
