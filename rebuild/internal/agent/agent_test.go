// Package agent tests for Agent's multi-device wiring: one Prober and one
// ClusterMonitor per opened RDMA device (see agent.go's createClusterMonitors
// and createResultsFanIn), so that every RNIC on a multi-rail host actively
// probes instead of only the first one.
//
// These tests avoid rdmabridge.Init()/OpenDevice()/CreateQueue(), which
// require real RDMA hardware or soft-RoCE, by constructing bare *Device and
// *Prober values directly (mirroring newTestProber() in
// cluster_monitor_test.go) and exercising the pure-Go wiring logic in
// isolation.
package agent

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
)

// fakeDevice builds a *rdmabridge.Device carrying only the metadata the
// agent-level wiring logic reads (GID, DeviceName). It never touches the
// zero-valued Cgo handles, so it is safe to use without a real RDMA context.
func fakeDevice(deviceName, gid string) *rdmabridge.Device {
	return &rdmabridge.Device{
		Info: rdmabridge.DeviceInfo{
			DeviceName: deviceName,
			GID:        gid,
			IPAddr:     "10.200.0." + gid,
		},
	}
}

// fakeProber builds a *Prober with only the fields exercised by the tests
// below (logger and resultChan) populated, bypassing NewProber (which
// requires a real RDMA device and queue).
func fakeProber(resultChanBuf int) *Prober {
	return &Prober{
		logger:     zerolog.Nop(),
		resultChan: make(chan *probe.ProbeResult, resultChanBuf),
	}
}

// newTestAgent builds an Agent with the given fake devices and probers
// wired in, for use by tests that exercise createClusterMonitors and
// createResultsFanIn without initializing any real RDMA resources.
func newTestAgent(devices []*rdmabridge.Device, probers []*Prober) *Agent {
	return &Agent{
		cfg: &config.AgentConfig{
			AgentID:                   "agent-1",
			TorID:                     "tor-1",
			PinglistUpdateIntervalSec: 3600,
		},
		devices: devices,
		probers: probers,
		logger:  zerolog.Nop(),
	}
}

func TestAgent_CreateClusterMonitors_OnePerDeviceWithMatchingRequesterGID(t *testing.T) {
	devices := []*rdmabridge.Device{
		fakeDevice("rxe0", "gid-0"),
		fakeDevice("rxe1", "gid-1"),
	}
	probers := []*Prober{fakeProber(1), fakeProber(1)}

	a := newTestAgent(devices, probers)
	a.createClusterMonitors()

	if len(a.monitors) != 2 {
		t.Fatalf("expected 2 cluster monitors (one per device), got %d", len(a.monitors))
	}

	for i, dev := range devices {
		monitor := a.monitors[i]
		if monitor.requesterGID != dev.Info.GID {
			t.Errorf("monitor[%d].requesterGID = %q, want device GID %q", i, monitor.requesterGID, dev.Info.GID)
		}
		if monitor.prober != probers[i] {
			t.Errorf("monitor[%d].prober is not wired to probers[%d]", i, i)
		}
	}

	// The two monitors must use distinct requester GIDs, matching the two
	// distinct devices -- this is the core multi-rail fix: every RNIC
	// requests its own pinglist instead of all devices sharing devices[0]'s
	// GID.
	if a.monitors[0].requesterGID == a.monitors[1].requesterGID {
		t.Errorf("expected distinct requester GIDs per device, both monitors use %q", a.monitors[0].requesterGID)
	}
}

func TestAgent_CreateResultsFanIn_MergesResultsFromEveryProber(t *testing.T) {
	probers := []*Prober{fakeProber(4), fakeProber(4)}
	a := newTestAgent(nil, probers)

	a.createResultsFanIn()

	// Emit one distinguishable result from each prober directly onto its
	// resultChan (emitResult is unexported but same-package, matching the
	// production emission path in prober.go).
	probers[0].emitResult(&probe.ProbeResult{SequenceNum: 100})
	probers[1].emitResult(&probe.ProbeResult{SequenceNum: 200})

	seen := map[uint64]bool{}
	for i := 0; i < 2; i++ {
		select {
		case result := <-a.results:
			seen[result.SequenceNum] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for fan-in result %d", i)
		}
	}

	if !seen[100] || !seen[200] {
		t.Fatalf("expected fan-in to deliver results from both probers, got %v", seen)
	}
}

func TestAgent_StopResultsFanIn_ClosesSharedChannelAfterAllProbersDestroyed(t *testing.T) {
	probers := []*Prober{fakeProber(1), fakeProber(1)}
	a := newTestAgent(nil, probers)

	a.createResultsFanIn()

	// Destroy() is safe on a bare fake Prober: Stop() is a no-op because
	// running was never set true (no goroutines were started), so
	// destroyOnce only closes resultChan and skips the nil queue teardown --
	// mirroring what Agent.Stop does to every real prober. Per
	// stopResultsFanIn's contract, this must happen before calling it so
	// every fan-in goroutine's range loop can observe the closed source
	// channel.
	for _, p := range probers {
		p.Destroy()
	}

	done := make(chan struct{})
	go func() {
		a.stopResultsFanIn()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopResultsFanIn did not return within 2s after all probers were destroyed")
	}

	select {
	case result, ok := <-a.results:
		if ok {
			t.Fatalf("expected a.results to be closed with no pending data, got result: %+v", result)
		}
	default:
		t.Fatal("expected a.results to already be closed once stopResultsFanIn returned")
	}
}

// TestAgent_StopResultsFanIn_NoConsumer_DoesNotDeadlock reproduces the
// scenario a review of PR #31 flagged: when metrics are disabled (or
// MetricsCollector creation failed), Start never drains a.results. If a
// fan-in goroutine has no way to abandon a blocked send once a.results
// fills up, stopResultsFanIn (called from Agent.Stop) would hang forever
// waiting on resultsWg, leaking the goroutine and every buffered result.
// createResultsFanIn's select on resultsDone must let it return promptly
// regardless.
func TestAgent_StopResultsFanIn_NoConsumer_DoesNotDeadlock(t *testing.T) {
	// More results than a.results' buffer (resultChanSize) can hold, so at
	// least one forwarded result is guaranteed to overflow it and block the
	// fan-in goroutine's send with nothing there to drain it.
	const overflow = resultChanSize + 8

	prober := fakeProber(overflow)
	a := newTestAgent(nil, []*Prober{prober})

	a.createResultsFanIn()

	for i := 0; i < overflow; i++ {
		prober.emitResult(&probe.ProbeResult{SequenceNum: uint64(i)})
	}

	// Nothing ever reads from a.results in this test: no metrics result
	// consumer, matching the metrics-disabled/unavailable scenario.
	prober.Destroy()

	done := make(chan struct{})
	go func() {
		a.stopResultsFanIn()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stopResultsFanIn deadlocked with no consumer draining a.results: " +
			"the fan-in goroutine could not abandon a blocked send")
	}
}
