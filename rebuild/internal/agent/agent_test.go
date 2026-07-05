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
	a.metricsResultsActive = true // a metrics consumer will drain a.results

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

// TestAgent_CreateResultsFanIn_TeesToAnalysis verifies that, with analysis
// reporting enabled, every fan-in result is delivered to BOTH the metrics
// channel and the analysis branch (the tee), so the analyzer sees the same
// stream the metrics consumer does.
func TestAgent_CreateResultsFanIn_TeesToAnalysis(t *testing.T) {
	probers := []*Prober{fakeProber(4)}
	a := newTestAgent(nil, probers)
	a.cfg.AnalysisReportEnabled = true
	a.metricsResultsActive = true // a metrics consumer will drain a.results

	a.createResultsFanIn()

	if a.analysisResults == nil {
		t.Fatal("analysisResults channel not created when analysis enabled")
	}

	probers[0].emitResult(&probe.ProbeResult{SequenceNum: 7})

	// Metrics branch.
	select {
	case r := <-a.results:
		if r.SequenceNum != 7 {
			t.Errorf("metrics branch seq = %d, want 7", r.SequenceNum)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for result on metrics branch")
	}

	// Analysis branch (the tee).
	select {
	case r := <-a.analysisResults:
		if r.SequenceNum != 7 {
			t.Errorf("analysis branch seq = %d, want 7", r.SequenceNum)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for result on analysis branch")
	}
}

// TestAgent_CreateResultsFanIn_SlowAnalysisDoesNotStallMetrics verifies the
// key non-blocking contract: when the analysis branch backs up (nothing drains
// a.analysisResults, its buffer fills), the metrics path must still receive
// every result. The tee's analysis send is non-blocking (drops on a full
// buffer) precisely so a slow aggregator cannot stall metrics.
func TestAgent_CreateResultsFanIn_SlowAnalysisDoesNotStallMetrics(t *testing.T) {
	// More than the analysis branch buffer (resultChanSize) so it overflows.
	const total = resultChanSize + 100

	prober := fakeProber(total) // hold all emitted results without dropping
	a := newTestAgent(nil, []*Prober{prober})
	a.cfg.AnalysisReportEnabled = true
	a.metricsResultsActive = true // metrics consumer active; it drains a.results

	a.createResultsFanIn()

	// Nothing ever drains a.analysisResults: the aggregator is "stuck".
	for i := 0; i < total; i++ {
		prober.emitResult(&probe.ProbeResult{SequenceNum: uint64(i)})
	}
	prober.Destroy() // close Results() so the fan-in drains and eventually exits

	// The metrics branch must still receive all `total` results.
	got := 0
	timeout := time.After(5 * time.Second)
	for got < total {
		select {
		case _, ok := <-a.results:
			if !ok {
				t.Fatalf("metrics channel closed after %d results, want %d", got, total)
			}
			got++
		case <-timeout:
			t.Fatalf("slow analysis branch stalled metrics: only %d/%d results delivered", got, total)
		}
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

// TestAgent_StopResultsFanIn_ClosesAnalysisBranch verifies that shutting down
// the fan-in also closes the analysis branch (after every fan-in goroutine has
// exited), which is what ends the AnalysisReporter's run loop.
func TestAgent_StopResultsFanIn_ClosesAnalysisBranch(t *testing.T) {
	probers := []*Prober{fakeProber(1)}
	a := newTestAgent(nil, probers)
	a.cfg.AnalysisReportEnabled = true

	a.createResultsFanIn()
	for _, p := range probers {
		p.Destroy()
	}
	a.stopResultsFanIn()

	select {
	case _, ok := <-a.analysisResults:
		if ok {
			t.Fatal("expected analysisResults closed with no pending data")
		}
	default:
		t.Fatal("expected analysisResults to be closed after stopResultsFanIn")
	}
}

// TestAgent_StopResultsFanIn_NoConsumer_DoesNotDeadlock reproduces the
// scenario a review of PR #31 flagged: the metrics branch is active (so the
// fan-in forwards to a.results), but nothing is draining a.results at shutdown
// -- e.g. Stop is reached after the metrics result consumer has already
// stopped, or before Start ever ran it. If a fan-in goroutine had no way to
// abandon a blocked send once a.results fills up, stopResultsFanIn (called
// from Agent.Stop) would hang forever waiting on resultsWg, leaking the
// goroutine and every buffered result. createResultsFanIn's select on
// resultsDone must let it return promptly regardless.
func TestAgent_StopResultsFanIn_NoConsumer_DoesNotDeadlock(t *testing.T) {
	// More results than a.results' buffer (resultChanSize) can hold, so at
	// least one forwarded result is guaranteed to overflow it and block the
	// fan-in goroutine's send with nothing there to drain it.
	const overflow = resultChanSize + 8

	prober := fakeProber(overflow)
	a := newTestAgent(nil, []*Prober{prober})
	// Metrics branch active: the fan-in forwards to a.results, exercising the
	// resultsDone escape when nothing drains it.
	a.metricsResultsActive = true

	a.createResultsFanIn()

	for i := 0; i < overflow; i++ {
		prober.emitResult(&probe.ProbeResult{SequenceNum: uint64(i)})
	}

	// Nothing ever reads from a.results in this test: no metrics result
	// consumer is draining it.
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

// TestAgent_CreateResultsFanIn_NoMetricsConsumer_AnalysisStillFlows verifies
// the fix for the metrics/analysis coupling: when NO metrics consumer will
// drain a.results (metrics disabled, or MetricsCollector creation failed:
// a.metricsResultsActive == false) but analysis reporting IS enabled, the
// fan-in must keep delivering results to the analysis branch instead of
// blocking on a.results once its buffer fills.
//
// The emit-one/receive-one loop makes the check deterministic: a fan-in that
// (incorrectly) still forwarded to the undrained a.results would fill it after
// resultChanSize results and then block on the metrics send, so the analysis
// branch would stop receiving around that point. Because the loop runs well
// past resultChanSize, the fix (skip the a.results send when no consumer) is
// what lets every result reach analysis.
func TestAgent_CreateResultsFanIn_NoMetricsConsumer_AnalysisStillFlows(t *testing.T) {
	const total = resultChanSize + 50 // well past where a coupled fan-in would jam

	prober := fakeProber(total)
	a := newTestAgent(nil, []*Prober{prober})
	a.cfg.AnalysisReportEnabled = true
	a.metricsResultsActive = false // no metrics consumer will drain a.results

	a.createResultsFanIn()

	// Emit one, receive one. Draining each result before emitting the next
	// keeps the analysis buffer from filling (so nothing is dropped) and, more
	// importantly, proves flow continues past resultChanSize -- the point a
	// metrics-coupled fan-in would have jammed.
	for i := 0; i < total; i++ {
		prober.emitResult(&probe.ProbeResult{SequenceNum: uint64(i)})
		select {
		case <-a.analysisResults:
		case <-time.After(2 * time.Second):
			t.Fatalf("analysis stalled at result %d (past a.results buffer %d): "+
				"fan-in is coupled to the undrained metrics channel", i, resultChanSize)
		}
	}

	// Clean shutdown of the fan-in.
	prober.Destroy()
	a.stopResultsFanIn()
}
