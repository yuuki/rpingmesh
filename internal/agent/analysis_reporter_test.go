package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// fakeSender records ReportProbeAnalysis calls and can be scripted to error.
type fakeSender struct {
	mu      sync.Mutex
	reports []*controller_agent.ProbeAnalysisReport
	err     error
}

func (f *fakeSender) ReportProbeAnalysis(
	_ context.Context, report *controller_agent.ProbeAnalysisReport,
) (*controller_agent.ProbeAnalysisAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, report)
	if f.err != nil {
		return nil, f.err
	}
	return &controller_agent.ProbeAnalysisAck{Accepted: true}, nil
}

func (f *fakeSender) allSummaries() []*controller_agent.PathSummary {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*controller_agent.PathSummary
	for _, r := range f.reports {
		out = append(out, r.GetSummaries()...)
	}
	return out
}

func (f *fakeSender) reportCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reports)
}

// validProbeResult builds a Success result whose 6 timestamps yield a valid,
// positive NetworkRTT, so it aggregates into probe_success with an RTT sample.
func validProbeResult(src, tgt [16]byte, tor string, qpn uint32) *probe.ProbeResult {
	return &probe.ProbeResult{
		SourceGID:   src,
		TargetGID:   tgt,
		TargetTorID: tor,
		TargetQPN:   qpn,
		Success:     true,
		T1:          1000,
		T2:          2000,
		T3:          3000,
		T4:          3500,
		T5:          4500, // NetworkRTT = (4500-2000)-500 = 2000ns
		T6:          4600,
	}
}

func srcGID(b byte) [16]byte {
	var g [16]byte
	g[15] = b
	return g
}

// TestAnalysisReporter_FinalFlushOnInputClose verifies that closing the input
// channel (what Agent.stopResultsFanIn does at shutdown) makes the reporter
// flush its in-progress window and exit. A long window ensures the periodic
// ticker never fires, so the report we observe comes solely from the final
// flush.
func TestAnalysisReporter_FinalFlushOnInputClose(t *testing.T) {
	fake := &fakeSender{}
	input := make(chan *probe.ProbeResult, 4)
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 3600, input)
	r.Start(context.Background())

	src, tgt := srcGID(1), srcGID(2)
	input <- validProbeResult(src, tgt, "tor-b", 42)
	input <- validProbeResult(src, tgt, "tor-b", 42)
	close(input)

	r.Wait()

	summaries := fake.allSummaries()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary from final flush, got %d", len(summaries))
	}
	s := summaries[0]
	if s.GetProbeTotal() != 2 || s.GetProbeSuccess() != 2 {
		t.Errorf("summary counts: total=%d success=%d, want 2/2", s.GetProbeTotal(), s.GetProbeSuccess())
	}
	// source_tor is stamped by the reporter (the aggregator does not carry it).
	if s.GetSourceTorId() != "tor-a" {
		t.Errorf("SourceTorId = %q, want tor-a", s.GetSourceTorId())
	}
	if s.GetTargetTorId() != "tor-b" || s.GetTargetQpn() != 42 {
		t.Errorf("target metadata: tor=%q qpn=%d", s.GetTargetTorId(), s.GetTargetQpn())
	}
	if s.GetSourceGid() == "" || s.GetTargetGid() == "" {
		t.Errorf("GIDs not formatted onto proto summary")
	}
}

func TestAnalysisReporter_MapsEmptyTorLabels(t *testing.T) {
	fake := &fakeSender{}
	input := make(chan *probe.ProbeResult, 4)
	r := NewAnalysisReporter(fake, "agent-1", "", 3600, input)
	r.Start(context.Background())

	src, tgt := srcGID(1), srcGID(2)
	input <- validProbeResult(src, tgt, "", 42)
	close(input)
	r.Wait()

	summaries := fake.allSummaries()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]
	if s.GetSourceTorId() != probe.UnspecifiedTorLabel {
		t.Errorf("SourceTorId = %q, want %s", s.GetSourceTorId(), probe.UnspecifiedTorLabel)
	}
	if s.GetTargetTorId() != probe.UnspecifiedTorLabel {
		t.Errorf("TargetTorId = %q, want %s", s.GetTargetTorId(), probe.UnspecifiedTorLabel)
	}
}

// TestAnalysisReporter_CtxCancelAloneDoesNotStop verifies the shutdown
// contract: the reporter does NOT exit on ctx cancellation; it exits only when
// its input channel is closed. On a signal stop the ctx is cancelled before the
// fan-in is torn down, so exiting on ctx would drop the last results still
// draining out of the fan-in.
func TestAnalysisReporter_CtxCancelAloneDoesNotStop(t *testing.T) {
	fake := &fakeSender{}
	input := make(chan *probe.ProbeResult, 4)
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 3600, input)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	cancel()

	// The reporter must still be running: Wait must not return on ctx cancel.
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("reporter exited on ctx cancellation; it must exit only when input closes")
	case <-time.After(200 * time.Millisecond):
		// Expected: still running.
	}

	// Closing the input is the only thing that stops it.
	close(input)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reporter did not stop after input closed")
	}
}

// TestAnalysisReporter_SignalStopFlushesResultsAfterCtxCancel reproduces the
// signal-stop ordering the reporter must survive: cmd/agent cancels the Start
// context first, and only afterward does Agent.Stop tear down the probers and
// fan-in, pushing the last results and finally closing the input. Those
// post-cancel results must be aggregated into the final window AND actually
// sent, even though ctx is already cancelled.
func TestAnalysisReporter_SignalStopFlushesResultsAfterCtxCancel(t *testing.T) {
	fake := &fakeSender{}
	input := make(chan *probe.ProbeResult, 8)
	// Long window so the periodic ticker never fires: the only send is the
	// final flush, making the assertion unambiguous.
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 3600, input)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// Signal stop: context is cancelled FIRST...
	cancel()

	// ...then the fan-in's final results arrive (as probers are stopped), and
	// only then is the input closed by stopResultsFanIn.
	src, tgt := srcGID(1), srcGID(2)
	input <- validProbeResult(src, tgt, "tor-b", 42)
	input <- validProbeResult(src, tgt, "tor-b", 42)
	input <- validProbeResult(src, tgt, "tor-b", 42)
	close(input)

	r.Wait()

	// All three post-cancel results must be in the final window and delivered.
	summaries := fake.allSummaries()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 final summary, got %d (post-cancel results were dropped)", len(summaries))
	}
	if got := summaries[0].GetProbeTotal(); got != 3 {
		t.Errorf("final summary ProbeTotal = %d, want 3 (all post-cancel results aggregated)", got)
	}
	if fake.reportCount() != 1 {
		t.Errorf("final flush was not sent despite cancelled ctx: reportCount = %d, want 1", fake.reportCount())
	}
}

// TestAnalysisReporter_ReportBestEffortOnError verifies a send error is
// swallowed (best-effort), not propagated or panicking.
func TestAnalysisReporter_ReportBestEffortOnError(t *testing.T) {
	fake := &fakeSender{err: errors.New("controller down")}
	input := make(chan *probe.ProbeResult, 4)
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 3600, input)
	r.Start(context.Background())

	input <- validProbeResult(srcGID(1), srcGID(2), "tor-b", 1)
	close(input)
	r.Wait() // must return despite the send error

	if fake.reportCount() != 1 {
		t.Errorf("expected 1 (failed) report attempt, got %d", fake.reportCount())
	}
}

// TestAnalysisReporter_PeriodicSkippedAfterCancelRecoveredByFinalFlush verifies
// the fix for the periodic-send-after-cancel data loss: once ctx is cancelled,
// a periodic collection is skipped entirely, so its completed windows are NOT
// removed from the aggregator by a Collect whose send would then fail on the
// cancelled ctx. The windows survive in the aggregator and are delivered by the
// final flush (independent context) instead.
func TestAnalysisReporter_PeriodicSkippedAfterCancelRecoveredByFinalFlush(t *testing.T) {
	fake := &fakeSender{}
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 1, nil) // 1s windows

	// Aggregate two results into window [0, 1e9); pin nowFn past that window so
	// a periodic Collect would consider it complete (and would remove it).
	src, tgt := srcGID(1), srcGID(2)
	r.agg.AddResult(validProbeResult(src, tgt, "tor-b", 42), 0)
	r.agg.AddResult(validProbeResult(src, tgt, "tor-b", 42), 0)
	r.nowFn = func() time.Time { return time.Unix(2, 0) } // 2s: window [0,1s) is complete

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown has begun

	// Periodic collection under a cancelled ctx must be a no-op: nothing sent,
	// and the completed window must remain in the aggregator (not consumed by a
	// Collect that would then fail to send).
	r.collectAndReport(ctx)
	if fake.reportCount() != 0 {
		t.Fatalf("periodic report ran under cancelled ctx (reportCount=%d, want 0): "+
			"its Collected window would be lost", fake.reportCount())
	}

	// The final flush (independent context) must recover and send the window.
	r.flushFinal()
	summaries := fake.allSummaries()
	if len(summaries) != 1 {
		t.Fatalf("final flush did not recover the window: got %d summaries, want 1", len(summaries))
	}
	if got := summaries[0].GetProbeTotal(); got != 2 {
		t.Errorf("recovered summary ProbeTotal=%d, want 2", got)
	}
}

// TestAnalysisReporter_PeriodicCollectsWhenLive is the positive control for the
// test above: with a live (non-cancelled) ctx, a periodic collection DOES
// harvest and send the completed window, confirming the skip is specifically
// gated on ctx cancellation.
func TestAnalysisReporter_PeriodicCollectsWhenLive(t *testing.T) {
	fake := &fakeSender{}
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 1, nil)

	src, tgt := srcGID(1), srcGID(2)
	r.agg.AddResult(validProbeResult(src, tgt, "tor-b", 42), 0)
	r.nowFn = func() time.Time { return time.Unix(2, 0) } // window [0,1s) complete

	r.collectAndReport(context.Background()) // live ctx: must collect + send
	r.sendWg.Wait()                          // the send runs on its own goroutine
	if fake.reportCount() != 1 {
		t.Fatalf("live periodic report did not send: reportCount=%d, want 1", fake.reportCount())
	}
	if summaries := fake.allSummaries(); len(summaries) != 1 || summaries[0].GetProbeTotal() != 1 {
		t.Fatalf("live periodic report sent wrong data: %+v", summaries)
	}
}

// TestAnalysisReporter_BatchSplitting verifies that more than
// maxSummariesPerReport summaries are split across multiple bounded reports.
func TestAnalysisReporter_BatchSplitting(t *testing.T) {
	fake := &fakeSender{}
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 30, nil)

	n := maxSummariesPerReport + 5
	summaries := make([]probe.PathSummary, n)
	for i := range summaries {
		summaries[i] = probe.PathSummary{
			SourceGID:   srcGID(1),
			TargetGID:   srcGID(byte(i%200 + 1)),
			TargetTorID: "tor-b",
			ProbeTotal:  1,
		}
	}
	r.report(context.Background(), summaries)

	if fake.reportCount() != 2 {
		t.Errorf("expected 2 reports for %d summaries (cap %d), got %d",
			n, maxSummariesPerReport, fake.reportCount())
	}
	if got := len(fake.allSummaries()); got != n {
		t.Errorf("total summaries across reports = %d, want %d", got, n)
	}
}

// TestAnalysisReporter_PerResultSourceTorWins verifies that a source ToR
// stamped on the results (per-device ToRs) overrides the reporter default.
func TestAnalysisReporter_PerResultSourceTorWins(t *testing.T) {
	fake := &fakeSender{}
	input := make(chan *probe.ProbeResult, 4)
	r := NewAnalysisReporter(fake, "agent-1", "host-tor", 3600, input)
	r.Start(context.Background())

	res := validProbeResult(srcGID(1), srcGID(2), "tor-b", 42)
	res.SourceTorID = "leaf-a"
	input <- res
	close(input)
	r.Wait()

	summaries := fake.allSummaries()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if got := summaries[0].GetSourceTorId(); got != "leaf-a" {
		t.Errorf("SourceTorId = %q, want leaf-a", got)
	}
}

// TestAnalysisReporter_PinglistTypeMappedToProto verifies that the pinglist
// type of each summary reaches the controller, converted by value to the
// proto enum, so the analyzer can evaluate service paths apart from cluster
// ones.
func TestAnalysisReporter_PinglistTypeMappedToProto(t *testing.T) {
	fake := &fakeSender{}
	input := make(chan *probe.ProbeResult, 4)
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 3600, input)
	r.Start(context.Background())

	input <- validProbeResult(srcGID(1), srcGID(2), "tor-b", 42)
	service := validProbeResult(srcGID(1), srcGID(2), "tor-b", 42)
	service.PinglistType = probe.PinglistServiceTracing
	input <- service
	inter := validProbeResult(srcGID(1), srcGID(3), "tor-c", 43)
	inter.PinglistType = probe.PinglistInterTor
	input <- inter
	close(input)
	r.Wait()

	got := map[controller_agent.PinglistType]int{}
	for _, s := range fake.allSummaries() {
		got[s.GetPinglistType()]++
	}
	want := map[controller_agent.PinglistType]int{
		controller_agent.PinglistType_TOR_MESH:        1,
		controller_agent.PinglistType_SERVICE_TRACING: 1,
		controller_agent.PinglistType_INTER_TOR:       1,
	}
	for typ, n := range want {
		if got[typ] != n {
			t.Errorf("summaries of type %s = %d, want %d (all: %v)", typ, got[typ], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("summary types = %v, want exactly %v", got, want)
	}
}

// TestPinglistTypeMirrorsProto pins the by-value conversion between
// probe.PinglistType and the proto enum that fillTargetMetadata and the
// reporter's toProto rely on.
func TestPinglistTypeMirrorsProto(t *testing.T) {
	for _, tc := range []struct {
		p     probe.PinglistType
		proto controller_agent.PinglistType
	}{
		{probe.PinglistTorMesh, controller_agent.PinglistType_TOR_MESH},
		{probe.PinglistInterTor, controller_agent.PinglistType_INTER_TOR},
		{probe.PinglistServiceTracing, controller_agent.PinglistType_SERVICE_TRACING},
	} {
		if int32(tc.p) != int32(tc.proto) {
			t.Errorf("probe.%s = %d, proto %s = %d; values must match", tc.p, tc.p, tc.proto, tc.proto)
		}
	}
}

// TestAnalysisReporter_DropsServiceSummariesWhenControllerLacksSupport covers
// a controller downgrade: service results were aggregated while the
// controller evaluated them apart, then a heartbeat learned of an older
// controller. The flag is re-checked at send time, so the service summary is
// dropped instead of being judged as a cluster path, while the cluster
// summary of the same window is still sent.
func TestAnalysisReporter_DropsServiceSummariesWhenControllerLacksSupport(t *testing.T) {
	fake := &fakeSender{}
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 30, nil)
	var supported atomic.Bool
	supported.Store(true)
	r.SetServiceSummariesAllowed(supported.Load)

	src, tgt := srcGID(1), srcGID(2)
	service := validProbeResult(src, tgt, "tor-b", 42)
	service.PinglistType = probe.PinglistServiceTracing
	r.agg.AddResult(validProbeResult(src, tgt, "tor-b", 42), 0)
	r.agg.AddResult(service, 0)

	supported.Store(false) // the controller was downgraded
	r.flushFinal()
	summaries := fake.allSummaries()
	if len(summaries) != 1 || summaries[0].GetPinglistType() != controller_agent.PinglistType_TOR_MESH {
		t.Fatalf("summaries sent = %+v, want only the cluster summary", summaries)
	}

	// Only service summaries aggregated: nothing is sent at all.
	r.agg.AddResult(service, 0)
	r.flushFinal()
	if fake.reportCount() != 1 {
		t.Errorf("reportCount = %d, want 1 (a report of only dropped summaries must not be sent)", fake.reportCount())
	}

	// Supported again (controller upgraded): service summaries flow.
	supported.Store(true)
	r.agg.AddResult(service, 0)
	r.flushFinal()
	if got := fake.allSummaries(); len(got) != 2 || got[1].GetPinglistType() != controller_agent.PinglistType_SERVICE_TRACING {
		t.Errorf("summaries after re-enable = %+v, want the service summary added", got)
	}
}

// blockingSender holds every ReportProbeAnalysis call until release is closed.
type blockingSender struct {
	*fakeSender
	release chan struct{}
}

func (b *blockingSender) ReportProbeAnalysis(
	ctx context.Context, report *controller_agent.ProbeAnalysisReport,
) (*controller_agent.ProbeAnalysisAck, error) {
	<-b.release
	return b.fakeSender.ReportProbeAnalysis(ctx, report)
}

// TestAnalysisReporter_SlowSendDoesNotStallInput verifies that a periodic
// send blocked in its RPC does not stop the reporter from draining its input:
// results arriving during the send are aggregated. On the drain loop the send
// would leave the fan-in's non-blocking tee dropping results once the channel
// filled.
func TestAnalysisReporter_SlowSendDoesNotStallInput(t *testing.T) {
	fake := &blockingSender{fakeSender: &fakeSender{}, release: make(chan struct{})}
	input := make(chan *probe.ProbeResult, 2) // tiny buffer: a stalled loop blocks the sends below
	r := NewAnalysisReporter(fake, "agent-1", "tor-a", 3600, input)
	r.nowFn = func() time.Time { return time.Unix(7200, 0) } // window [0,3600s) is complete

	src, tgt := srcGID(1), srcGID(2)
	r.agg.AddResult(validProbeResult(src, tgt, "tor-b", 42), 0)
	r.collectAndReport(context.Background()) // the send now blocks in the RPC
	r.Start(context.Background())

	const n = 50
	deadline := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case input <- validProbeResult(src, tgt, "tor-b", 42):
		case <-deadline:
			t.Fatalf("input blocked after %d results while a send was in flight: the drain loop is stalled", i)
		}
	}

	// A tick while the send is still in flight must not collect: the
	// second window stays in the aggregator for the next collection.
	r.collectAndReport(context.Background())

	close(fake.release)
	close(input)
	r.Wait()

	if fake.reportCount() != 2 {
		t.Fatalf("reportCount = %d, want 2 (blocked periodic send + final flush)", fake.reportCount())
	}
	summaries := fake.allSummaries()
	if len(summaries) != 2 || summaries[1].GetProbeTotal() != n {
		t.Errorf("summaries = %+v, want the final window with ProbeTotal %d", summaries, n)
	}
}
