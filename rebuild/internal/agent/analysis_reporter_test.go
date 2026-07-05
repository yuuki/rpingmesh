package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
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
