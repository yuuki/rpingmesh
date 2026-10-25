package analyzer

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func testConfig() Config {
	return Config{
		Cluster:         Thresholds{LossRatio: 0.02, NetworkRTTP99Ns: 500_000},
		Service:         Thresholds{LossRatio: 0.10, NetworkRTTP99Ns: 2_000_000},
		WindowRetention: 3,
	}
}

// serviceSummary is summary for a path of a traced service flow.
func serviceSummary(sourceTor, targetTor string, total, failed uint32, p99 uint64, windowStart uint64) *controller_agent.PathSummary {
	s := summary(sourceTor, targetTor, total, failed, p99, windowStart)
	s.PinglistType = controller_agent.PinglistType_SERVICE_TRACING
	return s
}

func summary(sourceTor, targetTor string, total, failed uint32, p99 uint64, windowStart uint64) *controller_agent.PathSummary {
	return &controller_agent.PathSummary{
		SourceGid:         "fe80::1",
		SourceTorId:       sourceTor,
		TargetGid:         "fe80::2",
		TargetTorId:       targetTor,
		ProbeTotal:        total,
		ProbeFailed:       failed,
		ProbeSuccess:      total - failed,
		NetworkRttP99Ns:   p99,
		WindowStartUnixNs: windowStart,
	}
}

func report(summaries ...*controller_agent.PathSummary) *controller_agent.ProbeAnalysisReport {
	return &controller_agent.ProbeAnalysisReport{
		AgentId:   "agent-1",
		Summaries: summaries,
	}
}

func TestAnalyzer_LossViolationThreshold(t *testing.T) {
	a := New(testConfig(), nil)
	ctx := context.Background()

	// loss = 2/100 = 0.02 == threshold: NOT a violation (strictly greater).
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 2, 0, 1))); v != 0 {
		t.Errorf("loss exactly at threshold: got %d violations, want 0", v)
	}
	// loss = 3/100 = 0.03 > 0.02: violation.
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 3, 0, 2))); v != 1 {
		t.Errorf("loss above threshold: got %d violations, want 1", v)
	}
	// loss = 1/100 = 0.01 < threshold: no violation.
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 1, 0, 3))); v != 0 {
		t.Errorf("loss below threshold: got %d violations, want 0", v)
	}
}

func TestAnalyzer_RTTViolationThreshold(t *testing.T) {
	a := New(testConfig(), nil)
	ctx := context.Background()

	// p99 == threshold: not a violation (strictly greater).
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 0, 500_000, 1))); v != 0 {
		t.Errorf("p99 at threshold: got %d, want 0", v)
	}
	// p99 above threshold: violation.
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 0, 500_001, 2))); v != 1 {
		t.Errorf("p99 above threshold: got %d, want 1", v)
	}
}

func TestAnalyzer_BothViolationsCountSummaryOnce(t *testing.T) {
	a := New(testConfig(), nil)
	ctx := context.Background()

	// A single summary breaching BOTH loss and RTT counts as one violating
	// summary (the ack reports violating summaries, not per-kind breaches).
	s := summary("tor-a", "tor-b", 100, 50, 1_000_000, 1)
	if v := a.Ingest(ctx, report(s)); v != 1 {
		t.Errorf("summary breaching both thresholds: got %d, want 1", v)
	}
}

func TestAnalyzer_RTTCheckDisabledWhenThresholdZero(t *testing.T) {
	cfg := testConfig()
	cfg.Cluster.NetworkRTTP99Ns = 0 // disable RTT check
	a := New(cfg, nil)

	// Huge p99 but no loss: with the RTT check disabled, no violation.
	if v := a.Ingest(context.Background(), report(summary("tor-a", "tor-b", 100, 0, 9_000_000, 1))); v != 0 {
		t.Errorf("RTT check disabled: got %d violations, want 0", v)
	}
}

// TestAnalyzer_ServiceSummariesUseServiceThresholds verifies that a
// SERVICE_TRACING summary is judged against the service-network thresholds
// and a cluster summary of the same path against the cluster ones, so a
// service flow's loss or RTT never trips (or hides behind) the cluster SLO.
func TestAnalyzer_ServiceSummariesUseServiceThresholds(t *testing.T) {
	a := New(testConfig(), nil)
	ctx := context.Background()

	// loss 0.05: above the cluster threshold (0.02), below the service one (0.10).
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 5, 0, 1))); v != 1 {
		t.Errorf("cluster loss 0.05: got %d violations, want 1", v)
	}
	if v := a.Ingest(ctx, report(serviceSummary("tor-a", "tor-b", 100, 5, 0, 1))); v != 0 {
		t.Errorf("service loss 0.05: got %d violations, want 0", v)
	}
	// loss 0.20: above both.
	if v := a.Ingest(ctx, report(serviceSummary("tor-a", "tor-b", 100, 20, 0, 1))); v != 1 {
		t.Errorf("service loss 0.20: got %d violations, want 1", v)
	}

	// p99 1 ms: above the cluster threshold (500 µs), below the service one (2 ms).
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 0, 1_000_000, 2))); v != 1 {
		t.Errorf("cluster p99 1ms: got %d violations, want 1", v)
	}
	if v := a.Ingest(ctx, report(serviceSummary("tor-a", "tor-b", 100, 0, 1_000_000, 2))); v != 0 {
		t.Errorf("service p99 1ms: got %d violations, want 0", v)
	}
	if v := a.Ingest(ctx, report(serviceSummary("tor-a", "tor-b", 100, 0, 2_000_001, 2))); v != 1 {
		t.Errorf("service p99 above threshold: got %d violations, want 1", v)
	}

	// Inter-ToR summaries are cluster paths too.
	inter := summary("tor-a", "tor-c", 100, 5, 0, 3)
	inter.PinglistType = controller_agent.PinglistType_INTER_TOR
	if v := a.Ingest(ctx, report(inter)); v != 1 {
		t.Errorf("inter-ToR loss 0.05: got %d violations, want 1", v)
	}
}

// TestAnalyzer_ServiceRTTCheckDisabledIndependently verifies that the two
// networks' RTT checks are switched off independently.
func TestAnalyzer_ServiceRTTCheckDisabledIndependently(t *testing.T) {
	cfg := testConfig()
	cfg.Service.NetworkRTTP99Ns = 0
	a := New(cfg, nil)
	ctx := context.Background()

	if v := a.Ingest(ctx, report(serviceSummary("tor-a", "tor-b", 100, 0, 9_000_000, 1))); v != 0 {
		t.Errorf("service RTT check disabled: got %d violations, want 0", v)
	}
	if v := a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 0, 9_000_000, 1))); v != 1 {
		t.Errorf("cluster RTT check still on: got %d violations, want 1", v)
	}
}

func TestAnalyzer_ZeroTotalNoDivideByZero(t *testing.T) {
	a := New(testConfig(), nil)
	// Empty window (total 0) must not panic nor be flagged as loss.
	if v := a.Ingest(context.Background(), report(summary("tor-a", "tor-b", 0, 0, 0, 1))); v != 0 {
		t.Errorf("empty window: got %d violations, want 0", v)
	}
}

func TestAnalyzer_MultipleSummariesInReport(t *testing.T) {
	a := New(testConfig(), nil)
	ctx := context.Background()

	// Two violating (loss, rtt) + one clean summary in one report.
	v := a.Ingest(ctx, report(
		summary("tor-a", "tor-b", 100, 10, 0, 1),      // loss violation
		summary("tor-a", "tor-c", 100, 0, 800_000, 1), // rtt violation
		summary("tor-a", "tor-d", 100, 0, 100_000, 1), // clean
	))
	if v != 2 {
		t.Errorf("got %d violating summaries, want 2", v)
	}
}

func TestAnalyzer_WindowRetentionRing(t *testing.T) {
	cfg := testConfig()
	cfg.WindowRetention = 3
	a := New(cfg, nil)
	ctx := context.Background()

	// Ingest 5 distinct windows; only the last 3 must be retained.
	for w := uint64(1); w <= 5; w++ {
		a.Ingest(ctx, report(summary("tor-a", "tor-b", 100, 0, 0, w)))
	}
	if got := a.RetainedWindows(); got != 3 {
		t.Errorf("RetainedWindows = %d, want 3 (ring capped at retention)", got)
	}

	// Summaries sharing a window start coalesce into one retained window.
	a.Ingest(ctx, report(
		summary("tor-a", "tor-b", 100, 0, 0, 5),
		summary("tor-a", "tor-c", 100, 0, 0, 5),
	))
	if got := a.RetainedWindows(); got != 3 {
		t.Errorf("RetainedWindows = %d, want 3 after same-window ingest", got)
	}
}

func TestAnalyzer_PerWindowSummaryCap(t *testing.T) {
	cfg := testConfig()
	cfg.WindowRetention = 2
	cfg.MaxSummariesPerWindow = 2
	a := New(cfg, nil)
	ctx := context.Background()

	// Three summaries in one window: only the first two are retained.
	a.Ingest(ctx, report(
		summary("tor-a", "tor-b", 100, 0, 0, 1),
		summary("tor-a", "tor-c", 100, 0, 0, 1),
		summary("tor-a", "tor-d", 100, 0, 0, 1),
	))
	if got := a.RetainedWindows(); got != 1 {
		t.Errorf("RetainedWindows = %d, want 1", got)
	}
	if got := a.RetainedSummaries(); got != 2 {
		t.Errorf("RetainedSummaries = %d, want 2 (per-window cap)", got)
	}

	// A new window is still accepted; the previous window stays at the cap.
	a.Ingest(ctx, report(summary("tor-a", "tor-e", 100, 0, 0, 2)))
	if got := a.RetainedWindows(); got != 2 {
		t.Errorf("RetainedWindows = %d, want 2 after second window", got)
	}
	if got := a.RetainedSummaries(); got != 3 {
		t.Errorf("RetainedSummaries = %d, want 3 (2 in window 1 + 1 in window 2)", got)
	}

	// Same-window ingest under the cap still coalesces (existing ring contract).
	a.Ingest(ctx, report(summary("tor-a", "tor-f", 100, 0, 0, 2)))
	if got := a.RetainedSummaries(); got != 4 {
		t.Errorf("RetainedSummaries = %d, want 4 after coalescing into window 2", got)
	}
	a.Ingest(ctx, report(summary("tor-a", "tor-g", 100, 0, 0, 2)))
	if got := a.RetainedSummaries(); got != 4 {
		t.Errorf("RetainedSummaries = %d, want 4 (window 2 at cap)", got)
	}
}

func TestAnalyzer_NilReportSafe(t *testing.T) {
	a := New(testConfig(), nil)
	if v := a.Ingest(context.Background(), nil); v != 0 {
		t.Errorf("nil report: got %d, want 0", v)
	}
}

func TestAnalyzer_MapsEmptyTorLabels(t *testing.T) {
	a := New(testConfig(), nil)
	s := summary("", "  ", 100, 50, 0, 1)

	if v := a.Ingest(context.Background(), report(s)); v != 1 {
		t.Fatalf("loss violation: got %d, want 1", v)
	}
	if s.GetSourceTorId() != probe.UnspecifiedTorLabel {
		t.Errorf("SourceTorId = %q, want %s", s.GetSourceTorId(), probe.UnspecifiedTorLabel)
	}
	if s.GetTargetTorId() != probe.UnspecifiedTorLabel {
		t.Errorf("TargetTorId = %q, want %s", s.GetTargetTorId(), probe.UnspecifiedTorLabel)
	}
}
