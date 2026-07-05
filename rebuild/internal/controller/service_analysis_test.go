package controller

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc/codes"
)

// fakeAnalyzer records ingest calls and returns a scripted violation count so
// the ReportProbeAnalysis handler can be tested without the real analyzer.
type fakeAnalyzer struct {
	calls      int
	lastReport *controller_agent.ProbeAnalysisReport
	violations int
}

func (f *fakeAnalyzer) Ingest(_ context.Context, r *controller_agent.ProbeAnalysisReport) int {
	f.calls++
	f.lastReport = r
	return f.violations
}

func TestReportProbeAnalysis_WithAnalyzer(t *testing.T) {
	svc := newTestService(&fakeRegistry{})
	az := &fakeAnalyzer{violations: 2}
	svc.SetAnalyzer(az)

	report := &controller_agent.ProbeAnalysisReport{
		AgentId: "agent-1",
		Summaries: []*controller_agent.PathSummary{
			summaryFixture("tor-a", "tor-b", 100, 50),
		},
	}
	ack, err := svc.ReportProbeAnalysis(context.Background(), report)
	if err != nil {
		t.Fatalf("ReportProbeAnalysis: %v", err)
	}
	if !ack.GetAccepted() {
		t.Errorf("Accepted = false, want true")
	}
	if ack.GetSlaViolations() != 2 {
		t.Errorf("SlaViolations = %d, want 2", ack.GetSlaViolations())
	}
	if az.calls != 1 {
		t.Errorf("analyzer.Ingest calls = %d, want 1", az.calls)
	}
	if got := len(az.lastReport.GetSummaries()); got != 1 {
		t.Errorf("analyzer saw %d summaries, want 1", got)
	}
}

func TestReportProbeAnalysis_NoAnalyzer(t *testing.T) {
	svc := newTestService(&fakeRegistry{})

	ack, err := svc.ReportProbeAnalysis(context.Background(), &controller_agent.ProbeAnalysisReport{
		AgentId: "agent-1",
	})
	if err != nil {
		t.Fatalf("ReportProbeAnalysis: %v", err)
	}
	if ack.GetAccepted() {
		t.Errorf("Accepted = true, want false when analyzer disabled")
	}
}

func TestReportProbeAnalysis_EmptyAgentID(t *testing.T) {
	svc := newTestService(&fakeRegistry{})
	svc.SetAnalyzer(&fakeAnalyzer{})

	_, err := svc.ReportProbeAnalysis(context.Background(), &controller_agent.ProbeAnalysisReport{})
	if err == nil {
		t.Fatal("expected InvalidArgument for empty agent_id, got nil")
	}
	if code := statusCode(t, err); code != codes.InvalidArgument {
		t.Errorf("status code = %v, want InvalidArgument", code)
	}
}

func summaryFixture(sourceTor, targetTor string, total, failed uint32) *controller_agent.PathSummary {
	return &controller_agent.PathSummary{
		SourceGid:    "fe80::1",
		SourceTorId:  sourceTor,
		TargetGid:    "fe80::2",
		TargetTorId:  targetTor,
		ProbeTotal:   total,
		ProbeFailed:  failed,
		ProbeSuccess: total - failed,
	}
}
