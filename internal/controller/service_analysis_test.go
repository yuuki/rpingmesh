package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if ack.GetSloViolations() != 2 {
		t.Errorf("SloViolations = %d, want 2", ack.GetSloViolations())
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

// TestReportProbeAnalysis_BoundsAgentID verifies that a report whose
// agent_id is longer than a registration's may be, or holds a NUL byte, is
// rejected before it reaches the analyzer, which keeps the ID in memory.
func TestReportProbeAnalysis_BoundsAgentID(t *testing.T) {
	for _, tc := range []struct {
		name, agentID string
		want          codes.Code
	}{
		{"at the limit", strings.Repeat("a", maxFieldLen), codes.OK},
		{"one byte over", strings.Repeat("a", maxFieldLen+1), codes.InvalidArgument},
		{"512 KiB", strings.Repeat("a", 512<<10), codes.InvalidArgument},
		{"NUL byte", "agent\x00-1", codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(&fakeRegistry{})
			az := &fakeAnalyzer{}
			svc.SetAnalyzer(az)
			_, err := svc.ReportProbeAnalysis(context.Background(), &controller_agent.ProbeAnalysisReport{
				AgentId:   tc.agentID,
				Summaries: []*controller_agent.PathSummary{summaryFixture("tor-a", "tor-b", 100, 1)},
			})
			if got := status.Code(err); got != tc.want {
				t.Fatalf("status = %v, want %v (%v)", got, tc.want, err)
			}
			if wantCalls := map[bool]int{true: 1, false: 0}[tc.want == codes.OK]; az.calls != wantCalls {
				t.Errorf("analyzer.Ingest calls = %d, want %d", az.calls, wantCalls)
			}
		})
	}
}

// TestHoldsRNIC verifies the record of served registrations that fault
// localization checks a report's source RNICs against: an RNIC is held by
// the agent that registered it, in any spelling of the GID, not by another
// agent, not when the registry skipped it, and not after the record expired.
func TestHoldsRNIC(t *testing.T) {
	const (
		held    = "fe80:0000:0000:0000:0000:0000:0000:0001"
		skipped = "fe80:0000:0000:0000:0000:0000:0000:0002"
	)
	now := time.Unix(1_700_000_000, 0)
	svc := newTestService(&fakeRegistry{registerSkipped: []string{skipped}})
	svc.now = func() time.Time { return now }

	if svc.HoldsRNIC("agent-1", held) {
		t.Fatal("an RNIC is held before any registration")
	}
	resp, err := svc.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{
		AgentId: "agent-1",
		Rnics:   []*controller_agent.RnicInfo{{Gid: held, Qpn: 1}, {Gid: skipped, Qpn: 2}},
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("RegisterAgent: %v, %+v", err, resp)
	}

	for _, tc := range []struct {
		name, agentID, gid string
		want               bool
	}{
		{"the registering agent", "agent-1", held, true},
		{"the same GID, abbreviated", "agent-1", "fe80::1", true},
		{"another agent", "agent-2", held, false},
		{"no agent", "", held, false},
		{"an RNIC the registry skipped", "agent-1", skipped, false},
		{"an RNIC nobody registered", "agent-1", "fe80::3", false},
		{"not a GID", "agent-1", "not-a-gid", false},
	} {
		if got := svc.HoldsRNIC(tc.agentID, tc.gid); got != tc.want {
			t.Errorf("%s: HoldsRNIC(%q, %q) = %v, want %v", tc.name, tc.agentID, tc.gid, got, tc.want)
		}
	}

	now = now.Add(sourceOwnerTTL)
	if !svc.HoldsRNIC("agent-1", held) {
		t.Error("the record expired before sourceOwnerTTL passed")
	}
	now = now.Add(time.Second)
	if svc.HoldsRNIC("agent-1", held) {
		t.Error("the record outlived sourceOwnerTTL without a new registration")
	}
}

// TestRecordSources_IsBounded verifies that the record of served
// registrations stops growing at maxSourceOwners and takes new RNICs again
// once old records expired.
func TestRecordSources_IsBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc := newTestService(&fakeRegistry{})
	svc.now = func() time.Time { return now }
	rnic := func(i int) *controller_agent.RnicInfo {
		return &controller_agent.RnicInfo{Gid: fmt.Sprintf("fd00::%x:%x", i>>16, i&0xffff)}
	}
	batch := make([]*controller_agent.RnicInfo, 0, 4096)
	for i := 0; i < maxSourceOwners+4096; i++ {
		batch = append(batch, rnic(i))
		if len(batch) == cap(batch) {
			svc.recordSources("agent-1", batch, nil)
			batch = batch[:0]
		}
	}
	if len(svc.sources) != maxSourceOwners {
		t.Fatalf("%d records, want %d", len(svc.sources), maxSourceOwners)
	}
	if svc.HoldsRNIC("agent-1", rnic(maxSourceOwners+1).GetGid()) {
		t.Error("an RNIC registered into a full table is held")
	}
	now = now.Add(sourceOwnerTTL + time.Second)
	svc.recordSources("agent-2", []*controller_agent.RnicInfo{rnic(maxSourceOwners + 1)}, nil)
	if !svc.HoldsRNIC("agent-2", rnic(maxSourceOwners+1).GetGid()) || len(svc.sources) != 1 {
		t.Errorf("after the old records expired: %d records, want only the new one", len(svc.sources))
	}
}
