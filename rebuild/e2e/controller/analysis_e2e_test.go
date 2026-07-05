package controller

import (
	"context"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// TestReportProbeAnalysisSLADetection exercises the full ReportProbeAnalysis
// path against a real controller (with its analyzer enabled by default): a
// pseudo-agent reports a batch of per-path window summaries, one of which
// breaches the default loss SLA and one the default p99-RTT SLA, and the
// controller's analyzer must flag exactly those. The ack's sla_violations
// count is the observable end-to-end signal (no OTLP collector needed here).
//
// It runs in the RDMA-free e2e-controller compose stack
// (docker-compose.e2e-controller.yml), like the registration/pinglist tests.
func TestReportProbeAnalysisSLADetection(t *testing.T) {
	client := newClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report := &controller_agent.ProbeAnalysisReport{
		AgentId: "analysis-agent-1",
		Summaries: []*controller_agent.PathSummary{
			// Loss violation: 10% loss >> default 2% threshold.
			{
				SourceGid:         "fe80::a1",
				SourceTorId:       "tor-src",
				TargetGid:         "fe80::b1",
				TargetTorId:       "tor-dst-1",
				TargetQpn:         100,
				WindowStartUnixNs: uint64(time.Now().UnixNano()),
				WindowDurationMs:  30000,
				ProbeTotal:        100,
				ProbeSuccess:      90,
				ProbeFailed:       10,
				NetworkRttP99Ns:   100_000, // healthy RTT
			},
			// RTT violation: p99 800us >> default 500us threshold, no loss.
			{
				SourceGid:         "fe80::a1",
				SourceTorId:       "tor-src",
				TargetGid:         "fe80::b2",
				TargetTorId:       "tor-dst-2",
				TargetQpn:         101,
				WindowStartUnixNs: uint64(time.Now().UnixNano()),
				WindowDurationMs:  30000,
				ProbeTotal:        100,
				ProbeSuccess:      100,
				ProbeFailed:       0,
				NetworkRttP99Ns:   800_000,
			},
			// Clean path: no loss, healthy RTT -> no violation.
			{
				SourceGid:         "fe80::a1",
				SourceTorId:       "tor-src",
				TargetGid:         "fe80::b3",
				TargetTorId:       "tor-dst-3",
				TargetQpn:         102,
				WindowStartUnixNs: uint64(time.Now().UnixNano()),
				WindowDurationMs:  30000,
				ProbeTotal:        100,
				ProbeSuccess:      100,
				ProbeFailed:       0,
				NetworkRttP99Ns:   120_000,
			},
		},
	}

	ack, err := client.ReportProbeAnalysis(ctx, report)
	if err != nil {
		t.Fatalf("ReportProbeAnalysis failed: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatalf("report not accepted; is the analyzer enabled on the controller?")
	}
	// Two of the three summaries breach an SLA (loss, rtt); the third is clean.
	if ack.GetSlaViolations() != 2 {
		t.Errorf("SlaViolations = %d, want 2 (1 loss + 1 rtt, 1 clean)", ack.GetSlaViolations())
	}
}

// TestReportProbeAnalysisNoViolations verifies a batch of healthy summaries is
// accepted with zero violations.
func TestReportProbeAnalysisNoViolations(t *testing.T) {
	client := newClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report := &controller_agent.ProbeAnalysisReport{
		AgentId: "analysis-agent-2",
		Summaries: []*controller_agent.PathSummary{
			{
				SourceGid:       "fe80::c1",
				SourceTorId:     "tor-src",
				TargetGid:       "fe80::d1",
				TargetTorId:     "tor-dst",
				ProbeTotal:      1000,
				ProbeSuccess:    1000,
				ProbeFailed:     0,
				NetworkRttP99Ns: 50_000,
			},
		},
	}

	ack, err := client.ReportProbeAnalysis(ctx, report)
	if err != nil {
		t.Fatalf("ReportProbeAnalysis failed: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatalf("report not accepted")
	}
	if ack.GetSlaViolations() != 0 {
		t.Errorf("SlaViolations = %d, want 0", ack.GetSlaViolations())
	}
}
