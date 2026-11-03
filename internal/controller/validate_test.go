package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
)

func validRegistration() *controller_agent.AgentRegistrationRequest {
	return &controller_agent.AgentRegistrationRequest{
		AgentId:  "agent-1",
		AgentIp:  "10.0.0.1",
		Hostname: "host-1",
		TorId:    "tor-1",
		Rnics: []*controller_agent.RnicInfo{
			{Gid: "fe80::1", Qpn: 7, IpAddress: "10.0.0.1", DeviceName: "mlx5_0"},
		},
	}
}

func TestRegisterAgent_RejectsMalformedInput(t *testing.T) {
	long := strings.Repeat("x", maxFieldLen+1)
	cases := map[string]func(*controller_agent.AgentRegistrationRequest){
		"bad gid":          func(r *controller_agent.AgentRegistrationRequest) { r.Rnics[0].Gid = "not-a-gid" },
		"oversized gid":    func(r *controller_agent.AgentRegistrationRequest) { r.Rnics[0].Gid = long },
		"bad rnic ip":      func(r *controller_agent.AgentRegistrationRequest) { r.Rnics[0].IpAddress = "nope" },
		"bad agent ip":     func(r *controller_agent.AgentRegistrationRequest) { r.AgentIp = "nope" },
		"long hostname":    func(r *controller_agent.AgentRegistrationRequest) { r.Hostname = long },
		"long agent_id":    func(r *controller_agent.AgentRegistrationRequest) { r.AgentId = long },
		"long tor_id":      func(r *controller_agent.AgentRegistrationRequest) { r.TorId = long },
		"long rnic tor_id": func(r *controller_agent.AgentRegistrationRequest) { r.Rnics[0].TorId = long },
		"long device":      func(r *controller_agent.AgentRegistrationRequest) { r.Rnics[0].DeviceName = long },
		"long netdev":      func(r *controller_agent.AgentRegistrationRequest) { r.Rnics[0].Netdev = long },
		"nil rnic":         func(r *controller_agent.AgentRegistrationRequest) { r.Rnics = append(r.Rnics, nil) },
		"too many rnics": func(r *controller_agent.AgentRegistrationRequest) {
			for len(r.Rnics) <= MaxRnicsPerAgent {
				r.Rnics = append(r.Rnics, &controller_agent.RnicInfo{Gid: "fe80::2"})
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeRegistry{}
			req := validRegistration()
			mutate(req)
			_, err := newTestService(fake).RegisterAgent(context.Background(), req)
			if statusCode(t, err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", statusCode(t, err))
			}
			if fake.registerCalls != 0 {
				t.Fatal("malformed request reached the registry")
			}
		})
	}
}

func TestRegisterAgent_AcceptsIPv4GID(t *testing.T) {
	req := validRegistration()
	req.Rnics[0].Gid = "0000:0000:0000:0000:0000:ffff:0a00:0001"
	if _, err := newTestService(&fakeRegistry{}).RegisterAgent(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterAgent_ReportsSkippedGIDs(t *testing.T) {
	fake := &fakeRegistry{registerSkipped: []string{"fe80::1"}}
	resp, err := newTestService(fake).RegisterAgent(context.Background(), validRegistration())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetSuccess() || !strings.Contains(resp.GetMessage(), "skipped 1") {
		t.Fatalf("response = %+v, want success mentioning the skipped RNIC", resp)
	}
}

func TestGetPinglist_RejectsBadRequesterGID(t *testing.T) {
	_, err := newTestService(&fakeRegistry{}).GetPinglist(context.Background(), &controller_agent.PinglistRequest{
		AgentId: "agent-1", RequesterGid: "junk", Type: controller_agent.PinglistType_TOR_MESH,
	})
	if statusCode(t, err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", statusCode(t, err))
	}
}

func TestReportProbeAnalysis_FiltersSummaries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc := newTestService(&fakeRegistry{})
	svc.now = func() time.Time { return now }
	az := &fakeAnalyzer{}
	svc.SetAnalyzer(az)

	good := &controller_agent.PathSummary{SourceGid: "fe80::1", TargetGid: "fe80::2", WindowStartUnixNs: uint64(now.UnixNano())}
	future := &controller_agent.PathSummary{SourceGid: "fe80::1", WindowStartUnixNs: uint64(now.Add(time.Hour).UnixNano())}
	huge := &controller_agent.PathSummary{SourceGid: strings.Repeat("a", 1<<16), WindowStartUnixNs: uint64(now.UnixNano())}
	longTor := &controller_agent.PathSummary{TargetTorId: strings.Repeat("t", maxFieldLen+1)}

	_, err := svc.ReportProbeAnalysis(context.Background(), &controller_agent.ProbeAnalysisReport{
		AgentId:   "agent-1",
		Summaries: []*controller_agent.PathSummary{good, future, huge, nil, longTor},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := az.lastReport.GetSummaries(); len(got) != 1 || got[0] != good {
		t.Fatalf("ingested %d summaries, want only the well-formed one", len(got))
	}
}

func TestReportProbeAnalysis_RejectsOversizedBatch(t *testing.T) {
	svc := newTestService(&fakeRegistry{})
	az := &fakeAnalyzer{}
	svc.SetAnalyzer(az)
	sums := make([]*controller_agent.PathSummary, MaxSummariesPerReport+1)
	_, err := svc.ReportProbeAnalysis(context.Background(), &controller_agent.ProbeAnalysisReport{AgentId: "a", Summaries: sums})
	if statusCode(t, err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", statusCode(t, err))
	}
	if az.calls != 0 {
		t.Fatal("oversized batch reached the analyzer")
	}
}
