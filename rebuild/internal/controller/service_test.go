package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/yuuki/rpingmesh/rebuild/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestService wraps NewControllerService with a fixed, valid ECMP config so
// the request-handling tests need not care about Eq.(1) flow-label sizing.
func newTestService(reg registryClient) *ControllerService {
	return NewControllerService(reg, pinglist.ECMPConfig{
		PathsAssumed:        16,
		CoverageProbability: 0.9,
		MaxFlowLabels:       64,
	}, pinglist.DefaultInterTorSampleSize)
}

// fakeRegistry implements registryClient without any real rqlite backend,
// so that ControllerService's RegisterAgent/GetPinglist request handling
// (validation, error mapping) can be unit tested in isolation.
type fakeRegistry struct {
	registerErr   error
	registerCalls int
	lastAgentID   string
	lastAgentIP   string
	lastRnics     []*controller_agent.RnicInfo

	torMeshRnics  []*controller_agent.RnicInfo
	torMeshErr    error
	interTorRnics []*controller_agent.RnicInfo
	interTorErr   error
}

func (f *fakeRegistry) RegisterRNICs(_ context.Context, agentID, agentIP string, rnics []*controller_agent.RnicInfo) error {
	f.registerCalls++
	f.lastAgentID = agentID
	f.lastAgentIP = agentIP
	f.lastRnics = rnics
	return f.registerErr
}

func (f *fakeRegistry) GetRNICsByToR(_ context.Context, _ string) ([]*controller_agent.RnicInfo, error) {
	return f.torMeshRnics, f.torMeshErr
}

func (f *fakeRegistry) GetActiveRNICsInOtherToRs(_ context.Context, _ string) ([]*controller_agent.RnicInfo, error) {
	return f.interTorRnics, f.interTorErr
}

// ResolveHostnameByGID reports the requester as unregistered ("") so the
// service-level tests exercise the GID self-exclusion fallback; the same-host
// filtering itself is covered by the pinglist package's unit tests.
func (f *fakeRegistry) ResolveHostnameByGID(_ context.Context, _ string) (string, error) {
	return "", nil
}

func statusCode(t *testing.T, err error) codes.Code {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status error, got: %v", err)
	}
	return st.Code()
}

func TestRegisterAgent_MissingAgentID(t *testing.T) {
	svc := newTestService(&fakeRegistry{})

	_, err := svc.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{
		TorId: "tor-1",
	})
	if err == nil {
		t.Fatal("expected an error for missing agent_id, got nil")
	}
	if got := statusCode(t, err); got != codes.InvalidArgument {
		t.Errorf("status code = %v, want %v", got, codes.InvalidArgument)
	}
}

func TestRegisterAgent_MissingTorID(t *testing.T) {
	svc := newTestService(&fakeRegistry{})

	_, err := svc.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{
		AgentId: "agent-1",
	})
	if err == nil {
		t.Fatal("expected an error for missing tor_id, got nil")
	}
	if got := statusCode(t, err); got != codes.InvalidArgument {
		t.Errorf("status code = %v, want %v", got, codes.InvalidArgument)
	}
}

func TestRegisterAgent_RegistryFailure(t *testing.T) {
	fake := &fakeRegistry{registerErr: errors.New("write failed")}
	svc := newTestService(fake)

	resp, err := svc.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{
		AgentId: "agent-1",
		TorId:   "tor-1",
		Rnics: []*controller_agent.RnicInfo{
			{Gid: "gid-1"},
			{Gid: "gid-2"},
		},
	})

	if err == nil {
		t.Fatal("expected an error when the registry fails, got nil")
	}
	if got := statusCode(t, err); got != codes.Internal {
		t.Errorf("status code = %v, want %v", got, codes.Internal)
	}
	if resp == nil {
		t.Fatal("expected a non-nil response even on failure")
	}
	if resp.GetSuccess() {
		t.Error("resp.Success = true, want false on registry failure")
	}
	if fake.registerCalls != 1 {
		t.Errorf("registerCalls = %d, want 1 (all RNICs registered in a single call)", fake.registerCalls)
	}
}

func TestRegisterAgent_Success(t *testing.T) {
	fake := &fakeRegistry{}
	svc := newTestService(fake)

	resp, err := svc.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{
		AgentId:  "agent-1",
		AgentIp:  "10.0.0.1",
		Hostname: "host-1",
		TorId:    "tor-1",
		Rnics: []*controller_agent.RnicInfo{
			{Gid: "gid-1"},
			{Gid: "gid-2"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetSuccess() {
		t.Errorf("resp.Success = false, want true; message: %s", resp.GetMessage())
	}
	if fake.registerCalls != 1 {
		t.Errorf("registerCalls = %d, want 1", fake.registerCalls)
	}
	if fake.lastAgentID != "agent-1" || fake.lastAgentIP != "10.0.0.1" {
		t.Errorf("registry received agentID=%q agentIP=%q, want agent-1/10.0.0.1", fake.lastAgentID, fake.lastAgentIP)
	}
	// Hostname and tor_id from the top-level request must be propagated to
	// every RNIC before registration.
	for _, rnic := range fake.lastRnics {
		if rnic.GetHostName() != "host-1" || rnic.GetTorId() != "tor-1" {
			t.Errorf("rnic %s: hostname=%q torID=%q, want host-1/tor-1", rnic.GetGid(), rnic.GetHostName(), rnic.GetTorId())
		}
	}
}

func TestGetPinglist_MissingAgentID(t *testing.T) {
	svc := newTestService(&fakeRegistry{})

	_, err := svc.GetPinglist(context.Background(), &controller_agent.PinglistRequest{
		RequesterGid: "gid-1",
	})
	if err == nil {
		t.Fatal("expected an error for missing agent_id, got nil")
	}
	if got := statusCode(t, err); got != codes.InvalidArgument {
		t.Errorf("status code = %v, want %v", got, codes.InvalidArgument)
	}
}

func TestGetPinglist_MissingRequesterGID(t *testing.T) {
	svc := newTestService(&fakeRegistry{})

	_, err := svc.GetPinglist(context.Background(), &controller_agent.PinglistRequest{
		AgentId: "agent-1",
	})
	if err == nil {
		t.Fatal("expected an error for missing requester_gid, got nil")
	}
	if got := statusCode(t, err); got != codes.InvalidArgument {
		t.Errorf("status code = %v, want %v", got, codes.InvalidArgument)
	}
}

func TestGetPinglist_UnknownType(t *testing.T) {
	svc := newTestService(&fakeRegistry{})

	_, err := svc.GetPinglist(context.Background(), &controller_agent.PinglistRequest{
		AgentId:      "agent-1",
		RequesterGid: "gid-1",
		Type:         controller_agent.PinglistType(999),
	})
	if err == nil {
		t.Fatal("expected an error for an unknown pinglist type, got nil")
	}
	if got := statusCode(t, err); got != codes.InvalidArgument {
		t.Errorf("status code = %v, want %v", got, codes.InvalidArgument)
	}
}

func TestGetPinglist_TorMeshSuccess(t *testing.T) {
	fake := &fakeRegistry{
		torMeshRnics: []*controller_agent.RnicInfo{
			{Gid: "requester-gid"}, // excluded from results (self)
			{Gid: "peer-gid", TorId: "tor-1"},
		},
	}
	svc := newTestService(fake)

	resp, err := svc.GetPinglist(context.Background(), &controller_agent.PinglistRequest{
		AgentId:      "agent-1",
		RequesterGid: "requester-gid",
		TorId:        "tor-1",
		Type:         controller_agent.PinglistType_TOR_MESH,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetTargets()) != 1 {
		t.Fatalf("got %d targets, want 1 (requester's own RNIC excluded)", len(resp.GetTargets()))
	}
	if resp.GetTargets()[0].GetTargetGid() != "peer-gid" {
		t.Errorf("target GID = %q, want peer-gid", resp.GetTargets()[0].GetTargetGid())
	}
}

func TestGetPinglist_RegistryFailure(t *testing.T) {
	fake := &fakeRegistry{torMeshErr: errors.New("query failed")}
	svc := newTestService(fake)

	_, err := svc.GetPinglist(context.Background(), &controller_agent.PinglistRequest{
		AgentId:      "agent-1",
		RequesterGid: "gid-1",
		TorId:        "tor-1",
		Type:         controller_agent.PinglistType_TOR_MESH,
	})
	if err == nil {
		t.Fatal("expected an error when the registry fails, got nil")
	}
	if got := statusCode(t, err); got != codes.Internal {
		t.Errorf("status code = %v, want %v", got, codes.Internal)
	}
}
