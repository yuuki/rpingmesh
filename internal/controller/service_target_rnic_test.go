package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
)

// gidRegistry is a fakeRegistry whose GetRNICByGID answers from a map, so
// GetTargetRnicInfo's resolution can be exercised end to end.
type gidRegistry struct {
	fakeRegistry
	byGID map[string]*controller_agent.RnicInfo
	err   error
}

func (g *gidRegistry) GetRNICByGID(_ context.Context, gid string) (*controller_agent.RnicInfo, error) {
	if g.err != nil {
		return nil, g.err
	}
	return g.byGID[gid], nil
}

func TestGetTargetRnicInfo_Validation(t *testing.T) {
	svc := newTestService(&gidRegistry{})
	ctx := context.Background()

	_, err := svc.GetTargetRnicInfo(ctx, &controller_agent.TargetRnicInfoRequest{RequesterGid: "fe80::1"})
	if statusCode(t, err) != codes.InvalidArgument {
		t.Errorf("missing agent_id: code = %v, want InvalidArgument", statusCode(t, err))
	}
	_, err = svc.GetTargetRnicInfo(ctx, &controller_agent.TargetRnicInfoRequest{AgentId: "a"})
	if statusCode(t, err) != codes.InvalidArgument {
		t.Errorf("missing requester_gid: code = %v, want InvalidArgument", statusCode(t, err))
	}
	tooMany := make([]string, MaxTargetRnicInfoGIDs+1)
	_, err = svc.GetTargetRnicInfo(ctx, &controller_agent.TargetRnicInfoRequest{AgentId: "a", RequesterGid: "fe80::1", TargetGids: tooMany})
	if statusCode(t, err) != codes.InvalidArgument || !strings.Contains(err.Error(), "too many") {
		t.Errorf("oversized request: err = %v, want InvalidArgument/too many", err)
	}
}

func TestGetTargetRnicInfo_Resolves(t *testing.T) {
	reg := &gidRegistry{byGID: map[string]*controller_agent.RnicInfo{
		"fe80::1": {Gid: "fe80::1", HostName: "host-a", TorId: "tor-a"},
		"fe80::2": {Gid: "fe80::2", HostName: "host-a", TorId: "tor-a", Qpn: 11},
		"fe80::3": {Gid: "fe80::3", HostName: "host-b", TorId: "tor-b", Qpn: 77, IpAddress: "10.0.0.3", DeviceName: "mlx5_0", Netdev: "ens1"},
	}}
	svc := newTestService(reg)

	resp, err := svc.GetTargetRnicInfo(context.Background(), &controller_agent.TargetRnicInfoRequest{
		AgentId:      "agent-a",
		RequesterGid: "fe80::1",
		TargetGids:   []string{"fe80::3", "fe80::2", "fe80::9", "fe80::3"},
	})
	if err != nil {
		t.Fatalf("GetTargetRnicInfo: %v", err)
	}
	if len(resp.GetTargets()) != 1 {
		t.Fatalf("got %d targets, want 1: %v", len(resp.GetTargets()), resp.GetTargets())
	}
	tg := resp.GetTargets()[0]
	if tg.GetTargetGid() != "fe80::3" || tg.GetTargetQpn() != 77 || tg.GetTargetTorId() != "tor-b" ||
		tg.GetTargetHostname() != "host-b" || tg.GetTargetIp() != "10.0.0.3" ||
		tg.GetTargetDeviceName() != "mlx5_0" || tg.GetTargetNetdev() != "ens1" {
		t.Errorf("unexpected target: %v", tg)
	}
	if tg.GetPinglistType() != controller_agent.PinglistType_SERVICE_TRACING || tg.GetFlowLabelCount() != 1 {
		t.Errorf("target type/count = %v/%d, want SERVICE_TRACING/1", tg.GetPinglistType(), tg.GetFlowLabelCount())
	}
}

func TestGetTargetRnicInfo_RegistryError(t *testing.T) {
	reg := &gidRegistry{err: errors.New("rqlite down")}
	svc := newTestService(reg)
	_, err := svc.GetTargetRnicInfo(context.Background(), &controller_agent.TargetRnicInfoRequest{
		AgentId: "agent-a", RequesterGid: "fe80::1", TargetGids: []string{"fe80::3"},
	})
	if statusCode(t, err) != codes.Internal {
		t.Errorf("code = %v, want Internal", statusCode(t, err))
	}
}
