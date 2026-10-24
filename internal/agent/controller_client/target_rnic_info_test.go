package controller_client

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGetTargetRnicInfo_Success verifies the request is built from the
// arguments and the resolved targets are returned as the server sent them.
func TestGetTargetRnicInfo_Success(t *testing.T) {
	srv := &fakeControllerServer{
		targetInfoFunc: func(req *controller_agent.TargetRnicInfoRequest) (*controller_agent.TargetRnicInfoResponse, error) {
			return &controller_agent.TargetRnicInfoResponse{Targets: []*controller_agent.PingTarget{
				{TargetGid: req.GetTargetGids()[0], TargetQpn: 77, PinglistType: controller_agent.PinglistType_SERVICE_TRACING},
			}}, nil
		},
	}
	c := newTestClient(t, srv)

	targets, err := c.GetTargetRnicInfo(context.Background(), "agent-a", "fe80::1", []string{"fe80::3", "fe80::4"})
	if err != nil {
		t.Fatalf("GetTargetRnicInfo: %v", err)
	}
	if len(targets) != 1 || targets[0].GetTargetGid() != "fe80::3" || targets[0].GetTargetQpn() != 77 {
		t.Fatalf("unexpected targets: %v", targets)
	}

	srv.mu.Lock()
	req := srv.lastTargetInfoReq
	srv.mu.Unlock()
	if req.GetAgentId() != "agent-a" || req.GetRequesterGid() != "fe80::1" || len(req.GetTargetGids()) != 2 {
		t.Errorf("unexpected request: %v", req)
	}
}

// TestGetTargetRnicInfo_Unimplemented verifies that a controller without the
// RPC surfaces codes.Unimplemented through the wrapped error, which the
// service monitor relies on to log once and stop asking.
func TestGetTargetRnicInfo_Unimplemented(t *testing.T) {
	srv := &fakeControllerServer{
		targetInfoFunc: func(*controller_agent.TargetRnicInfoRequest) (*controller_agent.TargetRnicInfoResponse, error) {
			return nil, status.Error(codes.Unimplemented, "unknown method")
		},
	}
	c := newTestClient(t, srv)
	_, err := c.GetTargetRnicInfo(context.Background(), "agent-a", "fe80::1", []string{"fe80::3"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("status code = %v, want Unimplemented (err: %v)", status.Code(err), err)
	}
}
