package controller

import (
	"net"
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/protobuf/proto"
)

// FuzzValidateRegistration feeds arbitrary wire-format RegisterAgent
// requests (the controller may serve unauthenticated agents) through
// validateRegistration and checks that whatever it accepts respects the
// bounds the registry relies on. RnicInfo.host_name is not checked: the
// service overwrites it with the request-wide hostname before storing.
func FuzzValidateRegistration(f *testing.F) {
	for _, req := range []*controller_agent.AgentRegistrationRequest{
		validRegistration(),
		{AgentId: "a", Rnics: []*controller_agent.RnicInfo{{Gid: "0000:0000:0000:0000:0000:ffff:0a00:0001", PlaneId: "rail0", Netdev: "ens1f0"}}},
		{AgentId: "a", AgentIp: "fe80::1", TorId: "tor-1"},
		{},
	} {
		b, err := proto.Marshal(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var req controller_agent.AgentRegistrationRequest
		if proto.Unmarshal(data, &req) != nil {
			return
		}
		if validateRegistration(&req) != nil {
			return
		}
		for _, s := range []string{req.GetAgentId(), req.GetHostname(), req.GetTorId()} {
			if len(s) > maxFieldLen {
				t.Fatalf("accepted a %d-byte field", len(s))
			}
		}
		if ip := req.GetAgentIp(); ip != "" && net.ParseIP(ip) == nil {
			t.Fatalf("accepted agent_ip %q", ip)
		}
		if len(req.GetRnics()) > MaxRnicsPerAgent {
			t.Fatalf("accepted %d rnics", len(req.GetRnics()))
		}
		for _, rnic := range req.GetRnics() {
			if _, err := probe.ParseGID(rnic.GetGid()); err != nil || len(rnic.GetGid()) > maxGIDLen {
				t.Fatalf("accepted rnic gid %q", rnic.GetGid())
			}
			if ip := rnic.GetIpAddress(); ip != "" && net.ParseIP(ip) == nil {
				t.Fatalf("accepted rnic ip_address %q", ip)
			}
			for _, s := range []string{rnic.GetTorId(), rnic.GetPlaneId(), rnic.GetDeviceName(), rnic.GetNetdev()} {
				if len(s) > maxFieldLen {
					t.Fatalf("accepted a %d-byte rnic field", len(s))
				}
			}
		}
	})
}
