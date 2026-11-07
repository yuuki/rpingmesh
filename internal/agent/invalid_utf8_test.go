package agent

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestBuildRegistrationRequest_InvalidUTF8Names: Linux accepts netdev, RDMA
// device and host names that are not valid UTF-8, but a proto3 string must
// be valid UTF-8, or the whole RegisterAgent request fails to marshal and the
// agent never registers. Such bytes are sent as U+FFFD instead.
func TestBuildRegistrationRequest_InvalidUTF8Names(t *testing.T) {
	a := newTestAgent(fakeDevices("mlx5_\xff"), fakeProbers(1))
	a.cfg.HostName = "host-\xfe"
	a.rnics[0].netdev = "ens\xff1"

	req := a.buildRegistrationRequest()
	if _, err := proto.Marshal(req); err != nil {
		t.Fatalf("registration request does not marshal: %v", err)
	}
	rnic := req.GetRnics()[0]
	if req.GetHostname() != "host-�" || rnic.GetHostName() != "host-�" ||
		rnic.GetDeviceName() != "mlx5_�" || rnic.GetNetdev() != "ens�1" {
		t.Fatalf("hostname %q/%q, device %q, netdev %q: want the invalid bytes replaced by U+FFFD",
			req.GetHostname(), rnic.GetHostName(), rnic.GetDeviceName(), rnic.GetNetdev())
	}
}
