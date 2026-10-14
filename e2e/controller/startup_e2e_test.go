package controller

import (
	"os"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// TestControllerStartsBeforeRqlite verifies that a controller started before
// its rqlite is ready keeps retrying the connection instead of exiting, and
// serves agents once rqlite comes up (issue #66). docker-compose
// .e2e-controller.yml starts controller_early against rqlite_late, whose
// rqlited only starts after a delay; EARLY_CONTROLLER_ADDR points at it.
func TestControllerStartsBeforeRqlite(t *testing.T) {
	addr := os.Getenv("EARLY_CONTROLLER_ADDR")
	if addr == "" {
		t.Skip("EARLY_CONTROLLER_ADDR not set; run via docker-compose.e2e-controller.yml")
	}

	// The gRPC port opens only after the registry is initialized, i.e. once
	// rqlite_late is ready (~15s delay plus backoff). An exited controller
	// never opens it, so this fails rather than passing on a restart.
	waitForController(t, addr, 75*time.Second)

	client, err := controller_client.NewGRPCControllerClient(addr, nil)
	if err != nil {
		t.Fatalf("failed to create gRPC client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	registerAgent(t, client, "agent-early", "10.0.9.1", "host-early", "tor-early",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::e1", 100, "10.0.9.1", "host-early", "tor-early", "mlx5_0"),
		})

	getPinglist(t, client, "agent-early", "tor-early", "fe80::e1", controller_agent.PinglistType_TOR_MESH)
}
