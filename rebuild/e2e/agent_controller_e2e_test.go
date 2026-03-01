// Package e2e contains end-to-end tests that exercise the Agent-to-Controller
// gRPC communication path through a real rqlite-backed Controller.
//
// These tests require a running Controller (connected to rqlite). The
// controller address is read from the CONTROLLER_ADDR environment variable
// (default: "localhost:50051"). Use docker-compose.e2e.yml to start the
// required infrastructure.
package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// rqliteURL returns the HTTP URL of the rqlite instance used by the Controller.
func rqliteURL() string {
	if url := os.Getenv("RQLITE_URL"); url != "" {
		return url
	}
	return "http://localhost:4001"
}

// cleanDatabase deletes all rows from the rnics table via the rqlite HTTP API.
// This ensures test isolation when tests share a single rqlite instance.
func cleanDatabase(t *testing.T) {
	t.Helper()
	body := strings.NewReader(`[["DELETE FROM rnics"]]`)
	resp, err := http.Post(rqliteURL()+"/db/execute", "application/json", body)
	if err != nil {
		t.Fatalf("failed to clean database: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to clean database: HTTP %d", resp.StatusCode)
	}
}

// controllerAddr returns the gRPC address of the Controller under test.
func controllerAddr() string {
	if addr := os.Getenv("CONTROLLER_ADDR"); addr != "" {
		return addr
	}
	return "localhost:50051"
}

// waitForController blocks until the Controller's gRPC port is reachable or
// the timeout expires. This handles startup ordering when the test container
// starts before the controller is fully ready.
func waitForController(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("controller at %s not reachable within %s", addr, timeout)
}

// newClient creates a GRPCControllerClient connected to the test Controller.
func newClient(t *testing.T) *controller_client.GRPCControllerClient {
	t.Helper()
	addr := controllerAddr()
	waitForController(t, addr, 30*time.Second)

	client, err := controller_client.NewGRPCControllerClient(addr)
	if err != nil {
		t.Fatalf("failed to create gRPC client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// makeRNIC builds an RnicInfo proto for test purposes.
func makeRNIC(gid string, qpn uint32, ip, hostname, torID, device string) *controller_agent.RnicInfo {
	return &controller_agent.RnicInfo{
		Gid:        gid,
		Qpn:        qpn,
		IpAddress:  ip,
		HostName:   hostname,
		TorId:      torID,
		DeviceName: device,
	}
}

// registerAgent is a test helper that registers an agent and asserts success.
func registerAgent(
	t *testing.T,
	client *controller_client.GRPCControllerClient,
	agentID, agentIP, hostname, torID string,
	rnics []*controller_agent.RnicInfo,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &controller_agent.AgentRegistrationRequest{
		AgentId:  agentID,
		AgentIp:  agentIP,
		Hostname: hostname,
		TorId:    torID,
		Rnics:    rnics,
	}

	resp, err := client.RegisterAgent(ctx, req)
	if err != nil {
		t.Fatalf("RegisterAgent failed for %s: %v", agentID, err)
	}
	if !resp.GetSuccess() {
		t.Fatalf("RegisterAgent rejected for %s: %s", agentID, resp.GetMessage())
	}
}

// getPinglist is a test helper that fetches a pinglist and asserts no error.
func getPinglist(
	t *testing.T,
	client *controller_client.GRPCControllerClient,
	agentID, torID, requesterGID string,
	ptype controller_agent.PinglistType,
) []*controller_agent.PingTarget {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	targets, err := client.GetPinglist(ctx, agentID, torID, requesterGID, ptype)
	if err != nil {
		t.Fatalf("GetPinglist(%s) failed for %s: %v", ptype, agentID, err)
	}
	return targets
}

// containsGID checks whether any PingTarget in the slice has the given GID.
func containsGID(targets []*controller_agent.PingTarget, gid string) bool {
	for _, t := range targets {
		if t.GetTargetGid() == gid {
			return true
		}
	}
	return false
}

// containsTorID checks whether any PingTarget in the slice has the given ToR ID.
func containsTorID(targets []*controller_agent.PingTarget, torID string) bool {
	for _, t := range targets {
		if t.GetTargetTorId() == torID {
			return true
		}
	}
	return false
}

// TestAgentRegistration verifies that an agent can register its RNICs with the
// Controller and that re-registration (upsert) succeeds without error.
func TestAgentRegistration(t *testing.T) {
	cleanDatabase(t)
	client := newClient(t)

	rnics := []*controller_agent.RnicInfo{
		makeRNIC("fe80::1", 100, "10.0.0.1", "host-01", "tor-01", "mlx5_0"),
		makeRNIC("fe80::2", 101, "10.0.0.2", "host-01", "tor-01", "mlx5_1"),
	}

	// First registration.
	registerAgent(t, client, "agent-01", "192.168.1.1", "host-01", "tor-01", rnics)

	// Re-registration (upsert) should also succeed.
	registerAgent(t, client, "agent-01", "192.168.1.1", "host-01", "tor-01", rnics)

	// Verify the RNICs are queryable via a TOR_MESH pinglist from a different
	// requester GID. Use a GID that does NOT belong to agent-01 so both of
	// agent-01's RNICs appear in the results.
	targets := getPinglist(t, client, "other-agent", "tor-01", "fe80::ff", controller_agent.PinglistType_TOR_MESH)
	if len(targets) < 2 {
		t.Fatalf("expected at least 2 targets from tor-01, got %d", len(targets))
	}
	if !containsGID(targets, "fe80::1") {
		t.Errorf("expected target fe80::1 in TOR_MESH results")
	}
	if !containsGID(targets, "fe80::2") {
		t.Errorf("expected target fe80::2 in TOR_MESH results")
	}
}

// TestPinglistTorMesh verifies the TOR_MESH pinglist returns all RNICs in the
// same ToR, excluding the requester's own RNIC.
func TestPinglistTorMesh(t *testing.T) {
	cleanDatabase(t)
	client := newClient(t)

	// Register three agents in the same ToR, each with one RNIC.
	registerAgent(t, client, "mesh-agent-1", "192.168.1.10", "mesh-host-1", "tor-mesh",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::10", 200, "10.1.0.1", "mesh-host-1", "tor-mesh", "mlx5_0"),
		})
	registerAgent(t, client, "mesh-agent-2", "192.168.1.11", "mesh-host-2", "tor-mesh",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::11", 201, "10.1.0.2", "mesh-host-2", "tor-mesh", "mlx5_0"),
		})
	registerAgent(t, client, "mesh-agent-3", "192.168.1.12", "mesh-host-3", "tor-mesh",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::12", 202, "10.1.0.3", "mesh-host-3", "tor-mesh", "mlx5_0"),
		})

	// Agent-1 requests TOR_MESH — should see agent-2 and agent-3 but NOT itself.
	targets := getPinglist(t, client, "mesh-agent-1", "tor-mesh", "fe80::10", controller_agent.PinglistType_TOR_MESH)

	if len(targets) != 2 {
		t.Fatalf("expected 2 TOR_MESH targets, got %d", len(targets))
	}
	if containsGID(targets, "fe80::10") {
		t.Errorf("requester's own GID fe80::10 should be excluded from TOR_MESH")
	}
	if !containsGID(targets, "fe80::11") {
		t.Errorf("expected fe80::11 in TOR_MESH results")
	}
	if !containsGID(targets, "fe80::12") {
		t.Errorf("expected fe80::12 in TOR_MESH results")
	}

	// Verify deterministic 5-tuple fields are populated.
	for _, tgt := range targets {
		if tgt.GetFlowLabel() == 0 && tgt.GetSourcePort() == 0 {
			t.Errorf("PingTarget %s has zero flow_label and source_port", tgt.GetTargetGid())
		}
		if tgt.GetTargetQpn() == 0 {
			t.Errorf("PingTarget %s has zero QPN", tgt.GetTargetGid())
		}
		if tgt.GetTargetIp() == "" {
			t.Errorf("PingTarget %s has empty IP", tgt.GetTargetGid())
		}
	}
}

// TestPinglistInterTor verifies the INTER_TOR pinglist samples one RNIC from
// each ToR other than the requester's own.
func TestPinglistInterTor(t *testing.T) {
	cleanDatabase(t)
	client := newClient(t)

	// Register agents across three different ToRs.
	registerAgent(t, client, "inter-agent-1", "192.168.2.10", "inter-host-1", "tor-A",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::a1", 300, "10.2.0.1", "inter-host-1", "tor-A", "mlx5_0"),
		})
	registerAgent(t, client, "inter-agent-2", "192.168.2.11", "inter-host-2", "tor-B",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::b1", 301, "10.2.0.2", "inter-host-2", "tor-B", "mlx5_0"),
		})
	registerAgent(t, client, "inter-agent-3", "192.168.2.12", "inter-host-3", "tor-C",
		[]*controller_agent.RnicInfo{
			makeRNIC("fe80::c1", 302, "10.2.0.3", "inter-host-3", "tor-C", "mlx5_0"),
		})

	// Agent-1 (tor-A) requests INTER_TOR — should see targets from tor-B and tor-C.
	targets := getPinglist(t, client, "inter-agent-1", "tor-A", "fe80::a1", controller_agent.PinglistType_INTER_TOR)

	if len(targets) < 2 {
		t.Fatalf("expected at least 2 INTER_TOR targets, got %d", len(targets))
	}
	if containsTorID(targets, "tor-A") {
		t.Errorf("own ToR 'tor-A' should be excluded from INTER_TOR results")
	}
	if !containsTorID(targets, "tor-B") {
		t.Errorf("expected tor-B in INTER_TOR results")
	}
	if !containsTorID(targets, "tor-C") {
		t.Errorf("expected tor-C in INTER_TOR results")
	}
}

// TestFullTopology simulates a realistic multi-ToR deployment and verifies the
// combined TOR_MESH + INTER_TOR pinglist that ClusterMonitor would produce.
func TestFullTopology(t *testing.T) {
	cleanDatabase(t)
	client := newClient(t)

	// Build a topology: 3 ToRs, 2 agents per ToR, 1 RNIC each.
	type agentDef struct {
		id, ip, hostname, torID, gid, rnicIP, device string
		qpn                                          uint32
	}

	agents := []agentDef{
		{"topo-a1", "192.168.10.1", "topo-host-a1", "tor-X", "fe80::xa1", "10.10.0.1", "mlx5_0", 400},
		{"topo-a2", "192.168.10.2", "topo-host-a2", "tor-X", "fe80::xa2", "10.10.0.2", "mlx5_0", 401},
		{"topo-b1", "192.168.10.3", "topo-host-b1", "tor-Y", "fe80::yb1", "10.10.0.3", "mlx5_0", 402},
		{"topo-b2", "192.168.10.4", "topo-host-b2", "tor-Y", "fe80::yb2", "10.10.0.4", "mlx5_0", 403},
		{"topo-c1", "192.168.10.5", "topo-host-c1", "tor-Z", "fe80::zc1", "10.10.0.5", "mlx5_0", 404},
		{"topo-c2", "192.168.10.6", "topo-host-c2", "tor-Z", "fe80::zc2", "10.10.0.6", "mlx5_0", 405},
	}

	for _, a := range agents {
		registerAgent(t, client, a.id, a.ip, a.hostname, a.torID,
			[]*controller_agent.RnicInfo{
				makeRNIC(a.gid, a.qpn, a.rnicIP, a.hostname, a.torID, a.device),
			})
	}

	// topo-a1 (tor-X) fetches both pinglist types — mimics ClusterMonitor.
	requesterGID := "fe80::xa1"
	torMesh := getPinglist(t, client, "topo-a1", "tor-X", requesterGID, controller_agent.PinglistType_TOR_MESH)
	interTor := getPinglist(t, client, "topo-a1", "tor-X", requesterGID, controller_agent.PinglistType_INTER_TOR)

	// TOR_MESH: should contain topo-a2 (same ToR, different agent) but not self.
	if len(torMesh) != 1 {
		t.Fatalf("expected 1 TOR_MESH target (topo-a2), got %d", len(torMesh))
	}
	if !containsGID(torMesh, "fe80::xa2") {
		t.Errorf("expected fe80::xa2 in TOR_MESH results")
	}
	if containsGID(torMesh, requesterGID) {
		t.Errorf("requester %s should be excluded from TOR_MESH", requesterGID)
	}

	// INTER_TOR: should have at least one target from tor-Y and one from tor-Z.
	if len(interTor) < 2 {
		t.Fatalf("expected at least 2 INTER_TOR targets, got %d", len(interTor))
	}
	if !containsTorID(interTor, "tor-Y") {
		t.Errorf("expected tor-Y in INTER_TOR results")
	}
	if !containsTorID(interTor, "tor-Z") {
		t.Errorf("expected tor-Z in INTER_TOR results")
	}
	if containsTorID(interTor, "tor-X") {
		t.Errorf("own ToR tor-X should be excluded from INTER_TOR")
	}

	// Combined list (what ClusterMonitor would produce).
	combined := make([]*controller_agent.PingTarget, 0, len(torMesh)+len(interTor))
	combined = append(combined, torMesh...)
	combined = append(combined, interTor...)

	expectedMinTargets := 3 // 1 from TOR_MESH + 2 from INTER_TOR
	if len(combined) < expectedMinTargets {
		t.Fatalf("combined pinglist: expected at least %d targets, got %d", expectedMinTargets, len(combined))
	}

	// Verify all targets have valid fields.
	for i, tgt := range combined {
		if tgt.GetTargetGid() == "" {
			t.Errorf("target[%d] has empty GID", i)
		}
		if tgt.GetTargetIp() == "" {
			t.Errorf("target[%d] has empty IP", i)
		}
		if tgt.GetTargetTorId() == "" {
			t.Errorf("target[%d] has empty ToR ID", i)
		}
		if tgt.GetTargetHostname() == "" {
			t.Errorf("target[%d] has empty hostname", i)
		}
		if tgt.GetTargetDeviceName() == "" {
			t.Errorf("target[%d] has empty device name", i)
		}
	}

	t.Logf("Full topology test passed: %d TOR_MESH + %d INTER_TOR = %d combined targets",
		len(torMesh), len(interTor), len(combined))

	// Log target details for debugging.
	for _, tgt := range combined {
		t.Logf("  target: gid=%s qpn=%d ip=%s tor=%s host=%s flow_label=%d",
			tgt.GetTargetGid(), tgt.GetTargetQpn(), tgt.GetTargetIp(),
			tgt.GetTargetTorId(), tgt.GetTargetHostname(), tgt.GetFlowLabel())
	}
}

// TestRegistrationValidation verifies that the Controller rejects invalid
// registration requests.
func TestRegistrationValidation(t *testing.T) {
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name    string
		agentID string
		torID   string
	}{
		{"empty agent_id", "", "tor-01"},
		{"empty tor_id", "agent-01", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &controller_agent.AgentRegistrationRequest{
				AgentId: tt.agentID,
				TorId:   tt.torID,
				Rnics: []*controller_agent.RnicInfo{
					makeRNIC("fe80::99", 999, "10.99.0.1", "host-99", tt.torID, "mlx5_0"),
				},
			}
			_, err := client.RegisterAgent(ctx, req)
			if err == nil {
				t.Errorf("expected error for %s, got success", tt.name)
			} else {
				t.Logf("correctly rejected %s: %v", tt.name, err)
			}
		})
	}
}

// TestPinglistEmptyToR verifies that requesting a TOR_MESH pinglist for a ToR
// with no other agents returns an empty list (not an error).
func TestPinglistEmptyToR(t *testing.T) {
	cleanDatabase(t)
	client := newClient(t)

	// Register a single agent in an isolated ToR.
	gid := fmt.Sprintf("fe80::empty-%d", time.Now().UnixNano()%10000)
	torID := fmt.Sprintf("tor-empty-%d", time.Now().UnixNano()%10000)
	registerAgent(t, client, "lonely-agent", "192.168.99.1", "lonely-host", torID,
		[]*controller_agent.RnicInfo{
			makeRNIC(gid, 500, "10.99.0.1", "lonely-host", torID, "mlx5_0"),
		})

	// TOR_MESH should return empty (only self in the ToR, and self is excluded).
	targets := getPinglist(t, client, "lonely-agent", torID, gid, controller_agent.PinglistType_TOR_MESH)
	if len(targets) != 0 {
		t.Fatalf("expected 0 TOR_MESH targets for single-agent ToR, got %d", len(targets))
	}
}
