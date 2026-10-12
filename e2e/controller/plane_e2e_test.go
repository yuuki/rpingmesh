package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// executeSQL runs statements through the rqlite HTTP API as one request.
func executeSQL(t *testing.T, stmts ...string) {
	t.Helper()
	payload := make([][]string, len(stmts))
	for i, s := range stmts {
		payload[i] = []string{s}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal statements: %v", err)
	}
	resp, err := http.Post(rqliteURL()+"/db/execute", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("execute %v: %v", stmts, err)
	}
	defer resp.Body.Close()
	var out struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode rqlite response: %v", err)
	}
	for i, r := range out.Results {
		if r.Error != "" {
			t.Fatalf("statement %q failed: %s", stmts[i], r.Error)
		}
	}
}

func registerPlaned(t *testing.T, agentID, host string, rnics ...*controller_agent.RnicInfo) *controller_agent.AgentRegistrationResponse {
	t.Helper()
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.RegisterAgent(ctx, &controller_agent.AgentRegistrationRequest{
		AgentId: agentID, Hostname: host, Rnics: rnics,
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("RegisterAgent(%s): resp=%v err=%v", agentID, resp, err)
	}
	return resp
}

func planedRNIC(gid string, qpn uint32, host, tor, device, plane string) *controller_agent.RnicInfo {
	r := makeRNIC(gid, qpn, "10.9.0.1", host, tor, device)
	r.PlaneId = plane
	return r
}

func planedPinglist(t *testing.T, requesterGID, torID, planeID string, ptype controller_agent.PinglistType) []*controller_agent.PingTarget {
	t.Helper()
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	targets, err := client.GetPinglist(ctx, "plane-requester", torID, requesterGID, planeID, ptype)
	if err != nil {
		t.Fatalf("GetPinglist: %v", err)
	}
	return targets
}

// TestPlaneRestrictedPinglists drives a rail-optimized topology (two rails,
// two leaves per rail) through the real controller and rqlite, so the
// plane_id column round-trips through registration, storage, and the
// pinglist queries.
func TestPlaneRestrictedPinglists(t *testing.T) {
	cleanDatabase(t)

	for h := 1; h <= 4; h++ {
		host := fmt.Sprintf("plane-host-%d", h)
		leaf := "a"
		if h > 2 {
			leaf = "b"
		}
		resp := registerPlaned(t, fmt.Sprintf("plane-agent-%d", h), host,
			planedRNIC(fmt.Sprintf("fe80::%d0", h), uint32(500+h), host, "leaf-r0-"+leaf, "mlx5_0", "rail0"),
			planedRNIC(fmt.Sprintf("fe80::%d1", h), uint32(600+h), host, "leaf-r1-"+leaf, "mlx5_1", "rail1"),
		)
		if !resp.GetPerRnicPlaneId() {
			t.Fatal("controller did not report per_rnic_plane_id support")
		}
	}

	// Registered plane: rail0 requester samples only rail0 leaves.
	targets := planedPinglist(t, "fe80::10", "leaf-r0-a", "", controller_agent.PinglistType_INTER_TOR)
	if len(targets) == 0 {
		t.Fatal("rail0 requester got no inter-ToR targets")
	}
	for _, tgt := range targets {
		if tgt.GetTargetTorId() != "leaf-r0-b" {
			t.Errorf("rail0 requester sampled %s on %s, want only leaf-r0-b", tgt.GetTargetGid(), tgt.GetTargetTorId())
		}
	}

	// Unregistered requester: the plane in the request applies.
	targets = planedPinglist(t, "fe80::99", "leaf-r1-a", "rail1", controller_agent.PinglistType_INTER_TOR)
	if len(targets) != 1 || targets[0].GetTargetTorId() != "leaf-r1-b" {
		t.Errorf("request-plane fallback: got %v, want one target on leaf-r1-b", targets)
	}

	// No plane anywhere (legacy requester): every foreign leaf, any rail.
	targets = planedPinglist(t, "fe80::98", "leaf-r0-a", "", controller_agent.PinglistType_INTER_TOR)
	if !containsTorID(targets, "leaf-r1-a") || !containsTorID(targets, "leaf-r1-b") || !containsTorID(targets, "leaf-r0-b") {
		t.Errorf("legacy requester: got ToRs %v, want leaf-r0-b, leaf-r1-a and leaf-r1-b", targets)
	}
}

// TestPlaneRestrictedUntaggedMesh checks the unspecified (empty ToR) mesh:
// with a plane, only same-plane RNICs of other hosts are returned.
func TestPlaneRestrictedUntaggedMesh(t *testing.T) {
	cleanDatabase(t)
	for h := 1; h <= 3; h++ {
		host := fmt.Sprintf("untagged-host-%d", h)
		registerPlaned(t, fmt.Sprintf("untagged-agent-%d", h), host,
			planedRNIC(fmt.Sprintf("fe80::e%d0", h), uint32(700+h), host, "", "mlx5_0", "rail0"),
			planedRNIC(fmt.Sprintf("fe80::e%d1", h), uint32(800+h), host, "", "mlx5_1", "rail1"),
		)
	}
	targets := planedPinglist(t, "fe80::e10", "", "", controller_agent.PinglistType_TOR_MESH)
	if len(targets) != 2 || !containsGID(targets, "fe80::e20") || !containsGID(targets, "fe80::e30") {
		t.Errorf("untagged rail0 mesh = %v, want fe80::e20 and fe80::e30", targets)
	}
}

// TestRegistryPlaneMigration recreates the pre-plane rnics schema with a
// legacy row, then opens the registry as a newly upgraded controller would:
// the plane_id column must be added, the legacy row must read back with an
// empty plane, and new registrations must store planes.
func TestRegistryPlaneMigration(t *testing.T) {
	now := time.Now().Unix()
	executeSQL(t,
		`DROP TABLE IF EXISTS rnics`,
		`CREATE TABLE rnics (
			rnic_gid TEXT PRIMARY KEY,
			qpn INTEGER NOT NULL,
			agent_id TEXT NOT NULL,
			agent_ip TEXT NOT NULL,
			rnic_ip TEXT NOT NULL,
			tor_id TEXT NOT NULL,
			hostname TEXT NOT NULL,
			device_name TEXT NOT NULL,
			last_updated_epoch INTEGER NOT NULL
		)`,
		fmt.Sprintf(`INSERT INTO rnics VALUES ('fe80::f1', 900, 'legacy-agent', '192.0.2.1', '10.9.9.1', 'tor-legacy', 'legacy-host', 'mlx5_0', %d)`, now),
	)

	// Opening twice also covers the already-migrated path.
	for i := 0; i < 2; i++ {
		reg, err := registry.NewRnicRegistry(rqliteURL(), 0, 0)
		if err != nil {
			t.Fatalf("NewRnicRegistry (open %d): %v", i+1, err)
		}
		reg.Close()
	}

	reg, err := registry.NewRnicRegistry(rqliteURL(), 0, 0)
	if err != nil {
		t.Fatalf("NewRnicRegistry: %v", err)
	}
	defer reg.Close()
	ctx := context.Background()

	legacy, err := reg.GetRNICByGID(ctx, "fe80::f1")
	if err != nil || legacy == nil {
		t.Fatalf("GetRNICByGID(legacy): %v, %v", legacy, err)
	}
	if legacy.GetPlaneId() != "" || legacy.GetTorId() != "tor-legacy" {
		t.Errorf("legacy row = %+v, want tor-legacy with empty plane", legacy)
	}

	// The running controller writes through the migrated table.
	registerPlaned(t, "migrated-agent", "migrated-host",
		planedRNIC("fe80::f2", 901, "migrated-host", "tor-new", "mlx5_0", "rail0"))
	row, err := reg.GetRNICByGID(ctx, "fe80::f2")
	if err != nil || row == nil {
		t.Fatalf("GetRNICByGID(new): %v, %v", row, err)
	}
	if row.GetPlaneId() != "rail0" {
		t.Errorf("new row plane = %q, want rail0", row.GetPlaneId())
	}
	cleanDatabase(t)
}
