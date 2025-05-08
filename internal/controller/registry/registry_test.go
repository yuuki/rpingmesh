package registry

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func getDBURI() string {
	dbURI := os.Getenv("RQLITE_DB_URI")
	if dbURI == "" {
		dbURI = "http://localhost:4001" // Default value for Docker container environment
	}
	return dbURI
}

// clearRnicsTable cleans up the rnics table before each test
func clearRnicsTable(t *testing.T, registry *RnicRegistry) {
	t.Helper()
	_, err := registry.conn.WriteOne("DELETE FROM rnics")
	require.NoError(t, err, "Failed to clear rnics table")
}

func TestRnicRegistryBasic(t *testing.T) {
	dbURI := getDBURI()

	// Create registry
	registry, err := NewRnicRegistry(dbURI)
	require.NoError(t, err, "Failed to create registry")
	defer registry.Close()

	// Clear test data
	clearRnicsTable(t, registry)

	// Test context
	ctx := context.Background()

	// Test RNIC information
	testRNIC := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1234",
		Qpn:       1025,
		IpAddress: "192.168.1.10",
		HostName:  "test-host-1",
		TorId:     "tor-A",
	}

	// Register RNIC
	err = registry.RegisterRNIC(ctx, "test-agent-1", "192.168.1.10", testRNIC)
	require.NoError(t, err, "Failed to register RNIC")

	// Get RNIC by GID
	rnic, err := registry.GetRNICInfo(ctx, "", testRNIC.Gid)
	require.NoError(t, err, "Failed to get RNIC by GID")
	require.NotNil(t, rnic, "RNIC not found")
	assert.Equal(t, testRNIC.Gid, rnic.Gid, "GID mismatch")
	assert.Equal(t, testRNIC.Qpn, rnic.Qpn, "QPN mismatch")
	assert.Equal(t, testRNIC.IpAddress, rnic.IpAddress, "IP address mismatch")

	// Get RNIC by IP
	rnic, err = registry.GetRNICInfo(ctx, testRNIC.IpAddress, "")
	require.NoError(t, err, "Failed to get RNIC by IP")
	require.NotNil(t, rnic, "RNIC not found")
	assert.Equal(t, testRNIC.Gid, rnic.Gid, "GID mismatch")

	// Get RNICs by ToR ID
	rnics, err := registry.GetRNICsByToR(ctx, testRNIC.TorId)
	require.NoError(t, err, "Failed to get RNICs by ToR")
	require.Len(t, rnics, 1, "Unexpected number of RNICs")
	assert.Equal(t, testRNIC.Gid, rnics[0].Gid, "GID mismatch")
}

func TestMultipleRNICs(t *testing.T) {
	dbURI := getDBURI()

	// Create registry
	registry, err := NewRnicRegistry(dbURI)
	require.NoError(t, err, "Failed to create registry")
	defer registry.Close()

	// Clear test data
	clearRnicsTable(t, registry)

	// Test context
	ctx := context.Background()

	// Test RNIC information (multiple ToRs)
	testRNICs := []*controller_agent.RnicInfo{
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
			Qpn:       1001,
			IpAddress: "192.168.1.1",
			HostName:  "host-1",
			TorId:     "tor-A",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1002",
			Qpn:       1002,
			IpAddress: "192.168.1.2",
			HostName:  "host-2",
			TorId:     "tor-A",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:2001",
			Qpn:       2001,
			IpAddress: "192.168.2.1",
			HostName:  "host-3",
			TorId:     "tor-B",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:3001",
			Qpn:       3001,
			IpAddress: "192.168.3.1",
			HostName:  "host-4",
			TorId:     "tor-C",
		},
	}

	// Register multiple RNICs
	for i, rnic := range testRNICs {
		agentID := "agent-" + rnic.HostName
		err = registry.RegisterRNIC(ctx, agentID, rnic.IpAddress, rnic)
		require.NoError(t, err, "Failed to register RNIC %d", i)
	}

	// Get ToR ID list
	torIDs, err := registry.GetTorIDs(ctx)
	require.NoError(t, err, "Failed to get ToR IDs")
	assert.Len(t, torIDs, 3, "Unexpected number of ToR IDs")
	assert.Contains(t, torIDs, "tor-A", "Missing tor-A")
	assert.Contains(t, torIDs, "tor-B", "Missing tor-B")
	assert.Contains(t, torIDs, "tor-C", "Missing tor-C")

	// Get RNICs belonging to ToR-A only
	rnicsA, err := registry.GetRNICsByToR(ctx, "tor-A")
	require.NoError(t, err, "Failed to get RNICs by ToR A")
	assert.Len(t, rnicsA, 2, "Unexpected number of RNICs in tor-A")

	// Get samples from other ToRs
	otherRNICs, err := registry.GetSampleRNICsFromOtherToRs(ctx, "tor-A")
	require.NoError(t, err, "Failed to get sample RNICs from other ToRs")
	assert.GreaterOrEqual(t, len(otherRNICs), 1, "Expected at least one RNIC from other ToRs")
	for _, rnic := range otherRNICs {
		assert.NotEqual(t, "tor-A", rnic.TorId, "Found RNIC from excluded ToR")
	}

	// List all RNICs
	allRNICs, err := registry.ListAllRNICs(ctx)
	require.NoError(t, err, "Failed to list all RNICs")
	assert.Len(t, allRNICs, 4, "Unexpected number of RNICs in total")
}

func TestRnicRegistryStaleEntries(t *testing.T) {
	dbURI := getDBURI()

	// Create registry
	registry, err := NewRnicRegistry(dbURI)
	require.NoError(t, err, "Failed to create registry")
	defer registry.Close()

	// Clear test data
	clearRnicsTable(t, registry)

	// Test context
	ctx := context.Background()

	// Test RNIC information
	testRNIC := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:9999",
		Qpn:       9999,
		IpAddress: "192.168.9.9",
		HostName:  "test-stale-host",
		TorId:     "tor-X",
	}

	// Register RNIC
	err = registry.RegisterRNIC(ctx, "test-stale-agent", "192.168.9.9", testRNIC)
	require.NoError(t, err, "Failed to register RNIC")

	// Directly manipulate database time for testing stale data
	// Note: In production, test reliability may depend on execution time
	// For more robust tests, time should be mocked
	conn := registry.conn
	updateSQL := `
	UPDATE rnics
	SET last_updated = datetime('now', '-20 minutes')
	WHERE rnic_gid = ?;
	`
	stmt := gorqlite.ParameterizedStatement{
		Query:     updateSQL,
		Arguments: []interface{}{testRNIC.Gid},
	}
	_, err = conn.WriteOneParameterized(stmt)
	require.NoError(t, err, "Failed to update last_updated timestamp")

	// Try to get RNIC after time advancement (should not be found)
	time.Sleep(1 * time.Second) // Wait a bit after database update
	rnic, err := registry.GetRNICInfo(ctx, "", testRNIC.Gid)
	require.NoError(t, err, "Failed to get RNIC")
	assert.Nil(t, rnic, "Expected RNIC to be filtered out due to staleness")

	// Cleanup stale entries
	err = registry.CleanupStaleEntries(ctx)
	require.NoError(t, err, "Failed to cleanup stale entries")

	// Verify after cleanup
	rnics, err := registry.ListAllRNICs(ctx)
	require.NoError(t, err, "Failed to list RNICs after cleanup")
	for _, r := range rnics {
		assert.NotEqual(t, testRNIC.Gid, r.Gid, "Found stale RNIC after cleanup")
	}
}
