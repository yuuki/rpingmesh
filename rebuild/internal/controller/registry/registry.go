package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// RnicRegistry manages RNIC information stored in rqlite.
type RnicRegistry struct {
	conn *gorqlite.Connection
}

// NewRnicRegistry creates a new RNIC registry connected to the given rqlite URI.
// It initializes the database schema (table + indexes) before returning.
func NewRnicRegistry(dbURI string) (*RnicRegistry, error) {
	log.Info().Str("dbURI", dbURI).Msg("Initializing RNIC registry with rqlite")

	conn, err := gorqlite.Open(dbURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rqlite: %w", err)
	}

	registry := &RnicRegistry{
		conn: conn,
	}

	if err := registry.initializeSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return registry, nil
}

// Close closes the underlying rqlite connection.
func (r *RnicRegistry) Close() error {
	if r.conn != nil {
		r.conn.Close()
	}
	return nil
}

// initializeSchema creates the rnics table and associated indexes if they
// do not already exist. Each index is created in a separate write call
// because rqlite's WriteOne executes a single statement at a time.
func (r *RnicRegistry) initializeSchema() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS rnics (
		rnic_gid TEXT PRIMARY KEY,
		qpn INTEGER NOT NULL,
		agent_id TEXT NOT NULL,
		agent_ip TEXT NOT NULL,
		rnic_ip TEXT NOT NULL,
		tor_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		device_name TEXT NOT NULL,
		last_updated_epoch INTEGER NOT NULL
	);`

	if _, err := r.conn.WriteOne(createTableSQL); err != nil {
		return fmt.Errorf("failed to create rnics table: %w", err)
	}

	// Create each index separately to avoid multi-statement issues.
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_rnics_agent_id ON rnics (agent_id);`,
		`CREATE INDEX IF NOT EXISTS idx_rnics_tor_id ON rnics (tor_id);`,
		`CREATE INDEX IF NOT EXISTS idx_rnics_rnic_ip ON rnics (rnic_ip);`,
		`CREATE INDEX IF NOT EXISTS idx_rnics_last_updated ON rnics (last_updated_epoch);`,
	}

	for _, idx := range indexes {
		if _, err := r.conn.WriteOne(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// RegisterRNIC upserts an RNIC entry in the registry. The last_updated_epoch
// field is set to the current Unix timestamp (seconds).
func (r *RnicRegistry) RegisterRNIC(
	ctx context.Context,
	agentID string,
	agentIP string,
	rnic *controller_agent.RnicInfo,
) error {
	log.Info().
		Str("agentID", agentID).
		Str("rnicGID", rnic.GetGid()).
		Msg("Registering RNIC")

	upsertSQL := `
	INSERT OR REPLACE INTO rnics
	(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name, last_updated_epoch)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`

	now := time.Now().Unix()

	stmt := gorqlite.ParameterizedStatement{
		Query: upsertSQL,
		Arguments: []interface{}{
			rnic.GetGid(),
			rnic.GetQpn(),
			agentID,
			agentIP,
			rnic.GetIpAddress(),
			rnic.GetTorId(),
			rnic.GetHostName(),
			rnic.GetDeviceName(),
			now,
		},
	}

	if _, err := r.conn.WriteOneParameterized(stmt); err != nil {
		return fmt.Errorf("failed to register RNIC: %w", err)
	}

	return nil
}

// GetRNICsByToR returns all active RNICs (updated within the last 5 minutes)
// belonging to the specified ToR switch.
func (r *RnicRegistry) GetRNICsByToR(
	ctx context.Context,
	torID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Str("torID", torID).Msg("Getting RNICs by ToR")

	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
	FROM rnics
	WHERE tor_id = ?
	AND last_updated_epoch > (strftime('%s','now') - 300);`

	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{torID},
	}

	result, err := r.conn.QueryOneParameterized(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query RNICs by ToR: %w", err)
	}

	return scanRnicInfoRows(result)
}

// GetSampleRNICsFromOtherToRs returns one representative RNIC from each ToR
// other than the excluded one, limited to 5 ToRs. Only active entries
// (updated within the last 5 minutes) are considered.
func (r *RnicRegistry) GetSampleRNICsFromOtherToRs(
	ctx context.Context,
	excludeTorID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Str("excludeTorID", excludeTorID).Msg("Getting sample RNICs from other ToRs")

	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
	FROM rnics
	WHERE tor_id != ?
	AND last_updated_epoch > (strftime('%s','now') - 300)
	GROUP BY tor_id
	LIMIT 5;`

	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{excludeTorID},
	}

	result, err := r.conn.QueryOneParameterized(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query sample RNICs from other ToRs: %w", err)
	}

	return scanRnicInfoRows(result)
}

// GetRNICInfo looks up a single RNIC by GID (primary key) or IP address.
// Only active entries (updated within the last 5 minutes) are returned.
// Returns (nil, nil) when no matching entry is found.
func (r *RnicRegistry) GetRNICInfo(
	ctx context.Context,
	targetIP string,
	targetGID string,
) (*controller_agent.RnicInfo, error) {
	log.Debug().
		Str("targetIP", targetIP).
		Str("targetGID", targetGID).
		Msg("Getting RNIC info")

	if targetIP == "" && targetGID == "" {
		return nil, errors.New("either targetIP or targetGID must be provided")
	}

	var stmt gorqlite.ParameterizedStatement

	if targetGID != "" {
		// Query by GID (primary key) for fastest lookup.
		querySQL := `
		SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
		FROM rnics
		WHERE rnic_gid = ?
		AND last_updated_epoch > (strftime('%s','now') - 300)
		LIMIT 1;`
		stmt = gorqlite.ParameterizedStatement{
			Query:     querySQL,
			Arguments: []interface{}{targetGID},
		}
	} else {
		// Fallback to IP-based lookup.
		querySQL := `
		SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
		FROM rnics
		WHERE rnic_ip = ?
		AND last_updated_epoch > (strftime('%s','now') - 300)
		LIMIT 1;`
		stmt = gorqlite.ParameterizedStatement{
			Query:     querySQL,
			Arguments: []interface{}{targetIP},
		}
	}

	result, err := r.conn.QueryOneParameterized(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query RNIC info: %w", err)
	}

	// Return nil when no matching row is found.
	if !result.Next() {
		return nil, nil
	}

	var gid, ip, hostname, torID, deviceName string
	var qpn int64
	if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID, &deviceName); err != nil {
		return nil, fmt.Errorf("failed to scan RNIC info row: %w", err)
	}

	return &controller_agent.RnicInfo{
		Gid:        gid,
		Qpn:        uint32(qpn),
		IpAddress:  ip,
		HostName:   hostname,
		TorId:      torID,
		DeviceName: deviceName,
	}, nil
}

// CleanupStaleEntries removes RNIC entries that have not been updated in
// the last 15 minutes (900 seconds).
func (r *RnicRegistry) CleanupStaleEntries(ctx context.Context) error {
	log.Info().Msg("Cleaning up stale RNIC entries")

	cleanupSQL := `
	DELETE FROM rnics
	WHERE last_updated_epoch < (strftime('%s','now') - 900);`

	result, err := r.conn.WriteOne(cleanupSQL)
	if err != nil {
		return fmt.Errorf("failed to cleanup stale entries: %w", err)
	}

	log.Info().
		Int64("removed", result.RowsAffected).
		Msg("Cleaned up stale RNIC entries")

	return nil
}

// ListAllRNICs returns all active RNICs (updated within the last 15 minutes),
// ordered by tor_id and hostname.
func (r *RnicRegistry) ListAllRNICs(ctx context.Context) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Msg("Listing all active RNICs")

	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
	FROM rnics
	WHERE last_updated_epoch > (strftime('%s','now') - 900)
	ORDER BY tor_id, hostname;`

	result, err := r.conn.QueryOne(querySQL)
	if err != nil {
		return nil, fmt.Errorf("failed to list RNICs: %w", err)
	}

	return scanRnicInfoRows(result)
}

// GetTorIDs returns the distinct set of ToR switch IDs that have at least
// one active RNIC (updated within the last 15 minutes).
func (r *RnicRegistry) GetTorIDs(ctx context.Context) ([]string, error) {
	log.Debug().Msg("Getting active ToR IDs")

	querySQL := `
	SELECT DISTINCT tor_id
	FROM rnics
	WHERE last_updated_epoch > (strftime('%s','now') - 900)
	ORDER BY tor_id;`

	result, err := r.conn.QueryOne(querySQL)
	if err != nil {
		return nil, fmt.Errorf("failed to get ToR IDs: %w", err)
	}

	var torIDs []string
	for result.Next() {
		var torID string
		if err := result.Scan(&torID); err != nil {
			return nil, fmt.Errorf("failed to scan ToR ID row: %w", err)
		}
		torIDs = append(torIDs, torID)
	}

	return torIDs, nil
}

// scanRnicInfoRows is a helper that iterates over query result rows and
// converts them into a slice of RnicInfo proto messages.
func scanRnicInfoRows(result gorqlite.QueryResult) ([]*controller_agent.RnicInfo, error) {
	var rnics []*controller_agent.RnicInfo

	for result.Next() {
		var gid, ip, hostname, torID, deviceName string
		var qpn int64

		if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID, &deviceName); err != nil {
			return nil, fmt.Errorf("failed to scan RNIC row: %w", err)
		}

		rnics = append(rnics, &controller_agent.RnicInfo{
			Gid:        gid,
			Qpn:        uint32(qpn),
			IpAddress:  ip,
			HostName:   hostname,
			TorId:      torID,
			DeviceName: deviceName,
		})
	}

	return rnics, nil
}
