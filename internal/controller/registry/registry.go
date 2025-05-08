package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rqlite/gorqlite"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// RnicRegistry manages RNIC information
type RnicRegistry struct {
	conn *gorqlite.Connection
}

// NewRnicRegistry creates a new RNIC registry
func NewRnicRegistry(dbURI string) (*RnicRegistry, error) {
	log.Info().Str("dbURI", dbURI).Msg("Initializing RNIC registry with rqlite")

	// Connect to rqlite
	conn, err := gorqlite.Open(dbURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rqlite: %w", err)
	}

	// Create registry
	registry := &RnicRegistry{
		conn: conn,
	}

	// Initialize database schema
	if err := registry.initializeSchema(); err != nil {
		// Close connection if initialization fails
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return registry, nil
}

// initializeSchema creates the necessary tables if they don't exist
func (r *RnicRegistry) initializeSchema() error {
	// Create rnics table
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS rnics (
		rnic_gid TEXT PRIMARY KEY,
		qpn INTEGER NOT NULL,
		agent_id TEXT NOT NULL,
		agent_ip TEXT NOT NULL,
		rnic_ip TEXT NOT NULL,
		tor_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		last_updated TEXT NOT NULL
	);
	`

	// Create indexes for efficient queries
	createIndexesSQL := `
	CREATE INDEX IF NOT EXISTS idx_rnics_agent_id ON rnics (agent_id);
	CREATE INDEX IF NOT EXISTS idx_rnics_tor_id ON rnics (tor_id);
	CREATE INDEX IF NOT EXISTS idx_rnics_rnic_ip ON rnics (rnic_ip);
	`

	// Execute schema creation
	_, err := r.conn.WriteOne(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create rnics table: %w", err)
	}

	_, err = r.conn.WriteOne(createIndexesSQL)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// Close closes the registry
func (r *RnicRegistry) Close() error {
	// Close database connection
	if r.conn != nil {
		r.conn.Close()
	}
	return nil
}

// RegisterRNIC registers an RNIC with the registry
func (r *RnicRegistry) RegisterRNIC(
	ctx context.Context,
	agentID string,
	agentIP string,
	rnic *controller_agent.RnicInfo,
) error {
	log.Info().
		Str("agentID", agentID).
		Str("rnicGID", rnic.Gid).
		Msg("Registering RNIC")

	// Upsert RNIC in database
	upsertSQL := `
	INSERT OR REPLACE INTO rnics
	(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, last_updated)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?);
	`

	// Current time in RFC3339 format
	now := time.Now().UTC().Format(time.RFC3339)

	// Create parameterized statement
	stmt := gorqlite.ParameterizedStatement{
		Query: upsertSQL,
		Arguments: []interface{}{
			rnic.Gid,
			rnic.Qpn,
			agentID,
			agentIP,
			rnic.IpAddress,
			rnic.TorId,
			rnic.HostName,
			now,
		},
	}

	// Execute upsert
	_, err := r.conn.WriteOneParameterized(stmt)
	if err != nil {
		return fmt.Errorf("failed to register RNIC: %w", err)
	}

	return nil
}

// GetRNICsByToR gets all RNICs in a ToR
func (r *RnicRegistry) GetRNICsByToR(
	ctx context.Context,
	torID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Info().Str("torID", torID).Msg("Getting RNICs by ToR")

	// Query for all RNICs in the specified ToR
	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id
	FROM rnics
	WHERE tor_id = ?
	AND last_updated > datetime('now', '-5 minutes');
	`

	// Create parameterized statement
	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{torID},
	}

	// Execute query
	result, err := r.conn.QueryOneParameterized(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query RNICs by ToR: %w", err)
	}

	var rnics []*controller_agent.RnicInfo

	// Iterate through result rows
	for result.Next() {
		var gid, ip, hostname, torID string
		var qpn uint32

		// Scan row values
		if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Add to result list
		rnics = append(rnics, &controller_agent.RnicInfo{
			Gid:       gid,
			Qpn:       qpn,
			IpAddress: ip,
			HostName:  hostname,
			TorId:     torID,
		})
	}

	return rnics, nil
}

// GetSampleRNICsFromOtherToRs gets sample RNICs from other ToRs
func (r *RnicRegistry) GetSampleRNICsFromOtherToRs(
	ctx context.Context,
	excludeTorID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Info().Str("excludeTorID", excludeTorID).Msg("Getting sample RNICs from other ToRs")

	// Query for a sample of RNICs from each ToR except the excluded one
	// This is a simplified implementation - in a real system, you might want
	// a more sophisticated sampling strategy
	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id
	FROM rnics
	WHERE tor_id != ?
	AND last_updated > datetime('now', '-5 minutes')
	GROUP BY tor_id
	LIMIT 5;
	`

	// Create parameterized statement
	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{excludeTorID},
	}

	// Execute query
	result, err := r.conn.QueryOneParameterized(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query sample RNICs: %w", err)
	}

	var rnics []*controller_agent.RnicInfo

	// Iterate through result rows
	for result.Next() {
		var gid, ip, hostname, torID string
		var qpn uint32

		// Scan row values
		if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Add to result list
		rnics = append(rnics, &controller_agent.RnicInfo{
			Gid:       gid,
			Qpn:       qpn,
			IpAddress: ip,
			HostName:  hostname,
			TorId:     torID,
		})
	}

	return rnics, nil
}

// GetRNICInfo gets RNIC info by IP or GID
func (r *RnicRegistry) GetRNICInfo(
	ctx context.Context,
	targetIP string,
	targetGID string,
) (*controller_agent.RnicInfo, error) {
	log.Info().
		Str("targetIP", targetIP).
		Str("targetGID", targetGID).
		Msg("Getting RNIC info")

	if targetIP == "" && targetGID == "" {
		return nil, errors.New("either targetIP or targetGID must be provided")
	}

	var stmt gorqlite.ParameterizedStatement

	if targetGID != "" {
		// Query by GID (primary key)
		querySQL := `
		SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id
		FROM rnics
		WHERE rnic_gid = ?
		AND last_updated > datetime('now', '-5 minutes')
		LIMIT 1;
		`
		stmt = gorqlite.ParameterizedStatement{
			Query:     querySQL,
			Arguments: []interface{}{targetGID},
		}
	} else {
		// Query by IP address
		querySQL := `
		SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id
		FROM rnics
		WHERE rnic_ip = ?
		AND last_updated > datetime('now', '-5 minutes')
		LIMIT 1;
		`
		stmt = gorqlite.ParameterizedStatement{
			Query:     querySQL,
			Arguments: []interface{}{targetIP},
		}
	}

	// Execute query
	result, err := r.conn.QueryOneParameterized(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query RNIC info: %w", err)
	}

	// Check if we have a result
	if !result.Next() {
		return nil, nil // No match found
	}

	// Scan values
	var gid, ip, hostname, torID string
	var qpn uint32
	if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID); err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	// Return the RNIC info
	return &controller_agent.RnicInfo{
		Gid:       gid,
		Qpn:       qpn,
		IpAddress: ip,
		HostName:  hostname,
		TorId:     torID,
	}, nil
}

// CleanupStaleEntries removes entries that haven't been updated recently
func (r *RnicRegistry) CleanupStaleEntries(ctx context.Context) error {
	log.Info().Msg("Cleaning up stale RNIC entries")

	// Delete entries that haven't been updated in more than 15 minutes
	cleanupSQL := `
	DELETE FROM rnics
	WHERE last_updated < datetime('now', '-15 minutes');
	`

	// Execute cleanup
	result, err := r.conn.WriteOne(cleanupSQL)
	if err != nil {
		return fmt.Errorf("failed to cleanup stale entries: %w", err)
	}

	log.Info().Int("removed", int(result.RowsAffected)).Msg("Cleaned up stale RNIC entries")

	return nil
}

// ListAllRNICs lists all RNICs in the registry (for debugging/admin purposes)
func (r *RnicRegistry) ListAllRNICs(ctx context.Context) ([]*controller_agent.RnicInfo, error) {
	log.Info().Msg("Listing all RNICs")

	// Query for all active RNICs
	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id
	FROM rnics
	WHERE last_updated > datetime('now', '-15 minutes')
	ORDER BY tor_id, hostname;
	`

	// Execute query
	result, err := r.conn.QueryOne(querySQL)
	if err != nil {
		return nil, fmt.Errorf("failed to list RNICs: %w", err)
	}

	var rnics []*controller_agent.RnicInfo

	// Iterate through result rows
	for result.Next() {
		var gid, ip, hostname, torID string
		var qpn uint32

		// Scan row values
		if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Add to result list
		rnics = append(rnics, &controller_agent.RnicInfo{
			Gid:       gid,
			Qpn:       qpn,
			IpAddress: ip,
			HostName:  hostname,
			TorId:     torID,
		})
	}

	return rnics, nil
}

// GetTorIDs gets a list of all active ToR IDs
func (r *RnicRegistry) GetTorIDs(ctx context.Context) ([]string, error) {
	log.Info().Msg("Getting ToR IDs")

	// Query for distinct ToR IDs
	querySQL := `
	SELECT DISTINCT tor_id
	FROM rnics
	WHERE last_updated > datetime('now', '-15 minutes')
	ORDER BY tor_id;
	`

	// Execute query
	result, err := r.conn.QueryOne(querySQL)
	if err != nil {
		return nil, fmt.Errorf("failed to get ToR IDs: %w", err)
	}

	var torIDs []string

	// Iterate through result rows
	for result.Next() {
		var torID string

		// Scan row values
		if err := result.Scan(&torID); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Add to result list
		torIDs = append(torIDs, torID)
	}

	return torIDs, nil
}
