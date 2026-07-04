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

// Default thresholds used when the caller does not supply a positive value
// to NewRnicRegistry. These mirror the values that were previously
// hardcoded directly into the SQL queries.
const (
	// DefaultActiveThresholdSec is the window (in seconds) within which an
	// RNIC entry's last_updated_epoch must fall to be considered "active"
	// for pinglist generation and lookups.
	DefaultActiveThresholdSec = 300

	// DefaultStaleThresholdSec is the window (in seconds) after which an
	// RNIC entry is considered stale and eligible for removal.
	DefaultStaleThresholdSec = 900

	// DefaultInterTorSampleSize is the default number of distinct ToRs
	// sampled for inter-ToR pinglist generation.
	DefaultInterTorSampleSize = 5
)

// RnicRegistry manages RNIC information stored in rqlite.
type RnicRegistry struct {
	conn *gorqlite.Connection

	// activeThresholdSec is the "active" window (seconds) used by queries
	// that only consider recently-updated RNIC entries.
	activeThresholdSec int
	// staleThresholdSec is the window (seconds) after which entries are
	// considered stale and removed or excluded.
	staleThresholdSec int
	// interTorSampleSize caps the number of distinct ToRs sampled by
	// GetSampleRNICsFromOtherToRs.
	interTorSampleSize int
}

// NewRnicRegistry creates a new RNIC registry connected to the given rqlite
// URI. It initializes the database schema (table + indexes) before
// returning. activeThresholdSec, staleThresholdSec, and interTorSampleSize
// configure the thresholds described above; a value <= 0 falls back to the
// corresponding Default* constant.
func NewRnicRegistry(dbURI string, activeThresholdSec, staleThresholdSec, interTorSampleSize int) (*RnicRegistry, error) {
	log.Info().Str("dbURI", dbURI).Msg("Initializing RNIC registry with rqlite")

	if activeThresholdSec <= 0 {
		activeThresholdSec = DefaultActiveThresholdSec
	}
	if staleThresholdSec <= 0 {
		staleThresholdSec = DefaultStaleThresholdSec
	}
	if interTorSampleSize <= 0 {
		interTorSampleSize = DefaultInterTorSampleSize
	}

	conn, err := gorqlite.Open(dbURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rqlite: %w", err)
	}

	registry := &RnicRegistry{
		conn:               conn,
		activeThresholdSec: activeThresholdSec,
		staleThresholdSec:  staleThresholdSec,
		interTorSampleSize: interTorSampleSize,
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
// because rqlite's WriteOne executes a single statement at a time. This
// runs once at startup, before any request-scoped context exists, so it
// uses context.Background().
func (r *RnicRegistry) initializeSchema() error {
	ctx := context.Background()

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

	if _, err := r.conn.WriteOneContext(ctx, createTableSQL); err != nil {
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
		if _, err := r.conn.WriteOneContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// RegisterRNICs upserts all of the given RNIC entries for a single agent as
// one atomic rqlite transaction (WriteParameterizedContext executes all
// statements as a single transaction). This guarantees that a partial
// failure (e.g. a constraint violation on one RNIC) never leaves some of the
// agent's RNICs registered while others are silently dropped. The
// last_updated_epoch field is set to the current Unix timestamp (seconds)
// for every row.
func (r *RnicRegistry) RegisterRNICs(
	ctx context.Context,
	agentID string,
	agentIP string,
	rnics []*controller_agent.RnicInfo,
) error {
	if len(rnics) == 0 {
		return nil
	}

	log.Info().
		Str("agentID", agentID).
		Int("rnicCount", len(rnics)).
		Msg("Registering RNICs")

	upsertSQL := `
	INSERT OR REPLACE INTO rnics
	(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name, last_updated_epoch)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`

	now := time.Now().Unix()

	statements := make([]gorqlite.ParameterizedStatement, 0, len(rnics))
	for _, rnic := range rnics {
		statements = append(statements, gorqlite.ParameterizedStatement{
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
		})
	}

	results, err := r.conn.WriteParameterizedContext(ctx, statements)
	if err != nil {
		return fmt.Errorf("failed to register RNICs: %w", err)
	}

	for i, res := range results {
		if res.Err != nil {
			return fmt.Errorf("failed to register RNIC %s: %w", rnics[i].GetGid(), res.Err)
		}
	}

	return nil
}

// GetRNICsByToR returns all active RNICs (updated within the configured
// active-threshold window) belonging to the specified ToR switch.
func (r *RnicRegistry) GetRNICsByToR(
	ctx context.Context,
	torID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Str("torID", torID).Msg("Getting RNICs by ToR")

	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
	FROM rnics
	WHERE tor_id = ?
	AND last_updated_epoch > (strftime('%s','now') - ?);`

	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{torID, r.activeThresholdSec},
	}

	result, err := r.conn.QueryOneParameterizedContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query RNICs by ToR: %w", err)
	}

	return scanRnicInfoRows(result)
}

// GetSampleRNICsFromOtherToRs returns one representative RNIC from each ToR
// other than the excluded one, up to interTorSampleSize distinct ToRs. Only
// active entries (updated within the configured active-threshold window)
// are considered. Candidate rows are fetched in random order (ORDER BY
// RANDOM()) so that, across repeated calls, a different representative ToR
// set and RNIC is chosen each time rather than always sampling the same
// fixed 5 ToRs and RNICs (as GROUP BY without ORDER BY would, since SQLite
// does not guarantee which row within a group is returned).
func (r *RnicRegistry) GetSampleRNICsFromOtherToRs(
	ctx context.Context,
	excludeTorID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Str("excludeTorID", excludeTorID).Msg("Getting sample RNICs from other ToRs")

	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
	FROM rnics
	WHERE tor_id != ?
	AND last_updated_epoch > (strftime('%s','now') - ?)
	ORDER BY RANDOM();`

	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{excludeTorID, r.activeThresholdSec},
	}

	result, err := r.conn.QueryOneParameterizedContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to query sample RNICs from other ToRs: %w", err)
	}

	candidates, err := scanRnicInfoRows(result)
	if err != nil {
		return nil, err
	}

	// Pick at most one RNIC per distinct ToR, up to interTorSampleSize
	// ToRs. Since candidates arrived in random order, this yields a
	// randomly chosen representative ToR set and RNIC on each call.
	seenToRs := make(map[string]bool, r.interTorSampleSize)
	sampled := make([]*controller_agent.RnicInfo, 0, r.interTorSampleSize)
	for _, rnic := range candidates {
		if seenToRs[rnic.GetTorId()] {
			continue
		}
		seenToRs[rnic.GetTorId()] = true
		sampled = append(sampled, rnic)
		if len(sampled) >= r.interTorSampleSize {
			break
		}
	}

	return sampled, nil
}

// GetRNICInfo looks up a single RNIC by GID (primary key) or IP address.
// Only active entries (updated within the configured active-threshold
// window) are returned. Returns (nil, nil) when no matching entry is found.
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
		AND last_updated_epoch > (strftime('%s','now') - ?)
		LIMIT 1;`
		stmt = gorqlite.ParameterizedStatement{
			Query:     querySQL,
			Arguments: []interface{}{targetGID, r.activeThresholdSec},
		}
	} else {
		// Fallback to IP-based lookup.
		querySQL := `
		SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
		FROM rnics
		WHERE rnic_ip = ?
		AND last_updated_epoch > (strftime('%s','now') - ?)
		LIMIT 1;`
		stmt = gorqlite.ParameterizedStatement{
			Query:     querySQL,
			Arguments: []interface{}{targetIP, r.activeThresholdSec},
		}
	}

	result, err := r.conn.QueryOneParameterizedContext(ctx, stmt)
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

// CleanupStaleEntries removes RNIC entries that have not been updated
// within the configured stale-threshold window.
func (r *RnicRegistry) CleanupStaleEntries(ctx context.Context) error {
	log.Info().Msg("Cleaning up stale RNIC entries")

	cleanupSQL := `
	DELETE FROM rnics
	WHERE last_updated_epoch < (strftime('%s','now') - ?);`

	stmt := gorqlite.ParameterizedStatement{
		Query:     cleanupSQL,
		Arguments: []interface{}{r.staleThresholdSec},
	}

	result, err := r.conn.WriteOneParameterizedContext(ctx, stmt)
	if err != nil {
		return fmt.Errorf("failed to cleanup stale entries: %w", err)
	}

	log.Info().
		Int64("removed", result.RowsAffected).
		Msg("Cleaned up stale RNIC entries")

	return nil
}

// ListAllRNICs returns all active RNICs (updated within the configured
// stale-threshold window), ordered by tor_id and hostname.
func (r *RnicRegistry) ListAllRNICs(ctx context.Context) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Msg("Listing all active RNICs")

	querySQL := `
	SELECT rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name
	FROM rnics
	WHERE last_updated_epoch > (strftime('%s','now') - ?)
	ORDER BY tor_id, hostname;`

	stmt := gorqlite.ParameterizedStatement{
		Query:     querySQL,
		Arguments: []interface{}{r.staleThresholdSec},
	}

	result, err := r.conn.QueryOneParameterizedContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to list RNICs: %w", err)
	}

	return scanRnicInfoRows(result)
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
