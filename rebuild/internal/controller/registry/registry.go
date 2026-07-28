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
)

// dbConn is the subset of gorqlite.Connection's API used by RnicRegistry. It
// is declared here, at the point of use, so that RnicRegistry's methods can
// be unit tested against a fake connection instead of a real rqlite-backed
// one.
type dbConn interface {
	Close()
	WriteOneContext(ctx context.Context, sqlStatement string) (gorqlite.WriteResult, error)
	WriteOneParameterizedContext(ctx context.Context, statement gorqlite.ParameterizedStatement) (gorqlite.WriteResult, error)
	WriteParameterizedContext(ctx context.Context, sqlStatements []gorqlite.ParameterizedStatement) ([]gorqlite.WriteResult, error)
	QueryOneParameterizedContext(ctx context.Context, statement gorqlite.ParameterizedStatement) (gorqlite.QueryResult, error)
}

// RnicRegistry manages RNIC information stored in rqlite.
type RnicRegistry struct {
	conn dbConn

	// activeThresholdSec is the "active" window (seconds) used by queries
	// that only consider recently-updated RNIC entries.
	activeThresholdSec int
	// staleThresholdSec is the window (seconds) after which entries are
	// considered stale and removed or excluded.
	staleThresholdSec int
}

// NewRnicRegistry creates a new RNIC registry connected to the given rqlite
// URI. It initializes the database schema (table + indexes) before
// returning. activeThresholdSec and staleThresholdSec configure the thresholds
// described above; a value <= 0 falls back to the corresponding Default*
// constant. Inter-ToR sampling (one representative RNIC per foreign ToR) is
// performed by the pinglist generator, not here, because it must run after the
// generator's same-host / same-address-family filtering so that a ToR is only
// dropped when it has no valid target for the requester (see issues #39, #41).
func NewRnicRegistry(dbURI string, activeThresholdSec, staleThresholdSec int) (*RnicRegistry, error) {
	log.Info().Str("dbURI", dbURI).Msg("Initializing RNIC registry with rqlite")

	if activeThresholdSec <= 0 {
		activeThresholdSec = DefaultActiveThresholdSec
	}
	if staleThresholdSec <= 0 {
		staleThresholdSec = DefaultStaleThresholdSec
	}

	conn, err := gorqlite.Open(dbURI)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rqlite: %w", err)
	}

	registry := &RnicRegistry{
		conn:               conn,
		activeThresholdSec: activeThresholdSec,
		staleThresholdSec:  staleThresholdSec,
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

// RegisterRNICs replaces the full set of RNIC entries registered for a
// single agent as one atomic rqlite transaction (WriteParameterizedContext
// executes all statements as a single transaction): it first deletes every
// existing row for agentID, then inserts one row per entry in rnics. This
// set-replacement semantics (rather than a per-RNIC upsert) ensures that
// RNICs no longer reported by the agent (e.g. a NIC removed, an allowlist
// change, or a QP recreated with a new QPN) are removed immediately instead
// of lingering in the registry - and therefore in pinglists - until the
// stale-threshold window expires. This holds even when rnics is empty (the
// agent currently has no RNICs at all): the DELETE still runs, on its own,
// so the agent's previously-registered rows don't linger either. This is
// safe for the agent's periodic heartbeat re-registration too, since the
// agent always sends its complete current RNIC set on every registration
// and heartbeat call (see buildRegistrationRequest in
// internal/agent/agent.go), never a partial delta. The whole operation
// still runs in a single transaction, so a partial failure (e.g. a
// constraint violation on one RNIC) never leaves the agent with some RNICs
// deleted and none re-inserted. The last_updated_epoch field is set to the
// current Unix timestamp (seconds) for every row.
func (r *RnicRegistry) RegisterRNICs(
	ctx context.Context,
	agentID string,
	agentIP string,
	rnics []*controller_agent.RnicInfo,
) error {
	log.Info().
		Str("agentID", agentID).
		Int("rnicCount", len(rnics)).
		Msg("Registering RNICs")

	deleteSQL := `DELETE FROM rnics WHERE agent_id = ?;`

	insertSQL := `
	INSERT OR REPLACE INTO rnics
	(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name, last_updated_epoch)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`

	now := time.Now().Unix()

	statements := make([]gorqlite.ParameterizedStatement, 0, len(rnics)+1)
	statements = append(statements, gorqlite.ParameterizedStatement{
		Query:     deleteSQL,
		Arguments: []interface{}{agentID},
	})
	for _, rnic := range rnics {
		statements = append(statements, gorqlite.ParameterizedStatement{
			Query: insertSQL,
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
		return fmt.Errorf("failed to replace RNICs: %w", err)
	}

	if results[0].Err != nil {
		return fmt.Errorf("failed to delete stale RNICs for agent %s: %w", agentID, results[0].Err)
	}

	for i, res := range results[1:] {
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

// GetActiveRNICsInOtherToRs returns every active RNIC (updated within the
// configured active-threshold window) that belongs to a ToR other than the
// excluded one, in random order (ORDER BY RANDOM()).
//
// It intentionally does NOT sample one-per-ToR here: the pinglist generator
// samples after filtering out same-host and cross-address-family targets, so
// that inter-ToR coverage is only dropped for a foreign ToR when that ToR has
// no valid representative for the requester. Sampling in SQL (or here) before
// that filtering could silently blind a whole ToR whenever its randomly-chosen
// representative happened to be a same-host or cross-family RNIC (issues #39,
// #41). Rows are still returned in random order so the generator picks a
// randomly-varying representative per ToR across repeated calls.
func (r *RnicRegistry) GetActiveRNICsInOtherToRs(
	ctx context.Context,
	excludeTorID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Str("excludeTorID", excludeTorID).Msg("Getting active RNICs in other ToRs")

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
		return nil, fmt.Errorf("failed to query active RNICs in other ToRs: %w", err)
	}

	return scanRnicInfoRows(result)
}

// ResolveHostnameByGID returns the hostname the RNIC identified by gid is
// registered under, or "" when no active entry matches (e.g. the requester has
// not registered yet). A "" result signals the pinglist generator to fall back
// to GID-based self-exclusion instead of same-host filtering. Genuine query
// errors are propagated. It reuses GetRNICInfo's active-window GID lookup.
func (r *RnicRegistry) ResolveHostnameByGID(
	ctx context.Context,
	gid string,
) (string, error) {
	if gid == "" {
		return "", nil
	}
	info, err := r.GetRNICInfo(ctx, "", gid)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", nil
	}
	return info.GetHostName(), nil
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
