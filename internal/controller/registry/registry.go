package registry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rqlite/gorqlite"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
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

	// now stamps last_updated_epoch and computes the active/stale cutoffs
	// (time.Now; injectable in tests). Cutoffs are bound as parameters rather
	// than using SQLite's 'now': rqlite rewrites 'now' in write statements in
	// the server's local timezone, so on a non-UTC host the stale cleanup once
	// deleted every row.
	now func() time.Time
}

// cutoff returns the Unix epoch (seconds) before which an entry falls outside
// a window of windowSec seconds.
func (r *RnicRegistry) cutoff(windowSec int) int64 {
	return r.now().Unix() - int64(windowSec)
}

// Startup connection retry backoff bounds. rqlited accepts TCP connections
// before its store is open and a leader is elected, so a controller started
// alongside rqlite (at boot, or when both units restart) can see transient
// errors such as "store is not open" on its first attempts.
const (
	connectInitialBackoff = 1 * time.Second
	connectMaxBackoff     = 30 * time.Second
)

// NewRnicRegistry creates a new RNIC registry connected to the given rqlite
// URI. It initializes the database schema (table + indexes) before
// returning. activeThresholdSec and staleThresholdSec configure the thresholds
// described above; a value <= 0 falls back to the corresponding Default*
// constant.
//
// Opening the connection and initializing the schema are retried with
// exponential backoff (1s doubling up to 30s) until they succeed, ctx is
// cancelled, or connectTimeout elapses, so the controller tolerates an rqlite
// node that is still starting. connectTimeout <= 0 makes a single attempt.
func NewRnicRegistry(ctx context.Context, dbURI string, activeThresholdSec, staleThresholdSec int, connectTimeout time.Duration) (*RnicRegistry, error) {
	log.Info().Str("dbURI", dbURI).Msg("Initializing RNIC registry with rqlite")

	if activeThresholdSec <= 0 {
		activeThresholdSec = DefaultActiveThresholdSec
	}
	if staleThresholdSec <= 0 {
		staleThresholdSec = DefaultStaleThresholdSec
	}

	open := func() (dbConn, error) {
		conn, err := gorqlite.Open(dbURI)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	conn, err := connectWithRetry(ctx, open, connectTimeout, retryBackoff{
		initial: connectInitialBackoff,
		max:     connectMaxBackoff,
	})
	if err != nil {
		return nil, err
	}

	return &RnicRegistry{
		conn:               conn,
		activeThresholdSec: activeThresholdSec,
		staleThresholdSec:  staleThresholdSec,
		now:                time.Now,
	}, nil
}

// retryBackoff bounds the exponential backoff between connection attempts.
// sleep waits for d or until ctx is done; nil uses a timer (tests inject a
// fake to run without real delays).
type retryBackoff struct {
	initial time.Duration
	max     time.Duration
	sleep   func(ctx context.Context, d time.Duration) error
}

func (b retryBackoff) wait(ctx context.Context, d time.Duration) error {
	if b.sleep != nil {
		return b.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// connectWithRetry opens a connection with open and initializes the schema on
// it, retrying both steps together until they succeed. A connection whose
// schema initialization fails is closed before the next attempt. It gives up
// when timeout (> 0) elapses or ctx is cancelled, returning the last attempt's
// error; timeout <= 0 makes exactly one attempt.
func connectWithRetry(ctx context.Context, open func() (dbConn, error), timeout time.Duration, backoff retryBackoff) (dbConn, error) {
	attemptOnce := func(ctx context.Context) (dbConn, error) {
		conn, err := open()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to rqlite: %w", err)
		}
		r := &RnicRegistry{conn: conn}
		if err := r.initializeSchema(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to initialize schema: %w", err)
		}
		return conn, nil
	}

	if timeout <= 0 {
		return attemptOnce(ctx)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	delay := backoff.initial
	for attempt := 1; ; attempt++ {
		conn, err := attemptOnce(ctx)
		if err == nil {
			if attempt > 1 {
				log.Info().Int("attempt", attempt).Msg("Connected to rqlite")
			}
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("gave up after %d attempt(s) within %s: %w", attempt, timeout, err)
		}
		log.Warn().
			Err(err).
			Int("attempt", attempt).
			Dur("retryIn", delay).
			Msg("rqlite not ready; retrying")
		if waitErr := backoff.wait(ctx, delay); waitErr != nil {
			return nil, fmt.Errorf("gave up after %d attempt(s) within %s: %w", attempt, timeout, err)
		}
		delay = min(delay*2, backoff.max)
	}
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
// because rqlite's WriteOne executes a single statement at a time. ctx
// bounds the startup connection attempt (see connectWithRetry).
func (r *RnicRegistry) initializeSchema(ctx context.Context) error {
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
		last_updated_epoch INTEGER NOT NULL,
		plane_id TEXT NOT NULL DEFAULT '',
		netdev TEXT NOT NULL DEFAULT ''
	);`

	if _, err := r.conn.WriteOneContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("failed to create rnics table: %w", err)
	}

	if err := r.migrateAddColumns(ctx, "plane_id", "netdev"); err != nil {
		return err
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

// migrateAddColumns adds each of the named TEXT columns (plane_id, netdev)
// to an rnics table created by a controller that predates them. CREATE TABLE
// IF NOT EXISTS leaves such a table untouched, so missing columns are
// detected via PRAGMA table_info and added with ALTER TABLE. The DEFAULT ”
// keeps existing rows (and INSERTs from an older controller sharing the
// database, which name their columns explicitly) valid: an empty plane means
// "no restriction" and an empty netdev means "unknown". A "duplicate column
// name" error is tolerated, since another controller sharing the rqlite
// cluster may have added the column concurrently.
func (r *RnicRegistry) migrateAddColumns(ctx context.Context, columns ...string) error {
	result, err := r.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
		Query: `PRAGMA table_info(rnics);`,
	})
	if err != nil {
		return fmt.Errorf("failed to inspect rnics table: %w", err)
	}
	existing := make(map[string]bool)
	for result.Next() {
		row, err := result.Map()
		if err != nil {
			return fmt.Errorf("failed to read rnics table info: %w", err)
		}
		if name, _ := row["name"].(string); name != "" {
			existing[name] = true
		}
	}

	for _, column := range columns {
		if existing[column] {
			continue
		}
		log.Info().Str("column", column).Msg("Migrating rnics table: adding column")
		// column comes from the fixed list above, never from user input.
		wr, err := r.conn.WriteOneContext(ctx,
			fmt.Sprintf(`ALTER TABLE rnics ADD COLUMN %s TEXT NOT NULL DEFAULT '';`, column))
		if err == nil {
			err = wr.Err
		}
		if err != nil && !isDuplicateColumnErr(err, wr.Err) {
			return fmt.Errorf("failed to add %s column to rnics table: %w", column, err)
		}
	}
	return nil
}

// isDuplicateColumnErr reports whether an ALTER TABLE ADD COLUMN failed only
// because the column already exists. gorqlite reports a statement error both
// as the call error (a summary) and as the result's Err (SQLite's message).
func isDuplicateColumnErr(errs ...error) bool {
	for _, err := range errs {
		if err != nil && strings.Contains(err.Error(), "duplicate column name") {
			return true
		}
	}
	return false
}

// RegisterRNICs replaces the full set of RNIC entries registered for agentID
// in one rqlite transaction: it deletes every existing row for the agent and
// inserts one row per entry in rnics. Set replacement (rather than a per-RNIC
// upsert) drops RNICs the agent no longer reports as soon as it re-registers,
// instead of after the stale-threshold window; the DELETE still runs when
// rnics is empty. The agent always sends its complete RNIC set (see
// buildRegistrationRequest in internal/agent/agent.go), never a delta.
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
	for _, rnic := range rnics {
		log.Debug().
			Str("agentID", agentID).
			Str("gid", rnic.GetGid()).
			Str("device", rnic.GetDeviceName()).
			Str("torID", rnic.GetTorId()).
			Str("planeID", rnic.GetPlaneId()).
			Str("netdev", rnic.GetNetdev()).
			Msg("Registering RNIC")
	}

	deleteSQL := `DELETE FROM rnics WHERE agent_id = ?;`

	insertSQL := `
	INSERT OR REPLACE INTO rnics
	(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name, plane_id, netdev, last_updated_epoch)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	now := r.now().Unix()

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
				rnic.GetPlaneId(),
				rnic.GetNetdev(),
				now,
			},
		})
	}

	results, err := r.conn.WriteParameterizedContext(ctx, statements)
	if err != nil {
		return fmt.Errorf("failed to replace RNICs: %w", err)
	}
	// gorqlite returns one result per statement; anything else means the
	// response cannot be matched to the statements, so do not index into it.
	if len(results) != len(statements) {
		return fmt.Errorf("failed to replace RNICs: got %d results for %d statements", len(results), len(statements))
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

// rnicColumns is the column list selected by every RNIC read; scanRnicInfo
// reads rows in this order.
const rnicColumns = "rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name, plane_id, netdev"

// queryRnics runs `SELECT rnicColumns FROM rnics` followed by where (the WHERE
// clause plus any trailing ORDER BY / LIMIT, terminated by ';') with the given
// bound arguments, and scans every returned row.
func (r *RnicRegistry) queryRnics(ctx context.Context, where string, args ...interface{}) ([]*controller_agent.RnicInfo, error) {
	stmt := gorqlite.ParameterizedStatement{
		Query:     "\n\tSELECT " + rnicColumns + "\n\tFROM rnics\n\t" + where,
		Arguments: args,
	}

	result, err := r.conn.QueryOneParameterizedContext(ctx, stmt)
	if err != nil {
		return nil, err
	}

	return scanRnicInfoRows(result)
}

// GetRNICsByToR returns all active RNICs (updated within the configured
// active-threshold window) belonging to the specified ToR switch.
func (r *RnicRegistry) GetRNICsByToR(
	ctx context.Context,
	torID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Debug().Str("torID", torID).Msg("Getting RNICs by ToR")

	rnics, err := r.queryRnics(ctx, `WHERE tor_id = ?
	AND last_updated_epoch > ?;`, torID, r.cutoff(r.activeThresholdSec))
	if err != nil {
		return nil, fmt.Errorf("failed to query RNICs by ToR: %w", err)
	}
	return rnics, nil
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

	rnics, err := r.queryRnics(ctx, `WHERE tor_id != ?
	AND last_updated_epoch > ?
	ORDER BY RANDOM();`, excludeTorID, r.cutoff(r.activeThresholdSec))
	if err != nil {
		return nil, fmt.Errorf("failed to query active RNICs in other ToRs: %w", err)
	}
	return rnics, nil
}

// GetRNICByGID returns the active registry row (updated within the configured
// active-threshold window) of the RNIC identified by gid, or (nil, nil) when
// gid is empty or no active entry matches (e.g. the requester has not
// registered yet). The pinglist generator uses the row's hostname for
// same-host filtering and its plane_id for plane restriction; a nil result
// makes it fall back to GID-based self-exclusion and the plane carried in the
// request. Genuine query errors are propagated.
func (r *RnicRegistry) GetRNICByGID(
	ctx context.Context,
	gid string,
) (*controller_agent.RnicInfo, error) {
	if gid == "" {
		return nil, nil
	}

	log.Debug().Str("targetGID", gid).Msg("Getting RNIC info")

	// rnic_gid is the primary key, so at most one row matches.
	rnics, err := r.queryRnics(ctx, `WHERE rnic_gid = ?
	AND last_updated_epoch > ?
	LIMIT 1;`, gid, r.cutoff(r.activeThresholdSec))
	if err != nil {
		return nil, fmt.Errorf("failed to query RNIC info: %w", err)
	}
	if len(rnics) == 0 {
		return nil, nil
	}
	return rnics[0], nil
}

// CleanupStaleEntries removes RNIC entries that have not been updated
// within the configured stale-threshold window.
func (r *RnicRegistry) CleanupStaleEntries(ctx context.Context) error {
	log.Info().Msg("Cleaning up stale RNIC entries")

	cleanupSQL := `
	DELETE FROM rnics
	WHERE last_updated_epoch < ?;`

	stmt := gorqlite.ParameterizedStatement{
		Query:     cleanupSQL,
		Arguments: []interface{}{r.cutoff(r.staleThresholdSec)},
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

// scanRnicInfoRows converts every row of result into an RnicInfo.
func scanRnicInfoRows(result gorqlite.QueryResult) ([]*controller_agent.RnicInfo, error) {
	var rnics []*controller_agent.RnicInfo

	for result.Next() {
		info, err := scanRnicInfo(result)
		if err != nil {
			return nil, fmt.Errorf("failed to scan RNIC row: %w", err)
		}
		rnics = append(rnics, info)
	}

	return rnics, nil
}

// scanRnicInfo converts the current row of a query selecting rnicColumns into
// an RnicInfo.
func scanRnicInfo(result gorqlite.QueryResult) (*controller_agent.RnicInfo, error) {
	var gid, ip, hostname, torID, deviceName, planeID, netdev string
	var qpn int64
	if err := result.Scan(&gid, &qpn, &ip, &hostname, &torID, &deviceName, &planeID, &netdev); err != nil {
		return nil, err
	}
	return &controller_agent.RnicInfo{
		Gid:        gid,
		Qpn:        uint32(qpn),
		IpAddress:  ip,
		HostName:   hostname,
		TorId:      torID,
		DeviceName: deviceName,
		PlaneId:    planeID,
		Netdev:     netdev,
	}, nil
}
