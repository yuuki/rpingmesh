package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Default thresholds used when the caller does not supply a positive value
// to NewRnicRegistry. config.Default{Active,Stale}ThresholdSec carry the same
// values (pinned equal by a test in internal/config).
const (
	// DefaultActiveThresholdSec is the window (in seconds) within which an
	// RNIC entry's last_updated_epoch must fall to be considered "active"
	// for pinglist generation and lookups.
	DefaultActiveThresholdSec = 300

	// DefaultStaleThresholdSec is the window (in seconds) after which an
	// RNIC entry is considered stale and eligible for removal.
	DefaultStaleThresholdSec = 900
)

// statement is one SQL statement and its bound arguments. Statements are
// written once, with ? placeholders and SQL that SQLite (rqlite) and
// PostgreSQL both accept; each store executes them in its own dialect.
type statement struct {
	query string
	args  []any
}

// statementError reports which statement of a store.execTx batch failed.
type statementError struct {
	index int
	err   error
}

func (e *statementError) Error() string {
	return fmt.Sprintf("statement %d: %v", e.index, e.err)
}

func (e *statementError) Unwrap() error { return e.err }

// store is the database the registry keeps its rows in: rqlite (rqliteStore)
// or PostgreSQL (pgStore). RnicRegistry builds every statement and
// interprets every result; a store only executes them.
type store interface {
	// backend names the database for logs ("rqlite" or "postgres").
	backend() string
	// initSchema creates the rnics table and its indexes, and adds the
	// columns that a table created by an older controller lacks.
	initSchema(ctx context.Context) error
	// execTx runs stmts in one transaction and returns the number of rows
	// each statement changed. A failing statement is reported as a
	// *statementError.
	execTx(ctx context.Context, stmts []statement) ([]int64, error)
	// exec runs one statement and returns the number of rows it changed.
	exec(ctx context.Context, stmt statement) (int64, error)
	// queryRnics runs a SELECT of rnicColumns and scans every row.
	queryRnics(ctx context.Context, stmt statement) ([]*controller_agent.RnicInfo, error)
	// anyOf returns a predicate that matches column against any of values,
	// and its arguments.
	anyOf(column string, values []string) (string, []any)
	close()
}

// RnicRegistry manages the RNIC information agents register, stored in
// rqlite or PostgreSQL.
type RnicRegistry struct {
	store store

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
	// deleted every row. The controller's clock is used on every backend, so
	// all controllers sharing a database must keep their clocks in sync.
	now func() time.Time
}

// cutoff returns the Unix epoch (seconds) before which an entry falls outside
// a window of windowSec seconds.
func (r *RnicRegistry) cutoff(windowSec int) int64 {
	return r.now().Unix() - int64(windowSec)
}

// Startup connection retry backoff bounds. rqlited accepts TCP connections
// before its store is open and a leader is elected, and PostgreSQL refuses
// connections while it starts up or recovers, so a controller started
// alongside its database (at boot, or when both units restart) can see
// transient errors on its first attempts.
const (
	connectInitialBackoff = 1 * time.Second
	connectMaxBackoff     = 30 * time.Second
)

// NewRnicRegistry creates a new RNIC registry connected to the database at
// dbURI and initializes the database schema (table + indexes) before
// returning. The URI's scheme selects the backend: http or https for rqlite,
// postgres or postgresql for PostgreSQL (see newPostgresOpener for the
// parameters it accepts). activeThresholdSec and staleThresholdSec configure
// the thresholds described above; a value <= 0 falls back to the
// corresponding Default* constant.
//
// Opening the connection and initializing the schema are retried with
// exponential backoff (1s doubling up to 30s) until they succeed, ctx is
// cancelled, or connectTimeout elapses, so the controller tolerates a
// database that is still starting. connectTimeout <= 0 makes a single
// attempt. A PostgreSQL URI that pgx cannot parse is not retried.
func NewRnicRegistry(ctx context.Context, dbURI string, activeThresholdSec, staleThresholdSec int, connectTimeout time.Duration) (*RnicRegistry, error) {
	if activeThresholdSec <= 0 {
		activeThresholdSec = DefaultActiveThresholdSec
	}
	if staleThresholdSec <= 0 {
		staleThresholdSec = DefaultStaleThresholdSec
	}

	var open func() (store, error)
	switch scheme := uriScheme(dbURI); scheme {
	case "http", "https":
		open = newRqliteOpener(dbURI)
	case "postgres", "postgresql":
		var err error
		if open, err = newPostgresOpener(dbURI); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported database URI scheme %q: want http or https (rqlite), or postgres or postgresql (PostgreSQL)", scheme)
	}

	st, err := connectWithRetry(ctx, open, connectTimeout, retryBackoff{
		initial: connectInitialBackoff,
		max:     connectMaxBackoff,
	})
	if err != nil {
		return nil, err
	}
	log.Info().Str("backend", st.backend()).Msg("RNIC registry initialized")

	return &RnicRegistry{
		store:              st,
		activeThresholdSec: activeThresholdSec,
		staleThresholdSec:  staleThresholdSec,
		now:                time.Now,
	}, nil
}

// uriScheme returns the lower-cased scheme of uri (the text before "://"),
// or "" when uri has none.
func uriScheme(uri string) string {
	scheme, _, ok := strings.Cut(uri, "://")
	if !ok {
		return ""
	}
	return strings.ToLower(scheme)
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

// connectWithRetry opens a store with open and initializes the schema on
// it, retrying both steps together until they succeed. A store whose schema
// initialization fails is closed before the next attempt. It gives up when
// timeout (> 0) elapses or ctx is cancelled, returning the last attempt's
// error; timeout <= 0 makes exactly one attempt.
func connectWithRetry(ctx context.Context, open func() (store, error), timeout time.Duration, backoff retryBackoff) (store, error) {
	attemptOnce := func(ctx context.Context) (store, error) {
		st, err := open()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to the registry database: %w", err)
		}
		if err := st.initSchema(ctx); err != nil {
			st.close()
			return nil, fmt.Errorf("failed to initialize schema: %w", err)
		}
		return st, nil
	}

	if timeout <= 0 {
		return attemptOnce(ctx)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	delay := backoff.initial
	for attempt := 1; ; attempt++ {
		st, err := attemptOnce(ctx)
		if err == nil {
			if attempt > 1 {
				log.Info().Int("attempt", attempt).Msg("Connected to the registry database")
			}
			return st, nil
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("gave up after %d attempt(s) within %s: %w", attempt, timeout, err)
		}
		log.Warn().
			Err(err).
			Int("attempt", attempt).
			Dur("retryIn", delay).
			Msg("Registry database not ready; retrying")
		if waitErr := backoff.wait(ctx, delay); waitErr != nil {
			return nil, fmt.Errorf("gave up after %d attempt(s) within %s: %w", attempt, timeout, err)
		}
		delay = min(delay*2, backoff.max)
	}
}

// Close closes the underlying database connection.
func (r *RnicRegistry) Close() error {
	if r.store != nil {
		r.store.close()
	}
	return nil
}

// rnicsTableColumns are the columns of the rnics table that a controller may
// find missing from a table created by an older release; every store adds
// them as TEXT NOT NULL with an empty-string default. The default keeps
// existing rows (and
// INSERTs from an older controller sharing the database, which name their
// columns explicitly) valid: an empty plane means "no restriction" and an
// empty netdev means "unknown". Columns are only ever added, never changed
// or dropped, because older controllers may share the database.
var rnicsTableColumns = []string{"plane_id", "netdev"}

// rnicsIndexes are the indexes every store creates on the rnics table.
var rnicsIndexes = []struct{ name, column string }{
	{"idx_rnics_agent_id", "agent_id"},
	{"idx_rnics_tor_id", "tor_id"},
	{"idx_rnics_rnic_ip", "rnic_ip"},
	{"idx_rnics_last_updated", "last_updated_epoch"},
}

// RegisterRNICs replaces the full set of RNIC entries registered for agentID
// in one transaction: it deletes every existing row for the agent and
// inserts one row per entry in rnics. Set replacement (rather than a per-RNIC
// upsert) drops RNICs the agent no longer reports as soon as it re-registers,
// instead of after the stale-threshold window; the DELETE still runs when
// rnics is empty. The agent always sends its complete RNIC set (see
// buildRegistrationRequest in internal/agent/agent.go), never a delta.
//
// A GID whose row belongs to a different agent_id and is still active
// (updated within the active-threshold window) is not taken over: the insert
// leaves that row untouched and the GID is returned in skipped. Without this,
// any client able to reach the controller could re-register a victim's GID
// with its own QPN/IP and make every prober's traffic for that RNIC fail. A
// row whose agent stopped heartbeating is replaced as before, so a genuine
// move (a renamed host, an RNIC moved to another host) completes once the old
// row leaves the active window.
func (r *RnicRegistry) RegisterRNICs(
	ctx context.Context,
	agentID string,
	agentIP string,
	rnics []*controller_agent.RnicInfo,
) (skipped []string, err error) {
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

	// The DELETE above already removed this agent's own rows, so a conflict
	// here is always another agent's row; it is replaced only once inactive.
	// SQLite adopted this upsert syntax from PostgreSQL: in both, an update
	// rejected by the WHERE changes no row.
	insertSQL := `
	INSERT INTO rnics
	(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name, plane_id, netdev, last_updated_epoch)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(rnic_gid) DO UPDATE SET
		qpn = excluded.qpn,
		agent_id = excluded.agent_id,
		agent_ip = excluded.agent_ip,
		rnic_ip = excluded.rnic_ip,
		tor_id = excluded.tor_id,
		hostname = excluded.hostname,
		device_name = excluded.device_name,
		plane_id = excluded.plane_id,
		netdev = excluded.netdev,
		last_updated_epoch = excluded.last_updated_epoch
	WHERE rnics.last_updated_epoch <= ?;`

	now := r.now().Unix()
	activeCutoff := r.cutoff(r.activeThresholdSec)

	statements := make([]statement, 0, len(rnics)+1)
	statements = append(statements, statement{
		query: deleteSQL,
		args:  []any{agentID},
	})
	for _, rnic := range rnics {
		statements = append(statements, statement{
			query: insertSQL,
			args: []any{
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
				activeCutoff,
			},
		})
	}

	affected, err := r.store.execTx(ctx, statements)
	var stmtErr *statementError
	switch {
	case errors.As(err, &stmtErr) && stmtErr.index == 0:
		return nil, fmt.Errorf("failed to delete stale RNICs for agent %s: %w", agentID, stmtErr.err)
	case errors.As(err, &stmtErr) && stmtErr.index <= len(rnics):
		return nil, fmt.Errorf("failed to register RNIC %s: %w", rnics[stmtErr.index-1].GetGid(), stmtErr.err)
	case err != nil:
		return nil, fmt.Errorf("failed to replace RNICs: %w", err)
	}
	// A store returns one count per statement; anything else means the
	// response cannot be matched to the statements, so do not index into it.
	if len(affected) != len(statements) {
		return nil, fmt.Errorf("failed to replace RNICs: got %d results for %d statements", len(affected), len(statements))
	}

	for i, n := range affected[1:] {
		// An upsert whose WHERE rejected the update changes no row.
		if n == 0 {
			skipped = append(skipped, rnics[i].GetGid()) //nolint:gosec // G602: len(affected) == len(rnics)+1 is checked above
		}
	}

	return skipped, nil
}

// rnicColumns is the column list selected by every RNIC read; every store's
// queryRnics scans rows in this order.
const rnicColumns = "rnic_gid, qpn, rnic_ip, hostname, tor_id, device_name, plane_id, netdev"

// queryRnics runs `SELECT rnicColumns FROM rnics` followed by where (the WHERE
// clause plus any trailing ORDER BY / LIMIT, terminated by ';') with the given
// bound arguments, and scans every returned row.
func (r *RnicRegistry) queryRnics(ctx context.Context, where string, args ...any) ([]*controller_agent.RnicInfo, error) {
	return r.store.queryRnics(ctx, statement{
		query: "\n\tSELECT " + rnicColumns + "\n\tFROM rnics\n\t" + where,
		args:  args,
	})
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

// gidLookupChunk bounds the GIDs of one GetRNICsByGIDs query, below SQLite's
// historical 999-variable limit.
const gidLookupChunk = 500

// GetRNICsByGIDs returns the active registry rows (updated within the
// configured active-threshold window) of the given GIDs, keyed by GID. GIDs
// that are not registered are absent from the map. The lookup costs one query
// per gidLookupChunk GIDs rather than one per GID, so a large
// GetTargetRnicInfo request cannot turn into thousands of database round
// trips.
//
// A GID containing a NUL byte is left out without a query: RegisterAgent
// only stores parseable GIDs, so it cannot match a row, and PostgreSQL
// rejects such a string as a parameter, which would fail the whole lookup.
func (r *RnicRegistry) GetRNICsByGIDs(
	ctx context.Context,
	gids []string,
) (map[string]*controller_agent.RnicInfo, error) {
	out := make(map[string]*controller_agent.RnicInfo, len(gids))
	lookup := make([]string, 0, len(gids))
	for _, gid := range gids {
		if !strings.ContainsRune(gid, 0) {
			lookup = append(lookup, gid)
		}
	}
	cutoff := r.cutoff(r.activeThresholdSec)
	for start := 0; start < len(lookup); start += gidLookupChunk {
		chunk := lookup[start:min(start+gidLookupChunk, len(lookup))]
		predicate, args := r.store.anyOf("rnic_gid", chunk)
		rnics, err := r.queryRnics(ctx, `WHERE `+predicate+`
	AND last_updated_epoch > ?;`, append(args, cutoff)...)
		if err != nil {
			return nil, fmt.Errorf("failed to query RNIC info: %w", err)
		}
		for _, rnic := range rnics {
			out[rnic.GetGid()] = rnic
		}
	}
	return out, nil
}

// CleanupStaleEntries removes RNIC entries that have not been updated
// within the configured stale-threshold window.
func (r *RnicRegistry) CleanupStaleEntries(ctx context.Context) error {
	log.Info().Msg("Cleaning up stale RNIC entries")

	removed, err := r.store.exec(ctx, statement{
		query: `
	DELETE FROM rnics
	WHERE last_updated_epoch < ?;`,
		args: []any{r.cutoff(r.staleThresholdSec)},
	})
	if err != nil {
		return fmt.Errorf("failed to cleanup stale entries: %w", err)
	}

	log.Info().
		Int64("removed", removed).
		Msg("Cleaned up stale RNIC entries")

	return nil
}
