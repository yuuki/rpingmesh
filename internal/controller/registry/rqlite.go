package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/rqlite/gorqlite"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// dbConn is the subset of gorqlite.Connection's API used by rqliteStore. It
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

// rqliteStore keeps the registry in rqlite through its HTTP API. gorqlite
// bounds every request with its own 10 s HTTP timeout.
type rqliteStore struct {
	conn dbConn
}

// newRqliteOpener returns the open function of connectWithRetry for the
// rqlite at dbURI.
func newRqliteOpener(dbURI string) func() (store, error) {
	return func() (store, error) {
		conn, err := gorqlite.Open(dbURI)
		if err != nil {
			return nil, fmt.Errorf("rqlite: %w", err)
		}
		return &rqliteStore{conn: conn}, nil
	}
}

func (s *rqliteStore) backend() string { return "rqlite" }

func (s *rqliteStore) close() { s.conn.Close() }

func toParameterized(stmt statement) gorqlite.ParameterizedStatement {
	return gorqlite.ParameterizedStatement{Query: stmt.query, Arguments: stmt.args}
}

// execTx sends stmts in one request, which gorqlite runs as one rqlite
// transaction.
func (s *rqliteStore) execTx(ctx context.Context, stmts []statement) ([]int64, error) {
	params := make([]gorqlite.ParameterizedStatement, len(stmts))
	for i, stmt := range stmts {
		params[i] = toParameterized(stmt)
	}
	results, err := s.conn.WriteParameterizedContext(ctx, params)
	if err != nil {
		return nil, err
	}
	// gorqlite returns one result per statement; anything else means the
	// response cannot be matched to the statements.
	if len(results) != len(stmts) {
		return nil, fmt.Errorf("got %d results for %d statements", len(results), len(stmts))
	}
	affected := make([]int64, len(results))
	for i, res := range results {
		if res.Err != nil {
			return nil, &statementError{index: i, err: res.Err}
		}
		affected[i] = res.RowsAffected
	}
	return affected, nil
}

func (s *rqliteStore) exec(ctx context.Context, stmt statement) (int64, error) {
	result, err := s.conn.WriteOneParameterizedContext(ctx, toParameterized(stmt))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected, nil
}

func (s *rqliteStore) queryRnics(ctx context.Context, stmt statement) ([]*controller_agent.RnicInfo, error) {
	result, err := s.conn.QueryOneParameterizedContext(ctx, toParameterized(stmt))
	if err != nil {
		return nil, err
	}

	var rnics []*controller_agent.RnicInfo
	for result.Next() {
		info, err := scanRqliteRnic(result)
		if err != nil {
			return nil, fmt.Errorf("failed to scan RNIC row: %w", err)
		}
		rnics = append(rnics, info)
	}
	return rnics, nil
}

// anyOf matches with an IN list of one bound parameter per value.
func (s *rqliteStore) anyOf(column string, values []string) (string, []any) {
	args := make([]any, len(values))
	for i, v := range values {
		args[i] = v
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")
	return column + ` IN (` + placeholders + `)`, args
}

// scanRqliteRnic converts the current row of a query selecting rnicColumns
// into an RnicInfo.
func scanRqliteRnic(result gorqlite.QueryResult) (*controller_agent.RnicInfo, error) {
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

// initSchema creates the rnics table and associated indexes if they do not
// already exist. Each statement is sent in a separate write call because
// rqlite's WriteOne executes a single statement at a time. ctx bounds the
// startup connection attempt (see connectWithRetry).
func (s *rqliteStore) initSchema(ctx context.Context) error {
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

	if _, err := s.conn.WriteOneContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("failed to create rnics table: %w", err)
	}

	if err := s.migrateAddColumns(ctx, rnicsTableColumns...); err != nil {
		return err
	}

	for _, idx := range rnicsIndexes {
		// The names come from the fixed list rnicsIndexes, never from input.
		ddl := fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON rnics (%s);`, idx.name, idx.column)
		if _, err := s.conn.WriteOneContext(ctx, ddl); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// migrateAddColumns adds each of the named TEXT columns (see
// rnicsTableColumns) to an rnics table created by a controller that predates
// them. CREATE TABLE IF NOT EXISTS leaves such a table untouched, so missing
// columns are detected via PRAGMA table_info and added with ALTER TABLE. A
// "duplicate column name" error is tolerated, since another controller
// sharing the rqlite cluster may have added the column concurrently.
func (s *rqliteStore) migrateAddColumns(ctx context.Context, columns ...string) error {
	result, err := s.conn.QueryOneParameterizedContext(ctx, gorqlite.ParameterizedStatement{
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
		wr, err := s.conn.WriteOneContext(ctx,
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
