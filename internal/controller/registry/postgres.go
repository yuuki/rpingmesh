package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

const (
	// pgDefaultOpTimeout bounds a database call whose context carries no
	// deadline, as gorqlite's HTTP timeout bounds every rqlite request: a
	// stuck PostgreSQL server must not hold an RPC or the stale-entry
	// cleanup forever.
	pgDefaultOpTimeout = 10 * time.Second

	// pgDefaultConnectTimeout bounds establishing one connection when the
	// URI does not set connect_timeout (pgx waits indefinitely by default).
	pgDefaultConnectTimeout = 10 * time.Second

	// pgApplicationName identifies the controller's sessions in
	// pg_stat_activity unless the URI sets application_name.
	pgApplicationName = "rpingmesh-controller"

	// pgSchemaLockKey is the transaction-level advisory lock that serializes
	// schema setup between controllers starting at once ("rpm_rnic" in
	// ASCII). Concurrent CREATE TABLE IF NOT EXISTS statements can otherwise
	// fail on PostgreSQL with a unique violation in its system catalogs.
	pgSchemaLockKey int64 = 0x72706d5f726e6963

	// pgTxAttempts bounds the attempts of a registration transaction that
	// PostgreSQL aborted with a deadlock or a serialization failure. Under
	// rqlite every write is serialized and neither can happen; here two
	// agents registering the same GIDs at once can deadlock.
	pgTxAttempts = 3
)

// pgStore keeps the registry in PostgreSQL through a pgx connection pool.
type pgStore struct {
	pool *pgxpool.Pool
}

// newPostgresOpener parses the PostgreSQL URI dbURI and returns the open
// function of connectWithRetry for it. A URI that pgx cannot parse is an
// error here, before any connection attempt, since retrying cannot fix it.
//
// dbURI is a libpq-style URI (postgres://user@host:port/dbname?params). pgx
// also reads the libpq environment variables (PGHOST, PGPASSFILE, PGSSLMODE,
// ...) for values the URI leaves out, and accepts its pool settings
// (pool_max_conns, ...) as URI parameters. The defaults it lacks are set
// here: a connect timeout and an application_name.
func newPostgresOpener(dbURI string) (func() (store, error), error) {
	// pgx recognizes a URI only by a lower-case scheme.
	scheme, rest, _ := strings.Cut(dbURI, "://")
	cfg, err := pgxpool.ParseConfig(strings.ToLower(scheme) + "://" + rest)
	if err != nil {
		// pgx masks the password in its error text.
		return nil, fmt.Errorf("invalid PostgreSQL database URI: %w", err)
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = pgDefaultConnectTimeout
	}
	if _, ok := cfg.ConnConfig.RuntimeParams["application_name"]; !ok {
		cfg.ConnConfig.RuntimeParams["application_name"] = pgApplicationName
	}
	if weakness := pgTransportWeakness(&cfg.ConnConfig.Config); weakness != "" {
		log.Warn().
			Str("transport", weakness).
			Msg("The PostgreSQL server is not authenticated: anyone on the network path can read or forge the registry, and the password may be exposed. Set sslmode=verify-full (and sslrootcert) in database_uri, or connect over a Unix socket")
	}

	return func() (store, error) {
		// NewWithConfig does not connect: initSchema's first query does.
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg.Copy())
		if err != nil {
			return nil, fmt.Errorf("postgres: %w", err)
		}
		return &pgStore{pool: pool}, nil
	}, nil
}

// pgTransportWeakness describes how a connection made with cc can reach a
// PostgreSQL server that is not authenticated by its certificate:
// "plaintext" when some route may connect without TLS (sslmode disable,
// allow or prefer), "unverified TLS" when TLS is used without checking the
// certificate (sslmode require without sslrootcert), or "" when every route
// verifies the server. Routes over a Unix socket or to a loopback address do
// not cross the network and are not reported.
func pgTransportWeakness(cc *pgconn.Config) string {
	routes := append([]*pgconn.FallbackConfig{{Host: cc.Host, Port: cc.Port, TLSConfig: cc.TLSConfig}}, cc.Fallbacks...)
	weakness := ""
	for _, r := range routes {
		if isLocalPostgresHost(r.Host) {
			continue
		}
		switch {
		case r.TLSConfig == nil:
			return "plaintext"
		case r.TLSConfig.InsecureSkipVerify && r.TLSConfig.VerifyPeerCertificate == nil:
			weakness = "unverified TLS"
		}
	}
	return weakness
}

// isLocalPostgresHost reports whether host is a Unix socket directory or a
// loopback address.
func isLocalPostgresHost(host string) bool {
	if strings.HasPrefix(host, "/") || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *pgStore) backend() string { return "postgres" }

func (s *pgStore) close() { s.pool.Close() }

// withDefaultTimeout bounds ctx by pgDefaultOpTimeout unless it already has
// a deadline.
func withDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, pgDefaultOpTimeout)
}

// rebind rewrites the ? placeholders of query as PostgreSQL's $1, $2, ...,
// skipping ? inside single-quoted literals.
func rebind(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	quoted := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			quoted = !quoted
		case c == '?' && !quoted:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// execTx runs stmts in one transaction, retrying it from the start when
// PostgreSQL aborted it with a deadlock or a serialization failure.
func (s *pgStore) execTx(ctx context.Context, stmts []statement) ([]int64, error) {
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	for attempt := 1; ; attempt++ {
		affected, err := s.execTxOnce(ctx, stmts)
		if err == nil || attempt == pgTxAttempts || !isRetryableTxErr(err) || ctx.Err() != nil {
			return affected, err
		}
		log.Debug().Err(err).Int("attempt", attempt).Msg("Registry transaction aborted by PostgreSQL; retrying")
	}
}

// execTxOnce sends stmts in one pipelined batch inside an explicit
// transaction, so a registration costs a few round trips whatever its RNIC
// count.
func (s *pgStore) execTxOnce(ctx context.Context, stmts []statement) ([]int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	// A no-op once the transaction committed.
	defer func() { _ = tx.Rollback(ctx) }()

	batch := &pgx.Batch{}
	for _, stmt := range stmts {
		batch.Queue(rebind(stmt.query), stmt.args...)
	}
	results := tx.SendBatch(ctx, batch)
	affected := make([]int64, len(stmts))
	for i := range stmts {
		tag, err := results.Exec()
		if err != nil {
			_ = results.Close()
			return nil, &statementError{index: i, err: err}
		}
		affected[i] = tag.RowsAffected()
	}
	if err := results.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return affected, nil
}

// isRetryableTxErr reports whether err aborted a transaction that can simply
// be run again: SQLSTATE 40P01 (deadlock_detected) or 40001
// (serialization_failure).
func isRetryableTxErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40P01" || pgErr.Code == "40001")
}

func (s *pgStore) exec(ctx context.Context, stmt statement) (int64, error) {
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	tag, err := s.pool.Exec(ctx, rebind(stmt.query), stmt.args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *pgStore) queryRnics(ctx context.Context, stmt statement) ([]*controller_agent.RnicInfo, error) {
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, rebind(stmt.query), stmt.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rnics []*controller_agent.RnicInfo
	for rows.Next() {
		var gid, ip, hostname, torID, deviceName, planeID, netdev string
		var qpn int64
		if err := rows.Scan(&gid, &qpn, &ip, &hostname, &torID, &deviceName, &planeID, &netdev); err != nil {
			return nil, fmt.Errorf("failed to scan RNIC row: %w", err)
		}
		rnics = append(rnics, &controller_agent.RnicInfo{
			Gid:        gid,
			Qpn:        uint32(qpn),
			IpAddress:  ip,
			HostName:   hostname,
			TorId:      torID,
			DeviceName: deviceName,
			PlaneId:    planeID,
			Netdev:     netdev,
		})
	}
	return rnics, rows.Err()
}

// anyOf matches with = ANY over one text[] parameter, so every lookup is
// the same prepared statement whatever the number of values.
func (s *pgStore) anyOf(column string, values []string) (string, []any) {
	return column + ` = ANY(?)`, []any{values}
}

// initSchema creates the rnics table, adds the columns and indexes it lacks,
// in one transaction serialized between controllers by an advisory lock.
// The catalog is inspected first and DDL is issued only for what is missing,
// so a controller whose role may only read and write the rows of a table
// prepared by an administrator still starts. Column types are BIGINT where
// SQLite's INTEGER (64-bit) holds Unix seconds or a QPN.
func (s *pgStore) initSchema(ctx context.Context) error {
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgSchemaLockKey); err != nil {
		return fmt.Errorf("failed to lock the rnics schema: %w", err)
	}

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('rnics') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("failed to inspect rnics table: %w", err)
	}
	if !exists {
		if _, err := tx.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS rnics (
		rnic_gid TEXT PRIMARY KEY,
		qpn BIGINT NOT NULL,
		agent_id TEXT NOT NULL,
		agent_ip TEXT NOT NULL,
		rnic_ip TEXT NOT NULL,
		tor_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		device_name TEXT NOT NULL,
		last_updated_epoch BIGINT NOT NULL,
		plane_id TEXT NOT NULL DEFAULT '',
		netdev TEXT NOT NULL DEFAULT ''
	)`); err != nil {
			return fmt.Errorf("failed to create rnics table: %w", err)
		}
	}

	existing, err := pgCatalogNames(ctx, tx, `SELECT attname FROM pg_attribute
	WHERE attrelid = 'rnics'::regclass AND attnum > 0 AND NOT attisdropped`)
	if err != nil {
		return fmt.Errorf("failed to inspect rnics columns: %w", err)
	}
	for _, column := range rnicsTableColumns {
		if existing[column] {
			continue
		}
		log.Info().Str("column", column).Msg("Migrating rnics table: adding column")
		// column comes from the fixed list rnicsTableColumns, never from input.
		if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER TABLE rnics ADD COLUMN IF NOT EXISTS %s TEXT NOT NULL DEFAULT ''`, column)); err != nil {
			return fmt.Errorf("failed to add %s column to rnics table: %w", column, err)
		}
	}

	indexes, err := pgCatalogNames(ctx, tx, `SELECT c.relname FROM pg_index i
	JOIN pg_class c ON c.oid = i.indexrelid
	WHERE i.indrelid = 'rnics'::regclass`)
	if err != nil {
		return fmt.Errorf("failed to inspect rnics indexes: %w", err)
	}
	for _, idx := range rnicsIndexes {
		if indexes[idx.name] {
			continue
		}
		// The names come from the fixed list rnicsIndexes, never from input.
		if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON rnics (%s)`, idx.name, idx.column)); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// pgCatalogNames runs a catalog query returning one name per row and
// returns the set of names.
func pgCatalogNames(ctx context.Context, tx pgx.Tx, query string) (map[string]bool, error) {
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set, nil
}
