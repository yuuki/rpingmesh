package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

func TestRebind(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"SELECT 1", "SELECT 1"},
		{"WHERE a = ? AND b > ?;", "WHERE a = $1 AND b > $2;"},
		{"VALUES (?, '?', ?)", "VALUES ($1, '?', $2)"},
		{"WHERE a = 'it''s ?' AND b = ?", "WHERE a = 'it''s ?' AND b = $1"},
	} {
		if got := rebind(tc.in); got != tc.want {
			t.Errorf("rebind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRebind_RegistryStatements checks that every statement the registry
// sends has as many placeholders as arguments once rebound.
func TestRebind_RegistryStatements(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)
	ctx := context.Background()
	if _, err := reg.RegisterRNICs(ctx, "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("fe80::1")}); err != nil {
		t.Fatal(err)
	}
	_, _ = reg.GetRNICsByToR(ctx, "tor-1")
	_, _ = reg.GetActiveRNICsInOtherToRs(ctx, "tor-1")
	_, _ = reg.GetRNICByGID(ctx, "fe80::1")
	if err := reg.CleanupStaleEntries(ctx); err != nil {
		t.Fatal(err)
	}
	var stmts []statement
	for _, batch := range fake.writeParameterizedCalls {
		for _, p := range batch {
			stmts = append(stmts, statement{query: p.Query, args: p.Arguments})
		}
	}
	for _, p := range append(fake.queryOneParameterizedCalls, fake.writeOneParameterizedCalls...) {
		stmts = append(stmts, statement{query: p.Query, args: p.Arguments})
	}
	for _, st := range stmts {
		q := rebind(st.query)
		if strings.Contains(q, "?") {
			t.Errorf("placeholder left in %q", q)
		}
		if n := len(st.args); !strings.Contains(q, fmt.Sprintf("$%d", n)) || strings.Contains(q, fmt.Sprintf("$%d", n+1)) {
			t.Errorf("%d arguments for %q", n, q)
		}
	}
}

func TestPgTransportWeakness(t *testing.T) {
	// pgx falls back on the libpq environment for what the URI leaves out.
	for _, env := range []string{"PGHOST", "PGSSLMODE", "PGSSLROOTCERT", "PGSERVICE", "PGSERVICEFILE"} {
		t.Setenv(env, "")
	}
	ca := writeTestCA(t)
	for _, tc := range []struct {
		uri, want string
	}{
		{"postgres://db.example:5432/rpm?sslmode=disable", "plaintext"},
		{"postgres://db.example/rpm?sslmode=prefer", "plaintext"},
		{"postgres://db.example/rpm?sslmode=allow", "plaintext"},
		{"postgres://db.example/rpm?sslmode=require", "unverified TLS"},
		{"postgres://db.example/rpm?sslmode=verify-ca", "TLS verified against the system roots, not the host name"},
		{"postgres://db.example/rpm?sslmode=verify-ca&sslrootcert=" + ca, ""},
		// libpq and pgx treat require with a root certificate as verify-ca.
		{"postgres://db.example/rpm?sslmode=require&sslrootcert=" + ca, ""},
		{"postgres://db.example/rpm?sslmode=verify-full", ""},
		{"postgres://db.example/rpm?sslmode=verify-full&sslrootcert=" + ca, ""},
		{"postgres://localhost/rpm?sslmode=disable", ""},
		{"postgres://127.0.0.1/rpm?sslmode=disable", ""},
		{"postgres://[::1]/rpm?sslmode=disable", ""},
		{"postgres:///rpm?host=/var/run/postgresql", ""},
		// Every host of a multi-host URI is a route.
		{"postgres://127.0.0.1,db.example/rpm?sslmode=disable", "plaintext"},
		{"postgres://db-a.example,db-b.example/rpm?sslmode=verify-full", ""},
	} {
		cfg, err := pgconn.ParseConfig(tc.uri)
		if err != nil {
			t.Fatalf("ParseConfig(%q): %v", tc.uri, err)
		}
		if got := pgTransportWeakness(cfg); got != tc.want {
			t.Errorf("pgTransportWeakness(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// writeTestCA writes a self-signed CA certificate in PEM to a temporary
// file, for sslrootcert, and returns its path.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rpingmesh test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIsRetryableTxErr(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&pgconn.PgError{Code: "40P01"}, true},
		{&pgconn.PgError{Code: "40001"}, true},
		{&statementError{index: 3, err: &pgconn.PgError{Code: "40P01"}}, true},
		{&pgconn.PgError{Code: "23505"}, false},
		{errors.New("connection reset"), false},
		{context.DeadlineExceeded, false},
	} {
		if got := isRetryableTxErr(tc.err); got != tc.want {
			t.Errorf("isRetryableTxErr(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestUriScheme(t *testing.T) {
	for in, want := range map[string]string{
		"http://localhost:4001":      "http",
		"HTTPS://rqlite.example":     "https",
		"postgres://u@db/rpm":        "postgres",
		"PostgreSQL://u@db/rpm":      "postgresql",
		"host=db.example dbname=rpm": "",
		"":                           "",
	} {
		if got := uriScheme(in); got != want {
			t.Errorf("uriScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewRnicRegistry_UnsupportedScheme(t *testing.T) {
	for _, uri := range []string{"mysql://db.example/rpm", "host=db.example dbname=rpm"} {
		if _, err := NewRnicRegistry(context.Background(), uri, 0, 0, time.Hour); err == nil ||
			!strings.Contains(err.Error(), "unsupported database URI scheme") {
			t.Errorf("NewRnicRegistry(%q) error = %v, want an unsupported scheme", uri, err)
		}
	}
}

// TestNewRnicRegistry_InvalidPostgresURIFailsFast checks that a URI pgx
// cannot parse is reported at once, without the startup retries, and with
// its password masked.
func TestNewRnicRegistry_InvalidPostgresURIFailsFast(t *testing.T) {
	start := time.Now()
	_, err := NewRnicRegistry(context.Background(), "postgres://rpm:s3cret@db.example/rpm?sslmode=bogus", 0, 0, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "invalid PostgreSQL database URI") {
		t.Fatalf("error = %v, want an invalid URI", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error exposes the password: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v, want no retries", elapsed)
	}
}

// TestNewRnicRegistry_PostgresUnreachable checks that a server that refuses
// connections is an error of the single attempt (connectTimeout 0).
func TestNewRnicRegistry_PostgresUnreachable(t *testing.T) {
	_, err := NewRnicRegistry(context.Background(), "postgres://rpm@127.0.0.1:1/rpm?sslmode=disable", 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "failed to initialize schema") {
		t.Fatalf("error = %v, want a failed schema initialization", err)
	}
}

// --- Integration tests against a real PostgreSQL server --------------------
//
// They run only when RPINGMESH_TEST_POSTGRES_URI names a database the test
// may create schemas (and, for the least-privilege test, roles) in, e.g.
//
//	RPINGMESH_TEST_POSTGRES_URI='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable'
//
// Each test works in a schema of its own, selected through search_path.

const testPostgresEnv = "RPINGMESH_TEST_POSTGRES_URI"

// pgTestDB is a scratch schema of the test database.
type pgTestDB struct {
	admin  *pgx.Conn // connected to the test database, outside the schema
	schema string
	uri    string // the test URI with search_path set to schema
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// withParam returns uri with the query parameter key set to value.
func withParam(t *testing.T, uri, key, value string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse %s: %v", testPostgresEnv, err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func newPgTestDB(t *testing.T) *pgTestDB {
	t.Helper()
	base := os.Getenv(testPostgresEnv)
	if base == "" {
		t.Skipf("%s is not set", testPostgresEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to %s: %v", testPostgresEnv, err)
	}
	schema := "rpm_test_" + randomSuffix(t)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		_ = admin.Close(ctx)
	})
	return &pgTestDB{admin: admin, schema: schema, uri: withParam(t, base, "search_path", schema)}
}

// open opens a registry on the test schema with a clock the test controls.
func (db *pgTestDB) open(t *testing.T, now *time.Time) *RnicRegistry {
	t.Helper()
	reg, err := NewRnicRegistry(context.Background(), db.uri, 0, 0, 0)
	if err != nil {
		t.Fatalf("NewRnicRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	if now != nil {
		reg.now = func() time.Time { return *now }
	}
	return reg
}

func pgRnic(gid, tor, host string, qpn uint32) *controller_agent.RnicInfo {
	return &controller_agent.RnicInfo{
		Gid: gid, Qpn: qpn, IpAddress: "192.0.2.10", HostName: host, TorId: tor,
		DeviceName: "mlx5_0", PlaneId: "rail0", Netdev: "eth0",
	}
}

func gidsOf(rnics []*controller_agent.RnicInfo) map[string]bool {
	out := make(map[string]bool, len(rnics))
	for _, r := range rnics {
		out[r.GetGid()] = true
	}
	return out
}

// TestPostgres_RegisterAndQuery round-trips every field through every query
// execution mode of pgx; a connection pooler in transaction mode (PgBouncer)
// needs one that does not keep prepared statements, such as exec or
// simple_protocol.
func TestPostgres_RegisterAndQuery(t *testing.T) {
	for _, mode := range []string{"cache_statement", "cache_describe", "describe_exec", "exec", "simple_protocol"} {
		t.Run(mode, func(t *testing.T) {
			db := newPgTestDB(t)
			db.uri = withParam(t, db.uri, "default_query_exec_mode", mode)
			testPostgresRegisterAndQuery(t, db)
		})
	}
}

func testPostgresRegisterAndQuery(t *testing.T, db *pgTestDB) {
	now := time.Unix(testNowUnix, 0)
	reg := db.open(t, &now)
	ctx := context.Background()

	// A QPN above 2^31 needs BIGINT on PostgreSQL.
	a := []*controller_agent.RnicInfo{
		pgRnic("fe80::a1", "tor-a", "host-a", 1<<32-1),
		pgRnic("fe80::a2", "tor-a", "host-a", 17),
	}
	b := []*controller_agent.RnicInfo{pgRnic("fe80::b1", "tor-b", "host-b", 18)}
	for agent, rnics := range map[string][]*controller_agent.RnicInfo{"agent-a": a, "agent-b": b} {
		skipped, err := reg.RegisterRNICs(ctx, agent, "192.0.2.1", rnics)
		if err != nil || len(skipped) != 0 {
			t.Fatalf("RegisterRNICs(%s) = %v, %v", agent, skipped, err)
		}
	}

	got, err := reg.GetRNICByGID(ctx, "fe80::a1")
	if err != nil || got == nil {
		t.Fatalf("GetRNICByGID = %v, %v", got, err)
	}
	want := pgRnic("fe80::a1", "tor-a", "host-a", 1<<32-1)
	if got.GetGid() != want.GetGid() || got.GetQpn() != want.GetQpn() || got.GetIpAddress() != want.GetIpAddress() ||
		got.GetHostName() != want.GetHostName() || got.GetTorId() != want.GetTorId() ||
		got.GetDeviceName() != want.GetDeviceName() || got.GetPlaneId() != want.GetPlaneId() || got.GetNetdev() != want.GetNetdev() {
		t.Errorf("GetRNICByGID = %+v, want %+v", got, want)
	}

	byToR, err := reg.GetRNICsByToR(ctx, "tor-a")
	if err != nil || len(byToR) != 2 || !gidsOf(byToR)["fe80::a2"] {
		t.Errorf("GetRNICsByToR(tor-a) = %v, %v", byToR, err)
	}
	others, err := reg.GetActiveRNICsInOtherToRs(ctx, "tor-a")
	if err != nil || len(others) != 1 || others[0].GetGid() != "fe80::b1" {
		t.Errorf("GetActiveRNICsInOtherToRs(tor-a) = %v, %v", others, err)
	}

	// More GIDs than one chunk, an unknown GID and one PostgreSQL could not
	// even bind.
	gids := []string{"fe80::a2", "fe80::b1", "fe80::ff", "fe80::\x00"}
	for i := 0; i < gidLookupChunk; i++ {
		gids = append(gids, fmt.Sprintf("fe80::1:%x", i))
	}
	rows, err := reg.GetRNICsByGIDs(ctx, gids)
	if err != nil || len(rows) != 2 || rows["fe80::a2"] == nil || rows["fe80::b1"] == nil {
		t.Errorf("GetRNICsByGIDs = %v, %v", rows, err)
	}

	// Re-registering a smaller set removes the RNIC the agent dropped.
	if _, err := reg.RegisterRNICs(ctx, "agent-a", "192.0.2.1", a[:1]); err != nil {
		t.Fatal(err)
	}
	if gone, err := reg.GetRNICByGID(ctx, "fe80::a2"); err != nil || gone != nil {
		t.Errorf("dropped RNIC = %v, %v; want it removed", gone, err)
	}
	// An empty set removes them all.
	if _, err := reg.RegisterRNICs(ctx, "agent-a", "192.0.2.1", nil); err != nil {
		t.Fatal(err)
	}
	if byToR, err := reg.GetRNICsByToR(ctx, "tor-a"); err != nil || len(byToR) != 0 {
		t.Errorf("GetRNICsByToR after an empty registration = %v, %v", byToR, err)
	}
}

func TestPostgres_ActiveWindowTakeoverAndCleanup(t *testing.T) {
	db := newPgTestDB(t)
	now := time.Unix(testNowUnix, 0)
	reg := db.open(t, &now)
	ctx := context.Background()

	if _, err := reg.RegisterRNICs(ctx, "agent-a", "192.0.2.1", []*controller_agent.RnicInfo{pgRnic("fe80::1", "tor-a", "host-a", 1)}); err != nil {
		t.Fatal(err)
	}
	// Another agent cannot take over an active GID.
	skipped, err := reg.RegisterRNICs(ctx, "agent-b", "192.0.2.2", []*controller_agent.RnicInfo{
		pgRnic("fe80::1", "tor-b", "host-b", 2),
		pgRnic("fe80::2", "tor-b", "host-b", 3),
	})
	if err != nil || len(skipped) != 1 || skipped[0] != "fe80::1" {
		t.Fatalf("skipped = %v, %v; want [fe80::1]", skipped, err)
	}
	if row, _ := reg.GetRNICByGID(ctx, "fe80::1"); row == nil || row.GetHostName() != "host-a" {
		t.Errorf("fe80::1 = %v, want agent-a's row kept", row)
	}

	// Once agent-a has been silent past the active window, its row leaves
	// the pinglists and agent-b takes the GID over.
	now = now.Add(DefaultActiveThresholdSec * time.Second)
	if row, _ := reg.GetRNICByGID(ctx, "fe80::1"); row != nil {
		t.Errorf("inactive fe80::1 = %v, want nil", row)
	}
	skipped, err = reg.RegisterRNICs(ctx, "agent-b", "192.0.2.2", []*controller_agent.RnicInfo{pgRnic("fe80::1", "tor-b", "host-b", 2)})
	if err != nil || len(skipped) != 0 {
		t.Fatalf("takeover of an inactive GID: skipped = %v, %v", skipped, err)
	}
	if row, _ := reg.GetRNICByGID(ctx, "fe80::1"); row == nil || row.GetHostName() != "host-b" {
		t.Errorf("fe80::1 = %v, want agent-b's row", row)
	}

	// The cleanup deletes rows older than the stale window only.
	if _, err := reg.RegisterRNICs(ctx, "agent-c", "192.0.2.3", []*controller_agent.RnicInfo{pgRnic("fe80::3", "tor-c", "host-c", 4)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add((DefaultStaleThresholdSec - 1) * time.Second)
	if _, err := reg.RegisterRNICs(ctx, "agent-c", "192.0.2.3", []*controller_agent.RnicInfo{pgRnic("fe80::3", "tor-c", "host-c", 4)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := reg.CleanupStaleEntries(ctx); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := db.admin.Query(ctx, "SELECT rnic_gid FROM "+db.schema+".rnics ORDER BY rnic_gid")
	if err != nil {
		t.Fatal(err)
	}
	if left, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0] != "fe80::3" {
		t.Errorf("rows after cleanup = %v, want [fe80::3]", left)
	}
}

// TestPostgres_SchemaInitIsIdempotentAndConcurrent opens the registry from
// several controllers at once on an empty schema, then once more.
func TestPostgres_SchemaInitIsIdempotentAndConcurrent(t *testing.T) {
	db := newPgTestDB(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg, err := NewRnicRegistry(context.Background(), db.uri, 0, 0, 0)
			if err == nil {
				_ = reg.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent NewRnicRegistry: %v", err)
		}
	}
	db.open(t, nil)

	var indexes int
	if err := db.admin.QueryRow(context.Background(),
		"SELECT count(*) FROM pg_indexes WHERE schemaname = $1 AND tablename = 'rnics'", db.schema).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	// The primary key and rnicsIndexes.
	if indexes != len(rnicsIndexes)+1 {
		t.Errorf("rnics has %d indexes, want %d", indexes, len(rnicsIndexes)+1)
	}
}

// TestPostgres_MigratesLegacyTable opens the registry on a table that lacks
// the columns and indexes added since its creation.
func TestPostgres_MigratesLegacyTable(t *testing.T) {
	db := newPgTestDB(t)
	ctx := context.Background()
	if _, err := db.admin.Exec(ctx, `CREATE TABLE `+db.schema+`.rnics (
		rnic_gid TEXT PRIMARY KEY,
		qpn BIGINT NOT NULL,
		agent_id TEXT NOT NULL,
		agent_ip TEXT NOT NULL,
		rnic_ip TEXT NOT NULL,
		tor_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		device_name TEXT NOT NULL,
		last_updated_epoch BIGINT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.admin.Exec(ctx, `INSERT INTO `+db.schema+`.rnics VALUES
		('fe80::f1', 900, 'legacy-agent', '192.0.2.1', '10.9.9.1', 'tor-legacy', 'legacy-host', 'mlx5_0', $1)`, testNowUnix); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(testNowUnix, 0)
	reg := db.open(t, &now)
	legacy, err := reg.GetRNICByGID(ctx, "fe80::f1")
	if err != nil || legacy == nil || legacy.GetPlaneId() != "" || legacy.GetNetdev() != "" || legacy.GetTorId() != "tor-legacy" {
		t.Fatalf("legacy row = %v, %v; want tor-legacy with an empty plane and netdev", legacy, err)
	}
	if _, err := reg.RegisterRNICs(ctx, "agent-new", "192.0.2.2", []*controller_agent.RnicInfo{pgRnic("fe80::f2", "tor-new", "new-host", 901)}); err != nil {
		t.Fatal(err)
	}
	if row, err := reg.GetRNICByGID(ctx, "fe80::f2"); err != nil || row == nil || row.GetPlaneId() != "rail0" || row.GetNetdev() != "eth0" {
		t.Errorf("new row = %v, %v", row, err)
	}
	var indexes int
	if err := db.admin.QueryRow(ctx,
		"SELECT count(*) FROM pg_indexes WHERE schemaname = $1 AND tablename = 'rnics'", db.schema).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if indexes != len(rnicsIndexes)+1 {
		t.Errorf("rnics has %d indexes, want %d", indexes, len(rnicsIndexes)+1)
	}
}

// TestPostgres_RowPrivilegesSuffice checks that a controller whose role may
// only read and write the rows of a table set up beforehand starts: the
// schema setup issues no DDL when nothing is missing.
func TestPostgres_RowPrivilegesSuffice(t *testing.T) {
	db := newPgTestDB(t)
	ctx := context.Background()
	db.open(t, nil) // the administrator creates the schema

	role := "rpm_dml_" + randomSuffix(t)
	password := randomSuffix(t)
	if _, err := db.admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, password)); err != nil {
		t.Skipf("cannot create a role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.admin.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = db.admin.Exec(context.Background(), "DROP ROLE "+role)
	})
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA " + db.schema + " TO " + role,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON " + db.schema + ".rnics TO " + role,
	} {
		if _, err := db.admin.Exec(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(db.uri)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, password)

	reg, err := NewRnicRegistry(ctx, u.String(), 0, 0, 0)
	if err != nil {
		t.Fatalf("NewRnicRegistry as a row-privileged role: %v", err)
	}
	defer reg.Close()
	if _, err := reg.RegisterRNICs(ctx, "agent-a", "192.0.2.1", []*controller_agent.RnicInfo{pgRnic("fe80::1", "tor-a", "host-a", 1)}); err != nil {
		t.Errorf("RegisterRNICs as a row-privileged role: %v", err)
	}
}

// TestPostgres_RegistrationRetriesAfterDeadlock forces a deadlock between a
// registration and another transaction, and checks that the registration
// that PostgreSQL aborted is run again and succeeds.
func TestPostgres_RegistrationRetriesAfterDeadlock(t *testing.T) {
	db := newPgTestDB(t)
	// The registry's sessions are found by this name below; other tests'
	// sessions on the same server must not match.
	appName := "rpm-test-deadlock-" + randomSuffix(t)
	db.uri = withParam(t, db.uri, "application_name", appName)
	reg := db.open(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := reg.RegisterRNICs(ctx, "agent-b", "192.0.2.2", []*controller_agent.RnicInfo{pgRnic("fe80::2", "tor-b", "host-b", 2)}); err != nil {
		t.Fatal(err)
	}

	// The other transaction locks agent-b's row, which the registration
	// below will wait for after inserting fe80::1.
	other, err := pgx.Connect(ctx, withParam(t, db.uri, "application_name", "rpm-test-other"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	tx, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT 1 FROM rnics WHERE rnic_gid = 'fe80::2' FOR UPDATE"); err != nil {
		t.Fatal(err)
	}

	type result struct {
		skipped []string
		err     error
	}
	done := make(chan result, 1)
	go func() {
		skipped, err := reg.RegisterRNICs(ctx, "agent-a", "192.0.2.1", []*controller_agent.RnicInfo{
			pgRnic("fe80::1", "tor-a", "host-a", 1),
			pgRnic("fe80::2", "tor-a", "host-a", 3),
		})
		done <- result{skipped, err}
	}()

	// Wait until the registration blocks on the lock.
	for {
		var waiting int
		if err := db.admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE application_name = $1 AND wait_event_type = 'Lock'`, appName).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case r := <-done:
			t.Fatalf("registration finished without waiting: %v, %v", r.skipped, r.err)
		case <-time.After(20 * time.Millisecond):
		}
	}

	// Inserting fe80::1 now waits for the registration, which waits for this
	// transaction: PostgreSQL aborts one of them after deadlock_timeout.
	_, insertErr := tx.Exec(ctx, `INSERT INTO rnics
		(rnic_gid, qpn, agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name, last_updated_epoch)
		VALUES ('fe80::1', 9, 'agent-x', '', '', 'tor-x', 'host-x', 'mlx5_9', 0)`)
	if insertErr != nil && !isRetryableTxErr(insertErr) {
		t.Fatalf("insert in the other transaction: %v", insertErr)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("registration after a deadlock: %v", r.err)
	}
	if len(r.skipped) != 1 || r.skipped[0] != "fe80::2" {
		t.Errorf("skipped = %v, want [fe80::2] (agent-b is active)", r.skipped)
	}
	if row, err := reg.GetRNICByGID(ctx, "fe80::1"); err != nil || row == nil || row.GetHostName() != "host-a" {
		t.Errorf("fe80::1 = %v, %v; want agent-a's row", row, err)
	}
}

// TestPostgres_SchemaSetupGivesUpOnLockedTable opens the registry on a table
// that needs a column while another session holds a lock on it: the ALTER
// TABLE must give up after pgSchemaLockTimeout, so the queries of running
// controllers queued behind it are not stalled for the whole connect
// timeout, and the setup must succeed once the lock is released.
func TestPostgres_SchemaSetupGivesUpOnLockedTable(t *testing.T) {
	db := newPgTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db.open(t, nil)
	if _, err := db.admin.Exec(ctx, "ALTER TABLE "+db.schema+".rnics DROP COLUMN netdev"); err != nil {
		t.Fatal(err)
	}

	// A long transaction elsewhere, e.g. an operator's idle psql session.
	holder, err := pgx.Connect(ctx, db.uri)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(ctx)
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT count(*) FROM rnics"); err != nil {
		t.Fatal(err)
	}

	// While the setup waits for its lock, a running controller's read
	// queues behind it; it must complete once the setup gives up.
	readDone := make(chan time.Duration, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		start := time.Now()
		conn, err := pgx.Connect(ctx, db.uri)
		if err == nil {
			_, err = conn.Exec(ctx, "SELECT count(*) FROM rnics")
			_ = conn.Close(ctx)
		}
		if err != nil {
			t.Errorf("read during the schema setup: %v", err)
		}
		readDone <- time.Since(start)
	}()

	start := time.Now()
	_, err = NewRnicRegistry(ctx, db.uri, 0, 0, 0)
	elapsed := time.Since(start)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("NewRnicRegistry on a locked table: %v, want lock_not_available (55P03)", err)
	}
	if elapsed > 8*time.Second {
		t.Errorf("schema setup gave up after %v, want about %s", elapsed, pgSchemaLockTimeout)
	}
	if waited := <-readDone; waited > 8*time.Second {
		t.Errorf("a concurrent read waited %v behind the schema setup", waited)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	db.open(t, nil)
}
