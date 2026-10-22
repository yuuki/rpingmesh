package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// fakeConn implements dbConn without any real rqlite backend, so that
// RnicRegistry's SQL-generation and error-handling logic can be unit tested
// in isolation, the same way ControllerService's registryClient interface
// (internal/controller/service_test.go) is faked at its point of use.
type fakeConn struct {
	// writeParameterizedCalls captures every batch of statements passed to
	// WriteParameterizedContext, in call order, so tests can assert on the
	// exact statements/arguments sent for each RegisterRNICs call.
	writeParameterizedCalls [][]gorqlite.ParameterizedStatement
	// writeParameterizedErr, if set, is returned as the call-level error
	// from WriteParameterizedContext (simulating a transport/HTTP failure).
	writeParameterizedErr error
	// writeParameterizedResults, if set, is returned verbatim as the
	// per-statement results from WriteParameterizedContext. If nil, a
	// slice of zero-value (no-error) results matching the statement count
	// is returned instead.
	writeParameterizedResults []gorqlite.WriteResult

	// queryOneParameterizedCalls captures every statement passed to
	// QueryOneParameterizedContext, in call order.
	queryOneParameterizedCalls []gorqlite.ParameterizedStatement
	queryOneParameterizedErr   error

	// writeOneParameterizedCalls captures every statement passed to
	// WriteOneParameterizedContext, in call order.
	writeOneParameterizedCalls []gorqlite.ParameterizedStatement
	writeOneParameterizedErr   error

	// writeOneCalls captures every statement passed to WriteOneContext (the
	// schema DDL); writeOneErrs returns the mapped error for a statement
	// containing the key.
	writeOneCalls []string
	writeOneErrs  map[string]error

	// closed counts Close calls.
	closed int
}

func (f *fakeConn) Close() { f.closed++ }

func (f *fakeConn) WriteOneContext(_ context.Context, sqlStatement string) (gorqlite.WriteResult, error) {
	f.writeOneCalls = append(f.writeOneCalls, sqlStatement)
	for substr, err := range f.writeOneErrs {
		if strings.Contains(sqlStatement, substr) {
			return gorqlite.WriteResult{Err: err}, err
		}
	}
	return gorqlite.WriteResult{}, nil
}

func (f *fakeConn) WriteOneParameterizedContext(_ context.Context, statement gorqlite.ParameterizedStatement) (gorqlite.WriteResult, error) {
	f.writeOneParameterizedCalls = append(f.writeOneParameterizedCalls, statement)
	if f.writeOneParameterizedErr != nil {
		return gorqlite.WriteResult{}, f.writeOneParameterizedErr
	}
	return gorqlite.WriteResult{}, nil
}

func (f *fakeConn) QueryOneParameterizedContext(_ context.Context, statement gorqlite.ParameterizedStatement) (gorqlite.QueryResult, error) {
	f.queryOneParameterizedCalls = append(f.queryOneParameterizedCalls, statement)
	if f.queryOneParameterizedErr != nil {
		return gorqlite.QueryResult{}, f.queryOneParameterizedErr
	}
	// A zero-value QueryResult behaves like an empty result set: Next()
	// returns false immediately. gorqlite.QueryResult's fields backing
	// actual rows are unexported, so populating real rows from outside the
	// gorqlite package isn't possible; the row-scanning path is exercised
	// by the e2e tests against a real rqlite server instead.
	return gorqlite.QueryResult{}, nil
}

func (f *fakeConn) WriteParameterizedContext(_ context.Context, statements []gorqlite.ParameterizedStatement) ([]gorqlite.WriteResult, error) {
	f.writeParameterizedCalls = append(f.writeParameterizedCalls, statements)
	if f.writeParameterizedErr != nil {
		return nil, f.writeParameterizedErr
	}
	if f.writeParameterizedResults != nil {
		return f.writeParameterizedResults, nil
	}
	return make([]gorqlite.WriteResult, len(statements)), nil
}

// newTestRegistry builds an RnicRegistry backed by conn, with the same
// default thresholds NewRnicRegistry would apply, but without touching a
// real rqlite server (no Open/initializeSchema call).
func newTestRegistry(conn dbConn) *RnicRegistry {
	return &RnicRegistry{
		conn:               conn,
		activeThresholdSec: DefaultActiveThresholdSec,
		staleThresholdSec:  DefaultStaleThresholdSec,
		now:                func() time.Time { return time.Unix(testNowUnix, 0) },
	}
}

// testNowUnix is the fixed clock of newTestRegistry, so tests can assert the
// exact epoch cutoffs bound into queries.
const testNowUnix = int64(1_800_000_000)

var (
	wantActiveCutoff = testNowUnix - DefaultActiveThresholdSec
	wantStaleCutoff  = testNowUnix - DefaultStaleThresholdSec
)

func testRnic(gid string) *controller_agent.RnicInfo {
	return &controller_agent.RnicInfo{
		Gid:        gid,
		Qpn:        7,
		IpAddress:  "10.0.0.1",
		HostName:   "host-1",
		TorId:      "tor-1",
		DeviceName: "mlx5_0",
		PlaneId:    "rail0",
	}
}

func TestRegisterRNICs_FreshRegistrationInsertsAll(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	rnics := []*controller_agent.RnicInfo{testRnic("gid-1"), testRnic("gid-2")}
	if err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", rnics); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fake.writeParameterizedCalls) != 1 {
		t.Fatalf("WriteParameterizedContext called %d times, want 1", len(fake.writeParameterizedCalls))
	}

	statements := fake.writeParameterizedCalls[0]
	if len(statements) != 3 { // 1 DELETE + 2 INSERT
		t.Fatalf("got %d statements, want 3 (1 delete + 2 insert)", len(statements))
	}

	// The DELETE must run first, scoped to the registering agent, so that a
	// re-registration with a different RNIC set (tested below) always
	// starts from a clean slate for that agent.
	del := statements[0]
	if !strings.Contains(del.Query, "DELETE FROM rnics") {
		t.Errorf("statement 0 query = %q, want a DELETE FROM rnics", del.Query)
	}
	if len(del.Arguments) != 1 || del.Arguments[0] != "agent-1" {
		t.Errorf("delete arguments = %v, want [agent-1]", del.Arguments)
	}

	// Every reported RNIC must be inserted after the delete, in order.
	for i, rn := range rnics {
		ins := statements[i+1]
		if !strings.Contains(ins.Query, "INSERT") {
			t.Errorf("statement %d query = %q, want an INSERT", i+1, ins.Query)
		}
		if len(ins.Arguments) < 3 {
			t.Fatalf("statement %d has %d arguments, want at least 3", i+1, len(ins.Arguments))
		}
		if got := ins.Arguments[0]; got != rn.GetGid() {
			t.Errorf("insert %d gid = %v, want %v", i, got, rn.GetGid())
		}
		if got := ins.Arguments[2]; got != "agent-1" {
			t.Errorf("insert %d agent_id = %v, want agent-1", i, got)
		}
	}
}

func TestRegisterRNICs_ReRegistrationWithSmallerSetReplacesRows(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)
	ctx := context.Background()

	// Initial registration reports three RNICs for the agent.
	first := []*controller_agent.RnicInfo{testRnic("gid-1"), testRnic("gid-2"), testRnic("gid-3")}
	if err := reg.RegisterRNICs(ctx, "agent-1", "10.0.0.1", first); err != nil {
		t.Fatalf("first registration: unexpected error: %v", err)
	}

	// Re-registration (e.g. a heartbeat after a NIC was removed) reports
	// only one of those RNICs.
	second := []*controller_agent.RnicInfo{testRnic("gid-1")}
	if err := reg.RegisterRNICs(ctx, "agent-1", "10.0.0.1", second); err != nil {
		t.Fatalf("second registration: unexpected error: %v", err)
	}

	if len(fake.writeParameterizedCalls) != 2 {
		t.Fatalf("WriteParameterizedContext called %d times, want 2", len(fake.writeParameterizedCalls))
	}

	secondBatch := fake.writeParameterizedCalls[1]
	// A DELETE for agent-1 followed by exactly one INSERT: gid-2 and gid-3
	// are not part of this batch at all, so against a real rqlite backend
	// the preceding DELETE removes them instead of leaving them stale.
	if len(secondBatch) != 2 {
		t.Fatalf("second batch has %d statements, want 2 (1 delete + 1 insert)", len(secondBatch))
	}
	if !strings.Contains(secondBatch[0].Query, "DELETE FROM rnics") {
		t.Fatalf("second batch statement 0 = %q, want a DELETE FROM rnics", secondBatch[0].Query)
	}
	if secondBatch[0].Arguments[0] != "agent-1" {
		t.Errorf("second batch delete agent_id = %v, want agent-1", secondBatch[0].Arguments[0])
	}
	if got := secondBatch[1].Arguments[0]; got != "gid-1" {
		t.Errorf("second batch insert gid = %v, want gid-1", got)
	}
}

func TestRegisterRNICs_DeleteStatementErrorPropagates(t *testing.T) {
	wantErr := errors.New("db locked")
	fake := &fakeConn{
		writeParameterizedResults: []gorqlite.WriteResult{
			{Err: wantErr}, // the DELETE statement fails
			{},
		},
	}
	reg := newTestRegistry(fake)

	err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("gid-1")})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

func TestRegisterRNICs_InsertStatementErrorPropagates(t *testing.T) {
	wantErr := errors.New("constraint violation")
	fake := &fakeConn{
		writeParameterizedResults: []gorqlite.WriteResult{
			{}, // the DELETE statement succeeds
			{Err: wantErr},
		},
	}
	reg := newTestRegistry(fake)

	err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("gid-1")})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "gid-1") {
		t.Errorf("error = %q, want it to identify the failing RNIC gid-1", err.Error())
	}
}

func TestRegisterRNICs_TransactionErrorPropagates(t *testing.T) {
	wantErr := errors.New("connection refused")
	fake := &fakeConn{writeParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("gid-1")})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

// TestRegisterRNICs_ResultCountMismatchIsError verifies that a response with
// fewer results than statements is reported as an error instead of indexing
// past the end of the result slice.
func TestRegisterRNICs_ResultCountMismatchIsError(t *testing.T) {
	fake := &fakeConn{writeParameterizedResults: []gorqlite.WriteResult{}}
	reg := newTestRegistry(fake)

	err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("gid-1")})
	if err == nil {
		t.Fatal("expected an error for a result count that does not match the statement count")
	}
	if !strings.Contains(err.Error(), "0 results for 2 statements") {
		t.Errorf("error = %q, want it to report the result/statement counts", err)
	}
}

func TestRegisterRNICs_EmptyRNICsStillDeletesAgentRows(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	// An agent whose current RNIC set became empty (all NICs lost, or all
	// removed by an allowlist change) must still have its previously
	// registered rows deleted - the empty set is itself the agent's current
	// state, and set-replacement semantics apply just as much as when the
	// set shrinks but isn't empty.
	if err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fake.writeParameterizedCalls) != 1 {
		t.Fatalf("WriteParameterizedContext called %d times, want 1 (a delete-only batch)", len(fake.writeParameterizedCalls))
	}
	batch := fake.writeParameterizedCalls[0]
	if len(batch) != 1 {
		t.Fatalf("got %d statements, want 1 (just the DELETE, no RNICs to insert)", len(batch))
	}
	if !strings.Contains(batch[0].Query, "DELETE FROM rnics") {
		t.Errorf("statement 0 query = %q, want a DELETE FROM rnics", batch[0].Query)
	}
	if len(batch[0].Arguments) != 1 || batch[0].Arguments[0] != "agent-1" {
		t.Errorf("delete arguments = %v, want [agent-1]", batch[0].Arguments)
	}
}

func TestRegisterRNICs_ReRegistrationWithEmptySetRemovesAllPreviousRows(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)
	ctx := context.Background()

	// Register two different agents, each with their own RNICs.
	if err := reg.RegisterRNICs(ctx, "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("gid-1"), testRnic("gid-2")}); err != nil {
		t.Fatalf("agent-1 registration: unexpected error: %v", err)
	}
	if err := reg.RegisterRNICs(ctx, "agent-2", "10.0.0.2", []*controller_agent.RnicInfo{testRnic("gid-3")}); err != nil {
		t.Fatalf("agent-2 registration: unexpected error: %v", err)
	}

	// agent-1 re-registers reporting no RNICs at all (e.g. every NIC was
	// lost or removed from the allowlist). This must still delete agent-1's
	// rows so they don't linger, scoped only to agent-1 - agent-2's rows
	// must be untouched.
	if err := reg.RegisterRNICs(ctx, "agent-1", "10.0.0.1", nil); err != nil {
		t.Fatalf("agent-1 empty re-registration: unexpected error: %v", err)
	}

	if len(fake.writeParameterizedCalls) != 3 {
		t.Fatalf("WriteParameterizedContext called %d times, want 3", len(fake.writeParameterizedCalls))
	}

	thirdBatch := fake.writeParameterizedCalls[2]
	if len(thirdBatch) != 1 {
		t.Fatalf("third batch has %d statements, want 1 (a delete-only batch)", len(thirdBatch))
	}
	if !strings.Contains(thirdBatch[0].Query, "DELETE FROM rnics") {
		t.Fatalf("third batch statement 0 = %q, want a DELETE FROM rnics", thirdBatch[0].Query)
	}
	if got := thirdBatch[0].Arguments[0]; got != "agent-1" {
		t.Errorf("third batch delete agent_id = %v, want agent-1 (must not touch agent-2's rows)", got)
	}
}

func TestGetRNICsByToR_UsesActiveThresholdAndTorID(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	rnics, err := reg.GetRNICsByToR(context.Background(), "tor-42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rnics) != 0 {
		t.Errorf("got %d rnics, want 0 from a fake with no rows", len(rnics))
	}

	if len(fake.queryOneParameterizedCalls) != 1 {
		t.Fatalf("QueryOneParameterizedContext called %d times, want 1", len(fake.queryOneParameterizedCalls))
	}
	args := fake.queryOneParameterizedCalls[0].Arguments
	if args[0] != "tor-42" || args[1] != wantActiveCutoff {
		t.Errorf("arguments = %v, want [tor-42 %d]", args, wantActiveCutoff)
	}
}

func TestGetRNICsByToR_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("query failed")
	fake := &fakeConn{queryOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	_, err := reg.GetRNICsByToR(context.Background(), "tor-1")
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

func TestGetActiveRNICsInOtherToRs_UsesActiveThresholdAndExcludesToR(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	if _, err := reg.GetActiveRNICsInOtherToRs(context.Background(), "tor-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fake.queryOneParameterizedCalls) != 1 {
		t.Fatalf("QueryOneParameterizedContext called %d times, want 1", len(fake.queryOneParameterizedCalls))
	}
	args := fake.queryOneParameterizedCalls[0].Arguments
	if args[0] != "tor-1" || args[1] != wantActiveCutoff {
		t.Errorf("arguments = %v, want [tor-1 %d]", args, wantActiveCutoff)
	}
}

func TestGetActiveRNICsInOtherToRs_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("query failed")
	fake := &fakeConn{queryOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	_, err := reg.GetActiveRNICsInOtherToRs(context.Background(), "tor-1")
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

// TestGetRNICByGID_EmptyGIDShortCircuits verifies that an empty GID
// resolves to nil without touching the database, so callers get the
// unregistered-fallback signal cheaply.
func TestGetRNICByGID_EmptyGIDShortCircuits(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	info, err := reg.GetRNICByGID(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Errorf("info = %v, want nil", info)
	}
	if len(fake.queryOneParameterizedCalls) != 0 {
		t.Errorf("made %d queries, want 0 for an empty GID", len(fake.queryOneParameterizedCalls))
	}
}

// TestGetRNICByGID_NotFoundReturnsEmpty verifies that a GID with no
// active row resolves to nil (not an error), so the generator falls back to GID
// self-exclusion rather than failing the request.
func TestGetRNICByGID_NotFoundReturnsEmpty(t *testing.T) {
	fake := &fakeConn{} // fakeConn yields an empty result set
	reg := newTestRegistry(fake)

	info, err := reg.GetRNICByGID(context.Background(), "fe80::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Errorf("info = %v, want nil for a GID with no active row", info)
	}
	if len(fake.queryOneParameterizedCalls) != 1 {
		t.Fatalf("QueryOneParameterizedContext called %d times, want 1", len(fake.queryOneParameterizedCalls))
	}
	if !strings.Contains(fake.queryOneParameterizedCalls[0].Query, "rnic_gid = ?") {
		t.Errorf("query = %q, want a GID lookup", fake.queryOneParameterizedCalls[0].Query)
	}
}

// TestGetRNICByGID_QueryErrorPropagates verifies that a genuine query
// failure is surfaced (not swallowed as nil), so it is distinguishable from a
// not-found result.
func TestGetRNICByGID_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("query failed")
	fake := &fakeConn{queryOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	_, err := reg.GetRNICByGID(context.Background(), "fe80::1")
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

func TestCleanupStaleEntries_UsesStaleThreshold(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	if err := reg.CleanupStaleEntries(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fake.writeOneParameterizedCalls) != 1 {
		t.Fatalf("WriteOneParameterizedContext called %d times, want 1", len(fake.writeOneParameterizedCalls))
	}
	args := fake.writeOneParameterizedCalls[0].Arguments
	if len(args) != 1 || args[0] != wantStaleCutoff {
		t.Errorf("arguments = %v, want [%d]", args, wantStaleCutoff)
	}
}

func TestCleanupStaleEntries_WriteErrorPropagates(t *testing.T) {
	wantErr := errors.New("write failed")
	fake := &fakeConn{writeOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	err := reg.CleanupStaleEntries(context.Background())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

func TestClose_ClosesUnderlyingConnection(t *testing.T) {
	reg := newTestRegistry(&fakeConn{})
	if err := reg.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNoStatementUsesSQLiteNow guards against SQLite's 'now': rqlite rewrites
// it in write statements using the server's local timezone, which on a
// non-UTC host made the stale cleanup delete every row. All windows must be
// bound as epoch cutoffs computed from the registry clock instead.
func TestNoStatementUsesSQLiteNow(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)
	ctx := context.Background()

	_ = reg.RegisterRNICs(ctx, "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("gid-1")})
	_, _ = reg.GetRNICsByToR(ctx, "tor-1")
	_, _ = reg.GetActiveRNICsInOtherToRs(ctx, "tor-1")
	_, _ = reg.GetRNICByGID(ctx, "gid-1")
	_ = reg.CleanupStaleEntries(ctx)

	var stmts []gorqlite.ParameterizedStatement
	for _, batch := range fake.writeParameterizedCalls {
		stmts = append(stmts, batch...)
	}
	stmts = append(stmts, fake.queryOneParameterizedCalls...)
	stmts = append(stmts, fake.writeOneParameterizedCalls...)
	if len(stmts) < 6 {
		t.Fatalf("captured %d statements, want at least 6", len(stmts))
	}
	for _, st := range stmts {
		if strings.Contains(strings.ToLower(st.Query), "'now'") {
			t.Errorf("statement uses SQLite 'now': %s", st.Query)
		}
	}

	// RegisterRNICs stamps rows with the same clock the cutoffs use.
	ins := fake.writeParameterizedCalls[0][1]
	if got := ins.Arguments[len(ins.Arguments)-1]; got != testNowUnix {
		t.Errorf("last_updated_epoch = %v, want %d", got, testNowUnix)
	}
}

// TestRegisterRNICs_StoresPlaneID verifies that each RNIC's plane_id is
// written to the plane_id column.
func TestRegisterRNICs_StoresPlaneID(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	untagged := testRnic("gid-2")
	untagged.PlaneId = ""
	if err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1",
		[]*controller_agent.RnicInfo{testRnic("gid-1"), untagged}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmts := fake.writeParameterizedCalls[0]
	for i, want := range []string{"rail0", ""} {
		ins := stmts[i+1]
		if !strings.Contains(ins.Query, "plane_id") {
			t.Fatalf("insert query lacks plane_id: %s", ins.Query)
		}
		// plane_id is bound right before netdev and last_updated_epoch.
		if got := ins.Arguments[len(ins.Arguments)-3]; got != want {
			t.Errorf("insert %d plane_id = %v, want %q", i, got, want)
		}
	}
}

// TestRegisterRNICs_StoresNetdev verifies that each RNIC's netdev is written
// to the netdev column, and that an unresolved netdev is stored as empty.
func TestRegisterRNICs_StoresNetdev(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	resolved := testRnic("gid-1")
	resolved.Netdev = "ens1f0"
	if err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1",
		[]*controller_agent.RnicInfo{resolved, testRnic("gid-2")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmts := fake.writeParameterizedCalls[0]
	for i, want := range []string{"ens1f0", ""} {
		ins := stmts[i+1]
		if !strings.Contains(ins.Query, "plane_id, netdev, last_updated_epoch") {
			t.Fatalf("insert query lacks netdev: %s", ins.Query)
		}
		// netdev is bound right before last_updated_epoch.
		if got := ins.Arguments[len(ins.Arguments)-2]; got != want {
			t.Errorf("insert %d netdev = %v, want %q", i, got, want)
		}
	}
}

// TestReadQueriesSelectPlaneID verifies that every RNIC read returns the
// plane_id column, which the pinglist generator filters on.
func TestReadQueriesSelectPlaneID(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)
	ctx := context.Background()

	_, _ = reg.GetRNICsByToR(ctx, "tor-1")
	_, _ = reg.GetActiveRNICsInOtherToRs(ctx, "tor-1")
	_, _ = reg.GetRNICByGID(ctx, "gid-1")

	if len(fake.queryOneParameterizedCalls) != 3 {
		t.Fatalf("captured %d queries, want 3", len(fake.queryOneParameterizedCalls))
	}
	for _, q := range fake.queryOneParameterizedCalls {
		if !strings.Contains(q.Query, "device_name, plane_id, netdev") {
			t.Errorf("query does not select plane_id and netdev: %s", q.Query)
		}
	}
}

// TestInitializeSchema_AddsPlaneColumnToLegacyTable verifies the migration
// path for a table created before plane support: PRAGMA table_info reports no
// plane_id column (the fake's empty result), so the column is added.
func TestInitializeSchema_AddsPlaneColumnToLegacyTable(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	if err := reg.initializeSchema(context.Background()); err != nil {
		t.Fatalf("initializeSchema: %v", err)
	}
	if !strings.Contains(fake.writeOneCalls[0], "plane_id TEXT NOT NULL DEFAULT ''") {
		t.Errorf("CREATE TABLE lacks plane_id: %s", fake.writeOneCalls[0])
	}
	if len(fake.queryOneParameterizedCalls) != 1 ||
		!strings.Contains(fake.queryOneParameterizedCalls[0].Query, "PRAGMA table_info(rnics)") {
		t.Fatalf("queries = %v, want one PRAGMA table_info(rnics)", fake.queryOneParameterizedCalls)
	}
	var alters int
	for _, stmt := range fake.writeOneCalls {
		if strings.Contains(stmt, "ALTER TABLE rnics ADD COLUMN plane_id TEXT NOT NULL DEFAULT ''") {
			alters++
		}
	}
	if alters != 1 {
		t.Errorf("ALTER TABLE issued %d times, want 1; statements: %v", alters, fake.writeOneCalls)
	}
	if !strings.Contains(fake.writeOneCalls[0], "netdev TEXT NOT NULL DEFAULT ''") {
		t.Errorf("CREATE TABLE lacks netdev: %s", fake.writeOneCalls[0])
	}
	var netdevAlters int
	for _, stmt := range fake.writeOneCalls {
		if strings.Contains(stmt, "ALTER TABLE rnics ADD COLUMN netdev TEXT NOT NULL DEFAULT ''") {
			netdevAlters++
		}
	}
	if netdevAlters != 1 {
		t.Errorf("netdev ALTER TABLE issued %d times, want 1; statements: %v", netdevAlters, fake.writeOneCalls)
	}
}

// TestInitializeSchema_ToleratesConcurrentPlaneMigration verifies that a
// "duplicate column name" failure (another controller added the column
// between our PRAGMA and ALTER) is not a startup error.
func TestInitializeSchema_ToleratesConcurrentPlaneMigration(t *testing.T) {
	fake := &fakeConn{writeOneErrs: map[string]error{
		"ALTER TABLE": errors.New("duplicate column name: plane_id"),
	}}
	if err := newTestRegistry(fake).initializeSchema(context.Background()); err != nil {
		t.Fatalf("initializeSchema: %v, want the duplicate column tolerated", err)
	}
}

// TestInitializeSchema_PlaneMigrationErrorsPropagate verifies that genuine
// migration failures stop startup instead of leaving a table whose INSERTs
// would fail on the missing column.
func TestInitializeSchema_PlaneMigrationErrorsPropagate(t *testing.T) {
	alterErr := errors.New("database is locked")
	if err := newTestRegistry(&fakeConn{writeOneErrs: map[string]error{"ALTER TABLE": alterErr}}).
		initializeSchema(context.Background()); !errors.Is(err, alterErr) {
		t.Errorf("ALTER failure: got %v, want wrapping %v", err, alterErr)
	}

	queryErr := errors.New("query failed")
	if err := newTestRegistry(&fakeConn{queryOneParameterizedErr: queryErr}).
		initializeSchema(context.Background()); !errors.Is(err, queryErr) {
		t.Errorf("PRAGMA failure: got %v, want wrapping %v", err, queryErr)
	}
}

// recordingSleep returns a retryBackoff sleep that records each requested
// delay and returns immediately, unless ctx is already done.
func recordingSleep(delays *[]time.Duration) func(context.Context, time.Duration) error {
	return func(ctx context.Context, d time.Duration) error {
		*delays = append(*delays, d)
		return ctx.Err()
	}
}

// TestConnectWithRetry_RetriesUntilReady verifies that transient open and
// schema failures (rqlite still starting) are retried with doubling, capped
// backoff, and that a connection whose schema init failed is closed.
func TestConnectWithRetry_RetriesUntilReady(t *testing.T) {
	notOpen := errors.New("store is not open")
	schemaFailing := &fakeConn{writeOneErrs: map[string]error{"CREATE TABLE": errors.New("not leader")}}
	ready := &fakeConn{}

	var opens int
	open := func() (dbConn, error) {
		opens++
		switch {
		case opens <= 3:
			return nil, notOpen
		case opens == 4:
			return schemaFailing, nil
		default:
			return ready, nil
		}
	}
	var delays []time.Duration
	conn, err := connectWithRetry(context.Background(), open, time.Minute, retryBackoff{
		initial: time.Second, max: 3 * time.Second, sleep: recordingSleep(&delays),
	})
	if err != nil {
		t.Fatalf("connectWithRetry: %v", err)
	}
	if conn != ready {
		t.Fatalf("got conn %v, want the ready connection", conn)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 3 * time.Second}
	if len(delays) != len(want) {
		t.Fatalf("delays = %v, want %v", delays, want)
	}
	for i := range want {
		if delays[i] != want[i] {
			t.Errorf("delays[%d] = %v, want %v", i, delays[i], want[i])
		}
	}
	if schemaFailing.closed != 1 {
		t.Errorf("schema-failing conn closed %d times, want 1", schemaFailing.closed)
	}
	if ready.closed != 0 {
		t.Errorf("ready conn closed %d times, want 0", ready.closed)
	}
}

// TestConnectWithRetry_GivesUpAtDeadline verifies that the last error is
// returned once the overall connect timeout elapses.
func TestConnectWithRetry_GivesUpAtDeadline(t *testing.T) {
	notOpen := errors.New("store is not open")
	open := func() (dbConn, error) { return nil, notOpen }
	// A real (short) sleep so the deadline actually passes.
	_, err := connectWithRetry(context.Background(), open, 50*time.Millisecond, retryBackoff{
		initial: 10 * time.Millisecond, max: 20 * time.Millisecond,
	})
	if !errors.Is(err, notOpen) {
		t.Fatalf("got %v, want wrapping %v", err, notOpen)
	}
	if !strings.Contains(err.Error(), "gave up after") {
		t.Errorf("error %q lacks the attempt summary", err)
	}
}

// TestConnectWithRetry_StopsOnCancel verifies that cancelling ctx (e.g. a
// shutdown signal while waiting for rqlite) ends the retry loop.
func TestConnectWithRetry_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	notOpen := errors.New("store is not open")
	var opens int
	open := func() (dbConn, error) {
		opens++
		cancel()
		return nil, notOpen
	}
	if _, err := connectWithRetry(ctx, open, time.Hour, retryBackoff{
		initial: time.Hour, max: time.Hour,
	}); !errors.Is(err, notOpen) {
		t.Fatalf("got %v, want wrapping %v", err, notOpen)
	}
	if opens != 1 {
		t.Errorf("opens = %d, want 1", opens)
	}
}

// TestConnectWithRetry_ZeroTimeoutSingleAttempt verifies that a non-positive
// timeout disables retries.
func TestConnectWithRetry_ZeroTimeoutSingleAttempt(t *testing.T) {
	notOpen := errors.New("store is not open")
	var opens int
	open := func() (dbConn, error) { opens++; return nil, notOpen }
	var delays []time.Duration
	if _, err := connectWithRetry(context.Background(), open, 0, retryBackoff{
		initial: time.Second, max: time.Second, sleep: recordingSleep(&delays),
	}); !errors.Is(err, notOpen) {
		t.Fatalf("got %v, want wrapping %v", err, notOpen)
	}
	if opens != 1 || len(delays) != 0 {
		t.Errorf("opens = %d, delays = %v; want one attempt and no wait", opens, delays)
	}
}
