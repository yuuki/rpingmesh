package registry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rqlite/gorqlite"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
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
}

func (f *fakeConn) Close() {}

func (f *fakeConn) WriteOneContext(_ context.Context, _ string) (gorqlite.WriteResult, error) {
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
		interTorSampleSize: DefaultInterTorSampleSize,
	}
}

func testRnic(gid string) *controller_agent.RnicInfo {
	return &controller_agent.RnicInfo{
		Gid:        gid,
		Qpn:        7,
		IpAddress:  "10.0.0.1",
		HostName:   "host-1",
		TorId:      "tor-1",
		DeviceName: "mlx5_0",
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

func TestRegisterRNICs_EmptyRNICsIsNoOp(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	if err := reg.RegisterRNICs(context.Background(), "agent-1", "10.0.0.1", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.writeParameterizedCalls) != 0 {
		t.Errorf("WriteParameterizedContext called %d times, want 0 for an empty RNIC set", len(fake.writeParameterizedCalls))
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
	if args[0] != "tor-42" || args[1] != DefaultActiveThresholdSec {
		t.Errorf("arguments = %v, want [tor-42 %d]", args, DefaultActiveThresholdSec)
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

func TestGetSampleRNICsFromOtherToRs_UsesActiveThresholdAndExcludesToR(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	if _, err := reg.GetSampleRNICsFromOtherToRs(context.Background(), "tor-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fake.queryOneParameterizedCalls) != 1 {
		t.Fatalf("QueryOneParameterizedContext called %d times, want 1", len(fake.queryOneParameterizedCalls))
	}
	args := fake.queryOneParameterizedCalls[0].Arguments
	if args[0] != "tor-1" || args[1] != DefaultActiveThresholdSec {
		t.Errorf("arguments = %v, want [tor-1 %d]", args, DefaultActiveThresholdSec)
	}
}

func TestGetSampleRNICsFromOtherToRs_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("query failed")
	fake := &fakeConn{queryOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	_, err := reg.GetSampleRNICsFromOtherToRs(context.Background(), "tor-1")
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want wrapping %v", err, wantErr)
	}
}

func TestGetRNICInfo_RequiresIPOrGID(t *testing.T) {
	reg := newTestRegistry(&fakeConn{})

	_, err := reg.GetRNICInfo(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected an error when neither targetIP nor targetGID is provided")
	}
}

func TestGetRNICInfo_QueriesByGIDWhenProvided(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	rnic, err := reg.GetRNICInfo(context.Background(), "10.0.0.9", "gid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rnic != nil {
		t.Errorf("got %v, want nil for a fake with no matching row", rnic)
	}

	if len(fake.queryOneParameterizedCalls) != 1 {
		t.Fatalf("QueryOneParameterizedContext called %d times, want 1", len(fake.queryOneParameterizedCalls))
	}
	stmt := fake.queryOneParameterizedCalls[0]
	if !strings.Contains(stmt.Query, "rnic_gid = ?") {
		t.Errorf("query = %q, want lookup by rnic_gid since targetGID was provided", stmt.Query)
	}
	if stmt.Arguments[0] != "gid-1" {
		t.Errorf("arguments = %v, want first argument gid-1", stmt.Arguments)
	}
}

func TestGetRNICInfo_FallsBackToIPWhenGIDMissing(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	if _, err := reg.GetRNICInfo(context.Background(), "10.0.0.9", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := fake.queryOneParameterizedCalls[0]
	if !strings.Contains(stmt.Query, "rnic_ip = ?") {
		t.Errorf("query = %q, want lookup by rnic_ip since targetGID was empty", stmt.Query)
	}
	if stmt.Arguments[0] != "10.0.0.9" {
		t.Errorf("arguments = %v, want first argument 10.0.0.9", stmt.Arguments)
	}
}

func TestGetRNICInfo_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("query failed")
	fake := &fakeConn{queryOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	_, err := reg.GetRNICInfo(context.Background(), "", "gid-1")
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
	if len(args) != 1 || args[0] != DefaultStaleThresholdSec {
		t.Errorf("arguments = %v, want [%d]", args, DefaultStaleThresholdSec)
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

func TestListAllRNICs_UsesStaleThreshold(t *testing.T) {
	fake := &fakeConn{}
	reg := newTestRegistry(fake)

	rnics, err := reg.ListAllRNICs(context.Background())
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
	if len(args) != 1 || args[0] != DefaultStaleThresholdSec {
		t.Errorf("arguments = %v, want [%d]", args, DefaultStaleThresholdSec)
	}
}

func TestListAllRNICs_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("query failed")
	fake := &fakeConn{queryOneParameterizedErr: wantErr}
	reg := newTestRegistry(fake)

	_, err := reg.ListAllRNICs(context.Background())
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
