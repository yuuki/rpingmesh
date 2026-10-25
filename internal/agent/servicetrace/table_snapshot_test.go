package servicetrace

import "testing"

func TestTableSnapshotStaysUnbound(t *testing.T) {
	tb := NewTable()
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, PID: 42}
	tb.ReconcileQPs([]QPResource{qp, qp, {Dev: devA, LocalQPN: 9, QPType: QPTypeUD, PID: 42}, {Dev: devA, LocalQPN: 10, QPType: QPTypeRC, Kernel: true}})
	if tb.QPCount() != 1 || len(tb.Connections()) != 0 || tb.Counters() != (Counters{}) {
		t.Fatalf("snapshot fabricated connections or events: qps=%d conns=%v counters=%+v", tb.QPCount(), tb.Connections(), tb.Counters())
	}
	if got := tb.UnboundQPs(); len(got) != 1 || got[0] != qp {
		t.Fatalf("unbound QPs = %+v", got)
	}
	// A netlink QPN is not a uverbs handle, even when their numbers match.
	ev := connectEvent(ctxA, qp.LocalQPN, qp.RemoteQPN, 0, 7)
	ev.Dev, ev.PID = devA, qp.PID
	tb.Apply(ev)
	if len(tb.Connections()) != 0 || tb.Counters().UnknownQPs != 1 || !tb.SnapshotDirty() {
		t.Fatal("must not guess the identity of an unknown modify")
	}
}

func TestTableSnapshotAndLiveEvents(t *testing.T) {
	for _, snapshotFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "snapshot_first", false: "event_first"}[snapshotFirst], func(t *testing.T) {
			tb := NewTable()
			qp := QPResource{Dev: devA, LocalQPN: 0x100, QPType: QPTypeRC, PID: 42}
			if snapshotFirst {
				tb.ReconcileQPs([]QPResource{qp})
			}
			tb.Apply(createEvent(ctxA, devA, 17, qp.LocalQPN, QPTypeRC))
			tb.Apply(connectEvent(ctxA, 17, 0x200, 0, 7))
			tb.ReconcileQPs([]QPResource{qp, {Dev: devB, LocalQPN: qp.LocalQPN, QPType: QPTypeRC, PID: 42}})
			if tb.QPCount() != 2 || len(tb.UnboundQPs()) != 1 || len(tb.Connections()) != 1 || tb.Connections()[0].Handle != 17 {
				t.Fatalf("snapshot overwrote or duplicated a live QP: qps=%d unbound=%v conns=%v", tb.QPCount(), tb.UnboundQPs(), tb.Connections())
			}
			// A successful empty refresh removes stale inventory, not traced QPs.
			tb.ReconcileQPs(nil)
			if tb.QPCount() != 1 || len(tb.Connections()) != 1 {
				t.Fatal("refresh removed a traced connection")
			}
			tb.Apply(Event{Kind: KindQPDestroy, Context: ctxA, QPHandle: 17})
			if tb.QPCount() != 0 {
				t.Fatal("destroy left a duplicate snapshot QP")
			}
		})
	}
}

func TestTableSnapshotQPNReuse(t *testing.T) {
	tb := NewTable()
	tb.ReconcileQPs([]QPResource{{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x999, QPType: QPTypeRC, PID: 99}})
	// A new owner can reuse a QPN that was destroyed during the dump.
	// Do not copy the previous owner's type, remote QPN or PID.
	ev := createEvent(ctxA, devA, 1, 0x100, QPTypeUC)
	tb.Apply(ev)
	tb.Apply(connectEvent(ctxA, 1, 0x200, 0, 7))
	conns := tb.Connections()
	if len(tb.UnboundQPs()) != 0 || len(conns) != 1 || conns[0].PID != 42 || conns[0].QPType != QPTypeUC || conns[0].RemoteQPN != 0x200 {
		t.Fatalf("reused QPN inherited stale metadata: %+v", conns)
	}
}

func recoveredResource(t *testing.T, dev, qpn, pid uint32) QPResource {
	t.Helper()
	qp := QPResource{Dev: dev, LocalQPN: qpn, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: pid, OwnerTGID: pid}
	c, err := decodeMlx5QP(mlx5QPFixture(qp, 0x1234), qp)
	if err != nil {
		t.Fatal(err)
	}
	qp.Recovered = &c
	return qp
}

func TestTableRecoveredConnectionsAndLifecycle(t *testing.T) {
	tb := NewTable()
	qp := recoveredResource(t, devA, 0x100, 42)
	other := recoveredResource(t, devB, 0x101, 43)
	if !tb.ReconcileQPs([]QPResource{qp, other}) || len(tb.Connections()) != 2 || len(tb.UnboundQPs()) != 0 {
		t.Fatal("driver-recovered QPs did not become connections")
	}
	// The table owns copied connection values, not the collector's pointer.
	qp.Recovered.RemoteGID[15] = 99
	if tb.Connections()[0].RemoteGID[15] != 7 {
		t.Fatal("collector mutated a published connection")
	}
	// A handle cannot be inferred, so invalidate only this device/owner.
	ev := Event{Kind: KindQPModify, Dev: devA, Context: ctxA, QPHandle: 22, PID: 42}
	if !tb.Apply(ev) || len(tb.Connections()) != 1 || len(tb.UnboundQPs()) != 1 || !tb.SnapshotDirty() {
		t.Fatal("unknown lifecycle event did not conservatively invalidate snapshot connections")
	}
	if tb.Counters().UnknownQPs != 1 {
		t.Fatal("a raw snapshot must not pretend it identified a uverbs handle")
	}
	// Process exit reaps recovered resources without inventing context events.
	tb.ReapContexts(func(uint32) bool { return false })
	if tb.QPCount() != 0 || tb.Counters().ContextCloses != 0 {
		t.Fatal("reaping snapshot owners left resources or fabricated context events")
	}
}

func TestTableRejectsSnapshotRacingLifecycle(t *testing.T) {
	tb := NewTable()
	qp := recoveredResource(t, devA, 0x100, 42)
	generation := tb.EventGeneration()
	tb.Apply(createEvent(ctxA, devA, 1, 0x100, QPTypeRC))
	tb.Apply(Event{Kind: KindQPDestroy, Context: ctxA, QPHandle: 1})
	if changed, accepted := tb.ReconcileQPsIfCurrent([]QPResource{qp}, generation); changed || accepted || tb.QPCount() != 0 {
		t.Fatal("late raw snapshot resurrected a destroyed QP")
	}
	if _, accepted := tb.ReconcileQPsIfCurrent([]QPResource{qp}, tb.EventGeneration()); !accepted {
		t.Fatal("unchanged lifecycle rejected a fresh snapshot")
	}
	if !tb.Apply(createEvent(ctxA, devA, 2, 0x100, QPTypeRC)) || len(tb.Connections()) != 0 || len(tb.UnboundQPs()) != 0 || tb.QPCount() != 1 {
		t.Fatal("create did not supersede the recovered QPN")
	}
}

func TestTableSnapshotIgnoresOtherDevicesAndKnownUDChurn(t *testing.T) {
	tb := NewTable()
	qp := recoveredResource(t, devA, 0x100, 42)
	generation := tb.EventGeneration()
	tb.Apply(createEvent(ctxB, devB, 1, 0x101, QPTypeRC))
	tb.Apply(createEvent(ctxA, devA, 2, 0x102, QPTypeUD))
	tb.Apply(Event{Kind: KindQPModify, Context: ctxA, QPHandle: 2, Dev: devA, PID: 42})
	tb.Apply(Event{Kind: KindQPDestroy, Context: ctxA, QPHandle: 2, Dev: devA, PID: 42})
	if _, accepted := tb.ReconcileQPsIfCurrent([]QPResource{qp}, generation); !accepted || len(tb.Connections()) != 1 {
		t.Fatal("unrelated device or known UD churn starved recovery")
	}
}

func TestTableUnknownThreadOwnerInvalidatesDevice(t *testing.T) {
	tb := NewTable()
	qp := recoveredResource(t, devA, 0x100, 42)
	qp.PID = 1001 // netlink owner task; tracer events carry TGID 42
	tb.ReconcileQPs([]QPResource{qp})
	if !tb.Apply(Event{Kind: KindQPDestroy, Dev: devA, PID: 42, QPHandle: 99}) || len(tb.Connections()) != 0 {
		t.Fatal("TID/TGID mismatch kept a destroyed snapshot connection")
	}
}

// A user QP can outlive its creator thread. Missing PID is not proof of a
// kernel resource, and an unresolved owner TID cannot establish process exit.
func TestTableSnapshotSurvivesCreatorThreadExit(t *testing.T) {
	for _, tid := range []uint32{0, 1001} {
		tb := NewTable()
		qp := recoveredResource(t, devA, 0x100, 42)
		qp.PID, qp.OwnerTGID, qp.Recovered.PID = tid, 0, 0
		tb.ReconcileQPs([]QPResource{qp})
		tb.ReapContexts(func(uint32) bool { return false })
		if len(tb.Connections()) != 1 || tb.QPCount() != 1 {
			t.Fatalf("creator task %d exit removed a live user QP", tid)
		}
		tb.ReconcileQPs(nil)
		if len(tb.Connections()) != 0 || tb.QPCount() != 0 {
			t.Fatal("an absent resource survived a successful refresh")
		}
	}
}
