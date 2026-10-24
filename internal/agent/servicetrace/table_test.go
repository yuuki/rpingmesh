package servicetrace

import "testing"

const (
	ctxA = uint64(0x1000)
	ctxB = uint64(0x2000)
	devA = uint32(0xe7000c0) // 231:192
	devB = uint32(0xe7000c1) // 231:193
)

func createEvent(ctx uint64, dev, handle, qpn, qpType uint32) Event {
	return Event{Kind: KindQPCreate, Context: ctx, Dev: dev, QPHandle: handle, QPNum: qpn, QPType: qpType, PID: 42, Comm: "app"}
}

func connectEvent(ctx uint64, handle, destQPN, flowLabel uint32, dgidLast byte) Event {
	ev := Event{
		Kind: KindQPModify, Context: ctx, QPHandle: handle,
		AttrMask: AttrMaskState | AttrMaskAV | AttrMaskDestQPN, QPState: QPStateRTR,
		DestQPNum: destQPN, FlowLabel: flowLabel, SGIDIndex: 3, DestPortNum: 1, TimestampNS: 99,
	}
	ev.DGID[10], ev.DGID[11], ev.DGID[15] = 0xff, 0xff, dgidLast
	return ev
}

func TestTableConnectDestroy(t *testing.T) {
	tb := NewTable()
	if tb.Apply(createEvent(ctxA, devA, 1, 0x100, QPTypeRC)) {
		t.Error("a create of a new handle must not change the connection set")
	}
	if len(tb.Connections()) != 0 || tb.QPCount() != 1 {
		t.Fatalf("after create: %d connections, %d QPs", len(tb.Connections()), tb.QPCount())
	}
	if !tb.Apply(connectEvent(ctxA, 1, 0x200, 0, 7)) {
		t.Error("the RTR transition must change the connection set")
	}
	conns := tb.Connections()
	if len(conns) != 1 {
		t.Fatalf("got %d connections, want 1", len(conns))
	}
	c := conns[0]
	if c.Dev != devA || c.LocalQPN != 0x100 || c.RemoteQPN != 0x200 || c.RemoteGID[15] != 7 ||
		c.PID != 42 || c.Comm != "app" || c.SGIDIndex != 3 || c.Port != 1 || c.ConnectedAtNS != 99 {
		t.Fatalf("unexpected connection: %+v", c)
	}
	if got := c.EffectiveFlowLabel(); got != CalcFlowLabel(0x100, 0x200) {
		t.Errorf("EffectiveFlowLabel = %#x, want the QPN-derived label", got)
	}
	// An RTR without the address vector's port falls back to the QP port.
	tb2 := NewTable()
	tb2.Apply(createEvent(ctxA, devA, 1, 0x100, QPTypeRC))
	ev := connectEvent(ctxA, 1, 0x200, 0, 7)
	ev.DestPortNum, ev.PortNum = 0, 2
	tb2.Apply(ev)
	if conns := tb2.Connections(); len(conns) != 1 || conns[0].Port != 2 {
		t.Errorf("fallback port: %+v", conns)
	}
	// RTS carries no address vector: ignored, nothing changes.
	if tb.Apply(Event{Kind: KindQPModify, Context: ctxA, QPHandle: 1, AttrMask: AttrMaskState, QPState: QPStateRTS}) {
		t.Error("RTR->RTS must not change the connection set")
	}
	if !tb.Apply(Event{Kind: KindQPDestroy, Context: ctxA, QPHandle: 1}) {
		t.Error("destroying a connected QP must change the connection set")
	}
	if len(tb.Connections()) != 0 || tb.QPCount() != 0 {
		t.Fatalf("after destroy: %d connections, %d QPs", len(tb.Connections()), tb.QPCount())
	}
	cnt := tb.Counters()
	if cnt.Creates != 1 || cnt.Connects != 1 || cnt.Destroys != 1 || cnt.Ignored != 1 {
		t.Errorf("counters = %+v", cnt)
	}
}

func TestTableHandlesAreScopedToContext(t *testing.T) {
	tb := NewTable()
	tb.Apply(createEvent(ctxA, devA, 1, 0x100, QPTypeRC))
	tb.Apply(createEvent(ctxB, devB, 1, 0x300, QPTypeRC))
	tb.Apply(connectEvent(ctxA, 1, 0x200, 0x11, 1))
	tb.Apply(connectEvent(ctxB, 1, 0x400, 0x22, 2))
	conns := tb.Connections()
	if len(conns) != 2 {
		t.Fatalf("got %d connections, want 2", len(conns))
	}
	if conns[0].Dev != devA || conns[0].LocalQPN != 0x100 || conns[0].FlowLabel != 0x11 {
		t.Errorf("first connection: %+v", conns[0])
	}
	if conns[1].Dev != devB || conns[1].LocalQPN != 0x300 || conns[1].FlowLabel != 0x22 {
		t.Errorf("second connection: %+v", conns[1])
	}
	// Closing one context drops only its QPs.
	if !tb.Apply(Event{Kind: KindContextClose, Context: ctxA}) {
		t.Error("closing a context with a connection must change the set")
	}
	conns = tb.Connections()
	if len(conns) != 1 || conns[0].Context != ctxB {
		t.Fatalf("after context close: %+v", conns)
	}
	if tb.Apply(Event{Kind: KindContextClose, Context: ctxA}) {
		t.Error("closing an unknown context must not change the set")
	}
}

func TestTableResetAndReconnect(t *testing.T) {
	tb := NewTable()
	tb.Apply(createEvent(ctxA, devA, 5, 0x100, QPTypeRC))
	tb.Apply(connectEvent(ctxA, 5, 0x200, 0, 1))
	if !tb.Apply(Event{Kind: KindQPModify, Context: ctxA, QPHandle: 5, AttrMask: AttrMaskState, QPState: QPStateReset}) {
		t.Error("a reset of a connected QP must change the set")
	}
	if len(tb.Connections()) != 0 || tb.QPCount() != 1 {
		t.Fatal("reset must drop the connection but keep the QP")
	}
	if tb.Apply(Event{Kind: KindQPModify, Context: ctxA, QPHandle: 5, AttrMask: AttrMaskState, QPState: QPStateReset}) {
		t.Error("a second reset must not change the set")
	}
	if !tb.Apply(connectEvent(ctxA, 5, 0x999, 0, 9)) {
		t.Error("reconnecting must change the set")
	}
	conns := tb.Connections()
	if len(conns) != 1 || conns[0].RemoteQPN != 0x999 || conns[0].RemoteGID[15] != 9 {
		t.Fatalf("after reconnect: %+v", conns)
	}
	if tb.Counters().Resets != 2 {
		t.Errorf("Resets = %d, want 2", tb.Counters().Resets)
	}
}

func TestTableReconnectReplacesRemote(t *testing.T) {
	tb := NewTable()
	tb.Apply(createEvent(ctxA, devA, 5, 0x100, QPTypeRC))
	tb.Apply(connectEvent(ctxA, 5, 0x200, 0, 1))
	if !tb.Apply(connectEvent(ctxA, 5, 0x201, 0, 2)) {
		t.Error("a new RTR must replace the connection")
	}
	conns := tb.Connections()
	if len(conns) != 1 || conns[0].RemoteQPN != 0x201 {
		t.Fatalf("after second RTR: %+v", conns)
	}
}

func TestTableIgnoresUnconnectedTypes(t *testing.T) {
	tb := NewTable()
	for _, qpType := range []uint32{QPTypeUD, QPTypeRawPacket, QPTypeDriver} {
		tb.Apply(createEvent(ctxA, devA, qpType, 0x100+qpType, qpType))
		if tb.Apply(connectEvent(ctxA, qpType, 0x200, 0, 1)) {
			t.Errorf("type %d must never form a connection", qpType)
		}
	}
	if len(tb.Connections()) != 0 {
		t.Fatalf("got %d connections, want 0", len(tb.Connections()))
	}
	if tb.Counters().Ignored != 3 {
		t.Errorf("Ignored = %d, want 3", tb.Counters().Ignored)
	}
}

func TestTableUnknownQPs(t *testing.T) {
	tb := NewTable()
	if tb.Apply(connectEvent(ctxA, 1, 0x200, 0, 1)) {
		t.Error("a connect for an unknown QP must not change the set")
	}
	if tb.Apply(Event{Kind: KindQPDestroy, Context: ctxA, QPHandle: 1}) {
		t.Error("a destroy for an unknown QP must not change the set")
	}
	tb.Apply(createEvent(ctxA, devA, 2, 0x100, QPTypeRC))
	if tb.Apply(Event{Kind: KindQPDestroy, Context: ctxA, QPHandle: 3}) {
		t.Error("a destroy for an unknown handle in a known context must not change the set")
	}
	if got := tb.Counters().UnknownQPs; got != 3 {
		t.Errorf("UnknownQPs = %d, want 3", got)
	}
}

func TestTableReapContexts(t *testing.T) {
	tb := NewTable()
	evA := createEvent(ctxA, devA, 1, 0x100, QPTypeRC)
	evA.PID = 100
	tb.Apply(evA)
	tb.Apply(connectEvent(ctxA, 1, 0x200, 0, 1))
	evB := createEvent(ctxB, devB, 1, 0x300, QPTypeRC) // never connected
	evB.PID = 200
	tb.Apply(evB)
	evC := createEvent(0x3000, devA, 1, 0x400, QPTypeRC) // unknown owner
	evC.PID = 0
	tb.Apply(evC)

	alive := func(pid uint32) bool { return pid == 100 }
	removed, changed := tb.ReapContexts(alive)
	if removed != 1 || changed {
		t.Fatalf("first reap: removed=%d changed=%v, want 1/false (ctxB had no connection)", removed, changed)
	}
	if tb.QPCount() != 2 {
		t.Fatalf("QPCount = %d, want 2 (ctxA and the unknown-owner context)", tb.QPCount())
	}
	removed, changed = tb.ReapContexts(func(uint32) bool { return false })
	if removed != 1 || !changed {
		t.Fatalf("second reap: removed=%d changed=%v, want 1/true", removed, changed)
	}
	if n := len(tb.Connections()); n != 0 {
		t.Fatalf("%d connections remain after reaping their owner", n)
	}
	if tb.QPCount() != 1 {
		t.Fatalf("QPCount = %d, want 1 (the unknown-owner context is kept)", tb.QPCount())
	}
	if tb.Counters().ContextCloses != 2 {
		t.Errorf("ContextCloses = %d, want 2", tb.Counters().ContextCloses)
	}
}

func TestTableRecreateOverStaleHandle(t *testing.T) {
	tb := NewTable()
	tb.Apply(createEvent(ctxA, devA, 1, 0x100, QPTypeRC))
	tb.Apply(connectEvent(ctxA, 1, 0x200, 0, 1))
	// The destroy was lost; the kernel reused the handle.
	if !tb.Apply(createEvent(ctxA, devA, 1, 0x101, QPTypeRC)) {
		t.Error("re-creating a connected handle must change the set")
	}
	if len(tb.Connections()) != 0 || tb.QPCount() != 1 {
		t.Fatal("the stale connection must be gone and the new QP tracked")
	}
}
