package servicetrace

import "testing"

func kernelConnect() Event {
	return Event{Source: SourceKernel, Kind: KindQPModify, Context: 0x1234, Dev: devA,
		DeviceName: "mlx5_0", QPType: QPTypeRC, QPNum: 101, DestQPNum: 202,
		AttrMask: AttrMaskState | AttrMaskAV | AttrMaskDestQPN, QPState: QPStateRTR,
		DGID: [16]byte{15: 1}, DestPortNum: 1, IsGlobal: 1, FlowLabel: 123,
		SGIDIndex: 3, HopLimit: 64, TrafficClass: 96, SL: 3}
}

func TestKernelConnectionLifecycle(t *testing.T) {
	for _, end := range []string{"destroy", "reset", "error"} {
		t.Run(end, func(t *testing.T) {
			table := NewTable()
			ev := kernelConnect()
			// Worker identity must not become ownership, even if supplied.
			ev.PID, ev.CgroupID, ev.Comm = 123, 456, "kworker"
			if !table.Apply(ev) || table.QPCount() != 1 {
				t.Fatal("kernel RTR without a create did not establish a connection")
			}
			c := table.Connections()[0]
			if !c.Kernel || c.FromSnapshot || c.PID != 0 || c.CgroupID != 0 || c.Comm != "" ||
				c.RemoteQPN != 202 || c.RemoteGID != ev.DGID || c.Port != 1 ||
				c.SGIDIndex != 3 || c.TrafficClass != 96 || c.SL != 3 || c.EffectiveFlowLabel() != 123 {
				t.Fatalf("connection = %+v", c)
			}
			table.ReapContexts(func(uint32) bool { return false })
			if len(table.Connections()) != 1 {
				t.Fatal("kernel connection was reaped with a worker")
			}
			switch end {
			case "destroy":
				ev.Kind = KindQPDestroy
			case "reset":
				ev.QPState = QPStateReset
			case "error":
				ev.QPState = QPStateErr
			}
			if !table.Apply(ev) || len(table.Connections()) != 0 || table.QPCount() != 0 {
				t.Fatal("kernel disconnect did not remove connection")
			}
		})
	}
}

func TestKernelAndUverbsIdentitiesAreSeparate(t *testing.T) {
	table := NewTable()
	ev := kernelConnect()
	table.Apply(Event{Source: SourceWrite, Kind: KindQPCreate, Context: ev.Context,
		Dev: devA, QPHandle: 0, QPNum: 303, QPType: QPTypeRC})
	user := ev
	user.Source = SourceWrite
	table.Apply(user)
	table.Apply(ev)
	if len(table.Connections()) != 2 {
		t.Fatal("kernel QP pointer collided with uverbs context")
	}
	table.Apply(Event{Source: SourceWrite, Kind: KindContextClose, Context: ev.Context, Dev: devA})
	if got := table.Connections(); len(got) != 1 || !got[0].Kernel {
		t.Fatalf("uverbs close affected kernel QP: %+v", got)
	}
}

func TestKernelPointerReuseIgnoresOldDisconnect(t *testing.T) {
	for name, replace := range map[string]func(*Event){
		"qpn":    func(e *Event) { e.QPNum++ },
		"device": func(e *Event) { e.Dev = devB },
		"type":   func(e *Event) { e.QPType = QPTypeUC },
	} {
		for _, end := range []string{"destroy", "reset", "error"} {
			t.Run(name+"/"+end, func(t *testing.T) {
				table := NewTable()
				old := kernelConnect()
				table.Apply(old)
				next := old
				replace(&next)
				table.Apply(next)
				want := table.Connections()[0]
				// A destroy return can arrive after the freed pointer was reused.
				disconnect := func(e Event) Event {
					switch end {
					case "destroy":
						e.Kind = KindQPDestroy
					case "reset":
						e.QPState = QPStateReset
					case "error":
						e.QPState = QPStateErr
					}
					return e
				}
				if table.Apply(disconnect(old)) {
					t.Fatal("old disconnect changed the replacement connection")
				}
				if got := table.Connections(); len(got) != 1 || got[0] != want {
					t.Fatalf("replacement connection was not preserved: %+v", got)
				}
				if !table.Apply(disconnect(next)) || len(table.Connections()) != 0 {
					t.Fatal("matching disconnect did not remove the replacement")
				}
			})
		}
	}
}

func TestKernelRejectsIncompleteAndUnconnectedEvents(t *testing.T) {
	for name, mutate := range map[string]func(*Event){
		"driver":      func(e *Event) { e.QPType = QPTypeDriver },
		"UD":          func(e *Event) { e.QPType = QPTypeUD },
		"no AV":       func(e *Event) { e.AttrMask &^= AttrMaskAV },
		"no QPN mask": func(e *Event) { e.AttrMask &^= AttrMaskDestQPN },
		"no GID":      func(e *Event) { e.DGID = [16]byte{} },
		"no port":     func(e *Event) { e.DestPortNum = 0 },
		"non global":  func(e *Event) { e.IsGlobal = 0 },
		"no identity": func(e *Event) { e.Context = 0 },
		"RTS":         func(e *Event) { e.QPState = QPStateRTS },
	} {
		t.Run(name, func(t *testing.T) {
			table := NewTable()
			ev := kernelConnect()
			mutate(&ev)
			if table.Apply(ev) || len(table.Connections()) != 0 {
				t.Fatal("invalid kernel event became a connection")
			}
		})
	}
}

func TestKernelInventoryReconciliation(t *testing.T) {
	table := NewTable()
	ev := kernelConnect()
	table.Apply(ev)
	qp := QPResource{Dev: devA, LocalQPN: ev.QPNum, RemoteQPN: ev.DestQPNum,
		QPType: QPTypeRC, QPState: QPStateRTS, Kernel: true}
	if table.ReconcileQPs([]QPResource{qp}) || len(table.Connections()) != 1 {
		t.Fatal("live inventory removed kernel QP")
	}
	if !table.ReconcileQPs(nil) || len(table.Connections()) != 0 {
		t.Fatal("missed destroy was not repaired by inventory")
	}
	for _, state := range []uint8{QPStateReset, QPStateErr} {
		table.Apply(ev)
		qp.QPState = state
		if !table.ReconcileQPs([]QPResource{qp}) {
			t.Fatal("disconnected inventory QP was retained")
		}
	}
	table.Apply(ev)
	qp.QPState, qp.Kernel = QPStateRTS, false
	if !table.ReconcileQPs([]QPResource{qp}) || len(table.Connections()) != 0 {
		t.Fatal("QPN reused by a user QP retained the kernel connection")
	}
}

func TestKernelInventoryRace(t *testing.T) {
	table := NewTable()
	generation := table.EventGeneration()
	table.Apply(kernelConnect())
	if _, accepted := table.ReconcileQPsIfCurrent(nil, generation, map[uint32]string{devA: "mlx5_0", devB: "mlx5_9"}); accepted || len(table.Connections()) != 1 {
		t.Fatal("stale empty inventory removed concurrent kernel connect")
	}
	generation = table.EventGeneration()
	if changed, accepted := table.ReconcileQPsIfCurrent(nil, generation, map[uint32]string{devA: "mlx5_0", devB: "mlx5_9"}); !accepted || !changed || len(table.Connections()) != 0 {
		t.Fatal("fresh empty inventory failed to remove kernel connection")
	}
}

func TestDecodeKernelEvent(t *testing.T) {
	ev := kernelConnect()
	ev.PID, ev.CgroupID = 123, 456
	raw := append(rawEvent(ev), make([]byte, 64)...)
	copy(raw[eventSize:], "mlx5_0")
	got, err := DecodeEvent(raw)
	if err != nil || got.DeviceName != "mlx5_0" || got.QPNum != ev.QPNum || got.PID != 0 || got.CgroupID != 0 {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	for _, bad := range [][]byte{raw[:eventSize], raw[:len(raw)-1], append(rawEvent(ev), make([]byte, 64)...)} {
		if _, err := DecodeEvent(bad); err == nil {
			t.Fatal("accepted malformed kernel event")
		}
	}
}

func TestKernelInventoryPreservesUnscannedDevices(t *testing.T) {
	table := NewTable()
	scanned := kernelConnect()
	unscanned := scanned
	unscanned.Dev, unscanned.Context = devB, scanned.Context+1
	table.Apply(scanned)
	table.Apply(unscanned)
	generation := table.EventGeneration()
	// Activity outside the inventory scope must neither be deleted nor
	// mark an otherwise complete inventory as stale.
	unscanned.TimestampNS++
	table.Apply(unscanned)
	changed, accepted := table.ReconcileQPsIfCurrent(nil, generation, map[uint32]string{devA: "mlx5_0"})
	if !changed || !accepted || table.SnapshotDirty() {
		t.Fatalf("changed=%v accepted=%v dirty=%v", changed, accepted, table.SnapshotDirty())
	}
	if conns := table.Connections(); len(conns) != 1 || conns[0].Dev != devB || table.QPCount() != 1 {
		t.Fatalf("empty inventory removed an unscanned device: %+v", conns)
	}
	if changed, accepted := table.ReconcileQPsIfCurrent(nil, table.EventGeneration(), map[uint32]string{}); changed || !accepted || table.QPCount() != 1 {
		t.Fatal("empty scope removed a connection")
	}
	if changed, accepted := table.ReconcileQPsIfCurrent(nil, table.EventGeneration(), map[uint32]string{devB: "mlx5_9"}); !changed || !accepted || table.QPCount() != 0 {
		t.Fatal("fresh inventory of the remaining device did not reap it")
	}
}
