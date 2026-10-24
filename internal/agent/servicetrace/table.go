package servicetrace

import (
	"sort"
	"sync"
)

// Connection is one connected application QP: a QP of a connected transport
// (RC, UC, XRC) that the tracer saw reach RTR with an address vector. It is
// the agent's view of one service flow.
type Connection struct {
	// Dev is the device number of the uverbs node (see Event.Dev); Context
	// and Handle identify the QP within the tracer.
	Dev     uint32
	Context uint64
	Handle  uint32

	LocalQPN uint32
	QPType   uint32

	// Owner.
	PID      uint32
	Comm     string
	CgroupID uint64

	// Remote endpoint and the address-vector fields that shape the flow.
	RemoteGID [16]byte
	RemoteQPN uint32
	// FlowLabel is the label the application set; 0 leaves the driver to
	// derive one from the QPNs (see EffectiveFlowLabel).
	FlowLabel uint32
	// SGIDIndex and Port locate the connection's source GID in the device's
	// GID table (the address vector's port, not the QP's INIT-time port).
	SGIDIndex    uint8
	Port         uint8
	TrafficClass uint8
	SL           uint8
	HopLimit     uint8

	ConnectedAtNS uint64
}

// EffectiveFlowLabel returns the flow label that decides the connection's
// UDP source port (see the package-level EffectiveFlowLabel).
func (c Connection) EffectiveFlowLabel() uint32 {
	return EffectiveFlowLabel(c.FlowLabel, c.LocalQPN, c.RemoteQPN)
}

// Counters are the Table's event statistics.
type Counters struct {
	Creates       uint64
	Connects      uint64
	Resets        uint64
	Destroys      uint64
	ContextCloses uint64
	// UnknownQPs counts modify and destroy events for a QP the table never
	// saw created: QPs that predate the tracer, or a lost create event.
	UnknownQPs uint64
	// Ignored counts modify events that are neither a connect nor a reset,
	// or that concern a QP type without a single remote (UD, raw, driver).
	Ignored uint64
}

type qpEntry struct {
	qpn      uint32
	qpType   uint32
	pid      uint32
	comm     string
	cgroupID uint64
	conn     *Connection
}

type uverbsContext struct {
	dev uint32
	// pid is the thread group that created the context's first QP, used to
	// reap the context if its close event was lost (see ReapContexts).
	pid uint32
	qps map[uint32]*qpEntry
}

// Table folds tracer events into the set of live connections. It is safe for
// concurrent use: the tracer goroutine applies events while the service
// monitor reads snapshots.
type Table struct {
	mu       sync.Mutex
	ctxs     map[uint64]*uverbsContext
	counters Counters
}

// NewTable returns an empty table.
func NewTable() *Table {
	return &Table{ctxs: make(map[uint64]*uverbsContext)}
}

// Apply folds ev into the table and reports whether the set of connections
// changed (a connection appeared, disappeared or was replaced), so the
// caller knows when to rebuild its probe targets.
func (t *Table) Apply(ev Event) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch ev.Kind {
	case KindQPCreate:
		t.counters.Creates++
		c := t.ctxs[ev.Context]
		if c == nil {
			c = &uverbsContext{dev: ev.Dev, pid: ev.PID, qps: make(map[uint32]*qpEntry)}
			t.ctxs[ev.Context] = c
		}
		// The kernel reuses handles once freed, so a create over an existing
		// handle means its destroy was missed: the old entry is gone.
		prev := c.qps[ev.QPHandle]
		c.qps[ev.QPHandle] = &qpEntry{
			qpn:      ev.QPNum,
			qpType:   ev.QPType,
			pid:      ev.PID,
			comm:     ev.Comm,
			cgroupID: ev.CgroupID,
		}
		return prev != nil && prev.conn != nil

	case KindQPModify:
		c := t.ctxs[ev.Context]
		var q *qpEntry
		if c != nil {
			q = c.qps[ev.QPHandle]
		}
		if q == nil {
			t.counters.UnknownQPs++
			return false
		}
		switch {
		case ev.IsConnect():
			if !IsConnectedType(q.qpType) {
				t.counters.Ignored++
				return false
			}
			t.counters.Connects++
			// The port the address vector names (the one sgid_index refers
			// to); the command's own port_num travels with the INIT
			// transition and is zero here.
			port := ev.DestPortNum
			if port == 0 {
				port = ev.PortNum
			}
			q.conn = &Connection{
				Dev:           c.dev,
				Context:       ev.Context,
				Handle:        ev.QPHandle,
				LocalQPN:      q.qpn,
				QPType:        q.qpType,
				PID:           q.pid,
				Comm:          q.comm,
				CgroupID:      q.cgroupID,
				RemoteGID:     ev.DGID,
				RemoteQPN:     ev.DestQPNum,
				FlowLabel:     ev.FlowLabel & FlowLabelMask,
				SGIDIndex:     ev.SGIDIndex,
				Port:          port,
				TrafficClass:  ev.TrafficClass,
				SL:            ev.SL,
				HopLimit:      ev.HopLimit,
				ConnectedAtNS: ev.TimestampNS,
			}
			return true
		case ev.IsReset():
			t.counters.Resets++
			had := q.conn != nil
			q.conn = nil
			return had
		default:
			t.counters.Ignored++
			return false
		}

	case KindQPDestroy:
		t.counters.Destroys++
		c := t.ctxs[ev.Context]
		if c == nil {
			t.counters.UnknownQPs++
			return false
		}
		q := c.qps[ev.QPHandle]
		if q == nil {
			t.counters.UnknownQPs++
			return false
		}
		delete(c.qps, ev.QPHandle)
		if len(c.qps) == 0 {
			delete(t.ctxs, ev.Context)
		}
		return q.conn != nil

	case KindContextClose:
		t.counters.ContextCloses++
		c := t.ctxs[ev.Context]
		if c == nil {
			return false
		}
		delete(t.ctxs, ev.Context)
		for _, q := range c.qps {
			if q.conn != nil {
				return true
			}
		}
		return false
	}
	return false
}

// ReapContexts drops every context whose owning process alive reports as
// gone, and returns how many it dropped and whether a connection went with
// them. The tracer reports a context's release as an event, but the ring
// buffer can drop events under load, and a lost close would otherwise leave
// the process's connections in the table forever; the owner's existence is
// the one fact user space can check without the kernel's help. Contexts
// whose owner pid is unknown (0) are kept.
func (t *Table) ReapContexts(alive func(pid uint32) bool) (removed int, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, c := range t.ctxs {
		if c.pid == 0 || alive(c.pid) {
			continue
		}
		delete(t.ctxs, key)
		removed++
		t.counters.ContextCloses++
		for _, q := range c.qps {
			if q.conn != nil {
				changed = true
			}
		}
	}
	return removed, changed
}

// Connections returns a snapshot of the live connections, ordered by device,
// context and handle.
func (t *Table) Connections() []Connection {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Connection
	for _, c := range t.ctxs {
		for _, q := range c.qps {
			if q.conn != nil {
				out = append(out, *q.conn)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Dev != b.Dev {
			return a.Dev < b.Dev
		}
		if a.Context != b.Context {
			return a.Context < b.Context
		}
		return a.Handle < b.Handle
	})
	return out
}

// QPCount returns the number of QPs the table tracks, connected or not.
func (t *Table) QPCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, c := range t.ctxs {
		n += len(c.qps)
	}
	return n
}

// Counters returns the event statistics.
func (t *Table) Counters() Counters {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counters
}
