package servicetrace

import (
	"sort"
	"sync"
)

// Connection is one connected user or kernel QP: a QP of a connected transport
// (RC, UC, XRC) whose address vector was traced at RTR or recovered from
// a supported driver snapshot. It is the agent's view of one service flow.
type Connection struct {
	// Kernel identifies a connection owned by a kernel ULP, without a
	// user process or cgroup owner.
	Kernel bool
	// FromSnapshot identifies driver-recovered connections with no uverbs
	// context/handle. Their lifetime is reconciled by device/QPN.
	FromSnapshot bool
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

// Table folds user and kernel tracer events into live connections. It is safe for
// concurrent use: the tracer goroutine applies events while the service
// monitor reads snapshots.
type Table struct {
	mu       sync.Mutex
	ctxs     map[uint64]*uverbsContext
	counters Counters
	// snapshotQPs holds netlink resources without a uverbs identity. Some
	// have a driver-recovered connection; the others remain unbound.
	snapshotQPs   map[qpResourceKey]QPResource
	generation    map[uint32]uint64
	snapshotDirty bool
	kernelQPs     map[uint64]Connection // struct ib_qp pointer, separate from uverbs contexts
}

// NewTable returns an empty table.
func NewTable() *Table {
	return &Table{ctxs: make(map[uint64]*uverbsContext), snapshotQPs: make(map[qpResourceKey]QPResource), generation: make(map[uint32]uint64), kernelQPs: make(map[uint64]Connection)}
}

// Apply folds ev into the table and reports whether the set of connections
// changed or a snapshot needs refreshing, so the caller knows when to
// rebuild its probe targets.
func (t *Table) Apply(ev Event) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ev.Source == SourceKernel {
		t.generation[ev.Dev]++
		return t.applyKernel(ev)
	}
	t.advanceGeneration(ev)
	switch ev.Kind {
	case KindQPCreate:
		return t.applyCreate(ev)
	case KindQPModify:
		return t.applyModify(ev)
	case KindQPDestroy:
		return t.applyDestroy(ev)
	case KindContextClose:
		return t.applyContextClose(ev)
	}
	return false
}

// lookup returns the context and QP an event refers to; either is nil when
// unknown. Caller holds mu.
func (t *Table) lookup(ev Event) (*uverbsContext, *qpEntry) {
	c := t.ctxs[ev.Context]
	if c == nil {
		return nil, nil
	}
	return c, c.qps[ev.QPHandle]
}

// hasConnection reports whether any QP of the context is connected.
func (c *uverbsContext) hasConnection() bool {
	for _, q := range c.qps {
		if q.conn != nil {
			return true
		}
	}
	return false
}

func (t *Table) applyCreate(ev Event) bool {
	t.counters.Creates++
	key := qpResourceKey{ev.Dev, ev.QPNum}
	hadSnapshot := t.snapshotQPs[key].Recovered != nil
	delete(t.snapshotQPs, key)
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
	return hadSnapshot || (prev != nil && prev.conn != nil)
}

func (t *Table) applyModify(ev Event) bool {
	c, q := t.lookup(ev)
	if q == nil {
		t.counters.UnknownQPs++
		return t.invalidateSnapshotDevice(ev)
	}
	switch {
	case ev.IsConnect():
		if !IsConnectedType(q.qpType) {
			t.counters.Ignored++
			return false
		}
		t.counters.Connects++
		q.conn = newConnection(c, q, ev)
		return true
	case ev.IsReset():
		t.counters.Resets++
		had := q.conn != nil
		q.conn = nil
		return had
	}
	t.counters.Ignored++
	return false
}

func (t *Table) applyDestroy(ev Event) bool {
	t.counters.Destroys++
	c, q := t.lookup(ev)
	if q == nil {
		t.counters.UnknownQPs++
		return t.invalidateSnapshotDevice(ev)
	}
	delete(c.qps, ev.QPHandle)
	if len(c.qps) == 0 {
		delete(t.ctxs, ev.Context)
	}
	return q.conn != nil
}

func (t *Table) applyContextClose(ev Event) bool {
	t.counters.ContextCloses++
	changed := t.invalidateSnapshotDevice(ev)
	c := t.ctxs[ev.Context]
	if c == nil {
		return changed
	}
	delete(t.ctxs, ev.Context)
	return changed || c.hasConnection()
}

// newConnection builds the connection an RTR transition establishes.
func newConnection(c *uverbsContext, q *qpEntry, ev Event) *Connection {
	// The port the address vector names (the one sgid_index refers to);
	// the command's own port_num travels with the INIT transition and is
	// zero here.
	port := ev.DestPortNum
	if port == 0 {
		port = ev.PortNum
	}
	return &Connection{
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
}

// ReapContexts drops every context whose owning process alive reports as
// gone, and returns how many it dropped and whether a connection went with
// them. The tracer reports a context's release as an event, but the ring
// buffer can drop events under load, and a lost close would otherwise leave
// the process's connections in the table forever; the owner's existence is
// the one fact user space can check without the kernel's help. Contexts
// whose owner pid is unknown (0) are kept. Snapshot resources are also
// reaped only using a resolved OwnerTGID. An unresolved creator TID may
// exit while other threads keep the QP alive; refreshes check those QPs.
// No context events are invented for snapshot resources.
func (t *Table) ReapContexts(alive func(pid uint32) bool) (removed int, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, c := range t.ctxs {
		if c.pid == 0 || alive(c.pid) {
			continue
		}
		delete(t.ctxs, key)
		t.generation[c.dev]++
		removed++
		t.counters.ContextCloses++
		changed = changed || c.hasConnection()
	}
	for key, qp := range t.snapshotQPs {
		owner := qp.OwnerTGID
		if owner != 0 && !alive(owner) {
			delete(t.snapshotQPs, key)
			t.generation[qp.Dev]++
			changed = changed || qp.Recovered != nil
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
	for _, c := range t.kernelQPs {
		out = append(out, c)
	}
	for _, c := range t.ctxs {
		for _, q := range c.qps {
			if q.conn != nil {
				out = append(out, *q.conn)
			}
		}
	}
	for _, qp := range t.snapshotQPs {
		if qp.Recovered != nil {
			out = append(out, *qp.Recovered)
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
		if a.Handle != b.Handle {
			return a.Handle < b.Handle
		}
		return a.LocalQPN < b.LocalQPN
	})
	return out
}

// QPCount returns all user traced/snapshot QPs plus connected kernel QPs.
func (t *Table) QPCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.snapshotQPs) + len(t.kernelQPs)
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

type qpResourceKey struct {
	dev uint32
	qpn uint32
}

// ReconcileQPs replaces user snapshots and reaps missing kernel connections
// without modifying uverbs entries.
// The monitor uses ReconcileQPsIfCurrent to guard collection against events.
func (t *Table) ReconcileQPs(resources []QPResource) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reconcileQPs(resources)
}

// EventGeneration identifies the lifecycle state before a snapshot starts.
func (t *Table) EventGeneration() map[uint32]uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[uint32]uint64, len(t.generation))
	for dev, generation := range t.generation {
		out[dev] = generation
	}
	return out
}

// SnapshotDirty reports whether an unidentifiable lifecycle event invalidated
// snapshot resources and should trigger a debounced refresh.
func (t *Table) SnapshotDirty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotDirty
}

// ReconcileQPsIfCurrent rejects late snapshot results when any lifecycle
// event arrived on that device during collection. Unchanged devices are
// accepted independently. It returns connection changes/overall acceptance.
func (t *Table) ReconcileQPsIfCurrent(resources []QPResource, generation map[uint32]uint64) (bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	blocked := make(map[uint32]bool)
	var current []QPResource
	for _, qp := range resources {
		if t.generation[qp.Dev] != generation[qp.Dev] {
			blocked[qp.Dev] = true
		} else {
			current = append(current, qp)
		}
	}
	for _, qp := range t.snapshotQPs {
		if t.generation[qp.Dev] != generation[qp.Dev] {
			blocked[qp.Dev] = true
			current = append(current, qp)
		}
	}
	// Preserve kernel connections on devices changed during collection,
	// including a connection whose QP was absent from the older inventory.
	for _, c := range t.kernelQPs {
		if t.generation[c.Dev] != generation[c.Dev] {
			blocked[c.Dev] = true
			current = append(current, QPResource{Dev: c.Dev, LocalQPN: c.LocalQPN,
				RemoteQPN: c.RemoteQPN, QPType: c.QPType, QPState: QPStateRTS, Kernel: true})
		}
	}
	changed := t.reconcileQPs(current)
	t.snapshotDirty = len(blocked) > 0
	return changed, !t.snapshotDirty
}

// UntracedQPs excludes known uverbs QPs before expensive driver queries.
func (t *Table) UntracedQPs(resources []QPResource) []QPResource {
	t.mu.Lock()
	defer t.mu.Unlock()
	known := t.knownQPs()
	var out []QPResource
	for _, qp := range resources {
		if !known[qpResourceKey{qp.Dev, qp.LocalQPN}] {
			out = append(out, qp)
		}
	}
	return out
}

func (t *Table) knownQPs() map[qpResourceKey]bool {
	known := make(map[qpResourceKey]bool)
	for _, c := range t.ctxs {
		for _, q := range c.qps {
			known[qpResourceKey{c.dev, q.qpn}] = true
		}
	}
	return known
}

func (t *Table) reconcileQPs(resources []QPResource) bool {
	changed := t.reconcileKernelQPs(resources)
	known := t.knownQPs()
	next := make(map[qpResourceKey]QPResource)
	for _, qp := range resources {
		key := qpResourceKey{qp.Dev, qp.LocalQPN}
		if qp.Kernel || !IsConnectedType(qp.QPType) || known[key] {
			continue
		}
		if qp.Recovered != nil {
			conn := *qp.Recovered // own the value, never the caller's pointer
			conn.Context, conn.Handle, conn.FromSnapshot = 0, 0, true
			qp.Recovered = &conn
		}
		next[key] = qp
	}
	for key, qp := range t.snapshotQPs {
		other := next[key].Recovered
		if qp.Recovered != nil && (other == nil || *qp.Recovered != *other) {
			changed = true
		}
	}
	for key, qp := range next {
		if qp.Recovered != nil && t.snapshotQPs[key].Recovered == nil {
			changed = true
		}
	}
	t.snapshotQPs, t.snapshotDirty = next, false
	return changed
}

// A uverbs handle cannot be inferred from PID or a remote QPN. The netlink
// owner is a TID, the event carries a TGID, and contexts can be shared across
// processes. Invalidate the device conservatively instead of guessing.
func (t *Table) invalidateSnapshotDevice(ev Event) bool {
	matched := false
	for key, qp := range t.snapshotQPs {
		if qp.Dev == ev.Dev {
			qp.Recovered = nil
			t.snapshotQPs[key] = qp
			matched = true
		}
	}
	t.snapshotDirty = t.snapshotDirty || matched
	return matched
}

// UnboundQPs returns snapshot QPs lacking a recovered address vector.
// They cannot be returned by Connections or used as probe targets.
func (t *Table) UnboundQPs() []QPResource {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]QPResource, 0, len(t.snapshotQPs))
	for _, qp := range t.snapshotQPs {
		if qp.Recovered == nil {
			out = append(out, qp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dev != out[j].Dev {
			return out[i].Dev < out[j].Dev
		}
		return out[i].LocalQPN < out[j].LocalQPN
	})
	return out
}

// Epochs are per device. Known UD/raw/driver QPs cannot affect a recovered
// connected QP, and must not starve recovery during unrelated queue churn.
func (t *Table) advanceGeneration(ev Event) {
	dev := ev.Dev
	if c := t.ctxs[ev.Context]; c != nil {
		dev = c.dev
		if q := c.qps[ev.QPHandle]; q != nil && ev.Kind != KindContextClose && ev.Kind != KindQPCreate && !IsConnectedType(q.qpType) {
			return
		}
	}
	if ev.Kind == KindQPCreate && !IsConnectedType(ev.QPType) {
		return
	}
	t.generation[dev]++
}
