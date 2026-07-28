package probe

// PendingMeasurement tracks the in-flight 6-timestamp state of a single probe.
//
// The three inputs — the send-side timestamps (T1/T2), the first ACK, and the
// second ACK — can arrive in ANY order relative to one another. In particular
// an ACK can arrive before the send-side timestamps are known: SendProbe
// blocks until its own send completion (T2), and on a low-latency RNIC the ACK
// can reach the ACK-processing loop before the send call has returned and
// recorded T1/T2. The pending entry is therefore created (and its sequence
// number registered) BEFORE the send, and the send-side timestamps are applied
// afterwards via ApplySend. This state machine buffers whichever inputs arrive
// first and only reports completion once all three are present. The two ACKs
// may themselves also arrive out of order (second before first).
//
// PendingMeasurement is NOT safe for concurrent use; callers must provide their
// own synchronization (the prober guards it with its pending-map mutex).
//
// This logic is deliberately kept free of any RDMA/cgo dependency so it can be
// unit-tested on any platform.
type PendingMeasurement struct {
	T1 uint64 // Prober send time (CLOCK_MONOTONIC via Zig)
	T2 uint64 // NIC HW timestamp of probe send completion (or SW fallback)
	T3 uint64 // Responder recv timestamp
	T4 uint64 // Responder first ACK send completion timestamp
	T5 uint64 // Prober first ACK recv timestamp
	T6 uint64 // Prober second ACK recv time (CLOCK_MONOTONIC, same domain as T1)

	sendApplied      bool
	firstAckArrived  bool
	secondAckArrived bool
}

// NewPendingMeasurement creates an empty pending measurement. It is registered
// at probe-send time BEFORE the send so that an ACK arriving before the send
// completes still finds its pending entry; the send-side timestamps (T1/T2)
// are filled in afterwards via ApplySend.
func NewPendingMeasurement() *PendingMeasurement {
	return &PendingMeasurement{}
}

// ApplySend records the send-side timestamps T1 (prober send time) and T2
// (send-completion timestamp), which become known only once SendProbe returns.
// Until this is called the measurement can never be Complete(), so the ACK
// handlers cannot finalize (and delete) the entry before the send path has
// recorded T1/T2 — even if both ACKs have already arrived.
func (m *PendingMeasurement) ApplySend(t1, t2 uint64) {
	m.T1 = t1
	m.T2 = t2
	m.sendApplied = true
}

// ApplyFirstAck records the timestamps associated with the first ACK: T3 (the
// responder recv timestamp echoed in the ACK) and T5 (the prober's recv
// timestamp for this ACK). The first ACK's T3 is treated as authoritative and
// overwrites any value previously supplied by an out-of-order second ACK.
func (m *PendingMeasurement) ApplyFirstAck(t3, t5 uint64) {
	m.T3 = t3
	m.T5 = t5
	m.firstAckArrived = true
}

// ApplySecondAck records the timestamps associated with the second ACK: T3 and
// T4 (both carried in the ACK payload) and T6 (the prober's recv time for this
// ACK, captured by the caller). T3 from the second ACK is only used when the
// first ACK has not yet supplied it, so that the first ACK's value wins once
// both arrive regardless of ordering.
func (m *PendingMeasurement) ApplySecondAck(t3, t4, t6 uint64) {
	if !m.firstAckArrived {
		m.T3 = t3
	}
	m.T4 = t4
	m.T6 = t6
	m.secondAckArrived = true
}

// Complete reports whether all three inputs — the send-side timestamps and
// both ACKs — have arrived, so the measurement is ready to be finalized into a
// ProbeResult. Requiring sendApplied guarantees T1/T2 are present in the
// result and that an ACK-only arrival (before the send completes) cannot
// finalize the entry prematurely.
func (m *PendingMeasurement) Complete() bool {
	return m.sendApplied && m.firstAckArrived && m.secondAckArrived
}

// Result copies the six timestamps into a ProbeResult. Caller-owned fields
// (sequence number, target metadata, Success) are filled in by the caller.
func (m *PendingMeasurement) Result() ProbeResult {
	return ProbeResult{
		T1: m.T1,
		T2: m.T2,
		T3: m.T3,
		T4: m.T4,
		T5: m.T5,
		T6: m.T6,
	}
}
