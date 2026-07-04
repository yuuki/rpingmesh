package probe

// PendingMeasurement tracks the in-flight 6-timestamp state of a single probe
// as its two ACKs arrive. The two ACKs may arrive out of order (the second ACK
// can be delivered before the first), so this state machine records whichever
// arrives first and only reports completion once both have been seen.
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

	firstAckArrived  bool
	secondAckArrived bool
}

// NewPendingMeasurement creates a pending measurement seeded with T1 and T2,
// which are known at probe-send time.
func NewPendingMeasurement(t1, t2 uint64) *PendingMeasurement {
	return &PendingMeasurement{T1: t1, T2: t2}
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

// Complete reports whether both ACKs have arrived and the measurement is ready
// to be finalized into a ProbeResult.
func (m *PendingMeasurement) Complete() bool {
	return m.firstAckArrived && m.secondAckArrived
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
