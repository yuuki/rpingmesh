package probe

import "testing"

// TestPendingMeasurement_InOrder verifies the normal case where the first ACK
// arrives before the second ACK.
func TestPendingMeasurement_InOrder(t *testing.T) {
	m := NewPendingMeasurement(100, 101)

	if m.Complete() {
		t.Fatal("measurement should not be complete before any ACK")
	}

	m.ApplyFirstAck(200 /*t3*/, 301 /*t5*/)
	if m.Complete() {
		t.Fatal("measurement should not be complete after only the first ACK")
	}

	m.ApplySecondAck(200 /*t3*/, 202 /*t4*/, 302 /*t6*/)
	if !m.Complete() {
		t.Fatal("measurement should be complete after both ACKs")
	}

	got := m.Result()
	want := ProbeResult{T1: 100, T2: 101, T3: 200, T4: 202, T5: 301, T6: 302}
	if got != want {
		t.Errorf("Result = %+v, want %+v", got, want)
	}
}

// TestPendingMeasurement_OutOfOrder verifies that a second ACK arriving before
// the first ACK is accepted and the measurement still completes with all six
// timestamps intact. This is the regression guard for the reorder bug where a
// second-ACK-first arrival orphaned the first ACK and lost the measurement.
func TestPendingMeasurement_OutOfOrder(t *testing.T) {
	m := NewPendingMeasurement(100, 101)

	// Second ACK arrives first: T3, T4, T6 recorded; T5 still unknown.
	m.ApplySecondAck(200 /*t3*/, 202 /*t4*/, 302 /*t6*/)
	if m.Complete() {
		t.Fatal("measurement should not be complete after only the second ACK")
	}

	// First ACK arrives afterwards: supplies T5 and authoritative T3.
	m.ApplyFirstAck(200 /*t3*/, 301 /*t5*/)
	if !m.Complete() {
		t.Fatal("measurement should be complete after both ACKs (out of order)")
	}

	got := m.Result()
	want := ProbeResult{T1: 100, T2: 101, T3: 200, T4: 202, T5: 301, T6: 302}
	if got != want {
		t.Errorf("Result = %+v, want %+v", got, want)
	}
}

// TestPendingMeasurement_FirstAckT3Wins verifies that when the two ACKs carry
// differing T3 values (e.g., due to a responder-side quirk), the first ACK's
// T3 is used regardless of arrival order.
func TestPendingMeasurement_FirstAckT3Wins(t *testing.T) {
	// First ACK arrives first, then second ACK carries a different T3.
	m1 := NewPendingMeasurement(100, 101)
	m1.ApplyFirstAck(200, 301)
	m1.ApplySecondAck(999 /*divergent t3*/, 202, 302)
	if m1.Result().T3 != 200 {
		t.Errorf("in-order: T3 = %d, want 200 (first ACK wins)", m1.Result().T3)
	}

	// Second ACK arrives first with a divergent T3, then the first ACK
	// overwrites it with the authoritative value.
	m2 := NewPendingMeasurement(100, 101)
	m2.ApplySecondAck(999 /*divergent t3*/, 202, 302)
	if m2.Result().T3 != 999 {
		t.Errorf("out-of-order interim: T3 = %d, want 999 (only second ACK seen)", m2.Result().T3)
	}
	m2.ApplyFirstAck(200, 301)
	if m2.Result().T3 != 200 {
		t.Errorf("out-of-order final: T3 = %d, want 200 (first ACK wins)", m2.Result().T3)
	}
}

// TestPendingMeasurement_ResultFeedsCalculateRTT verifies that a completed
// measurement produces a ProbeResult that CalculateRTT accepts as valid once
// the caller-owned Success flag is set.
func TestPendingMeasurement_ResultFeedsCalculateRTT(t *testing.T) {
	m := NewPendingMeasurement(100_000, 101_000)
	m.ApplyFirstAck(200_000, 301_000)
	m.ApplySecondAck(200_000, 202_000, 302_000)

	res := m.Result()
	res.Success = true
	rtt := CalculateRTT(&res)
	if !rtt.Valid {
		t.Fatalf("expected valid RTT, got error: %s", rtt.ValidationError)
	}
}
