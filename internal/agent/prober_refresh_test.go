package agent

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// newRefreshTestProber builds a Prober with a hint channel whose current
// pinglist contains targets.
func newRefreshTestProber(targets ...*controller_agent.PingTarget) *Prober {
	p := &Prober{logger: zerolog.Nop(), refreshHint: make(chan struct{}, 1)}
	p.UpdateTargets(targets)
	return p
}

func hintPending(p *Prober) bool {
	select {
	case <-p.refreshHint:
		return true
	default:
		return false
	}
}

// TestProber_TimeoutStreak_RequestsRefresh verifies that a refresh is
// requested exactly when a target reaches staleTargetTimeoutStreak
// consecutive timeouts.
func TestProber_TimeoutStreak_RequestsRefresh(t *testing.T) {
	target := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 7}
	p := newRefreshTestProber(target)

	for i := 1; i < staleTargetTimeoutStreak; i++ {
		p.recordTargetOutcome(target, true)
		if hintPending(p) {
			t.Fatalf("refresh requested after %d timeouts, want only after %d", i, staleTargetTimeoutStreak)
		}
	}
	p.recordTargetOutcome(target, true)
	if !hintPending(p) {
		t.Fatalf("no refresh requested after %d consecutive timeouts", staleTargetTimeoutStreak)
	}
}

// TestProber_TimeoutStreak_ResetBySuccess verifies that a completed probe
// resets the streak, so intermittent loss (here staleTargetTimeoutStreak-1
// timeouts between successes) does not request refreshes.
func TestProber_TimeoutStreak_ResetBySuccess(t *testing.T) {
	target := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 7}
	p := newRefreshTestProber(target)

	for round := 0; round < 3; round++ {
		for i := 1; i < staleTargetTimeoutStreak; i++ {
			p.recordTargetOutcome(target, true)
		}
		p.recordTargetOutcome(target, false)
	}
	if hintPending(p) {
		t.Error("refresh requested although every timeout was followed by a success")
	}
}

// TestProber_TimeoutStreak_PerTargetAndClearedOnUpdate verifies that streaks
// are tracked per (GID, QPN) and cleared when a new pinglist arrives.
func TestProber_TimeoutStreak_PerTargetAndClearedOnUpdate(t *testing.T) {
	oldQPN := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 7}
	newQPN := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 8}
	p := newRefreshTestProber(oldQPN, newQPN)

	for i := 1; i < staleTargetTimeoutStreak; i++ {
		p.recordTargetOutcome(oldQPN, true)
	}
	p.recordTargetOutcome(newQPN, true)
	if hintPending(p) {
		t.Fatal("timeouts to different QPNs must not share a streak")
	}

	p.UpdateTargets([]*controller_agent.PingTarget{oldQPN})
	p.recordTargetOutcome(oldQPN, true)
	if hintPending(p) {
		t.Error("UpdateTargets must clear existing streaks")
	}
}

// TestProber_TimeoutStreak_IgnoresTargetsNotInPinglist verifies that
// timeouts of probes addressed to a (GID, QPN) no longer in the pinglist --
// sent before a refresh replaced the QPN, expiring after it -- are not
// counted and cannot re-trigger a refresh.
func TestProber_TimeoutStreak_IgnoresTargetsNotInPinglist(t *testing.T) {
	oldQPN := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 7}
	newQPN := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 8}
	p := newRefreshTestProber(newQPN)

	for i := 0; i < 2*staleTargetTimeoutStreak; i++ {
		p.recordTargetOutcome(oldQPN, true)
	}
	if hintPending(p) {
		t.Error("timeouts to a QPN no longer in the pinglist must not request a refresh")
	}
}

// TestProber_RecordTargetOutcome_NilHint verifies that a Prober without a
// hint channel (struct literal) tracks streaks without blocking or panicking.
func TestProber_RecordTargetOutcome_NilHint(t *testing.T) {
	p := &Prober{logger: zerolog.Nop()}
	target := &controller_agent.PingTarget{TargetGid: "g1", TargetQpn: 7}
	for i := 0; i < 2*staleTargetTimeoutStreak; i++ {
		p.recordTargetOutcome(target, true)
	}
	p.recordTargetOutcome(nil, true)
}
