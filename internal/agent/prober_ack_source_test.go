package agent

import (
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// TestApplyAck_RejectsForeignSource checks that an ACK carrying the right
// sequence number but coming from a GID/QPN other than the probed responder
// is dropped, and that the genuine ACKs still complete the probe afterwards.
func TestApplyAck_RejectsForeignSource(t *testing.T) {
	const seq = uint64(0xdeadbeef00000001)
	targetGID, err := probe.ParseGID("fe80::1")
	if err != nil {
		t.Fatal(err)
	}
	otherGID, err := probe.ParseGID("fe80::2")
	if err != nil {
		t.Fatal(err)
	}
	target := &controller_agent.PingTarget{TargetGid: "fe80::1", TargetQpn: 100}

	ack := func(gid [16]byte, qpn uint32, ackType uint8, t3, t4, ts uint64) *rdmabridge.CompletionEvent {
		return &rdmabridge.CompletionEvent{
			SequenceNum: seq,
			IsAck:       true,
			AckType:     ackType,
			T3:          t3,
			T4:          t4,
			TimestampNS: ts,
			SourceGID:   gid,
			SourceQPN:   qpn,
		}
	}

	p := fakeProber(1)
	pp := &pendingProbe{
		target:    target,
		meas:      probe.NewPendingMeasurement(),
		createdAt: time.Now(),
		targetGID: targetGID,
		targetQPN: 100,
	}
	pp.meas.ApplySend(1, 100)
	p.pending[seq] = pp

	// Forged pair: right seq, wrong GID (first) and wrong QPN (second).
	p.handleACKEvent(ack(otherGID, 100, rdmabridge.AckTypeFirst, 1000, 0, 2400))
	p.handleACKEvent(ack(targetGID, 101, rdmabridge.AckTypeSecond, 1000, 1300, 0))

	select {
	case r := <-p.resultChan:
		t.Fatalf("forged ACKs completed the probe: %+v", r)
	default:
	}
	p.pendingMu.Lock()
	_, still := p.pending[seq]
	p.pendingMu.Unlock()
	if !still {
		t.Fatal("forged ACK removed the pending entry")
	}

	// Genuine pair from the probed responder completes it.
	p.handleACKEvent(ack(targetGID, 100, rdmabridge.AckTypeFirst, 1000, 0, 2400))
	p.handleACKEvent(ack(targetGID, 100, rdmabridge.AckTypeSecond, 1000, 1300, 0))

	select {
	case r := <-p.resultChan:
		if r.T3 != 1000 || r.T4 != 1300 || r.T5 != 2400 {
			t.Fatalf("unexpected timestamps: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("genuine ACKs did not complete the probe")
	}
}
