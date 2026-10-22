package e2e_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

// TestResponderAckPairBurst sends a burst of probes, far more than the
// responder queue's 32 send slots, back to back at an agent.Responder and
// requires both ACKs for every probe. The responder answers with
// Queue.SendAckPair, which returns once the first ACK is posted and leaves
// the second ACK to the CQ poller, so this exercises the asynchronous path:
// T4 stamped into the staged second ACK from the first ACK's completion,
// slot reuse for the second ACK, and the responder's wait for a free slot
// when every slot is in flight. It runs in event and busy CQ poll modes,
// since the second ACK is posted from the poller thread in both.
func TestResponderAckPairBurst(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}
	for _, tc := range []struct {
		name string
		mode int
	}{
		{name: "event", mode: rdmabridge.CQPollEvent},
		{name: "busy", mode: rdmabridge.CQPollBusy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runResponderAckPairBurst(t, tc.mode)
		})
	}
}

// ackPair collects the two ACKs of one probe as seen by the prober.
type ackPair struct {
	first, second *rdmabridge.CompletionEvent
}

func runResponderAckPairBurst(t *testing.T, mode int) {
	const (
		numProbes = 256
		// Large enough that the burst cannot overflow either ring: this
		// test is about the ACK path, not ring sizing.
		ringCapacity = 4096
		ackTimeout   = 20 * time.Second
	)

	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	proberDev, err := rdmaCtx.OpenDeviceByName(proberDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open prober device %q: %v", proberDeviceName, err)
	}
	defer proberDev.Close()
	proberDev.CQPollMode = mode

	responderDev, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open responder device %q: %v", responderDeviceName, err)
	}
	defer responderDev.Close()
	responderDev.CQPollMode = mode

	proberRing, err := rdmabridge.NewEventRing(ringCapacity)
	if err != nil {
		t.Fatalf("create prober ring: %v", err)
	}
	defer proberRing.Destroy()
	responderRing, err := rdmabridge.NewEventRing(ringCapacity)
	if err != nil {
		t.Fatalf("create responder ring: %v", err)
	}
	defer responderRing.Destroy()

	proberQueue, err := proberDev.CreateQueue(rdmabridge.QueueTypeSender, proberRing)
	if err != nil {
		t.Fatalf("create prober queue: %v", err)
	}
	defer proberQueue.Destroy()

	responder, err := agent.NewResponder(responderDev, responderRing)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer responder.Destroy()
	responderInfo := responder.GetQueueInfo()

	responderGID, err := probe.ParseGID(responderDev.Info.GID)
	if err != nil {
		t.Fatalf("parse responder GID %q: %v", responderDev.Info.GID, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := responder.Start(ctx); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}

	var (
		mu       sync.Mutex
		pairs    = make(map[uint64]*ackPair, numProbes)
		complete = make(chan struct{})
		done     int
	)
	startEventPoller(ctx, proberQueue, proberRing, func(ev rdmabridge.CompletionEvent) {
		if ev.IsSend || !ev.IsAck || ev.Status != 0 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		p := pairs[ev.SequenceNum]
		if p == nil {
			p = &ackPair{}
			pairs[ev.SequenceNum] = p
		}
		e := ev
		switch ev.AckType {
		case rdmabridge.AckTypeFirst:
			p.first = &e
		case rdmabridge.AckTypeSecond:
			p.second = &e
		}
		if p.first != nil && p.second != nil {
			done++
			if done == numProbes {
				close(complete)
			}
		}
	})

	// Send the whole burst before waiting for any ACK, so the responder
	// receives probes faster than it can complete ACK pairs.
	const seqBase = uint64(0x5eed) << 32
	for i := uint64(0); i < numProbes; i++ {
		res := proberQueue.SendProbe(responderGID, responderInfo.QPN, seqBase+i, 0, probeTimeoutMS)
		if res.Error != nil {
			t.Fatalf("SendProbe(%d): %v", i, res.Error)
		}
	}

	select {
	case <-complete:
	case <-time.After(ackTimeout):
	}

	mu.Lock()
	defer mu.Unlock()
	if done != numProbes {
		t.Fatalf("got both ACKs for %d of %d probes within %s (responder ring drops: %d)",
			done, numProbes, ackTimeout, responderRing.DropCount())
	}
	for i := uint64(0); i < numProbes; i++ {
		p := pairs[seqBase+i]
		first, second := p.first, p.second
		if second.T3 != first.T3 || second.T1 != first.T1 {
			t.Errorf("seq %d: second ACK (T1=%d T3=%d) does not echo the first (T1=%d T3=%d)",
				i, second.T1, second.T3, first.T1, first.T3)
		}
		if second.T4 == 0 {
			t.Errorf("seq %d: T4 is zero in the second ACK", i)
		}
		// With software timestamps (rxe) T3 and T4 are both CLOCK_MONOTONIC
		// on the responder, and T4 is taken after the first ACK completes.
		if responderInfo.UsesSWTimestamps && second.T4 < second.T3 {
			t.Errorf("seq %d: T4=%d < T3=%d", i, second.T4, second.T3)
		}
	}
	if occ := responderRing.TakeMaxOccupancy(); occ == 0 || occ > responderRing.Capacity() {
		t.Errorf("responder ring max occupancy = %d, want 1..%d", occ, responderRing.Capacity())
	}
	t.Logf("all %d ACK pairs received; responder ring capacity %d", numProbes, responderRing.Capacity())
}
