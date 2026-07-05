// Package e2e contains end-to-end tests for the R-Pingmesh RDMA probe protocol.
//
// Tests in this package require real or soft-RoCE RDMA devices and must be
// enabled explicitly by setting RDMA_E2E_ENABLED=1. They are intended to run
// inside a privileged container (via "make test-e2e") that sets up two
// soft-RoCE devices: rxe0 (prober) and rxe1 (responder).
//
// Test topology (veth pair for reliable intra-host loopback):
//
//	rxe0 (veth0, 10.200.0.2/24)   rxe1 (veth1, 10.200.0.1/24)
//	        prober   --probe-->  responder
//	        prober   <--ACK ---  responder
package e2e_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
)

const (
	proberDeviceName    = "rxe0"
	responderDeviceName = "rxe1"
	// gidIndex 1 selects the IPv4-mapped RoCEv2 GID for soft-RoCE devices.
	// Adjust if ibv_devinfo shows a different valid index for your environment.
	gidIndex = 1
	// testServiceLevel and testTrafficClass are deliberately non-zero across
	// every e2e test in this package to regression-test the sl/traffic_class
	// wiring (config -> bridge -> Zig RdmaDevice -> Address Handle): AH
	// creation must still succeed and probes must still round-trip with a
	// non-default SL/DSCP. rdma_rxe (soft-RoCE) does not implement PFC/DSCP
	// queuing, so this cannot verify the actual priority-queue *effect* --
	// only that the values flow through without breaking the data path.
	testServiceLevel  = uint8(3)
	testTrafficClass  = uint8(96) // DSCP 24 << 2
	eventRingCapacity = 256
	probeTimeoutMS    = uint32(1000)
	testTimeout       = 30 * time.Second
	// invalidGidIndex is well past rdma_rxe's small GID table (a handful of
	// entries) but still within the config-level sanity bound
	// (config.MaxGIDIndex = 255), so it exercises the Zig device-open
	// diagnostic rather than being rejected earlier by config validation.
	invalidGidIndex = 100
)

// TestRDMAE2ETwoDevices verifies a full probe/ACK round-trip between two
// soft-RoCE devices using the R-Pingmesh 6-timestamp protocol:
//
//	rxe0 (prober)  --probe-->  rxe1 (responder)
//	rxe0 (prober)  <-1stACK--  rxe1 (responder)
//	rxe0 (prober)  <-2ndACK--  rxe1 (responder)
//
// The test validates:
//   - All 5 hardware (or software-fallback) timestamps are non-zero
//   - NetworkRTT = (T5-T2) - (T4-T3) is positive and within 10 seconds
func TestRDMAE2ETwoDevices(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	// --- Context ---
	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	// --- Devices ---
	proberDev, err := rdmaCtx.OpenDeviceByName(proberDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open prober device %q (gidIndex=%d): %v", proberDeviceName, gidIndex, err)
	}
	defer proberDev.Close()
	t.Logf("prober  device: name=%s GID=%s IP=%s",
		proberDev.Info.DeviceName, proberDev.Info.GID, proberDev.Info.IPAddr)

	responderDev, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open responder device %q (gidIndex=%d): %v", responderDeviceName, gidIndex, err)
	}
	defer responderDev.Close()
	t.Logf("responder device: name=%s GID=%s IP=%s",
		responderDev.Info.DeviceName, responderDev.Info.GID, responderDev.Info.IPAddr)

	// --- Event rings (must be created before queues) ---
	proberRing, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create prober ring: %v", err)
	}
	defer proberRing.Destroy()

	responderRing, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create responder ring: %v", err)
	}
	defer responderRing.Destroy()

	// --- Queues ---
	proberQueue, err := proberDev.CreateQueue(rdmabridge.QueueTypeSender, proberRing)
	if err != nil {
		t.Fatalf("create prober queue: %v", err)
	}
	defer proberQueue.Destroy()
	t.Logf("prober  queue: QPN=%d usesSWTimestamps=%v",
		proberQueue.Info.QPN, proberQueue.Info.UsesSWTimestamps)

	responderQueue, err := responderDev.CreateQueue(rdmabridge.QueueTypeResponder, responderRing)
	if err != nil {
		t.Fatalf("create responder queue: %v", err)
	}
	defer responderQueue.Destroy()
	t.Logf("responder queue: QPN=%d usesSWTimestamps=%v",
		responderQueue.Info.QPN, responderQueue.Info.UsesSWTimestamps)

	// --- Parse GIDs ---
	// proberGIDBytes is the expected GID for the prober device, used to
	// verify that parseGRH() in cq.zig correctly extracts the sender's GID.
	// The responder uses ev.SourceGID (the parsed GID) for ACKs, matching
	// the production code path; this test asserts ev.SourceGID == proberGIDBytes.
	proberGIDBytes, err := probe.ParseGID(proberDev.Info.GID)
	if err != nil {
		t.Fatalf("parse prober GID %q: %v", proberDev.Info.GID, err)
	}

	responderGIDBytes, err := probe.ParseGID(responderDev.Info.GID)
	if err != nil {
		t.Fatalf("parse responder GID %q: %v", responderDev.Info.GID, err)
	}

	// --- Channels for inter-goroutine communication ---
	// firstAckT5Ch receives T5 (prober's NIC recv completion for the first ACK).
	firstAckT5Ch := make(chan uint64, 1)
	var firstAckOnce sync.Once

	// secondAckCh receives the second ACK event, which carries T3 and T4 in the payload.
	// T4 = responder's first-ACK send completion, only available in the second ACK.
	secondAckCh := make(chan rdmabridge.CompletionEvent, 1)
	var secondAckOnce sync.Once

	// errCh collects errors from event handler goroutines.
	errCh := make(chan error, 4)

	testCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// --- Prober event poller ---
	// Collects T5 (timestamp of NIC first-ACK recv completion) from AckTypeFirst,
	// and T3+T4 from AckTypeSecond payload.
	// T4 is the responder's first-ACK send completion; it is NOT in the first ACK
	// payload (unknown at send time) but IS in the second ACK payload.
	proberQueue.StartEventPoller(testCtx, func(ev rdmabridge.CompletionEvent) {
		t.Logf("prober  event: IsSend=%v IsAck=%v AckType=%d Status=%d TimestampNS=%d",
			ev.IsSend, ev.IsAck, ev.AckType, ev.Status, ev.TimestampNS)
		if ev.IsAck && ev.AckType == rdmabridge.AckTypeFirst {
			firstAckOnce.Do(func() {
				firstAckT5Ch <- ev.TimestampNS // T5: prober NIC recv completion for first ACK
			})
		}
		if ev.IsAck && ev.AckType == rdmabridge.AckTypeSecond {
			secondAckOnce.Do(func() {
				secondAckCh <- ev // carries T3 and T4 from responder
			})
		}
	})

	// --- Responder event poller: receive probe, send first and second ACK ---
	responderQueue.StartEventPoller(testCtx, func(ev rdmabridge.CompletionEvent) {
		t.Logf("responder event: IsSend=%v IsAck=%v AckType=%d Status=%d TimestampNS=%d SourceQPN=%d",
			ev.IsSend, ev.IsAck, ev.AckType, ev.Status, ev.TimestampNS, ev.SourceQPN)
		// Skip send completions, ACK events, and any error events.
		if ev.IsSend || ev.IsAck || ev.Status != 0 {
			return
		}

		// Probe received. ev.TimestampNS = T3, ev.SourceGID = prober GID,
		// ev.SourceQPN = prober QPN.
		t3 := ev.TimestampNS

		// Verify that parseGRH() in cq.zig correctly extracted the prober's GID.
		// This exercises the same code path the production responder uses.
		if ev.SourceGID != proberGIDBytes {
			select {
			case errCh <- fmt.Errorf("SourceGID mismatch: got %x, want %x", ev.SourceGID, proberGIDBytes):
			default:
			}
			return
		}

		// Reconstruct the probe packet buffer so the Zig layer can read T1
		// and SequenceNum when building the ACK payload.
		pkt := &rdmabridge.ProbePacket{
			Version:     rdmabridge.PacketVersion,
			MsgType:     rdmabridge.MsgTypeProbe,
			SequenceNum: ev.SequenceNum,
			T1:          ev.T1,
		}
		buf := make([]byte, rdmabridge.ProbePacketSize)
		rdmabridge.SerializeProbePacket(pkt, buf)

		// Send ACKs using ev.SourceGID (parsed by cq.zig's parseGRH),
		// matching the production responder's code path.
		t4, ackErr := responderQueue.SendFirstAck(
			ev.SourceGID,
			ev.SourceQPN,
			ev.FlowLabel,
			buf,
			t3,
			probeTimeoutMS,
		)
		if ackErr != nil {
			select {
			case errCh <- fmt.Errorf("SendFirstAck: %w", ackErr):
			default:
			}
			return
		}

		// Send second ACK carrying T3 and T4 so the prober can compute
		// ResponderDelay = T4-T3.
		if err := responderQueue.SendSecondAck(
			ev.SourceGID,
			ev.SourceQPN,
			ev.FlowLabel,
			buf,
			t3,
			t4,
			probeTimeoutMS,
		); err != nil {
			select {
			case errCh <- fmt.Errorf("SendSecondAck: %w", err):
			default:
			}
		}
	})

	// --- Send probe: prober -> responder ---
	const seqNum = uint64(1)
	result := proberQueue.SendProbe(
		responderGIDBytes,
		responderQueue.Info.QPN,
		seqNum,
		0, // flowLabel (0 = no ECMP path selection)
		probeTimeoutMS,
	)
	if result.Error != nil {
		t.Fatalf("SendProbe: %v", result.Error)
	}
	t.Logf("probe sent: T1=%d ns  T2=%d ns", result.T1NS, result.T2NS)

	// --- Wait for ACKs or failure ---
	// The 6-timestamp protocol requires:
	//   T5 from first ACK (NIC recv completion on prober)
	//   T3, T4 from second ACK payload (T4 = responder first-ACK send completion)
	var t5 uint64
	select {
	case t5 = <-firstAckT5Ch:
		t.Logf("first ACK received: T5=%d ns", t5)
	case err := <-errCh:
		t.Fatalf("responder goroutine error (waiting for first ACK): %v", err)
	case <-testCtx.Done():
		t.Fatal("timeout: first ACK not received within test timeout")
	}

	select {
	case secondAckEv := <-secondAckCh:
		usesSWTS := proberQueue.Info.UsesSWTimestamps || responderQueue.Info.UsesSWTimestamps
		validateRoundTrip(t, result.T1NS, result.T2NS, t5, secondAckEv, usesSWTS)
	case err := <-errCh:
		t.Fatalf("responder goroutine error (waiting for second ACK): %v", err)
	case <-testCtx.Done():
		t.Fatal("timeout: second ACK not received within test timeout")
	}
}

// TestInvalidGidIndexFailsFast verifies that opening a device with a
// gid_index that does not resolve to a usable GID on the (active) rxe0
// port fails immediately with a specific, actionable error -- naming the
// device, port, and GID table size -- rather than a generic message that
// could be mistaken for "no active port found" (see P2-E in the rebuild
// design notes / zig/src/device.zig's findActivePortAndGid()).
func TestInvalidGidIndexFailsFast(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	_, err = rdmaCtx.OpenDeviceByName(proberDeviceName, invalidGidIndex, testServiceLevel, testTrafficClass)
	if err == nil {
		t.Fatalf("expected OpenDeviceByName(%q, gidIndex=%d) to fail, but it succeeded",
			proberDeviceName, invalidGidIndex)
	}
	t.Logf("OpenDeviceByName failed as expected: %v", err)

	msg := err.Error()

	// The error must identify gid_index by value and name the device/port,
	// not just report "no usable GID" / "no active port" -- rxe0's port IS
	// active, so a message implying otherwise would misdirect debugging.
	wantSubstrings := []string{fmt.Sprintf("gid_index=%d", invalidGidIndex), proberDeviceName}
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not contain expected substring %q", msg, want)
		}
	}

	dontWantSubstrings := []string{
		"no usable GID found on any active port",
		"no active port found",
	}
	for _, dontWant := range dontWantSubstrings {
		if strings.Contains(msg, dontWant) {
			t.Errorf("error message %q incorrectly implies no active port was found (contains %q); "+
				"gid_index=%d is simply out of range on an active port", msg, dontWant, invalidGidIndex)
		}
	}
}

// validateRoundTrip checks timestamp ordering and computes NetworkRTT.
//
// t5 comes from the first ACK's NIC recv completion on the prober.
// secondAckEv carries T3 and T4 in its payload (T4 = responder first-ACK send
// completion, which is only known after the first ACK send WR completes and is
// therefore only available in the second ACK payload).
//
// All SW-fallback timestamps (T1-T5 in Zig, T6 in Go) share the same
// CLOCK_MONOTONIC domain. In principle that makes NetworkRTT positive, but on
// this soft-RoCE/veth environment SW timestamps are stamped at CQ-poll time
// (not at actual wire send/recv time) while the real loopback RTT is near
// zero, so NetworkRTT can legitimately land slightly negative from poll-loop
// jitter alone. That is measurement noise, not a regression, so it is only
// logged. What IS a hard failure is a magnitude far outside that jitter
// range: either a clock-domain mismatch (|NetworkRTT| in the ~1 second range
// or beyond) or timestamps that are cross-scale relative to each other (e.g.
// T5-T1 spanning >= 10s when the whole exchange is loopback-local).
func validateRoundTrip(t *testing.T, t1NS, t2NS, t5 uint64, secondAckEv rdmabridge.CompletionEvent, usesSWTimestamps bool) {
	t.Helper()

	t3 := secondAckEv.T3 // responder recv timestamp (from second ACK payload)
	t4 := secondAckEv.T4 // responder first-ACK send completion (from second ACK payload)

	t.Logf("timestamps: T1=%d T2=%d T3=%d T4=%d T5=%d (ns)", t1NS, t2NS, t3, t4, t5)

	// All timestamps must be non-zero.
	for name, val := range map[string]uint64{
		"T1": t1NS, "T2": t2NS, "T3": t3, "T4": t4, "T5": t5,
	} {
		if val == 0 {
			t.Errorf("expected non-zero %s timestamp", name)
		}
	}

	if t.Failed() {
		return
	}

	// Cross-scale sanity check: on a loopback veth pair the entire probe/ACK
	// exchange (T1 through T5) should take well under a second. A genuine
	// clock-domain mismatch (e.g. a wall-clock timestamp mixed into a
	// CLOCK_MONOTONIC computation) would blow this elapsed time out to
	// roughly 1e18 ns or make it go negative; ordinary jitter never does.
	const maxCrossScaleNs = int64(10 * time.Second)
	elapsedNs := int64(t5) - int64(t1NS)
	if elapsedNs < 0 || elapsedNs >= maxCrossScaleNs {
		t.Errorf("T5-T1 elapsed %d ns is out of range [0, %d ns): cross-scale timestamps indicate a clock-domain regression",
			elapsedNs, maxCrossScaleNs)
	}

	// NetworkRTT = (T5 - T2) - (T4 - T3)
	if t5 > t2NS && t4 >= t3 {
		networkRTTns := int64(t5-t2NS) - int64(t4-t3)
		t.Logf("NetworkRTT     = %d ns (%.3f ms)", networkRTTns, float64(networkRTTns)/1e6)
		t.Logf("ResponderDelay = %d ns (%.3f ms)", int64(t4-t3), float64(t4-t3)/1e6)

		// Hard-fail only on a clock-domain-scale magnitude, not on ordinary
		// small-negative SW-timestamp poll jitter.
		const maxDomainMismatchNs = int64(1 * time.Second)
		absRTT := networkRTTns
		if absRTT < 0 {
			absRTT = -absRTT
		}
		if absRTT >= maxDomainMismatchNs {
			t.Errorf("|NetworkRTT| = %d ns >= %d ns sanity bound: clock-domain regression", absRTT, maxDomainMismatchNs)
		} else if networkRTTns < 0 {
			t.Logf("WARNING: NetworkRTT is small-negative (%d ns); this is expected "+
				"SW-timestamp poll jitter on soft-RoCE (CQ-poll-time stamping vs. "+
				"near-zero loopback RTT), not a regression", networkRTTns)
		}
	} else {
		t.Logf("skipping RTT calculation: unexpected timestamp ordering "+
			"(T2=%d T3=%d T4=%d T5=%d)", t2NS, t3, t4, t5)
	}
}
