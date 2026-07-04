// Package e2e contains end-to-end tests for the R-Pingmesh system.
//
// TestMultiRNICBothDevicesProbe validates the multi-rail fix in
// internal/agent/agent.go: every opened RDMA device gets its own Prober (not
// just devices[0]), so on a multi-rail host every RNIC actively probes
// instead of only being probed BY other agents. This test proves the fix at
// the Prober/Responder/ClusterMonitor level (the same layer
// probe_otel_e2e_test.go exercises for a single device) by wiring BOTH
// rxe0 and rxe1 as prober+responder pairs pointed at each other:
//
//	rxe0 prober --probe--> rxe1 responder
//	rxe1 prober --probe--> rxe0 responder
//
// and asserting that both directions independently produce at least one
// successful (all 6 timestamps collected) ProbeResult.
package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/agent"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// TestMultiRNICBothDevicesProbe verifies that when every opened device gets
// its own Prober and Responder (mirroring what Agent.Initialize now does for
// every device instead of only devices[0]), both directions of the
// rxe0<->rxe1 pair independently complete probes. A regression that only
// wires up devices[0] as a prober would still pass single-device tests like
// TestRDMAE2ETwoDevices and TestProbeToOTelMetrics but would leave rxe1 (or
// any non-first device) never sending a single probe -- exactly the blind
// spot this test is designed to catch.
func TestMultiRNICBothDevicesProbe(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	const (
		torA            = "tor-e2e-a"
		torB            = "tor-e2e-b"
		probeIntervalMS = uint32(200)
		resultTimeout   = 20 * time.Second
	)

	// --- RDMA context ---
	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	// --- Devices: rxe0 and rxe1, each acting as BOTH a prober and a responder ---
	devA, err := rdmaCtx.OpenDeviceByName(proberDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open device %q: %v", proberDeviceName, err)
	}
	defer devA.Close()
	t.Logf("device A (%s): GID=%s IP=%s", proberDeviceName, devA.Info.GID, devA.Info.IPAddr)

	devB, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open device %q: %v", responderDeviceName, err)
	}
	defer devB.Close()
	t.Logf("device B (%s): GID=%s IP=%s", responderDeviceName, devB.Info.GID, devB.Info.IPAddr)

	// --- Event rings: one prober ring and one responder ring per device,
	// matching Agent.createEventRings' one-ring-per-role-per-device layout. ---
	proberRingA, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create prober ring A: %v", err)
	}
	defer proberRingA.Destroy()
	respRingA, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create responder ring A: %v", err)
	}
	defer respRingA.Destroy()

	proberRingB, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create prober ring B: %v", err)
	}
	defer proberRingB.Destroy()
	respRingB, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create responder ring B: %v", err)
	}
	defer respRingB.Destroy()

	// --- Responders: one per device, so each device can be probed by the other. ---
	responderA, err := agent.NewResponder(devA, respRingA)
	if err != nil {
		t.Fatalf("NewResponder(A): %v", err)
	}
	responderB, err := agent.NewResponder(devB, respRingB)
	if err != nil {
		t.Fatalf("NewResponder(B): %v", err)
	}

	// --- Probers: one per device, each targeting the OTHER device's responder. ---
	proberA, err := agent.NewProber(devA, proberRingA, probeIntervalMS)
	if err != nil {
		t.Fatalf("NewProber(A): %v", err)
	}
	proberB, err := agent.NewProber(devB, proberRingB, probeIntervalMS)
	if err != nil {
		t.Fatalf("NewProber(B): %v", err)
	}

	// --- Mock controllers: A's pinglist points at B's responder, and vice versa. ---
	respAQueueInfo := responderA.GetQueueInfo()
	respBQueueInfo := responderB.GetQueueInfo()

	clientAToB := &mockControllerClient{
		targets: []*controller_agent.PingTarget{
			{
				TargetGid:        devB.Info.GID,
				TargetQpn:        respBQueueInfo.QPN,
				TargetIp:         devB.Info.IPAddr,
				TargetHostname:   "e2e-device-b",
				TargetTorId:      torB,
				TargetDeviceName: devB.Info.DeviceName,
			},
		},
	}
	clientBToA := &mockControllerClient{
		targets: []*controller_agent.PingTarget{
			{
				TargetGid:        devA.Info.GID,
				TargetQpn:        respAQueueInfo.QPN,
				TargetIp:         devA.Info.IPAddr,
				TargetHostname:   "e2e-device-a",
				TargetTorId:      torA,
				TargetDeviceName: devA.Info.DeviceName,
			},
		},
	}

	// updateIntervalSec=3600 so only the initial immediate fetch runs per monitor,
	// matching NewClusterMonitor's per-device requester GID wiring in
	// Agent.createClusterMonitors (each device's own GID is its requester_gid).
	monitorA := agent.NewClusterMonitor(clientAToB, proberA, "e2e-agent", torA, devA.Info.GID, 3600)
	monitorB := agent.NewClusterMonitor(clientBToA, proberB, "e2e-agent", torB, devB.Info.GID, 3600)

	// --- Start everything: responders first, then probers, then monitors,
	// matching Agent.Start's ordering. ---
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := responderA.Start(ctx); err != nil {
		t.Fatalf("responderA.Start: %v", err)
	}
	if err := responderB.Start(ctx); err != nil {
		t.Fatalf("responderB.Start: %v", err)
	}
	if err := proberA.Start(ctx); err != nil {
		t.Fatalf("proberA.Start: %v", err)
	}
	if err := proberB.Start(ctx); err != nil {
		t.Fatalf("proberB.Start: %v", err)
	}
	if err := monitorA.Start(ctx); err != nil {
		t.Fatalf("monitorA.Start: %v", err)
	}
	if err := monitorB.Start(ctx); err != nil {
		t.Fatalf("monitorB.Start: %v", err)
	}

	// --- Wait for at least one successful (all 6 timestamps collected)
	// result from EACH direction. result.Success reflects only that the ACK
	// round trip completed (see Prober.finalizeIfCompleteLocked), independent
	// of probe.CalculateRTT's Valid verdict, so this assertion is not
	// sensitive to the small-negative-RTT SW-timestamp jitter documented in
	// probe_otel_e2e_test.go. ---
	successA := waitForSuccess(t, "A->B", proberA.Results(), resultTimeout)
	successB := waitForSuccess(t, "B->A", proberB.Results(), resultTimeout)

	// --- Controlled, symmetric shutdown (mirrors Agent.Stop's ordering:
	// monitors, then probers, then responders). ---
	monitorA.Stop()
	monitorB.Stop()
	proberA.Destroy()
	proberB.Destroy()
	responderA.Destroy()
	responderB.Destroy()

	if !successA {
		t.Errorf("device A (%s) never produced a successful probe result targeting device B (%s): "+
			"this is the multi-rail blind spot this test guards against", proberDeviceName, responderDeviceName)
	}
	if !successB {
		t.Errorf("device B (%s) never produced a successful probe result targeting device A (%s): "+
			"this is the multi-rail blind spot this test guards against", responderDeviceName, proberDeviceName)
	}
}

// waitForSuccess drains resultCh until a Success==true result is observed or
// timeout elapses, logging every result seen along the way. It returns
// false (without failing the test itself, letting the caller decide) if no
// successful result arrives in time.
func waitForSuccess(t *testing.T, label string, resultCh <-chan *probe.ProbeResult, timeout time.Duration) bool {
	t.Helper()

	deadline := time.After(timeout)
	for {
		select {
		case result, ok := <-resultCh:
			if !ok {
				t.Logf("%s: result channel closed before a successful probe was observed", label)
				return false
			}
			t.Logf("%s: result seq=%d success=%v error=%q", label, result.SequenceNum, result.Success, result.ErrorMessage)
			if result.Success {
				return true
			}
		case <-deadline:
			t.Logf("%s: timed out after %s waiting for a successful probe result", label, timeout)
			return false
		}
	}
}
