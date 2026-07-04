// Package e2e — TestECMPMultiFlowLabel validates the multi-flow-label probing
// MECHANISM end to end on soft-RoCE.
//
// Soft-RoCE over a veth pair has no real ECMP fabric, so this test does not (and
// cannot) assert that different flow labels take different physical paths.
// Instead it verifies the observable mechanism the feature adds:
//
//  1. A target carrying FlowLabelSeed + FlowLabelCount > 1 causes the Prober to
//     rotate through a set of DISTINCT flow labels (round-robin), rather than
//     always using one deterministic label.
//  2. Every probe still completes the 6-timestamp round trip (the ACK-matching
//     path is unaffected by varying the flow label per send).
//
// It shares the soft-RoCE devices (rxe0/rxe1) and RDMA_E2E_ENABLED gate with
// the other RDMA e2e tests, and is exercised via `make test-e2e`.
package e2e_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/agent"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

func TestECMPMultiFlowLabel(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	const (
		sourceTorID     = "tor-ecmp-source"
		targetTorID     = "tor-ecmp-target"
		probeIntervalMS = uint32(150)
		flowLabelCount  = uint32(4)
		flowLabelSeed   = uint32(0x0BADF00D)
		collectTimeout  = 20 * time.Second
		drainTimeout    = 2 * time.Second
	)

	// --- RDMA context and devices ---
	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	proberDev, err := rdmaCtx.OpenDeviceByName(proberDeviceName, gidIndex)
	if err != nil {
		t.Fatalf("open prober device %q: %v", proberDeviceName, err)
	}
	defer proberDev.Close()

	responderDev, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex)
	if err != nil {
		t.Fatalf("open responder device %q: %v", responderDeviceName, err)
	}
	defer responderDev.Close()

	// --- Event rings (before queues) ---
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

	// --- Prober and Responder ---
	prober, err := agent.NewProber(proberDev, proberRing, probeIntervalMS)
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	responder, err := agent.NewResponder(responderDev, responderRing)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	// --- Mock controller: one target with a multi-label ECMP set ---
	responderQueueInfo := responder.GetQueueInfo()
	mockClient := &mockControllerClient{
		targets: []*controller_agent.PingTarget{
			{
				TargetGid:        responderDev.Info.GID,
				TargetQpn:        responderQueueInfo.QPN,
				TargetIp:         responderDev.Info.IPAddr,
				TargetHostname:   "e2e-ecmp-responder",
				TargetTorId:      targetTorID,
				TargetDeviceName: responderDev.Info.DeviceName,
				// The base (legacy) flow label; ignored when count > 1.
				FlowLabel:      flowLabelSeed & 0xFFFFF,
				FlowLabelSeed:  flowLabelSeed,
				FlowLabelCount: flowLabelCount,
			},
		},
	}
	t.Logf("mock target: GID=%s QPN=%d flow_label_count=%d seed=%#x",
		responderDev.Info.GID, responderQueueInfo.QPN, flowLabelCount, flowLabelSeed)

	monitor := agent.NewClusterMonitor(
		mockClient, prober, "e2e-ecmp-agent", sourceTorID, proberDev.Info.GID, 3600,
	)

	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout+10*time.Second)
	defer cancel()

	if err := responder.Start(ctx); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	if err := prober.Start(ctx); err != nil {
		t.Fatalf("prober.Start: %v", err)
	}
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("monitor.Start: %v", err)
	}

	// --- Consume results, tracking distinct flow labels and timeouts ---
	var (
		mu             sync.Mutex
		distinctLabels = map[uint32]struct{}{}
		completed      int
		timeouts       int
	)
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for result := range prober.Results() {
			mu.Lock()
			if result.Success {
				completed++
				distinctLabels[result.FlowLabel] = struct{}{}
			} else if strings.Contains(result.ErrorMessage, "timed out") {
				timeouts++
			}
			mu.Unlock()
		}
	}()

	// Wait until we have observed the full label set completing, or time out.
	// With round-robin over flowLabelCount labels at ~1 probe / probeInterval,
	// this needs only a few hundred ms; the generous deadline absorbs jitter.
	deadline := time.Now().Add(collectTimeout)
	for time.Now().Before(deadline) {
		mu.Lock()
		enough := len(distinctLabels) >= int(flowLabelCount) && completed >= int(flowLabelCount)
		mu.Unlock()
		if enough {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// --- Controlled shutdown before assertions ---
	monitor.Stop()
	prober.Destroy() // closes Results(), so the consumer's range loop ends
	responder.Destroy()

	select {
	case <-consumerDone:
	case <-time.After(drainTimeout):
		t.Log("WARNING: result consumer did not drain within drainTimeout")
	}

	// --- Assertions ---
	mu.Lock()
	defer mu.Unlock()
	t.Logf("completed=%d distinct_flow_labels=%d timeouts=%d", completed, len(distinctLabels), timeouts)

	if completed == 0 {
		t.Fatal("no probes completed the 6-timestamp round trip")
	}
	// The ACK-matching path must be unaffected by per-send flow-label variation.
	if timeouts != 0 {
		t.Fatalf("%d probes timed out waiting for ACKs: multi-flow-label send broke the ACK path", timeouts)
	}
	// The mechanism: probes to a single target used MULTIPLE distinct flow
	// labels. index 0 of the set folds in the wall-clock rotation epoch and the
	// other three are seed-fixed, so with count=4 we expect 4 distinct labels;
	// tolerate at most one hash collision to stay non-flaky.
	if got := len(distinctLabels); got < int(flowLabelCount)-1 {
		t.Fatalf("observed %d distinct flow labels, want ~%d: round-robin over the "+
			"ECMP label set is not taking effect", got, flowLabelCount)
	}
}
