package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// TestCQPollModes runs the full Prober/Responder pipeline with each CQ poll
// mode forced on both soft-RoCE devices and requires successful 6-timestamp
// probes in every mode. rxe has no hardware timestamps, so the default
// (auto) resolves to busy polling there; forcing "event" is what exercises
// the completion-channel poller (ibv_req_notify_cq + poll()) and its
// eventfd hand-off to the Go consumers in this environment.
func TestCQPollModes(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	cases := []struct {
		name       string
		mode       int
		wantEvents bool
	}{
		{name: "event", mode: rdmabridge.CQPollEvent, wantEvents: true},
		{name: "busy", mode: rdmabridge.CQPollBusy, wantEvents: false},
		// rxe uses software timestamps, for which auto selects busy polling.
		{name: "auto", mode: rdmabridge.CQPollAuto, wantEvents: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runCQPollModeProbe(t, tc.mode, tc.wantEvents)
		})
	}
}

func runCQPollModeProbe(t *testing.T, mode int, wantEvents bool) {
	const (
		probeIntervalMS = uint32(100)
		wantSuccesses   = 5
		resultTimeout   = 20 * time.Second
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

	prober, err := agent.NewProber(proberDev, proberRing, probeIntervalMS)
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	responder, err := agent.NewResponder(responderDev, responderRing)
	if err != nil {
		prober.Destroy()
		t.Fatalf("NewResponder: %v", err)
	}

	proberInfo := prober.GetQueueInfo()
	responderInfo := responder.GetQueueInfo()
	t.Logf("prober queue: QPN=%d usesSWTimestamps=%v usesCQEvents=%v",
		proberInfo.QPN, proberInfo.UsesSWTimestamps, proberInfo.UsesCQEvents)
	t.Logf("responder queue: QPN=%d usesSWTimestamps=%v usesCQEvents=%v",
		responderInfo.QPN, responderInfo.UsesSWTimestamps, responderInfo.UsesCQEvents)
	if proberInfo.UsesCQEvents != wantEvents || responderInfo.UsesCQEvents != wantEvents {
		t.Errorf("UsesCQEvents = (prober %v, responder %v), want %v",
			proberInfo.UsesCQEvents, responderInfo.UsesCQEvents, wantEvents)
	}

	mockClient := &mockControllerClient{
		targets: []*controller_agent.PingTarget{
			{
				TargetGid:        responderDev.Info.GID,
				TargetQpn:        responderInfo.QPN,
				TargetIp:         responderDev.Info.IPAddr,
				TargetHostname:   "e2e-cq-mode-responder",
				TargetTorId:      "tor-cq-mode-target",
				TargetDeviceName: responderDev.Info.DeviceName,
			},
		},
	}
	monitor := agent.NewClusterMonitor(mockClient, prober, "e2e-cq-mode-agent", "tor-cq-mode-source", proberDev.Info.GID, 3600)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	// Several consecutive successes prove the poller keeps re-arming the CQ
	// and the Go consumers keep waking, not just that a first event arrived.
	successes := 0
	deadline := time.After(resultTimeout)
wait:
	for successes < wantSuccesses {
		select {
		case result, ok := <-prober.Results():
			if !ok {
				break wait
			}
			if result.Success {
				successes++
			} else {
				t.Logf("probe seq=%d failed: %s", result.SequenceNum, result.ErrorMessage)
			}
		case <-deadline:
			break wait
		}
	}

	// Stop must return promptly even though the consumers are parked in
	// their idle waits.
	stopStart := time.Now()
	monitor.Stop()
	prober.Destroy()
	responder.Destroy()
	if d := time.Since(stopStart); d > 5*time.Second {
		t.Errorf("shutdown took %s; idle waits did not wake on Stop", d)
	}

	if successes < wantSuccesses {
		t.Fatalf("got %d successful probes within %s, want %d", successes, resultTimeout, wantSuccesses)
	}
}
