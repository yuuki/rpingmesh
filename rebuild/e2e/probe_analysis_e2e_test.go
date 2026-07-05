// Package e2e: TestProbeToPathAggregator validates the analyzer's agent-side
// data path on real (soft-RoCE) RDMA devices:
//
//	Prober → RDMA probe → Responder ACKs → ProbeResult (SourceGID stamped)
//	    → PathAggregator window aggregation → PathSummary
//
// It complements TestProbeToOTelMetrics (the metrics branch) by exercising the
// second fan-out branch introduced for Phase 1 analysis. Assertions are shape
// assertions (matching the soft-RoCE tolerance policy): it does not require any
// specific success/loss ratio, only that real results aggregate into a summary
// keyed by the prober's actual source GID and the target's ToR.
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

func TestProbeToPathAggregator(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	const (
		sourceTorID     = "tor-agg-source"
		targetTorID     = "tor-agg-target"
		probeIntervalMS = uint32(200)
		windowNs        = uint64(60 * time.Second) // one window spanning the whole test
		gatherDuration  = 3 * time.Second
		drainTimeout    = 2 * time.Second
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

	responderDev, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open responder device %q: %v", responderDeviceName, err)
	}
	defer responderDev.Close()

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
		t.Fatalf("NewResponder: %v", err)
	}

	responderQueueInfo := responder.GetQueueInfo()
	mockClient := &mockControllerClient{
		targets: []*controller_agent.PingTarget{
			{
				TargetGid:        responderDev.Info.GID,
				TargetQpn:        responderQueueInfo.QPN,
				TargetIp:         responderDev.Info.IPAddr,
				TargetHostname:   "e2e-agg-responder",
				TargetTorId:      targetTorID,
				TargetDeviceName: responderDev.Info.DeviceName,
			},
		},
	}

	monitor := agent.NewClusterMonitor(mockClient, prober, "e2e-agg-agent", sourceTorID, proberDev.Info.GID, 3600)

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

	// Feed real probe results into a PathAggregator (the analysis branch's
	// consumer), exactly as the AnalysisReporter would.
	agg := probe.NewPathAggregator(windowNs)
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-prober.Results():
				if !ok {
					return
				}
				agg.AddResult(result, uint64(time.Now().UnixNano()))
			}
		}
	}()

	// Let the prober run for a few windows' worth of probe rounds so the
	// aggregator accumulates real results.
	time.Sleep(gatherDuration)

	// Controlled shutdown, then drain.
	monitor.Stop()
	prober.Destroy()
	responder.Destroy()
	select {
	case <-consumerDone:
	case <-time.After(drainTimeout):
		t.Log("WARNING: aggregator consumer did not drain within drainTimeout")
	}

	summaries := agg.Flush()
	if len(summaries) == 0 {
		t.Fatal("no path summaries produced from real probe results")
	}

	for _, s := range summaries {
		if s.SourceGID == ([16]byte{}) {
			t.Errorf("summary has zero SourceGID; prober did not stamp the source RNIC GID")
		}
		if s.TargetTorID != targetTorID {
			t.Errorf("summary TargetTorID = %q, want %q", s.TargetTorID, targetTorID)
		}
		if s.ProbeTotal == 0 {
			t.Errorf("summary ProbeTotal = 0, want > 0")
		}
		// total must partition into success + failed + invalid.
		if s.ProbeTotal != s.ProbeSuccess+s.ProbeFailed+s.InvalidRTTCount {
			t.Errorf("summary counts do not partition: total=%d success=%d failed=%d invalid=%d",
				s.ProbeTotal, s.ProbeSuccess, s.ProbeFailed, s.InvalidRTTCount)
		}
		t.Logf("summary: total=%d success=%d failed=%d invalid=%d min=%d max=%d p50=%d p99=%d",
			s.ProbeTotal, s.ProbeSuccess, s.ProbeFailed, s.InvalidRTTCount,
			s.NetworkRTTMinNs, s.NetworkRTTMaxNs, s.NetworkRTTP50Ns, s.NetworkRTTP99Ns)
	}
}
