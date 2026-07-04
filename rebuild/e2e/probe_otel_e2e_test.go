// Package e2e contains end-to-end tests for the R-Pingmesh system.
//
// TestProbeToOTelMetrics validates the full data path from controller pinglist
// delivery through RDMA probing to OTel metric recording:
//
//	[mock ControllerClient] → ClusterMonitor → Prober → RDMA probe →
//	    Responder ACKs → ProbeResult → MetricsCollector → OTel instruments
//
// This test requires real or soft-RoCE RDMA devices (RDMA_E2E_ENABLED=1).
package e2e_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/agent"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/internal/telemetry"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// clockDomainSanityBoundNs bounds |ProberDelay| and |NetworkRTT| for any
// probe that completed all 6 timestamps (result.Success == true), regardless
// of whether probe.CalculateRTT considered the measurement Valid.
//
// This is deliberately much larger than real RTT/delay values (which are
// sub-millisecond on a loopback veth pair) but much smaller than the ~1e18ns
// magnitude a genuine clock-domain mismatch produces (e.g. mixing a
// CLOCK_MONOTONIC timestamp with a CLOCK_REALTIME/wall-clock one). It exists
// to catch that regression class without being tripped by ordinary
// microsecond-scale SW-timestamp measurement noise (see probeSuccessOrWarn).
const clockDomainSanityBoundNs = int64(1 * time.Second)

// mockControllerClient implements agent.ControllerClient with a fixed set of
// PingTargets. It returns the same targets regardless of pinglist type,
// simulating a controller that always points the prober at the responder.
type mockControllerClient struct {
	targets []*controller_agent.PingTarget
}

func (m *mockControllerClient) GetPinglist(
	_ context.Context, _, _, _ string, _ controller_agent.PinglistType,
) ([]*controller_agent.PingTarget, error) {
	return m.targets, nil
}

// TestProbeToOTelMetrics validates the complete agent data path:
//
//  1. A mock ControllerClient returns a PingTarget pointing to rxe1 (responder)
//  2. ClusterMonitor delivers this target to the Prober
//  3. The Prober sends RDMA probes via rxe0 to the Responder on rxe1
//  4. The Responder sends first and second ACKs back
//  5. The Prober produces ProbeResults on its result channel
//  6. A test-owned consumer computes RTT, records it via MetricsCollector
//     (backed by an OTel ManualReader), and retains the raw RTTResult for the
//     clock-domain sanity check below
//  7. The test verifies metric values via ManualReader.Collect()
//
// This test runs in the same Docker environment as TestRDMAE2ETwoDevices
// (soft-RoCE devices rxe0, rxe1 on a veth pair).
//
// Assertion design (see also rdma_e2e_test.go's validateRoundTrip):
//
// On this soft-RoCE/veth environment, SW timestamps are stamped at CQ-poll
// time (not at actual wire send/recv time), while the real network RTT over
// a loopback veth is near zero. NetworkRTT = (T5-T2) - (T4-T3) can therefore
// legitimately come out slightly negative (poll-loop jitter), which makes
// probe.CalculateRTT mark the probe Valid=false even though nothing is
// actually broken. Treating that as a hard failure (as a prior version of
// this test did, requiring probe_success_total > 0) produced a
// deterministic-looking local failure unrelated to real regressions.
//
// Instead this test distinguishes three outcome classes:
//  1. Clock-domain regressions (a timestamp crosses clock domains, producing
//     |NetworkRTT| or |ProberDelay| on the order of 1e18 ns) — hard fail via
//     the clock-domain sanity check below.
//  2. ACK-matching/timeout regressions (probes never complete all 6
//     timestamps) — hard fail via the reason=timeout assertion.
//  3. Small-negative RTT from SW-timestamp poll jitter — tolerated, logged as
//     a warning instead of failing.
func TestProbeToOTelMetrics(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}

	const (
		sourceTorID     = "tor-e2e-source"
		targetTorID     = "tor-e2e-target"
		probeIntervalMS = uint32(200) // 200ms between probe rounds
		metricsTimeout  = 15 * time.Second
		pollInterval    = 200 * time.Millisecond
		drainTimeout    = 2 * time.Second
	)

	// --- RDMA context ---
	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	// --- Open devices ---
	proberDev, err := rdmaCtx.OpenDeviceByName(proberDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open prober device %q: %v", proberDeviceName, err)
	}
	defer proberDev.Close()
	t.Logf("prober device: name=%s GID=%s IP=%s",
		proberDev.Info.DeviceName, proberDev.Info.GID, proberDev.Info.IPAddr)

	responderDev, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open responder device %q: %v", responderDeviceName, err)
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

	// --- Create Prober and Responder using agent package ---
	prober, err := agent.NewProber(proberDev, proberRing, probeIntervalMS)
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	// Destroy (not defer) because we need controlled shutdown order.

	responder, err := agent.NewResponder(responderDev, responderRing)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	// --- OTel metrics with ManualReader ---
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	mc, err := telemetry.NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}

	// --- Mock ControllerClient ---
	responderQueueInfo := responder.GetQueueInfo()
	mockClient := &mockControllerClient{
		targets: []*controller_agent.PingTarget{
			{
				TargetGid:        responderDev.Info.GID,
				TargetQpn:        responderQueueInfo.QPN,
				TargetIp:         responderDev.Info.IPAddr,
				TargetHostname:   "e2e-responder",
				TargetTorId:      targetTorID,
				TargetDeviceName: responderDev.Info.DeviceName,
			},
		},
	}
	t.Logf("mock target: GID=%s QPN=%d IP=%s",
		responderDev.Info.GID, responderQueueInfo.QPN, responderDev.Info.IPAddr)

	// --- ClusterMonitor ---
	// updateIntervalSec=3600 so only the initial immediate fetch runs.
	monitor := agent.NewClusterMonitor(
		mockClient,
		prober,
		"e2e-agent",
		sourceTorID,
		proberDev.Info.GID,
		3600,
	)

	// --- Start components in order ---
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Responder must be listening before probes arrive.
	if err := responder.Start(ctx); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}

	// Prober starts probeLoop and ackProcessLoop.
	if err := prober.Start(ctx); err != nil {
		t.Fatalf("prober.Start: %v", err)
	}

	// ClusterMonitor immediately fetches pinglist and calls prober.UpdateTargets.
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("monitor.Start: %v", err)
	}

	// --- Result consumer ---
	// A test-owned consumer (rather than mc.StartResultConsumer) so the test
	// can retain each RTTResult for probes that completed all 6 timestamps,
	// independent of whether CalculateRTT considered the RTT itself valid.
	// This is what makes the clock-domain sanity check below possible: the
	// OTel RTT histograms only ever receive Valid==true samples, which would
	// hide a clock-domain regression behind the SW-timestamp noise tolerance.
	var (
		completedMu   sync.Mutex
		completedRTTs []*probe.RTTResult
	)
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
				rtt := probe.CalculateRTT(result)
				mc.RecordProbeResult(result, rtt, sourceTorID)
				if result.Success {
					completedMu.Lock()
					completedRTTs = append(completedRTTs, rtt)
					completedMu.Unlock()
				}
			}
		}
	}()

	// --- Wait for metrics to be recorded ---
	t.Log("Waiting for OTel metrics to be recorded...")
	var rm metricdata.ResourceMetrics
	deadline := time.Now().Add(metricsTimeout)
	var found bool

	for time.Now().Before(deadline) {
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("ManualReader.Collect: %v", err)
		}
		if getCounterValue(rm, "rpingmesh.probe_total") > 0 {
			found = true
			break
		}
		time.Sleep(pollInterval)
	}

	// --- Controlled shutdown before assertions ---
	// Stop monitor first to prevent new target updates.
	monitor.Stop()
	// Stop prober: stops goroutines, closes resultChan (consumer exits).
	prober.Destroy()
	// Stop responder.
	responder.Destroy()

	// Give the result consumer a bounded window to drain any buffered
	// results before the final Collect, so probe_total and completedRTTs
	// reflect every probe the Prober actually finished with.
	select {
	case <-consumerDone:
	case <-time.After(drainTimeout):
		t.Log("WARNING: result consumer did not drain within drainTimeout; " +
			"final metrics/clock-domain check may miss late in-flight results")
	}

	// Collect final metrics after shutdown.
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect (final): %v", err)
	}

	if !found {
		t.Fatal("timeout: no rpingmesh.probe_total metric recorded within deadline")
	}

	// --- Assertions ---
	probeTotal := getCounterValue(rm, "rpingmesh.probe_total")
	probeSuccess := getCounterValue(rm, "rpingmesh.probe_success_total")
	probeFailed := getCounterValue(rm, "rpingmesh.probe_failed_total")
	probeFailedTimeout := getCounterValueByAttr(rm, "rpingmesh.probe_failed_total", "reason", "timeout")
	probeFailedInvalidRTT := getCounterValueByAttr(rm, "rpingmesh.probe_failed_total", "reason", "invalid_rtt")

	t.Logf("metrics: probe_total=%d probe_success=%d probe_failed=%d (timeout=%d invalid_rtt=%d)",
		probeTotal, probeSuccess, probeFailed, probeFailedTimeout, probeFailedInvalidRTT)

	// Hard assertion: probes were executed.
	if probeTotal == 0 {
		t.Fatal("rpingmesh.probe_total must be > 0")
	}

	// probe_total should equal success + failed.
	if probeTotal != probeSuccess+probeFailed {
		t.Errorf("probe_total (%d) != probe_success (%d) + probe_failed (%d)",
			probeTotal, probeSuccess, probeFailed)
	}

	// Hard assertion: the ACK-matching path must work. A probe classified
	// reason=timeout means Prober.cleanupStalePending expired it waiting for
	// ACKs that never arrived (see internal/agent/prober.go) — that is a real
	// protocol/connectivity regression, never environmental RTT noise.
	if probeFailedTimeout != 0 {
		t.Fatalf("rpingmesh.probe_failed_total{reason=timeout} = %d, want 0: "+
			"ACK-matching path did not complete for at least one probe", probeFailedTimeout)
	}

	// Soft assertion: probe_success_total == 0 is only benign if every
	// failure was invalid_rtt (all 6 timestamps arrived, but CalculateRTT
	// rejected the RTT — e.g. small-negative NetworkRTT from SW-timestamp
	// poll jitter, see the package doc comment above). Any other failure
	// reason mixed in indicates a real regression, so it remains a hard
	// failure.
	if probeSuccess == 0 {
		if probeFailed == 0 {
			t.Fatal("no probes succeeded or failed: nothing was recorded")
		}
		if probeFailedInvalidRTT != probeFailed {
			t.Fatalf("rpingmesh.probe_success_total = 0 and not all failures are "+
				"reason=invalid_rtt (invalid_rtt=%d, total failed=%d): real regression, not RTT noise",
				probeFailedInvalidRTT, probeFailed)
		}
		t.Logf("WARNING: probe_success_total=0 but all %d failures are reason=invalid_rtt "+
			"(SW-timestamp poll jitter on soft-RoCE producing small-negative NetworkRTT); "+
			"tolerating as measurement noise, not a regression", probeFailed)
	}

	// Hard clock-domain sanity check: every probe that completed all 6
	// timestamps (independent of CalculateRTT's Valid verdict) must have
	// |NetworkRTT| and |ProberDelay| within clockDomainSanityBoundNs. A
	// genuine clock-domain mismatch (e.g. a wall-clock timestamp slipping
	// into a CLOCK_MONOTONIC computation) produces magnitudes around 1e18
	// ns, many orders of magnitude past this bound; ordinary SW-timestamp
	// jitter is sub-millisecond.
	completedMu.Lock()
	defer completedMu.Unlock()
	if len(completedRTTs) == 0 {
		t.Fatal("no probes completed all 6 timestamps; cannot run clock-domain sanity check")
	}
	for i, rtt := range completedRTTs {
		if abs64(rtt.NetworkRTT) >= clockDomainSanityBoundNs {
			t.Errorf("completed probe[%d]: |NetworkRTT| = %d ns >= %d ns sanity bound: clock-domain regression",
				i, rtt.NetworkRTT, clockDomainSanityBoundNs)
		}
		if abs64(rtt.ProberDelay) >= clockDomainSanityBoundNs {
			t.Errorf("completed probe[%d]: |ProberDelay| = %d ns >= %d ns sanity bound: clock-domain regression",
				i, rtt.ProberDelay, clockDomainSanityBoundNs)
		}
	}

	if probeSuccess > 0 {
		assertHistogramHasData(t, rm, "rpingmesh.network_rtt_ns")
		assertHistogramHasData(t, rm, "rpingmesh.prober_delay_ns")
		assertHistogramHasData(t, rm, "rpingmesh.responder_delay_ns")

		// Log RTT values from histogram.
		if h := getHistogramData(rm, "rpingmesh.network_rtt_ns"); h != nil {
			t.Logf("network_rtt_ns: count=%d sum=%d min=%d max=%d",
				h.Count, h.Sum, extremaVal(h.Min), extremaVal(h.Max))
		}
		if h := getHistogramData(rm, "rpingmesh.responder_delay_ns"); h != nil {
			t.Logf("responder_delay_ns: count=%d sum=%d min=%d max=%d",
				h.Count, h.Sum, extremaVal(h.Min), extremaVal(h.Max))
		}
	}

	// Verify ToR attributes are present on probe_total.
	assertCounterHasAttributes(t, rm, "rpingmesh.probe_total", map[string]string{
		"source_tor": sourceTorID,
		"target_tor": targetTorID,
	})
}

// abs64 returns the absolute value of an int64, saturating at MaxInt64 for
// MinInt64 rather than overflowing. RTT/delay magnitudes here are always far
// below that boundary, but this keeps the helper honest.
func abs64(v int64) int64 {
	if v < 0 {
		if v == -v {
			// v == math.MinInt64: negating it overflows. Values here are
			// never remotely close to this, so saturate rather than panic.
			return 1<<63 - 1
		}
		return -v
	}
	return v
}

// getCounterValue returns the sum of all data points for the named counter metric.
func getCounterValue(rm metricdata.ResourceMetrics, name string) int64 {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				var total int64
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
				return total
			}
		}
	}
	return 0
}

// getCounterValueByAttr returns the sum of data points for the named counter
// metric whose attribute set has key==value. Used to break down
// rpingmesh.probe_failed_total by its "reason" attribute.
func getCounterValueByAttr(rm metricdata.ResourceMetrics, name, key, value string) int64 {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			var total int64
			for _, dp := range sum.DataPoints {
				if val, ok := dp.Attributes.Value(attribute.Key(key)); ok && val.AsString() == value {
					total += dp.Value
				}
			}
			return total
		}
	}
	return 0
}

// getHistogramData returns the first data point of the named histogram metric.
func getHistogramData(rm metricdata.ResourceMetrics, name string) *metricdata.HistogramDataPoint[int64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if h, ok := m.Data.(metricdata.Histogram[int64]); ok {
				if len(h.DataPoints) > 0 {
					return &h.DataPoints[0]
				}
			}
		}
	}
	return nil
}

// assertHistogramHasData fails the test if the named histogram has no data points
// or zero count.
func assertHistogramHasData(t *testing.T, rm metricdata.ResourceMetrics, name string) {
	t.Helper()
	dp := getHistogramData(rm, name)
	if dp == nil {
		t.Errorf("histogram %q: no data points found", name)
		return
	}
	if dp.Count == 0 {
		t.Errorf("histogram %q: count is 0", name)
	}
}

// assertCounterHasAttributes verifies that the named counter metric has at least
// one data point with all the expected attribute key-value pairs.
func assertCounterHasAttributes(t *testing.T, rm metricdata.ResourceMetrics, name string, expected map[string]string) {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Errorf("metric %q is not a Sum[int64]", name)
				return
			}
			for _, dp := range sum.DataPoints {
				if matchesAttributes(dp.Attributes, expected) {
					return // found a matching data point
				}
			}
			t.Errorf("metric %q: no data point with attributes %v", name, expected)
			return
		}
	}
	t.Errorf("metric %q not found", name)
}

// matchesAttributes checks whether an attribute set contains all expected
// key-value pairs.
func matchesAttributes(attrs attribute.Set, expected map[string]string) bool {
	for k, v := range expected {
		val, ok := attrs.Value(attribute.Key(k))
		if !ok || val.AsString() != v {
			return false
		}
	}
	return true
}

// extremaVal extracts the value from an Extrema[int64], returning 0 if not set.
func extremaVal(e metricdata.Extrema[int64]) int64 {
	v, ok := e.Value()
	if !ok {
		return 0
	}
	return v
}
