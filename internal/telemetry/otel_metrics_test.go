package telemetry

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/buildinfo"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// serviceNameOf returns the service.name attribute value from a resource
// built by buildResource, or ("", false) if it is not present.
func serviceNameOf(t *testing.T, serviceName string) (string, bool) {
	t.Helper()

	res, err := buildResource(serviceName)
	if err != nil {
		t.Fatalf("buildResource(%q) returned error: %v", serviceName, err)
	}

	for _, kv := range res.Attributes() {
		if kv.Key == semconv.ServiceNameKey {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// TestBuildResource_DefaultServiceName verifies that NewMetricsCollector's
// zero-option behavior (service.name="rpingmesh-agent") is preserved.
func TestBuildResource_DefaultServiceName(t *testing.T) {
	got, ok := serviceNameOf(t, defaultServiceName)
	if !ok {
		t.Fatal("service.name attribute not found in resource")
	}
	if got != "rpingmesh-agent" {
		t.Errorf("service.name = %q, want rpingmesh-agent", got)
	}
}

func TestBuildResource_UsesBuildVersion(t *testing.T) {
	res, err := buildResource(defaultServiceName)
	if err != nil {
		t.Fatalf("buildResource(%q) returned error: %v", defaultServiceName, err)
	}

	for _, kv := range res.Attributes() {
		if kv.Key == semconv.ServiceVersionKey {
			if got, want := kv.Value.AsString(), buildinfo.Version; got != want {
				t.Fatalf("service.version = %q, want %q", got, want)
			}
			return
		}
	}
	t.Fatal("service.version attribute not found in resource")
}

// TestBuildResource_InstanceID verifies that buildResource sets a non-empty
// service.instance.id attribute, and that it matches os.Hostname() in the
// common case (no fallback triggered). This is the attribute
// prometheusremotewrite derives the Prometheus `instance` label from; a
// missing or empty value here means every agent process reporting the same
// metric name+ToR-pair attributes collides onto one series (see
// buildResource's doc comment).
func TestBuildResource_InstanceID(t *testing.T) {
	res, err := buildResource(defaultServiceName)
	if err != nil {
		t.Fatalf("buildResource(%q) returned error: %v", defaultServiceName, err)
	}

	var got string
	var ok bool
	for _, kv := range res.Attributes() {
		if kv.Key == semconv.ServiceInstanceIDKey {
			got, ok = kv.Value.AsString(), true
			break
		}
	}
	if !ok {
		t.Fatal("service.instance.id attribute not found in resource")
	}
	if got == "" {
		t.Error("service.instance.id is empty, want a non-empty host identifier")
	}

	wantHost, hostErr := os.Hostname()
	if hostErr == nil && got != wantHost {
		t.Errorf("service.instance.id = %q, want os.Hostname() = %q", got, wantHost)
	}
}

// TestInstanceID_NonEmpty verifies instanceID() never returns an empty
// string: an empty service.instance.id would be exactly the bug this
// attribute exists to prevent (per-agent series collision).
func TestInstanceID_NonEmpty(t *testing.T) {
	if got := instanceID(); got == "" {
		t.Error("instanceID() returned an empty string, want a non-empty host identifier")
	}
}

// TestWithServiceName_Overrides verifies that the WithServiceName option
// value flows through to the OTel resource's service.name attribute.
func TestWithServiceName_Overrides(t *testing.T) {
	options := collectorOptions{serviceName: defaultServiceName}
	WithServiceName("rpingmesh-controller")(&options)

	if options.serviceName != "rpingmesh-controller" {
		t.Fatalf("collectorOptions.serviceName = %q, want rpingmesh-controller", options.serviceName)
	}

	got, ok := serviceNameOf(t, options.serviceName)
	if !ok {
		t.Fatal("service.name attribute not found in resource")
	}
	if got != "rpingmesh-controller" {
		t.Errorf("service.name = %q, want rpingmesh-controller", got)
	}
}

// failedCounterReason returns the "reason" attribute value of the sole
// probe_failed_total data point recorded by reader, failing the test if the
// metric or data point is missing.
func failedCounterReason(t *testing.T, reader *sdkmetric.ManualReader) string {
	t.Helper()
	got := otelmetrics.TotalByAttr(t, otelmetrics.Collect(t, reader), "rpingmesh.probe_failed_total", "reason")
	if len(got) != 1 {
		t.Fatalf("rpingmesh.probe_failed_total by reason = %v, want exactly one data point", got)
	}
	for reason := range got {
		return reason
	}
	return ""
}

// TestRecordProbeResult_FailureReason verifies that RecordProbeResult
// classifies each non-successful probe outcome into the correct fixed
// "reason" attribute bucket (see probeFailureReason), so timeout and
// send-error regressions stay distinguishable from benign SW-timestamp RTT
// noise (invalid_rtt) in the exported metric.
func TestRecordProbeResult_FailureReason(t *testing.T) {
	cases := []struct {
		name       string
		result     *probe.ProbeResult
		rtt        *probe.RTTResult
		wantReason string
	}{
		{
			name:       "timeout",
			result:     &probe.ProbeResult{Success: false, ErrorMessage: "timed out waiting for ACKs"},
			rtt:        nil,
			wantReason: reasonTimeout,
		},
		{
			name:       "send_error",
			result:     &probe.ProbeResult{Success: false, ErrorMessage: "probe send failed: some error"},
			rtt:        nil,
			wantReason: reasonSendError,
		},
		{
			name:       "invalid_rtt",
			result:     &probe.ProbeResult{Success: true},
			rtt:        &probe.RTTResult{Valid: false, ValidationError: "negative NetworkRTT (-100 ns) indicates clock skew"},
			wantReason: reasonInvalidRTT,
		},
		{
			name:       "unknown",
			result:     &probe.ProbeResult{Success: false, ErrorMessage: "some other unclassified error"},
			rtt:        nil,
			wantReason: reasonUnknown,
		},
		// The typed classification wins over the error message wording.
		{
			name:       "typed timeout",
			result:     &probe.ProbeResult{Success: false, FailureReason: probe.FailureTimeout, ErrorMessage: "no ACKs"},
			rtt:        nil,
			wantReason: reasonTimeout,
		},
		{
			name:       "typed send_error",
			result:     &probe.ProbeResult{Success: false, FailureReason: probe.FailureSendError, ErrorMessage: "ibv_post_send: EIO"},
			rtt:        nil,
			wantReason: reasonSendError,
		},
		{
			name:       "typed unknown",
			result:     &probe.ProbeResult{Success: false, FailureReason: "something_new", ErrorMessage: "timed out"},
			rtt:        nil,
			wantReason: reasonUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, reader := newTestCollector(t)

			mc.RecordProbeResult(tc.result, tc.rtt, "tor-source")

			if got := failedCounterReason(t, reader); got != tc.wantReason {
				t.Errorf("reason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}

// TestRecordProbeResult_Success verifies that a successful probe with a
// valid RTT increments probe_total and probe_success_total (but not
// probe_failed_total) and records the three RTT histograms with the exact
// nanosecond values supplied.
func TestRecordProbeResult_Success(t *testing.T) {
	mc, reader := newTestCollector(t)

	result := &probe.ProbeResult{
		TargetTorID: "tor-target",
		Success:     true,
	}
	rtt := &probe.RTTResult{
		NetworkRTT:     1200,
		ProberDelay:    300,
		ResponderDelay: 150,
		Valid:          true,
	}
	mc.RecordProbeResult(result, rtt, "tor-source")

	rm := otelmetrics.Collect(t, reader)

	if m := otelmetrics.Find(rm, "rpingmesh.probe_failed_total"); m != nil {
		t.Errorf("rpingmesh.probe_failed_total: expected no data points recorded on success, got %+v", m.Data)
	}

	sumMetric := otelmetrics.Find(rm, "rpingmesh.probe_success_total")
	if sumMetric == nil {
		t.Fatal("rpingmesh.probe_success_total metric not found")
	}
	sum, ok := sumMetric.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("rpingmesh.probe_success_total = %+v, want a single data point with value 1", sumMetric.Data)
	}

	totalMetric := otelmetrics.Find(rm, "rpingmesh.probe_total")
	if totalMetric == nil {
		t.Fatal("rpingmesh.probe_total metric not found")
	}
	totalSum, ok := totalMetric.Data.(metricdata.Sum[int64])
	if !ok || len(totalSum.DataPoints) != 1 || totalSum.DataPoints[0].Value != 1 {
		t.Fatalf("rpingmesh.probe_total = %+v, want a single data point with value 1", totalMetric.Data)
	}

	histCases := []struct {
		name string
		want int64
	}{
		{"rpingmesh.network_rtt_ns", rtt.NetworkRTT},
		{"rpingmesh.prober_delay_ns", rtt.ProberDelay},
		{"rpingmesh.responder_delay_ns", rtt.ResponderDelay},
	}
	for _, hc := range histCases {
		hm := otelmetrics.Find(rm, hc.name)
		if hm == nil {
			t.Fatalf("%s metric not found", hc.name)
		}
		hist, ok := hm.Data.(metricdata.Histogram[int64])
		if !ok || len(hist.DataPoints) != 1 {
			t.Fatalf("%s = %+v, want a single histogram data point", hc.name, hm.Data)
		}
		if got := hist.DataPoints[0].Sum; got != hc.want {
			t.Errorf("%s sum = %d, want %d", hc.name, got, hc.want)
		}
	}
}

func TestRecordProbeResult_EmptyTorMapped(t *testing.T) {
	mc, reader := newTestCollector(t)

	mc.RecordProbeResult(&probe.ProbeResult{TargetTorID: "  ", Success: false, ErrorMessage: "timed out waiting for ACKs"}, nil, "")

	rm := otelmetrics.Collect(t, reader)
	totalMetric := otelmetrics.Find(rm, "rpingmesh.probe_total")
	if totalMetric == nil {
		t.Fatal("rpingmesh.probe_total metric not found")
	}
	totalSum, ok := totalMetric.Data.(metricdata.Sum[int64])
	if !ok || len(totalSum.DataPoints) != 1 {
		t.Fatalf("rpingmesh.probe_total = %+v, want a single data point", totalMetric.Data)
	}
	src, ok := totalSum.DataPoints[0].Attributes.Value("source_tor")
	if !ok || src.AsString() != probe.UnspecifiedTorLabel {
		t.Errorf("source_tor = %q, want %s", src.AsString(), probe.UnspecifiedTorLabel)
	}
	tgt, ok := totalSum.DataPoints[0].Attributes.Value("target_tor")
	if !ok || tgt.AsString() != probe.UnspecifiedTorLabel {
		t.Errorf("target_tor = %q, want %s", tgt.AsString(), probe.UnspecifiedTorLabel)
	}
}

// TestRecordProbeResult_SourceRnicAttributes verifies that every probe metric
// carries the source_rdma_device / source_netdev attributes from the result,
// that an empty name maps to the "unspecified" label, and that results from
// two local RNICs on the same ToR pair stay in separate series.
func TestRecordProbeResult_SourceRnicAttributes(t *testing.T) {
	mc, reader := newTestCollector(t)

	ok := &probe.ProbeResult{
		TargetTorID: "leaf-b", Success: true,
		T1: 100, T2: 200, T3: 1000, T4: 1100, T5: 1500, T6: 1700,
		SourceRdmaDevice: "mlx5_0", SourceNetdev: "ens1f0",
	}
	mc.RecordProbeResult(ok, probe.CalculateRTT(ok), "leaf-a")
	mc.RecordProbeResult(&probe.ProbeResult{
		TargetTorID: "leaf-b", ErrorMessage: "timed out waiting for ACKs",
		SourceRdmaDevice: "mlx5_1",
	}, nil, "leaf-a")

	rm := otelmetrics.Collect(t, reader)

	type rnic struct{ device, netdev string }
	attrsOf := func(set attribute.Set) rnic {
		dev, okDev := set.Value("source_rdma_device")
		nd, okNd := set.Value("source_netdev")
		if !okDev || !okNd {
			t.Fatalf("missing source RNIC attributes in %v", set.ToSlice())
		}
		return rnic{dev.AsString(), nd.AsString()}
	}
	want0 := rnic{"mlx5_0", "ens1f0"}
	want1 := rnic{"mlx5_1", probe.UnspecifiedTorLabel}

	// probe_total: one series per source RNIC.
	total := otelmetrics.Find(rm, "rpingmesh.probe_total")
	if total == nil {
		t.Fatal("rpingmesh.probe_total metric not found")
	}
	totalSum := total.Data.(metricdata.Sum[int64])
	got := map[rnic]int64{}
	for _, dp := range totalSum.DataPoints {
		got[attrsOf(dp.Attributes)] += dp.Value
	}
	if len(got) != 2 || got[want0] != 1 || got[want1] != 1 {
		t.Errorf("probe_total series = %v, want one each for %v and %v", got, want0, want1)
	}

	for _, name := range []string{"rpingmesh.probe_success_total", "rpingmesh.probe_failed_total"} {
		m := otelmetrics.Find(rm, name)
		if m == nil {
			t.Fatalf("%s metric not found", name)
		}
		sum := m.Data.(metricdata.Sum[int64])
		if len(sum.DataPoints) != 1 {
			t.Fatalf("%s = %+v, want a single data point", name, sum)
		}
		want := want0
		if name == "rpingmesh.probe_failed_total" {
			want = want1
		}
		if g := attrsOf(sum.DataPoints[0].Attributes); g != want {
			t.Errorf("%s source RNIC = %v, want %v", name, g, want)
		}
	}
	for _, name := range []string{"rpingmesh.network_rtt_ns", "rpingmesh.prober_delay_ns", "rpingmesh.responder_delay_ns"} {
		m := otelmetrics.Find(rm, name)
		if m == nil {
			t.Fatalf("%s metric not found", name)
		}
		hist := m.Data.(metricdata.Histogram[int64])
		if len(hist.DataPoints) != 1 {
			t.Fatalf("%s = %+v, want a single data point", name, hist)
		}
		if g := attrsOf(hist.DataPoints[0].Attributes); g != want0 {
			t.Errorf("%s source RNIC = %v, want %v", name, g, want0)
		}
	}
}

// TestRecordProbeResult_NilResult verifies that RecordProbeResult is a no-op
// when passed a nil ProbeResult (defensive guard against a caller mistake),
// so no metrics are recorded and no panic occurs.
func TestRecordProbeResult_NilResult(t *testing.T) {
	mc, reader := newTestCollector(t)

	mc.RecordProbeResult(nil, nil, "tor-source")

	rm := otelmetrics.Collect(t, reader)
	if m := otelmetrics.Find(rm, "rpingmesh.probe_total"); m != nil {
		if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) > 0 {
			t.Errorf("rpingmesh.probe_total: expected no data points for nil result, got %+v", sum)
		}
	}
}

// TestRegisterEventRingDropCallback verifies that the observable counter
// reports one data point per ring label supplied via the readers map, each
// tagged with the corresponding "ring" attribute and current drop count.
func TestRegisterEventRingDropCallback(t *testing.T) {
	mc, reader := newTestCollector(t)

	dropCounts := map[string]uint64{"prober": 3, "responder": 7}
	readers := map[string]func() uint64{
		"prober":    func() uint64 { return dropCounts["prober"] },
		"responder": func() uint64 { return dropCounts["responder"] },
	}
	if err := mc.RegisterEventRingDropCallback(readers); err != nil {
		t.Fatalf("RegisterEventRingDropCallback: %v", err)
	}

	rm := otelmetrics.Collect(t, reader)

	m := otelmetrics.Find(rm, "rpingmesh.event_ring_dropped_total")
	if m == nil {
		t.Fatal("rpingmesh.event_ring_dropped_total metric not found")
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 2 {
		t.Fatalf("rpingmesh.event_ring_dropped_total = %+v, want 2 data points", m.Data)
	}

	got := map[string]int64{}
	for _, dp := range sum.DataPoints {
		ring, ok := dp.Attributes.Value("ring")
		if !ok {
			t.Fatalf("data point missing ring attribute: %+v", dp)
		}
		got[ring.AsString()] = dp.Value
	}
	want := map[string]int64{"prober": 3, "responder": 7}
	for label, wantVal := range want {
		if got[label] != wantVal {
			t.Errorf("ring %q dropped count = %d, want %d", label, got[label], wantVal)
		}
	}
}

// TestRegisterSelfThrottleCallback verifies that the self_throttle gauge reports
// the current rate multiplier returned by the registered reader, as a single
// attribute-free data point.
func TestRegisterSelfThrottleCallback(t *testing.T) {
	mc, reader := newTestCollector(t)

	multiplier := 0.25
	if err := mc.RegisterSelfThrottleCallback(func() float64 { return multiplier }); err != nil {
		t.Fatalf("RegisterSelfThrottleCallback: %v", err)
	}

	rm := otelmetrics.Collect(t, reader)

	m := otelmetrics.Find(rm, "rpingmesh.agent.self_throttle")
	if m == nil {
		t.Fatal("rpingmesh.agent.self_throttle metric not found")
	}
	gauge, ok := m.Data.(metricdata.Gauge[float64])
	if !ok || len(gauge.DataPoints) != 1 {
		t.Fatalf("rpingmesh.agent.self_throttle = %+v, want 1 gauge data point", m.Data)
	}
	if got := gauge.DataPoints[0].Value; got != multiplier {
		t.Errorf("self_throttle = %g, want %g", got, multiplier)
	}
	if n := gauge.DataPoints[0].Attributes.Len(); n != 0 {
		t.Errorf("self_throttle carries %d attributes, want 0 (low cardinality)", n)
	}
}

// TestStartResultConsumer verifies that StartResultConsumer reads
// ProbeResults from the channel, computes RTT via probe.CalculateRTT, and
// records them, and that it exits cleanly when the channel is closed.
func TestStartResultConsumer(t *testing.T) {
	mc, reader := newTestCollector(t)

	resultChan := make(chan *probe.ProbeResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mc.StartResultConsumer(ctx, resultChan, "tor-source")

	resultChan <- &probe.ProbeResult{
		TargetTorID: "tor-target",
		Success:     true,
		T1:          1_000_000,
		T2:          1_000_100,
		T3:          1_000_200,
		T4:          1_000_300,
		T5:          1_000_400,
		T6:          1_000_600,
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		rm := otelmetrics.Collect(t, reader)
		if m := otelmetrics.Find(rm, "rpingmesh.probe_total"); m != nil {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) == 1 && sum.DataPoints[0].Value == 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for StartResultConsumer to record a metric")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Closing the channel must make the consumer goroutine return instead of
	// spinning forever; there is no direct way to observe goroutine exit
	// short of a race/leak detector, so this only guards against a panic on
	// close (e.g. a subsequent send).
	close(resultChan)
}

// TestStartResultConsumer_PerResultSourceTor verifies that a result's own
// SourceTorID (stamped by the prober from its device's ToR) is used as the
// source_tor attribute instead of the consumer default.
func TestStartResultConsumer_PerResultSourceTor(t *testing.T) {
	mc, reader := newTestCollector(t)

	resultChan := make(chan *probe.ProbeResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mc.StartResultConsumer(ctx, resultChan, "host-tor")

	resultChan <- &probe.ProbeResult{
		TargetTorID:  "tor-target",
		SourceTorID:  "leaf-a",
		Success:      false,
		ErrorMessage: "timed out waiting for ACKs",
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		rm := otelmetrics.Collect(t, reader)
		if m := otelmetrics.Find(rm, "rpingmesh.probe_total"); m != nil {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) == 1 {
				src, _ := sum.DataPoints[0].Attributes.Value("source_tor")
				if got := src.AsString(); got != "leaf-a" {
					t.Fatalf("source_tor = %q, want leaf-a", got)
				}
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for StartResultConsumer to record a metric")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(resultChan)
}

// TestNewMetricsCollector_Construct verifies that NewMetricsCollector builds
// a working collector without needing an actual OTLP collector: the
// underlying gRPC client connects lazily, so no network I/O occurs until a
// flush is attempted. It also exercises WithServiceName and the Shutdown
// error path with an already-cancelled context, which fails fast without
// attempting a real export.
func TestNewMetricsCollector_Construct(t *testing.T) {
	mc, err := NewMetricsCollector(context.Background(), "127.0.0.1:1", WithServiceName("rpingmesh-test"))
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := mc.Shutdown(ctx); err == nil {
		t.Error("Shutdown with a pre-cancelled context: want error, got nil")
	}
}

// TestBuildResource_HostName verifies that buildResource sets host.name to
// os.Hostname(). Collector pipelines that strip service.instance.id still
// need a per-host identity to keep agents on distinct series.
func TestBuildResource_HostName(t *testing.T) {
	wantHost, hostErr := os.Hostname()
	if hostErr != nil || wantHost == "" {
		t.Skip("os.Hostname unavailable; host.name is intentionally omitted")
	}

	res, err := buildResource(defaultServiceName)
	if err != nil {
		t.Fatalf("buildResource(%q) returned error: %v", defaultServiceName, err)
	}

	for _, kv := range res.Attributes() {
		if kv.Key == semconv.HostNameKey {
			if got := kv.Value.AsString(); got != wantHost {
				t.Errorf("host.name = %q, want os.Hostname() = %q", got, wantHost)
			}
			return
		}
	}
	t.Fatal("host.name attribute not found in resource")
}

// TestBucketBoundaries_StrictlyIncreasing verifies that every histogram
// ladder is strictly increasing, as OTel requires.
func TestBucketBoundaries_StrictlyIncreasing(t *testing.T) {
	ladders := map[string][]float64{
		"networkRTTBucketBoundaries": networkRTTBucketBoundaries,
		"delayBucketBoundaries":      delayBucketBoundaries,
	}
	for name, ladder := range ladders {
		for i := 1; i < len(ladder); i++ {
			if ladder[i] <= ladder[i-1] {
				t.Fatalf("%s not strictly increasing at %d: %v <= %v", name, i, ladder[i], ladder[i-1])
			}
		}
	}
}

// TestNetworkRTTBucketBoundaries_ContainsDefaultSLA verifies that the default
// analyzer SLA threshold (config.DefaultAnalyzerSLANetworkRTTP99Ns) is an RTT
// bucket boundary, so dashboards can read the share of probes above it off
// one bucket, and that the RTT ladder still reaches 10ms for congestion.
func TestNetworkRTTBucketBoundaries_ContainsDefaultSLA(t *testing.T) {
	if !IsNetworkRTTBucketBoundary(config.DefaultAnalyzerSLANetworkRTTP99Ns) {
		t.Errorf("default analyzer SLA %dns is not a network RTT bucket boundary",
			uint64(config.DefaultAnalyzerSLANetworkRTTP99Ns))
	}
	if IsNetworkRTTBucketBoundary(config.DefaultAnalyzerSLANetworkRTTP99Ns + 1) {
		t.Error("IsNetworkRTTBucketBoundary accepted a non-boundary value")
	}
	if last := networkRTTBucketBoundaries[len(networkRTTBucketBoundaries)-1]; last < 10_000_000 {
		t.Errorf("last network RTT boundary = %vns, want >= 10ms", last)
	}
}

// TestRecordProbeResult_HistogramBoundaries verifies that the RTT histogram
// and the two delay histograms export their own bucket ladders.
func TestRecordProbeResult_HistogramBoundaries(t *testing.T) {
	mc, reader := newTestCollector(t)
	mc.RecordProbeResult(&probe.ProbeResult{TargetTorID: "tor-b", Success: true},
		&probe.RTTResult{NetworkRTT: 5_000, ProberDelay: 80_000, ResponderDelay: 60_000, Valid: true}, "tor-a")

	rm := otelmetrics.Collect(t, reader)
	cases := map[string][]float64{
		"rpingmesh.network_rtt_ns":     networkRTTBucketBoundaries,
		"rpingmesh.prober_delay_ns":    delayBucketBoundaries,
		"rpingmesh.responder_delay_ns": delayBucketBoundaries,
	}
	for name, want := range cases {
		m := otelmetrics.Find(rm, name)
		if m == nil {
			t.Fatalf("%s metric not found", name)
		}
		dp := m.Data.(metricdata.Histogram[int64]).DataPoints[0]
		if !slices.Equal(dp.Bounds, want) {
			t.Errorf("%s bounds = %v, want %v", name, dp.Bounds, want)
		}
	}
}

// TestRecordProbeResult_DelayTargetTor verifies that, by default,
// rpingmesh.prober_delay_ns drops target_tor while
// rpingmesh.responder_delay_ns keeps it, that each option flips only its own
// histogram, and that network RTT and the counters always keep target_tor.
func TestRecordProbeResult_DelayTargetTor(t *testing.T) {
	cases := []struct {
		name                 string
		opts                 []Option
		proberKeep, respKeep bool
	}{
		{"default", nil, false, true},
		{"prober_on", []Option{WithProberDelayTargetTor(true)}, true, true},
		{"responder_off", []Option{WithResponderDelayTargetTor(false)}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, reader := newTestCollector(t, tc.opts...)
			rtt := &probe.RTTResult{NetworkRTT: 5_000, ProberDelay: 80_000, ResponderDelay: 60_000, Valid: true}
			for _, tor := range []string{"tor-b", "tor-c"} {
				mc.RecordProbeResult(&probe.ProbeResult{TargetTorID: tor, Success: true,
					SourceRdmaDevice: "mlx5_0", SourceNetdev: "eth0"}, rtt, "tor-a")
			}

			rm := otelmetrics.Collect(t, reader)
			for name, keep := range map[string]bool{
				"rpingmesh.prober_delay_ns":    tc.proberKeep,
				"rpingmesh.responder_delay_ns": tc.respKeep,
			} {
				dps := otelmetrics.Find(rm, name).Data.(metricdata.Histogram[int64]).DataPoints
				wantPoints := 1
				if keep {
					wantPoints = 2
				}
				if len(dps) != wantPoints {
					t.Fatalf("%s has %d data points, want %d", name, len(dps), wantPoints)
				}
				for _, dp := range dps {
					if _, ok := dp.Attributes.Value("target_tor"); ok != keep {
						t.Errorf("%s target_tor present = %v, want %v", name, ok, keep)
					}
					for _, k := range []attribute.Key{"source_tor", "source_rdma_device", "source_netdev"} {
						if _, ok := dp.Attributes.Value(k); !ok {
							t.Errorf("%s missing %s", name, k)
						}
					}
				}
				if !keep && dps[0].Count != 2 {
					t.Errorf("%s count = %d, want 2 (both targets in one series)", name, dps[0].Count)
				}
			}
			if dps := otelmetrics.Find(rm, "rpingmesh.network_rtt_ns").Data.(metricdata.Histogram[int64]).DataPoints; len(dps) != 2 {
				t.Errorf("rpingmesh.network_rtt_ns has %d data points, want 2 (one per target_tor)", len(dps))
			}
			if dps := otelmetrics.Find(rm, "rpingmesh.probe_total").Data.(metricdata.Sum[int64]).DataPoints; len(dps) != 2 {
				t.Errorf("rpingmesh.probe_total has %d data points, want 2 (one per target_tor)", len(dps))
			}
		})
	}
}

// TestNetworkRTTBucketBoundaries_TailSteps verifies that the RTT ladder keeps
// intermediate boundaries between 1ms and 10ms, so histogram_quantile does
// not report a congested 1.1ms distribution as ~5.5ms.
func TestNetworkRTTBucketBoundaries_TailSteps(t *testing.T) {
	for _, ns := range []uint64{1_000_000, 2_500_000, 5_000_000, 10_000_000} {
		if !IsNetworkRTTBucketBoundary(ns) {
			t.Errorf("%dns is not a network RTT bucket boundary", ns)
		}
	}
}
