package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
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
// probe_failed_total data point recorded by mc, failing the test if the
// metric or data point is missing.
func failedCounterReason(t *testing.T, mc *MetricsCollector, reader *sdkmetric.ManualReader) string {
	t.Helper()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "rpingmesh.probe_failed_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) == 0 {
				t.Fatalf("rpingmesh.probe_failed_total: no data points")
			}
			reason, ok := sum.DataPoints[0].Attributes.Value("reason")
			if !ok {
				t.Fatalf("rpingmesh.probe_failed_total: missing reason attribute")
			}
			return reason.AsString()
		}
	}
	t.Fatalf("rpingmesh.probe_failed_total metric not found")
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			defer provider.Shutdown(context.Background())

			mc, err := NewMetricsCollectorWithProvider(provider)
			if err != nil {
				t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
			}

			mc.RecordProbeResult(tc.result, tc.rtt, "tor-source")

			if got := failedCounterReason(t, mc, reader); got != tc.wantReason {
				t.Errorf("reason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}

// findMetric returns the named metric from a collected ResourceMetrics, or
// nil if not present.
func findMetric(rm *metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i, m := range sm.Metrics {
			if m.Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

// TestRecordProbeResult_Success verifies that a successful probe with a
// valid RTT increments probe_total and probe_success_total (but not
// probe_failed_total) and records the three RTT histograms with the exact
// nanosecond values supplied.
func TestRecordProbeResult_Success(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}

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

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}

	if m := findMetric(&rm, "rpingmesh.probe_failed_total"); m != nil {
		t.Errorf("rpingmesh.probe_failed_total: expected no data points recorded on success, got %+v", m.Data)
	}

	sumMetric := findMetric(&rm, "rpingmesh.probe_success_total")
	if sumMetric == nil {
		t.Fatal("rpingmesh.probe_success_total metric not found")
	}
	sum, ok := sumMetric.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("rpingmesh.probe_success_total = %+v, want a single data point with value 1", sumMetric.Data)
	}

	totalMetric := findMetric(&rm, "rpingmesh.probe_total")
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
		hm := findMetric(&rm, hc.name)
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

// TestRecordProbeResult_NilResult verifies that RecordProbeResult is a no-op
// when passed a nil ProbeResult (defensive guard against a caller mistake),
// so no metrics are recorded and no panic occurs.
func TestRecordProbeResult_NilResult(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}

	mc.RecordProbeResult(nil, nil, "tor-source")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	if m := findMetric(&rm, "rpingmesh.probe_total"); m != nil {
		if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) > 0 {
			t.Errorf("rpingmesh.probe_total: expected no data points for nil result, got %+v", sum)
		}
	}
}

// TestRegisterEventRingDropCallback verifies that the observable counter
// reports one data point per ring label supplied via the readers map, each
// tagged with the corresponding "ring" attribute and current drop count.
func TestRegisterEventRingDropCallback(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}

	dropCounts := map[string]uint64{"prober": 3, "responder": 7}
	readers := map[string]func() uint64{
		"prober":    func() uint64 { return dropCounts["prober"] },
		"responder": func() uint64 { return dropCounts["responder"] },
	}
	if err := mc.RegisterEventRingDropCallback(readers); err != nil {
		t.Fatalf("RegisterEventRingDropCallback: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}

	m := findMetric(&rm, "rpingmesh.event_ring_dropped_total")
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

// TestStartResultConsumer verifies that StartResultConsumer reads
// ProbeResults from the channel, computes RTT via probe.CalculateRTT, and
// records them, and that it exits cleanly when the channel is closed.
func TestStartResultConsumer(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}

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
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("ManualReader.Collect: %v", err)
		}
		if m := findMetric(&rm, "rpingmesh.probe_total"); m != nil {
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
