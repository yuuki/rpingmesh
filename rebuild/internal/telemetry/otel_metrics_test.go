package telemetry

import (
	"context"
	"testing"

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
