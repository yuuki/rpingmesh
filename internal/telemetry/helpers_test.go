package telemetry

import (
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestCollector returns a MetricsCollector configured with opts and backed
// by a ManualReader.
func newTestCollector(t *testing.T, opts ...Option) (*MetricsCollector, *sdkmetric.ManualReader) {
	t.Helper()
	return newTestCollectorOn(t, nil, opts...)
}

// newTestCollectorOn is newTestCollector with extra MeterProvider options
// (e.g. sdkmetric.WithCardinalityLimit).
func newTestCollectorOn(t *testing.T, providerOpts []sdkmetric.Option, opts ...Option) (*MetricsCollector, *sdkmetric.ManualReader) {
	t.Helper()
	provider, reader := otelmetrics.NewManualProvider(t, providerOpts...)
	mc, err := NewMetricsCollectorWithProvider(provider, opts...)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}
	return mc, reader
}

// collectFrom records results (with source ToR "tor-a") on a collector
// configured with opts and built on a provider with providerOpts, and returns
// the collected metrics.
func collectFrom(t *testing.T, providerOpts []sdkmetric.Option, opts []Option, results ...*probe.ProbeResult) *metricdata.ResourceMetrics {
	t.Helper()
	mc, reader := newTestCollectorOn(t, providerOpts, opts...)
	for _, r := range results {
		mc.RecordProbeResult(r, probe.CalculateRTT(r), "tor-a")
	}
	return otelmetrics.Collect(t, reader)
}

// recordAndCollect is collectFrom on a default provider.
func recordAndCollect(t *testing.T, opts []Option, results ...*probe.ProbeResult) *metricdata.ResourceMetrics {
	t.Helper()
	return collectFrom(t, nil, opts, results...)
}
