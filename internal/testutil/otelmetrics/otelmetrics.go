// Package otelmetrics holds test helpers for reading metrics back from an
// OTel SDK ManualReader. internal/telemetry's unit tests and the e2e tests
// both verify exported probe metrics this way; sharing the lookup helpers
// keeps them from asserting on the metricdata types in slightly different
// ways. It must not import internal/telemetry: telemetry's in-package tests
// import it.
package otelmetrics

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// NewManualProvider returns a MeterProvider that exports only through the
// returned ManualReader, so a test reads metrics back in memory with Collect.
// opts are applied after the reader (e.g. sdkmetric.WithCardinalityLimit).
// The provider is shut down when the test ends.
func NewManualProvider(t testing.TB, opts ...sdkmetric.Option) (*sdkmetric.MeterProvider, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(append([]sdkmetric.Option{sdkmetric.WithReader(reader)}, opts...)...)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return provider, reader
}

// Collect gathers the current metrics of reader.
func Collect(t testing.TB, reader *sdkmetric.ManualReader) *metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	return &rm
}

// Find returns the named metric from rm, or nil when it was not exported.
func Find(rm *metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i, m := range sm.Metrics {
			if m.Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

// SumPoints returns the data points of the int64 counter name, or nil when it
// was not exported. It fails the test if name is not a Sum[int64].
func SumPoints(t testing.TB, rm *metricdata.ResourceMetrics, name string) []metricdata.DataPoint[int64] {
	t.Helper()
	m := Find(rm, name)
	if m == nil {
		return nil
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%s is %T, want Sum[int64]", name, m.Data)
	}
	return sum.DataPoints
}

// HistogramPoints returns the data points of the int64 histogram name, or nil
// when it was not exported. It fails the test if name is not a
// Histogram[int64].
func HistogramPoints(t testing.TB, rm *metricdata.ResourceMetrics, name string) []metricdata.HistogramDataPoint[int64] {
	t.Helper()
	m := Find(rm, name)
	if m == nil {
		return nil
	}
	h, ok := m.Data.(metricdata.Histogram[int64])
	if !ok {
		t.Fatalf("%s is %T, want Histogram[int64]", name, m.Data)
	}
	return h.DataPoints
}

// Total sums every data point of the int64 counter name (0 when absent).
func Total(t testing.TB, rm *metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	var total int64
	for _, dp := range SumPoints(t, rm, name) {
		total += dp.Value
	}
	return total
}

// TotalByAttr sums the data points of the int64 counter name by the value of
// attribute attr, failing the test if a data point lacks it. It returns nil
// when the metric was not exported.
func TotalByAttr(t testing.TB, rm *metricdata.ResourceMetrics, name, attr string) map[string]int64 {
	t.Helper()
	points := SumPoints(t, rm, name)
	if points == nil {
		return nil
	}
	got := map[string]int64{}
	for _, dp := range points {
		v, ok := dp.Attributes.Value(attribute.Key(attr))
		if !ok {
			t.Fatalf("%s data point missing %s attribute: %+v", name, attr, dp)
		}
		got[v.AsString()] += dp.Value
	}
	return got
}

// DataPointAttrs returns the attribute set of every data point of the int64
// counter or histogram name, or nil when it was not exported.
func DataPointAttrs(t testing.TB, rm *metricdata.ResourceMetrics, name string) []attribute.Set {
	t.Helper()
	m := Find(rm, name)
	if m == nil {
		return nil
	}
	var sets []attribute.Set
	switch data := m.Data.(type) {
	case metricdata.Sum[int64]:
		for _, dp := range data.DataPoints {
			sets = append(sets, dp.Attributes)
		}
	case metricdata.Histogram[int64]:
		for _, dp := range data.DataPoints {
			sets = append(sets, dp.Attributes)
		}
	default:
		t.Fatalf("%s: unexpected data type %T", name, m.Data)
	}
	return sets
}

// HasAttributes reports whether set carries every key/value pair of want.
func HasAttributes(set attribute.Set, want map[string]string) bool {
	for k, v := range want {
		val, ok := set.Value(attribute.Key(k))
		if !ok || val.AsString() != v {
			return false
		}
	}
	return true
}
