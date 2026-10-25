package analyzer

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestMetrics returns Metrics backed by a ManualReader so tests can collect
// and inspect the recorded data points.
func newTestMetrics(t *testing.T) (*Metrics, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	m, err := NewMetrics(provider.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	return m, reader
}

// collectSum collects from reader and returns the Int64 sum data of the named
// instrument.
func collectSum(t *testing.T, reader *sdkmetric.ManualReader, name string) metricdata.Sum[int64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: data is %T, want metricdata.Sum[int64]", name, m.Data)
			}
			return sum
		}
	}
	t.Fatalf("instrument %s not found in collected metrics", name)
	return metricdata.Sum[int64]{}
}

// TestMetrics_RecordViolationAttributes verifies that an SLO violation is
// counted under exactly the ToR-level attributes network, source_tor,
// target_tor and kind, with no GID-level attribute (the project-wide
// cardinality rule), and that the two networks are separate series.
func TestMetrics_RecordViolationAttributes(t *testing.T) {
	m, reader := newTestMetrics(t)
	ctx := context.Background()

	m.recordViolation(ctx, NetworkCluster, "tor-a", "tor-b", KindLoss)
	m.recordViolation(ctx, NetworkCluster, "tor-a", "tor-b", KindLoss)
	m.recordViolation(ctx, NetworkCluster, "tor-a", "tor-c", KindRTT)
	m.recordViolation(ctx, NetworkService, "tor-a", "tor-b", KindLoss)

	sum := collectSum(t, reader, "rpingmesh.analyzer.sla_violations_total")
	if !sum.IsMonotonic {
		t.Error("sla_violations_total is not monotonic; want a counter")
	}
	if len(sum.DataPoints) != 3 {
		t.Fatalf("got %d data points, want 3 (one per distinct attribute set)", len(sum.DataPoints))
	}

	want := map[attribute.Set]int64{
		attribute.NewSet(
			attribute.String("network", NetworkCluster),
			attribute.String("source_tor", "tor-a"),
			attribute.String("target_tor", "tor-b"),
			attribute.String("kind", KindLoss),
		): 2,
		attribute.NewSet(
			attribute.String("network", NetworkCluster),
			attribute.String("source_tor", "tor-a"),
			attribute.String("target_tor", "tor-c"),
			attribute.String("kind", KindRTT),
		): 1,
		attribute.NewSet(
			attribute.String("network", NetworkService),
			attribute.String("source_tor", "tor-a"),
			attribute.String("target_tor", "tor-b"),
			attribute.String("kind", KindLoss),
		): 1,
	}
	for _, dp := range sum.DataPoints {
		wantValue, ok := want[dp.Attributes]
		if !ok {
			t.Errorf("unexpected attribute set %v", dp.Attributes.ToSlice())
			continue
		}
		if dp.Value != wantValue {
			t.Errorf("attributes %v: value = %d, want %d", dp.Attributes.ToSlice(), dp.Value, wantValue)
		}
		if dp.Attributes.Len() != 4 {
			t.Errorf("attributes %v: %d attributes, want exactly network, source_tor, target_tor, kind", dp.Attributes.ToSlice(), dp.Attributes.Len())
		}
	}
}

// TestMetrics_ServiceViolationTaggedByNetwork verifies, through the
// Analyzer, that a service-path violation lands on the counter with
// network="service" and a cluster one with network="cluster".
func TestMetrics_ServiceViolationTaggedByNetwork(t *testing.T) {
	m, reader := newTestMetrics(t)
	a := New(testConfig(), m)

	a.Ingest(context.Background(), report(
		summary("tor-a", "tor-b", 100, 50, 0, 1),        // cluster loss violation
		serviceSummary("tor-a", "tor-b", 100, 50, 0, 1), // service loss violation
	))

	violations := collectSum(t, reader, "rpingmesh.analyzer.sla_violations_total")
	if len(violations.DataPoints) != 2 {
		t.Fatalf("sla_violations_total data points = %d, want 2", len(violations.DataPoints))
	}
	seen := map[string]bool{}
	for _, dp := range violations.DataPoints {
		network, ok := dp.Attributes.Value("network")
		if !ok {
			t.Fatalf("data point %v has no network attribute", dp.Attributes.ToSlice())
		}
		seen[network.AsString()] = true
		if dp.Value != 1 {
			t.Errorf("network %s: value = %d, want 1", network.AsString(), dp.Value)
		}
	}
	if !seen[NetworkCluster] || !seen[NetworkService] {
		t.Errorf("networks seen = %v, want both cluster and service", seen)
	}
}

// TestMetrics_RecordSummaryCountsIngested verifies the ingested-summary counter
// through the Analyzer, and that it carries no attributes.
func TestMetrics_RecordSummaryCountsIngested(t *testing.T) {
	m, reader := newTestMetrics(t)
	a := New(testConfig(), m)

	a.Ingest(context.Background(), report(
		summary("tor-a", "tor-b", 100, 0, 0, 1),
		summary("tor-a", "tor-c", 100, 50, 0, 1), // loss violation
	))

	sum := collectSum(t, reader, "rpingmesh.analyzer.path_summaries_total")
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 2 {
		t.Fatalf("path_summaries_total data points = %+v, want one point with value 2", sum.DataPoints)
	}
	if n := sum.DataPoints[0].Attributes.Len(); n != 0 {
		t.Errorf("path_summaries_total has %d attributes, want 0", n)
	}

	// The violating summary must have reached the violation counter with the
	// analyzer's (label-mapped) ToR IDs.
	violations := collectSum(t, reader, "rpingmesh.analyzer.sla_violations_total")
	if len(violations.DataPoints) != 1 {
		t.Fatalf("sla_violations_total data points = %d, want 1", len(violations.DataPoints))
	}
	got := violations.DataPoints[0].Attributes
	wantAttrs := attribute.NewSet(
		attribute.String("network", NetworkCluster),
		attribute.String("source_tor", "tor-a"),
		attribute.String("target_tor", "tor-c"),
		attribute.String("kind", KindLoss),
	)
	if !got.Equals(&wantAttrs) {
		t.Errorf("violation attributes = %v, want %v", got.ToSlice(), wantAttrs.ToSlice())
	}
}

// TestMetrics_NilIsNoop verifies that a nil *Metrics (metrics export
// unavailable) is safe to record on.
func TestMetrics_NilIsNoop(t *testing.T) {
	var m *Metrics
	m.recordSummary(context.Background())
	m.recordViolation(context.Background(), NetworkCluster, "tor-a", "tor-b", KindRTT)
}
