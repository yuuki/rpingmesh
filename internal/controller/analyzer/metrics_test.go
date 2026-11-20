package analyzer

import (
	"context"
	"reflect"
	"sort"
	"strings"
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

	sum := collectSum(t, reader, "rpingmesh.analyzer.slo_violations_total")
	if !sum.IsMonotonic {
		t.Error("slo_violations_total is not monotonic; want a counter")
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

	violations := collectSum(t, reader, "rpingmesh.analyzer.slo_violations_total")
	if len(violations.DataPoints) != 2 {
		t.Fatalf("slo_violations_total data points = %d, want 2", len(violations.DataPoints))
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
	violations := collectSum(t, reader, "rpingmesh.analyzer.slo_violations_total")
	if len(violations.DataPoints) != 1 {
		t.Fatalf("slo_violations_total data points = %d, want 1", len(violations.DataPoints))
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

// collectNames returns the names of the instruments that exported data.
func collectNames(t *testing.T, reader *sdkmetric.ManualReader) []string {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names = append(names, m.Name)
		}
	}
	sort.Strings(names)
	return names
}

// gaugePoints returns the data points of the named gauge by attribute set,
// or nil when the gauge exported nothing.
func gaugePoints[N int64 | float64](t *testing.T, reader *sdkmetric.ManualReader, name string) map[attribute.Set]N {
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
			gauge, ok := m.Data.(metricdata.Gauge[N])
			if !ok {
				t.Fatalf("%s: data is %T, want a gauge", name, m.Data)
			}
			out := make(map[attribute.Set]N, len(gauge.DataPoints))
			for _, dp := range gauge.DataPoints {
				out[dp.Attributes] = dp.Value
			}
			return out
		}
	}
	return nil
}

// TestMetrics_LocalizationOffExportsNothingNew verifies the compatibility
// promise of opt-in localization: an analyzer without it exports exactly
// the two Phase 1 instruments, also after ingesting degraded paths.
func TestMetrics_LocalizationOffExportsNothingNew(t *testing.T) {
	m, reader := newTestMetrics(t)
	a := New(testConfig(), m)
	for w := 0; w < 3; w++ {
		for _, o := range lossyTor0() {
			a.Ingest(context.Background(), report(o.summary(w)))
		}
	}
	want := []string{"rpingmesh.analyzer.path_summaries_total", "rpingmesh.analyzer.slo_violations_total"}
	if got := collectNames(t, reader); !reflect.DeepEqual(got, want) {
		t.Errorf("exported instruments = %v, want %v", got, want)
	}
}

// TestMetrics_LocalizationSuspectAttributes verifies, for every kind of
// component, the exact attribute set a suspect is exported under: the
// signal kind, the state, the component kind and the ToR, spine group and
// rail that apply. No attribute ever carries a GID or an agent ID.
func TestMetrics_LocalizationSuspectAttributes(t *testing.T) {
	m, reader := newTestMetrics(t)
	findings := []Finding{
		{Signal: KindLoss, State: StateLocalized, Suspects: []Suspect{{
			Component:  Component{Kind: ComponentRNIC, Tor: "tor-a", SpineGroup: "pod-a", Rail: "rail0", GID: "fd00::1", AgentID: "host-1"},
			Confidence: 0.97,
		}}},
		// A second RNIC under the same ToR shares the attribute set.
		{Signal: KindLoss, State: StateLocalized, Suspects: []Suspect{{
			Component:  Component{Kind: ComponentRNIC, Tor: "tor-a", SpineGroup: "pod-a", Rail: "rail0", GID: "fd00::2", AgentID: "host-2"},
			Confidence: 0.99,
		}}},
		{Signal: KindLoss, State: StateLocalized, Suspects: []Suspect{{
			Component: Component{Kind: ComponentHost, AgentID: "host-3"}, Confidence: 1,
		}}},
		{Signal: KindLoss, State: StateAmbiguous, Suspects: []Suspect{
			{Component: Component{Kind: ComponentTorUplink, Tor: "tor-b"}, Confidence: 0.6},
			{Component: Component{Kind: ComponentTor, Tor: "tor-b"}, Confidence: 0.4},
		}},
		{Signal: KindRTT, State: StateLocalized, Suspects: []Suspect{{
			Component: Component{Kind: ComponentSpineGroup, SpineGroup: "pod-a", Rail: "rail0"}, Confidence: 0.96,
		}}},
		{Signal: KindRTT, State: StateNotLocalizable, Suspects: []Suspect{{
			Component: Component{Kind: ComponentRail, Rail: "rail1"}, Confidence: 1,
		}}, Members: []string{"tor-c", "tor-d", "tor-e"}, MemberCount: 3},
		{Signal: KindLoss, State: StateNotLocalizable, Suspects: []Suspect{{
			Component: Component{Kind: ComponentFabric}, Confidence: 0.98,
		}}},
		{Signal: KindLoss, State: StateNotLocalizable, Suspects: []Suspect{{
			Component: Component{Kind: ComponentBackground}, Confidence: 1,
		}}},
	}
	if err := m.registerLocalization(func() []Finding { return findings }); err != nil {
		t.Fatalf("registerLocalization: %v", err)
	}

	set := func(kv ...string) attribute.Set {
		var attrs []attribute.KeyValue
		for i := 0; i < len(kv); i += 2 {
			attrs = append(attrs, attribute.String(kv[i], kv[i+1]))
		}
		return attribute.NewSet(attrs...)
	}
	type point struct {
		count      int64
		confidence float64
	}
	want := map[attribute.Set]point{
		set("kind", "loss", "state", "localized", "component", "rnic", "tor", "tor-a", "spine_group", "pod-a", "rail", "rail0"): {2, 0.99},
		set("kind", "loss", "state", "localized", "component", "host"):                                                          {1, 1},
		set("kind", "loss", "state", "ambiguous", "component", "tor_uplink", "tor", "tor-b"):                                    {1, 0.6},
		set("kind", "loss", "state", "ambiguous", "component", "tor", "tor", "tor-b"):                                           {1, 0.4},
		set("kind", "rtt", "state", "localized", "component", "spine_group", "spine_group", "pod-a", "rail", "rail0"):           {1, 0.96},
		set("kind", "rtt", "state", "not_localizable", "component", "rail", "rail", "rail1"):                                    {1, 1},
		set("kind", "loss", "state", "not_localizable", "component", "fabric"):                                                  {1, 0.98},
		set("kind", "loss", "state", "not_localizable", "component", "background"):                                              {1, 1},
	}

	counts := gaugePoints[int64](t, reader, "rpingmesh.analyzer.localization_suspects")
	confidences := gaugePoints[float64](t, reader, "rpingmesh.analyzer.localization_suspect_confidence")
	if len(counts) != len(want) || len(confidences) != len(want) {
		t.Fatalf("%d suspect series and %d confidence series, want %d each", len(counts), len(confidences), len(want))
	}
	for attrs, p := range want {
		if got, ok := counts[attrs]; !ok || got != p.count {
			t.Errorf("localization_suspects%v = %d (present %v), want %d", attrs.ToSlice(), got, ok, p.count)
		}
		if got, ok := confidences[attrs]; !ok || got != p.confidence {
			t.Errorf("localization_suspect_confidence%v = %v (present %v), want %v", attrs.ToSlice(), got, ok, p.confidence)
		}
	}
	allowed := map[attribute.Key]bool{"kind": true, "state": true, "component": true, "tor": true, "spine_group": true, "rail": true}
	for attrs := range counts {
		for _, kv := range attrs.ToSlice() {
			if !allowed[kv.Key] {
				t.Errorf("unexpected attribute %s=%s", kv.Key, kv.Value.AsString())
			}
			if v := kv.Value.AsString(); strings.Contains(v, "fd00") || strings.Contains(v, "host-") {
				t.Errorf("attribute %s carries an RNIC or host identity: %q", kv.Key, v)
			}
		}
	}
}

// TestMetrics_LocalizationSeriesFollowFindings verifies, through the
// localizer, that the suspect gauges appear with a finding and end when it
// clears (instead of staying at zero), and the two counters.
func TestMetrics_LocalizationSeriesFollowFindings(t *testing.T) {
	m, reader := newTestMetrics(t)
	az, clock := newTestLocalizer(t, LocalizationConfig{Windows: 2, MaxPathsPerWindow: 200}, m)
	ctx := context.Background()
	healthy := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })

	// Nothing evaluated yet: no localization series at all.
	if names := collectNames(t, reader); len(names) != 0 {
		t.Fatalf("instruments exported before any report: %v", names)
	}

	for w := 0; w < 2; w++ {
		ingestWindow(az, clock, w, lossyTor0())
		clock.ns = windowClose(w)
		az.loc.evaluate(ctx)
	}
	wantAttrs := attribute.NewSet(
		attribute.String("kind", KindLoss),
		attribute.String("state", StateLocalized),
		attribute.String("component", ComponentTor),
		attribute.String("tor", "tor-0"),
	)
	counts := gaugePoints[int64](t, reader, "rpingmesh.analyzer.localization_suspects")
	if len(counts) != 1 || counts[wantAttrs] != 1 {
		t.Fatalf("localization_suspects = %v, want one series for tor-0", counts)
	}
	confidences := gaugePoints[float64](t, reader, "rpingmesh.analyzer.localization_suspect_confidence")
	if c := confidences[wantAttrs]; c < DefaultLocalizationMinConfidence || c > 1 {
		t.Errorf("localization_suspect_confidence = %v, want within [%v, 1]", c, DefaultLocalizationMinConfidence)
	}
	if runs := collectSum(t, reader, "rpingmesh.analyzer.localization_runs_total"); len(runs.DataPoints) != 1 ||
		runs.DataPoints[0].Value != 2 || runs.DataPoints[0].Attributes.Len() != 0 {
		t.Errorf("localization_runs_total = %+v, want 2 without attributes", runs.DataPoints)
	}

	// Two healthy windows: the finding clears and its series end.
	for w := 2; w < 4; w++ {
		ingestWindow(az, clock, w, healthy)
		clock.ns = windowClose(w)
		az.loc.evaluate(ctx)
	}
	if counts := gaugePoints[int64](t, reader, "rpingmesh.analyzer.localization_suspects"); len(counts) != 0 {
		t.Errorf("localization_suspects after the finding cleared = %v, want no series", counts)
	}
	if confidences := gaugePoints[float64](t, reader, "rpingmesh.analyzer.localization_suspect_confidence"); len(confidences) != 0 {
		t.Errorf("localization_suspect_confidence after the finding cleared = %v, want no series", confidences)
	}

	// The mesh has 132 paths; a window capped at 200 keeps them all. A
	// second fabric's worth of paths in one window exceeds the cap.
	extra := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })
	for i := range extra {
		extra[i].src, extra[i].dst = "x-"+extra[i].src, "x-"+extra[i].dst
	}
	ingestWindow(az, clock, 4, healthy)
	ingestWindow(az, clock, 4, extra)
	dropped := collectSum(t, reader, "rpingmesh.analyzer.localization_dropped_paths_total")
	if want := int64(2*len(healthy) - 200); len(dropped.DataPoints) != 1 || dropped.DataPoints[0].Value != want ||
		dropped.DataPoints[0].Attributes.Len() != 0 {
		t.Errorf("localization_dropped_paths_total = %+v, want %d without attributes", dropped.DataPoints, want)
	}
}

// TestMetrics_LocalizationNilIsNoop verifies that the localizer runs
// without metrics (log-only findings).
func TestMetrics_LocalizationNilIsNoop(t *testing.T) {
	var m *Metrics
	if err := m.registerLocalization(func() []Finding { return nil }); err != nil {
		t.Errorf("registerLocalization on nil Metrics: %v", err)
	}
	m.recordLocalizationRun(context.Background())
	m.recordDroppedPaths(context.Background(), 3)

	// Metrics that exist but whose localization instruments were never
	// registered.
	registered, _ := newTestMetrics(t)
	registered.recordLocalizationRun(context.Background())
	registered.recordDroppedPaths(context.Background(), 3)
}
