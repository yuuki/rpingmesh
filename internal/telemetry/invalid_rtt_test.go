package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/probe"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestCollector returns a MetricsCollector backed by a ManualReader.
func newTestCollector(t *testing.T, opts ...Option) (*MetricsCollector, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	mc, err := NewMetricsCollectorWithProvider(provider, opts...)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}
	return mc, reader
}

// collect gathers the current metrics of reader.
func collect(t *testing.T, reader *sdkmetric.ManualReader) *metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	return &rm
}

// countsByAttr sums an int64 counter's data points by the value of attr.
func countsByAttr(t *testing.T, rm *metricdata.ResourceMetrics, name, attr string) map[string]int64 {
	t.Helper()
	m := findMetric(rm, name)
	if m == nil {
		return nil
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%s is %T, want Sum[int64]", name, m.Data)
	}
	got := map[string]int64{}
	for _, dp := range sum.DataPoints {
		v, ok := dp.Attributes.Value(attribute.Key(attr))
		if !ok {
			t.Fatalf("%s data point missing %s attribute: %+v", name, attr, dp)
		}
		got[v.AsString()] += dp.Value
	}
	return got
}

// TestRecordProbeResult_InvalidKind verifies that rejected measurements are
// counted on rpingmesh.probe_invalid_total by probe.InvalidKind, while
// timeouts and valid probes are not.
func TestRecordProbeResult_InvalidKind(t *testing.T) {
	mc, reader := newTestCollector(t)
	sec := uint64(time.Second)
	results := []*probe.ProbeResult{
		// ResponderDelay of 3s from a backlogged responder (counted twice).
		{Success: true, T1: 1_000, T2: 2_000, T3: 50 * sec, T4: 53 * sec, T5: 2_000 + 3*sec + 10_000, T6: 2_000 + 3*sec + 20_000},
		{Success: true, T1: 1_000, T2: 2_000, T3: 50 * sec, T4: 53 * sec, T5: 2_000 + 3*sec + 10_000, T6: 2_000 + 3*sec + 20_000},
		// Negative NetworkRTT.
		{Success: true, T1: 100_000, T2: 101_000, T3: 200_000, T4: 300_000, T5: 150_000, T6: 160_000},
		// Valid.
		{Success: true, T1: 100_000, T2: 101_000, T3: 200_000, T4: 202_000, T5: 301_000, T6: 302_000},
		// Timeout.
		{Success: false, ErrorMessage: "timed out waiting for ACKs"},
	}
	for _, r := range results {
		mc.RecordProbeResult(r, probe.CalculateRTT(r), "tor-a")
	}

	rm := collect(t, reader)
	got := countsByAttr(t, rm, "rpingmesh.probe_invalid_total", "kind")
	want := map[string]int64{
		string(probe.InvalidKindResponderDelayTooLarge): 2,
		string(probe.InvalidKindNegativeNetworkRTT):     1,
	}
	if len(got) != len(want) {
		t.Fatalf("probe_invalid_total by kind = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("probe_invalid_total{kind=%q} = %d, want %d", k, got[k], v)
		}
	}
	failed := countsByAttr(t, rm, "rpingmesh.probe_failed_total", "reason")
	if failed[reasonInvalidRTT] != 3 || failed[reasonTimeout] != 1 {
		t.Errorf("probe_failed_total by reason = %v, want invalid_rtt=3 timeout=1", failed)
	}
}

// TestRecordProbeResult_InvalidKindTargetRnic verifies the destination-RNIC
// counterpart of probe_invalid_total.
func TestRecordProbeResult_InvalidKindTargetRnic(t *testing.T) {
	mc, reader := newTestCollector(t, WithTargetRnicLabels(TargetRnicLabels{Enabled: true}))
	r := &probe.ProbeResult{
		Success: true, T1: 100_000, T2: 101_000, T3: 200_000, T4: 199_000, T5: 301_000, T6: 302_000,
		TargetHostname: "host-b", TargetRdmaDevice: "mlx5_1", TargetNetdev: "eth1",
	}
	mc.RecordProbeResult(r, probe.CalculateRTT(r), "tor-a")

	rm := collect(t, reader)
	got := countsByAttr(t, rm, targetRnicMetricPrefix+"probe_invalid_total", "kind")
	if got[string(probe.InvalidKindNegativeResponderDelay)] != 1 || len(got) != 1 {
		t.Fatalf("target_rnic.probe_invalid_total by kind = %v", got)
	}
	hosts := countsByAttr(t, rm, targetRnicMetricPrefix+"probe_invalid_total", "target_hostname")
	if hosts["host-b"] != 1 {
		t.Errorf("target_rnic.probe_invalid_total by target_hostname = %v", hosts)
	}
	// The failed counter's attribute set must not have picked up "kind".
	m := findMetric(rm, targetRnicMetricPrefix+"probe_failed_total")
	for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
		if _, ok := dp.Attributes.Value("kind"); ok {
			t.Errorf("target_rnic.probe_failed_total carries a kind attribute: %+v", dp)
		}
	}
}

// TestInvalidRTTWarnLimiter verifies that one Warn log passes per interval
// and reports how many were suppressed before it.
func TestInvalidRTTWarnLimiter(t *testing.T) {
	var l invalidRTTWarnLimiter
	t0 := time.Unix(1000, 0)
	if ok, n := l.allow(t0); !ok || n != 0 {
		t.Fatalf("first allow = %v, %d; want true, 0", ok, n)
	}
	for i := 1; i <= 3; i++ {
		if ok, _ := l.allow(t0.Add(time.Duration(i) * time.Second)); ok {
			t.Fatalf("allow inside the interval returned true")
		}
	}
	if ok, n := l.allow(t0.Add(invalidRTTWarnInterval)); !ok || n != 3 {
		t.Fatalf("allow after the interval = %v, %d; want true, 3", ok, n)
	}
}

// TestRegisterEventRingOccupancyCallback verifies the occupancy and capacity
// gauges and that each collection calls the reader once.
func TestRegisterEventRingOccupancyCallback(t *testing.T) {
	mc, reader := newTestCollector(t)
	calls := 0
	maxOcc := uint64(700)
	err := mc.RegisterEventRingOccupancyCallback(map[string]func() EventRingOccupancy{
		"responder": func() EventRingOccupancy {
			calls++
			v := maxOcc
			maxOcc = 0 // reset on read, as EventRing.TakeMaxOccupancy does
			return EventRingOccupancy{Max: v, Capacity: 1024}
		},
	})
	if err != nil {
		t.Fatalf("RegisterEventRingOccupancyCallback: %v", err)
	}

	gauge := func(rm *metricdata.ResourceMetrics, name string) int64 {
		m := findMetric(rm, name)
		if m == nil {
			t.Fatalf("%s not found", name)
		}
		g := m.Data.(metricdata.Gauge[int64])
		if len(g.DataPoints) != 1 {
			t.Fatalf("%s = %+v, want 1 data point", name, g)
		}
		if v, _ := g.DataPoints[0].Attributes.Value("ring"); v.AsString() != "responder" {
			t.Fatalf("%s ring attribute = %q", name, v.AsString())
		}
		return g.DataPoints[0].Value
	}

	rm := collect(t, reader)
	if v := gauge(rm, "rpingmesh.event_ring_occupancy_max"); v != 700 {
		t.Errorf("occupancy_max = %d, want 700", v)
	}
	if v := gauge(rm, "rpingmesh.event_ring_capacity"); v != 1024 {
		t.Errorf("capacity = %d, want 1024", v)
	}
	rm = collect(t, reader)
	if v := gauge(rm, "rpingmesh.event_ring_occupancy_max"); v != 0 {
		t.Errorf("occupancy_max after reset = %d, want 0", v)
	}
	if calls != 2 {
		t.Errorf("reader called %d times for 2 collections, want 2", calls)
	}
}

// TestRegisterTimestampModeCallback verifies the per-queue hw_timestamps
// gauge.
func TestRegisterTimestampModeCallback(t *testing.T) {
	mc, reader := newTestCollector(t)
	err := mc.RegisterTimestampModeCallback(func() []QueueTimestampMode {
		return []QueueTimestampMode{
			{RdmaDevice: "mlx5_0", Queue: "prober", HWTimestamps: true},
			{RdmaDevice: "mlx5_0", Queue: "responder", HWTimestamps: false},
		}
	})
	if err != nil {
		t.Fatalf("RegisterTimestampModeCallback: %v", err)
	}
	m := findMetric(collect(t, reader), "rpingmesh.agent.hw_timestamps")
	if m == nil {
		t.Fatal("rpingmesh.agent.hw_timestamps not found")
	}
	got := map[string]int64{}
	for _, dp := range m.Data.(metricdata.Gauge[int64]).DataPoints {
		dev, _ := dp.Attributes.Value("rdma_device")
		q, _ := dp.Attributes.Value("queue")
		got[dev.AsString()+"/"+q.AsString()] = dp.Value
	}
	if got["mlx5_0/prober"] != 1 || got["mlx5_0/responder"] != 0 || len(got) != 2 {
		t.Errorf("hw_timestamps = %v, want mlx5_0/prober=1 mlx5_0/responder=0", got)
	}
}
