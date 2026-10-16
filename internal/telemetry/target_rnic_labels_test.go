package telemetry

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

var targetRnicLabelKeys = []attribute.Key{"target_hostname", "target_rdma_device", "target_netdev"}

// recordAndCollect records results on a collector configured with opts and
// returns the collected metrics.
func recordAndCollect(t *testing.T, opts []Option, results ...*probe.ProbeResult) *metricdata.ResourceMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	mc, err := NewMetricsCollectorWithProvider(provider, opts...)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}
	for _, r := range results {
		mc.RecordProbeResult(r, probe.CalculateRTT(r), "tor-a")
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	return &rm
}

// successfulResult returns a successful probe to the given target RNIC.
func successfulResult(host, device, netdev string, ptype controller_agent.PinglistType) *probe.ProbeResult {
	return &probe.ProbeResult{
		TargetTorID:      "tor-a",
		TargetHostname:   host,
		TargetRdmaDevice: device,
		TargetNetdev:     netdev,
		PinglistType:     ptype,
		SourceRdmaDevice: "mlx5_0",
		SourceNetdev:     "ens1f0",
		T1:               1, T2: 100, T3: 1000, T4: 1300, T5: 2400, T6: 2500,
		Success: true,
	}
}

// dataPointAttrs returns the attribute set of every data point of metric name.
func dataPointAttrs(t *testing.T, rm *metricdata.ResourceMetrics, name string) []attribute.Set {
	t.Helper()
	m := findMetric(rm, name)
	if m == nil {
		t.Fatalf("%s metric not found", name)
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

func hasTargetRnicLabels(set attribute.Set) bool {
	for _, k := range targetRnicLabelKeys {
		if _, ok := set.Value(k); ok {
			return true
		}
	}
	return false
}

func targetRnicValues(set attribute.Set) [3]string {
	var vals [3]string
	for i, k := range targetRnicLabelKeys {
		v, _ := set.Value(k)
		vals[i] = v.AsString()
	}
	return vals
}

// TestRecordProbeResult_TargetRnicLabelsOffByDefault verifies that without
// WithTargetRnicLabels no destination-RNIC attribute is recorded.
func TestRecordProbeResult_TargetRnicLabelsOffByDefault(t *testing.T) {
	rm := recordAndCollect(t, nil,
		successfulResult("host-b", "mlx5_1", "ens2f0", controller_agent.PinglistType_TOR_MESH))

	for _, name := range []string{"rpingmesh.probe_total", "rpingmesh.probe_success_total", "rpingmesh.network_rtt_ns"} {
		for _, set := range dataPointAttrs(t, rm, name) {
			if hasTargetRnicLabels(set) {
				t.Errorf("%s has destination-RNIC labels by default: %v", name, set.ToSlice())
			}
		}
	}
}

// TestRecordProbeResult_TargetRnicLabelsCounters verifies that the counters
// mode labels the counters (including probe_failed_total) with the target
// RNIC but leaves the RTT histograms at the default label set.
func TestRecordProbeResult_TargetRnicLabelsCounters(t *testing.T) {
	failed := &probe.ProbeResult{
		TargetTorID: "tor-a", TargetHostname: "host-c", TargetRdmaDevice: "mlx5_2", TargetNetdev: "ens3f0",
		Success: false, ErrorMessage: "timed out waiting for ACKs",
	}
	rm := recordAndCollect(t, []Option{WithTargetRnicLabels(TargetRnicLabels{Enabled: true})},
		successfulResult("host-b", "mlx5_1", "ens2f0", controller_agent.PinglistType_TOR_MESH), failed)

	want := map[string][3]string{
		"rpingmesh.probe_success_total": {"host-b", "mlx5_1", "ens2f0"},
		"rpingmesh.probe_failed_total":  {"host-c", "mlx5_2", "ens3f0"},
	}
	for name, vals := range want {
		sets := dataPointAttrs(t, rm, name)
		if len(sets) != 1 || targetRnicValues(sets[0]) != vals {
			t.Errorf("%s attributes = %v, want target labels %v", name, sets, vals)
		}
	}
	if sets := dataPointAttrs(t, rm, "rpingmesh.probe_total"); len(sets) != 2 {
		t.Errorf("probe_total has %d series, want one per target RNIC (2)", len(sets))
	}
	for _, name := range []string{"rpingmesh.network_rtt_ns", "rpingmesh.prober_delay_ns", "rpingmesh.responder_delay_ns"} {
		for _, set := range dataPointAttrs(t, rm, name) {
			if hasTargetRnicLabels(set) {
				t.Errorf("%s has destination-RNIC labels in counters mode: %v", name, set.ToSlice())
			}
		}
	}
}

// TestRecordProbeResult_TargetRnicLabelsHistograms verifies that the all mode
// also labels the RTT histograms.
func TestRecordProbeResult_TargetRnicLabelsHistograms(t *testing.T) {
	rm := recordAndCollect(t, []Option{WithTargetRnicLabels(TargetRnicLabels{Enabled: true, Histograms: true})},
		successfulResult("host-b", "mlx5_1", "ens2f0", controller_agent.PinglistType_TOR_MESH))

	for _, name := range []string{"rpingmesh.network_rtt_ns", "rpingmesh.prober_delay_ns", "rpingmesh.responder_delay_ns"} {
		sets := dataPointAttrs(t, rm, name)
		if len(sets) != 1 || targetRnicValues(sets[0]) != [3]string{"host-b", "mlx5_1", "ens2f0"} {
			t.Errorf("%s attributes = %v, want destination-RNIC labels", name, sets)
		}
	}
}

// TestRecordProbeResult_TargetRnicLabelsScope verifies that inter-ToR
// targets get the fixed out-of-scope value unless IncludeInterTor is set, and
// that an unknown target netdev reads "unspecified".
func TestRecordProbeResult_TargetRnicLabelsScope(t *testing.T) {
	interTor := successfulResult("host-x", "mlx5_0", "", controller_agent.PinglistType_INTER_TOR)

	cases := []struct {
		name   string
		labels TargetRnicLabels
		want   [3]string
	}{
		{"tor_mesh", TargetRnicLabels{Enabled: true},
			[3]string{outOfScopeTargetLabel, outOfScopeTargetLabel, outOfScopeTargetLabel}},
		{"all", TargetRnicLabels{Enabled: true, IncludeInterTor: true},
			[3]string{"host-x", "mlx5_0", unspecifiedDeviceLabel}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rm := recordAndCollect(t, []Option{WithTargetRnicLabels(tc.labels)}, interTor)
			sets := dataPointAttrs(t, rm, "rpingmesh.probe_total")
			if len(sets) != 1 || targetRnicValues(sets[0]) != tc.want {
				t.Errorf("probe_total attributes = %v, want target labels %v", sets, tc.want)
			}
		})
	}
}
