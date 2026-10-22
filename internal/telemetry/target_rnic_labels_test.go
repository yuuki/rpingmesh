package telemetry

import (
	"fmt"
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

var targetRnicLabelKeys = []attribute.Key{"target_hostname", "target_rdma_device", "target_netdev"}

// successfulResult returns a successful probe to the given target RNIC.
func successfulResult(host, device, netdev string, sampled bool) *probe.ProbeResult {
	return &probe.ProbeResult{
		TargetTorID:      "tor-a",
		TargetHostname:   host,
		TargetRdmaDevice: device,
		TargetNetdev:     netdev,
		TargetSampled:    sampled,
		SourceRdmaDevice: "mlx5_0",
		SourceNetdev:     "ens1f0",
		T1:               1, T2: 100, T3: 1000, T4: 1300, T5: 2400, T6: 2500,
		Success: true,
	}
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

var (
	defaultProbeMetrics = []string{
		"rpingmesh.probe_total", "rpingmesh.probe_success_total", "rpingmesh.probe_failed_total",
		"rpingmesh.network_rtt_ns", "rpingmesh.prober_delay_ns", "rpingmesh.responder_delay_ns",
	}
	targetCounterMetrics = []string{
		"rpingmesh.target_rnic.probe_total", "rpingmesh.target_rnic.probe_success_total",
		"rpingmesh.target_rnic.probe_failed_total",
	}
	targetHistogramMetrics = []string{
		"rpingmesh.target_rnic.network_rtt_ns", "rpingmesh.target_rnic.prober_delay_ns",
		"rpingmesh.target_rnic.responder_delay_ns",
	}
)

// assertDefaultMetricsUnlabelled fails if any default probe metric carries a
// destination-RNIC label.
func assertDefaultMetricsUnlabelled(t *testing.T, rm *metricdata.ResourceMetrics) {
	t.Helper()
	for _, name := range defaultProbeMetrics {
		for _, set := range otelmetrics.DataPointAttrs(t, rm, name) {
			if hasTargetRnicLabels(set) {
				t.Errorf("%s has destination-RNIC labels: %v", name, set.ToSlice())
			}
		}
	}
}

// TestRecordProbeResult_TargetRnicMetricsOffByDefault verifies that without
// WithTargetRnicLabels no target_rnic metric is exported.
func TestRecordProbeResult_TargetRnicMetricsOffByDefault(t *testing.T) {
	rm := recordAndCollect(t, nil, successfulResult("host-b", "mlx5_1", "ens2f0", false))

	for _, name := range append(targetCounterMetrics, targetHistogramMetrics...) {
		if m := otelmetrics.Find(rm, name); m != nil {
			t.Errorf("%s exported by default: %+v", name, m.Data)
		}
	}
	assertDefaultMetricsUnlabelled(t, rm)
}

// TestRecordProbeResult_TargetRnicCounters verifies that the counters mode
// records the target_rnic counters (including probe_failed_total with its
// reason) with the target RNIC, records no target_rnic histograms, and
// leaves the default metrics unlabelled.
func TestRecordProbeResult_TargetRnicCounters(t *testing.T) {
	failed := &probe.ProbeResult{
		TargetTorID: "tor-a", TargetHostname: "host-c", TargetRdmaDevice: "mlx5_2", TargetNetdev: "ens3f0",
		Success: false, ErrorMessage: "timed out waiting for ACKs",
	}
	rm := recordAndCollect(t, []Option{WithTargetRnicLabels(TargetRnicLabels{Enabled: true})},
		successfulResult("host-b", "mlx5_1", "ens2f0", false), failed)

	want := map[string][3]string{
		"rpingmesh.target_rnic.probe_success_total": {"host-b", "mlx5_1", "ens2f0"},
		"rpingmesh.target_rnic.probe_failed_total":  {"host-c", "mlx5_2", "ens3f0"},
	}
	for name, vals := range want {
		sets := otelmetrics.DataPointAttrs(t, rm, name)
		if len(sets) != 1 || targetRnicValues(sets[0]) != vals {
			t.Errorf("%s attributes = %v, want target labels %v", name, sets, vals)
		}
	}
	if sets := otelmetrics.DataPointAttrs(t, rm, "rpingmesh.target_rnic.probe_failed_total"); len(sets) == 1 {
		if v, _ := sets[0].Value("reason"); v.AsString() != reasonTimeout {
			t.Errorf("target_rnic.probe_failed_total reason = %q, want %q", v.AsString(), reasonTimeout)
		}
	}
	if sets := otelmetrics.DataPointAttrs(t, rm, "rpingmesh.target_rnic.probe_total"); len(sets) != 2 {
		t.Errorf("target_rnic.probe_total has %d series, want one per target RNIC (2)", len(sets))
	}
	for _, name := range targetHistogramMetrics {
		if m := otelmetrics.Find(rm, name); m != nil {
			t.Errorf("%s exported in counters mode", name)
		}
	}
	assertDefaultMetricsUnlabelled(t, rm)
}

// TestRecordProbeResult_TargetRnicHistograms verifies that the all mode also
// records the target_rnic RTT histograms.
func TestRecordProbeResult_TargetRnicHistograms(t *testing.T) {
	rm := recordAndCollect(t, []Option{WithTargetRnicLabels(TargetRnicLabels{Enabled: true, Histograms: true})},
		successfulResult("host-b", "mlx5_1", "ens2f0", false))

	for _, name := range targetHistogramMetrics {
		sets := otelmetrics.DataPointAttrs(t, rm, name)
		if len(sets) != 1 || targetRnicValues(sets[0]) != [3]string{"host-b", "mlx5_1", "ens2f0"} {
			t.Errorf("%s attributes = %v, want destination-RNIC labels", name, sets)
		}
	}
	assertDefaultMetricsUnlabelled(t, rm)
}

// TestRecordProbeResult_TargetRnicScope verifies that sampled targets get the
// fixed placeholder unless IncludeSampled is set, and that an unknown target
// netdev reads "unspecified".
func TestRecordProbeResult_TargetRnicScope(t *testing.T) {
	sampled := successfulResult("host-x", "mlx5_0", "", true)

	cases := []struct {
		name   string
		labels TargetRnicLabels
		want   [3]string
	}{
		{"stable", TargetRnicLabels{Enabled: true},
			[3]string{sampledTargetLabel, sampledTargetLabel, sampledTargetLabel}},
		{"all", TargetRnicLabels{Enabled: true, IncludeSampled: true},
			[3]string{"host-x", "mlx5_0", unspecifiedDeviceLabel}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rm := recordAndCollect(t, []Option{WithTargetRnicLabels(tc.labels)}, sampled)
			sets := otelmetrics.DataPointAttrs(t, rm, "rpingmesh.target_rnic.probe_total")
			if len(sets) != 1 || targetRnicValues(sets[0]) != tc.want {
				t.Errorf("target_rnic.probe_total attributes = %v, want target labels %v", sets, tc.want)
			}
		})
	}
}

// TestRecordProbeResult_TargetRnicOverflowIsolated verifies that when the
// target_rnic instruments exceed the cardinality limit, only they fold into
// the overflow series: the default ToR-level series stay intact.
func TestRecordProbeResult_TargetRnicOverflowIsolated(t *testing.T) {
	const limit = 3
	var results []*probe.ProbeResult
	for i := 0; i < 10; i++ {
		results = append(results, successfulResult(fmt.Sprintf("host-%d", i), "mlx5_0", "ens1f0", false))
	}
	rm := collectFrom(t, []sdkmetric.Option{sdkmetric.WithCardinalityLimit(limit)},
		[]Option{WithTargetRnicLabels(TargetRnicLabels{Enabled: true})}, results...)

	overflow := attribute.Key("otel.metric.overflow")
	targetSets := otelmetrics.DataPointAttrs(t, rm, "rpingmesh.target_rnic.probe_total")
	var sawOverflow bool
	for _, set := range targetSets {
		if _, ok := set.Value(overflow); ok {
			sawOverflow = true
		}
	}
	if !sawOverflow {
		t.Fatalf("target_rnic.probe_total did not overflow at limit %d: %v", limit, targetSets)
	}

	sets := otelmetrics.DataPointAttrs(t, rm, "rpingmesh.probe_total")
	if len(sets) != 1 {
		t.Fatalf("probe_total has %d series, want 1 ToR-level series", len(sets))
	}
	if _, ok := sets[0].Value(overflow); ok {
		t.Errorf("probe_total folded into the overflow series: %v", sets[0].ToSlice())
	}
	if v, _ := sets[0].Value("target_tor"); v.AsString() != "tor-a" {
		t.Errorf("probe_total target_tor = %q, want tor-a", v.AsString())
	}
}
