package telemetry

import (
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// serviceProbeMetrics are the service instruments a successful probe
// exports (probe_failed_total has no data point until a failure).
var serviceProbeMetrics = []string{
	"rpingmesh.service.probe_total", "rpingmesh.service.probe_success_total",
	"rpingmesh.service.network_rtt_ns", "rpingmesh.service.prober_delay_ns",
	"rpingmesh.service.responder_delay_ns",
}

func serviceResult() *probe.ProbeResult {
	r := successfulResult("host-b", "mlx5_1", "ens2f0", false)
	r.ServiceTracing = true
	return r
}

// TestRecordProbeResult_ServiceTracingSeparateInstruments verifies that a
// service-tracing probe is recorded on the rpingmesh.service.* instruments
// only: never on the default cluster instruments, never on the
// destination-RNIC ones.
func TestRecordProbeResult_ServiceTracingSeparateInstruments(t *testing.T) {
	rm := recordAndCollect(t,
		[]Option{WithServiceTracing(true), WithTargetRnicLabels(TargetRnicLabels{Enabled: true, Histograms: true})},
		serviceResult(), successfulResult("host-c", "mlx5_2", "ens3f0", false))

	for _, name := range serviceProbeMetrics {
		if otelmetrics.Find(rm, name) == nil {
			t.Errorf("%s was not exported", name)
		}
	}
	if got := otelmetrics.Total(t, rm, "rpingmesh.service.probe_total"); got != 1 {
		t.Errorf("rpingmesh.service.probe_total = %d, want 1", got)
	}
	if got := otelmetrics.Total(t, rm, "rpingmesh.probe_total"); got != 1 {
		t.Errorf("rpingmesh.probe_total = %d, want 1 (the cluster probe only)", got)
	}
	if got := otelmetrics.Total(t, rm, "rpingmesh.target_rnic.probe_total"); got != 1 {
		t.Errorf("rpingmesh.target_rnic.probe_total = %d, want 1 (the cluster probe only)", got)
	}
	for _, set := range otelmetrics.DataPointAttrs(t, rm, "rpingmesh.service.probe_total") {
		if !otelmetrics.HasAttributes(set, map[string]string{
			"source_tor": "tor-a", "target_tor": "tor-a", "source_rdma_device": "mlx5_0", "source_netdev": "ens1f0",
		}) || hasTargetRnicLabels(set) {
			t.Errorf("service probe attributes = %v", set.ToSlice())
		}
	}
}

// TestRecordProbeResult_ServiceTracingWithoutOption verifies that without
// WithServiceTracing a service-tracing probe is recorded nowhere.
func TestRecordProbeResult_ServiceTracingWithoutOption(t *testing.T) {
	rm := recordAndCollect(t, nil, serviceResult())
	if m := otelmetrics.Find(rm, "rpingmesh.service.probe_total"); m != nil {
		t.Error("rpingmesh.service.probe_total exported without WithServiceTracing")
	}
	if m := otelmetrics.Find(rm, "rpingmesh.probe_total"); m != nil {
		t.Error("a service-tracing probe leaked into rpingmesh.probe_total")
	}
}

// TestRecordProbeResult_ServiceTracingFailure verifies the failure path of
// the service instruments carries the reason like the default ones.
func TestRecordProbeResult_ServiceTracingFailure(t *testing.T) {
	r := serviceResult()
	r.Success = false
	r.FailureReason = probe.FailureTimeout
	rm := recordAndCollect(t, []Option{WithServiceTracing(true)}, r)
	by := otelmetrics.TotalByAttr(t, rm, "rpingmesh.service.probe_failed_total", "reason")
	if by["timeout"] != 1 {
		t.Errorf("rpingmesh.service.probe_failed_total by reason = %v, want timeout=1", by)
	}
}

func gaugeValues(t *testing.T, rm *metricdata.ResourceMetrics, name string) map[string]int64 {
	t.Helper()
	m := otelmetrics.Find(rm, name)
	if m == nil {
		t.Fatalf("%s was not exported", name)
	}
	g, ok := m.Data.(metricdata.Gauge[int64])
	if !ok {
		t.Fatalf("%s is %T, want Gauge[int64]", name, m.Data)
	}
	out := make(map[string]int64, len(g.DataPoints))
	for _, dp := range g.DataPoints {
		out[attrKey(dp.Attributes)] = dp.Value
	}
	return out
}

func attrKey(set attribute.Set) string {
	return set.Encoded(attribute.DefaultEncoder())
}

// TestRegisterServiceTracingCallback verifies the tracer gauges and counters
// report the sample's values with bounded attributes.
func TestRegisterServiceTracingCallback(t *testing.T) {
	mc, reader := newTestCollector(t, WithServiceTracing(true))
	sample := ServiceTracingSample{
		Active: true,
		Devices: []ServiceTracingDevice{
			{RdmaDevice: "mlx5_0", Connections: 3, FlowsProbed: 2, FlowsUnresolved: 1},
			{RdmaDevice: "", Connections: 1},
		},
		Creates: 10, Connects: 5, Resets: 1, Destroys: 4, ContextCloses: 2, UnknownQPs: 7,
		RingBufferDropped: 3, ParseErrors: 2, DecodeErrors: 1,
	}
	if err := mc.RegisterServiceTracingCallback(func() ServiceTracingSample { return sample }); err != nil {
		t.Fatalf("RegisterServiceTracingCallback: %v", err)
	}
	rm := otelmetrics.Collect(t, reader)

	if got := gaugeValues(t, rm, "rpingmesh.agent.service_trace_active"); got[attrKey(*attribute.EmptySet())] != 1 {
		t.Errorf("service_trace_active = %v, want 1", got)
	}
	conns := gaugeValues(t, rm, "rpingmesh.agent.service_connections")
	if conns[attrKey(attribute.NewSet(attribute.String("source_rdma_device", "mlx5_0")))] != 3 ||
		conns[attrKey(attribute.NewSet(attribute.String("source_rdma_device", unspecifiedDeviceLabel)))] != 1 {
		t.Errorf("service_connections = %v", conns)
	}
	flows := gaugeValues(t, rm, "rpingmesh.agent.service_flows")
	probed := attrKey(attribute.NewSet(attribute.String("source_rdma_device", "mlx5_0"), attribute.String("state", "probed")))
	unresolved := attrKey(attribute.NewSet(attribute.String("source_rdma_device", "mlx5_0"), attribute.String("state", "unresolved")))
	if flows[probed] != 2 || flows[unresolved] != 1 {
		t.Errorf("service_flows = %v", flows)
	}
	events := otelmetrics.TotalByAttr(t, rm, "rpingmesh.agent.service_trace_events_total", "kind")
	for kind, want := range map[string]int64{"create": 10, "connect": 5, "reset": 1, "destroy": 4, "context_close": 2, "unknown_qp": 7} {
		if events[kind] != want {
			t.Errorf("service_trace_events_total{kind=%s} = %d, want %d", kind, events[kind], want)
		}
	}
	dropped := otelmetrics.TotalByAttr(t, rm, "rpingmesh.agent.service_trace_dropped_total", "reason")
	for reason, want := range map[string]int64{"ring_buffer": 3, "parse": 2, "decode": 1} {
		if dropped[reason] != want {
			t.Errorf("service_trace_dropped_total{reason=%s} = %d, want %d", reason, dropped[reason], want)
		}
	}
}

// TestRegisterServiceTracingCallback_RequiresOption verifies the callback
// cannot be registered without the service instruments.
func TestRegisterServiceTracingCallback_RequiresOption(t *testing.T) {
	mc, _ := newTestCollector(t)
	if err := mc.RegisterServiceTracingCallback(func() ServiceTracingSample { return ServiceTracingSample{} }); err == nil {
		t.Fatal("expected an error without WithServiceTracing")
	}
}
