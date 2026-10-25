package telemetry

import (
	"context"
	"testing"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestServiceLabelsProbeMetrics(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		mc, reader := newTestCollector(t, WithServiceTracing(true), WithServiceLabels(func() []string {
			if enabled {
				return []string{"training", "tenant"}
			}
			return nil
		}()))
		r := serviceResult()
		r.Services = []string{"training", "training", "tenant", "pid-123", "pid-456"}
		mc.RecordProbeResult(r, probe.CalculateRTT(r), "tor-a")
		failed := *r
		failed.Success, failed.FailureReason = false, probe.FailureSendError
		mc.RecordProbeResult(&failed, nil, "tor-a")
		invalid := *r
		invalid.T2 = invalid.T1 - 1
		mc.RecordProbeResult(&invalid, probe.CalculateRTT(&invalid), "tor-a")
		unknown := serviceResult()
		mc.RecordProbeResult(unknown, probe.CalculateRTT(unknown), "tor-a")
		rm := new(metricdata.ResourceMetrics)
		if err := reader.Collect(context.Background(), rm); err != nil {
			t.Fatal(err)
		}
		names := append(append([]string{}, serviceProbeMetrics...), "rpingmesh.service.probe_failed_total", "rpingmesh.service.probe_invalid_total")
		for _, name := range names {
			for _, attrs := range otelmetrics.DataPointAttrs(t, rm, name) {
				v, exists := attrs.Value(attribute.Key("service"))
				if enabled {
					if !exists || (v.AsString() != "training" && v.AsString() != "tenant" && v.AsString() != "_unspecified") {
						t.Errorf("%s service = %v", name, v)
					}
				} else if exists {
					t.Errorf("disabled %s has service", name)
				}
				for _, key := range []string{"pid", "comm", "cgroup_id", "cgroup_path"} {
					if _, exists := attrs.Value(attribute.Key(key)); exists {
						t.Errorf("%s exposes %s", name, key)
					}
				}
			}
		}
		if enabled {
			by := otelmetrics.TotalByAttr(t, rm, "rpingmesh.service.probe_total", "service")
			if by["training"] != 3 || by["tenant"] != 3 || by["_unspecified"] != 4 {
				t.Errorf("totals = %v", by)
			}
		} else if got := otelmetrics.Total(t, rm, "rpingmesh.service.probe_total"); got != 4 {
			t.Errorf("total=%d, want 4", got)
		}
		if otelmetrics.Find(rm, "rpingmesh.probe_total") != nil {
			t.Fatal("service labels leaked into cluster metrics")
		}
	}
}

func TestServiceLabelsGauges(t *testing.T) {
	mc, reader := newTestCollector(t, WithServiceTracing(true), WithServiceLabels([]string{"training"}))
	if err := mc.RegisterServiceTracingCallback(func() ServiceTracingSample {
		return ServiceTracingSample{Devices: []ServiceTracingDevice{
			{RdmaDevice: "mlx5_0", Service: "training", Connections: 3, FlowsProbed: 1},
			{RdmaDevice: "mlx5_0", Service: "unknown-a", Connections: 2, FlowsUnresolved: 1},
			{RdmaDevice: "mlx5_0", Service: "unknown-b", Connections: 4, FlowsProbed: 2},
		}}
	}); err != nil {
		t.Fatal(err)
	}
	rm := new(metricdata.ResourceMetrics)
	if err := reader.Collect(context.Background(), rm); err != nil {
		t.Fatal(err)
	}
	m := otelmetrics.Find(rm, "rpingmesh.agent.service_connections")
	g := m.Data.(metricdata.Gauge[int64])
	if len(g.DataPoints) != 2 {
		t.Fatalf("connections = %v", g.DataPoints)
	}
	for _, dp := range g.DataPoints {
		v, _ := dp.Attributes.Value(attribute.Key("service"))
		want := int64(3)
		if v.AsString() == "_unspecified" {
			want = 6
		}
		if dp.Value != want {
			t.Errorf("%s=%d want %d", v.AsString(), dp.Value, want)
		}
	}
	for _, dp := range otelmetrics.Find(rm, "rpingmesh.agent.service_flows").Data.(metricdata.Gauge[int64]).DataPoints {
		if _, ok := dp.Attributes.Value(attribute.Key("service")); !ok {
			t.Fatal("flows missing service")
		}
	}
}
