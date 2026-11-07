package telemetry

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
	"github.com/yuuki/rpingmesh/internal/testutil/otlptest"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
)

// TestOTLPExport_InvalidUTF8DeviceNames: Linux accepts netdev and RDMA device
// names that are not valid UTF-8, but OTLP carries attribute values as
// protobuf strings, so one such attribute used to fail the marshaling of the
// whole export and every metric of the agent was lost.
func TestOTLPExport_InvalidUTF8DeviceNames(t *testing.T) {
	provider, reader := otelmetrics.NewManualProvider(t)
	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		t.Fatalf("NewMetricsCollectorWithProvider: %v", err)
	}
	r := &probe.ProbeResult{
		T1: 100_000, T2: 101_000, T3: 200_000, T4: 202_000, T5: 301_000, T6: 302_000,
		Success: true, TargetTorID: "tor-b", SourceRdmaDevice: "mlx5_\xff", SourceNetdev: "ens\xfe1",
	}
	mc.RecordProbeResult(r, probe.CalculateRTT(r), "tor-a")
	rm := otelmetrics.Collect(t, reader)

	collector := otlptest.Start(t, otlptest.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp, err := newOTLPExporter(ctx, config.OTLPExporterConfig{Endpoint: collector.Addr()},
		otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{Enabled: false}))
	if err != nil {
		t.Fatalf("newOTLPExporter: %v", err)
	}
	defer func() { _ = exp.Shutdown(context.Background()) }()
	if err := exp.Export(ctx, rm); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n := len(collector.Accepted()); n != 1 {
		t.Fatalf("collector accepted %d requests, want 1", n)
	}
}

// FuzzDeviceMetricLabel checks that every device, netdev and host name
// attribute is valid UTF-8 and never empty, and that a valid name passes
// through unchanged (apart from surrounding space).
func FuzzDeviceMetricLabel(f *testing.F) {
	for _, s := range []string{"mlx5_0", " ens1f0np0 ", "", "  ", "mlx5_\xff", "\xc3", "rxe0\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := deviceMetricLabel(name)
		if got == "" || !utf8.ValidString(got) {
			t.Fatalf("deviceMetricLabel(%q) = %q", name, got)
		}
		if trimmed := strings.TrimSpace(name); trimmed != "" && utf8.ValidString(trimmed) && got != trimmed {
			t.Fatalf("deviceMetricLabel(%q) = %q, want %q", name, got, trimmed)
		}
	})
}
