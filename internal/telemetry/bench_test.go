package telemetry

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/testutil/otelmetrics"
)

// BenchmarkRecordProbeResult measures the metrics cost of one completed
// probe, recorded on every probe of every target, at the default log level
// (info): the per-probe detail is a Debug log that would otherwise dominate.
func BenchmarkRecordProbeResult(b *testing.B) {
	level := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	b.Cleanup(func() { zerolog.SetGlobalLevel(level) })

	provider, _ := otelmetrics.NewManualProvider(b)
	mc, err := NewMetricsCollectorWithProvider(provider)
	if err != nil {
		b.Fatal(err)
	}
	r := &probe.ProbeResult{
		T1: 100_000, T2: 101_000, T3: 200_000, T4: 202_000, T5: 301_000, T6: 302_000,
		Success: true, TargetTorID: "tor-b", SourceRdmaDevice: "mlx5_0", SourceNetdev: "ens1f0",
	}
	rtt := probe.CalculateRTT(r)
	b.ReportAllocs()
	for b.Loop() {
		mc.RecordProbeResult(r, rtt, "tor-a")
	}
}
