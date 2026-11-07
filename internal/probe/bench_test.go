package probe

import "testing"

// Benchmarks of the per-probe path: every completed probe is checked by
// CalculateRTT and folded into the analysis aggregator, and every target's
// flow-label set is expanded on each pinglist refresh and rotation.

func benchResult() *ProbeResult {
	return &ProbeResult{
		SourceGID: [16]byte{15: 1}, TargetGID: [16]byte{15: 2},
		T1: 100_000, T2: 101_000, T3: 200_000, T4: 202_000, T5: 301_000, T6: 302_000,
		Success: true, PinglistType: PinglistTorMesh,
	}
}

func BenchmarkCalculateRTT(b *testing.B) {
	r := benchResult()
	b.ReportAllocs()
	for b.Loop() {
		if !CalculateRTT(r).Valid {
			b.Fatal("invalid RTT")
		}
	}
}

func BenchmarkPathAggregatorAddResult(b *testing.B) {
	agg := NewPathAggregator(30_000_000_000)
	r := benchResult()
	var ts uint64
	b.ReportAllocs()
	for b.Loop() {
		ts += 1_000_000 // one probe per millisecond on one path
		agg.AddResult(r, ts)
	}
}

func BenchmarkGenerateFlowLabels(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		GenerateFlowLabels(0x12345, 64, 7)
	}
}
