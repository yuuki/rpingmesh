package probe

import (
	"testing"
)

const (
	testWindowNs = uint64(1_000_000_000) // 1s windows
	// recvNs anchors for two adjacent windows.
	win0Recv = uint64(500_000_000)   // in [0, 1e9)
	win1Recv = uint64(1_500_000_000) // in [1e9, 2e9)
)

func gid(b byte) [16]byte {
	var g [16]byte
	g[15] = b
	return g
}

// validResult builds a Success result whose 6 timestamps yield exactly
// networkRTTNs of NetworkRTT (with a fixed, valid ResponderDelay=500 and
// ProberDelay=100), so tests can drive specific RTT samples through the
// bucketed quantile estimator.
func validResult(src, tgt [16]byte, tor string, qpn uint32, networkRTTNs uint64) *ProbeResult {
	return &ProbeResult{
		SourceGID:   src,
		TargetGID:   tgt,
		TargetTorID: tor,
		TargetQPN:   qpn,
		Success:     true,
		T1:          1000,
		T2:          2000,
		T3:          3000,
		T4:          3500,
		T5:          networkRTTNs + 2500,
		T6:          networkRTTNs + 1600,
	}
}

func failedResult(src, tgt [16]byte, tor string) *ProbeResult {
	return &ProbeResult{
		SourceGID:    src,
		TargetGID:    tgt,
		TargetTorID:  tor,
		Success:      false,
		ErrorMessage: "timed out waiting for ACKs",
	}
}

// invalidRTTResult is Success (all 6 timestamps present) but the RTT fails
// validation (negative NetworkRTT), so it counts as invalid_rtt, not loss.
func invalidRTTResult(src, tgt [16]byte, tor string) *ProbeResult {
	return &ProbeResult{
		SourceGID:   src,
		TargetGID:   tgt,
		TargetTorID: tor,
		Success:     true,
		T1:          1000,
		T2:          2000,
		T3:          3000,
		T4:          3500,
		T5:          2100, // NetworkRTT = (2100-2000)-500 = -400 -> invalid
		T6:          3000,
	}
}

func TestPathAggregator_CountsAndLoss(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	// 6 valid, 3 failed, 1 invalid -> total 10, loss 3/10.
	for i := 0; i < 6; i++ {
		agg.AddResult(validResult(src, tgt, "tor-b", 42, 1000), win0Recv)
	}
	for i := 0; i < 3; i++ {
		agg.AddResult(failedResult(src, tgt, "tor-b"), win0Recv)
	}
	agg.AddResult(invalidRTTResult(src, tgt, "tor-b"), win0Recv)

	summaries := agg.Collect(win1Recv) // window0 is complete at 1.5e9
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]

	if s.ProbeTotal != 10 {
		t.Errorf("ProbeTotal = %d, want 10", s.ProbeTotal)
	}
	if s.ProbeSuccess != 6 {
		t.Errorf("ProbeSuccess = %d, want 6", s.ProbeSuccess)
	}
	if s.ProbeFailed != 3 {
		t.Errorf("ProbeFailed = %d, want 3", s.ProbeFailed)
	}
	if s.InvalidRTTCount != 1 {
		t.Errorf("InvalidRTTCount = %d, want 1", s.InvalidRTTCount)
	}
	if s.TargetTorID != "tor-b" || s.TargetQPN != 42 {
		t.Errorf("target metadata not carried: tor=%q qpn=%d", s.TargetTorID, s.TargetQPN)
	}
	if s.SourceGID != src || s.TargetGID != tgt {
		t.Errorf("path key not carried on summary")
	}
	if s.WindowStartUnixNs != 0 {
		t.Errorf("WindowStartUnixNs = %d, want 0 (aligned window0 start)", s.WindowStartUnixNs)
	}
	if s.WindowDurationMs != 1000 {
		t.Errorf("WindowDurationMs = %d, want 1000", s.WindowDurationMs)
	}
}

func TestPathAggregator_RTTStats(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	// Samples: 1us x many small, plus one large 8ms max, one small 100ns min.
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 100), win0Recv) // min
	for i := 0; i < 98; i++ {
		agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv) // 1us cluster
	}
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 8_000_000), win0Recv) // max, drives p99

	summaries := agg.Collect(win1Recv)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]

	if s.ProbeSuccess != 100 {
		t.Fatalf("ProbeSuccess = %d, want 100", s.ProbeSuccess)
	}
	if s.NetworkRTTMinNs != 100 {
		t.Errorf("min = %d, want 100", s.NetworkRTTMinNs)
	}
	if s.NetworkRTTMaxNs != 8_000_000 {
		t.Errorf("max = %d, want 8000000", s.NetworkRTTMaxNs)
	}
	// p50 should land in the 1us cluster's bucket (<= 1000ns boundary).
	if s.NetworkRTTP50Ns != 1000 {
		t.Errorf("p50 = %d, want 1000 (1us bucket upper bound)", s.NetworkRTTP50Ns)
	}
	// p99: rank = ceil(0.99*100) = 99, still inside the 1us cluster (99 of the
	// first 99 samples are <= 1us); the single 8ms sample is rank 100. So p99
	// estimates the 1us bucket, and must never exceed the observed max.
	if s.NetworkRTTP99Ns < 1000 || s.NetworkRTTP99Ns > s.NetworkRTTMaxNs {
		t.Errorf("p99 = %d, want in [1000, %d]", s.NetworkRTTP99Ns, s.NetworkRTTMaxNs)
	}
}

func TestPathAggregator_P99CapturesTail(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	// 90 fast (1us) + 10 slow (5ms): p99 must reflect the slow tail.
	for i := 0; i < 90; i++ {
		agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv)
	}
	for i := 0; i < 10; i++ {
		agg.AddResult(validResult(src, tgt, "tor-b", 1, 5_000_000), win0Recv)
	}

	s := agg.Collect(win1Recv)[0]
	// rank for p99 = 99 -> falls in the slow cluster (ranks 91..100).
	if s.NetworkRTTP99Ns < 1_000_000 {
		t.Errorf("p99 = %d, want >= 1ms (tail captured)", s.NetworkRTTP99Ns)
	}
	// p50 = rank 50 -> fast cluster.
	if s.NetworkRTTP50Ns != 1000 {
		t.Errorf("p50 = %d, want 1000", s.NetworkRTTP50Ns)
	}
}

// TestPathAggregator_P99NearestRankCapturesRareTail is the Codex counterexample
// for the off-by-one in the old round-half-up rank: 151 valid samples with only
// 2 slow ones. Nearest-rank p99 = ceil(0.99*151) = ceil(149.49) = 150, which
// lands on a slow sample; round-half-up gives round(149.99) = 149 (the fast
// bucket) and would hide the SLA breach.
func TestPathAggregator_P99NearestRankCapturesRareTail(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	for i := 0; i < 149; i++ {
		agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv) // fast (1us)
	}
	for i := 0; i < 2; i++ {
		agg.AddResult(validResult(src, tgt, "tor-b", 1, 5_000_000), win0Recv) // slow (5ms)
	}

	s := agg.Collect(win1Recv)[0]
	if s.ProbeSuccess != 151 {
		t.Fatalf("ProbeSuccess = %d, want 151", s.ProbeSuccess)
	}
	if s.NetworkRTTP99Ns < 5_000_000 {
		t.Errorf("p99 = %d, want >= 5000000: nearest-rank must capture the 2-of-151 slow tail",
			s.NetworkRTTP99Ns)
	}
	// The median stays firmly in the fast bucket.
	if s.NetworkRTTP50Ns != 1000 {
		t.Errorf("p50 = %d, want 1000", s.NetworkRTTP50Ns)
	}
}

// TestPathAggregator_P50NearestRank pins p50 (q=0.5) nearest-rank behavior for
// odd and even sample counts: rank = ceil(n/2). p50 is unchanged by the fix
// (round-half-up equals ceil at q=0.5), so these must stay consistent with the
// other percentile tests.
func TestPathAggregator_P50NearestRank(t *testing.T) {
	const (
		fastNs = uint64(1000)      // 1us -> "fast" bucket
		slowNs = uint64(5_000_000) // 5ms -> "slow" bucket
	)
	cases := []struct {
		name       string
		fast, slow int
		wantP50    uint64
	}{
		// even n=4: rank ceil(2)=2, among the 2 fast -> fast bucket.
		{"even_n4_rank2_fast", 2, 2, fastNs},
		// odd n=3: rank ceil(1.5)=2, 2nd smallest of [fast, slow, slow] -> slow.
		{"odd_n3_rank2_slow", 1, 2, slowNs},
		// odd n=5: rank ceil(2.5)=3, 3rd smallest of [fast x3, slow x2] -> fast.
		{"odd_n5_rank3_fast", 3, 2, fastNs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, tgt := gid(1), gid(2)
			agg := NewPathAggregator(testWindowNs)
			for i := 0; i < tc.fast; i++ {
				agg.AddResult(validResult(src, tgt, "tor-b", 1, fastNs), win0Recv)
			}
			for i := 0; i < tc.slow; i++ {
				agg.AddResult(validResult(src, tgt, "tor-b", 1, slowNs), win0Recv)
			}
			s := agg.Collect(win1Recv)[0]
			if s.NetworkRTTP50Ns != tc.wantP50 {
				t.Errorf("p50 = %d, want %d", s.NetworkRTTP50Ns, tc.wantP50)
			}
		})
	}
}

func TestPathAggregator_WindowBoundary(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	// Two probes in window0, three in window1 for the same path.
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv)
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv)
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win1Recv)
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win1Recv)
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win1Recv)

	// Collect only window0 (now=1.5e9): window1 is still open.
	first := agg.Collect(win1Recv)
	if len(first) != 1 {
		t.Fatalf("expected 1 window0 summary, got %d", len(first))
	}
	if first[0].ProbeTotal != 2 || first[0].WindowStartUnixNs != 0 {
		t.Errorf("window0 summary wrong: total=%d start=%d", first[0].ProbeTotal, first[0].WindowStartUnixNs)
	}

	// Now collect window1 (now=2.5e9).
	second := agg.Collect(2_500_000_000)
	if len(second) != 1 {
		t.Fatalf("expected 1 window1 summary, got %d", len(second))
	}
	if second[0].ProbeTotal != 3 || second[0].WindowStartUnixNs != testWindowNs {
		t.Errorf("window1 summary wrong: total=%d start=%d", second[0].ProbeTotal, second[0].WindowStartUnixNs)
	}
}

func TestPathAggregator_RolloverPreservesOldWindow(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	// A result in window0, then a later result for the SAME path in window1
	// (before any Collect). The rollover must preserve window0's data.
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv)
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win1Recv)

	// Collecting at a time past window1 yields BOTH windows.
	got := agg.Collect(2_500_000_000)
	if len(got) != 2 {
		t.Fatalf("expected 2 summaries (window0 rolled over + window1), got %d", len(got))
	}
}

func TestPathAggregator_ChurnPruning(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv)

	// Collect the completed window: the path must be removed from the map so a
	// path that goes silent does not accumulate memory.
	if got := agg.Collect(win1Recv); len(got) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(got))
	}
	// A second collect (nothing new added) must be empty: the path was pruned.
	if got := agg.Collect(2_500_000_000); len(got) != 0 {
		t.Errorf("expected 0 summaries after pruning, got %d", len(got))
	}
	// Flush must also be empty.
	if got := agg.Flush(); len(got) != 0 {
		t.Errorf("expected 0 summaries from Flush after pruning, got %d", len(got))
	}
}

func TestPathAggregator_MultiPathDistinctKeys(t *testing.T) {
	agg := NewPathAggregator(testWindowNs)

	srcA, srcB := gid(1), gid(2)
	tgt := gid(9)

	// Two source RNICs probing the same target (multi-rail): distinct paths.
	agg.AddResult(validResult(srcA, tgt, "tor-b", 1, 1000), win0Recv)
	agg.AddResult(validResult(srcB, tgt, "tor-b", 1, 1000), win0Recv)
	// Same source, different target: another distinct path.
	agg.AddResult(validResult(srcA, gid(10), "tor-c", 1, 1000), win0Recv)

	got := agg.Collect(win1Recv)
	if len(got) != 3 {
		t.Fatalf("expected 3 distinct path summaries, got %d", len(got))
	}
}

func TestPathAggregator_Flush(t *testing.T) {
	src, tgt := gid(1), gid(2)
	agg := NewPathAggregator(testWindowNs)

	// Add to an OPEN (not yet complete) window; Collect must not return it, but
	// Flush must.
	agg.AddResult(validResult(src, tgt, "tor-b", 1, 1000), win0Recv)

	if got := agg.Collect(win0Recv); len(got) != 0 {
		t.Fatalf("Collect returned an in-progress window: %d summaries", len(got))
	}
	if got := agg.Flush(); len(got) != 1 {
		t.Fatalf("Flush should return the in-progress window, got %d", len(got))
	}
}
