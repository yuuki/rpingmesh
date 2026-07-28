package probe

import (
	"math"
	"sort"
	"sync"
)

// PathKey identifies a single probe path: the source RNIC (this agent) and the
// target RNIC. Aggregation is keyed by (source, target) rather than by target
// alone so that a multi-rail host, where several local RNICs probe the same
// target, keeps each source RNIC's path distinct.
type PathKey struct {
	SourceGID [16]byte
	TargetGID [16]byte
}

// PathSummary is a window-aggregated summary of one probe path. It mirrors the
// controller_agent.PathSummary proto but lives in the RDMA-independent probe
// package so aggregation stays pure Go and unit-testable. SourceTorID is not
// carried here: it is an agent-wide constant that the analysis reporter stamps
// when translating to proto.
type PathSummary struct {
	SourceGID         [16]byte
	TargetGID         [16]byte
	TargetTorID       string
	TargetQPN         uint32
	WindowStartUnixNs uint64
	WindowDurationMs  uint32
	ProbeTotal        uint32
	ProbeSuccess      uint32
	ProbeFailed       uint32
	InvalidRTTCount   uint32
	NetworkRTTMinNs   uint64
	NetworkRTTMaxNs   uint64
	NetworkRTTP50Ns   uint64
	NetworkRTTP99Ns   uint64
}

// rttBucketBoundariesNs are the upper bounds (nanoseconds) of the fixed
// histogram buckets used to estimate RTT percentiles without retaining every
// sample. They span 100ns to 10ms, the datacenter-RDMA RTT range, matching the
// telemetry package's histogram boundaries. A value greater than the last
// boundary falls into an implicit overflow bucket whose representative value is
// the last boundary (percentiles are conservative upper-bound estimates). Exact
// min/max are tracked separately, so extremes are never lost to bucketing.
var rttBucketBoundariesNs = []uint64{
	100, 250, 500, 1_000, 2_500, 5_000, 10_000,
	25_000, 50_000, 100_000, 250_000, 500_000,
	1_000_000, 2_500_000, 5_000_000, 10_000_000,
}

// pathAccumulator accumulates probe outcomes for one path within one window.
type pathAccumulator struct {
	windowStartNs uint64
	targetTorID   string
	targetQPN     uint32

	total      uint32
	success    uint32
	failed     uint32
	invalidRTT uint32

	hasRTT bool
	minRTT uint64
	maxRTT uint64
	// buckets[i] counts valid RTT samples whose value is <=
	// rttBucketBoundariesNs[i] and > the previous boundary; the final element
	// (len == len(boundaries)+1) is the overflow bucket.
	buckets []uint64
}

func newPathAccumulator(windowStartNs uint64, targetTorID string, targetQPN uint32) *pathAccumulator {
	return &pathAccumulator{
		windowStartNs: windowStartNs,
		targetTorID:   targetTorID,
		targetQPN:     targetQPN,
		buckets:       make([]uint64, len(rttBucketBoundariesNs)+1),
	}
}

// observeRTT records one valid network-RTT sample (nanoseconds).
func (a *pathAccumulator) observeRTT(v uint64) {
	if !a.hasRTT || v < a.minRTT {
		a.minRTT = v
	}
	if !a.hasRTT || v > a.maxRTT {
		a.maxRTT = v
	}
	a.hasRTT = true

	idx := sort.Search(len(rttBucketBoundariesNs), func(i int) bool {
		return v <= rttBucketBoundariesNs[i]
	})
	a.buckets[idx]++
}

// quantile returns the estimated q-quantile (0..1) of the observed valid RTTs,
// as the upper boundary of the bucket containing the target rank. Returns 0
// when no valid RTT was observed. The exact min/max clamp the estimate so a
// coarse bucket never reports a value outside the observed range.
func (a *pathAccumulator) quantile(q float64) uint64 {
	if !a.hasRTT || a.success == 0 {
		return 0
	}
	// Nearest-rank method (1-indexed): rank = ceil(q * n). Round-half-up
	// (q*n + 0.5) is wrong -- it can pick a rank one below ceil(q*n) and so
	// miss a rare slow tail. E.g. n=151, q=0.99: ceil(0.99*151)=ceil(149.49)=150,
	// but round-half-up gives round(149.99)=149, landing one rank too low (in
	// the fast bucket) and hiding a 2-of-151 p99 breach. The small epsilon
	// absorbs float error so an integer-valued q*n (e.g. from q=0.9) is not
	// nudged up a whole rank by a representation like 9.0000000000000002.
	rank := uint64(math.Ceil(q*float64(a.success) - 1e-9))
	if rank < 1 {
		rank = 1
	}
	if rank > uint64(a.success) {
		rank = uint64(a.success)
	}

	var cum uint64
	for i, c := range a.buckets {
		cum += c
		if cum >= rank {
			var est uint64
			if i < len(rttBucketBoundariesNs) {
				est = rttBucketBoundariesNs[i]
			} else {
				// Overflow bucket: best available upper bound is the observed max.
				est = a.maxRTT
			}
			if est < a.minRTT {
				est = a.minRTT
			}
			if est > a.maxRTT {
				est = a.maxRTT
			}
			return est
		}
	}
	return a.maxRTT
}

// summary finalizes the accumulator into a PathSummary for the given path key
// and window duration.
func (a *pathAccumulator) summary(key PathKey, windowDurationMs uint32) PathSummary {
	return PathSummary{
		SourceGID:         key.SourceGID,
		TargetGID:         key.TargetGID,
		TargetTorID:       a.targetTorID,
		TargetQPN:         a.targetQPN,
		WindowStartUnixNs: a.windowStartNs,
		WindowDurationMs:  windowDurationMs,
		ProbeTotal:        a.total,
		ProbeSuccess:      a.success,
		ProbeFailed:       a.failed,
		InvalidRTTCount:   a.invalidRTT,
		NetworkRTTMinNs:   a.minRTT,
		NetworkRTTMaxNs:   a.maxRTT,
		NetworkRTTP50Ns:   a.quantile(0.50),
		NetworkRTTP99Ns:   a.quantile(0.99),
	}
}

// PathAggregator groups probe results into fixed, wall-clock-aligned windows
// per path key and emits one PathSummary per (path, completed window). It is
// pure Go and safe for concurrent use: AddResult (called from the fan-in feed)
// and Collect/Flush (called by the reporter) may run on different goroutines.
//
// Windows are aligned to multiples of windowNs so that every path shares the
// same window boundaries, which makes cross-path comparison at the controller
// straightforward. A path that stops probing is pruned automatically: once its
// current window elapses, Collect finalizes and removes it, so the internal map
// never grows without bound under path churn.
type PathAggregator struct {
	windowNs uint64

	mu    sync.Mutex
	paths map[PathKey]*pathAccumulator
	// ready holds summaries for windows that rolled over inside AddResult
	// (a result arrived for a newer window than the path's open accumulator)
	// before Collect had a chance to harvest them, so no window is ever lost.
	ready []PathSummary
}

// NewPathAggregator creates a PathAggregator with the given window length in
// nanoseconds. A non-positive windowNs is clamped to 1ns to avoid a divide by
// zero; callers should pass a sane value (e.g. 30s).
func NewPathAggregator(windowNs uint64) *PathAggregator {
	if windowNs == 0 {
		windowNs = 1
	}
	return &PathAggregator{
		windowNs: windowNs,
		paths:    make(map[PathKey]*pathAccumulator),
	}
}

// windowStart returns the aligned start of the window containing tsNs.
func (p *PathAggregator) windowStart(tsNs uint64) uint64 {
	return (tsNs / p.windowNs) * p.windowNs
}

// AddResult folds one probe result into the accumulator for its path and the
// window containing recvUnixNs (the wall-clock ingestion time; probe timestamps
// are CLOCK_MONOTONIC and must not be used for windowing). A result whose path
// jumps to a newer window finalizes the path's previous window into the ready
// list first.
func (p *PathAggregator) AddResult(r *ProbeResult, recvUnixNs uint64) {
	if r == nil {
		return
	}
	key := PathKey{SourceGID: r.SourceGID, TargetGID: r.TargetGID}
	ws := p.windowStart(recvUnixNs)

	p.mu.Lock()
	defer p.mu.Unlock()

	acc := p.paths[key]
	if acc != nil && acc.windowStartNs != ws {
		// The path moved to a different window; finalize the old one so its
		// data is not overwritten, then start fresh.
		p.ready = append(p.ready, acc.summary(key, p.windowDurationMs()))
		acc = nil
	}
	if acc == nil {
		acc = newPathAccumulator(ws, r.TargetTorID, r.TargetQPN)
		p.paths[key] = acc
	}

	acc.total++
	if !r.Success {
		acc.failed++
		return
	}
	rtt := CalculateRTT(r)
	if !rtt.Valid {
		acc.invalidRTT++
		return
	}
	acc.success++
	acc.observeRTT(uint64(rtt.NetworkRTT))
}

func (p *PathAggregator) windowDurationMs() uint32 {
	return uint32(p.windowNs / 1_000_000)
}

// Collect finalizes and returns summaries for every window that has fully
// elapsed as of nowUnixNs, removing those accumulators. Paths still within
// their current window are left untouched. Summaries buffered by a window
// rollover in AddResult are always returned. The returned slice is nil when
// nothing is ready.
func (p *PathAggregator) Collect(nowUnixNs uint64) []PathSummary {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := p.ready
	p.ready = nil

	dur := p.windowDurationMs()
	for key, acc := range p.paths {
		if acc.windowStartNs+p.windowNs <= nowUnixNs {
			out = append(out, acc.summary(key, dur))
			delete(p.paths, key)
		}
	}
	return out
}

// Flush finalizes and returns summaries for ALL accumulators regardless of
// whether their window has elapsed, clearing the aggregator. It is intended for
// shutdown, so a final partial window is not silently dropped.
func (p *PathAggregator) Flush() []PathSummary {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := p.ready
	p.ready = nil

	dur := p.windowDurationMs()
	for key, acc := range p.paths {
		out = append(out, acc.summary(key, dur))
		delete(p.paths, key)
	}
	return out
}
