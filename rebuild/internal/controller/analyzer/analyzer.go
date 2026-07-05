// Package analyzer implements the controller-side, Phase 1 R-Pingmesh analyzer:
// it ingests per-path window summaries reported by agents, retains the most
// recent windows in memory, and flags per-path SLA violations (loss ratio and
// p99 network-RTT threshold breaches).
//
// It is deliberately in-process with the controller (a separate package so it
// can later be split into a standalone binary): the topology needed for
// cross-agent fault localization already lives in the controller's registry.
// Phase 1 does no topology join; switch/link localization is Phase 2.
package analyzer

import (
	"context"
	"sort"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// Violation kinds, used as the "kind" metric attribute and in finding logs.
const (
	KindLoss = "loss"
	KindRTT  = "rtt"
)

// Config holds the analyzer's SLA thresholds and retention.
type Config struct {
	// SLALossRatio is the per-path loss ratio (probe_failed / probe_total)
	// above which a window is flagged as a loss violation.
	SLALossRatio float64
	// SLANetworkRTTP99Ns is the per-path p99 network-RTT threshold (ns) above
	// which a window is flagged as an RTT violation. 0 disables the RTT check.
	SLANetworkRTTP99Ns uint64
	// WindowRetention is the number of distinct windows retained in the
	// in-memory ring (oldest evicted first). Must be >= 1.
	WindowRetention int
}

// windowBucket groups the summaries retained for one aggregation window,
// identified by its wall-clock start. Kept for recency/retention and as the
// substrate a future Phase 2 cross-agent localization pass would read.
type windowBucket struct {
	windowStartUnixNs uint64
	summaries         []*controller_agent.PathSummary
}

// Analyzer ingests reported summaries, retains recent windows, and detects SLA
// violations. It is safe for concurrent use (Ingest may be called from many
// gRPC handler goroutines).
type Analyzer struct {
	cfg     Config
	metrics *Metrics
	logger  zerolog.Logger

	mu sync.Mutex
	// ring holds recent window buckets sorted ascending by windowStartUnixNs;
	// its length is capped at cfg.WindowRetention.
	ring []*windowBucket
}

// New creates an Analyzer with the given config and metrics (metrics may be
// nil, in which case findings are logged but no OTLP metrics are emitted).
// WindowRetention is clamped to at least 1.
func New(cfg Config, metrics *Metrics) *Analyzer {
	if cfg.WindowRetention < 1 {
		cfg.WindowRetention = 1
	}
	return &Analyzer{
		cfg:     cfg,
		metrics: metrics,
		logger:  log.With().Str("component", "analyzer").Logger(),
	}
}

// Ingest processes one reported batch of per-path window summaries: it records
// each summary, evaluates SLA thresholds, emits findings (logs + metrics), and
// retains the summaries in the in-memory window ring. It returns the number of
// summaries flagged with at least one SLA violation.
func (a *Analyzer) Ingest(ctx context.Context, report *controller_agent.ProbeAnalysisReport) int {
	if report == nil {
		return 0
	}

	agentID := report.GetAgentId()
	summaries := report.GetSummaries()

	a.mu.Lock()
	defer a.mu.Unlock()

	violatingSummaries := 0
	for _, s := range summaries {
		if s == nil {
			continue
		}
		a.metrics.recordSummary(ctx)
		a.retainLocked(s)

		if a.evaluate(ctx, agentID, s) {
			violatingSummaries++
		}
	}
	return violatingSummaries
}

// evaluate checks a single summary against the SLA thresholds, emitting a
// finding (log + metric) for each breach. It returns true if the summary
// breached at least one threshold.
func (a *Analyzer) evaluate(ctx context.Context, agentID string, s *controller_agent.PathSummary) bool {
	sourceTor := s.GetSourceTorId()
	targetTor := s.GetTargetTorId()
	violated := false

	// Loss violation: probe_failed / probe_total over the threshold. Guarded
	// by probe_total > 0 to avoid a spurious ratio on an empty window.
	if total := s.GetProbeTotal(); total > 0 {
		loss := float64(s.GetProbeFailed()) / float64(total)
		if loss > a.cfg.SLALossRatio {
			violated = true
			a.metrics.recordViolation(ctx, sourceTor, targetTor, KindLoss)
			a.logFinding(agentID, s, KindLoss).
				Float64("loss_ratio", loss).
				Float64("threshold", a.cfg.SLALossRatio).
				Msg("SLA violation: packet loss")
		}
	}

	// RTT violation: p99 network RTT over the threshold (0 disables the check).
	if a.cfg.SLANetworkRTTP99Ns > 0 && s.GetNetworkRttP99Ns() > a.cfg.SLANetworkRTTP99Ns {
		violated = true
		a.metrics.recordViolation(ctx, sourceTor, targetTor, KindRTT)
		a.logFinding(agentID, s, KindRTT).
			Uint64("p99_rtt_ns", s.GetNetworkRttP99Ns()).
			Uint64("threshold_ns", a.cfg.SLANetworkRTTP99Ns).
			Msg("SLA violation: high p99 network RTT")
	}

	return violated
}

// logFinding builds a Warn-level event pre-populated with the identifying
// fields common to every finding. GID-level detail is included here (findings
// logs), never as a metric attribute.
func (a *Analyzer) logFinding(agentID string, s *controller_agent.PathSummary, kind string) *zerolog.Event {
	return a.logger.Warn().
		Str("kind", kind).
		Str("agent_id", agentID).
		Str("source_gid", s.GetSourceGid()).
		Str("source_tor", s.GetSourceTorId()).
		Str("target_gid", s.GetTargetGid()).
		Str("target_tor", s.GetTargetTorId()).
		Uint32("probe_total", s.GetProbeTotal()).
		Uint32("probe_failed", s.GetProbeFailed()).
		Uint64("window_start_unix_ns", s.GetWindowStartUnixNs())
}

// retainLocked inserts a summary into the window ring under its window-start
// bucket, creating the bucket if needed and evicting the oldest window when the
// distinct-window count exceeds cfg.WindowRetention. Caller must hold a.mu.
func (a *Analyzer) retainLocked(s *controller_agent.PathSummary) {
	ws := s.GetWindowStartUnixNs()

	// Locate an existing bucket for this window (ring is small: retention count).
	for _, b := range a.ring {
		if b.windowStartUnixNs == ws {
			b.summaries = append(b.summaries, s)
			return
		}
	}

	// New window: insert keeping the ring sorted ascending by window start.
	b := &windowBucket{windowStartUnixNs: ws, summaries: []*controller_agent.PathSummary{s}}
	idx := sort.Search(len(a.ring), func(i int) bool {
		return a.ring[i].windowStartUnixNs >= ws
	})
	a.ring = append(a.ring, nil)
	copy(a.ring[idx+1:], a.ring[idx:])
	a.ring[idx] = b

	// Evict oldest windows beyond the retention cap.
	if len(a.ring) > a.cfg.WindowRetention {
		a.ring = a.ring[len(a.ring)-a.cfg.WindowRetention:]
	}
}

// RetainedWindows returns the number of distinct windows currently retained in
// the ring. Exposed for tests and diagnostics.
func (a *Analyzer) RetainedWindows() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.ring)
}
