// Package analyzer implements the controller-side, Phase 1 R-Pingmesh analyzer:
// it ingests per-path window summaries reported by agents, retains the most
// recent windows in memory, and flags per-path SLO violations (the loss-ratio
// and p99 network-RTT SLIs of a window over their thresholds).
//
// The paper's Analyzer evaluates the cluster network and the service network
// separately. Summaries of pinglist_type SERVICE_TRACING (probes sent along
// traced application flows) are therefore judged against their own
// thresholds, and their findings carry network="service", apart from the
// cluster paths (TOR_MESH, INTER_TOR) that may lead to the same target RNIC.
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
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Violation kinds, used as the "kind" metric attribute and in finding logs.
const (
	KindLoss = "loss"
	KindRTT  = "rtt"
)

// Networks a path summary can belong to, used as the "network" metric
// attribute and in finding logs: the cluster network (the controller's
// ToR-mesh and inter-ToR pinglists) or the service network (paths of traced
// application flows).
const (
	NetworkCluster = "cluster"
	NetworkService = "service"
)

// Thresholds are the SLO thresholds one network's path windows are evaluated
// against.
type Thresholds struct {
	// LossRatio is the per-path loss ratio (probe_failed / probe_total)
	// above which a window is flagged as a loss violation.
	LossRatio float64
	// NetworkRTTP99Ns is the per-path p99 network-RTT threshold (ns) above
	// which a window is flagged as an RTT violation. 0 disables the RTT check.
	NetworkRTTP99Ns uint64
}

// Config holds the analyzer's SLO thresholds and retention.
type Config struct {
	// Cluster applies to TOR_MESH and INTER_TOR summaries (and to summaries
	// from agents that predate pinglist_type, which report 0 = TOR_MESH).
	Cluster Thresholds
	// Service applies to SERVICE_TRACING summaries.
	Service Thresholds
	// WindowRetention is the number of distinct windows retained in the
	// in-memory ring (oldest evicted first). Must be >= 1.
	WindowRetention int
	// MaxSummariesPerWindow caps how many PathSummary records are kept in a
	// single window bucket. WindowRetention only bounds distinct window
	// starts; without this cap a stuck window_start or a retry storm can
	// grow one bucket without bound. Values < 1 are replaced by
	// DefaultMaxSummariesPerWindow.
	MaxSummariesPerWindow int
}

// DefaultMaxSummariesPerWindow is applied when Config.MaxSummariesPerWindow
// is unset or non-positive. 8192 is well above a healthy per-window report
// (agents already cap a single report at 256 summaries) and still bounds
// memory if one window start is reused indefinitely.
const DefaultMaxSummariesPerWindow = 8192

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
// WindowRetention is clamped to at least 1. MaxSummariesPerWindow values
// below 1 are replaced by DefaultMaxSummariesPerWindow.
func New(cfg Config, metrics *Metrics) *Analyzer {
	if cfg.WindowRetention < 1 {
		cfg.WindowRetention = 1
	}
	if cfg.MaxSummariesPerWindow < 1 {
		cfg.MaxSummariesPerWindow = DefaultMaxSummariesPerWindow
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
		s.SourceTorId = probe.TorMetricLabel(s.GetSourceTorId())
		s.TargetTorId = probe.TorMetricLabel(s.GetTargetTorId())
		a.metrics.recordSummary(ctx)
		a.retainLocked(s)

		if a.evaluate(ctx, agentID, s) {
			violatingSummaries++
		}
	}
	return violatingSummaries
}

// networkOf classifies a summary by the pinglist its target came from: the
// service network for SERVICE_TRACING, the cluster network otherwise.
func networkOf(s *controller_agent.PathSummary) string {
	if s.GetPinglistType() == controller_agent.PinglistType_SERVICE_TRACING {
		return NetworkService
	}
	return NetworkCluster
}

// thresholdsFor returns the SLO thresholds of the given network.
func (a *Analyzer) thresholdsFor(network string) Thresholds {
	if network == NetworkService {
		return a.cfg.Service
	}
	return a.cfg.Cluster
}

// evaluate checks a single summary against the SLO thresholds of its network,
// emitting a finding (log + metric) for each breach. It returns true if the
// summary breached at least one threshold.
func (a *Analyzer) evaluate(ctx context.Context, agentID string, s *controller_agent.PathSummary) bool {
	network := networkOf(s)
	thr := a.thresholdsFor(network)
	sourceTor := s.GetSourceTorId()
	targetTor := s.GetTargetTorId()
	violated := false

	// Loss violation: probe_failed / probe_total over the threshold. Guarded
	// by probe_total > 0 to avoid a spurious ratio on an empty window.
	if total := s.GetProbeTotal(); total > 0 {
		loss := float64(s.GetProbeFailed()) / float64(total)
		if loss > thr.LossRatio {
			violated = true
			a.metrics.recordViolation(ctx, network, sourceTor, targetTor, KindLoss)
			a.logFinding(agentID, network, s, KindLoss).
				Float64("loss_ratio", loss).
				Float64("threshold", thr.LossRatio).
				Msg("SLO violation: packet loss")
		}
	}

	// RTT violation: p99 network RTT over the threshold (0 disables the check).
	if thr.NetworkRTTP99Ns > 0 && s.GetNetworkRttP99Ns() > thr.NetworkRTTP99Ns {
		violated = true
		a.metrics.recordViolation(ctx, network, sourceTor, targetTor, KindRTT)
		a.logFinding(agentID, network, s, KindRTT).
			Uint64("p99_rtt_ns", s.GetNetworkRttP99Ns()).
			Uint64("threshold_ns", thr.NetworkRTTP99Ns).
			Msg("SLO violation: high p99 network RTT")
	}

	return violated
}

// logFinding builds a Warn-level event pre-populated with the identifying
// fields common to every finding. GID-level detail is included here (findings
// logs), never as a metric attribute. For the service network the per-path
// fields (agent_id, source_gid, target_gid) are the per-server view the paper
// recommends: service samples are spread unevenly over servers, so service
// findings should be read per path, not summed per ToR.
func (a *Analyzer) logFinding(agentID, network string, s *controller_agent.PathSummary, kind string) *zerolog.Event {
	return a.logger.Warn().
		Str("kind", kind).
		Str("network", network).
		Str("pinglist_type", s.GetPinglistType().String()).
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
			if len(b.summaries) >= a.cfg.MaxSummariesPerWindow {
				a.logger.Debug().
					Uint64("window_start_unix_ns", ws).
					Int("retained", len(b.summaries)).
					Int("cap", a.cfg.MaxSummariesPerWindow).
					Msg("dropping summary: per-window retention cap reached")
				return
			}
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
