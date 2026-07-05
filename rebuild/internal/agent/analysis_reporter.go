package agent

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// maxSummariesPerReport caps how many PathSummary entries a single
// ReportProbeAnalysis RPC carries, so a burst of many paths is split across a
// few bounded messages rather than one oversized one.
const maxSummariesPerReport = 256

// finalFlushTimeout bounds the best-effort send of the last partial window at
// shutdown, when the reporter's run context is already cancelled and a fresh
// context is used instead.
const finalFlushTimeout = 5 * time.Second

// analysisSender is the subset of controller_client.GRPCControllerClient used
// by the reporter. Declaring it here (at the point of use) lets the reporter
// be unit tested against a fake without a real gRPC connection.
type analysisSender interface {
	ReportProbeAnalysis(
		ctx context.Context,
		report *controller_agent.ProbeAnalysisReport,
	) (*controller_agent.ProbeAnalysisAck, error)
}

// AnalysisReporter drains merged probe results into a per-path PathAggregator
// and, at each window boundary, ships the completed window summaries to the
// controller via ReportProbeAnalysis. It is deliberately best-effort: a send
// failure drops that batch and is logged, never retried, so a slow or
// unreachable controller cannot stall probing or block shutdown.
type AnalysisReporter struct {
	agg         *probe.PathAggregator
	sender      analysisSender
	agentID     string
	sourceTorID string
	windowDur   time.Duration

	// input is the fan-out branch of the prober results fan-in; closed by
	// Agent.stopResultsFanIn during shutdown, which is what ends the run loop.
	input <-chan *probe.ProbeResult

	// nowFn is injectable so tests can control window boundaries.
	nowFn func() time.Time

	logger zerolog.Logger
	wg     sync.WaitGroup
}

// NewAnalysisReporter constructs a reporter aggregating into windowSec-long
// windows and reporting to sender on behalf of agentID (whose RNICs all share
// sourceTorID). input is the result stream to consume.
func NewAnalysisReporter(
	sender analysisSender,
	agentID, sourceTorID string,
	windowSec uint32,
	input <-chan *probe.ProbeResult,
) *AnalysisReporter {
	if windowSec == 0 {
		windowSec = 1
	}
	windowDur := time.Duration(windowSec) * time.Second
	return &AnalysisReporter{
		agg:         probe.NewPathAggregator(uint64(windowDur.Nanoseconds())),
		sender:      sender,
		agentID:     agentID,
		sourceTorID: sourceTorID,
		windowDur:   windowDur,
		input:       input,
		nowFn:       time.Now,
		logger:      log.With().Str("component", "analysis_reporter").Logger(),
	}
}

// Start launches the reporter goroutine. It returns immediately; the goroutine
// runs until input is closed or ctx is cancelled, then flushes a final partial
// window (best-effort) before exiting. Call Wait to block until it has exited
// (do so before closing the gRPC client so the final flush can still be sent).
func (r *AnalysisReporter) Start(ctx context.Context) {
	r.wg.Add(1)
	go r.run(ctx)
	r.logger.Info().
		Dur("window", r.windowDur).
		Msg("Analysis reporter started")
}

// Wait blocks until the reporter goroutine has fully exited.
func (r *AnalysisReporter) Wait() {
	r.wg.Wait()
}

func (r *AnalysisReporter) run(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(r.windowDur)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.flushFinal()
			return
		case res, ok := <-r.input:
			if !ok {
				// The fan-in closed the branch: agent is shutting down.
				r.flushFinal()
				return
			}
			r.agg.AddResult(res, uint64(r.nowFn().UnixNano()))
		case <-ticker.C:
			summaries := r.agg.Collect(uint64(r.nowFn().UnixNano()))
			r.report(ctx, summaries)
		}
	}
}

// flushFinal emits any remaining (including in-progress) window summaries on a
// fresh context, since run's context may already be cancelled at this point.
func (r *AnalysisReporter) flushFinal() {
	summaries := r.agg.Flush()
	if len(summaries) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), finalFlushTimeout)
	defer cancel()
	r.report(ctx, summaries)
}

// report batches summaries into bounded ProbeAnalysisReport messages and sends
// them best-effort. Any send error is logged and the batch dropped; monitoring
// is best-effort and must never stall probing.
func (r *AnalysisReporter) report(ctx context.Context, summaries []probe.PathSummary) {
	if len(summaries) == 0 {
		return
	}

	for start := 0; start < len(summaries); start += maxSummariesPerReport {
		end := start + maxSummariesPerReport
		if end > len(summaries) {
			end = len(summaries)
		}
		batch := summaries[start:end]

		report := &controller_agent.ProbeAnalysisReport{
			AgentId:   r.agentID,
			Summaries: make([]*controller_agent.PathSummary, 0, len(batch)),
		}
		for i := range batch {
			report.Summaries = append(report.Summaries, r.toProto(&batch[i]))
		}

		ack, err := r.sender.ReportProbeAnalysis(ctx, report)
		if err != nil {
			r.logger.Warn().Err(err).
				Int("summary_count", len(batch)).
				Msg("Failed to report probe analysis, dropping batch (best-effort)")
			continue
		}
		r.logger.Debug().
			Int("summary_count", len(batch)).
			Bool("accepted", ack.GetAccepted()).
			Uint32("sla_violations", ack.GetSlaViolations()).
			Msg("Reported probe analysis window")
	}
}

// toProto maps an aggregator PathSummary to its proto form, stamping the
// agent-wide source ToR (which the aggregator does not carry) and rendering
// GIDs as canonical strings.
func (r *AnalysisReporter) toProto(s *probe.PathSummary) *controller_agent.PathSummary {
	return &controller_agent.PathSummary{
		SourceGid:        probe.FormatGID(s.SourceGID),
		SourceTorId:      r.sourceTorID,
		TargetGid:        probe.FormatGID(s.TargetGID),
		TargetTorId:      s.TargetTorID,
		TargetQpn:        s.TargetQPN,
		WindowStartUnixNs: s.WindowStartUnixNs,
		WindowDurationMs:  s.WindowDurationMs,
		ProbeTotal:        s.ProbeTotal,
		ProbeSuccess:      s.ProbeSuccess,
		ProbeFailed:       s.ProbeFailed,
		NetworkRttMinNs:   s.NetworkRTTMinNs,
		NetworkRttMaxNs:   s.NetworkRTTMaxNs,
		NetworkRttP50Ns:   s.NetworkRTTP50Ns,
		NetworkRttP99Ns:   s.NetworkRTTP99Ns,
		InvalidRttCount:   s.InvalidRTTCount,
	}
}
