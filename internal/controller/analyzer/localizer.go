package analyzer

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Defaults and bounds of the localization settings. The config package
// carries the same defaults (pinned equal by a test there).
const (
	// DefaultLocalizationWindows is the default evidence span, in closed
	// windows. With the agents' default 30 s window it is two minutes: long
	// enough to pool the probes a sub-percent loss needs, short enough that
	// a repaired fault leaves the findings within minutes.
	DefaultLocalizationWindows = 4
	// MaxLocalizationWindows is the longest evidence span: one bit per
	// window records which windows had events.
	MaxLocalizationWindows = 64
	// DefaultLocalizationBaselineLossRatio is the default loss ratio of a
	// healthy path, 1/20 of the default loss SLO.
	DefaultLocalizationBaselineLossRatio = 0.001
	// DefaultLocalizationMinConfidence is the default posterior a suspect
	// needs to be reported as localized.
	DefaultLocalizationMinConfidence = 0.95
	// DefaultLocalizationMaxPathsPerWindow is the default cap on the paths
	// kept per window: 200 000 paths cover about 10 000 RNICs that each probe
	// 20 targets.
	DefaultLocalizationMaxPathsPerWindow = 200_000

	// baselineRTTViolationRatio is the share of path windows over the RTT
	// threshold that counts as healthy. Unlike the loss baseline it is not a
	// setting: a window over the threshold is already an SLO violation, so a
	// fabric where more than 1% of the windows violate needs a different
	// analyzer_slo_network_rtt_p99_ns, not a different baseline.
	baselineRTTViolationRatio = 0.01

	// localizationTick is how often the localizer checks for newly closed
	// windows. An evaluation runs only when the evidence span changed.
	localizationTick = 5 * time.Second
)

// LocalizationConfig holds the settings of the Phase 2 localizer.
type LocalizationConfig struct {
	// Topology holds the fabric facts above the ToRs. nil states none: the
	// localizer then names RNICs, hosts, ToRs and ToR uplinks, and reports
	// anything broader as not localizable.
	Topology *Topology
	// Windows is the evidence span: the number of most recent closed windows
	// pooled per evaluation. Values outside [1, MaxLocalizationWindows] are
	// replaced by DefaultLocalizationWindows.
	Windows int
	// BaselineLossRatio is the loss ratio of a healthy path. A component is
	// suspected only for loss in excess of it. Values outside (0, 1) are
	// replaced by DefaultLocalizationBaselineLossRatio.
	BaselineLossRatio float64
	// MinConfidence is the posterior probability a single suspect needs to
	// be reported as localized; below it the finding lists the candidates.
	// Values outside [0.5, 1) are replaced by
	// DefaultLocalizationMinConfidence.
	MinConfidence float64
	// MaxPathsPerWindow caps the paths kept per window. Values below 1 are
	// replaced by DefaultLocalizationMaxPathsPerWindow.
	MaxPathsPerWindow int
}

func (c LocalizationConfig) withDefaults() LocalizationConfig {
	if c.Windows < 1 || c.Windows > MaxLocalizationWindows {
		c.Windows = DefaultLocalizationWindows
	}
	if !(c.BaselineLossRatio > 0 && c.BaselineLossRatio < 1) {
		c.BaselineLossRatio = DefaultLocalizationBaselineLossRatio
	}
	if !(c.MinConfidence >= 0.5 && c.MinConfidence < 1) {
		c.MinConfidence = DefaultLocalizationMinConfidence
	}
	if c.MaxPathsPerWindow < 1 {
		c.MaxPathsPerWindow = DefaultLocalizationMaxPathsPerWindow
	}
	return c
}

// windowVersion identifies the evidence of one window at one evaluation.
type windowVersion struct {
	startNs uint64
	version uint64
}

// localizer is the Phase 2 engine: it keeps the evidence of recent windows,
// runs the tomography whenever the span of closed windows changes, and
// publishes the findings to logs and metrics.
type localizer struct {
	cfg     LocalizationConfig
	metrics *Metrics
	logger  zerolog.Logger
	// now is the clock that decides which windows are closed (time.Now;
	// injectable in tests).
	now func() time.Time

	// mu guards store. An evaluation holds it only while it copies the span
	// out of the store, not while it solves.
	mu    sync.Mutex
	store *evidenceStore

	// evalMu serializes evaluations and guards the fields below it.
	evalMu sync.Mutex
	// lastSpan is the evidence the previous evaluation ran on.
	lastSpan []windowVersion
	// open holds the findings of the previous evaluation by key, to log a
	// finding when it appears and when it clears.
	open map[string]Finding
	// unlistedTors, droppedPaths and mixedWindows are what the previous
	// evaluation saw of the conditions that weaken the evidence, so that
	// each is logged when it changes and not on every evaluation.
	unlistedTors int
	droppedPaths uint64
	mixedWindows bool

	// findings is the result of the latest evaluation, read by the metric
	// callbacks.
	findings atomic.Pointer[[]Finding]
}

func newLocalizer(cfg LocalizationConfig, rttThresholdNs uint64, metrics *Metrics) *localizer {
	cfg = cfg.withDefaults()
	l := &localizer{
		cfg:     cfg,
		metrics: metrics,
		logger:  log.With().Str("component", "localizer").Logger(),
		now:     time.Now,
		store:   newEvidenceStore(cfg.Windows, cfg.MaxPathsPerWindow, rttThresholdNs),
		open:    make(map[string]Finding),
	}
	if err := metrics.registerLocalization(l.currentFindings); err != nil {
		l.logger.Warn().Err(err).Msg("Failed to register localization metrics; continuing with log-only findings")
	}
	return l
}

// currentFindings returns the findings of the latest evaluation. The slice
// must not be modified.
func (l *localizer) currentFindings() []Finding {
	if p := l.findings.Load(); p != nil {
		return *p
	}
	return nil
}

// observe folds the cluster-network summaries of one report into the
// evidence store.
func (l *localizer) observe(ctx context.Context, agentID string, summaries []*controller_agent.PathSummary) {
	nowNs := uint64(l.now().UnixNano())
	dropped := 0
	l.mu.Lock()
	for _, s := range summaries {
		if s != nil && l.store.observe(agentID, s, nowNs) {
			dropped++
		}
	}
	l.mu.Unlock()
	l.metrics.recordDroppedPaths(ctx, dropped)
}

// run evaluates on every tick until ctx is cancelled.
func (l *localizer) run(ctx context.Context) {
	ticker := time.NewTicker(localizationTick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.evaluate(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// evaluate runs the tomography on the current evidence span, unless the
// span is the one the previous evaluation ran on. It reports whether it ran.
func (l *localizer) evaluate(ctx context.Context) bool {
	l.evalMu.Lock()
	defer l.evalMu.Unlock()

	started := time.Now()
	nowNs := uint64(l.now().UnixNano())

	l.mu.Lock()
	l.store.prune(nowNs)
	windows, otherPaths := l.store.span(nowNs)
	versions := make([]windowVersion, len(windows))
	for i, w := range windows {
		versions[i] = windowVersion{startNs: w.startNs, version: w.version}
	}
	if sameSpan(versions, l.lastSpan) {
		l.mu.Unlock()
		return false
	}
	// Only the copy is made under the lock that Ingest takes; pooling the
	// windows and solving are not.
	snapshots := make([]*windowSnapshot, len(windows))
	for i, w := range windows {
		snapshots[i] = w.snapshot(l.store.agents)
	}
	stats := l.store.stats
	l.mu.Unlock()
	l.lastSpan = versions
	sp := buildSpan(snapshots, l.cfg.Topology)

	findings := localize(sp,
		solverParams{baseline: l.cfg.BaselineLossRatio, minConfidence: l.cfg.MinConfidence, spanWindows: l.cfg.Windows},
		solverParams{baseline: baselineRTTViolationRatio, minConfidence: l.cfg.MinConfidence, spanWindows: l.cfg.Windows},
	)
	l.findings.Store(&findings)
	l.metrics.recordLocalizationRun(ctx)
	l.logTransitions(findings)
	l.logWeakEvidence(sp, stats, otherPaths)

	l.logger.Debug().
		Int("windows", sp.windows).
		Int("paths", len(sp.paths)).
		Int("rnics", len(sp.rnics)).
		Int("tors", len(sp.tors)).
		Int("findings", len(findings)).
		Uint64("unattributable_summaries", stats.unattributable).
		Uint64("out_of_range_summaries", stats.outOfRange).
		Uint64("dropped_paths", stats.dropped).
		Int("other_window_length_paths", otherPaths).
		Dur("duration", time.Since(started)).
		Msg("Localization evaluated")
	return true
}

// maxUnlistedTorsLogged bounds the ToR IDs one warning lists.
const maxUnlistedTorsLogged = 8

// logWeakEvidence warns about the conditions under which findings are
// coarser than they could be: ToRs that report but that the topology file
// does not state facts for (a typo in the file, or a new rack), paths that
// were dropped because a window reached its cap, and agents that report
// windows of another length than most. Each is logged when it changes.
func (l *localizer) logWeakEvidence(sp *span, stats evidenceStats, otherPaths int) {
	if mixed := otherPaths > 0; mixed != l.mixedWindows {
		l.mixedWindows = mixed
		if mixed {
			l.logger.Warn().
				Int("paths", otherPaths).
				Msg("Agents report windows of different lengths; only the windows of the most common length are used for fault localization (set the same analysis_window_sec on all agents)")
		}
	}
	if l.cfg.Topology != nil {
		var unlisted []string
		for i := range sp.tors {
			if !sp.tors[i].known() {
				unlisted = append(unlisted, sp.tors[i].name)
			}
		}
		if len(unlisted) != l.unlistedTors {
			l.unlistedTors = len(unlisted)
			if len(unlisted) > 0 {
				sort.Strings(unlisted)
				l.logger.Warn().
					Strs("tors", unlisted[:min(len(unlisted), maxUnlistedTorsLogged)]).
					Int("tor_count", len(unlisted)).
					Msg("ToRs report paths but have no rail or spine group in the topology file; faults above them are not localizable")
			}
		}
	}
	if stats.dropped != l.droppedPaths {
		l.logger.Warn().
			Uint64("dropped_paths", stats.dropped-l.droppedPaths).
			Int("max_paths_per_window", l.cfg.MaxPathsPerWindow).
			Msg("Path summaries were left out of the localization evidence: a window reached analyzer_localization_max_paths_per_window")
		l.droppedPaths = stats.dropped
	}
}

func sameSpan(a, b []windowVersion) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// logTransitions logs each finding once when it appears and once when it
// clears. A finding is identified by its signal, state and candidate set, so
// a change of the candidates clears one finding and opens another.
func (l *localizer) logTransitions(findings []Finding) {
	current := make(map[string]Finding, len(findings))
	for _, f := range findings {
		key := f.key()
		current[key] = f
		if _, known := l.open[key]; !known {
			logFindingFields(l.logger.Warn(), f).Msg("Fault localization finding")
		}
	}
	cleared := make([]string, 0, len(l.open))
	for key := range l.open {
		if _, still := current[key]; !still {
			cleared = append(cleared, key)
		}
	}
	sort.Strings(cleared)
	for _, key := range cleared {
		logFindingFields(l.logger.Info(), l.open[key]).Msg("Fault localization finding cleared")
	}
	l.open = current
}

// logFindingFields adds a finding to a log event. This is where the
// identities that never reach a metric go: the GID of a suspected RNIC and
// the agent of a suspected RNIC or host.
func logFindingFields(ev *zerolog.Event, f Finding) *zerolog.Event {
	top := f.Suspects[0]
	ev = ev.
		Str("kind", f.Signal).
		Str("state", f.State)
	ev = logComponentFields(ev, top.Component).
		Float64("confidence", top.Confidence).
		Float64("excess_ratio", top.ExcessRatio).
		Float64("evidence_nats", top.EvidenceNats).
		Int("paths", top.Paths).
		Int("failed_paths", top.FailedPaths).
		Uint64("trials", top.Trials).
		Uint64("events", top.Events).
		Int("windows", top.Windows)
	if len(f.Suspects) > 1 {
		candidates := zerolog.Arr()
		for _, s := range f.Suspects {
			candidates = candidates.Dict(logComponentFields(zerolog.Dict(), s.Component).
				Float64("confidence", s.Confidence).
				Float64("excess_ratio", s.ExcessRatio))
		}
		ev = ev.Array("candidates", candidates).Bool("candidates_truncated", f.Truncated)
	}
	if f.MemberCount > 0 {
		ev = ev.Strs("members", f.Members).Int("member_count", f.MemberCount)
	}
	return ev
}

func logComponentFields(ev *zerolog.Event, c Component) *zerolog.Event {
	ev = ev.Str("component", c.Kind)
	for _, f := range []struct{ key, value string }{
		{"tor", c.Tor},
		{"spine_group", c.SpineGroup},
		{"rail", c.Rail},
		{"gid", c.GID},
		{"agent_id", c.AgentID},
	} {
		if f.value != "" {
			ev = ev.Str(f.key, f.value)
		}
	}
	return ev
}

// buildSpan pools the evidence of the span's windows per path and joins it
// with the topology facts and the known agents. Indexes are local to the
// span: a window's RNIC table is translated once, so strings are compared
// per RNIC, not per path. Paths keep the order in which they were first
// reported, so the result does not depend on map iteration.
func buildSpan(windows []*windowSnapshot, topo *Topology) *span {
	sp := &span{
		windows:    len(windows),
		lossEvents: make([][]spanEvent, len(windows)),
		rttEvents:  make([][]spanEvent, len(windows)),
	}
	most := 0
	for _, w := range windows {
		most = max(most, len(w.pathKeys))
	}
	rnicIdx := make(map[string]int32)
	torIdx := make(map[string]int32)
	groupIdx := make(map[string]int32)
	railIdx := make(map[string]int32)
	pathIdx := make(map[pathKey]int32, most)
	sp.paths = make([]spanPath, 0, most)

	rail := func(name string) int32 {
		if name == "" {
			return -1
		}
		idx, ok := railIdx[name]
		if !ok {
			idx = int32(len(sp.rails))
			sp.rails = append(sp.rails, name)
			railIdx[name] = idx
		}
		return idx
	}
	tor := func(name string) int32 {
		if idx, ok := torIdx[name]; ok {
			return idx
		}
		facts, _ := topo.Lookup(name)
		t := spanTor{name: name, group: -1, rail: rail(facts.Rail)}
		if facts.SpineGroup != "" {
			idx, ok := groupIdx[facts.SpineGroup]
			if !ok {
				idx = int32(len(sp.groups))
				sp.groups = append(sp.groups, facts.SpineGroup)
				sp.groupRail = append(sp.groupRail, t.rail)
				groupIdx[facts.SpineGroup] = idx
			}
			t.group = idx
		}
		idx := int32(len(sp.tors))
		sp.tors = append(sp.tors, t)
		torIdx[name] = idx
		return idx
	}

	var local []int32 // window RNIC index -> span RNIC index
	for wi, w := range windows {
		local = local[:0]
		for _, r := range w.rnics {
			torID := tor(r.tor)
			idx, ok := rnicIdx[r.gid]
			if !ok {
				idx = int32(len(sp.rnics))
				sp.rnics = append(sp.rnics, spanRNIC{gid: r.gid, agent: r.agent, tor: torID, host: -1})
				rnicIdx[r.gid] = idx
			} else {
				// The newest window's statement of an RNIC's ToR wins.
				sp.rnics[idx].tor = torID
				if r.agent != "" {
					sp.rnics[idx].agent = r.agent
				}
			}
			local = append(local, idx)
		}
		for i, key := range w.pathKeys {
			ev := &w.pathEv[i]
			src, dst := local[key.src], local[key.dst]
			spanKey := pathKey{src: uint32(src), dst: uint32(dst)}
			idx, ok := pathIdx[spanKey]
			if !ok {
				idx = int32(len(sp.paths))
				sp.paths = append(sp.paths, spanPath{src: src, dst: dst})
				pathIdx[spanKey] = idx
			}
			p := &sp.paths[idx]
			p.probes = saturatingAdd(p.probes, ev.probes)
			p.failed = saturatingAdd(p.failed, ev.failed)
			if ev.failed > 0 {
				p.lossMask |= 1 << uint(wi)
				sp.lossEvents[wi] = append(sp.lossEvents[wi], spanEvent{path: idx, count: ev.failed})
			}
			if ev.rttValid {
				p.rttWindows++
				if ev.rttBad {
					p.rttBad++
					p.rttMask |= 1 << uint(wi)
					sp.rttEvents[wi] = append(sp.rttEvents[wi], spanEvent{path: idx, count: 1})
				}
			}
		}
	}

	// A host component needs at least two RNICs: with one, the host and the
	// RNIC have the same paths.
	perAgent := make(map[string]int32)
	for i := range sp.rnics {
		if agent := sp.rnics[i].agent; agent != "" {
			perAgent[agent]++
		}
	}
	hostIdx := make(map[string]int32)
	for i := range sp.rnics {
		agent := sp.rnics[i].agent
		if agent == "" || perAgent[agent] < 2 {
			continue
		}
		idx, ok := hostIdx[agent]
		if !ok {
			idx = int32(len(sp.hosts))
			sp.hosts = append(sp.hosts, agent)
			hostIdx[agent] = idx
		}
		sp.rnics[i].host = idx
	}
	return sp
}
