package analyzer

import (
	"math"
	"sort"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// The localizer keeps its own evidence instead of reading the Phase 1 window
// ring: the ring retains whole PathSummary messages under a per-window cap
// sized for SLO detection, while localization needs every path of a window
// and only four numbers of each. The stores are independent, so enabling
// localization changes nothing in Phase 1.

const (
	// closeMarginNs is added to a window's own length to get the grace
	// period after which the window is closed. An agent collects a window on
	// a ticker of one window length that is not aligned to the window
	// boundary, so a window reaches the controller up to one window length
	// after it ends; the margin covers the RPC.
	closeMarginNs = uint64(10_000_000_000)

	// extraRetainedWindows is how many windows the store keeps beyond the
	// evidence span: those still open or waiting for their grace period, and
	// one of slack for clock skew between agents.
	extraRetainedWindows = 6

	// agentTTLNs is how long the store remembers which agent reported an
	// RNIC. It outlives the evidence span on purpose: a host that went down
	// stops reporting, and its RNICs must still be grouped into one host
	// component while other agents keep probing them (until the registry
	// drops them from pinglists, after active_threshold_sec).
	agentTTLNs = uint64(15 * 60 * 1_000_000_000)

	// maxKnownAgentsRNICs bounds the RNIC-to-agent table against a flood of
	// distinct source GIDs.
	maxKnownAgentsRNICs = 1 << 18
)

// pathKey identifies a path within one window by the indexes of its source
// and target RNICs in that window's RNIC table.
type pathKey struct {
	src, dst uint32
}

// pathEvidence is what the localizer keeps of one path in one window.
type pathEvidence struct {
	probes uint32 // probe_total: every probe is one loss trial
	failed uint32 // probe_failed
	// rttValid: the window produced at least one valid RTT, so its p99 is
	// one RTT trial. rttBad: that p99 exceeded the cluster RTT threshold.
	rttValid bool
	rttBad   bool
}

// windowRNIC is one RNIC seen in a window, as a path's source or target.
type windowRNIC struct {
	gid string
	tor uint32 // index into windowEvidence.tors
	// torFromSource records that tor was stated by the RNIC's own agent (the
	// RNIC was a path's source). It then wins over the ToR a prober copied
	// from its pinglist, which can lag a re-registration.
	torFromSource bool
}

// windowEvidence holds the evidence of one aggregation window. GIDs and ToR
// IDs are interned per window, so a window's memory is released as a whole
// when it is evicted and no table grows with RNIC churn.
type windowEvidence struct {
	startNs uint64
	durNs   uint64

	rnics   []windowRNIC
	rnicIdx map[string]uint32
	tors    []string
	torIdx  map[string]uint32
	// The paths in the order they were first reported: pathIdx maps a path
	// to its position in pathKeys and pathEv. Slices, so that an evaluation
	// copies a window in one move and reads it in a stable order.
	pathIdx  map[pathKey]uint32
	pathKeys []pathKey
	pathEv   []pathEvidence

	// version changes whenever the window's evidence changes, so an
	// evaluation can tell whether anything arrived since the previous one.
	version uint64
}

// snapshotRNIC is one RNIC of a window snapshot.
type snapshotRNIC struct {
	gid   string
	tor   string
	agent string // agent that reported the RNIC, "" when unknown
}

// windowSnapshot is a copy of a window's evidence that an evaluation reads
// without holding the store's lock.
type windowSnapshot struct {
	rnics    []snapshotRNIC
	pathKeys []pathKey
	pathEv   []pathEvidence
}

// snapshot copies the window. agents names the agent of each RNIC.
func (w *windowEvidence) snapshot(agents map[string]agentRecord) *windowSnapshot {
	snap := &windowSnapshot{
		rnics:    make([]snapshotRNIC, len(w.rnics)),
		pathKeys: append([]pathKey(nil), w.pathKeys...),
		pathEv:   append([]pathEvidence(nil), w.pathEv...),
	}
	for i, r := range w.rnics {
		snap.rnics[i] = snapshotRNIC{gid: r.gid, tor: w.tors[r.tor], agent: agents[r.gid].agentID}
	}
	return snap
}

func (w *windowEvidence) endNs() uint64 { return w.startNs + w.durNs }

// closedAt reports whether the window is closed at nowNs: its end plus the
// grace period has passed, so the agents' reports for it have arrived.
func (w *windowEvidence) closedAt(nowNs uint64) bool {
	return w.endNs()+w.durNs+closeMarginNs <= nowNs
}

// hasPath reports whether the window already holds the path src -> dst.
func (w *windowEvidence) hasPath(src, dst string) bool {
	srcIdx, ok := w.rnicIdx[src]
	if !ok {
		return false
	}
	dstIdx, ok := w.rnicIdx[dst]
	if !ok {
		return false
	}
	_, ok = w.pathIdx[pathKey{src: srcIdx, dst: dstIdx}]
	return ok
}

// path returns the evidence of the path key, adding the path when it is
// new.
func (w *windowEvidence) path(key pathKey) *pathEvidence {
	idx, ok := w.pathIdx[key]
	if !ok {
		idx = uint32(len(w.pathKeys))
		w.pathIdx[key] = idx
		w.pathKeys = append(w.pathKeys, key)
		w.pathEv = append(w.pathEv, pathEvidence{})
	}
	return &w.pathEv[idx]
}

func (w *windowEvidence) internTor(tor string) uint32 {
	if idx, ok := w.torIdx[tor]; ok {
		return idx
	}
	idx := uint32(len(w.tors))
	w.tors = append(w.tors, tor)
	w.torIdx[tor] = idx
	return idx
}

func (w *windowEvidence) internRNIC(gid, tor string, isSource bool) uint32 {
	torID := w.internTor(tor)
	idx, ok := w.rnicIdx[gid]
	if !ok {
		idx = uint32(len(w.rnics))
		w.rnics = append(w.rnics, windowRNIC{gid: gid, tor: torID, torFromSource: isSource})
		w.rnicIdx[gid] = idx
		return idx
	}
	if r := &w.rnics[idx]; isSource || !r.torFromSource {
		r.tor = torID
		r.torFromSource = r.torFromSource || isSource
	}
	return idx
}

// agentRecord remembers the agent that last reported an RNIC as a source.
type agentRecord struct {
	agentID    string
	lastSeenNs uint64
}

// evidenceStats counts what the store did not keep, for the evaluation log.
type evidenceStats struct {
	// unattributable: summaries without a GID or with an unspecified ToR on
	// either end. They cannot be attributed to a component.
	unattributable uint64
	// outOfRange: summaries of a window too old to enter an evidence span,
	// too far in the future, without a duration, or that does not start on
	// a multiple of its length.
	outOfRange uint64
	// dropped: paths not kept because a window reached maxPathsPerWindow.
	dropped uint64
}

// evidenceStore keeps the per-window path evidence of the most recent
// windows. It is not safe for concurrent use: the localizer guards it.
type evidenceStore struct {
	spanWindows       int
	maxPathsPerWindow int
	rttThresholdNs    uint64

	// windows is ascending by startNs, then by durNs: windows of different
	// lengths that start together are kept apart.
	windows []*windowEvidence
	// windowNs is the window length the evidence span is built from: the
	// one that holds the most paths among the retained windows (0 before
	// the first window). Agents are meant to share one analysis_window_sec.
	// When they do not (a misconfigured agent, a rollout of a new value),
	// windows of another length are not pooled with the others, and they
	// are the first to go when the store is full, so that a minority cannot
	// push the majority's evidence out.
	windowNs uint64
	agents   map[string]agentRecord
	stats    evidenceStats
}

func newEvidenceStore(spanWindows, maxPathsPerWindow int, rttThresholdNs uint64) *evidenceStore {
	return &evidenceStore{
		spanWindows:       spanWindows,
		maxPathsPerWindow: maxPathsPerWindow,
		rttThresholdNs:    rttThresholdNs,
		agents:            make(map[string]agentRecord),
	}
}

// observe folds one cluster-network path summary into the evidence of its
// window. Summaries of traced service flows are left out: they are sampled
// along application flows, not by the controller's pinglists, and the paper
// evaluates them per path. It returns true when the summary would have added
// a path to a window that is already at its cap.
func (s *evidenceStore) observe(agentID string, sum *controller_agent.PathSummary, nowNs uint64) (droppedAtCap bool) {
	if sum.GetPinglistType() == controller_agent.PinglistType_SERVICE_TRACING {
		return false
	}
	src, dst := sum.GetSourceGid(), sum.GetTargetGid()
	srcTor := probe.TorMetricLabel(sum.GetSourceTorId())
	dstTor := probe.TorMetricLabel(sum.GetTargetTorId())
	if src == "" || dst == "" || src == dst ||
		srcTor == probe.UnspecifiedTorLabel || dstTor == probe.UnspecifiedTorLabel {
		s.stats.unattributable++
		return false
	}
	if sum.GetProbeTotal() == 0 {
		return false
	}

	startNs := sum.GetWindowStartUnixNs()
	durNs := uint64(sum.GetWindowDurationMs()) * 1_000_000
	if !s.inRange(startNs, durNs, nowNs) {
		s.stats.outOfRange++
		return false
	}

	w := s.window(startNs, durNs)
	if w == nil {
		s.stats.outOfRange++
		return false
	}
	// The cap is checked before the RNICs are interned, so a window at its
	// cap grows no further, whatever the GIDs of the summaries it refuses.
	if len(w.pathKeys) >= s.maxPathsPerWindow && !w.hasPath(src, dst) {
		s.stats.dropped++
		return true
	}
	ev := w.path(pathKey{
		src: w.internRNIC(src, srcTor, true),
		dst: w.internRNIC(dst, dstTor, false),
	})

	failed := min(sum.GetProbeFailed(), sum.GetProbeTotal())
	ev.probes = saturatingAdd(ev.probes, sum.GetProbeTotal())
	ev.failed = saturatingAdd(ev.failed, failed)
	if sum.GetProbeSuccess() > 0 {
		ev.rttValid = true
		if s.rttThresholdNs > 0 && sum.GetNetworkRttP99Ns() > s.rttThresholdNs {
			ev.rttBad = true
		}
	}
	w.version++

	if agentID != "" {
		if _, known := s.agents[src]; known || len(s.agents) < maxKnownAgentsRNICs {
			s.agents[src] = agentRecord{agentID: agentID, lastSeenNs: nowNs}
		}
	}
	return false
}

// inRange reports whether a window can still enter an evidence span: it has
// a duration, starts on a multiple of it, does not start more than one
// window ahead of the controller's clock, and is not older than the span
// plus the retained slack.
//
// Agents align their windows to multiples of the window length
// (probe.PathAggregator), so all agents share the same windows. A window
// that starts elsewhere comes from no agent. Accepting it would let a few
// summaries open windows between the agents' own: they would take the
// places of the agents' windows in the store and put more windows into one
// span than the span is configured to hold.
func (s *evidenceStore) inRange(startNs, durNs, nowNs uint64) bool {
	if durNs == 0 || startNs%durNs != 0 || startNs > math.MaxUint64-2*durNs-closeMarginNs {
		return false
	}
	if startNs > nowNs+durNs {
		return false
	}
	horizon := uint64(s.spanWindows+extraRetainedWindows) * durNs
	return startNs+durNs+horizon >= nowNs
}

// window returns the evidence of the window that starts at startNs and
// lasts durNs, creating it when needed. The number of retained windows is
// capped. When the cap is reached, the oldest window of a length other than
// windowNs is evicted, or else the oldest window; nil is returned for a new
// window that would itself be the one to evict.
func (s *evidenceStore) window(startNs, durNs uint64) *windowEvidence {
	before := func(w *windowEvidence) bool {
		return w.startNs < startNs || (w.startNs == startNs && w.durNs < durNs)
	}
	idx := sort.Search(len(s.windows), func(i int) bool { return !before(s.windows[i]) })
	if idx < len(s.windows) && s.windows[idx].startNs == startNs && s.windows[idx].durNs == durNs {
		return s.windows[idx]
	}
	if s.windowNs == 0 {
		s.windowNs = durNs
	}
	if len(s.windows) >= s.spanWindows+extraRetainedWindows {
		victim := -1
		for i, w := range s.windows {
			if w.durNs != s.windowNs {
				victim = i
				break
			}
		}
		switch {
		case victim >= 0 && durNs != s.windowNs && idx <= victim:
			// The new window is itself the oldest of another length.
			return nil
		case victim < 0 && idx == 0:
			return nil
		case victim < 0:
			victim = 0
		}
		s.windows = append(s.windows[:victim], s.windows[victim+1:]...)
		if victim < idx {
			idx--
		}
	}
	w := &windowEvidence{
		startNs: startNs,
		durNs:   durNs,
		rnicIdx: make(map[string]uint32),
		torIdx:  make(map[string]uint32),
		pathIdx: make(map[pathKey]uint32),
	}
	s.windows = append(s.windows, nil)
	copy(s.windows[idx+1:], s.windows[idx:])
	s.windows[idx] = w
	return w
}

// prune drops the windows that can no longer enter an evidence span and the
// agent records that expired.
func (s *evidenceStore) prune(nowNs uint64) {
	kept := s.windows[:0]
	for _, w := range s.windows {
		if s.inRange(w.startNs, w.durNs, nowNs) {
			kept = append(kept, w)
		}
	}
	for i := len(kept); i < len(s.windows); i++ {
		s.windows[i] = nil
	}
	s.windows = kept

	// The window length that holds the most paths; the longer one on a tie,
	// so the choice does not depend on the order of the windows.
	paths := make(map[uint64]int)
	for _, w := range s.windows {
		paths[w.durNs] += len(w.pathKeys)
	}
	s.windowNs = 0
	for durNs, n := range paths {
		if best := paths[s.windowNs]; s.windowNs == 0 || n > best || (n == best && durNs > s.windowNs) {
			s.windowNs = durNs
		}
	}

	for gid, rec := range s.agents {
		if rec.lastSeenNs+agentTTLNs < nowNs {
			delete(s.agents, gid)
		}
	}
}

// span returns the closed windows that form the evidence span at nowNs,
// oldest first: the windows of the length windowNs that ended within the
// last spanWindows window lengths before the newest closed one's end, and
// never more than spanWindows of them. It is empty when the newest closed
// window is stale (agents stopped reporting), so old evidence does not keep
// a finding alive. otherPaths counts the paths of the closed windows of
// other lengths, which are left out.
func (s *evidenceStore) span(nowNs uint64) (out []*windowEvidence, otherPaths int) {
	var newest *windowEvidence
	for _, w := range s.windows {
		switch {
		case !w.closedAt(nowNs):
		case w.durNs != s.windowNs:
			otherPaths += len(w.pathKeys)
		case newest == nil || w.endNs() > newest.endNs():
			newest = w
		}
	}
	if newest == nil {
		return nil, otherPaths
	}
	// The newest closed window is at most one window length behind the
	// closing horizon while agents report; allow one more for a late batch.
	if newest.endNs()+3*newest.durNs+closeMarginNs < nowNs {
		return nil, otherPaths
	}
	spanNs := uint64(s.spanWindows) * newest.durNs
	for _, w := range s.windows {
		if w.durNs == s.windowNs && w.closedAt(nowNs) && w.endNs()+spanNs > newest.endNs() {
			out = append(out, w)
		}
	}
	// Windows of one length that start on multiples of it do not overlap,
	// so this cut never applies. It is what the solver's per-window masks
	// rely on, so it does not rest on the alignment check alone.
	if len(out) > s.spanWindows {
		out = out[len(out)-s.spanWindows:]
	}
	return out, otherPaths
}

func saturatingAdd(a, b uint32) uint32 {
	if a > math.MaxUint32-b {
		return math.MaxUint32
	}
	return a + b
}
