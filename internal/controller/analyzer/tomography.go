package analyzer

import (
	"math"
	"math/bits"
	"sort"
)

// This file holds the inference of the Phase 2 localizer: a network
// tomography over the paths agents probed. It is a pure function of the
// evidence span and the topology facts, with no clock, lock or I/O, so it can
// be tested against a simulated fabric. docs/design/
// analyzer-phase2-localization.md gives the reasons for each step.
//
// Model. Every probed path (source RNIC -> target RNIC) crosses a known set
// of components: its two RNICs, their hosts, their ToRs and, when the ToRs
// differ, each ToR's uplinks and the tiers above them that the topology
// facts name. A path yields n trials and k events (probes and lost probes,
// or windows and windows over the RTT threshold). Events are modelled as
//
//	k ~ Poisson(n * (baseline + sum of the excess rates of the path's faulty components))
//
// which is the small-rate form of independent drops along the path. A fault
// in one of m equal-cost links shows as an excess of about 2f/m on every
// path through that ECMP stage (the probe and its ACK each cross it once),
// because the flow labels of a path spread over the links: the stage is
// identified, the link is not.
//
// Inference. Components are added greedily by the likelihood they gain over
// the current explanation, each with its maximum-likelihood excess rate,
// until no component gains enough (greedy). The rates are then refitted
// jointly (refit), and each composite component is replaced by more specific
// ones when those explain its events better (split).
//
// Confidence. For every component of the explanation, the alternatives that
// could take its place (the components sharing one of its paths with events)
// are each fitted in its stead (alternatives). With an equal prior on every
// component, the posterior probability of each alternative, and of "no fault
// here", follows from the likelihoods. The confidence of a suspect is that
// posterior. A finding is the smallest set of alternatives whose posteriors
// sum to the configured minimum confidence: one component when the evidence
// singles it out, several when they explain it equally well (findings.go).

// Evidence rules. A component is named only when it gains enough likelihood
// and its evidence is broad and persistent enough to rule out one stuck path
// or one burst.
const (
	// priorNats is the prior odds against a fault in any one component
	// during one evidence span, as a natural logarithm: e^-14 is about one
	// in 1.2 million. It sets how much likelihood a component must gain
	// before it is more probable than "no fault", so that a fabric of 10^4
	// components evaluated every 30 s stays quiet under noise.
	priorNats = 14.0

	// minFailedPairs is the least number of distinct RNIC pairs with events
	// a component needs. One pair can fail for reasons private to it (a
	// path pinned to one flow label that crosses a bad link nothing else of
	// the component uses).
	minFailedPairs = 3

	// minFailedMembers is the least number of a composite component's
	// members (a ToR's RNICs, a spine group's ToRs) with events, when at
	// least that many are observed. A ToR is not accused on one RNIC's
	// evidence.
	minFailedMembers = 2

	// minEventWindows is the least number of distinct windows of the span
	// with events, and maxWindowShare the largest share of a component's
	// events that two adjacent windows may hold together (one window, for
	// an evidence span configured to two windows). One burst is not a
	// fault. A burst that straddles a window boundary puts its events into
	// two adjacent windows, and so does a burst within one window when the
	// agents' clocks differ or their timeout sweeps fall on both sides of
	// the boundary. A fault is therefore reported once a third window holds
	// a quarter of its events, when it has lasted more than one window
	// length. Both rules are off for a span configured to one window.
	minEventWindows = 2
	maxWindowShare  = 0.75

	// maxExplanation bounds the components one evaluation can add to the
	// explanation of one signal, and with it the work of the solver.
	// maxFindingsPerSignal bounds how many of them are reported.
	maxExplanation       = 48
	maxFindingsPerSignal = 16

	// maxSplitParts bounds the components that may take the place of one
	// component in a split. A replacement by more parts would have to gain
	// that many times the prior, and searching for it costs one pass over
	// the affected components per part.
	maxSplitParts = 8

	// maxCandidates bounds the alternatives one ambiguous finding lists.
	maxCandidates = 8

	// maxSiblings is the most findings of one tier under one parent scope
	// that are reported individually. More ToRs than this under one spine
	// group (or rail, or fabric) degraded at once are far more likely to
	// share a cause the topology facts do not describe than to have failed
	// independently, so they are folded into one not-localizable finding
	// that names the scope and lists the members.
	maxSiblings = 2

	// maxScopeDispersion is the dispersion of a scope above which its
	// members are not reported individually (see siblingLimit).
	maxScopeDispersion = 2.0

	// maxMembersListed bounds the members a folded finding lists.
	maxMembersListed = 16

	// hintNats and hintExcessShare decide which unnamed siblings of a named
	// member count towards maxSiblings: those with at least hintNats of
	// evidence (half the prior) and an excess of at least hintExcessShare
	// of the named members'.
	hintNats        = priorNats / 2
	hintExcessShare = 0.25

	// powerNats is the evidence a fault above a ToR would be expected to
	// leave on each sibling before the siblings' silence clears that tier
	// (see siblingsWouldShow).
	powerNats = 3 * hintNats

	// maxRefitRounds bounds the joint refit of the selected components;
	// refitTolerance is the relative change of a rate below which it counts
	// as settled.
	maxRefitRounds = 30
	refitTolerance = 1e-4
)

// spanRNIC is one RNIC of an evidence span.
type spanRNIC struct {
	gid   string
	agent string // agent that reported the RNIC, "" when unknown
	tor   int32  // index into span.tors
	host  int32  // index into span.hosts, -1 without a host component
	// unanswering: the probes sent to the RNIC are lost while its own are
	// delivered (see markUnanswering). The loss solver leaves the paths to
	// it out.
	unanswering bool
}

// spanTor is one ToR of an evidence span with its topology facts.
type spanTor struct {
	name  string
	group int32 // index into span.groups, -1 when not stated
	rail  int32 // index into span.rails, -1 when not stated
}

// known reports whether the topology states anything above the ToR.
func (t *spanTor) known() bool { return t.group >= 0 || t.rail >= 0 }

// spanPath is one path of an evidence span, pooled over its windows.
type spanPath struct {
	src, dst int32
	probes   uint32
	failed   uint32
	// rttTrials counts the probes that returned a valid RTT, rttBad the
	// windows whose p99 exceeded the threshold.
	rttTrials uint32
	rttBad    uint32
	// lossMask and rttMask have bit w set when window w of the span had a
	// failed probe or an RTT violation on this path.
	lossMask uint64
	rttMask  uint64
}

// spanEvent is the events one path had in one window: lost probes, or 1 for
// a window over the RTT threshold.
type spanEvent struct {
	path  int32 // index into span.paths
	count uint32
}

// span is the pooled evidence of the closed windows under evaluation.
type span struct {
	rnics     []spanRNIC
	tors      []spanTor
	hosts     []string // agent IDs of the hosts with a host component
	groups    []string
	groupRail []int32 // rail of each group, -1 when not stated
	rails     []string
	paths     []spanPath
	windows   int
	// lossEvents and rttEvents list, per window of the span, the paths with
	// events in that window. They tell a fault that persists from a burst.
	lossEvents [][]spanEvent
	rttEvents  [][]spanEvent
	// unanswering counts the RNICs marked by markUnanswering.
	unanswering int
}

// solverParams are the settings of one solve.
type solverParams struct {
	// baseline is the event rate of a healthy path.
	baseline float64
	// minConfidence is the posterior a single suspect needs to be reported
	// as localized, and the mass a candidate set must reach.
	minConfidence float64
	// spanWindows is the configured evidence span. The persistence rules
	// use it, not the number of windows present, so that a controller that
	// has just started does not report on its first window.
	spanWindows int
}

// detectNats is the likelihood a component must gain to enter the
// explanation: enough to reach minConfidence against "no fault" when it has
// no competitor.
func (p solverParams) detectNats() float64 {
	return priorNats + math.Log(p.minConfidence/(1-p.minConfidence))
}

// localize runs the tomography on both signals of a span and returns the
// findings, in a stable order.
func localize(sp *span, loss, rtt solverParams) []Finding {
	if sp.unanswering == 0 {
		sp.unanswering = sp.markUnanswering(loss.baseline)
	}
	var findings []Finding
	findings = append(findings, newSolver(sp, KindLoss, loss).solve()...)
	findings = append(findings, newSolver(sp, KindRTT, rtt).solve()...)
	return findings
}

// solver holds the state of one solve of one signal.
type solver struct {
	sp     *span
	signal string
	p      solverParams

	// Component IDs: RNICs, hosts, ToRs, ToR uplinks, spine groups, rails,
	// the fabric, then the background, in this order, so a lower ID is a
	// more specific kind.
	baseHost, baseTor, baseUplink, baseGroup, baseRail, fabric, background int32
	numComp                                                                int

	// Per component: trials and paths over all its paths, and the indexes
	// of its paths with events (into the f* slices).
	trials     []float64
	pathCount  []int32
	failedOff  []int32
	failedList []int32

	// Paths with events.
	fpath   []int32   // index into sp.paths
	fevents []float64 // k
	ftrials []float64 // n
	frate   []float64 // current event rate per trial of the path
	fmask   []uint64
	fcompsO []int32 // offsets into fcomps
	fcomps  []int32 // components of each path with events
	// Events of each path with events, by window: the entries
	// fwinOff[f]..fwinOff[f+1] of fwin.
	fwinOff []int32
	fwin    []windowCount
	// The two largest dispersions among the components of the explanation
	// that cover each path with events, and the component of the largest
	// (see coverDispersion). Set once the explanation is final.
	fdisp       []float64
	fdispOwner  []int32
	fdispSecond []float64

	// Members observed per composite component (see observedMembers).
	members []int32

	// Greedy state.
	theta    []float64
	gain     []float64
	dirty    []bool
	selected []bool
	// banned marks components a split replaced by more specific ones (see
	// split); they do not re-enter the explanation.
	banned []bool
	// catchAll marks the components that have exactly the paths of the
	// fabric or of the background (see markCatchAlls). They are no place of
	// their own: the catch-all stands for them.
	catchAll []bool
	active   []int32 // components with at least one failed path
	eligible []int8  // 0 unknown, 1 eligible, -1 not

	// Scratch for counting distinct members and neighbours.
	rnicStamp []int32
	torStamp  []int32
	compStamp []int32
	stampGen  int32
}

// windowCount is the events of one path in one window of the span.
type windowCount struct {
	window uint8
	count  float64
}

func newSolver(sp *span, signal string, p solverParams) *solver {
	s := &solver{sp: sp, signal: signal, p: p}
	s.baseHost = int32(len(sp.rnics))
	s.baseTor = s.baseHost + int32(len(sp.hosts))
	s.baseUplink = s.baseTor + int32(len(sp.tors))
	s.baseGroup = s.baseUplink + int32(len(sp.tors))
	s.baseRail = s.baseGroup + int32(len(sp.groups))
	s.fabric = s.baseRail + int32(len(sp.rails))
	s.background = s.fabric + 1
	s.numComp = int(s.background) + 1
	return s
}

// observation returns the trials, events and window mask of a path for the
// solver's signal.
func (s *solver) observation(p *spanPath) (trials, events uint32, mask uint64) {
	if s.signal == KindRTT {
		return p.rttTrials, min(p.rttBad, p.rttTrials), p.rttMask
	}
	if s.sp.rnics[p.dst].unanswering {
		// Not the network's loss: the path is neither trials nor events.
		return 0, 0, 0
	}
	return p.probes, min(p.failed, p.probes), p.lossMask
}

// maxPathComponents is the most components one path crosses: two RNICs, two
// hosts, two ToRs, two uplink sets, two spine groups, two rails, the fabric
// and the background.
const maxPathComponents = 14

// components appends to buf[:0] the components the path crosses.
func (s *solver) components(p *spanPath, buf []int32) []int32 {
	buf = buf[:0]
	src, dst := &s.sp.rnics[p.src], &s.sp.rnics[p.dst]
	buf = append(buf, p.src, p.dst)
	if src.host >= 0 {
		buf = append(buf, s.baseHost+src.host)
	}
	if dst.host >= 0 && dst.host != src.host {
		buf = append(buf, s.baseHost+dst.host)
	}
	buf = append(buf, s.baseTor+src.tor)
	if dst.tor != src.tor {
		buf = append(buf, s.baseTor+dst.tor, s.baseUplink+src.tor, s.baseUplink+dst.tor)
		from := len(buf)
		buf = s.appendTiers(buf, from, src.tor, dst.tor)
		buf = s.appendTiers(buf, from, dst.tor, src.tor)
		buf = append(buf, s.fabric)
	}
	return append(buf, s.background)
}

// appendTiers appends the tiers above tor that a path from tor to peer
// crosses on tor's side. The tier directly above a ToR (its spine group, or
// its rail when it states no spine group) is crossed by every path that
// leaves the ToR. The rail above a spine group is crossed only by a path
// that leaves the group, which is known only when the peer's facts are
// stated: without them the path counts neither for nor against the rail.
func (s *solver) appendTiers(buf []int32, from int, tor, peer int32) []int32 {
	t, p := &s.sp.tors[tor], &s.sp.tors[peer]
	switch {
	case t.group >= 0:
		buf = appendUnique(buf, from, s.baseGroup+t.group)
		if t.rail >= 0 && p.known() && p.group != t.group {
			buf = appendUnique(buf, from, s.baseRail+t.rail)
		}
	case t.rail >= 0:
		buf = appendUnique(buf, from, s.baseRail+t.rail)
	}
	return buf
}

func appendUnique(buf []int32, from int, id int32) []int32 {
	for _, x := range buf[from:] {
		if x == id {
			return buf
		}
	}
	return append(buf, id)
}

// kindOf returns the kind of a component ID.
func (s *solver) kindOf(c int32) string {
	switch {
	case c < s.baseHost:
		return ComponentRNIC
	case c < s.baseTor:
		return ComponentHost
	case c < s.baseUplink:
		return ComponentTor
	case c < s.baseGroup:
		return ComponentTorUplink
	case c < s.baseRail:
		return ComponentSpineGroup
	case c < s.fabric:
		return ComponentRail
	case c == s.fabric:
		return ComponentFabric
	default:
		return ComponentBackground
	}
}

// prepare makes one pass over the paths: it sums each component's trials,
// records the paths with events and counts each composite component's
// observed members. It returns false when the signal has no events at all.
func (s *solver) prepare() bool {
	sp := s.sp
	s.trials = make([]float64, s.numComp)
	s.pathCount = make([]int32, s.numComp)
	interCount := make([]int32, s.numComp) // paths between two ToRs
	failedCount := make([]int32, s.numComp)

	rnicSeen := make([]bool, len(sp.rnics))
	rnicInter := make([]bool, len(sp.rnics))
	torSeen := make([]bool, len(sp.tors))
	torInter := make([]bool, len(sp.tors))
	torInRail := make([]bool, len(sp.tors))

	// The slices of the paths with events are sized in one pass, so that
	// a span in which most paths have events is not copied while it grows.
	withEvents := 0
	for i := range sp.paths {
		if trials, events, _ := s.observation(&sp.paths[i]); trials > 0 && events > 0 {
			withEvents++
		}
	}
	if withEvents == 0 {
		return false
	}
	s.fpath = make([]int32, 0, withEvents)
	s.fevents = make([]float64, 0, withEvents)
	s.ftrials = make([]float64, 0, withEvents)
	s.frate = make([]float64, 0, withEvents)
	s.fmask = make([]uint64, 0, withEvents)
	s.fcompsO = make([]int32, 1, withEvents+1)
	s.fcomps = make([]int32, 0, withEvents*10)

	var buf [maxPathComponents]int32
	for i := range sp.paths {
		p := &sp.paths[i]
		trials, events, mask := s.observation(p)
		if trials == 0 {
			continue
		}
		comps := s.components(p, buf[:0])
		for _, c := range comps {
			s.trials[c] += float64(trials)
			s.pathCount[c]++
		}

		srcTor, dstTor := sp.rnics[p.src].tor, sp.rnics[p.dst].tor
		rnicSeen[p.src], rnicSeen[p.dst] = true, true
		torSeen[srcTor], torSeen[dstTor] = true, true
		if srcTor != dstTor {
			rnicInter[p.src], rnicInter[p.dst] = true, true
			torInter[srcTor], torInter[dstTor] = true, true
			for _, c := range comps {
				interCount[c]++
				if c >= s.baseRail && c < s.fabric {
					rail := c - s.baseRail
					if sp.tors[srcTor].rail == rail {
						torInRail[srcTor] = true
					}
					if sp.tors[dstTor].rail == rail {
						torInRail[dstTor] = true
					}
				}
			}
		}

		if events == 0 {
			continue
		}
		s.fpath = append(s.fpath, int32(i))
		s.fevents = append(s.fevents, float64(events))
		s.ftrials = append(s.ftrials, float64(trials))
		s.frate = append(s.frate, s.p.baseline)
		s.fmask = append(s.fmask, mask)
		s.fcomps = append(s.fcomps, comps...)
		s.fcompsO = append(s.fcompsO, int32(len(s.fcomps)))
		for _, c := range comps {
			failedCount[c]++
		}
	}
	// Index the paths with events by component.
	s.failedOff = make([]int32, s.numComp+1)
	for c := 0; c < s.numComp; c++ {
		s.failedOff[c+1] = s.failedOff[c] + failedCount[c]
		if failedCount[c] > 0 {
			s.active = append(s.active, int32(c))
		}
	}
	s.failedList = make([]int32, s.failedOff[s.numComp])
	next := make([]int32, s.numComp)
	copy(next, s.failedOff[:s.numComp])
	for f := range s.fpath {
		for _, c := range s.pathComps(int32(f)) {
			s.failedList[next[c]] = int32(f)
			next[c]++
		}
	}

	s.observedMembers(rnicSeen, rnicInter, torSeen, torInter, torInRail)
	s.indexWindows()

	s.theta = make([]float64, s.numComp)
	s.gain = make([]float64, s.numComp)
	s.dirty = make([]bool, s.numComp)
	s.selected = make([]bool, s.numComp)
	s.banned = make([]bool, s.numComp)
	s.markCatchAlls(interCount)
	s.eligible = make([]int8, s.numComp)
	for _, c := range s.active {
		s.dirty[c] = true
	}
	s.rnicStamp = make([]int32, len(sp.rnics))
	s.torStamp = make([]int32, len(sp.tors))
	s.compStamp = make([]int32, s.numComp)
	return true
}

// markCatchAlls marks the components below the fabric that have exactly the
// paths of the background (every observed path) or of the fabric (every
// observed path between two ToRs). Such a component cannot be told from
// "all paths are degraded": a baseline set too low for the fabric, or a
// fault in a tier the facts do not describe. In a deployment of one ToR
// every path is that ToR's; in a fabric of one spine group every path
// between ToRs is that group's. Naming the ToR or the group would be a
// guess, so the component neither enters the explanation nor counts as an
// alternative: the catch-all takes its place, and the finding is "not
// localizable".
//
// A component's paths are a subset of the catch-all's, so equal counts mean
// equal sets (for the fabric: when all of the component's paths are between
// ToRs).
func (s *solver) markCatchAlls(interCount []int32) {
	s.catchAll = make([]bool, s.numComp)
	for c := int32(0); c < s.fabric; c++ {
		n := s.pathCount[c]
		if n == 0 {
			continue
		}
		if n == s.pathCount[s.background] || (interCount[c] == n && n == s.pathCount[s.fabric]) {
			s.catchAll[c] = true
		}
	}
}

// indexWindows records, for every path with events, its events by window.
func (s *solver) indexWindows() {
	events := s.sp.lossEvents
	if s.signal == KindRTT {
		events = s.sp.rttEvents
	}
	failedIdx := make([]int32, len(s.sp.paths))
	for i := range failedIdx {
		failedIdx[i] = -1
	}
	for f, path := range s.fpath {
		failedIdx[path] = int32(f)
	}
	s.fwinOff = make([]int32, len(s.fpath)+1)
	for _, window := range events {
		for _, ev := range window {
			if f := failedIdx[ev.path]; f >= 0 {
				s.fwinOff[f+1]++
			}
		}
	}
	for f := range s.fpath {
		s.fwinOff[f+1] += s.fwinOff[f]
	}
	s.fwin = make([]windowCount, s.fwinOff[len(s.fpath)])
	next := make([]int32, len(s.fpath))
	copy(next, s.fwinOff[:len(s.fpath)])
	for w, window := range events {
		for _, ev := range window {
			if f := failedIdx[ev.path]; f >= 0 {
				s.fwin[next[f]] = windowCount{window: uint8(w), count: float64(ev.count)}
				next[f]++
			}
		}
	}
}

// observedMembers counts, for each composite component, the members that
// take part in its paths: the RNICs of a host or under a ToR, the ToRs of a
// spine group, a rail or the fabric. A component with one observed member
// has the same paths as that member, so the member rule is waived for it and
// the two come out as equally likely.
func (s *solver) observedMembers(rnicSeen, rnicInter, torSeen, torInter, torInRail []bool) {
	sp := s.sp
	s.members = make([]int32, s.numComp)
	for r := range sp.rnics {
		if !rnicSeen[r] {
			continue
		}
		rnic := &sp.rnics[r]
		if rnic.host >= 0 {
			s.members[s.baseHost+rnic.host]++
		}
		s.members[s.baseTor+rnic.tor]++
		if rnicInter[r] {
			s.members[s.baseUplink+rnic.tor]++
		}
	}
	for t := range sp.tors {
		if !torSeen[t] {
			continue
		}
		tor := &sp.tors[t]
		s.members[s.background]++
		if torInter[t] {
			s.members[s.fabric]++
		}
		if torInter[t] && tor.group >= 0 {
			s.members[s.baseGroup+tor.group]++
		}
		if torInRail[t] && tor.rail >= 0 {
			s.members[s.baseRail+tor.rail]++
		}
	}
}

// pathComps returns the components of the f-th path with events.
func (s *solver) pathComps(f int32) []int32 {
	return s.fcomps[s.fcompsO[f]:s.fcompsO[f+1]]
}

// failed returns the paths with events of component c.
func (s *solver) failed(c int32) []int32 {
	return s.failedList[s.failedOff[c]:s.failedOff[c+1]]
}

// fit returns the maximum-likelihood excess rate of component c on top of
// the current rates, and the log-likelihood it gains:
//
//	gain(theta) = sum over c's paths with events of k*ln(1 + theta/rate) - trials(c)*theta
//
// Paths without events enter only through trials(c): each trial that did not
// fail speaks against the component. The gain is concave in theta, and its
// derivative is convex and decreasing, so Newton's method started left of
// the root converges to it from the left without overshooting.
func (s *solver) fit(c int32) (theta, gain float64) {
	trials := s.trials[c]
	failed := s.failed(c)
	if trials <= 0 || len(failed) == 0 {
		return 0, 0
	}
	var slope, events, maxRate float64
	for _, f := range failed {
		slope += s.fevents[f] / s.frate[f]
		events += s.fevents[f]
		maxRate = math.Max(maxRate, s.frate[f])
	}
	if slope <= trials {
		return 0, 0
	}
	// The root is at least events/trials - maxRate (it is exactly that when
	// every path has the rate maxRate).
	theta = math.Max(0, events/trials-maxRate)
	for iter := 0; iter < 64; iter++ {
		var d1, d2 float64
		for _, f := range failed {
			x := s.frate[f] + theta
			d1 += s.fevents[f] / x
			d2 += s.fevents[f] / (x * x)
		}
		step := (d1 - trials) / d2
		if !(step > 0) {
			break
		}
		theta += step
		if step <= 1e-10*theta {
			break
		}
	}
	for _, f := range failed {
		gain += s.fevents[f] * math.Log1p(theta/s.frate[f])
	}
	gain -= trials * theta
	if !(gain > 0) || math.IsInf(gain, 0) {
		return 0, 0
	}
	return theta, gain
}

// dispersion measures how unevenly the events of component c spread over its
// paths, given the rates currently in effect (which must include c's own
// excess): the Pearson statistic per path, 1 for Poisson counts. The model
// holds that a component adds the same excess to all of its paths. Events
// that pile up on a few of them say otherwise: a bystander whose three paths
// to a faulty RNIC fail while its other twenty are clean, or a spine group
// whose paths each use a single flow label, so that a path is hit fully or
// not at all. Dividing the gain by the dispersion (a quasi-likelihood) asks
// for more evidence exactly where the model fits worse.
//
// Paths without events enter with the rate baseline + excess, the least
// their rate can be, since their true rate is not tracked.
func (s *solver) dispersion(c int32, excess float64) float64 {
	paths := float64(s.pathCount[c])
	if paths < 2 {
		return 1
	}
	var stat, failedTrials float64
	for _, f := range s.failed(c) {
		expected := s.ftrials[f] * s.frate[f]
		d := s.fevents[f] - expected
		stat += d * d / expected
		failedTrials += s.ftrials[f]
	}
	stat += (s.trials[c] - failedTrials) * (s.p.baseline + excess)
	return math.Max(1, stat/(paths-1))
}

// placeDispersion returns the dispersion that discounts the evidence for
// the selected component c and for every alternative considered in its
// place: the larger of c's own dispersion and the dispersion of the
// explanation's other components that cover c's events.
//
// One scale for all alternatives of a place keeps them comparable: with a
// scale of its own, an alternative that explains a tenth of the events
// evenly would outrank the component that explains all of them unevenly.
//
// The second term keeps the noise of one fault from being read as another.
// When each path uses few flow labels, a faulty spine hits some paths of its
// group hard and spares others; a ToR whose paths happen to be hit harder
// than the group's average then shows an excess of its own. That excess is
// the group's dispersion, not a second fault.
func (s *solver) placeDispersion(c int32) float64 {
	return math.Max(s.dispersion(c, s.theta[c]), s.coverDispersion(c, c))
}

// coverDispersion returns the mean, weighted by events, of the dispersion of
// the explanation's components covering each of c's paths with events,
// leaving out the component except. It is 1 for events nothing else covers.
func (s *solver) coverDispersion(c, except int32) float64 {
	if s.fdisp == nil {
		return 1
	}
	var sum, events float64
	for _, f := range s.failed(c) {
		d := s.fdisp[f]
		if s.fdispOwner[f] == except {
			d = s.fdispSecond[f]
		}
		sum += s.fevents[f] * d
		events += s.fevents[f]
	}
	if events == 0 {
		return 1
	}
	return sum / events
}

// recordDispersions computes the dispersion of every component of the final
// explanation and notes, per path with events, the two largest among the
// components covering it.
func (s *solver) recordDispersions(order []int32) {
	s.fdisp = make([]float64, len(s.fpath))
	s.fdispSecond = make([]float64, len(s.fpath))
	s.fdispOwner = make([]int32, len(s.fpath))
	for f := range s.fdisp {
		s.fdisp[f], s.fdispSecond[f], s.fdispOwner[f] = 1, 1, -1
	}
	for _, c := range order {
		phi := s.dispersion(c, s.theta[c])
		for _, f := range s.failed(c) {
			switch {
			case phi > s.fdisp[f]:
				s.fdispSecond[f] = s.fdisp[f]
				s.fdisp[f], s.fdispOwner[f] = phi, c
			case phi > s.fdispSecond[f]:
				s.fdispSecond[f] = phi
			}
		}
	}
}

// shift adds delta to the rate of every path with events of component c and
// marks the components sharing those paths for a new fit.
func (s *solver) shift(c int32, delta float64) {
	if delta == 0 {
		return
	}
	for _, f := range s.failed(c) {
		s.frate[f] += delta
		for _, other := range s.pathComps(f) {
			s.dirty[other] = true
		}
	}
}

// nextGen starts a new use of the stamp arrays.
func (s *solver) nextGen() int32 {
	s.stampGen++
	return s.stampGen
}

// isEligible applies the breadth and persistence rules to component c. They
// depend only on which of its paths had events, so the result is cached.
func (s *solver) isEligible(c int32) bool {
	if s.eligible[c] != 0 {
		return s.eligible[c] > 0
	}
	ok := s.enoughPairs(c) && s.enoughWindows(c) && s.enoughMembers(c)
	if ok {
		s.eligible[c] = 1
	} else {
		s.eligible[c] = -1
	}
	return ok
}

// enoughPairs reports whether the events of c are on at least
// minFailedPairs distinct RNIC pairs. Both directions of a pair cross the
// same components, so they count once.
func (s *solver) enoughPairs(c int32) bool {
	var seen [minFailedPairs]uint64
	n := 0
next:
	for _, f := range s.failed(c) {
		p := &s.sp.paths[s.fpath[f]]
		lo, hi := p.src, p.dst
		if lo > hi {
			lo, hi = hi, lo
		}
		pair := uint64(lo)<<32 | uint64(hi)
		for _, k := range seen[:n] {
			if k == pair {
				continue next
			}
		}
		seen[n] = pair
		n++
		if n == minFailedPairs {
			return true
		}
	}
	return false
}

// eventWindows returns the number of windows in which c's paths had events.
func (s *solver) eventWindows(c int32) int {
	var mask uint64
	for _, f := range s.failed(c) {
		mask |= s.fmask[f]
	}
	return bits.OnesCount64(mask)
}

// enoughWindows reports whether the events of c persist: they fall in at
// least minEventWindows windows, and no two adjacent windows hold more than
// maxWindowShare of them together. Counting windows with events is not
// enough on its own, because background noise puts a stray event next to
// any burst. With a span configured to two windows the share is taken per
// window: such a span cannot tell a burst across the boundary from a fault.
//
// Windows are adjacent by their position in the span. A window for which
// nothing was reported is not in the span, so its neighbours count as
// adjacent: that errs towards waiting.
func (s *solver) enoughWindows(c int32) bool {
	if s.p.spanWindows < minEventWindows {
		return true
	}
	if s.eventWindows(c) < minEventWindows {
		return false
	}
	var perWindow [MaxLocalizationWindows]float64
	for _, f := range s.failed(c) {
		for _, wc := range s.fwin[s.fwinOff[f]:s.fwinOff[f+1]] {
			perWindow[wc.window] += wc.count
		}
	}
	windows := min(s.sp.windows, MaxLocalizationWindows)
	var total, busiest float64
	for w := 0; w < windows; w++ {
		n := perWindow[w]
		total += n
		if s.p.spanWindows > minEventWindows && w+1 < windows {
			n += perWindow[w+1]
		}
		busiest = math.Max(busiest, n)
	}
	return busiest <= maxWindowShare*total
}

// persists applies the persistence rule to what the selected component c
// itself explains: its events beyond what the rest of the explanation and
// the baseline account for, window by window. enoughWindows looks at all
// events on the component's paths, which is not the same once another
// component explains part of them: a ToR that drops packets for a few
// seconds while a fault above it lasts has events in every window (the
// fault's) and an excess of its own in one or two (the burst's). The share
// rule is the one of enoughWindows; trials are taken as spread evenly over
// the windows of the span.
func (s *solver) persists(c int32) bool {
	if s.p.spanWindows < minEventWindows {
		return true
	}
	windows := min(s.sp.windows, MaxLocalizationWindows)
	var perWindow [MaxLocalizationWindows]float64
	var expected, failedTrials float64
	for _, f := range s.failed(c) {
		for _, wc := range s.fwin[s.fwinOff[f]:s.fwinOff[f+1]] {
			perWindow[wc.window] += wc.count
		}
		expected += s.ftrials[f] * (s.frate[f] - s.theta[c])
		failedTrials += s.ftrials[f]
	}
	expected += (s.trials[c] - failedTrials) * s.p.baseline
	expected /= float64(windows)

	var total float64
	with := 0
	for w := 0; w < windows; w++ {
		perWindow[w] = math.Max(0, perWindow[w]-expected)
		total += perWindow[w]
		if perWindow[w] > 0 {
			with++
		}
	}
	if with < minEventWindows {
		return false
	}
	var busiest float64
	for w := 0; w < windows; w++ {
		n := perWindow[w]
		if s.p.spanWindows > minEventWindows && w+1 < windows {
			n += perWindow[w+1]
		}
		busiest = math.Max(busiest, n)
	}
	return busiest <= maxWindowShare*total
}

// enoughMembers reports whether the events of a composite component touch
// at least minFailedMembers of its members, when it has that many.
func (s *solver) enoughMembers(c int32) bool {
	if c < s.baseHost || s.members[c] < minFailedMembers {
		return true
	}
	gen := s.nextGen()
	count := 0
	mark := func(stamp []int32, id int32) bool {
		if stamp[id] != gen {
			stamp[id] = gen
			count++
		}
		return count >= minFailedMembers
	}
	sp := s.sp
	for _, f := range s.failed(c) {
		p := &sp.paths[s.fpath[f]]
		for _, r := range [2]int32{p.src, p.dst} {
			rnic := &sp.rnics[r]
			tor := &sp.tors[rnic.tor]
			var done bool
			switch {
			case c < s.baseTor:
				if rnic.host == c-s.baseHost {
					done = mark(s.rnicStamp, r)
				}
			case c < s.baseUplink:
				if rnic.tor == c-s.baseTor {
					done = mark(s.rnicStamp, r)
				}
			case c < s.baseGroup:
				if rnic.tor == c-s.baseUplink {
					done = mark(s.rnicStamp, r)
				}
			case c < s.baseRail:
				if tor.group == c-s.baseGroup {
					done = mark(s.torStamp, rnic.tor)
				}
			case c < s.fabric:
				if tor.rail == c-s.baseRail {
					done = mark(s.torStamp, rnic.tor)
				}
			default:
				done = mark(s.torStamp, rnic.tor)
			}
			if done {
				return true
			}
		}
	}
	return false
}

// greedy adds components to the explanation, largest gain first, until none
// gains detectNats. Equal gains go to the more specific component (the lower
// ID); the posterior later reports such a tie as an ambiguity. It returns
// the extended explanation and the log-likelihood the added components
// gained together.
//
// The evidence rules do not apply here: a component that may not be named
// (one stuck path, one burst) still explains its events. Left unexplained,
// they would be put down to a bystander that shares those paths.
func (s *solver) greedy(order []int32, limit int) ([]int32, float64) {
	detect := s.p.detectNats()
	var gained float64
	for len(order) < min(limit, maxExplanation) {
		best, bestGain := int32(-1), detect
		for _, c := range s.active {
			if s.selected[c] || s.banned[c] || s.catchAll[c] {
				continue
			}
			if s.dirty[c] {
				s.theta[c], s.gain[c] = s.fit(c)
				s.dirty[c] = false
			}
			if s.gain[c] > bestGain {
				best, bestGain = c, s.gain[c]
			}
		}
		if best < 0 {
			break
		}
		s.selected[best] = true
		s.shift(best, s.theta[best])
		order = append(order, best)
		gained += bestGain
	}
	return order, gained
}

// split tries to replace each composite component of the explanation by
// more specific ones. The greedy takes the component with the largest gain
// first, which is a broad one whenever several of its members are degraded:
// four lossy RNICs under one ToR gain more together, as "the ToR", than any
// one of them, although the ToR's other RNICs are clean. With the broad
// component removed, the greedy explains the same events again; the
// replacement is kept when it is the more probable explanation, i.e. when
// its likelihood exceeds the broad component's by more than the prior
// (priorNats) each extra component costs. The difference is divided by the
// broad component's dispersion first: with over-dispersed counts, several
// components always fit better than one.
func (s *solver) split(order []int32) []int32 {
	for _, c := range append([]int32(nil), order...) {
		if c < s.baseHost || !s.selected[c] {
			continue // an RNIC has nothing below it
		}
		without := make([]int32, 0, len(order))
		for _, other := range order {
			if other != c {
				without = append(without, other)
			}
		}
		phi := s.dispersion(c, s.theta[c])
		s.shift(c, -s.theta[c])
		s.selected[c] = false
		s.banned[c] = true
		theta, gain := s.fit(c)

		replaced, gained := s.greedy(without, len(without)+maxSplitParts)
		added := replaced[len(without):]
		if (gained-gain)/phi > float64(len(added)-1)*priorNats {
			order = replaced
			continue
		}
		for i := len(added) - 1; i >= 0; i-- {
			s.shift(added[i], -s.theta[added[i]])
			s.selected[added[i]] = false
		}
		s.banned[c] = false
		s.selected[c] = true
		s.theta[c], s.gain[c] = theta, gain
		s.shift(c, theta)
	}
	return order
}

// refit re-estimates each selected component's rate given the others, round
// after round until the rates settle, and drops the components that no
// longer gain detectNats. A broad component picked first on diluted evidence
// gives way here to the specific ones picked after it. It reports whether a
// component was dropped.
//
// The likelihood is concave in the rates, so this coordinate ascent
// converges to the joint maximum; components that share most of their paths
// (a spine group and its rail) need several rounds to trade their rates.
func (s *solver) refit(order []int32) ([]int32, bool) {
	detect := s.p.detectNats()
	dropped := false
	for round := 0; round < maxRefitRounds; round++ {
		settled := true
		kept := order[:0]
		for _, c := range order {
			old := s.theta[c]
			s.shiftRates(c, -old)
			theta, gain := s.fit(c)
			s.theta[c], s.gain[c] = theta, gain
			if gain < detect {
				s.selected[c] = false
				dropped, settled = true, false
				continue
			}
			s.shiftRates(c, theta)
			if math.Abs(theta-old) > refitTolerance*theta {
				settled = false
			}
			kept = append(kept, c)
		}
		order = kept
		if settled {
			break
		}
	}
	// Every rate may have moved: all cached fits are stale.
	for _, c := range s.active {
		s.dirty[c] = true
	}
	return order, dropped
}

// shiftRates adds delta to the rate of every path with events of component
// c, without marking the cached fits of other components stale.
func (s *solver) shiftRates(c int32, delta float64) {
	for _, f := range s.failed(c) {
		s.frate[f] += delta
	}
}

// candidate is one alternative for a place in the explanation. gain is its
// likelihood gain divided by the dispersion of the place (see
// placeDispersion).
type candidate struct {
	comp  int32
	theta float64
	gain  float64
	conf  float64
}

// alternatives fits, in the place of the selected component c, every
// component that shares one of its paths with events, and returns them with
// their posterior probabilities, highest first. The posterior of "no fault
// in this place" is the remainder to one.
func (s *solver) alternatives(c int32) []candidate {
	phi := s.placeDispersion(c)
	s.shift(c, -s.theta[c])
	gen := s.nextGen()
	var cands []candidate
	for _, f := range s.failed(c) {
		for _, other := range s.pathComps(f) {
			if s.compStamp[other] == gen {
				continue
			}
			s.compStamp[other] = gen
			// A component that a split replaced stays an alternative: it
			// lost its place to c, not its claim on the events.
			if (s.selected[other] && other != c) || s.catchAll[other] || !s.isEligible(other) {
				continue
			}
			// The fabric and the background stand for what the facts do
			// not describe. They are no alternative to a component the
			// facts do describe: in a fabric of one spine group, the
			// fabric has that group's very paths.
			if other >= s.fabric && c < s.fabric {
				continue
			}
			if theta, gain := s.fit(other); gain > 0 {
				cands = append(cands, candidate{comp: other, theta: theta, gain: gain / phi})
			}
		}
	}
	s.shift(c, s.theta[c])

	// Posterior with the prior odds e^-priorNats per component and 1 for
	// "no fault": conf = e^(gain-prior) / (1 + sum of e^(gain-prior)),
	// computed relative to the largest term to stay finite.
	top := 0.0
	for _, cand := range cands {
		top = math.Max(top, cand.gain-priorNats)
	}
	total := math.Exp(-top)
	for i := range cands {
		cands[i].conf = math.Exp(cands[i].gain - priorNats - top)
		total += cands[i].conf
	}
	for i := range cands {
		cands[i].conf /= total
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].conf != cands[j].conf {
			return cands[i].conf > cands[j].conf
		}
		return cands[i].comp < cands[j].comp
	})
	return cands
}

// solved is a finding with the component IDs of its suspects.
type solved struct {
	Finding
	comps []int32
}

// solve runs the tomography for the solver's signal.
func (s *solver) solve() []Finding {
	if s.p.baseline <= 0 || len(s.sp.paths) == 0 || !s.prepare() {
		return nil
	}

	order, _ := s.greedy(nil, maxExplanation)
	for pass := 0; pass < 2; pass++ {
		var dropped bool
		order, dropped = s.refit(order)
		if !dropped {
			break
		}
		// Dropping a component frees the events it explained.
		order, _ = s.greedy(order, maxExplanation)
	}
	order = s.split(order)
	// The rates the confidences are computed against are a joint fit, also
	// when the steps above ended on a greedy step.
	order, _ = s.refit(order)
	s.recordDispersions(order)

	var found []solved
	reported := make(map[string]struct{})
	for _, c := range order {
		if len(found) == maxFindingsPerSignal {
			break
		}
		if !s.isEligible(c) || !s.persists(c) {
			continue // explains its events, but may not be named
		}
		f, ok := s.finding(s.alternatives(c))
		if !ok {
			continue
		}
		// Two selected components can share their whole candidate set.
		key := f.key()
		if _, dup := reported[key]; dup {
			continue
		}
		reported[key] = struct{}{}
		found = append(found, f)
	}

	findings := s.foldSiblings(found)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].key() < findings[j].key() })
	return findings
}
