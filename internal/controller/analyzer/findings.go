package analyzer

import (
	"math"
	"sort"
)

// This file holds what the tomography reports: the components a finding can
// name, the finding itself, and the step from the solver's explanation to
// findings, including the folding of sibling findings into the scope they
// share.

// Component kinds a finding can name, most specific first. They are the
// values of the "component" metric attribute.
const (
	// ComponentRNIC is one RNIC with its cable and switch port: every path
	// that starts or ends at it.
	ComponentRNIC = "rnic"
	// ComponentHost is a host with at least two observed RNICs: every path
	// of any of them.
	ComponentHost = "host"
	// ComponentTor is a ToR switch as a whole: every path that starts or
	// ends under it, including the paths that stay under it.
	ComponentTor = "tor"
	// ComponentTorUplink is the set of a ToR's uplinks: every path between
	// it and another ToR, but not the paths that stay under it. One lossy
	// uplink (one ECMP member) shows here.
	ComponentTorUplink = "tor_uplink"
	// ComponentSpineGroup is a set of spines sharing the same ToRs: every
	// path between two ToRs of which at least one is in the group.
	ComponentSpineGroup = "spine_group"
	// ComponentRail is the tier that joins a rail's spine groups (or, in a
	// rail without spine groups, its ToRs): every path that crosses it.
	ComponentRail = "rail"
	// ComponentFabric is everything above the ToRs taken together: every
	// path between two ToRs. It catches what the topology facts do not
	// divide further and is only ever reported as not localizable.
	ComponentFabric = "fabric"
	// ComponentBackground is every observed path. Excess here means that
	// the baseline is exceeded everywhere alike: the baseline is set too
	// low for this fabric, or all of it is degraded. It is only ever
	// reported as not localizable, and the other components are then judged
	// against the background that was observed.
	ComponentBackground = "background"
)

// States of a finding. They are the values of the "state" metric attribute.
const (
	// StateLocalized: one component holds the minimum confidence.
	StateLocalized = "localized"
	// StateAmbiguous: several components explain the evidence; the finding
	// lists the candidates.
	StateAmbiguous = "ambiguous"
	// StateNotLocalizable: the evidence points at more siblings of one scope
	// than independent faults plausibly explain, or at the whole fabric. The
	// finding names the scope, not a suspect inside it.
	StateNotLocalizable = "not_localizable"
)

// Component identifies a component of the fabric. Only the fields that
// apply to its kind are set.
type Component struct {
	Kind string
	// Tor is the ToR of an rnic, tor or tor_uplink component.
	Tor string
	// SpineGroup and Rail are the component itself for those kinds, and the
	// stated facts of the ToR for the kinds below.
	SpineGroup string
	Rail       string
	// GID identifies an rnic component; AgentID an rnic's or a host's agent
	// ("" when no agent reported the RNIC). Neither is ever a metric
	// attribute.
	GID     string
	AgentID string
}

// identity is a stable key of the component for sorting and for telling
// findings apart between evaluations.
func (c Component) identity() string {
	switch c.Kind {
	case ComponentRNIC:
		return c.Kind + "/" + c.GID
	case ComponentHost:
		return c.Kind + "/" + c.AgentID
	case ComponentTor, ComponentTorUplink:
		return c.Kind + "/" + c.Tor
	case ComponentSpineGroup:
		return c.Kind + "/" + c.SpineGroup
	case ComponentRail:
		return c.Kind + "/" + c.Rail
	default:
		return c.Kind
	}
}

// Suspect is one candidate of a finding with its evidence.
type Suspect struct {
	Component Component
	// Confidence is the posterior probability that this component is the
	// faulty one, among the components that could explain the same events
	// and "no fault", under the model and an equal prior. On the scope of a
	// folded finding it is the largest confidence that one of the folded
	// findings puts on its candidates together.
	Confidence float64
	// ExcessRatio is the estimated rate of events this component adds to
	// each of its paths, on top of the baseline and of the other suspects:
	// lost probes per probe, or violating windows per window.
	ExcessRatio float64
	// EvidenceNats is the log-likelihood the component gains over the
	// explanation without it, divided by the dispersion of its place (see
	// solver.placeDispersion). It is what the confidence is computed from.
	EvidenceNats float64
	// Paths and FailedPaths count the component's observed paths and those
	// with events; Trials and Events their probes and lost probes (or
	// windows and violating windows).
	Paths       int
	FailedPaths int
	Trials      uint64
	Events      uint64
	// Windows counts the windows of the span in which the component's paths
	// had events.
	Windows int
}

// Finding is one result of an evaluation.
type Finding struct {
	// Signal is KindLoss or KindRTT.
	Signal string
	State  string
	// Suspects is the candidate set, highest confidence first: one suspect
	// when localized or not localizable, at least two when ambiguous.
	Suspects []Suspect
	// Truncated reports that an ambiguous finding lists maxCandidates
	// candidates whose confidences sum to less than the minimum confidence.
	Truncated bool
	// Members names the components folded into a not-localizable finding
	// (ToR IDs, spine groups or rails), sorted, at most maxMembersListed;
	// MemberCount is their number before the cut.
	Members     []string
	MemberCount int
}

// key identifies the finding between evaluations: its signal, state and
// candidate set.
func (f Finding) key() string {
	ids := make([]string, 0, len(f.Suspects))
	for _, s := range f.Suspects {
		ids = append(ids, s.Component.identity())
	}
	sort.Strings(ids)
	key := f.Signal + "|" + f.State
	for _, id := range ids {
		key += "|" + id
	}
	return key
}

// finding turns the alternatives of one place in the explanation into a
// finding: the smallest set of candidates whose posteriors reach the minimum
// confidence. ok is false when even all of them together do not, i.e. "no
// fault" keeps too much of the probability.
func (s *solver) finding(cands []candidate) (solved, bool) {
	var mass float64
	for _, cand := range cands {
		mass += cand.conf
	}
	// The sum of many posteriors can round to just under the threshold.
	const slack = 1e-9
	if len(cands) == 0 || mass < s.p.minConfidence-slack {
		return solved{}, false
	}

	f := solved{Finding: Finding{Signal: s.signal}}
	var cum float64
	for _, cand := range cands {
		if len(f.Suspects) == maxCandidates {
			f.Truncated = true
			break
		}
		f.Suspects = append(f.Suspects, s.suspect(cand))
		f.comps = append(f.comps, cand.comp)
		cum += cand.conf
		if cum >= s.p.minConfidence-slack {
			break
		}
	}
	switch {
	case len(f.Suspects) > 1:
		f.State = StateAmbiguous
	case f.comps[0] >= s.fabric:
		f.State = StateNotLocalizable
	default:
		f.State = StateLocalized
	}
	return f, true
}

// suspect describes a candidate for reporting.
func (s *solver) suspect(cand candidate) Suspect {
	var events float64
	for _, f := range s.failed(cand.comp) {
		events += s.fevents[f]
	}
	return Suspect{
		Component:    s.component(cand.comp),
		Confidence:   cand.conf,
		ExcessRatio:  cand.theta,
		EvidenceNats: cand.gain,
		Paths:        int(s.pathCount[cand.comp]),
		FailedPaths:  len(s.failed(cand.comp)),
		Trials:       uint64(s.trials[cand.comp]),
		Events:       uint64(events),
		Windows:      s.eventWindows(cand.comp),
	}
}

// component describes a component ID.
func (s *solver) component(c int32) Component {
	sp := s.sp
	torFacts := func(comp *Component, t int32) {
		tor := &sp.tors[t]
		comp.Tor = tor.name
		if tor.group >= 0 {
			comp.SpineGroup = sp.groups[tor.group]
		}
		if tor.rail >= 0 {
			comp.Rail = sp.rails[tor.rail]
		}
	}
	comp := Component{Kind: s.kindOf(c)}
	switch comp.Kind {
	case ComponentRNIC:
		rnic := &sp.rnics[c]
		comp.GID, comp.AgentID = rnic.gid, rnic.agent
		torFacts(&comp, rnic.tor)
	case ComponentHost:
		comp.AgentID = sp.hosts[c-s.baseHost]
	case ComponentTor:
		torFacts(&comp, c-s.baseTor)
	case ComponentTorUplink:
		torFacts(&comp, c-s.baseUplink)
	case ComponentSpineGroup:
		group := c - s.baseGroup
		comp.SpineGroup = sp.groups[group]
		if rail := sp.groupRail[group]; rail >= 0 {
			comp.Rail = sp.rails[rail]
		}
	case ComponentRail:
		comp.Rail = sp.rails[c-s.baseRail]
	}
	return comp
}

// Tiers of the fabric above the hosts, for folding siblings.
const (
	tierTor = iota
	tierGroup
	tierRail
)

// sibling places a component in the tree of tiers: its tier, its index
// within the tier (a ToR, spine group or rail index) and the component
// directly above it, its scope. ok is false for RNICs, hosts and the two
// catch-alls. A ToR's switch and its uplinks are the same member.
func (s *solver) sibling(c int32) (tier int, member, scope int32, ok bool) {
	sp := s.sp
	torScope := func(t int32) int32 {
		tor := &sp.tors[t]
		switch {
		case tor.group >= 0:
			return s.baseGroup + tor.group
		case tor.rail >= 0:
			return s.baseRail + tor.rail
		}
		return s.fabric
	}
	switch {
	case c < s.baseTor || c >= s.fabric:
		return 0, 0, 0, false
	case c < s.baseUplink:
		return tierTor, c - s.baseTor, torScope(c - s.baseTor), true
	case c < s.baseGroup:
		return tierTor, c - s.baseUplink, torScope(c - s.baseUplink), true
	case c < s.baseRail:
		group := c - s.baseGroup
		if rail := sp.groupRail[group]; rail >= 0 {
			return tierGroup, group, s.baseRail + rail, true
		}
		return tierGroup, group, s.fabric, true
	default:
		return tierRail, c - s.baseRail, s.fabric, true
	}
}

// siblingLimit is the most members of the group that are reported
// individually.
//
// No member is reported individually under a scope that is itself part of
// the explanation with a dispersion above maxScopeDispersion. The scope's
// excess is then spread too unevenly over its paths for the model to hold
// (a fault in a tier the facts do not describe, between the scope and its
// members, looks like this), and what remains on one member after
// subtracting the scope's average is that unevenness, not a second fault.
//
// The uplinks of ToRs whose upper tiers the topology does not state need
// more care, because the model holds nothing that a fault above them could
// be put on. Two such ToRs degraded at once are folded: two uplink faults
// cannot be told from one fault in the unknown tier above both. One such
// ToR is reported on its own only when a fault above it would have shown on
// the other ToRs (see siblingsWouldShow).
func (s *solver) siblingLimit(g *siblingGroup) int {
	if s.selected[g.scope] && s.dispersion(g.scope, s.theta[g.scope]) > maxScopeDispersion {
		return 0
	}
	if g.tier == tierTor && g.scope == s.fabric && g.uplinks {
		if !s.siblingsWouldShow(g) {
			return 0
		}
		return 1
	}
	return maxSiblings
}

// siblingsWouldShow reports whether an excess as large as the group's, if
// it sat in a tier above the ToRs, would have left evidence on every other
// ToR without stated facts: at least powerNats expected on each, three
// times what it takes to count as a hinted sibling. When it would, and the
// other ToRs are clean, the excess belongs to the named ToR. When it would
// not (a weak fault, or ToRs with few probes), their silence proves
// nothing.
func (s *solver) siblingsWouldShow(g *siblingGroup) bool {
	base, excess := s.p.baseline, g.minExcess
	// The gain per trial a path at the rate base+excess is expected to
	// yield over the baseline: the Kullback-Leibler divergence of the two
	// Poisson rates.
	perTrial := (base+excess)*math.Log((base+excess)/base) - excess
	siblings := 0
	for t := range s.sp.tors {
		if _, named := g.members[int32(t)]; named || s.sp.tors[t].known() {
			continue
		}
		trials := s.trials[s.baseUplink+int32(t)]
		if trials == 0 {
			continue
		}
		siblings++
		if trials*perTrial < powerNats {
			return false
		}
	}
	return siblings > 0
}

// memberName names a member of a tier.
func (s *solver) memberName(tier int, member int32) string {
	switch tier {
	case tierTor:
		return s.sp.tors[member].name
	case tierGroup:
		return s.sp.groups[member]
	default:
		return s.sp.rails[member]
	}
}

// siblingGroup collects the findings that point at members of one tier
// under one scope.
type siblingGroup struct {
	tier    int
	scope   int32
	members map[int32]struct{}
	idx     []int // indexes of the findings
	// minExcess is the smallest excess among the findings' suspects.
	minExcess float64
	// uplinks records that a finding names a ToR's uplinks, not only the
	// ToR as a whole. A fault above the ToRs can look like the former, but
	// not like the latter: it does not touch the paths under one ToR.
	uplinks bool
}

// foldSiblings replaces the findings that point at more members of one
// scope than siblingLimit allows by a single not-localizable finding on that
// scope. The solver explains each degraded member on its own when no
// component of the model covers them together, which happens when the
// topology facts are missing or coarser than the fabric. Several members
// degraded at once are then reported as what is known: the scope they share
// and who they are.
func (s *solver) foldSiblings(found []solved) []Finding {
	type groupKey struct {
		tier  int
		scope int32
	}
	groups := make(map[groupKey]*siblingGroup)
	var order []groupKey
next:
	for i, f := range found {
		var key groupKey
		var members []int32
		for j, c := range f.comps {
			tier, member, scope, ok := s.sibling(c)
			if !ok || (j > 0 && (tier != key.tier || scope != key.scope)) {
				continue next
			}
			key = groupKey{tier: tier, scope: scope}
			members = append(members, member)
		}
		g := groups[key]
		if g == nil {
			g = &siblingGroup{tier: key.tier, scope: key.scope, members: make(map[int32]struct{}), minExcess: math.Inf(1)}
			groups[key] = g
			order = append(order, key)
		}
		for _, m := range members {
			g.members[m] = struct{}{}
		}
		for _, sus := range f.Suspects {
			g.minExcess = math.Min(g.minExcess, sus.ExcessRatio)
			g.uplinks = g.uplinks || sus.Component.Kind == ComponentTorUplink
		}
		g.idx = append(g.idx, i)
	}

	folded := make(map[int]struct{})
	var merged []Finding
	for _, key := range order {
		g := groups[key]
		s.addHintedSiblings(g)
		if len(g.members) <= s.siblingLimit(g) {
			continue
		}
		m := Finding{
			Signal:      s.signal,
			State:       StateNotLocalizable,
			MemberCount: len(g.members),
			Suspects:    []Suspect{{Component: s.component(g.scope)}},
		}
		sus := &m.Suspects[0]
		for _, i := range g.idx {
			folded[i] = struct{}{}
			var mass float64
			for _, member := range found[i].Suspects {
				mass += member.Confidence
				sus.ExcessRatio = math.Max(sus.ExcessRatio, member.ExcessRatio)
				sus.EvidenceNats = math.Max(sus.EvidenceNats, member.EvidenceNats)
				sus.Windows = max(sus.Windows, member.Windows)
			}
			// The scope holds a fault at least as surely as its surest member.
			sus.Confidence = math.Max(sus.Confidence, math.Min(mass, 1))
		}
		for member := range g.members {
			m.Members = append(m.Members, s.memberName(g.tier, member))
		}
		sort.Strings(m.Members)
		if len(m.Members) > maxMembersListed {
			m.Members = m.Members[:maxMembersListed]
		}
		merged = append(merged, m)
	}

	kept := make([]Finding, 0, len(found))
	for i, f := range found {
		if _, gone := folded[i]; !gone {
			kept = append(kept, f.Finding)
		}
	}
	// A finding that already names the scope takes the folded members:
	// reporting the scope twice would say nothing more.
	for _, m := range merged {
		scope := m.Suspects[0].Component.identity()
		absorbed := false
		for i := range kept {
			if len(kept[i].Suspects) == 1 && kept[i].Suspects[0].Component.identity() == scope {
				kept[i].Members, kept[i].MemberCount = m.Members, m.MemberCount
				absorbed = true
				break
			}
		}
		if !absorbed {
			kept = append(kept, m)
		}
	}
	return kept
}

// addHintedSiblings adds to g the members of its scope that no finding
// names but that show the same kind of excess below the detection
// threshold: at least hintNats of evidence and a comparable rate. A fault
// that several siblings share is strongest in one of them by chance; that
// one alone would pass for a fault of its own.
func (s *solver) addHintedSiblings(g *siblingGroup) {
	hinted := func(c int32) bool {
		if s.banned[c] || len(s.failed(c)) == 0 || !s.isEligible(c) {
			return false
		}
		// A sibling can be part of the explanation without a finding of
		// its own, when its evidence does not reach the threshold once
		// discounted.
		theta, gain := s.theta[c], s.gain[c]
		if !s.selected[c] {
			theta, gain = s.fit(c)
		}
		return gain/s.coverDispersion(c, c) >= hintNats && theta >= hintExcessShare*g.minExcess
	}
	consider := func(member int32, comps ...int32) {
		if _, named := g.members[member]; named {
			return
		}
		_, _, scope, _ := s.sibling(comps[0])
		if scope != g.scope {
			return
		}
		for _, c := range comps {
			if hinted(c) {
				g.members[member] = struct{}{}
				return
			}
		}
	}
	switch g.tier {
	case tierTor:
		for t := range s.sp.tors {
			consider(int32(t), s.baseTor+int32(t), s.baseUplink+int32(t))
		}
	case tierGroup:
		for group := range s.sp.groups {
			consider(int32(group), s.baseGroup+int32(group))
		}
	case tierRail:
		for rail := range s.sp.rails {
			consider(int32(rail), s.baseRail+int32(rail))
		}
	}
}
