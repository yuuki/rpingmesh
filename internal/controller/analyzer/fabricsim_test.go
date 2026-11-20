package analyzer

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// simFabric is a synthetic rail-optimized Clos fabric that produces the path
// summaries agents would report. It is the ground truth the localizer is
// validated against: faults are injected into physical elements (one RNIC,
// one ToR-to-spine link, one spine, one core switch), and the localizer sees
// only what a controller sees.
//
// Layout. Each of rails rails has groups spine groups of tors ToRs; hosts
// hosts hang off every ToR position, and a host has one RNIC per rail, on
// the ToR of its position in that rail. A ToR has spines uplinks, one to each
// spine of its group; a spine has cores uplinks, one to each core switch of
// its rail.
//
// Probing follows the controller: every RNIC probes the other RNICs under
// its ToR (ToR-mesh) and one RNIC under each of interTor other ToRs of its
// rail (inter-ToR). A path cycles through flowLabels flow labels. Each
// (path, direction, label) is hashed to one ToR uplink, one core and one
// spine downlink, as ECMP does; the localizer is not told the hash.
//
// A probe is lost when the probe or its ACK is dropped by any element on its
// way, or by the background noise. Every probe is drawn on its own, so the
// counts carry binomial sampling noise.
type simFabric struct {
	rails, groups, tors, hosts int
	spines, cores              int

	flowLabels  int
	interTor    int
	meshProbes  int // probes per ToR-mesh path and window
	interProbes int // probes per inter-ToR path and window

	// noiseLoss is the probability that a probe is lost on a healthy path;
	// noiseRTT that a completed probe's RTT lands above the RTT threshold.
	noiseLoss float64
	noiseRTT  float64

	windowNs uint64
	seed     uint64
	faults   []simFault
	// silent lists agents that send no reports (their hosts still answer
	// probes).
	silent map[string]bool
	// windowFaults limits a fault to some windows: fault index -> windows.
	windowFaults map[int]map[int]bool

	rnics []simRNIC
	paths []simPath
	rng   *rand.Rand
}

// simFault is one faulty element. loss is its drop probability per packet
// that crosses it; delayNs is added to the RTT of a probe for each crossing.
type simFault struct {
	element string // "rnic", "host", "tor", "uplink", "spine", "core"
	rail    int
	group   int
	tor     int
	host    int
	member  int // uplink or spine index within the group, or core index
	loss    float64
	delayNs uint64
}

type simRNIC struct {
	rail, group, tor, host int
	gid                    string
	torID                  string
	agent                  string
}

// simHop is the ECMP choice of one direction of a path for one flow label:
// the spine reached from the first ToR, the core (when the path leaves the
// spine group) and the spine above the second ToR.
type simHop struct {
	up, core, down int8
}

type simPath struct {
	src, dst int
	mesh     bool
	fwd, rev []simHop // per flow label
	cursor   int      // next flow label, continuing across windows
}

const (
	simRTTThresholdNs = 500_000
	simWindowNs       = 30 * uint64(time.Second)
	simBaseStartNs    = 1_700_000_000 * uint64(time.Second)
)

// defaultSimFabric is two rails of two spine groups of four ToRs with six
// hosts per ToR position: 96 RNICs and 16 ToRs.
func defaultSimFabric(seed uint64) *simFabric {
	return &simFabric{
		rails: 2, groups: 2, tors: 4, hosts: 6,
		spines: 4, cores: 4,
		flowLabels: 64, interTor: 5,
		meshProbes: 60, interProbes: 30,
		noiseLoss: 1e-4, noiseRTT: 1e-4,
		windowNs: simWindowNs,
		seed:     seed,
	}
}

func (f *simFabric) torName(rail, group, tor int) string {
	return fmt.Sprintf("leaf-r%d-g%d-t%d", rail, group, tor)
}

func (f *simFabric) groupName(rail, group int) string {
	return fmt.Sprintf("pod-r%d-g%d", rail, group)
}

func (f *simFabric) railName(rail int) string { return fmt.Sprintf("rail%d", rail) }

func (f *simFabric) agentName(group, tor, host int) string {
	return fmt.Sprintf("host-g%d-t%d-h%02d", group, tor, host)
}

func (f *simFabric) gid(rail, group, tor, host int) string {
	return fmt.Sprintf("fd00:%04x:%04x:%04x:0000:0000:0000:%04x", rail, group, tor, host+1)
}

// topology returns the topology file of the fabric as the operator would
// write it. withGroups and withRails select which facts it states.
func (f *simFabric) topology(t testing.TB, withGroups, withRails bool) *Topology {
	t.Helper()
	var b strings.Builder
	b.WriteString("version: 1\ntors:\n")
	for r := 0; r < f.rails; r++ {
		for g := 0; g < f.groups; g++ {
			for tor := 0; tor < f.tors; tor++ {
				fmt.Fprintf(&b, "  %s:\n", f.torName(r, g, tor))
				if withRails {
					fmt.Fprintf(&b, "    rail: %s\n", f.railName(r))
				}
				if withGroups {
					fmt.Fprintf(&b, "    spine_group: %s\n", f.groupName(r, g))
				}
				if !withRails && !withGroups {
					b.WriteString("    {}\n")
				}
			}
		}
	}
	topo, err := ParseTopology([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseTopology of the simulated fabric: %v", err)
	}
	return topo
}

// build lays out the RNICs and draws every RNIC's targets and every path's
// ECMP hash.
func (f *simFabric) build() {
	f.rng = rand.New(rand.NewPCG(f.seed, 0x5eed))
	f.rnics = f.rnics[:0]
	f.paths = f.paths[:0]
	index := func(r, g, t, h int) int { return ((r*f.groups+g)*f.tors+t)*f.hosts + h }
	for r := 0; r < f.rails; r++ {
		for g := 0; g < f.groups; g++ {
			for t := 0; t < f.tors; t++ {
				for h := 0; h < f.hosts; h++ {
					f.rnics = append(f.rnics, simRNIC{
						rail: r, group: g, tor: t, host: h,
						gid:   f.gid(r, g, t, h),
						torID: f.torName(r, g, t),
						agent: f.agentName(g, t, h),
					})
				}
			}
		}
	}
	for src := range f.rnics {
		a := &f.rnics[src]
		for h := 0; h < f.hosts; h++ {
			if h != a.host {
				f.addPath(src, index(a.rail, a.group, a.tor, h), true)
			}
		}
		// One RNIC under each of interTor other ToRs of the rail.
		others := make([][2]int, 0, f.groups*f.tors)
		for g := 0; g < f.groups; g++ {
			for t := 0; t < f.tors; t++ {
				if g != a.group || t != a.tor {
					others = append(others, [2]int{g, t})
				}
			}
		}
		f.rng.Shuffle(len(others), func(i, j int) { others[i], others[j] = others[j], others[i] })
		for _, gt := range others[:min(f.interTor, len(others))] {
			f.addPath(src, index(a.rail, gt[0], gt[1], f.rng.IntN(f.hosts)), false)
		}
	}
}

func (f *simFabric) addPath(src, dst int, mesh bool) {
	p := simPath{src: src, dst: dst, mesh: mesh, cursor: f.rng.IntN(f.flowLabels)}
	if !mesh {
		a, b := &f.rnics[src], &f.rnics[dst]
		sameGroup := a.group == b.group
		hops := func() []simHop {
			out := make([]simHop, f.flowLabels)
			for l := range out {
				hop := simHop{up: int8(f.rng.IntN(f.spines)), core: -1}
				hop.down = hop.up // one spine joins two ToRs of a group
				if !sameGroup {
					hop.core = int8(f.rng.IntN(f.cores))
					hop.down = int8(f.rng.IntN(f.spines))
				}
				out[l] = hop
			}
			return out
		}
		p.fwd, p.rev = hops(), hops()
	}
	f.paths = append(f.paths, p)
}

// crossings returns how many times a packet sent from RNIC a to RNIC b over
// hop crosses the faulty element.
func (f *simFabric) crossings(fault *simFault, a, b *simRNIC, mesh bool, hop simHop) int {
	onTor := func(r *simRNIC) bool {
		return r.rail == fault.rail && r.group == fault.group && r.tor == fault.tor
	}
	n := 0
	switch fault.element {
	case "rnic":
		for _, r := range []*simRNIC{a, b} {
			if onTor(r) && r.host == fault.host {
				n++
			}
		}
	case "host":
		for _, r := range []*simRNIC{a, b} {
			if r.group == fault.group && r.tor == fault.tor && r.host == fault.host {
				n++
			}
		}
	case "tor":
		if onTor(a) {
			n++
		}
		if !mesh && onTor(b) {
			n++
		}
	case "uplink":
		if mesh {
			return 0
		}
		if onTor(a) && int(hop.up) == fault.member {
			n++
		}
		if onTor(b) && int(hop.down) == fault.member {
			n++
		}
	case "spine":
		if mesh || a.rail != fault.rail {
			return 0
		}
		if a.group == fault.group && int(hop.up) == fault.member {
			n++
		}
		if b.group == fault.group && a.group != b.group && int(hop.down) == fault.member {
			n++
		}
	case "core":
		if !mesh && a.rail == fault.rail && int(hop.core) == fault.member {
			n++
		}
	}
	return n
}

// simSummary is what one path reports for one window.
type simSummary struct {
	path          *simPath
	total, failed uint32
	p50, p99      uint64
	min, max      uint64
}

// window simulates every probe of one window and returns the summaries.
func (f *simFabric) window(w int) []simSummary {
	out := make([]simSummary, 0, len(f.paths))
	var rtts []uint64
	for i := range f.paths {
		p := &f.paths[i]
		a, b := &f.rnics[p.src], &f.rnics[p.dst]
		probes := f.interProbes
		baseRTT := uint64(20_000)
		if p.mesh {
			probes, baseRTT = f.meshProbes, 8_000
		}
		s := simSummary{path: p, total: uint32(probes)}
		rtts = rtts[:0]
		for n := 0; n < probes; n++ {
			label := p.cursor
			p.cursor = (p.cursor + 1) % f.flowLabels
			var fwd, rev simHop
			if !p.mesh {
				fwd, rev = p.fwd[label], p.rev[label]
			}
			survive := 1 - f.noiseLoss
			rtt := baseRTT + uint64(f.rng.IntN(2_000))
			for fi := range f.faults {
				fault := &f.faults[fi]
				if wf, limited := f.windowFaults[fi]; limited && !wf[w] {
					continue
				}
				// The probe travels a -> b, its ACK b -> a.
				n := f.crossings(fault, a, b, p.mesh, fwd) + f.crossings(fault, b, a, p.mesh, rev)
				if n > 0 {
					survive *= math.Pow(1-fault.loss, float64(n))
					rtt += uint64(n) * fault.delayNs
				}
			}
			if f.rng.Float64() >= survive {
				s.failed++
				continue
			}
			if f.rng.Float64() < f.noiseRTT {
				rtt = 2 * simRTTThresholdNs
			}
			rtts = append(rtts, rtt)
		}
		if len(rtts) > 0 {
			sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
			s.min, s.max = rtts[0], rtts[len(rtts)-1]
			s.p50 = rtts[simRank(0.50, len(rtts))]
			s.p99 = rtts[simRank(0.99, len(rtts))]
		}
		out = append(out, s)
	}
	return out
}

// simRank is the agent's nearest-rank index of quantile q among n samples.
func simRank(q float64, n int) int {
	rank := int(math.Ceil(q*float64(n) - 1e-9))
	return min(max(rank, 1), n) - 1
}

// reports turns one window's summaries into the ProbeAnalysisReport batches
// the agents would send: one agent per host, at most 256 summaries each.
func (f *simFabric) reports(w int, summaries []simSummary) []*controller_agent.ProbeAnalysisReport {
	byAgent := make(map[string][]*controller_agent.PathSummary)
	var agents []string
	for _, s := range summaries {
		a, b := &f.rnics[s.path.src], &f.rnics[s.path.dst]
		if f.silent[a.agent] {
			continue
		}
		ptype := controller_agent.PinglistType_INTER_TOR
		if s.path.mesh {
			ptype = controller_agent.PinglistType_TOR_MESH
		}
		if _, ok := byAgent[a.agent]; !ok {
			agents = append(agents, a.agent)
		}
		byAgent[a.agent] = append(byAgent[a.agent], &controller_agent.PathSummary{
			SourceGid:         a.gid,
			SourceTorId:       a.torID,
			TargetGid:         b.gid,
			TargetTorId:       b.torID,
			PinglistType:      ptype,
			WindowStartUnixNs: simBaseStartNs + uint64(w)*f.windowNs,
			WindowDurationMs:  uint32(f.windowNs / 1_000_000),
			ProbeTotal:        s.total,
			ProbeFailed:       s.failed,
			ProbeSuccess:      s.total - s.failed,
			NetworkRttMinNs:   s.min,
			NetworkRttMaxNs:   s.max,
			NetworkRttP50Ns:   s.p50,
			NetworkRttP99Ns:   s.p99,
		})
	}
	sort.Strings(agents)
	var out []*controller_agent.ProbeAnalysisReport
	for _, agent := range agents {
		sums := byAgent[agent]
		for start := 0; start < len(sums); start += 256 {
			out = append(out, &controller_agent.ProbeAnalysisReport{
				AgentId:   agent,
				Summaries: sums[start:min(start+256, len(sums))],
			})
		}
	}
	return out
}

// simClock is the controller's clock in a simulation.
type simClock struct{ ns uint64 }

func (c *simClock) now() time.Time { return time.Unix(0, int64(c.ns)) }

// simRun is one simulated controller with localization enabled.
type simRun struct {
	t      testing.TB
	fabric *simFabric
	az     *Analyzer
	clock  *simClock
	next   int // next window to simulate
}

// simAnalyzerConfig is the analyzer configuration the simulations use: the
// shipped SLO thresholds, with localization on.
func simAnalyzerConfig(loc LocalizationConfig) Config {
	return Config{
		Cluster:         Thresholds{LossRatio: 0.02, NetworkRTTP99Ns: simRTTThresholdNs},
		Service:         Thresholds{LossRatio: 0.02, NetworkRTTP99Ns: simRTTThresholdNs},
		WindowRetention: 4,
		Localization:    &loc,
	}
}

func newSimRun(t testing.TB, f *simFabric, loc LocalizationConfig) *simRun {
	t.Helper()
	f.build()
	clock := &simClock{ns: simBaseStartNs}
	az := New(simAnalyzerConfig(loc), nil)
	az.loc.now = clock.now
	return &simRun{t: t, fabric: f, az: az, clock: clock}
}

// feed simulates the next window and delivers its reports a few seconds
// after it ends, as agents do.
func (r *simRun) feed() {
	r.t.Helper()
	f := r.fabric
	w := r.next
	r.next++
	end := simBaseStartNs + uint64(w+1)*f.windowNs
	r.clock.ns = end + 5*uint64(time.Second)
	for _, rep := range f.reports(w, f.window(w)) {
		r.az.Ingest(context.Background(), rep)
	}
}

// evaluate moves the clock to the moment the last simulated window closes,
// evaluates, and returns the findings.
func (r *simRun) evaluate() []Finding {
	r.t.Helper()
	f := r.fabric
	end := simBaseStartNs + uint64(r.next)*f.windowNs
	r.clock.ns = end + f.windowNs + closeMarginNs
	r.az.loc.evaluate(context.Background())
	return r.az.loc.currentFindings()
}

// step simulates one window and evaluates once it has closed.
func (r *simRun) step() []Finding {
	r.t.Helper()
	r.feed()
	return r.evaluate()
}

// after simulates n windows and evaluates once, after the last has closed.
func (r *simRun) after(n int) []Finding {
	r.t.Helper()
	for i := 0; i < n; i++ {
		r.feed()
	}
	return r.evaluate()
}

// truth returns the identity of the component a fault must be localized to.
// One lossy uplink is a ToR's uplink set, one lossy spine its spine group,
// one lossy core switch its rail: the member of an ECMP stage is never
// identified.
func (f *simFabric) truth(fault simFault) string {
	switch fault.element {
	case "rnic":
		return ComponentRNIC + "/" + f.gid(fault.rail, fault.group, fault.tor, fault.host)
	case "host":
		return ComponentHost + "/" + f.agentName(fault.group, fault.tor, fault.host)
	case "tor":
		return ComponentTor + "/" + f.torName(fault.rail, fault.group, fault.tor)
	case "uplink":
		return ComponentTorUplink + "/" + f.torName(fault.rail, fault.group, fault.tor)
	case "spine":
		return ComponentSpineGroup + "/" + f.groupName(fault.rail, fault.group)
	case "core":
		return ComponentRail + "/" + f.railName(fault.rail)
	}
	panic("unknown fault element " + fault.element)
}

// describeFindings renders findings for test failure messages.
func describeFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "(no findings)"
	}
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "\n  %s %s:", f.Signal, f.State)
		for _, s := range f.Suspects {
			fmt.Fprintf(&b, " %s(conf=%.3f excess=%.4f nats=%.1f events=%d/%d paths=%d/%d)",
				s.Component.identity(), s.Confidence, s.ExcessRatio, s.EvidenceNats,
				s.Events, s.Trials, s.FailedPaths, s.Paths)
		}
		if f.MemberCount > 0 {
			fmt.Fprintf(&b, " members=%v (%d)", f.Members, f.MemberCount)
		}
	}
	return b.String()
}

// outcome classifies the findings of one simulation against its faults.
type outcome struct {
	// correct counts the faults named by a localized finding.
	correct int
	// ambiguous counts the findings whose candidate set holds a fault;
	// notLocalizable those that name a scope holding a fault.
	ambiguous      int
	notLocalizable int
	// misses lists the localized and ambiguous findings whose candidates
	// hold no fault. Each finding claims a probability of that: one minus
	// the confidences of its candidates. claimedMisses sums the claims.
	misses        []Finding
	claimedMisses float64
	// wrongScopes lists the not-localizable findings whose scope holds no
	// fault. Such a finding claims nothing it could be wrong about in part.
	wrongScopes []Finding
}

// claimedMiss returns the probability a finding leaves to "none of my
// candidates": one minus the sum of their confidences.
func claimedMiss(f Finding) float64 {
	sum := 0.0
	for _, s := range f.Suspects {
		sum += s.Confidence
	}
	return math.Max(0, 1-sum)
}

// accepted returns the identities a localized finding may name for fault,
// given the facts the topology file states. One lossy uplink is a ToR's
// uplink set, one lossy spine its spine group, one lossy core switch its
// rail. A faulty host may also be named RNIC by RNIC (its agent may be
// silent, or the host may have one RNIC). Without spine groups in the facts
// a rail's top tier is everything above its ToRs, so a lossy spine is in it.
func (f *simFabric) accepted(fault simFault, withGroups, withRails bool) map[string]bool {
	ok := map[string]bool{f.truth(fault): true}
	switch fault.element {
	case "host":
		for r := 0; r < f.rails; r++ {
			ok[ComponentRNIC+"/"+f.gid(r, fault.group, fault.tor, fault.host)] = true
		}
	case "spine":
		if !withGroups && withRails {
			ok[ComponentRail+"/"+f.railName(fault.rail)] = true
		}
	}
	return ok
}

// scopeHolds reports whether a scope (a spine group, a rail, the fabric or
// the background, as the suspect of a not-localizable finding or as one
// candidate of an ambiguous one) holds the fault. A scope holds the faults
// in the tiers it stands for: the links and switches above the ToRs within
// it. It also holds a faulty ToR that the finding lists as a member, since
// the finding then says "this ToR or what is above it". No scope holds an
// RNIC or a host, and the background (every path alike) holds no single
// fault at all.
func (f *simFabric) scopeHolds(scope Component, members []string, fault simFault) bool {
	inGroup := scope.SpineGroup == f.groupName(fault.rail, fault.group)
	inRail := scope.Rail == f.railName(fault.rail)
	var above bool
	switch scope.Kind {
	case ComponentFabric:
		above = true
	case ComponentRail:
		above = inRail
	case ComponentSpineGroup:
		// A core switch is above the spine groups, not in one.
		above = inGroup && fault.element != "core"
	default:
		return false
	}
	switch fault.element {
	case "uplink", "spine", "core":
		return above
	case "tor":
		tor := f.torName(fault.rail, fault.group, fault.tor)
		for _, m := range members {
			if m == tor {
				return above
			}
		}
	}
	return false
}

// judge classifies findings against the fabric's faults.
func (f *simFabric) judge(findings []Finding, withGroups, withRails bool) outcome {
	var out outcome
	named := make(map[int]bool)
	for _, fd := range findings {
		hit := false
		for i, fault := range f.faults {
			ok := f.accepted(fault, withGroups, withRails)
			switch fd.State {
			case StateLocalized:
				if ok[fd.Suspects[0].Component.identity()] {
					hit = true
					named[i] = true
				}
			case StateAmbiguous:
				for _, s := range fd.Suspects {
					hit = hit || ok[s.Component.identity()] || f.scopeHolds(s.Component, nil, fault)
				}
			case StateNotLocalizable:
				hit = hit || f.scopeHolds(fd.Suspects[0].Component, fd.Members, fault)
			}
		}
		if fd.State == StateNotLocalizable {
			if hit {
				out.notLocalizable++
			} else {
				out.wrongScopes = append(out.wrongScopes, fd)
			}
			continue
		}
		out.claimedMisses += claimedMiss(fd)
		switch {
		case !hit:
			out.misses = append(out.misses, fd)
		case fd.State == StateAmbiguous:
			out.ambiguous++
		}
	}
	out.correct = len(named)
	return out
}

// requireLocalized fails unless the findings of signal are exactly the
// localized suspects want, each with at least the default minimum
// confidence.
func requireLocalized(t *testing.T, findings []Finding, signal string, want ...string) {
	t.Helper()
	sort.Strings(want)
	var got []string
	count := 0
	for _, f := range findings {
		if f.Signal != signal {
			continue
		}
		count++
		if f.State == StateLocalized {
			got = append(got, f.Suspects[0].Component.identity())
			if c := f.Suspects[0].Confidence; c < DefaultLocalizationMinConfidence {
				t.Errorf("%s: confidence %.3f is below the minimum", f.Suspects[0].Component.identity(), c)
			}
		}
	}
	sort.Strings(got)
	if count != len(want) || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s findings: want exactly the localized suspects %v, got:%s", signal, want, describeFindings(findings))
	}
}

// requireNone fails if there is any finding.
func requireNone(t *testing.T, findings []Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("want no findings, got:%s", describeFindings(findings))
	}
}

// requireCandidates fails unless findings hold exactly one finding of
// signal, in state, whose candidates are exactly want.
func requireCandidates(t *testing.T, findings []Finding, signal, state string, want ...string) Finding {
	t.Helper()
	sort.Strings(want)
	var ofSignal []Finding
	for _, f := range findings {
		if f.Signal == signal {
			ofSignal = append(ofSignal, f)
		}
	}
	if len(ofSignal) != 1 || ofSignal[0].State != state {
		t.Fatalf("want one %s %s finding, got:%s", signal, state, describeFindings(findings))
	}
	var got []string
	for _, s := range ofSignal[0].Suspects {
		got = append(got, s.Component.identity())
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("want the candidates %v, got:%s", want, describeFindings(findings))
	}
	return ofSignal[0]
}
