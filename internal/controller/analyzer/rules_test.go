package analyzer

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// The tests of this file pin the decision rules of the localizer one by
// one. Each builds, by hand, evidence on which one rule decides the result:
// with the rule's constant changed or the rule removed, the test fails. The
// simulations cover the rules together and would not notice the loss of one.

// link is one path of a hand-built window, between RNIC sr under ToR st and
// RNIC dr under ToR dt, named as meshWindow names them.
func link(st, sr, dt, dr int, total, failed uint32) obs {
	return obs{
		agent: fmt.Sprintf("host-%d-%d", st, sr),
		src:   fmt.Sprintf("gid-%d-%d", st, sr), srcTor: fmt.Sprintf("tor-%d", st),
		dst: fmt.Sprintf("gid-%d-%d", dt, dr), dstTor: fmt.Sprintf("tor-%d", dt),
		total: total, failed: failed,
	}
}

// both is the path and its reverse, with the same counts.
func both(st, sr, dt, dr int, total, failed uint32) []obs {
	return []obs{link(st, sr, dt, dr, total, failed), link(dt, dr, st, sr, total, failed)}
}

// groupsTopology states one rail and the spine group of each ToR:
// groupOf[i] is the group of tor-i.
func groupsTopology(t *testing.T, groupOf ...int) *Topology {
	t.Helper()
	var b strings.Builder
	b.WriteString("version: 1\ntors:\n")
	for tor, g := range groupOf {
		fmt.Fprintf(&b, "  tor-%d: {rail: r0, spine_group: g%d}\n", tor, g)
	}
	topo, err := ParseTopology([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

func solveLoss(t *testing.T, topo *Topology, windows ...[]obs) []Finding {
	t.Helper()
	findings := localize(spanOf(t, topo, windows...), testParams(), testParams())
	checkFindingInvariants(t, findings, testParams().minConfidence)
	return findings
}

// TestRule_ThreeRNICPairs pins minFailedPairs and that the two directions
// of a pair count once: an RNIC whose every probe fails on two pairs, in
// both directions (four paths), is not named; on three pairs it is.
func TestRule_ThreeRNICPairs(t *testing.T) {
	healthy := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })
	// gid-0-9 is under tor-0 and has no other paths than the ones below.
	two := append(append([]obs{}, healthy...), both(0, 9, 1, 0, 1000, 300)...)
	two = append(two, both(0, 9, 2, 0, 1000, 300)...)
	requireNone(t, solveLoss(t, nil, repeat(two, 3)...))

	three := append(append([]obs{}, two...), both(0, 9, 1, 1, 1000, 300)...)
	requireLocalized(t, solveLoss(t, nil, repeat(three, 3)...), KindLoss, "rnic/gid-0-9")
}

// TestRule_TwoFailedMembers pins minFailedMembers, and that a component
// that may not be named is no alternative either. All paths of gid-0-0
// fail. Its ToR has a second RNIC that is barely probed, so the ToR and its
// uplinks explain the events almost as well as the RNIC. They have events
// on one member only, so the RNIC is named alone, with full confidence.
func TestRule_TwoFailedMembers(t *testing.T) {
	window := meshWindow(3, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if st == 0 || dt == 0 {
			return 0 // replaced below
		}
		return 0
	})
	kept := window[:0]
	for _, o := range window {
		if o.srcTor != "tor-0" && o.dstTor != "tor-0" {
			kept = append(kept, o)
		}
	}
	window = kept
	for tor := 1; tor <= 2; tor++ {
		for r := 0; r < 4; r++ {
			window = append(window, both(0, 0, tor, r, 1000, 300)...)
		}
	}
	window = append(window, both(0, 1, 1, 0, 10, 0)...)
	window = append(window, both(0, 0, 0, 1, 10, 3)...)

	findings := solveLoss(t, nil, repeat(window, 3)...)
	requireLocalized(t, findings, KindLoss, "rnic/gid-0-0")
	if conf := findings[0].Suspects[0].Confidence; conf < 0.999 {
		t.Errorf("confidence of the RNIC = %v, want nearly 1: its ToR has events on one member and is no alternative", conf)
	}
}

// wholeToRs returns a window of 8 ToRs of 3 RNICs in which every path of the
// given ToRs loses 2% of 1000 probes.
func wholeToRs(lossy ...int) []obs {
	bad := map[int]bool{}
	for _, tor := range lossy {
		bad[tor] = true
	}
	return meshWindow(8, 3, 1000, func(st, sr, dt, dr int) uint32 {
		if bad[st] || bad[dt] {
			return 20
		}
		return 0
	})
}

// TestRule_TwoSiblingsAtMost pins maxSiblings: two degraded ToRs under one
// spine group are reported one by one; three are folded into one finding
// that names the group and lists them.
func TestRule_TwoSiblingsAtMost(t *testing.T) {
	topo := groupsTopology(t, 0, 0, 0, 0, 0, 0, 1, 1)
	requireLocalized(t, solveLoss(t, topo, repeat(wholeToRs(0, 1), 3)...), KindLoss, "tor/tor-0", "tor/tor-1")

	findings := solveLoss(t, topo, repeat(wholeToRs(0, 1, 2), 3)...)
	f := requireCandidates(t, findings, KindLoss, StateNotLocalizable, "spine_group/g0")
	if got := strings.Join(f.Members, ","); got != "tor-0,tor-1,tor-2" || f.MemberCount != 3 {
		t.Errorf("members = %s (%d), want tor-0,tor-1,tor-2", got, f.MemberCount)
	}
}

// TestRule_HintedSiblingCounts pins the hinted siblings (hintNats and
// hintExcessShare): next to two degraded ToRs, a third ToR of the group
// with an excess of more than a quarter of theirs, on evidence too thin to
// be named, counts as a third sibling. The three are folded.
func TestRule_HintedSiblingCounts(t *testing.T) {
	topo := groupsTopology(t, 0, 0, 0, 0, 0, 0, 1, 1)
	// tor-2 is probed 6 times per path and window; 5 of its paths lose one
	// probe per window: 15 events on 2430 probes, an excess of 0.5% against
	// the 1.9% of tor-0 and tor-1, and 14.7 nats of evidence (17 name it).
	thin := func(weak bool) []obs {
		window := wholeToRs(0, 1)
		for i := range window {
			o := &window[i]
			if o.srcTor != "tor-2" && o.dstTor != "tor-2" {
				continue
			}
			o.total, o.failed = 6, 0
			// gid-2-0 to tor-3, gid-2-1 to tor-4, ... gid-2-1 to tor-7.
			for k := 0; k < 5; k++ {
				if weak && o.src == fmt.Sprintf("gid-2-%d", k%3) && o.dst == fmt.Sprintf("gid-%d-0", 3+k) {
					o.failed = 1
				}
			}
		}
		return window
	}
	requireLocalized(t, solveLoss(t, topo, repeat(thin(false), 3)...), KindLoss, "tor/tor-0", "tor/tor-1")

	findings := solveLoss(t, topo, repeat(thin(true), 3)...)
	f := requireCandidates(t, findings, KindLoss, StateNotLocalizable, "spine_group/g0")
	if got := strings.Join(f.Members, ","); got != "tor-0,tor-1,tor-2" {
		t.Errorf("members = %s, want tor-0,tor-1,tor-2: the third ToR is a hinted sibling", got)
	}
}

// uplinkWindow is a window of two spine groups of two ToRs with three RNICs
// each. Every path between tor-0 and the other group loses 2% of 1000
// probes. tor-1, the sibling of tor-0, has six paths to the other group
// with restProbes probes each, all delivered: the rest of the scope.
func uplinkWindow(restProbes uint32) []obs {
	var window []obs
	for a := 0; a < 3; a++ {
		for b := 0; b < 3; b++ {
			if a != b {
				window = append(window, link(0, a, 0, b, 1000, 0), link(2, a, 3, b, 1000, 0))
			}
			window = append(window, both(0, a, 2, b, 1000, 20)...)
			window = append(window, both(0, a, 3, b, 1000, 20)...)
		}
		window = append(window, both(1, a, 2, a, restProbes, 0)...)
	}
	return window
}

// TestRule_UplinksNeedACleanRestOfScope pins powerNats and aboveShare. The
// uplinks of tor-0 show an excess of 1.9%. A fault above tor-0, seen
// through fewer uplinks, would put half of that on the other paths of the
// spine group. With 900 probes on those paths, that would leave 13.7 nats
// of evidence: fewer than the 21 it takes to conclude from their silence.
// The finding is folded into the group. With 3600 probes (55 nats) the
// silence counts and the uplinks are named.
func TestRule_UplinksNeedACleanRestOfScope(t *testing.T) {
	topo := groupsTopology(t, 0, 0, 1, 1)
	findings := solveLoss(t, topo, repeat(uplinkWindow(50), 3)...)
	f := requireCandidates(t, findings, KindLoss, StateNotLocalizable, "spine_group/g0")
	if got := strings.Join(f.Members, ","); got != "tor-0" {
		t.Errorf("members = %s, want tor-0", got)
	}
	requireLocalized(t, solveLoss(t, topo, repeat(uplinkWindow(200), 3)...), KindLoss, "tor_uplink/tor-0")
}

// TestRule_UplinksUnderALossyScopeAreFolded pins the rule that a ToR's
// uplinks are not named under a scope that is itself part of the
// explanation: every path of the spine group loses 1%, the paths of tor-0
// 3%. A spine fault seen through fewer uplinks at tor-0 looks like this.
func TestRule_UplinksUnderALossyScopeAreFolded(t *testing.T) {
	topo := groupsTopology(t, 0, 0, 0, 0, 1, 1, 1, 1)
	window := meshWindow(8, 3, 1000, func(st, sr, dt, dr int) uint32 {
		switch {
		case st == dt:
			return 0
		case st == 0 || dt == 0:
			return 30
		case st < 4 || dt < 4:
			return 10
		}
		return 0
	})
	findings := solveLoss(t, topo, repeat(window, 3)...)
	for _, f := range findings {
		for _, s := range f.Suspects {
			if s.Component.Kind == ComponentTorUplink || s.Component.Kind == ComponentTor {
				t.Fatalf("a ToR is named under a lossy spine group:%s", describeFindings(findings))
			}
		}
	}
	f := requireCandidates(t, findings, KindLoss, StateLocalized, "spine_group/g0")
	if got := strings.Join(f.Members, ","); got != "tor-0" {
		t.Errorf("members of the group's finding = %q, want tor-0", got)
	}
}

// TestRule_UnansweringRNICsAreNotEvidence pins the direction rule on
// evidence that lasts: for three windows every probe to the RNICs of tor-0
// is lost, from the other ToRs and under tor-0, while the probes these
// RNICs send to the other ToRs are delivered. A failing ToR would lose
// those as well. Nothing is reported, and the RNICs are marked.
func TestRule_UnansweringRNICsAreNotEvidence(t *testing.T) {
	inbound := meshWindow(4, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if dt == 0 {
			return 1000
		}
		return 0
	})
	sp := spanOf(t, nil, repeat(inbound, 3)...)
	requireNone(t, localize(sp, testParams(), testParams()))
	if sp.unanswering != 4 {
		t.Errorf("%d RNICs marked as not answering, want the 4 of tor-0", sp.unanswering)
	}

	// The same loss in both directions is the ToR's.
	bothWays := meshWindow(4, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if dt == 0 || st == 0 {
			return 1000
		}
		return 0
	})
	sp = spanOf(t, nil, repeat(bothWays, 3)...)
	requireLocalized(t, localize(sp, testParams(), testParams()), KindLoss, "tor/tor-0")
	if sp.unanswering != 0 {
		t.Errorf("%d RNICs marked as not answering under a ToR that fails in both directions", sp.unanswering)
	}

	// An RNIC that sends nothing cannot be told from a failed one: it is
	// named.
	var silent []obs
	for _, o := range inbound {
		if o.srcTor != "tor-0" && (o.dstTor != "tor-0" || o.dst == "gid-0-0") {
			silent = append(silent, o)
		}
	}
	sp = spanOf(t, nil, repeat(silent, 3)...)
	findings := localize(sp, testParams(), testParams())
	if len(findings) != 1 || findings[0].Suspects[0].Component.GID != "gid-0-0" {
		t.Errorf("a silent RNIC that does not answer: want it named, got:%s", describeFindings(findings))
	}
}

// TestTallyJudge pins the thresholds of the direction rule: the verdict on
// a set of paths about an excess that other paths show.
func TestTallyJudge(t *testing.T) {
	const baseline, excess = 0.001, 0.1
	for _, tc := range []struct {
		name           string
		probes, failed float64
		want           verdict
	}{
		{"no probes", 0, 0, untestable},
		// 69 probes at 10.1% would lose 6.97: below hintNats even if none is lost.
		{"too few probes to tell", 69, 0, untestable},
		{"just enough probes, none lost", 70, 0, clear},
		{"a quarter of the excess is still clear", 1000, 26, clear},
		{"more than a quarter is carried", 1000, 27, carried},
		{"the full excess is carried", 1000, 101, carried},
		// 100 probes: 10.1 expected, 2 lost is within a quarter, but the
		// difference is only 4.9 nats.
		{"within a quarter, on thin evidence", 100, 2, carried},
	} {
		if got := (tally{probes: tc.probes, failed: tc.failed}).judge(baseline, excess); got != tc.want {
			t.Errorf("%s: judge = %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := (tally{probes: 1000, failed: 1}).excessNats(baseline); got != 0 {
		t.Errorf("excessNats at the baseline = %v, want 0", got)
	}
	// 10 lost of 1000 at a baseline of 1: 10 ln 10 - 9.
	if got, want := (tally{probes: 1000, failed: 10}).excessNats(baseline), 10*math.Log(10)-9; math.Abs(got-want) > 1e-9 {
		t.Errorf("excessNats = %v, want %v", got, want)
	}
}

// TestRule_OwnExcessMustPersist pins the persistence of what a component
// itself explains. Every path between ToRs loses 2% in all four windows (a
// fault the facts do not describe). tor-0 loses another 30% on all of its
// paths in two adjacent windows: a burst. The events on tor-0's paths are
// spread over four windows, but its own excess is not: tor-0 is not named.
func TestRule_OwnExcessMustPersist(t *testing.T) {
	window := func(burst bool) []obs {
		return meshWindow(4, 4, 1000, func(st, sr, dt, dr int) uint32 {
			var lost uint32
			if st != dt {
				lost = 20
			}
			if burst && (st == 0 || dt == 0) {
				lost += 300
			}
			return lost
		})
	}
	findings := solveLoss(t, nil, window(false), window(true), window(true), window(false))
	for _, f := range findings {
		if f.Suspects[0].Component.Tor == "tor-0" {
			t.Fatalf("tor-0 is named for a burst on top of a lasting fault:%s", describeFindings(findings))
		}
	}
	requireCandidates(t, findings, KindLoss, StateNotLocalizable, "fabric")

	// In three windows the excess persists, and tor-0 is named.
	findings = solveLoss(t, nil, window(false), window(true), window(true), window(true))
	named := false
	for _, f := range findings {
		named = named || (f.State == StateLocalized && f.Suspects[0].Component.identity() == "tor/tor-0")
	}
	if !named {
		t.Errorf("tor-0 is not named for an excess of three windows:%s", describeFindings(findings))
	}
}

// TestRule_RefitDropsWhatOthersExplain pins the drop in refit: a broad
// component that the greedy picked first loses its place once the specific
// components picked after it explain its events.
func TestRule_RefitDropsWhatOthersExplain(t *testing.T) {
	// Two of the four RNICs of tor-0 lose 30% on all of their paths.
	window := meshWindow(3, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if (st == 0 && sr < 2) || (dt == 0 && dr < 2) {
			return 300
		}
		return 0
	})
	s := newSolver(spanOf(t, nil, repeat(window, 3)...), KindLoss, testParams())
	if !s.prepare() {
		t.Fatal("no events")
	}
	tor := s.baseTor // tor-0 is the first ToR of the span
	if s.sp.tors[0].name != "tor-0" {
		t.Fatalf("first ToR of the span is %s", s.sp.tors[0].name)
	}
	order, _ := s.greedy(nil, maxExplanation)
	if len(order) == 0 || order[0] != tor {
		t.Fatalf("the greedy did not pick the ToR first (order %v): the test needs it to", order)
	}
	order, dropped := s.refit(order)
	for _, c := range order {
		if c == tor {
			t.Errorf("the ToR is still part of the explanation after the refit (excess %v, gain %v)", s.theta[tor], s.gain[tor])
		}
	}
	if !dropped || s.selected[tor] {
		t.Errorf("dropped = %v, selected = %v; want the ToR dropped", dropped, s.selected[tor])
	}
}

// TestRule_DispersionDiscountsTheEvidence pins the two uses of the
// dispersion in the confidence: the evidence of a component is its
// likelihood gain divided by the dispersion of its place, and that
// dispersion is at least the dispersion of the other components of the
// explanation that cover the same events.
func TestRule_DispersionDiscountsTheEvidence(t *testing.T) {
	// The paths of tor-0 lose 2% on average, unevenly: every second path
	// loses 4%, the others nothing.
	uneven := meshWindow(4, 4, 1000, func(st, sr, dt, dr int) uint32 {
		if (st == 0 || dt == 0) && (sr+dr)%2 == 0 {
			return 40
		}
		return 0
	})
	s := newSolver(spanOf(t, nil, repeat(uneven, 3)...), KindLoss, testParams())
	findings := s.solve()
	requireLocalized(t, findings, KindLoss, "tor/tor-0")
	tor := s.baseTor
	phi := s.dispersion(tor, s.theta[tor])
	if phi < 5 {
		t.Fatalf("dispersion of the ToR = %v: the test needs uneven evidence", phi)
	}
	if got, want := findings[0].Suspects[0].EvidenceNats, s.gain[tor]/phi; math.Abs(got-want) > 1e-6*want {
		t.Errorf("EvidenceNats = %v, want the gain %v divided by the dispersion %v = %v", got, s.gain[tor], phi, want)
	}

	// An RNIC of tor-0 covered by the ToR's uneven evidence: its place is
	// discounted by the ToR's dispersion, although its own events (were it
	// in the explanation) spread evenly.
	rnic := int32(-1)
	for i, r := range s.sp.rnics {
		if r.gid == "gid-0-0" {
			rnic = int32(i)
		}
	}
	if got := s.coverDispersion(rnic, rnic); math.Abs(got-phi) > 1e-9 {
		t.Errorf("dispersion covering the RNIC's events = %v, want the ToR's %v", got, phi)
	}
	if got := s.placeDispersion(rnic); got < phi {
		t.Errorf("placeDispersion of the RNIC = %v, want at least the ToR's %v", got, phi)
	}
	if got := s.coverDispersion(tor, tor); got != 1 {
		t.Errorf("dispersion covering the ToR's events, leaving out the ToR = %v, want 1", got)
	}
}

// TestSaturatingAdd pins the counters of a path against wrapping around.
func TestSaturatingAdd(t *testing.T) {
	for _, tc := range []struct{ a, b, want uint32 }{
		{1, 2, 3},
		{math.MaxUint32 - 1, 1, math.MaxUint32},
		{math.MaxUint32 - 1, 2, math.MaxUint32},
		{math.MaxUint32, math.MaxUint32, math.MaxUint32},
		{0, math.MaxUint32, math.MaxUint32},
	} {
		if got := saturatingAdd(tc.a, tc.b); got != tc.want {
			t.Errorf("saturatingAdd(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestEvidenceStore_SpanGoesStale pins when the evidence span is given up:
// three window lengths and the close margin after the newest closed
// window's end, so that a finding does not outlive the agents' reports.
func TestEvidenceStore_SpanGoesStale(t *testing.T) {
	store := newEvidenceStore(4, 100, 0)
	o := obs{agent: "host-a", src: "a", srcTor: "tor-0", dst: "b", dstTor: "tor-1", total: 30}
	store.observe(o.agent, o.summary(0), windowEnd(0))
	last := windowEnd(0) + 3*testWindowNs + closeMarginNs
	if span, _ := store.span(last); len(span) != 1 {
		t.Errorf("span holds %d windows three window lengths after the last report, want 1", len(span))
	}
	if span, _ := store.span(last + 1); len(span) != 0 {
		t.Errorf("span holds %d windows one nanosecond later, want none", len(span))
	}
}
