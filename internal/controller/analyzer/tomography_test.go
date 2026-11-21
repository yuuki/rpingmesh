package analyzer

import (
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"sort"
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// obs is one path's summary of one window, for hand-built evidence.
type obs struct {
	agent          string
	src, srcTor    string
	dst, dstTor    string
	total, failed  uint32
	p99            uint64
	serviceTracing bool
}

const (
	testWindowMs    = 30_000
	testWindowNs    = uint64(testWindowMs) * 1_000_000
	testBaseStartNs = uint64(1_699_999_200_000_000_000) // a multiple of every window length in use
)

func (o obs) summary(window int) *controller_agent.PathSummary {
	s := &controller_agent.PathSummary{
		SourceGid:         o.src,
		SourceTorId:       o.srcTor,
		TargetGid:         o.dst,
		TargetTorId:       o.dstTor,
		ProbeTotal:        o.total,
		ProbeFailed:       o.failed,
		NetworkRttP99Ns:   o.p99,
		WindowStartUnixNs: testBaseStartNs + uint64(window)*testWindowNs,
		WindowDurationMs:  testWindowMs,
	}
	if o.failed <= o.total {
		s.ProbeSuccess = o.total - o.failed
	}
	if o.serviceTracing {
		s.PinglistType = controller_agent.PinglistType_SERVICE_TRACING
	}
	return s
}

// snapshots returns copies of the windows of the evidence span at nowNs, as
// an evaluation takes them.
func (s *evidenceStore) snapshots(nowNs uint64) []*windowSnapshot {
	windows, _ := s.span(nowNs)
	out := make([]*windowSnapshot, len(windows))
	for i, w := range windows {
		out[i] = w.snapshot(s.agents)
	}
	return out
}

// spanOf builds the evidence span of the given windows the way the
// localizer does: through the evidence store.
func spanOf(t *testing.T, topo *Topology, windows ...[]obs) *span {
	t.Helper()
	store := newEvidenceStore(len(windows), 1<<20, simRTTThresholdNs)
	nowNs := testBaseStartNs + uint64(len(windows))*testWindowNs
	for w, window := range windows {
		for _, o := range window {
			store.observe(o.agent, o.summary(w), nowNs)
		}
	}
	store.prune(nowNs)
	closed := store.snapshots(nowNs + testWindowNs + closeMarginNs)
	if len(closed) != len(windows) {
		t.Fatalf("span holds %d windows, want %d", len(closed), len(windows))
	}
	return buildSpan(closed, topo)
}

// repeat returns the same window n times.
func repeat(window []obs, n int) [][]obs {
	out := make([][]obs, n)
	for i := range out {
		out[i] = window
	}
	return out
}

func testParams() solverParams {
	return solverParams{
		baseline:      DefaultLocalizationBaselineLossRatio,
		minConfidence: DefaultLocalizationMinConfidence,
		spanWindows:   DefaultLocalizationWindows,
	}
}

// meshWindow is one window of a small fabric: tors ToRs of rnics RNICs each,
// every RNIC probing every other RNIC with probes probes. loss returns the
// lost probes of a path.
func meshWindow(tors, rnics int, probes uint32, loss func(srcTor, srcRNIC, dstTor, dstRNIC int) uint32) []obs {
	var out []obs
	for st := 0; st < tors; st++ {
		for sr := 0; sr < rnics; sr++ {
			for dt := 0; dt < tors; dt++ {
				for dr := 0; dr < rnics; dr++ {
					if st == dt && sr == dr {
						continue
					}
					out = append(out, obs{
						agent: fmt.Sprintf("host-%d-%d", st, sr),
						src:   fmt.Sprintf("gid-%d-%d", st, sr), srcTor: fmt.Sprintf("tor-%d", st),
						dst: fmt.Sprintf("gid-%d-%d", dt, dr), dstTor: fmt.Sprintf("tor-%d", dt),
						total: probes, failed: loss(st, sr, dt, dr),
					})
				}
			}
		}
	}
	return out
}

// TestSolverFit_ClosedForm verifies the maximum-likelihood excess of a
// component whose paths all have the baseline rate: events/trials minus the
// baseline, with the Poisson log-likelihood gain of that rate.
func TestSolverFit_ClosedForm(t *testing.T) {
	// One RNIC (gid-0-0) loses 10 of 1000 probes on each of its paths.
	window := meshWindow(2, 3, 1000, func(st, sr, dt, dr int) uint32 {
		if (st == 0 && sr == 0) || (dt == 0 && dr == 0) {
			return 10
		}
		return 0
	})
	sp := spanOf(t, nil, repeat(window, 2)...)
	s := newSolver(sp, KindLoss, testParams())
	if !s.prepare() {
		t.Fatal("prepare found no events")
	}
	var rnic int32 = -1
	for i, r := range sp.rnics {
		if r.gid == "gid-0-0" {
			rnic = int32(i)
		}
	}
	if rnic < 0 {
		t.Fatal("gid-0-0 is not in the span")
	}

	// 5 peers, both directions, two windows of 1000 probes.
	const trials, events = 5 * 2 * 2 * 1000, 5 * 2 * 2 * 10
	if s.trials[rnic] != trials {
		t.Fatalf("trials = %v, want %d", s.trials[rnic], trials)
	}
	theta, gain := s.fit(rnic)
	base := DefaultLocalizationBaselineLossRatio
	wantTheta := float64(events)/trials - base
	if math.Abs(theta-wantTheta) > 1e-12 {
		t.Errorf("theta = %v, want %v", theta, wantTheta)
	}
	wantGain := events*math.Log((base+wantTheta)/base) - trials*wantTheta
	if math.Abs(gain-wantGain) > 1e-9*wantGain {
		t.Errorf("gain = %v, want %v", gain, wantGain)
	}
}

// TestSolverFit_MaximizesGain verifies the fit on paths with different
// rates, where there is no closed form: the returned excess is where the
// gain is largest, and a component whose paths lose less than the baseline
// gains nothing.
func TestSolverFit_MaximizesGain(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	window := meshWindow(3, 3, 500, func(st, sr, dt, dr int) uint32 {
		if st == 0 || dt == 0 {
			return uint32(rng.IntN(12))
		}
		return 0
	})
	sp := spanOf(t, nil, repeat(window, 2)...)
	s := newSolver(sp, KindLoss, testParams())
	if !s.prepare() {
		t.Fatal("prepare found no events")
	}
	// Give the paths with events different rates, as after other
	// components were selected.
	for f := range s.frate {
		s.frate[f] *= 1 + 5*rng.Float64()
	}
	gainAt := func(c int32, theta float64) float64 {
		g := -s.trials[c] * theta
		for _, f := range s.failed(c) {
			g += s.fevents[f] * math.Log1p(theta/s.frate[f])
		}
		return g
	}
	checked := 0
	for _, c := range s.active {
		theta, gain := s.fit(c)
		if theta == 0 {
			if gain != 0 {
				t.Errorf("component %d: gain %v without an excess", c, gain)
			}
			continue
		}
		checked++
		if math.Abs(gain-gainAt(c, theta)) > 1e-9*math.Abs(gain) {
			t.Errorf("component %d: gain = %v, the likelihood at theta gives %v", c, gain, gainAt(c, theta))
		}
		for _, step := range []float64{0.99, 1.01} {
			if other := gainAt(c, theta*step); other > gain+1e-9*math.Abs(gain) {
				t.Errorf("component %d: gain %v at theta %v, but %v at %v", c, gain, theta, other, theta*step)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no component had an excess to check")
	}

	// tor-1 and tor-2 lose nothing between themselves: below the baseline.
	for i, r := range sp.rnics {
		if sp.tors[r.tor].name != "tor-0" {
			if theta, gain := s.fit(s.baseTor + r.tor); gain > gainAt(s.baseTor+r.tor, theta)+1e-9 {
				t.Errorf("rnic %d: inconsistent gain", i)
			}
		}
	}
}

// TestSolverComponents verifies which components a path crosses, for every
// combination of topology facts at its two ends.
func TestSolverComponents(t *testing.T) {
	topo, err := ParseTopology([]byte(`
version: 1
tors:
  a1: {rail: r0, spine_group: ga}
  a2: {rail: r0, spine_group: ga}
  b1: {rail: r0, spine_group: gb}
  c1: {rail: r0}            # under the rail's spines, no spine group
  d1: {spine_group: gd}     # a spine group without a rail
  e1: {rail: r1, spine_group: ge}
`))
	if err != nil {
		t.Fatal(err)
	}
	path := func(src, srcTor, dst, dstTor string) obs {
		return obs{agent: "host-" + src, src: src, srcTor: srcTor, dst: dst, dstTor: dstTor, total: 10}
	}
	window := []obs{
		path("a1x", "a1", "a1y", "a1"), // stays under one ToR
		path("a1x", "a1", "a2x", "a2"), // same spine group
		path("a1x", "a1", "b1x", "b1"), // same rail, different spine groups
		path("a1x", "a1", "c1x", "c1"), // peer directly under the rail
		path("c1x", "c1", "u1x", "u1"), // peer without facts
		path("a1x", "a1", "u1x", "u1"), // peer without facts
		path("a1x", "a1", "d1x", "d1"), // peer in a spine group without a rail
		path("a1x", "a1", "e1x", "e1"), // different rails
		path("u1x", "u1", "u2x", "u2"), // no facts at either end
	}
	sp := spanOf(t, topo, window)
	s := newSolver(sp, KindLoss, testParams())

	names := func(p *spanPath) []string {
		var buf [maxPathComponents]int32
		var out []string
		for _, c := range s.components(p, buf[:0]) {
			out = append(out, s.component(c).identity())
		}
		sort.Strings(out)
		return out
	}
	want := map[string][]string{
		"a1x>a1y": {"rnic/a1x", "rnic/a1y", "tor/a1"},
		"a1x>a2x": {"rnic/a1x", "rnic/a2x", "tor/a1", "tor/a2", "tor_uplink/a1", "tor_uplink/a2",
			"spine_group/ga"},
		"a1x>b1x": {"rnic/a1x", "rnic/b1x", "tor/a1", "tor/b1", "tor_uplink/a1", "tor_uplink/b1",
			"spine_group/ga", "spine_group/gb", "rail/r0"},
		// c1 hangs off the rail's top tier: the path leaves ga for it.
		"a1x>c1x": {"rnic/a1x", "rnic/c1x", "tor/a1", "tor/c1", "tor_uplink/a1", "tor_uplink/c1",
			"spine_group/ga", "rail/r0"},
		// Every path that leaves c1 crosses the tier above it, the rail.
		"c1x>u1x": {"rnic/c1x", "rnic/u1x", "tor/c1", "tor/u1", "tor_uplink/c1", "tor_uplink/u1", "rail/r0"},
		// Whether the path leaves ga is unknown: it does not count for r0.
		"a1x>u1x": {"rnic/a1x", "rnic/u1x", "tor/a1", "tor/u1", "tor_uplink/a1", "tor_uplink/u1",
			"spine_group/ga"},
		"a1x>d1x": {"rnic/a1x", "rnic/d1x", "tor/a1", "tor/d1", "tor_uplink/a1", "tor_uplink/d1",
			"spine_group/ga", "spine_group/gd", "rail/r0"},
		"a1x>e1x": {"rnic/a1x", "rnic/e1x", "tor/a1", "tor/e1", "tor_uplink/a1", "tor_uplink/e1",
			"spine_group/ga", "spine_group/ge", "rail/r0", "rail/r1"},
		"u1x>u2x": {"rnic/u1x", "rnic/u2x", "tor/u1", "tor/u2", "tor_uplink/u1", "tor_uplink/u2"},
	}
	seen := 0
	for i := range sp.paths {
		p := &sp.paths[i]
		key := sp.rnics[p.src].gid + ">" + sp.rnics[p.dst].gid
		expected, ok := want[key]
		if !ok {
			t.Errorf("unexpected path %s", key)
			continue
		}
		seen++
		// Every path between two ToRs also counts for the fabric, and
		// every path for the background.
		expected = append([]string{ComponentBackground}, expected...)
		if key != "a1x>a1y" {
			expected = append(expected, ComponentFabric)
		}
		sort.Strings(expected)
		if got := names(p); !reflect.DeepEqual(got, expected) {
			t.Errorf("path %s crosses\n  %v, want\n  %v", key, got, expected)
		}
	}
	if seen != len(want) {
		t.Errorf("checked %d paths, want %d", seen, len(want))
	}
}

// TestLocalize_HostNeedsTwoRNICs verifies that a host component exists only
// for an agent with at least two observed RNICs: with one, the host and the
// RNIC would be the same paths.
func TestLocalize_HostNeedsTwoRNICs(t *testing.T) {
	window := []obs{
		// host-a reports from two RNICs, host-b from one.
		{agent: "host-a", src: "a0", srcTor: "t0", dst: "b0", dstTor: "t0", total: 10},
		{agent: "host-a", src: "a1", srcTor: "t1", dst: "c1", dstTor: "t1", total: 10},
		{agent: "host-b", src: "b0", srcTor: "t0", dst: "a0", dstTor: "t0", total: 10},
	}
	sp := spanOf(t, nil, window)
	if !reflect.DeepEqual(sp.hosts, []string{"host-a"}) {
		t.Fatalf("hosts = %v, want only host-a", sp.hosts)
	}
	for _, r := range sp.rnics {
		wantHost := int32(-1)
		if r.agent == "host-a" {
			wantHost = 0
		}
		if r.host != wantHost {
			t.Errorf("rnic %s (agent %q): host = %d, want %d", r.gid, r.agent, r.host, wantHost)
		}
	}
	// c1 never reported: its agent is unknown.
	for _, r := range sp.rnics {
		if r.gid == "c1" && r.agent != "" {
			t.Errorf("c1 has agent %q, want none", r.agent)
		}
	}
}

// TestLocalize_ByHand runs the solver on evidence small enough to check by
// hand: 4 ToRs of 4 RNICs in a full mesh, 1000 probes per path and window,
// with the losses of one fault each.
func TestLocalize_ByHand(t *testing.T) {
	topo, err := ParseTopology([]byte(`
version: 1
tors:
  tor-0: {rail: r0, spine_group: g0}
  tor-1: {rail: r0, spine_group: g0}
  tor-2: {rail: r0, spine_group: g1}
  tor-3: {rail: r0, spine_group: g1}
`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		loss func(st, sr, dt, dr int) uint32
		want string
	}{
		{"one RNIC", func(st, sr, dt, dr int) uint32 {
			if (st == 1 && sr == 2) || (dt == 1 && dr == 2) {
				return 20
			}
			return 0
		}, "rnic/gid-1-2"},
		{"one ToR, all of its paths", func(st, sr, dt, dr int) uint32 {
			if st == 2 || dt == 2 {
				return 20
			}
			return 0
		}, "tor/tor-2"},
		{"one ToR, only the paths that leave it", func(st, sr, dt, dr int) uint32 {
			if (st == 2) != (dt == 2) {
				return 20
			}
			return 0
		}, "tor_uplink/tor-2"},
		{"one spine group: the paths between ToRs that touch it", func(st, sr, dt, dr int) uint32 {
			if st != dt && (st >= 2 || dt >= 2) {
				return 20
			}
			return 0
		}, "spine_group/g1"},
		{"the rail: the paths between its spine groups", func(st, sr, dt, dr int) uint32 {
			if (st >= 2) != (dt >= 2) {
				return 20
			}
			return 0
		}, "rail/r0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp := spanOf(t, topo, repeat(meshWindow(4, 4, 1000, tc.loss), 2)...)
			findings := localize(sp, testParams(), testParams())
			requireLocalized(t, findings, KindLoss, tc.want)
			sus := findings[0].Suspects[0]
			// 20 of 1000 probes lost, over a baseline of 1 in 1000.
			if math.Abs(sus.ExcessRatio-0.019) > 1e-6 {
				t.Errorf("ExcessRatio = %v, want 0.019", sus.ExcessRatio)
			}
			if sus.Windows != 2 || sus.FailedPaths != sus.Paths {
				t.Errorf("suspect = %+v, want events in 2 windows on all of its paths", sus)
			}
			if sus.Confidence < 0.999 {
				t.Errorf("Confidence = %v, want nearly 1", sus.Confidence)
			}
		})
	}
}

// TestLocalize_EvidenceRules verifies each rule that keeps a component from
// being named although it gains likelihood.
func TestLocalize_EvidenceRules(t *testing.T) {
	lossy := func(match func(st, sr, dt, dr int) bool, lost uint32) func(st, sr, dt, dr int) uint32 {
		return func(st, sr, dt, dr int) uint32 {
			if match(st, sr, dt, dr) {
				return lost
			}
			return 0
		}
	}
	healthy := meshWindow(3, 4, 1000, func(int, int, int, int) uint32 { return 0 })

	t.Run("two RNIC pairs are not enough", func(t *testing.T) {
		// gid-0-0 loses probes to and from two peers only.
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool {
			a := st == 0 && sr == 0 && dt == 1 && dr < 2
			b := dt == 0 && dr == 0 && st == 1 && sr < 2
			return a || b
		}, 300))
		requireNone(t, localize(spanOf(t, nil, repeat(window, 2)...), testParams(), testParams()))
	})
	t.Run("three RNIC pairs are", func(t *testing.T) {
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool {
			a := st == 0 && sr == 0 && dt == 1 && dr < 3
			b := dt == 0 && dr == 0 && st == 1 && sr < 3
			return a || b
		}, 300))
		findings := localize(spanOf(t, nil, repeat(window, 2)...), testParams(), testParams())
		// The other paths of gid-0-0 are clean, which the model cannot
		// reconcile with an RNIC fault of 30%: whatever is reported, it is
		// not a confident accusation of something else.
		for _, f := range findings {
			if f.State == StateLocalized && f.Suspects[0].Component.identity() != "rnic/gid-0-0" {
				t.Errorf("localized %s", f.Suspects[0].Component.identity())
			}
		}
	})
	t.Run("one window is not enough", func(t *testing.T) {
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 || dt == 0 }, 50))
		sp := spanOf(t, nil, window, healthy, healthy, healthy)
		requireNone(t, localize(sp, testParams(), testParams()))
	})
	t.Run("one window is enough for a span of one window", func(t *testing.T) {
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 || dt == 0 }, 50))
		params := testParams()
		params.spanWindows = 1
		requireLocalized(t, localize(spanOf(t, nil, window), params, params), KindLoss, "tor/tor-0")
	})
	t.Run("a burst with a stray event in another window is not enough", func(t *testing.T) {
		burst := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 || dt == 0 }, 50))
		stray := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 && sr == 0 && dt == 0 && dr == 1 }, 1))
		sp := spanOf(t, nil, healthy, burst, stray, healthy)
		requireNone(t, localize(sp, testParams(), testParams()))
	})
	t.Run("the same loss in two windows is", func(t *testing.T) {
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 || dt == 0 }, 50))
		sp := spanOf(t, nil, healthy, window, window, healthy)
		requireLocalized(t, localize(sp, testParams(), testParams()), KindLoss, "tor/tor-0")
	})
	t.Run("the first window of a controller is not enough", func(t *testing.T) {
		// One window present, of a configured span of four.
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 || dt == 0 }, 50))
		requireNone(t, localize(spanOf(t, nil, window), testParams(), testParams()))
	})
	t.Run("a ToR is not named on one RNIC's evidence", func(t *testing.T) {
		// Every path of gid-0-0 fails. The RNIC is named, its ToR is not.
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool {
			return (st == 0 && sr == 0) || (dt == 0 && dr == 0)
		}, 1000))
		findings := localize(spanOf(t, nil, repeat(window, 2)...), testParams(), testParams())
		requireLocalized(t, findings, KindLoss, "rnic/gid-0-0")
	})
	t.Run("weak evidence is silence", func(t *testing.T) {
		// 3 lost probes of 22000 on tor-0's paths: more than the baseline
		// predicts for none of them.
		window := meshWindow(3, 4, 1000, lossy(func(st, sr, dt, dr int) bool { return st == 0 && dt == 1 && sr == dr }, 1))
		requireNone(t, localize(spanOf(t, nil, repeat(window, 2)...), testParams(), testParams()))
	})
}

// TestLocalize_Deterministic verifies that the findings do not depend on
// the order in which the summaries arrived.
func TestLocalize_Deterministic(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	window := meshWindow(4, 4, 600, func(st, sr, dt, dr int) uint32 {
		lost := uint32(0)
		if (st == 2) != (dt == 2) {
			lost += uint32(rng.IntN(8))
		}
		if (st == 0 && sr == 1) || (dt == 0 && dr == 1) {
			lost += uint32(20 + rng.IntN(10))
		}
		return lost
	})
	reference := localize(spanOf(t, nil, repeat(window, 3)...), testParams(), testParams())
	if len(reference) == 0 {
		t.Fatal("the reference run has no findings")
	}
	for i := 0; i < 5; i++ {
		shuffled := append([]obs(nil), window...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got := localize(spanOf(t, nil, repeat(shuffled, 3)...), testParams(), testParams())
		if describeFindings(got) != describeFindings(reference) {
			t.Fatalf("shuffle %d: findings differ:%s\nwant:%s", i, describeFindings(got), describeFindings(reference))
		}
	}
}

// TestLocalize_FindingsAreBounded verifies the caps on what one evaluation
// reports when a great many components fail at once: every second RNIC of
// a fabric loses probes.
func TestLocalize_FindingsAreBounded(t *testing.T) {
	window := meshWindow(8, 8, 200, func(st, sr, dt, dr int) uint32 {
		lost := uint32(0)
		if sr%2 == 0 {
			lost += 20
		}
		if dr%2 == 0 {
			lost += 20
		}
		return lost
	})
	findings := localize(spanOf(t, nil, repeat(window, 2)...), testParams(), testParams())
	if len(findings) == 0 || len(findings) > maxFindingsPerSignal {
		t.Fatalf("%d findings, want between 1 and %d", len(findings), maxFindingsPerSignal)
	}
	for _, f := range findings {
		if len(f.Suspects) > maxCandidates {
			t.Errorf("finding lists %d candidates, want at most %d", len(f.Suspects), maxCandidates)
		}
		if len(f.Members) > maxMembersListed {
			t.Errorf("finding lists %d members, want at most %d", len(f.Members), maxMembersListed)
		}
	}
}

// checkFindingInvariants fails if a finding breaks what its consumers (the
// metric callback, the log lines, alert rules) rely on.
func checkFindingInvariants(t *testing.T, findings []Finding, minConfidence float64) {
	t.Helper()
	perSignal := map[string]int{}
	for _, f := range findings {
		perSignal[f.Signal]++
		if f.Signal != KindLoss && f.Signal != KindRTT {
			t.Fatalf("finding has signal %q", f.Signal)
		}
		if len(f.Suspects) == 0 || len(f.Suspects) > maxCandidates {
			t.Fatalf("finding has %d suspects", len(f.Suspects))
		}
		switch f.State {
		case StateLocalized:
			if len(f.Suspects) != 1 || f.Suspects[0].Confidence < minConfidence-1e-6 {
				t.Fatalf("localized finding with %d suspects, confidence %v", len(f.Suspects), f.Suspects[0].Confidence)
			}
			if kind := f.Suspects[0].Component.Kind; kind == ComponentFabric || kind == ComponentBackground {
				t.Fatalf("localized finding names the %s", kind)
			}
		case StateAmbiguous:
			if len(f.Suspects) < 2 {
				t.Fatalf("ambiguous finding with %d suspects", len(f.Suspects))
			}
		case StateNotLocalizable:
			if len(f.Suspects) != 1 {
				t.Fatalf("not-localizable finding with %d suspects", len(f.Suspects))
			}
		default:
			t.Fatalf("finding has state %q", f.State)
		}
		var sum float64
		for i, s := range f.Suspects {
			for name, v := range map[string]float64{
				"confidence": s.Confidence, "excess": s.ExcessRatio, "evidence": s.EvidenceNats,
			} {
				if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
					t.Fatalf("suspect %s has %s %v", s.Component.identity(), name, v)
				}
			}
			if s.Confidence > 1+1e-9 {
				t.Fatalf("suspect %s has confidence %v", s.Component.identity(), s.Confidence)
			}
			if i > 0 && s.Confidence > f.Suspects[i-1].Confidence+1e-12 {
				t.Fatalf("suspects are not ordered by confidence: %v after %v", s.Confidence, f.Suspects[i-1].Confidence)
			}
			sum += s.Confidence
		}
		if f.State != StateNotLocalizable && sum > 1+1e-6 {
			t.Fatalf("the confidences of one finding sum to %v", sum)
		}
		if len(f.Members) > maxMembersListed || f.MemberCount < len(f.Members) {
			t.Fatalf("finding lists %d members of %d", len(f.Members), f.MemberCount)
		}
	}
	for signal, n := range perSignal {
		if n > maxFindingsPerSignal {
			t.Fatalf("%d %s findings, want at most %d", n, signal, maxFindingsPerSignal)
		}
	}
}
