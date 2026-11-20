package analyzer

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Benchmarks of the localizer at the scale it is bounded for: a fabric of
// 4 rails of 8 spine groups of 32 ToRs with 16 hosts per ToR position, i.e.
// 1024 ToRs and 16384 RNICs. Every RNIC probes 15 RNICs under its ToR and 5
// under other ToRs, which gives 327680 paths per window and over a million
// path summaries per evidence span of four windows.

type benchFabric struct {
	rails, groups, tors, hosts int
	interTor                   int
}

var largeFabric = benchFabric{rails: 4, groups: 8, tors: 32, hosts: 16, interTor: 5}

func (f benchFabric) torName(r, g, t int) string { return fmt.Sprintf("leaf-r%d-g%d-t%d", r, g, t) }
func (f benchFabric) gid(r, g, t, h int) string {
	return fmt.Sprintf("fd00:%04x:%04x:%04x:0000:0000:0000:%04x", r, g, t, h+1)
}

func (f benchFabric) topology(tb testing.TB) *Topology {
	tb.Helper()
	yaml := "version: 1\ntors:\n"
	for r := 0; r < f.rails; r++ {
		for g := 0; g < f.groups; g++ {
			for t := 0; t < f.tors; t++ {
				yaml += fmt.Sprintf("  %s: {rail: rail%d, spine_group: pod-r%d-g%d}\n", f.torName(r, g, t), r, r, g)
			}
		}
	}
	topo, err := ParseTopology([]byte(yaml))
	if err != nil {
		tb.Fatal(err)
	}
	return topo
}

// benchLoss returns the loss ratio of a path between two RNICs.
type benchLoss func(rail, srcGroup, srcTor, srcHost, dstGroup, dstTor, dstHost int) float64

// reports returns the summaries of one window, one report per host, with
// the targets every RNIC probes drawn once from the seed.
func (f benchFabric) reports(window int, loss benchLoss) []*controller_agent.ProbeAnalysisReport {
	targets := rand.New(rand.NewPCG(1, 1)) // the same targets in every window
	counts := rand.New(rand.NewPCG(2, uint64(window)))
	lost := func(probes uint32, ratio float64) uint32 {
		// The noise of a thousand probes is not what is measured here: a
		// rounded expectation with one random unit keeps the generator
		// cheap.
		expected := float64(probes) * ratio
		n := uint32(expected)
		if counts.Float64() < expected-float64(n) {
			n++
		}
		return n
	}
	var out []*controller_agent.ProbeAnalysisReport
	for g := 0; g < f.groups; g++ {
		for t := 0; t < f.tors; t++ {
			for h := 0; h < f.hosts; h++ {
				rep := &controller_agent.ProbeAnalysisReport{AgentId: fmt.Sprintf("host-g%d-t%d-h%02d", g, t, h)}
				for r := 0; r < f.rails; r++ {
					add := func(dg, dt, dh int, probes uint32, ptype controller_agent.PinglistType) {
						failed := lost(probes, loss(r, g, t, h, dg, dt, dh))
						rep.Summaries = append(rep.Summaries, &controller_agent.PathSummary{
							SourceGid: f.gid(r, g, t, h), SourceTorId: f.torName(r, g, t),
							TargetGid: f.gid(r, dg, dt, dh), TargetTorId: f.torName(r, dg, dt),
							PinglistType:      ptype,
							WindowStartUnixNs: testBaseStartNs + uint64(window)*testWindowNs,
							WindowDurationMs:  testWindowMs,
							ProbeTotal:        probes, ProbeFailed: failed, ProbeSuccess: probes - failed,
							NetworkRttP99Ns: 20_000,
						})
					}
					for dh := 0; dh < f.hosts; dh++ {
						if dh != h {
							add(g, t, dh, 60, controller_agent.PinglistType_TOR_MESH)
						}
					}
					for i := 0; i < f.interTor; i++ {
						dg, dt := targets.IntN(f.groups), targets.IntN(f.tors)
						if dg == g && dt == t {
							dt = (dt + 1) % f.tors
						}
						add(dg, dt, targets.IntN(f.hosts), 30, controller_agent.PinglistType_INTER_TOR)
					}
				}
				out = append(out, rep)
			}
		}
	}
	return out
}

// benchScenarios are the fabrics the solver is timed on.
var benchScenarios = []struct {
	name string
	loss benchLoss
}{
	// No excess anywhere: the solver finds that no component gains.
	{"healthy", func(int, int, int, int, int, int, int) float64 { return 1e-4 }},
	// One lossy spine: 0.5% on every path between ToRs that touches the
	// spine group, about 3% of all paths.
	{"one_spine_group", func(r, sg, st, _, dg, dt, _ int) float64 {
		if r == 1 && (sg != dg || st != dt) && (sg == 3 || dg == 3) {
			return 0.005
		}
		return 1e-4
	}},
	// Many faults at once: 32 RNICs, 8 ToRs' uplinks and two spine groups.
	{"many_faults", func(r, sg, st, sh, dg, dt, dh int) float64 {
		ratio := 1e-4
		inter := sg != dg || st != dt
		if (st == 7 && sh == 3) || (dt == 7 && dh == 3) {
			ratio += 0.05
		}
		if inter && r == 2 && ((sg == 5 && st%4 == 0) || (dg == 5 && dt%4 == 0)) {
			ratio += 0.01
		}
		if inter && ((r == 0 && (sg == 1 || dg == 1)) || (r == 3 && (sg == 6 || dg == 6))) {
			ratio += 0.005
		}
		return ratio
	}},
	// The worst case for the solver's work: every path has events.
	{"every_path_lossy", func(int, int, int, int, int, int, int) float64 { return 0.05 }},
}

type benchEvidence struct {
	once  sync.Once
	store *evidenceStore
	span  *span
}

var benchCache = make([]benchEvidence, len(benchScenarios))

// evidence returns the store and the span of scenario i, built once.
func evidence(tb testing.TB, i int) (*evidenceStore, *span) {
	tb.Helper()
	e := &benchCache[i]
	e.once.Do(func() {
		e.store = newEvidenceStore(DefaultLocalizationWindows, 1<<20, simRTTThresholdNs)
		nowNs := testBaseStartNs + DefaultLocalizationWindows*testWindowNs
		for w := 0; w < DefaultLocalizationWindows; w++ {
			for _, rep := range largeFabric.reports(w, benchScenarios[i].loss) {
				for _, s := range rep.GetSummaries() {
					e.store.observe(rep.GetAgentId(), s, nowNs)
				}
			}
		}
		e.span = buildSpan(e.store.snapshots(nowNs+testWindowNs+closeMarginNs), largeFabric.topology(tb))
	})
	return e.store, e.span
}

// BenchmarkLocalize times one evaluation of both signals on the pooled
// evidence of four windows.
func BenchmarkLocalize(b *testing.B) {
	for i, sc := range benchScenarios {
		b.Run(sc.name, func(b *testing.B) {
			_, sp := evidence(b, i)
			params := testParams()
			b.ReportAllocs()
			b.ReportMetric(float64(len(sp.paths)), "paths")
			var findings []Finding
			for b.Loop() {
				findings = localize(sp, params, params)
			}
			b.ReportMetric(float64(len(findings)), "findings")
		})
	}
}

// BenchmarkSnapshot times the copy of four windows. The localizer holds the
// lock that Ingest takes for this long, once per evaluation.
func BenchmarkSnapshot(b *testing.B) {
	store, _ := evidence(b, 0)
	nowNs := testBaseStartNs + (DefaultLocalizationWindows+1)*testWindowNs + closeMarginNs
	b.ReportAllocs()
	for b.Loop() {
		if snaps := store.snapshots(nowNs); len(snaps) != DefaultLocalizationWindows {
			b.Fatalf("%d windows in the span", len(snaps))
		}
	}
}

// BenchmarkBuildSpan times the pooling of four windows into a span, which
// runs outside that lock.
func BenchmarkBuildSpan(b *testing.B) {
	store, _ := evidence(b, 0)
	topo := largeFabric.topology(b)
	nowNs := testBaseStartNs + (DefaultLocalizationWindows+1)*testWindowNs + closeMarginNs
	snaps := store.snapshots(nowNs)
	b.ReportAllocs()
	for b.Loop() {
		if sp := buildSpan(snaps, topo); len(sp.paths) == 0 {
			b.Fatal("empty span")
		}
	}
}

// BenchmarkEvidenceObserve times the localizer's share of ingesting one
// path summary.
func BenchmarkEvidenceObserve(b *testing.B) {
	reports := largeFabric.reports(0, benchScenarios[0].loss)
	var summaries []*controller_agent.PathSummary
	for _, rep := range reports[:256] {
		summaries = append(summaries, rep.GetSummaries()...)
	}
	store := newEvidenceStore(DefaultLocalizationWindows, 1<<20, simRTTThresholdNs)
	nowNs := testBaseStartNs + testWindowNs
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		store.observe("host", summaries[i%len(summaries)], nowNs)
		i++
	}
}

// TestLocalize_LargeFabric runs the benchmark scenarios once as a test: the
// solver finds what was injected at the scale it is bounded for.
func TestLocalize_LargeFabric(t *testing.T) {
	if testing.Short() || raceDetector {
		t.Skip("builds the evidence of a 16384-RNIC fabric")
	}
	want := map[string][]string{
		"healthy":         nil,
		"one_spine_group": {"spine_group/pod-r1-g3"},
	}
	for i, sc := range benchScenarios {
		expected, ok := want[sc.name]
		if !ok {
			continue
		}
		t.Run(sc.name, func(t *testing.T) {
			_, sp := evidence(t, i)
			// 20 targets per RNIC, less the few inter-ToR targets drawn
			// twice.
			if got, most := len(sp.paths), 4*8*32*16*(15+5); got > most || got < most*99/100 {
				t.Fatalf("span holds %d paths, want about %d", got, most)
			}
			findings := localize(sp, testParams(), testParams())
			checkFindingInvariants(t, findings, DefaultLocalizationMinConfidence)
			requireLocalized(t, findings, KindLoss, expected...)
		})
	}
	t.Run("many_faults", func(t *testing.T) {
		_, sp := evidence(t, 2)
		findings := localize(sp, testParams(), testParams())
		checkFindingInvariants(t, findings, DefaultLocalizationMinConfidence)
		// The two spine groups are named; the other findings may be cut at
		// the cap, but none of them is on a component without a fault.
		got := map[string]bool{}
		for _, f := range findings {
			if f.State == StateLocalized {
				got[f.Suspects[0].Component.identity()] = true
			}
		}
		for _, id := range []string{"spine_group/pod-r0-g1", "spine_group/pod-r3-g6"} {
			if !got[id] {
				t.Errorf("%s is not localized:%s", id, describeFindings(findings))
			}
		}
	})
	t.Run("every_path_lossy", func(t *testing.T) {
		_, sp := evidence(t, 3)
		findings := localize(sp, testParams(), testParams())
		checkFindingInvariants(t, findings, DefaultLocalizationMinConfidence)
		requireCandidates(t, findings, KindLoss, StateNotLocalizable, ComponentBackground)
	})
}
