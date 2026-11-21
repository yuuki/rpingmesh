package analyzer

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/protobuf/proto"
)

// FuzzParseTopology feeds arbitrary bytes to the topology parser. The file
// is operator input read at startup; whatever the parser accepts must
// satisfy the invariants the localizer and the metric attributes rely on.
func FuzzParseTopology(f *testing.F) {
	for _, seed := range []string{
		validTopologyYAML,
		"version: 1\ntors: {leaf-1: {rail: rail0, spine_group: pod-a}}\n",
		`{"version": 1, "tors": {"leaf-1": {"rail": "rail0"}}}`,
		"version: 1\ntors:\n  a: &x {rail: r, spine_group: g}\n  b: *x\n",
		"version: 1\ntors: {1: {rail: 2}, true: {spine_group: null}}\n",
		"version: 1\ntors:\n  leaf-1: {rail: rail0, spine_group: pod-a}\n  leaf-2: {rail: rail1, spine_group: pod-a}\n",
		"",
		"version: 2\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		topo, err := ParseTopology(data)
		if err != nil {
			if topo != nil {
				t.Fatal("ParseTopology returned a topology with an error")
			}
			return
		}
		if n := topo.Tors(); n < 1 || n > MaxTopologyTors {
			t.Fatalf("accepted %d ToRs", n)
		}
		checkName := func(what, name string) {
			if len(name) > maxTopologyNameLen || !utf8.ValidString(name) || name != strings.TrimSpace(name) {
				t.Fatalf("accepted %s %q", what, name)
			}
			for _, r := range name {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("accepted %s %q with a control character", what, name)
				}
			}
		}
		rails := make(map[string]struct{})
		groupRail := make(map[string]string)
		for id, facts := range topo.tors {
			if id == "" || probe.IsReservedTorID(id) {
				t.Fatalf("accepted ToR ID %q", id)
			}
			checkName("ToR ID", id)
			checkName("rail", facts.Rail)
			checkName("spine group", facts.SpineGroup)
			if facts.Rail != "" {
				rails[facts.Rail] = struct{}{}
			}
			if facts.SpineGroup != "" {
				// A spine group belongs to one rail.
				if rail, seen := groupRail[facts.SpineGroup]; seen && rail != facts.Rail {
					t.Fatalf("spine group %q spans rails %q and %q", facts.SpineGroup, rail, facts.Rail)
				}
				groupRail[facts.SpineGroup] = facts.Rail
			}
			got, known := topo.Lookup(id)
			if got != facts || known != (facts.Rail != "" || facts.SpineGroup != "") {
				t.Fatalf("Lookup(%q) = %+v, %v; stored %+v", id, got, known, facts)
			}
		}
		if topo.Rails() != len(rails) || topo.SpineGroups() != len(groupRail) {
			t.Fatalf("counts: Rails() = %d (want %d), SpineGroups() = %d (want %d)",
				topo.Rails(), len(rails), topo.SpineGroups(), len(groupRail))
		}
	})
}

// fuzzTopology is a small topology the solver fuzz targets select facts
// from: two spine groups of two ToRs on one rail, a ToR directly under a
// second rail, and tor-5 to tor-7 without facts.
func fuzzTopology(t testing.TB) *Topology {
	t.Helper()
	topo, err := ParseTopology([]byte(`
version: 1
tors:
  tor-0: {rail: r0, spine_group: g0}
  tor-1: {rail: r0, spine_group: g0}
  tor-2: {rail: r0, spine_group: g1}
  tor-3: {rail: r0, spine_group: g1}
  tor-4: {rail: r1}
`))
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

// FuzzLocalize runs the solver on arbitrary evidence: paths between up to
// 8 ToRs of 4 RNICs with any probe and loss counts, over every span length
// the settings allow (1 to MaxLocalizationWindows windows), with and without
// topology facts. The solver must not panic or
// loop, and every finding must keep the invariants its consumers rely on
// (confidences in [0, 1], finite numbers, bounded candidate lists).
func FuzzLocalize(f *testing.F) {
	// The first byte selects the topology facts and the minimum confidence,
	// the second the number of windows. Each path is then six bytes: source
	// ToR and RNIC, target ToR and RNIC, probes, lost probes.
	seed := []byte{0x01, 0x01}
	for st := byte(0); st < 4; st++ {
		for dt := byte(0); dt < 4; dt++ {
			for r := byte(0); r < 3; r++ {
				lost := byte(0)
				if st == 1 || dt == 1 {
					lost = 9
				}
				seed = append(seed, st, r, dt, r+1, 200, lost)
			}
		}
	}
	f.Add(seed)
	f.Add(append([]byte{0x01, MaxLocalizationWindows - 1}, seed[2:]...))
	f.Add([]byte{0x00, 0, 0, 0, 1, 0, 255, 255, 0, 0, 1, 0, 255, 255})
	f.Add([]byte{0x01, 3, 5, 0, 6, 0, 10, 10, 6, 0, 7, 0, 10, 10, 7, 0, 5, 0, 10, 10})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 || len(data) > 6*4096 {
			return
		}
		mode := data[0]
		numWindows := 1 + int(data[1])%MaxLocalizationWindows
		data = data[2:]
		var topo *Topology
		if mode&1 != 0 {
			topo = fuzzTopology(t)
		}
		windows := make([][]obs, numWindows)
		for i := 0; i+6 <= len(data); i += 6 {
			b := data[i : i+6]
			o := obs{
				agent: "host-" + string('a'+b[1]%4),
				src:   "gid-" + string('0'+b[0]%8) + string('a'+b[1]%4), srcTor: "tor-" + string('0'+b[0]%8),
				dst: "gid-" + string('0'+b[2]%8) + string('a'+b[3]%4), dstTor: "tor-" + string('0'+b[2]%8),
				// Counts up to 65025, and more lost probes than probes.
				total: uint32(b[4]) * uint32(b[4]), failed: uint32(b[5]) * uint32(b[5]),
			}
			if b[5]&1 != 0 {
				o.p99 = 2 * simRTTThresholdNs
			}
			windows[(i/6)%numWindows] = append(windows[(i/6)%numWindows], o)
		}

		store := newEvidenceStore(numWindows, 1<<16, simRTTThresholdNs)
		nowNs := testBaseStartNs + uint64(numWindows)*testWindowNs
		for w, window := range windows {
			for _, o := range window {
				store.observe(o.agent, o.summary(w), nowNs)
			}
		}
		sp := buildSpan(store.snapshots(nowNs+testWindowNs+closeMarginNs), topo)
		params := solverParams{
			baseline:      DefaultLocalizationBaselineLossRatio,
			minConfidence: 0.5 + float64(mode>>1&7)/16, // 0.5 .. 0.94
			spanWindows:   numWindows,
		}
		findings := localize(sp, params, params)
		checkFindingInvariants(t, findings, params.minConfidence)
		// The result is a function of the evidence alone.
		if again := localize(sp, params, params); describeFindings(again) != describeFindings(findings) {
			t.Fatalf("two runs on the same span differ:%s\nand:%s", describeFindings(findings), describeFindings(again))
		}
	})
}

// FuzzLocalizerIngest feeds arbitrary wire-format ProbeAnalysisReport
// messages (the controller may serve unauthenticated agents) through Ingest
// with localization on, then evaluates, for every span length the settings
// allow. Whatever the reports hold, the evidence store must stay within its
// bounds, the span within its windows, and the findings valid.
func FuzzLocalizerIngest(f *testing.F) {
	for _, rep := range []*controller_agent.ProbeAnalysisReport{
		{AgentId: "host-a", Summaries: []*controller_agent.PathSummary{
			obs{src: "a", srcTor: "tor-1", dst: "b", dstTor: "tor-2", total: 100, failed: 7}.summary(0),
			obs{src: "a", srcTor: "tor-1", dst: "c", dstTor: "tor-1", total: 100, failed: 100, p99: 900_000}.summary(1),
		}},
		{AgentId: "", Summaries: []*controller_agent.PathSummary{{}, nil, {SourceGid: "a", TargetGid: "a"}}},
		{Summaries: []*controller_agent.PathSummary{{
			SourceGid: "a", SourceTorId: "t", TargetGid: "b", TargetTorId: "u",
			ProbeTotal: 1, ProbeFailed: 4_000_000_000, WindowStartUnixNs: ^uint64(0), WindowDurationMs: ^uint32(0),
		}}},
	} {
		b, err := proto.Marshal(rep)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, uint8(1))
		f.Add(b, uint8(MaxLocalizationWindows-1))
	}

	f.Fuzz(func(t *testing.T, data []byte, span uint8) {
		var rep controller_agent.ProbeAnalysisReport
		if proto.Unmarshal(data, &rep) != nil {
			return
		}
		const maxPaths = 64
		windows := 1 + int(span)%MaxLocalizationWindows
		last := windows - 1
		az, clock := newTestLocalizer(t, LocalizationConfig{Windows: windows, MaxPathsPerWindow: maxPaths, Topology: fuzzTopology(t)}, nil)
		clock.ns = windowEnd(last)
		az.Ingest(context.Background(), &rep)
		// The same summaries again, moved into the windows of the span, so
		// that arbitrary window bounds do not keep the evidence out; every
		// third one a third of a window late, as no agent reports it.
		for i, s := range rep.GetSummaries() {
			if s != nil {
				s.WindowStartUnixNs = testBaseStartNs + uint64(i%windows)*testWindowNs
				if i%3 == 2 {
					s.WindowStartUnixNs += testWindowNs / 3
				}
				s.WindowDurationMs = testWindowMs
			}
		}
		az.Ingest(context.Background(), &rep)

		store := az.loc.store
		if len(store.windows) > windows+extraRetainedWindows {
			t.Fatalf("%d windows retained", len(store.windows))
		}
		if span, _ := store.span(windowClose(last)); len(span) > windows {
			t.Fatalf("the span holds %d windows, configured for %d", len(span), windows)
		}
		for _, w := range store.windows {
			if len(w.pathKeys) > maxPaths || len(w.pathEv) != len(w.pathKeys) || len(w.rnics) > 2*maxPaths {
				t.Fatalf("window holds %d paths and %d RNICs with a cap of %d paths", len(w.pathKeys), len(w.rnics), maxPaths)
			}
		}
		clock.ns = windowClose(last)
		az.loc.evaluate(context.Background())
		checkFindingInvariants(t, az.loc.currentFindings(), DefaultLocalizationMinConfidence)
	})
}
