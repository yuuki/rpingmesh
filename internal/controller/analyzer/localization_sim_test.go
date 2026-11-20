package analyzer

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

// These tests validate the localizer end to end against the simulated
// fabric of fabricsim_test.go: summaries go through Analyzer.Ingest, windows
// close on the localizer's clock, and the findings are compared with the
// faults injected into the fabric. Every simulation is seeded, so the tests
// are deterministic.

// simWindows is how many windows a simulation runs before it is judged: the
// default evidence span.
const simWindows = DefaultLocalizationWindows

// TestLocalization_FaultClasses verifies that each class of fault is
// localized to its component, with the full topology facts: an RNIC or host
// anomaly, a ToR, one lossy ToR uplink (one ECMP member), one lossy spine
// and one lossy core switch. The loss ratios are those of gray failures:
// none of the uplink, spine or core faults breaches the 2% per-path loss
// SLO of Phase 1 on a single path.
func TestLocalization_FaultClasses(t *testing.T) {
	tests := []struct {
		name  string
		fault simFault
	}{
		{"one RNIC loses 5% of its packets", simFault{element: "rnic", rail: 0, group: 0, tor: 1, host: 2, loss: 0.05}},
		{"one RNIC is down", simFault{element: "rnic", rail: 1, group: 1, tor: 0, host: 4, loss: 1}},
		{"one host is down", simFault{element: "host", group: 1, tor: 2, host: 3, loss: 1}},
		{"one host loses 3% on every RNIC", simFault{element: "host", group: 0, tor: 3, host: 0, loss: 0.03}},
		{"one ToR loses 1%", simFault{element: "tor", rail: 1, group: 0, tor: 0, loss: 0.01}},
		{"one of four uplinks of a ToR loses 3%", simFault{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.03}},
		{"one of four uplinks of a ToR loses 1%", simFault{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.01}},
		{"one of four uplinks of a ToR is a black hole", simFault{element: "uplink", rail: 1, group: 0, tor: 2, member: 0, loss: 1}},
		{"one of four spines loses 2%", simFault{element: "spine", rail: 1, group: 1, member: 0, loss: 0.02}},
		{"one of four core switches loses 3%", simFault{element: "core", rail: 0, member: 1, loss: 0.03}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := defaultSimFabric(uint64(100 + i))
			f.faults = []simFault{tc.fault}
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
			requireLocalized(t, run.after(simWindows), KindLoss, f.truth(tc.fault))
		})
	}
}

// TestLocalization_ECMPMemberIsDilutedNotIdentified pins what a finding
// says about one lossy uplink: the suspect is the ToR's uplink set, and the
// excess it reports is the member's loss diluted over the ToR's four
// uplinks and counted for the probe and its ACK. Which member is lossy is
// not reported, because the controller does not know the ECMP hash.
func TestLocalization_ECMPMemberIsDilutedNotIdentified(t *testing.T) {
	f := defaultSimFabric(7)
	fault := simFault{element: "uplink", rail: 0, group: 0, tor: 1, member: 3, loss: 0.04}
	f.faults = []simFault{fault}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	findings := run.after(simWindows)
	requireLocalized(t, findings, KindLoss, f.truth(fault))

	sus := findings[0].Suspects[0]
	if sus.Component.Kind != ComponentTorUplink || sus.Component.GID != "" {
		t.Errorf("suspect = %+v, want the ToR's uplink set without any RNIC identity", sus.Component)
	}
	if sus.Component.SpineGroup != f.groupName(0, 0) || sus.Component.Rail != f.railName(0) {
		t.Errorf("suspect facts = %+v, want the ToR's spine group and rail", sus.Component)
	}
	// A probe crosses the ToR's uplinks once, its ACK once; each crossing
	// takes the lossy member with probability 1/4.
	want := 2 * fault.loss / float64(f.spines)
	if math.Abs(sus.ExcessRatio-want) > 0.3*want {
		t.Errorf("ExcessRatio = %.4f, want about %.4f (the member's %.2f over %d uplinks, twice)",
			sus.ExcessRatio, want, fault.loss, f.spines)
	}
}

// TestLocalization_RTT verifies the RTT signal: a component that delays
// packets beyond the RTT threshold, without losing any, is localized from
// the windows whose p99 exceeds the threshold.
func TestLocalization_RTT(t *testing.T) {
	const delay = 2 * simRTTThresholdNs
	tests := []struct {
		name  string
		fault simFault
	}{
		{"slow RNIC", simFault{element: "rnic", rail: 0, group: 1, tor: 1, host: 1, delayNs: delay}},
		{"slow ToR", simFault{element: "tor", rail: 1, group: 1, tor: 3, delayNs: delay}},
		{"slow ToR uplink", simFault{element: "uplink", rail: 0, group: 0, tor: 2, member: 1, delayNs: delay}},
		{"slow spine", simFault{element: "spine", rail: 1, group: 0, member: 2, delayNs: delay}},
		{"slow core switch", simFault{element: "core", rail: 0, member: 0, delayNs: delay}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := defaultSimFabric(uint64(200 + i))
			f.faults = []simFault{tc.fault}
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
			findings := run.after(simWindows)
			requireLocalized(t, findings, KindRTT, f.truth(tc.fault))
			requireLocalized(t, findings, KindLoss) // no loss: no loss finding
		})
	}
}

// TestLocalization_RTTDisabledWithoutThreshold verifies that the RTT signal
// follows the Phase 1 RTT check: a threshold of 0 disables both.
func TestLocalization_RTTDisabledWithoutThreshold(t *testing.T) {
	f := defaultSimFabric(11)
	f.faults = []simFault{{element: "spine", rail: 1, group: 0, member: 2, delayNs: 2 * simRTTThresholdNs}}
	f.build()
	cfg := simAnalyzerConfig(LocalizationConfig{Topology: f.topology(t, true, true)})
	cfg.Cluster.NetworkRTTP99Ns = 0
	clock := &simClock{ns: simBaseStartNs}
	az := New(cfg, nil)
	az.loc.now = clock.now
	run := &simRun{t: t, fabric: f, az: az, clock: clock}
	requireNone(t, run.after(simWindows))
}

// TestLocalization_HealthyFabricAccusesNothing verifies that sampling noise
// alone never produces a finding: 20 fabrics with different seeds (5 with
// the race detector), each evaluated on nine successive spans, at a
// background loss of a tenth, a half and the whole of the baseline, and with
// one in ten thousand probes above the RTT threshold.
func TestLocalization_HealthyFabricAccusesNothing(t *testing.T) {
	seeds, _ := sweepSize(t, 20)
	for _, noise := range []float64{1e-4, 5e-4, 1e-3} {
		t.Run(fmt.Sprintf("background loss %g", noise), func(t *testing.T) {
			for seed := uint64(1); seed <= uint64(seeds); seed++ {
				f := defaultSimFabric(300 + seed)
				f.noiseLoss = noise
				f.noiseRTT = 1e-4
				run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
				for step := 0; step < simWindows+5; step++ {
					if findings := run.step(); len(findings) != 0 {
						t.Fatalf("seed %d, window %d: want no findings, got:%s", seed, step, describeFindings(findings))
					}
				}
			}
		})
	}
}

// TestLocalization_NoiseAboveBaselineIsNotLocalized verifies what happens
// when the whole fabric loses more than the configured baseline (here five
// times as much, on every path): no component is accused. Whatever is
// reported is reported as not localizable.
func TestLocalization_NoiseAboveBaselineIsNotLocalized(t *testing.T) {
	for seed := uint64(1); seed <= 10; seed++ {
		f := defaultSimFabric(400 + seed)
		f.noiseLoss = 5e-3
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
		findings := run.after(simWindows)
		for _, fd := range findings {
			if fd.State != StateNotLocalizable {
				t.Fatalf("seed %d: want only not-localizable findings, got:%s", seed, describeFindings(findings))
			}
		}
	}
}

// TestLocalization_WithoutTopologyFacts verifies the two behaviours without
// a topology file. A fault at or below a ToR is still localized, because
// the summaries carry the ToR of both ends. A fault above the ToRs is not:
// the degraded ToRs are reported as members of the fabric, not accused.
func TestLocalization_WithoutTopologyFacts(t *testing.T) {
	t.Run("ToR uplink is localized", func(t *testing.T) {
		f := defaultSimFabric(21)
		fault := simFault{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.03}
		f.faults = []simFault{fault}
		run := newSimRun(t, f, LocalizationConfig{})
		requireLocalized(t, run.after(simWindows), KindLoss, f.truth(fault))
	})
	t.Run("RNIC is localized", func(t *testing.T) {
		f := defaultSimFabric(22)
		fault := simFault{element: "rnic", rail: 1, group: 0, tor: 1, host: 0, loss: 0.05}
		f.faults = []simFault{fault}
		run := newSimRun(t, f, LocalizationConfig{})
		requireLocalized(t, run.after(simWindows), KindLoss, f.truth(fault))
	})
	t.Run("spine is not localizable", func(t *testing.T) {
		f := defaultSimFabric(23)
		f.faults = []simFault{{element: "spine", rail: 1, group: 1, member: 0, loss: 0.03}}
		run := newSimRun(t, f, LocalizationConfig{})
		fd := requireCandidates(t, run.after(simWindows), KindLoss, StateNotLocalizable, ComponentFabric)
		// The ToRs of the spine's group are what the degraded paths share.
		want := []string{f.torName(1, 1, 0), f.torName(1, 1, 1), f.torName(1, 1, 2), f.torName(1, 1, 3)}
		if fmt.Sprint(fd.Members) != fmt.Sprint(want) || fd.MemberCount != len(want) {
			t.Errorf("members = %v (%d), want %v", fd.Members, fd.MemberCount, want)
		}
	})
	t.Run("two ToR uplinks are not told from one fault above both", func(t *testing.T) {
		f := defaultSimFabric(24)
		f.faults = []simFault{
			{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.03},
			{element: "uplink", rail: 0, group: 0, tor: 0, member: 1, loss: 0.03},
		}
		run := newSimRun(t, f, LocalizationConfig{})
		fd := requireCandidates(t, run.after(simWindows), KindLoss, StateNotLocalizable, ComponentFabric)
		want := []string{f.torName(0, 0, 0), f.torName(0, 1, 3)}
		if fmt.Sprint(fd.Members) != fmt.Sprint(want) {
			t.Errorf("members = %v, want %v", fd.Members, want)
		}
	})
}

// TestLocalization_CoarseFacts verifies a topology file that states rails
// but no spine groups, on a fabric that has spine groups. A core fault is
// localized to the rail. A fault in one spine of one group is not put on a
// ToR: it is reported on the rail, the finest tier the facts describe above
// the ToRs, either as the suspect or as the scope of the degraded ToRs.
func TestLocalization_CoarseFacts(t *testing.T) {
	t.Run("core switch", func(t *testing.T) {
		f := defaultSimFabric(31)
		fault := simFault{element: "core", rail: 0, member: 1, loss: 0.05}
		f.faults = []simFault{fault}
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, false, true)})
		requireLocalized(t, run.after(simWindows), KindLoss, f.truth(fault))
	})
	t.Run("spine", func(t *testing.T) {
		for seed := uint64(1); seed <= 10; seed++ {
			f := defaultSimFabric(32 + seed)
			f.faults = []simFault{{element: "spine", rail: 1, group: 1, member: 0, loss: 0.03}}
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, false, true)})
			findings := run.after(simWindows)
			if len(findings) != 1 || len(findings[0].Suspects) != 1 ||
				findings[0].Suspects[0].Component.identity() != ComponentRail+"/"+f.railName(1) {
				t.Fatalf("seed %d: want one finding on the rail, got:%s", seed, describeFindings(findings))
			}
		}
	})
}

// TestLocalization_TwoSimultaneousFaults verifies that two faults at once
// are both localized, whether they are far apart or share a spine group.
func TestLocalization_TwoSimultaneousFaults(t *testing.T) {
	tests := []struct {
		name   string
		faults []simFault
	}{
		{"an uplink and an RNIC on different rails", []simFault{
			{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.03},
			{element: "rnic", rail: 1, group: 0, tor: 1, host: 2, loss: 0.05},
		}},
		{"two uplinks under one spine group", []simFault{
			{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.03},
			{element: "uplink", rail: 0, group: 1, tor: 0, member: 1, loss: 0.04},
		}},
		{"a spine and an RNIC under it", []simFault{
			{element: "spine", rail: 1, group: 0, member: 3, loss: 0.03},
			{element: "rnic", rail: 1, group: 0, tor: 2, host: 5, loss: 0.2},
		}},
		{"a ToR and a core switch of its rail", []simFault{
			{element: "tor", rail: 0, group: 0, tor: 1, loss: 0.02},
			{element: "core", rail: 0, member: 2, loss: 0.05},
		}},
		{"two hosts down under one ToR position", []simFault{
			{element: "host", group: 1, tor: 1, host: 0, loss: 1},
			{element: "host", group: 1, tor: 1, host: 4, loss: 1},
		}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := defaultSimFabric(uint64(500 + i))
			f.faults = tc.faults
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
			requireLocalized(t, run.after(simWindows), KindLoss, f.truth(tc.faults[0]), f.truth(tc.faults[1]))
		})
	}
}

// TestLocalization_HostGoesDown verifies the case of a host that fails as a
// whole: from one window on, its RNICs answer nothing and its agent reports
// nothing. The other agents' probes to its two RNICs fail. The host is
// named as one component because the controller remembers which agent
// reported those RNICs before; without that memory (the agent never
// reported) each RNIC is named on its own.
func TestLocalization_HostGoesDown(t *testing.T) {
	fault := simFault{element: "host", group: 0, tor: 2, host: 1, loss: 1}
	down := map[int]bool{}
	for w := 2; w < 2+simWindows; w++ {
		down[w] = true
	}

	t.Run("its agent reported before", func(t *testing.T) {
		f := defaultSimFabric(91)
		f.faults = []simFault{fault}
		f.windowFaults = map[int]map[int]bool{0: down}
		f.silentFrom = map[string]int{f.agentName(0, 2, 1): 2}
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
		requireLocalized(t, run.after(2+simWindows), KindLoss, f.truth(fault))
	})
	t.Run("its agent never reported", func(t *testing.T) {
		f := defaultSimFabric(92)
		f.faults = []simFault{fault}
		f.windowFaults = map[int]map[int]bool{0: down}
		f.silent = map[string]bool{f.agentName(0, 2, 1): true}
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
		requireLocalized(t, run.after(2+simWindows), KindLoss,
			ComponentRNIC+"/"+f.gid(0, 0, 2, 1), ComponentRNIC+"/"+f.gid(1, 0, 2, 1))
	})
}

// TestLocalization_FourRNICsAreNotTheirToR verifies the split step: four of
// the six RNICs under one ToR lose packets, the other two are clean. The
// ToR is the component with the largest gain, but it is not the fault: the
// four RNICs are named, and the ToR is not.
func TestLocalization_FourRNICsAreNotTheirToR(t *testing.T) {
	f := defaultSimFabric(61)
	var want []string
	for h := 0; h < 4; h++ {
		fault := simFault{element: "rnic", rail: 0, group: 0, tor: 2, host: h, loss: 0.03}
		f.faults = append(f.faults, fault)
		want = append(want, f.truth(fault))
	}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	requireLocalized(t, run.after(simWindows), KindLoss, want...)
}

// TestLocalization_IndistinguishableComponents verifies that components
// with the same observed paths are reported together, each with its share
// of the confidence, instead of one of them being picked.
func TestLocalization_IndistinguishableComponents(t *testing.T) {
	t.Run("one RNIC under the ToR: RNIC, ToR and uplinks", func(t *testing.T) {
		// One host per ToR position: no path stays under a ToR, and the
		// ToR's only RNIC has exactly the ToR's paths.
		f := defaultSimFabric(71)
		f.hosts, f.interTor, f.interProbes = 1, 7, 120
		f.faults = []simFault{{element: "uplink", rail: 0, group: 1, tor: 3, member: 2, loss: 0.05}}
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
		tor := f.torName(0, 1, 3)
		fd := requireCandidates(t, run.after(simWindows), KindLoss, StateAmbiguous,
			ComponentRNIC+"/"+f.gid(0, 1, 3, 0), ComponentTor+"/"+tor, ComponentTorUplink+"/"+tor)
		for _, s := range fd.Suspects {
			if math.Abs(s.Confidence-1.0/3) > 0.01 {
				t.Errorf("%s: confidence %.3f, want 1/3", s.Component.identity(), s.Confidence)
			}
		}
	})
	t.Run("no report from under the ToR: ToR and uplinks", func(t *testing.T) {
		// The agents under the ToR are silent, so no path that stays under
		// it is observed: its uplinks cannot be told from the switch.
		for _, element := range []string{"uplink", "tor"} {
			f := defaultSimFabric(72)
			f.silent = map[string]bool{}
			for h := 0; h < f.hosts; h++ {
				f.silent[f.agentName(1, 3, h)] = true
			}
			f.faults = []simFault{{element: element, rail: 0, group: 1, tor: 3, member: 2, loss: 0.03}}
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
			tor := f.torName(0, 1, 3)
			fd := requireCandidates(t, run.after(simWindows), KindLoss, StateAmbiguous,
				ComponentTor+"/"+tor, ComponentTorUplink+"/"+tor)
			for _, s := range fd.Suspects {
				if math.Abs(s.Confidence-0.5) > 0.01 {
					t.Errorf("%s fault, %s: confidence %.3f, want 1/2", element, s.Component.identity(), s.Confidence)
				}
			}
		}
	})
	t.Run("two ToRs in the spine group: both uplink sets and the group", func(t *testing.T) {
		// Every path between two ToRs of the group joins the same two ToRs,
		// so a fault in either's uplinks or in a spine looks the same.
		f := defaultSimFabric(73)
		f.groups, f.tors, f.interTor = 1, 2, 1
		f.faults = []simFault{{element: "spine", rail: 0, group: 0, member: 1, loss: 0.05}}
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
		requireCandidates(t, run.after(simWindows), KindLoss, StateAmbiguous,
			ComponentSpineGroup+"/"+f.groupName(0, 0),
			ComponentTorUplink+"/"+f.torName(0, 0, 0), ComponentTorUplink+"/"+f.torName(0, 0, 1))
	})
}

// TestLocalization_OneBurstIsNotAFault verifies the persistence rule: a
// ToR that loses half of its packets during one window only is never
// reported, neither while the burst is the newest window nor while it ages
// through the span.
func TestLocalization_OneBurstIsNotAFault(t *testing.T) {
	f := defaultSimFabric(81)
	f.faults = []simFault{{element: "tor", rail: 0, group: 0, tor: 0, loss: 0.5}}
	f.windowFaults = map[int]map[int]bool{0: {2: true}}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	for step := 0; step < 2*simWindows+2; step++ {
		if findings := run.step(); len(findings) != 0 {
			t.Fatalf("window %d: want no findings for a one-window burst, got:%s", step, describeFindings(findings))
		}
	}
}

// TestLocalization_FaultLifecycle follows one fault through time: it is
// reported once a second window confirms it, stays reported while it
// lasts, and clears once the windows that saw it have left the span.
func TestLocalization_FaultLifecycle(t *testing.T) {
	f := defaultSimFabric(82)
	fault := simFault{element: "uplink", rail: 1, group: 0, tor: 1, member: 0, loss: 0.05}
	f.faults = []simFault{fault}
	// The fault lasts from window 3 to window 8.
	active := map[int]bool{}
	for w := 3; w <= 8; w++ {
		active[w] = true
	}
	f.windowFaults = map[int]map[int]bool{0: active}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})

	for w := 0; w <= 8+simWindows; w++ {
		findings := run.step()
		switch {
		case w < 4:
			// Healthy, then one window of evidence: not yet.
			if len(findings) != 0 {
				t.Fatalf("window %d: want no findings before a second window confirms, got:%s", w, describeFindings(findings))
			}
		case w <= 8:
			requireLocalized(t, findings, KindLoss, f.truth(fault))
		case w == 8+simWindows:
			// Every window of the span is healthy again.
			if len(findings) != 0 {
				t.Fatalf("window %d: want the finding cleared, got:%s", w, describeFindings(findings))
			}
		}
	}
}

// TestLocalization_StuckPathIsNotAFault verifies the breadth rule: one path
// on which every probe fails (a stale QPN after an agent restart) accuses
// neither of its RNICs nor anything above them.
func TestLocalization_StuckPathIsNotAFault(t *testing.T) {
	f := defaultSimFabric(83)
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	// Break one inter-ToR path and one ToR-mesh path, in both directions of
	// their RNIC pair.
	stuck := map[[2]int]bool{}
	for _, mesh := range []bool{true, false} {
		for i := range f.paths {
			if f.paths[i].mesh == mesh {
				stuck[[2]int{f.paths[i].src, f.paths[i].dst}] = true
				stuck[[2]int{f.paths[i].dst, f.paths[i].src}] = true
				break
			}
		}
	}
	for w := 0; w < simWindows; w++ {
		summaries := f.window(w)
		for i := range summaries {
			if stuck[[2]int{summaries[i].path.src, summaries[i].path.dst}] {
				summaries[i].failed = summaries[i].total
			}
		}
		run.next = w + 1
		run.clock.ns = simBaseStartNs + uint64(w+1)*f.windowNs + 1
		for _, rep := range f.reports(w, summaries) {
			run.az.Ingest(t.Context(), rep)
		}
	}
	requireNone(t, run.evaluate())
}

// TestLocalization_FewFlowLabels verifies the degraded case of one flow
// label per path. A path then crosses one ECMP member or the other, so a
// lossy spine hits some paths of its group fully and spares the rest, and
// ToRs whose paths happen to be hit more show an excess of their own. The
// spine group is still found, and no ToR under it is accused.
func TestLocalization_FewFlowLabels(t *testing.T) {
	for seed := uint64(1); seed <= 20; seed++ {
		f := defaultSimFabric(900 + seed)
		f.flowLabels = 1
		fault := simFault{element: "spine", rail: int(seed % 2), group: int(seed / 2 % 2), member: int(seed % 4), loss: 0.4}
		f.faults = []simFault{fault}
		run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
		requireLocalized(t, run.after(simWindows), KindLoss, f.truth(fault))
	}
}

// sweepSize returns how many scenarios a random sweep runs per variant and
// the seed it starts from. The defaults keep the sweep short and fixed. Set
// RPINGMESH_SIM_SCENARIOS and RPINGMESH_SIM_SEED to run a larger sweep, or
// one with other seeds, when changing the solver:
//
//	RPINGMESH_SIM_SCENARIOS=1000 RPINGMESH_SIM_SEED=7 go test \
//	    -run TestLocalization_RandomFaults ./internal/controller/analyzer/
func sweepSize(t *testing.T, scenarios int) (int, uint64) {
	t.Helper()
	if testing.Short() || raceDetector {
		scenarios /= 4
	}
	var seed uint64
	if v := os.Getenv("RPINGMESH_SIM_SCENARIOS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("RPINGMESH_SIM_SCENARIOS=%q is not a positive number", v)
		}
		scenarios = n
	}
	if v := os.Getenv("RPINGMESH_SIM_SEED"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			t.Fatalf("RPINGMESH_SIM_SEED=%q is not a number below 2^32", v)
		}
		seed = n << 32
	}
	return scenarios, seed
}

// randomFault draws one fault: its element uniformly, its loss log-uniform
// between 0.5% and 50%.
func randomFault(rng *rand.Rand, f *simFabric) simFault {
	elements := []string{"rnic", "host", "tor", "uplink", "spine", "core"}
	fault := simFault{
		element: elements[rng.IntN(len(elements))],
		rail:    rng.IntN(f.rails), group: rng.IntN(f.groups), tor: rng.IntN(f.tors), host: rng.IntN(f.hosts),
		loss: 0.005 * math.Pow(100, rng.Float64()),
	}
	switch fault.element {
	case "uplink", "spine":
		fault.member = rng.IntN(f.spines)
	case "core":
		fault.member = rng.IntN(f.cores)
	}
	return fault
}

// TestLocalization_RandomFaultsAreNeverMisattributed is the accuracy test:
// random faults of random strength on fabrics observed in different ways,
// among them partial topology facts, missing agents, few flow labels, small
// fabrics and several faults at once. The requirement is on false
// accusations, not on sensitivity. A finding may be missing (a fault too
// weak to tell from noise) or coarse (ambiguous, not localizable), but:
//
//   - no finding that claims a confidence of 0.999 or more may point at
//     components that hold no fault;
//   - the findings that do point at components without a fault must be no
//     more than the findings themselves allow for. A finding with a
//     confidence of 0.97 claims to be wrong 3 times in 100; the claims are
//     summed, and the misses may exceed the sum by three standard
//     deviations at most. This is what "confidence" promises;
//   - a not-localizable finding must name a scope that holds a fault.
//
// Each variant also pins a floor for the faults it does localize, so that
// silence cannot pass for accuracy.
func TestLocalization_RandomFaultsAreNeverMisattributed(t *testing.T) {
	silence := func(share float64) func(*rand.Rand, *simFabric) {
		return func(rng *rand.Rand, f *simFabric) {
			f.silent = map[string]bool{}
			for g := 0; g < f.groups; g++ {
				for tor := 0; tor < f.tors; tor++ {
					for h := 0; h < f.hosts; h++ {
						if rng.Float64() < share {
							f.silent[f.agentName(g, tor, h)] = true
						}
					}
				}
			}
		}
	}
	variants := []struct {
		name          string
		groups, rails bool // facts the topology file states
		mutate        func(rng *rand.Rand, f *simFabric)
		faults        int
		// minCorrect is the least share of the faults that must be
		// localized: about ten points below the share of the 400-scenario
		// sweeps in the design document. Faults above the ToRs cannot be
		// localized without the facts, weak faults on small or sparsely
		// observed fabrics stay below the detection threshold, and a fault
		// in a spine of a single spine group has no other spine group to
		// stand out against at the lowest loss ratios.
		minCorrect float64
	}{
		{"full facts", true, true, nil, 1, 0.9},
		{"rails only", false, true, nil, 1, 0.85},
		{"no topology file", false, false, nil, 1, 0.5},
		{"30% of the agents silent", true, true, silence(0.3), 1, 0.85},
		{"70% of the agents silent", true, true, silence(0.7), 1, 0.65},
		{"two faults at once", true, true, nil, 2, 0.85},
		{"three faults at once", true, true, nil, 3, 0.85},
		{"2 hosts per ToR, 2 inter-ToR targets, 4 flow labels", true, true, func(_ *rand.Rand, f *simFabric) {
			f.hosts, f.interTor, f.flowLabels = 2, 2, 4
		}, 1, 0.65},
		{"one flow label", true, true, func(_ *rand.Rand, f *simFabric) { f.flowLabels = 1 }, 1, 0.85},
		{"one rail, one spine group, 8 ToRs", true, true, func(_ *rand.Rand, f *simFabric) {
			f.rails, f.groups, f.tors = 1, 1, 8
		}, 1, 0.65},
		{"3 spine groups of 2 ToRs, 3 hosts", true, true, func(_ *rand.Rand, f *simFabric) {
			f.groups, f.tors, f.hosts = 3, 2, 3
		}, 1, 0.85},
		{"background loss at the baseline", true, true, func(_ *rand.Rand, f *simFabric) { f.noiseLoss = 1e-3 }, 1, 0.9},
	}
	scenarios, seed := sweepSize(t, 40)
	for vi, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed+uint64(vi), 7))
			var faults, correct, ambiguous, notLocalizable, silent, misses int
			var claimed float64
			for i := 0; i < scenarios; i++ {
				f := defaultSimFabric(seed + uint64(vi*1_000_000+i))
				if v.mutate != nil {
					v.mutate(rng, f)
				}
				for k := 0; k < v.faults; k++ {
					f.faults = append(f.faults, randomFault(rng, f))
				}
				run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, v.groups, v.rails)})
				findings := run.after(simWindows)
				checkFindingInvariants(t, findings, DefaultLocalizationMinConfidence)
				out := f.judge(findings, v.groups, v.rails)
				if len(out.wrongScopes) != 0 {
					t.Errorf("scenario %d, faults %+v: not-localizable findings on a scope without a fault:%s\nall findings:%s",
						i, f.faults, describeFindings(out.wrongScopes), describeFindings(findings))
				}
				for _, miss := range out.misses {
					if claimedMiss(miss) <= 0.001 {
						t.Errorf("scenario %d, faults %+v: a finding of confidence >= 0.999 holds no fault:%s\nall findings:%s",
							i, f.faults, describeFindings([]Finding{miss}), describeFindings(findings))
					} else {
						t.Logf("scenario %d, faults %+v: miss within its claimed confidence:%s",
							i, f.faults, describeFindings([]Finding{miss}))
					}
				}
				faults += len(f.faults)
				correct += out.correct
				ambiguous += out.ambiguous
				notLocalizable += out.notLocalizable
				misses += len(out.misses)
				claimed += out.claimedMisses
				if len(findings) == 0 {
					silent++
				}
			}
			t.Logf("%d faults in %d scenarios: %d localized, %d ambiguous findings, %d not-localizable findings, %d scenarios without a finding; %d findings hold no fault (the findings claim %.2f)",
				faults, scenarios, correct, ambiguous, notLocalizable, silent, misses, claimed)
			if allowed := math.Floor(claimed + 3*math.Sqrt(claimed) + 0.5); float64(misses) > allowed {
				t.Errorf("%d findings hold no fault, but their confidences claim %.2f: more than three standard deviations above",
					misses, claimed)
			}
			// The floor is a statement about a share: with the few
			// scenarios of a short run it would be noise.
			if share := float64(correct) / float64(faults); scenarios >= 40 && share < v.minCorrect {
				t.Errorf("localized %.0f%% of the faults, want at least %.0f%%", 100*share, 100*v.minCorrect)
			}
		})
	}
}
