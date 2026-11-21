package analyzer

import (
	"fmt"
	"strings"
	"testing"
)

// The tests of this file put the localizer through ordinary operations of
// a cluster: agents that restart, hosts and switches that are rebooted, a
// ToR that runs on fewer uplinks, a deployment of one ToR, one burst. None
// of them is a fault of a healthy component, so none may be reported as
// one. They run on the simulated fabric with the agents' timing
// (fabrictime_test.go).

// stepAll runs the simulation for n windows, evaluates after each, and
// returns every finding that was current after any of them, with the window.
func stepAll(run *simRun, n int) map[int][]Finding {
	out := make(map[int][]Finding)
	for w := 0; w < n; w++ {
		if findings := run.step(); len(findings) > 0 {
			out[w] = findings
		}
	}
	return out
}

// requireNoneEver fails when any evaluation reported a finding.
func requireNoneEver(t *testing.T, byWindow map[int][]Finding, what string) {
	t.Helper()
	for w, findings := range byWindow {
		t.Errorf("%s: findings after window %d:%s", what, w, describeFindings(findings))
		return
	}
}

// requireOnly fails when any evaluation reported a finding that allowed
// rejects.
func requireOnly(t *testing.T, byWindow map[int][]Finding, what string, allowed func(Finding) bool) {
	t.Helper()
	for w, findings := range byWindow {
		for _, f := range findings {
			if !allowed(f) {
				t.Errorf("%s: after window %d:%s", what, w, describeFindings(findings))
				return
			}
		}
	}
}

// TestLocalization_AgentRestartIsNotAFault restarts one agent at every
// phase of a window, with a short and a long stop, on hosts with one RNIC
// and with two. Every agent that probes the host loses its probes until it
// refreshes its pinglist, for 30 s to more than a minute; the restarted
// agent's own probes are delivered. Nothing may be reported.
func TestLocalization_AgentRestartIsNotAFault(t *testing.T) {
	step := 3.0
	if raceDetector || testing.Short() {
		step = 10
	}
	for _, rails := range []int{1, 2} {
		for _, down := range []float64{1, 20, 60} {
			t.Run(fmt.Sprintf("%d rails, down %.0f s", rails, down), func(t *testing.T) {
				for at := 60.0; at < 90; at += step {
					f := defaultSimFabric(uint64(1000 + at))
					f.rails = rails
					f.timing = agentTiming()
					f.timing.restarts = map[string]simRestart{f.agentName(1, 2, 3): {at: at, down: down}}
					run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
					requireNoneEver(t, stepAll(run, 10), fmt.Sprintf("restart at %.0f s", at))
				}
			})
		}
	}
}

// TestLocalization_RackRestartIsNotAToRFault restarts the agents of one
// rack one after the other, as a rolling upgrade ordered by rack does. All
// paths into the rack and all paths under its ToR lose their probes for a
// while, which is what a failing ToR looks like, except that the rack's own
// probes to the rest of the fabric are delivered.
func TestLocalization_RackRestartIsNotAToRFault(t *testing.T) {
	for _, spacing := range []float64{0, 2, 10} {
		t.Run(fmt.Sprintf("%.0f s apart", spacing), func(t *testing.T) {
			f := defaultSimFabric(7)
			f.timing = agentTiming()
			f.timing.restarts = map[string]simRestart{}
			for h := 0; h < f.hosts; h++ {
				f.timing.restarts[f.agentName(1, 2, h)] = simRestart{at: 62 + spacing*float64(h), down: 2}
			}
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
			requireNoneEver(t, stepAll(run, 12), "rack restart")
		})
	}
}

// TestLocalization_FleetRestartNamesNoComponent restarts every agent of the
// fabric within a minute. Then no RNIC is left whose probes show that the
// network is intact, and the loss on all paths cannot be told from a
// fabric-wide fault: it may be reported as not localizable, but no
// component may be named.
func TestLocalization_FleetRestartNamesNoComponent(t *testing.T) {
	f := defaultSimFabric(8)
	f.timing = agentTiming()
	f.timing.restarts = map[string]simRestart{}
	n := 0
	for g := 0; g < f.groups; g++ {
		for tor := 0; tor < f.tors; tor++ {
			for h := 0; h < f.hosts; h++ {
				f.timing.restarts[f.agentName(g, tor, h)] = simRestart{at: 61 + float64(n), down: 2}
				n++
			}
		}
	}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	requireOnly(t, stepAll(run, 12), "fleet restart", func(f Finding) bool {
		return f.State == StateNotLocalizable && f.Suspects[0].Component.Kind == ComponentBackground
	})
}

// TestLocalization_HostRebootNamesOnlyTheHost takes one host down for five
// minutes. While it is down it neither answers nor reports, which is all
// the localizer can know: it is reported as that host (or as its RNIC, on a
// fabric of one rail), never as its ToR or anything above. The finding is
// gone once the host is back.
func TestLocalization_HostRebootNamesOnlyTheHost(t *testing.T) {
	for _, rails := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d rails", rails), func(t *testing.T) {
			f := defaultSimFabric(9)
			f.rails = rails
			f.timing = agentTiming()
			agent := f.agentName(0, 1, 2)
			f.timing.restarts = map[string]simRestart{agent: {at: 70, down: 300}}
			run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
			byWindow := stepAll(run, 22)
			named := false
			requireOnly(t, byWindow, "host reboot", func(fd Finding) bool {
				for _, s := range fd.Suspects {
					c := s.Component
					if c.AgentID != agent || (c.Kind != ComponentHost && c.Kind != ComponentRNIC) {
						return false
					}
				}
				named = true
				return true
			})
			if !named {
				t.Error("a host that is down for five minutes was never reported")
			}
			if last, ok := byWindow[21]; ok {
				t.Errorf("findings long after the host is back:%s", describeFindings(last))
			}
		})
	}
}

// TestLocalization_RackOfSilentHostsIsNotLocalizedToItsToR takes every host
// of a rack down at once (maintenance, or a rack that loses power). Nothing
// under the ToR reports, so the evidence cannot tell the hosts from the ToR
// or its uplinks: the ToR may be among the candidates, but it is not
// reported as localized.
func TestLocalization_RackOfSilentHostsIsNotLocalizedToItsToR(t *testing.T) {
	f := defaultSimFabric(10)
	f.timing = agentTiming()
	f.timing.restarts = map[string]simRestart{}
	for h := 0; h < f.hosts; h++ {
		f.timing.restarts[f.agentName(1, 0, h)] = simRestart{at: 70, down: 300}
	}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	requireOnly(t, stepAll(run, 14), "rack down", func(fd Finding) bool {
		return fd.State != StateLocalized || fd.Suspects[0].Component.Kind == ComponentHost || fd.Suspects[0].Component.Kind == ComponentRNIC
	})
}

// TestLocalization_ToRRebootNamesTheToR takes one ToR down for three
// minutes while the agents under it keep reporting (over the management
// network): every path of the ToR fails in both directions. The ToR is the
// only component reported, and the finding clears after it is back.
func TestLocalization_ToRRebootNamesTheToR(t *testing.T) {
	f := defaultSimFabric(11)
	f.timing = agentTiming()
	fault := simFault{element: "tor", rail: 0, group: 1, tor: 2, loss: 1, fromSec: 75, untilSec: 255}
	f.faults = []simFault{fault}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	byWindow := stepAll(run, 18)
	named := false
	requireOnly(t, byWindow, "ToR reboot", func(fd Finding) bool {
		named = true
		return fd.State == StateLocalized && fd.Suspects[0].Component.identity() == f.truth(fault)
	})
	if !named {
		t.Error("a ToR that is down for three minutes was never reported")
	}
	if last, ok := byWindow[17]; ok {
		t.Errorf("findings long after the ToR is back:%s", describeFindings(last))
	}
}

// TestLocalization_ControllerRestart starts a second controller in the
// middle of a run, as after a restart: its evidence store is empty and its
// first windows are partial. With a healthy fabric it reports nothing; with
// a fault that lasts it reports that fault again, and nothing else, once
// three windows confirm it.
func TestLocalization_ControllerRestart(t *testing.T) {
	for _, faulty := range []bool{false, true} {
		t.Run(fmt.Sprintf("fault=%v", faulty), func(t *testing.T) {
			f := defaultSimFabric(12)
			f.timing = agentTiming()
			fault := simFault{element: "uplink", rail: 1, group: 0, tor: 1, member: 0, loss: 0.1}
			if faulty {
				f.faults = []simFault{fault}
			}
			loc := LocalizationConfig{Topology: f.topology(t, true, true)}
			first := newSimRun(t, f, loc)
			stepAll(first, 6)

			// The new controller sees the agents' reports from the middle of
			// window 6 on: of that window, only what arrives after its start.
			second := &simRun{t: t, fabric: f, az: New(simAnalyzerConfig(loc), nil), clock: first.clock, next: first.next}
			second.az.loc.now = second.clock.now
			half := 0
			for _, rep := range f.reports(second.next, f.window(second.next)) {
				if half++; half%2 == 0 {
					second.az.Ingest(t.Context(), rep)
				}
			}
			second.next++
			byWindow := map[int][]Finding{}
			if findings := second.evaluate(); len(findings) > 0 {
				byWindow[second.next-1] = findings
			}
			for w, findings := range stepAll(second, 8) {
				byWindow[second.next-8+w] = findings
			}
			if !faulty {
				requireNoneEver(t, byWindow, "healthy fabric after a controller restart")
				return
			}
			requireOnly(t, byWindow, "controller restart", func(fd Finding) bool {
				return fd.State == StateLocalized && fd.Suspects[0].Component.identity() == f.truth(fault)
			})
			if len(byWindow) == 0 {
				t.Error("the fault was not reported again after the controller restart")
			}
		})
	}
}

// TestLocalization_NewAgentIsNotAFault adds a host to a running fabric: it
// reports its own probes from the first moment, while the other agents
// learn of it only with their next pinglist. Nothing may be reported.
func TestLocalization_NewAgentIsNotAFault(t *testing.T) {
	f := defaultSimFabric(13)
	f.timing = agentTiming()
	// The host is "down" from before the first window until it joins: it
	// sends nothing, and nobody probes it before that (its paths as a
	// target lose their probes only if someone sends them).
	agent := f.agentName(0, 3, 1)
	f.silentFrom = map[string]int{}
	run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
	// Until window 4 the fabric runs without the host: nobody has it in a
	// pinglist, and it reports nothing.
	joined := 4
	kept := f.paths[:0]
	var later []simPath
	for _, p := range f.paths {
		if f.rnics[p.src].agent == agent || f.rnics[p.dst].agent == agent {
			later = append(later, p)
			continue
		}
		kept = append(kept, p)
	}
	f.paths = kept
	byWindow := stepAll(run, joined)
	// The host joins: its own probes start at once, the probes to it one
	// window later (the others' next pinglist).
	var inbound []simPath
	for _, p := range later {
		if f.rnics[p.src].agent == agent {
			f.paths = append(f.paths, p)
		} else {
			inbound = append(inbound, p)
		}
	}
	for w, findings := range stepAll(run, 1) {
		byWindow[joined+w] = findings
	}
	f.paths = append(f.paths, inbound...)
	for w, findings := range stepAll(run, 8) {
		byWindow[joined+1+w] = findings
	}
	requireNoneEver(t, byWindow, "a host joins")
}

// TestLocalization_OneBurstIsNotAFault_AcrossWindows drops half the packets
// of one ToR for a few seconds, at every phase of a window, with agents
// whose clocks agree and with half of them 15 s behind. The lost probes are
// reported 30 to 40 s later, around a window boundary or on both sides of
// it. One burst is not a fault, wherever the boundary falls.
func TestLocalization_OneBurstIsNotAFault_AcrossWindows(t *testing.T) {
	step := 3.0
	if raceDetector || testing.Short() {
		step = 10
	}
	for _, tc := range []struct {
		burst, skew float64
	}{
		{2, 0}, {5, 0}, {10, 0}, {20, 0},
		{2, 15}, {5, 15}, {10, 10},
	} {
		t.Run(fmt.Sprintf("%.0f s burst, clocks %.0f s apart", tc.burst, tc.skew), func(t *testing.T) {
			for at := 90.0; at < 120; at += step {
				f := defaultSimFabric(uint64(2000 + at))
				f.timing = agentTiming()
				f.faults = []simFault{{element: "tor", rail: 0, group: 1, tor: 2, loss: 0.5, fromSec: at, untilSec: at + tc.burst}}
				if tc.skew > 0 {
					f.timing.clockOffset = map[string]float64{}
					for g := 0; g < f.groups; g++ {
						for tor := 0; tor < f.tors; tor++ {
							for h := 0; h < f.hosts; h += 2 {
								f.timing.clockOffset[f.agentName(g, tor, h)] = -tc.skew
							}
						}
					}
				}
				run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
				requireNoneEver(t, stepAll(run, 12), fmt.Sprintf("burst at %.0f s", at))
			}
		})
	}
}

// TestLocalization_NarrowToRIsNotAccused runs one ToR on fewer uplinks than
// its siblings (a link is down, or the rack was built that way) while one
// spine of its group drops packets. The ToR sends a larger share of its
// paths through that spine, so its paths lose more than its siblings': the
// spine group holds the fault, and the ToR's uplinks, which are healthy,
// must not be reported as localized.
func TestLocalization_NarrowToRIsNotAccused(t *testing.T) {
	seeds := 8
	if raceDetector || testing.Short() {
		seeds = 2
	}
	for _, tc := range []struct {
		name    string
		uplinks []int
		spine   int
		loss    float64
	}{
		{"two of four uplinks, spine loses 1%", []int{0, 1}, 0, 0.01},
		{"two of four uplinks, spine loses 3%", []int{0, 1}, 0, 0.03},
		{"three of four uplinks, spine loses 3%", []int{0, 1, 2}, 0, 0.03},
		{"three of four uplinks, spine loses 10%", []int{0, 1, 2}, 0, 0.10},
		{"three of four uplinks, spine drops everything", []int{0, 1, 2}, 0, 1},
		{"one of four uplinks, spine loses 3%", []int{0}, 0, 0.03},
		{"two of four uplinks, not connected to the faulty spine", []int{0, 1}, 3, 0.03},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found := 0
			for seed := 0; seed < seeds; seed++ {
				f := defaultSimFabric(uint64(3000 + seed))
				f.tors, f.hosts = 6, 8
				f.uplinks = map[string][]int{f.torName(0, 1, 2): tc.uplinks}
				fault := simFault{element: "spine", rail: 0, group: 1, member: tc.spine, loss: tc.loss}
				f.faults = []simFault{fault}
				run := newSimRun(t, f, LocalizationConfig{Topology: f.topology(t, true, true)})
				findings := run.after(simWindows)
				for _, fd := range findings {
					if fd.State == StateLocalized && fd.Suspects[0].Component.identity() != f.truth(fault) {
						t.Fatalf("seed %d: a component other than the spine group is localized:%s", seed, describeFindings(findings))
					}
					if fd.State == StateLocalized {
						found++
					}
				}
			}
			if found < seeds*3/4 {
				t.Errorf("the spine group was localized in %d of %d runs", found, seeds)
			}
		})
	}
}

// TestLocalization_OneToRAndOneGroupAreNotLocalizable covers the smallest
// deployments. With one ToR every path is that ToR's, and with one spine
// group every path between ToRs is that group's: loss on all of them is as
// well a baseline that is set too low for the fabric as a fault of the ToR
// or the group. It is reported as not localizable. A fault below that
// level is still localized.
func TestLocalization_OneToRAndOneGroupAreNotLocalizable(t *testing.T) {
	kinds := func(findings []Finding) string {
		var out []string
		for _, f := range findings {
			out = append(out, f.State+" "+f.Suspects[0].Component.Kind)
		}
		return strings.Join(out, ", ")
	}
	for _, withTopology := range []bool{false, true} {
		topo := func(f *simFabric) *Topology {
			if !withTopology {
				return nil
			}
			return f.topology(t, true, true)
		}
		t.Run(fmt.Sprintf("one ToR, loss above the baseline, topology=%v", withTopology), func(t *testing.T) {
			f := defaultSimFabric(21)
			f.rails, f.groups, f.tors, f.hosts = 1, 1, 1, 16
			f.noiseLoss = 0.003
			run := newSimRun(t, f, LocalizationConfig{Topology: topo(f)})
			if got := kinds(run.after(simWindows)); got != "not_localizable background" {
				t.Errorf("findings: %s; want one not-localizable finding on the background", got)
			}
		})
		t.Run(fmt.Sprintf("one ToR, one lossy RNIC, topology=%v", withTopology), func(t *testing.T) {
			f := defaultSimFabric(22)
			f.rails, f.groups, f.tors, f.hosts = 1, 1, 1, 16
			fault := simFault{element: "rnic", host: 5, loss: 0.05}
			f.faults = []simFault{fault}
			run := newSimRun(t, f, LocalizationConfig{Topology: topo(f)})
			requireLocalized(t, run.after(simWindows), KindLoss, f.truth(fault))
		})
		t.Run(fmt.Sprintf("one spine group, a lossy spine, topology=%v", withTopology), func(t *testing.T) {
			f := defaultSimFabric(23)
			f.rails, f.groups = 1, 1
			f.faults = []simFault{{element: "spine", member: 1, loss: 0.05}}
			run := newSimRun(t, f, LocalizationConfig{Topology: topo(f)})
			if got := kinds(run.after(simWindows)); got != "not_localizable fabric" {
				t.Errorf("findings: %s; want one not-localizable finding on the fabric", got)
			}
		})
		t.Run(fmt.Sprintf("one spine group, a lossy ToR, topology=%v", withTopology), func(t *testing.T) {
			f := defaultSimFabric(24)
			f.rails, f.groups = 1, 1
			fault := simFault{element: "tor", tor: 2, loss: 0.03}
			f.faults = []simFault{fault}
			run := newSimRun(t, f, LocalizationConfig{Topology: topo(f)})
			requireLocalized(t, run.after(simWindows), KindLoss, f.truth(fault))
		})
	}
}
