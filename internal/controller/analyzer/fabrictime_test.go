package analyzer

import (
	"math"
	"sort"
)

// simTiming makes the simulated agents behave over time as the shipped
// agents do. Without it a probe is reported in the window in which it was
// sent, which hides everything that matters about an agent restart, a short
// burst or a clock that is off:
//
//   - A probe that gets no ACK is reported as lost when the agent's sweep
//     finds it older than the ACK timeout (30 s, sweep every 10 s), in the
//     window of that moment, not of the moment it was sent.
//   - An agent that restarts answers on a new queue pair. The agents that
//     probe it keep sending to the old one, and lose every probe, until
//     they refresh their pinglist: after three timeouts in a row to the
//     target, at most once per 30 s, and only once the restarted agent has
//     registered again.
//   - A restarted agent sends nothing while it is down, and what it had in
//     flight is never reported.
//   - Each agent stamps its windows with its own clock.
//
// Times are seconds since the start of window 0.
type simTiming struct {
	ackTimeout      float64
	sweep           float64
	minEarlyRefresh float64
	// restarts holds the restart of an agent: the moment it stops and how
	// long it stays down.
	restarts map[string]simRestart
	// clockOffset is added to an agent's clock.
	clockOffset map[string]float64

	sweepPhase map[string]float64 // per agent, drawn on first use
	sent       int                // windows whose probes have been sent
	acc        map[int]map[int]*simAcc
}

type simRestart struct {
	at, down float64
}

// simAcc collects what one path reports for one window.
type simAcc struct {
	total, failed uint32
	rtts          []uint64
}

// agentTiming returns the timing of the shipped agents.
func agentTiming() *simTiming {
	return &simTiming{ackTimeout: 30, sweep: 10, minEarlyRefresh: 30}
}

// nextSweep returns the first sweep of the agent at or after t.
func (f *simFabric) nextSweep(agent string, t float64) float64 {
	tm := f.timing
	if tm.sweepPhase == nil {
		tm.sweepPhase = make(map[string]float64)
	}
	phase, ok := tm.sweepPhase[agent]
	if !ok {
		phase = f.rng.Float64() * tm.sweep
		tm.sweepPhase[agent] = phase
	}
	return phase + math.Ceil((t-phase)/tm.sweep)*tm.sweep
}

// staleUntil returns the moment from which the prober reaches a target
// whose agent restarted again: its first pinglist refresh after the target
// registered its new queue pair. interval is the time between two probes of
// the path.
func (f *simFabric) staleUntil(prober string, r simRestart, interval float64) float64 {
	tm := f.timing
	// The third probe after the restart times out at the sweep that finds
	// it older than the ACK timeout; the prober then asks for a refresh.
	refresh := f.nextSweep(prober, r.at+2*interval+tm.ackTimeout)
	for refresh < r.at+r.down {
		refresh += tm.minEarlyRefresh
	}
	return refresh
}

// timedWindow returns the summaries the agents stamp with window w. The
// probes of the windows up to w+1 are sent first: a probe sent in window w
// can be reported in w+1 or w+2 (a timeout), and one sent in w+1 in w (a
// slow clock).
func (f *simFabric) timedWindow(w int) []simSummary {
	tm := f.timing
	if tm.acc == nil {
		tm.acc = make(map[int]map[int]*simAcc)
	}
	for ; tm.sent <= w+1; tm.sent++ {
		f.sendWindow(tm.sent)
	}
	paths := tm.acc[w]
	delete(tm.acc, w)
	idx := make([]int, 0, len(paths))
	for i := range paths {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	out := make([]simSummary, 0, len(idx))
	for _, i := range idx {
		acc := paths[i]
		s := simSummary{path: &f.paths[i], total: acc.total, failed: acc.failed}
		if rtts := acc.rtts; len(rtts) > 0 {
			sort.Slice(rtts, func(a, b int) bool { return rtts[a] < rtts[b] })
			s.min, s.max = rtts[0], rtts[len(rtts)-1]
			s.p50 = rtts[simRank(0.50, len(rtts))]
			s.p99 = rtts[simRank(0.99, len(rtts))]
		}
		out = append(out, s)
	}
	return out
}

// sendWindow sends the probes of window sw and files each result under the
// window in which its agent reports it.
func (f *simFabric) sendWindow(sw int) {
	tm := f.timing
	windowSec := float64(f.windowNs) / 1e9
	for i := range f.paths {
		p := &f.paths[i]
		a, b := &f.rnics[p.src], &f.rnics[p.dst]
		probes := f.interProbes
		baseRTT := uint64(20_000)
		if p.mesh {
			probes, baseRTT = f.meshProbes, 8_000
		}
		interval := windowSec / float64(probes)
		own, restarts := tm.restarts[a.agent]
		peer, peerRestarts := tm.restarts[b.agent]
		// stale: until when the prober sends to the peer's old queue pair.
		// staleAfterOwn: the same for the probes it sends after its own
		// restart, which begins with a new pinglist. That one holds the
		// peer's new queue pair when the peer was back by then.
		stale, staleAfterOwn := math.Inf(-1), math.Inf(-1)
		if peerRestarts {
			stale = f.staleUntil(a.agent, peer, interval)
			if started := own.at + own.down; restarts && started > peer.at {
				staleAfterOwn = started
				if back := peer.at + peer.down; started < back {
					staleAfterOwn = f.staleUntil(a.agent, simRestart{at: started, down: back - started}, interval)
				}
			}
		}
		for n := 0; n < probes; n++ {
			t := (float64(sw) + (float64(n)+0.5)/float64(probes)) * windowSec
			label := p.cursor
			p.cursor = (p.cursor + 1) % f.flowLabels
			if restarts && t >= own.at && t < own.at+own.down {
				continue // the prober is down
			}
			var fwd, rev simHop
			if !p.mesh {
				fwd, rev = p.fwd[label], p.rev[label]
			}
			survive := 1 - f.noiseLoss
			rtt := baseRTT + uint64(f.rng.IntN(2_000))
			for fi := 0; fi < len(f.faults)+len(f.bursts); fi++ {
				var fault *simFault
				if fi < len(f.faults) {
					fault = &f.faults[fi]
					if wf, limited := f.windowFaults[fi]; limited && !wf[sw] {
						continue
					}
				} else {
					fault = &f.bursts[fi-len(f.faults)]
				}
				if (fault.fromSec != 0 || fault.untilSec != 0) && (t < fault.fromSec || t >= fault.untilSec) {
					continue
				}
				if c := f.crossings(fault, a, b, p.mesh, fwd) + f.crossings(fault, b, a, p.mesh, rev); c > 0 {
					survive *= math.Pow(1-fault.loss, float64(c))
					rtt += uint64(c) * fault.delayNs
				}
			}
			lost := f.rng.Float64() >= survive
			// The target's responder does not answer: its agent is down, or
			// the prober still sends to the queue pair of before the restart.
			if peerRestarts && t >= peer.at {
				until := stale
				if restarts && t >= own.at+own.down && staleAfterOwn > math.Inf(-1) {
					until = staleAfterOwn
				}
				if t < until {
					lost = true
				}
			}
			reported := t
			if lost {
				reported = f.nextSweep(a.agent, t+tm.ackTimeout)
			}
			// What an agent has in flight when it stops is never reported.
			if restarts && t < own.at && reported >= own.at {
				continue
			}
			rw := int(math.Floor((reported + tm.clockOffset[a.agent]) / windowSec))
			if rw < 0 {
				continue
			}
			window := tm.acc[rw]
			if window == nil {
				window = make(map[int]*simAcc)
				tm.acc[rw] = window
			}
			acc := window[i]
			if acc == nil {
				acc = &simAcc{}
				window[i] = acc
			}
			acc.total++
			if lost {
				acc.failed++
				continue
			}
			if f.rng.Float64() < f.noiseRTT {
				rtt = 2 * simRTTThresholdNs
			}
			acc.rtts = append(acc.rtts, rtt)
		}
	}
}
