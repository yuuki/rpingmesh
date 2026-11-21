package analyzer

import "math"

// This file tells loss in the network from an RNIC that does not answer.
//
// A probe from x to y is a round trip: the probe crosses the network from x
// to y, the ACKs cross it from y to x. A probe from y to x crosses the same
// components. A fault in the network between or next to the two RNICs (a
// link, a switch, an RNIC's port or cable) therefore loses probes in both
// directions: those sent to an RNIC and those the RNIC sends itself.
//
// Loss in one direction only has another cause. The probes sent to an RNIC
// fail, and the probes the RNIC sends succeed, when its responder does not
// answer: after an agent restart the responder has a new queue pair number,
// and every agent that probes the RNIC keeps sending to the old one until it
// refreshes its pinglist. Those probes are reported as lost 30 s later
// (the agents' ACK timeout), for 30 s to more than a minute, on every path
// to that host. This is no fault of the network, and a rack whose agents are
// restarted one after the other would otherwise look like a failing ToR.
//
// markUnanswering finds these RNICs so that the loss solver leaves the paths
// to them out: they are neither trials nor events. The paths from them stay.

// pathClass separates the paths under one ToR from those between ToRs. A
// fault can touch one class and spare the other (a ToR's uplinks carry no
// path under the ToR), so the two directions are compared within a class.
const (
	classMesh = iota
	classInter
	numClasses
)

// tally is the probes and lost probes of a set of paths.
type tally struct {
	probes, failed float64
}

func (t *tally) add(p *spanPath) {
	t.probes += float64(p.probes)
	t.failed += float64(min(p.failed, p.probes))
}

// excessNats returns the log-likelihood that the loss of t gains over the
// baseline rate when it is put at its observed rate, 0 when the observed
// rate is not above the baseline.
func (t tally) excessNats(baseline float64) float64 {
	expected := t.probes * baseline
	if t.failed <= expected || expected <= 0 {
		return 0
	}
	return t.failed*math.Log(t.failed/expected) - (t.failed - expected)
}

// verdict is what a set of paths says about an excess loss rate that other
// paths show.
type verdict int

const (
	// untestable: the paths were not probed often enough to tell.
	untestable verdict = iota
	// clear: the paths do not carry the excess.
	clear
	// carried: the paths carry the excess, or a good part of it.
	carried
)

// judge reports whether the paths of t carry the excess loss rate excess on
// top of the baseline. They are clear of it when their own excess is at
// most hintExcessShare of it and they were probed often enough that the
// full excess would have left hintNats of evidence more than is there. They
// are untestable when even no loss at all would not amount to that.
func (t tally) judge(baseline, excess float64) verdict {
	expected := t.probes * (baseline + excess)
	if expected < hintNats {
		return untestable
	}
	if t.failed > t.probes*(baseline+hintExcessShare*excess) {
		return carried
	}
	nats := expected - t.failed
	if t.failed > 0 {
		nats += t.failed * math.Log(t.failed/expected)
	}
	if nats < hintNats {
		return carried
	}
	return clear
}

// markUnanswering marks the RNICs of the span that lose the probes sent to
// them while the probes they send are delivered, and returns how many there
// are. The probes to an RNIC count as lost in a class of paths when their
// loss has at least hintNats of evidence above the baseline. In such a
// class, the loss is not the network's when
//
//   - the RNIC's own probes, to RNICs that are reached normally, are clear
//     of it; and
//   - the RNICs whose probes to it are lost are clear of it on their probes
//     to other RNICs that are reached normally.
//
// The first condition rules out a fault at or near the RNIC, which its own
// probes would cross. The second rules out a fault at or near the probers:
// their loss to this RNIC is then not about this RNIC. "Reached normally"
// leaves out every RNIC with lost inbound probes, so that RNICs that stopped
// answering at the same time (a rack restarted at once) do not vouch for or
// against each other.
//
// An RNIC is marked when this holds in at least one class and is
// contradicted in none: a class in which either set of probes carries the
// loss speaks for the network. A class without enough probes to tell says
// nothing (under a ToR whose agents all restarted, no RNIC is reached
// normally). An RNIC that sends no probes at all (its host is down, or its
// agent stopped) is therefore not marked: nothing tells its silence from a
// fault, and the solver names it or its host.
func (sp *span) markUnanswering(baseline float64) int {
	n := len(sp.rnics)
	if n == 0 || baseline <= 0 {
		return 0
	}
	class := func(p *spanPath) int {
		if sp.rnics[p.src].tor == sp.rnics[p.dst].tor {
			return classMesh
		}
		return classInter
	}

	// Loss of the probes sent to each RNIC.
	inbound := make([][numClasses]tally, n)
	for i := range sp.paths {
		p := &sp.paths[i]
		inbound[p.dst][class(p)].add(p)
	}
	var lossy [numClasses][]bool
	reached := make([]bool, n) // no class of inbound paths is lossy
	any := false
	for c := 0; c < numClasses; c++ {
		lossy[c] = make([]bool, n)
	}
	for r := 0; r < n; r++ {
		reached[r] = true
		for c := 0; c < numClasses; c++ {
			if inbound[r][c].excessNats(baseline) >= hintNats {
				lossy[c][r] = true
				reached[r] = false
				any = true
			}
		}
	}
	if !any {
		return 0
	}

	// Loss of each RNIC's own probes to the RNICs that are reached normally.
	own := make([][numClasses]tally, n)
	for i := range sp.paths {
		p := &sp.paths[i]
		if reached[p.dst] {
			own[p.src][class(p)].add(p)
		}
	}
	// The same, summed over the RNICs whose probes to an RNIC are lost.
	probers := make([][numClasses]tally, n)
	for i := range sp.paths {
		p := &sp.paths[i]
		if c := class(p); p.failed > 0 && lossy[c][p.dst] {
			probers[p.dst][c].probes += own[p.src][c].probes
			probers[p.dst][c].failed += own[p.src][c].failed
		}
	}

	marked := 0
	for r := 0; r < n; r++ {
		if reached[r] {
			continue
		}
		cleared, contradicted := false, false
		for c := 0; c < numClasses; c++ {
			if !lossy[c][r] {
				continue
			}
			in := inbound[r][c]
			excess := in.failed/in.probes - baseline
			a, b := own[r][c].judge(baseline, excess), probers[r][c].judge(baseline, excess)
			switch {
			case a == carried || b == carried:
				contradicted = true
			case a == clear && b == clear:
				cleared = true
			}
		}
		if cleared && !contradicted {
			sp.rnics[r].unanswering = true
			marked++
		}
	}
	return marked
}
