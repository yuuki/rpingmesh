# Analyzer Phase 2: Topology-Aware Fault Localization

Status: implemented and opt-in (`analyzer_localization_enabled`, issue #145).
It is validated against a simulated fabric only; no run on real hardware has
been made. [Limitations](#limitations) lists what it cannot tell apart and
[Not implemented](#not-implemented) what is left out.

This document replaces an earlier draft that proposed a ToR-level
heuristic. [Differences from the earlier draft](#differences-from-the-earlier-draft)
records what changed and why.

## Goals

- Turn correlated path degradation into **fault localization**: name the
  component the degraded paths share. The classes are those of issue #145:
  a single RNIC or host, one ToR's uplinks (a lossy ECMP member), and a spine
  or rail-wide degradation.
- Find **gray failures**. One of *m* uplinks that drops 1–5% of its packets
  adds a fraction of a percent to each path through it. That is far below
  the 2% per-path loss SLO of Phase 1, so no single path ever reports it.
- **Never accuse the wrong component.** Silence and "cannot tell" are
  acceptable answers; a confident wrong answer is not.
- Change nothing for deployments that do not enable it: no new metric, no
  new work in `Ingest`, the same Phase 1 results.

## Non-Goals

- No new probing mechanism and no change to the wire format, the gRPC API,
  the registry schema or the agents.
- No identification of *which* ECMP member is faulty. The controller does
  not know a switch's ECMP hash; see [What a flow label can tell](#what-a-flow-label-can-tell).
- No alerting pipeline, no history. Findings are logs and gauges over the
  current evidence.

## What the controller knows

Checked against the code, because the inference can only be as good as its
inputs.

- **A `PathSummary` is one (source RNIC, target RNIC, pinglist type) per
  window.** It carries both GIDs, both ToR IDs, `probe_total`,
  `probe_failed`, and the RTT `min`/`max`/`p50`/`p99` of the window
  (`proto/controller_agent/controller_agent.proto`, fields 1–16). The agent
  ID is on the report envelope.
- **It carries no flow label.** `probe.PathAggregator` keys on the GID pair
  and the pinglist type; the flow labels a target is probed with (Eq. (1),
  64 with the default `ecmp_max_flow_labels`) are collapsed into one
  summary.
- **It carries no traffic class.** `traffic_class` is one setting per agent
  and is not reported.
- **It carries no rail.** The registry stores a plane per RNIC, but a summary
  does not, and the analyzer does not read the registry.
- **Probe counts are small.** At the shipped rates a ToR-mesh path gets 2
  probes/s and an inter-ToR path 1 probe/s: 60 and 30 probes per 30 s window.
  An inter-ToR path therefore sends less than one probe per flow label and
  window.
- **Each RNIC probes few other ToRs.** An inter-ToR pinglist samples
  `inter_tor_sample_size` (5) ToRs of the RNIC's plane, one RNIC each, and is
  refreshed every `pinglist_update_interval_sec` (300 s).
- **Nothing above the ToR is known.** A ToR ID comes from the agent
  (`tor_id`, `device_tor_ids`, or LLDP on the host, which sees the leaf
  only). There is no switch table, no link table, and no way for an agent to
  discover a spine. `scripts/topology/` derives ToR IDs and, for
  rail-optimized fabrics, rails; it does not know spines either.
- **Windows are shared.** Agents align windows to multiples of the window
  length on their wall clocks, so the summaries of one real window carry the
  same `window_start_unix_ns`. An agent reports a window up to one window
  length after it ends.

## What can be told apart

A fault is visible only through the set of paths it degrades. With the
inputs above:

| Fault | Paths it degrades | Reported as | Needs |
|-------|-------------------|-------------|-------|
| One RNIC, its cable or switch port | every path that starts or ends at the RNIC | `rnic` | ToR IDs |
| A host (all of its RNICs) | every path of any of its RNICs | `host` | at least two of its RNICs observed, and reports from its agent in the last 15 minutes |
| A ToR switch | every path that starts or ends under it, also those that stay under it | `tor` | ToR IDs |
| One or all uplinks of a ToR | every path between it and another ToR, not those that stay under it | `tor_uplink` | ToR IDs |
| One or all spines of a spine group | every path between two ToRs that touches the group | `spine_group` | topology file with `spine_group` |
| The tier above a rail's spine groups (or above its ToRs, when it has no spine groups) | every path that crosses that tier | `rail` | topology file with `rail` |

What cannot be told apart, by construction:

- **A member of an ECMP stage from the stage.** One lossy uplink of four and
  four uplinks each a quarter as lossy degrade the same paths by the same
  amount. The finding names the stage (`tor_uplink`, `spine_group`, `rail`)
  and its excess loss per probe; it never names a link or a spine.
- **Components with the same observed paths.** A ToR with one observed RNIC
  (RNIC, ToR and uplinks are the same paths), a ToR whose agents do not
  report (ToR and uplinks), a spine group with two ToRs (both uplink sets and
  the group). They are reported together as `ambiguous`, each with its share
  of the confidence.
- **A fault above the ToRs from its ToRs, without topology facts.** The
  degraded ToRs are reported as members of the `fabric`, as
  `not_localizable`.
- **A tier the topology file leaves out.** With rails but no spine groups in
  the file, a fault in one pod's spines is reported on the rail.

## Design

### Overview

```
ReportProbeAnalysis ─► Analyzer.Ingest ─► Phase 1 (unchanged)
                                │
                                └► evidence store: per window and path
                                   (probes, lost, RTT window over threshold)
                                                │  every 5 s, if the span changed
                                                ▼
              closed windows (the last analyzer_localization_windows)
                                                │  copy under the lock
                                                ▼
        pool per path ─► join topology facts ─► tomography (loss, then RTT)
                                                │
                                                ▼
                 findings ─► logs on change, gauges while they last
```

Files, all in `internal/controller/analyzer/`: `topology.go` (the topology
file), `evidence.go` (the store), `tomography.go` (the inference, a pure
function), `findings.go` (what is reported, and the folding of siblings),
`localizer.go` (windows, lifecycle, logs), `metrics.go` (the instruments).

### Topology facts

The file named by `analyzer_localization_topology_file` states, per ToR, the
two facts the summaries lack:

```yaml
version: 1
tors:
  leaf-a1-r0: {rail: rail0, spine_group: pod-a-r0}
  leaf-a1-r1: {rail: rail1}
```

- `spine_group`: the set of spines the ToR's uplinks connect to. Two ToRs of
  one group are joined by exactly one of its spines.
- `rail`: the set of ToRs that reach each other through one upper tier.
- Both are optional per ToR. A ToR that is not listed, or listed without
  either, has no stated tier above it.

Decisions:

- **Operator-supplied, because nothing else knows it.** LLDP on the host
  names the leaf only (and was not usable on the fabrics of
  [`multi-rail-tor-mapping.md`](multi-rail-tor-mapping.md)); agents see no
  spine. The registry's `plane_id` is close to a rail but is an agent setting
  meant for pinglists, is empty on fully connected fabrics, and says nothing
  about spine groups. Reading it would also tie the analyzer to the database.
  `scripts/topology/build_device_tor_map.py --format topology` writes the
  ToRs and rails of a rail-optimized fabric from collected RNIC facts, with
  the same ToR IDs as `device_tor_ids`; spine groups are added by hand.
- **Membership, not adjacency.** The file does not list spines, links or
  ECMP widths. The model only needs to know which paths cross which tier,
  and a list of switches would suggest that a spine can be named.
- **Strict.** Unknown keys, an unknown `version`, a ToR listed twice and a
  spine group whose ToRs state different rails are errors, and the controller
  does not start. A typo that silently dropped a fact would make the
  localizer name the wrong tier. Names are text: `rail: 0` is the rail "0".
- **Bounded and linear.** At most 8 MiB and 100 000 ToRs, names of at most
  255 bytes without control characters. The document is walked as a YAML node
  tree: decoding into a Go map makes the YAML library compare every pair of
  keys for duplicates, which took 56 s for 100 000 ToRs.
- **Read once at startup**, like the TLS files and the bearer token.
  Re-cabling needs a controller restart.

### Evidence

`Ingest` hands each summary of the cluster network to the evidence store
after Phase 1 has processed it. The store keeps, per window and path, four
values: probes, lost probes, whether the window had a valid RTT, and whether
its p99 exceeded `analyzer_slo_network_rtt_p99_ns`.

- **Its own store, not the Phase 1 ring.** The ring retains whole
  `PathSummary` messages under a cap of 8192 per window, sized for SLO
  detection. Localization needs every path of a window and 12 bytes of each.
- **Left out:** summaries of traced service flows (they are sampled along
  application flows and the paper evaluates them per path), summaries with an
  `unspecified` ToR or without a GID (they cannot be attributed), and windows
  without probes.
- **Interned per window.** GIDs and ToR IDs are replaced by indexes into
  per-window tables, so a window is released as a whole and no table grows
  with RNIC churn.
- **The agent of each source RNIC** is remembered for 15 minutes, longer than
  the span: a host that went down stops reporting, and its RNICs must still
  form one `host` component while others probe them (until the registry drops
  them from pinglists after `active_threshold_sec`).

**Closed windows.** A window `[start, start+D)` is closed when the
controller's clock passes `start + 2D + 10 s`: agents collect a window on a
ticker of period `D` that is not aligned to the boundary, so a window arrives
up to `D` after it ends, plus the RPC. Only closed windows are evaluated. A
summary that arrives later still counts in the next evaluation while its
window is in the span.

**Evidence span.** An evaluation pools the closed windows that ended within
the last `analyzer_localization_windows` window lengths (default 4, two
minutes). The span slides by one window. It is empty when the newest closed
window ended more than three window lengths (and 10 s) ago, so findings do
not outlive their evidence when agents stop reporting.

**One window length.** Agents are meant to share one `analysis_window_sec`.
When they do not (one misconfigured agent, or a new value being rolled out),
windows of different lengths are kept apart, the span is built from the
length that holds the most paths, and windows of other lengths are the first
to be evicted. A minority can therefore neither blur nor push out the
majority's evidence; its own paths are left out, which is logged.

**Evaluation.** A goroutine (`Analyzer.RunLocalization`) checks every 5 s
whether the span changed (other windows, or new summaries in them) and
evaluates only then. It holds the store's lock only while it copies the
span's windows (25 ms for 1.3 million path records); pooling and solving run
on the copy. Findings are a function of the current span and nothing else:
there is no finding state to go stale.

### Components

For each path, the components it crosses follow from the ToRs of its two
RNICs and the topology facts:

- both RNICs, and their hosts;
- the ToR of each RNIC;
- when the ToRs differ: each ToR's uplinks, and the tier directly above each
  ToR (its spine group, or its rail when it states no spine group);
- the rail above a spine group, when the path leaves the group. That is
  known only when the peer ToR's facts are stated; otherwise the path counts
  neither for nor against the rail;
- `fabric`: every path between two ToRs; `background`: every path.

`fabric` and `background` are catch-alls and are only ever reported as
`not_localizable`. `fabric` takes an excess that all paths between ToRs
share and the facts do not divide. `background` takes an excess on every
path: the baseline is too low for this fabric, or all of it is degraded. The
other components are then judged against the observed background, so a
baseline set too low yields one finding, not one per ToR.

### Model

A path yields *n* trials and *k* events: probes and lost probes, or windows
with a valid RTT and windows whose p99 exceeded the threshold. Events are
modelled as

```
k ~ Poisson( n × (baseline + Σ excess of the faulty components on the path) )
```

- **Counts, not per-path verdicts.** A path with 1 lost probe of 120 says
  almost nothing alone. Four hundred such paths through one ToR's uplinks
  say a lot. Summing probes and losses over a component's paths is what makes
  a 0.3% loss visible, and a per-path SLO flag would discard it.
- **Poisson** is the small-rate form of independent drops along a path, and
  it makes the excess rates additive. Its one useful property here: a path
  without events enters a component's likelihood only through its trials, so
  the solver works on the paths with events (few in a healthy fabric) and a
  sum of trials per component.
- **An ECMP stage is one component with a diluted rate.** A member that
  drops *f* of its packets among *m* equal-cost members adds about *2f/m* to
  each path through the stage (the probe and its ACK each cross it once),
  because a path's flow labels spread over the members.
- **Exoneration is built in.** A component's gain is
  `Σ k·ln(1 + θ/rate) − N·θ` over its paths with events and its *N* trials
  in total. Every probe that crossed the component and was not lost counts
  against it.

**Baseline.** `analyzer_localization_baseline_loss_ratio` (default 0.001) is
the loss of a healthy path. The RTT baseline is fixed at 1% of windows over
the threshold: a window over the threshold is already an SLO violation, so a
fabric above that needs a different threshold.

### What a flow label can tell

Issue #145 proposes to group by flow label. This implementation does not,
for two reasons.

1. *The data is not there.* A summary pools the labels of a path. Carrying
   them would need a `PathSummary` field and agent changes.
2. *They would add no power against gray failures.* A label identifies one
   path among several, not which one. The mapping from label to ECMP member
   differs per RNIC pair, so labels cannot be pooled across paths. Within a
   path, an inter-ToR label gets less than one probe per window. To see that
   one label loses 2% takes on the order of 150 probes on that label, i.e.
   about 9600 probes on the path or 2.7 hours at 1 probe/s. The pooled count
   per path already holds what the labels can say at these rates.

Labels would help for a black-holed member (the same labels fail every
time). There the path loss is 1/*m* and the stage is found within two
windows anyway; the labels would add "deterministic per flow" to the finding,
not a different suspect.

### Inference

`tomography.go`, per signal:

1. **Greedy.** Fit every component's maximum-likelihood excess on top of the
   current rates (Newton's method on a concave function) and add the one
   with the largest gain, until none gains the detection threshold (below).
   For one fault with the rest of the fabric at or below the baseline, the
   component that covers exactly the degraded paths has the largest gain: a
   broader one is diluted by clean trials, a narrower one explains fewer
   events.
2. **Refit.** Re-estimate the selected components' rates jointly by
   coordinate ascent until they settle, and drop those that no longer gain
   the threshold. The likelihood is concave in the rates, so this converges
   to the joint maximum.
3. **Split.** For each selected composite component, remove it and let the
   greedy explain its events with up to 8 other components. Keep the
   replacement when its likelihood exceeds the component's by more than the
   prior each extra component costs (the difference is first divided by the
   component's [dispersion](#dispersion): with over-dispersed counts, several
   components always fit better than one). Four lossy RNICs under a ToR whose
   other two RNICs are clean gain more as "the ToR" than any one of them, so
   the greedy alone would accuse the ToR.
4. **Refit** again, then compute confidences.

A component is part of the explanation whenever it gains the threshold, also
when the [evidence rules](#evidence-rules) forbid naming it. One stuck path
explains itself and is not reported. If it were left unexplained, its events
would be put down to a bystander that shares the path.

### Confidence

**Definition.** For a component of the explanation, every component that
shares one of its paths with events is fitted in its place. With the prior
odds `e^-14` for a fault in any one component during one span, and the
likelihood gains *g*, the posterior probability of alternative *c* is

```
confidence(c) = e^(g_c − 14) / (1 + Σ over alternatives e^(g − 14))
```

where the `1` stands for "no fault in this place". The confidence of a
suspect is the probability that it, and not another component or none, is
the cause of these events, given the model and equal priors.

**Finding.** The alternatives are taken in order of confidence until their
confidences sum to `analyzer_localization_min_confidence` (default 0.95):
the smallest set that holds the cause with that probability.

- one component: `localized`;
- several: `ambiguous`, each listed with its confidence (at most 8);
- all of them together below the minimum: no finding. "No fault" keeps too
  much of the probability.

**Detection threshold.** A component alone reaches the minimum confidence
when its gain is `14 + ln(c/(1−c))`: 16.9 nats at 0.95. A component with *N*
trials and a true excess *θ* over the baseline *ε* gains on average
`N·((ε+θ)·ln(1+θ/ε) − θ)`. With the default baseline and 20 000 probes per
span on a component (a ToR's uplinks with 16 RNICs), an excess of about 0.16%
is found half of the time and 0.25% almost always.

**Prior.** 14 nats is about one in 1.2 million. Under the model a healthy
component at exactly the baseline exceeds the threshold with a probability
of about 3·10⁻⁹ per evaluation, which keeps a fabric of 10⁴ components
evaluated every 30 s below one false finding in ten days at that worst case,
and far below when the fabric loses less than the baseline. All components
have the same prior: nothing in the inputs says that RNICs fail more often
than spines.

**Calibration.** The confidence is a statement under the model. The random
sweep of the tests checks it against the simulated fabric: the findings that
hold no fault must not be more than the findings' own confidences allow (see
[Validation](#validation)).

### Evidence rules

A component is named only when, in addition to the confidence:

| Rule | Reason |
|------|--------|
| its events are on at least 3 distinct RNIC pairs | one pair can fail for reasons of its own, such as a stale QPN after an agent restart; both directions of a pair count once |
| a composite component's events touch at least 2 of its members (a ToR's RNICs, a spine group's ToRs), when it has 2 or more observed | a ToR is not accused on one RNIC's evidence |
| its events are in at least 2 windows, and no window holds more than 75% of them | one burst is not a fault; a fault that has just begun is reported once a second window confirms it |
| the configured span is what counts, not the windows present | a controller that has just started does not report on its first window |

The persistence rules are off when `analyzer_localization_windows` is 1.

There is no minimum of probes per path. The likelihood weighs each path by
its probes, so a path with 30 probes simply counts for less than one with
300.

### Dispersion

The model holds that a component adds the same excess to all of its paths.
Two situations break that:

- a bystander: three paths of a host fail because their other end is a
  faulty RNIC that few others probe, while the host's twenty other paths are
  clean;
- few flow labels per path: with one label, a path crosses the faulty spine
  or it does not, so a group's paths are hit fully or not at all, and a ToR
  whose paths are hit more often than average shows an excess of its own.

Both show as over-dispersion: the Pearson statistic per path of a
component, 1 for Poisson counts. The gain of every alternative for a place is
divided by the larger of the selected component's own dispersion and the
dispersion of the other selected components covering its events (a
quasi-likelihood). More evidence is asked for exactly where the model fits
worse. One divisor per place keeps the alternatives comparable.

### Siblings

The solver explains each degraded member on its own when the model has no
component that covers them together. That happens when the facts are missing
or coarser than the fabric. Findings that point at ToRs (their switches or
uplinks) under one scope, at spine groups under one rail, or at rails are
therefore counted per scope and folded into one `not_localizable` finding on
the scope, which lists the members:

- more than 2 members: three ToRs under one spine group degraded at once
  are far more likely to share an undescribed cause than to have failed
  independently;
- members that no finding names but that show at least 7 nats of evidence
  and a comparable excess count too. A fault that siblings share is strongest
  in one of them by chance;
- any member, when the scope is itself in the explanation with a dispersion
  above 2. The scope's excess is then too uneven for the model, and what is
  left on a member is that unevenness;
- for ToRs without stated facts, whose scope is the `fabric`: two ToRs'
  uplinks at once, and a single ToR's uplinks unless a fault above it would
  have left at least 21 nats on every other such ToR. Their silence proves
  something only then.

The confidence of a folded finding is the largest confidence that one of
the folded findings put on its candidates together: the scope holds a fault
at least as surely as its surest member. When the scope is already a finding
of its own, it takes the members and no second finding is made.

Findings on RNICs and hosts are never folded: several hosts of a rack can
fail independently (a maintenance), and each is worth its own finding.

### RTT signal

The same solver runs on a second signal: per path, windows with a valid RTT
as trials and windows whose p99 exceeded `analyzer_slo_network_rtt_p99_ns` as
events. It finds a component that delays without dropping. It is off when
that threshold is 0, like the Phase 1 RTT check. With fewer than 100 probes
per window the agent's p99 is the window's maximum, so one delayed probe
marks the window.

### Output

**Logs.** One line at `warn` when a finding appears and one at `info` when it
clears; a finding is identified by its signal, state and candidates.
`component=localizer`, snake_case fields like the analyzer's: `kind`,
`state`, `component`, `tor`, `spine_group`, `rail`, `gid`, `agent_id`,
`confidence`, `excess_ratio`, `evidence_nats`, `paths`, `failed_paths`,
`trials`, `events`, `windows`, and `candidates` or `members` where they
apply. The GID of a suspected RNIC and the agent of a suspected RNIC or host
appear here and nowhere else.

Three conditions that make findings coarser are logged at `warn` when they
change: ToRs that report paths but have no facts in the topology file (the
first 8 IDs and their number), paths left out because a window reached
`analyzer_localization_max_paths_per_window`, and agents that report windows
of another length than most. Every evaluation is logged at `debug` with its
size and duration.

**Metrics**, on the analyzer's meter, registered only when localization is
enabled:

| Metric | Type | Attributes |
|--------|------|-----------|
| `rpingmesh.analyzer.localization_suspects` | Gauge | `kind`, `state`, `component`, `tor`, `spine_group`, `rail` |
| `rpingmesh.analyzer.localization_suspect_confidence` | Gauge | the same |
| `rpingmesh.analyzer.localization_runs_total` | Counter | none |
| `rpingmesh.analyzer.localization_dropped_paths_total` | Counter | none |

Cardinality of each attribute:

| Attribute | Values | Bound |
|-----------|--------|-------|
| `kind` | `loss`, `rtt` | 2 |
| `state` | `localized`, `ambiguous`, `not_localizable` | 3 |
| `component` | `rnic`, `host`, `tor`, `tor_uplink`, `spine_group`, `rail`, `fabric`, `background` | 8 |
| `tor` | the ToR of an `rnic`, `tor` or `tor_uplink` suspect | the ToRs that report |
| `spine_group` | the group of a `spine_group` suspect, or of the suspect's ToR | the groups in the topology file |
| `rail` | the rail of a `rail` or `spine_group` suspect, or of the suspect's ToR | the rails in the topology file |

`spine_group` and `rail` are functions of `tor` on the suspects that carry
one, so they add no series. A suspected RNIC is counted under its ToR, a
suspected host under `component="host"` alone; no GID, host name or agent ID
is ever an attribute. The gauges are observed from the current findings, so
a series ends when its finding clears. At any time a gauge has at most 256
series (2 signals × 16 findings × 8 candidates); over time at most
2 × 3 × (3T + G + R + 3) for T ToRs, G spine groups and R rails.

Two suspects can share an attribute set (two RNICs under one ToR):
`localization_suspects` is their number and
`localization_suspect_confidence` the highest of their confidences.

### Configuration

| Key | Default | |
|-----|---------|-|
| `analyzer_localization_enabled` | `false` | |
| `analyzer_localization_topology_file` | `""` | |
| `analyzer_localization_windows` | `4` | 1 to 64 |
| `analyzer_localization_baseline_loss_ratio` | `0.001` | in (0, 1) |
| `analyzer_localization_min_confidence` | `0.95` | in [0.5, 1) |
| `analyzer_localization_max_paths_per_window` | `200000` | at least 1 |

**Opt-in**, for three reasons: an upgraded controller must export and log
what it did before; the engine has only been validated in simulation; and it
costs memory and CPU in proportion to the fleet. The other constants (the
prior, the evidence rules, the sibling limits) are not settings. Each would
be a contract, and none has a value an operator could choose without the
measurements that are still missing.

### Bounds

For *P* paths in the span, *F* of them with events, and *C* components
(RNICs + hosts + 2 × ToRs + spine groups + rails + 2):

- **Memory, store:** about 55 bytes per path and retained window (measured:
  68.5 MB for four windows of 327 643 paths). A window keeps at most
  `analyzer_localization_max_paths_per_window` paths; more are dropped and
  counted. At most `windows + 6` windows are retained, and windows that
  start more than one window ahead of the controller's clock or are too old
  for a span are refused. The agent table holds at most 262 144 RNICs.
- **Memory, evaluation:** O(P) for the copy and the span, O(C + 14·F) for the
  solver (a path crosses at most 14 components).
- **Time:** O(14·P) to sum each component's trials, then O(F) per fit of a
  component with *F* paths with events. The greedy fits again only the
  components that share a path with the one it selected. One evaluation adds
  at most 48 components to an explanation, searches at most 8 replacements
  per split, refits for at most 30 rounds, and reports at most 16 findings of
  at most 8 candidates per signal.

Benchmarks (`BenchmarkLocalize`, `BenchmarkSnapshot`, `BenchmarkBuildSpan`,
`BenchmarkEvidenceObserve`) on a fabric of 1024 ToRs and 16 384 RNICs with
327 643 paths per window and a span of four windows. They ran on a 4-core
x86-64 machine shared with other builds (load average 16 to 30), where
repeated runs differ by a factor of two to three; the table gives the
fastest of three:

| Step | Time |
|------|------|
| Ingest of one summary (the localizer's share) | 0.5 µs |
| Copy of the span under the lock | 25 ms |
| Pooling the span | 220 ms |
| Solving, healthy fabric | 16 ms |
| Solving, one lossy spine | 29 ms |
| Solving, 32 RNICs, 8 ToR uplinks and 2 spine groups at once | 115 ms |
| Solving, every path lossy (the worst case for the solver) | 0.7 s, 74 MB |

## Validation

`fabricsim_test.go` simulates a rail-optimized Clos fabric: rails of spine
groups of ToRs, hosts with one RNIC per rail, ToR-mesh and inter-ToR
pinglists as the controller builds them, 64 flow labels per path, and an
ECMP hash per (path, direction, label) that the localizer is not told.
Faults are injected into physical elements: one RNIC, one host, one ToR, one
ToR-to-spine link, one spine, one core switch, each with a drop probability
or a delay. Every probe and its ACK are drawn separately, so counts carry
binomial noise. The summaries go through `Analyzer.Ingest`, windows close on
an injected clock, and the findings are compared with the injected faults.
All runs are seeded.

`localization_sim_test.go` covers:

- each fault class, loss and RTT, down to a 1% loss on one of four uplinks;
- a healthy fabric: 20 seeds × 9 spans at a background loss of 10%, 50% and
  100% of the baseline, with no finding;
- a whole fabric at 1.5, 2 and 5 times the baseline: only the
  `background`, as `not_localizable`;
- no topology file and a file with rails only;
- two faults at once; four lossy RNICs under one ToR;
- a host that goes down and stops reporting, with and without an earlier
  report from its agent;
- components that cannot be told apart, with their confidences (1/3 each,
  1/2 each);
- one burst, one stuck path, the lifecycle of a fault over time;
- one flow label per path.

**Random sweep** (`TestLocalization_RandomFaultsAreNeverMisattributed`): 12
variants (full facts, rails only, no file, 30% and 70% of the agents silent,
two and three faults at once, a small fabric with 4 flow labels, one flow
label, one spine group, three small spine groups, background loss at the
baseline), each with random faults of a loss between 0.5% and 50%. It
requires that:

- no finding with a confidence of 0.999 or more points at components
  without a fault;
- the findings that do are no more than the findings themselves allow for.
  A finding with a confidence of 0.97 claims to be wrong 3 times in 100; the
  claims are summed, and the misses may exceed the sum by three standard
  deviations at most;
- every `not_localizable` finding names a scope that holds a fault;
- each variant localizes at least a stated share of its faults, so that
  silence cannot pass for accuracy.

The default run is 40 scenarios per variant (10 with the race detector).
Four larger runs with other seeds, 400 scenarios per variant each
(`RPINGMESH_SIM_SCENARIOS=400 RPINGMESH_SIM_SEED=<n>` with the seeds 99,
2026, 31337 and 424242), gave, over 19 200 scenarios and 24 000 faults:

| | |
|-|-|
| Faults named by a `localized` finding | 21 639 (90.2%) |
| `ambiguous` findings that hold a fault | 172 |
| `not_localizable` findings on a scope that holds a fault | 514 |
| Findings with a confidence of 0.999 or more that hold no fault | 0 |
| Findings that hold no fault | 1 |
| Misses that the findings' confidences claimed | 7.1 |

The one miss: with a background loss equal to the baseline, a core switch
that lost 0.6% was reported as one of its rail's two spine groups with a
confidence of 0.971. In a rail of two spine groups every path that crosses
the core also touches that group, so the two differ only by the paths inside
the group, and noise on those tipped the balance. The findings claimed seven
times more misses than occurred, so the confidences err on the cautious side
in this simulator.

By variant, the share of the faults that were localized ranged from 97–99%
(full facts, and background loss at the baseline) down to 76–80% (70%
of the agents silent), 77–83% (the small fabric, and the single spine group)
and 63–68% (no topology file, where faults above the ToRs cannot be
localized). The rest were too weak to tell from noise, or reported as
ambiguous or not localizable.

The solver was developed against this simulator, and three of the four
seeds above were also run while its last rules were written: findings
without a fault in earlier runs of the seeds 99, 2026 and 31337 are what led
to the hinted siblings, the scope dispersion limit and the rule for ToRs
without facts. Only the seed 424242 was run once, after the solver was
final (4800 scenarios, no finding without a fault, 1.9 claimed). A simulator
also shares its author's assumptions: independent drops per packet, uniform
ECMP hashing, no correlated bursts beyond those injected.

`tomography_test.go` checks the fit against its closed form, the components
of a path for every combination of facts, each evidence rule, and that the
result does not depend on the order of arrival. `FuzzLocalize` and
`FuzzLocalizerIngest` run the solver and the ingest path on arbitrary
evidence and reports; `FuzzParseTopology` the parser.

## Limitations

- **Simulation only.** Nothing here has run against a real fabric. The
  defaults (baseline, prior, sibling limits) are reasoned, not measured.
- **ToR IDs are required.** RNICs without a ToR (`unspecified`) are left
  out; a fleet without ToR IDs yields no findings.
- **One controller must see all reports.** Evidence is in memory and not
  shared. Behind a load balancer each controller sees a part and finds less.
  A restart loses the evidence; findings need two windows again.
- **Clocks and windows.** Agents must agree on the window (the same
  `analysis_window_sec`, clocks within a window of each other and of the
  controller). Windows more than one window ahead of the controller's clock
  are refused, and the paths of agents with another window length than most
  are left out.
- **Facts are trusted.** A ToR placed in the wrong spine group yields wrong
  findings. A tier that the file leaves out is reported on the tier above
  it, or, for a weak fault, can show as a single member of that tier.
- **Weak faults above ToRs without facts** are reported as
  `not_localizable` with the ToR as a member, also when the fault is in that
  ToR's uplinks: the other ToRs carry too little evidence to clear the tier
  above.
- **Correlated loss is not modelled.** Loss in bursts carries less
  information per lost probe than the model assumes. The persistence rule and
  the dispersion discount limit the effect; they do not remove it.
- **Three or more faults that share paths** (a spine and a core switch of
  one rail, with two spine groups) can leave a finding that is `ambiguous`
  where a single fault would be `localized`.
- **Hosts are known from their own reports.** A host whose agent never
  reported is seen RNIC by RNIC.
- **At most 16 findings per signal.** A rack losing power is 16 host
  findings and a count of none of the rest.

## Not implemented

- **Flow-label and traffic-class identity** in `PathSummary` (see
  [What a flow label can tell](#what-a-flow-label-can-tell)). A later change
  could add per-label counts of the labels with losses, which would mark a
  black-holed member as such.
- **Dashboards and alert rules** for the new metrics. `make obs-verify`
  checks every dashboard query and rule against a seeded metrics stack in
  Docker, which was not available when this was written; a panel or rule
  that was never run through it would be worse than none.
  `sum by (kind, component, tor, spine_group, rail) (rpingmesh_analyzer_localization_suspects{state="localized"})`
  is the query to start from.
- **The controller e2e suite** (`e2e/controller`) is not extended; it also
  needs Docker.
- **Exact cross-agent RTT tails.** The RTT signal uses each path's own p99.
  Summing histogram buckets per ToR pair needs a `PathSummary` field.
- **Persistence and history** of findings or evidence.
- **Reloading** the topology file without a restart.
- **The registry's planes** as a source of rails.
- **Packaging** of the example topology file.

## Differences from the earlier draft

The earlier draft of this document proposed a ToR-level heuristic (the share
of a ToR's degraded edges), a score with weights, hysteresis over windows,
and left the fabric model for later. What changed:

| Earlier draft | Now | Why |
|---------------|-----|-----|
| Edges are degraded by the Phase 1 SLO (2% loss) | Probes and losses are summed per component | a lossy ECMP member stays below the SLO on every path |
| `breadthFrac`, `w_breadth`, `w_intra`, `w_sev` | a likelihood with one prior | the weights had no meaning an operator could reason about |
| `confidence = 1 − 1/(1 + agents)` | a posterior probability among alternatives | it said how many agents reported, not how likely the suspect is |
| ToR granularity; fabric model later | RNIC to rail, with an optional topology file | issue #145 asks for spine and rail |
| Sweeper with a watermark; each window localized exactly once | Clock-based closing; a sliding span, re-evaluated when it changes | late summaries are simply counted next time; no order dependence to guard |
| Hysteresis state machine (K windows to open, M to clear) | Persistence inside the span, no state | the result is a function of the evidence and can be reproduced from it |
| `retainedSummary` in the Phase 1 ring; the cap as a setting | A separate store with its own cap | the ring stays as it is; Phase 1 is untouched |
| `rtt_bucket_counts`, a `path_summaries` table | not built | they need a wire or schema change and are not needed to localize |

## Alternatives considered

- **Greedy set cover over degraded paths** (the common choice for Boolean
  tomography). Rejected: it needs a per-path verdict, which gray failures do
  not produce, and it has no notion of how sure it is.
- **Exact maximum-likelihood search** over sets of components. Rejected:
  exponential in the number of faults. The greedy with refit and split
  reaches the same answer on every simulated case and is bounded.
- **A robust estimate of the baseline** (a trimmed mean over RNICs).
  Rejected: a rail-wide fault would raise it and hide itself. The
  `background` component does the same job and reports that it did.
- **Reporting components individually without folding.** Rejected: with
  facts missing, a spine fault became as many confident ToR findings as it
  has ToRs.
- **A structural prior** (RNICs fail more often than spines). Rejected: a
  guess that would decide ties.
- **Localizing on the agent or in the collector.** Rejected in the earlier
  draft, for reasons that still hold: neither sees all agents.
