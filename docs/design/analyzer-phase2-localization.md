# Analyzer Phase 2: Topology-Aware Switch/Link Fault Localization

Status: design only, not implemented (tracking ID P3-H). It builds on the
Phase 1 analyzer merged in PR #36.

## Goals

- Turn the per-path SLA violations that Phase 1 detects into **fault
  localization**: name the ToR switch (and, once a fabric model exists, the
  link or spine) most likely responsible for a correlated set of degraded
  paths.
- Localize **across agents**. One agent sees only its own probes and cannot
  tell "my uplink is bad" from "the target ToR is bad". As in the SIGCOMM 2024
  R-Pingmesh paper, localization is a cross-agent intersection problem.
- Reuse the Phase 1 substrate: the in-memory window ring in
  `internal/controller/analyzer/analyzer.go`, the ToR-level OTLP convention,
  and the `PathSummary` proto.
- Keep metric output at **ToR granularity**. GID detail stays in findings logs.

## Non-Goals

- No new probing mechanism. No change to the 6-timestamp protocol or to the
  agent-side `PathAggregator` windowing.
- No localization finer than the topology supports. Today's registry is a flat
  RNIC→ToR map, so the achievable granularity is the **ToR switch and its
  adjacent links**. Per-link localization is specified but gated on a fabric
  model that does not exist yet (see
  [Advanced localization](#advanced-localization-set-cover-topology-gated)).
- No alerting or paging pipeline. Findings are structured logs and OTLP
  metrics.
- No historical query API. rqlite persistence is optional and additive.

## Current State (verified against code)

- **Phase 1 analyzer** (`internal/controller/analyzer/analyzer.go`).
  `Analyzer.Ingest` receives `ProbeAnalysisReport` batches, normalizes
  `source_tor_id`/`target_tor_id` with `probe.TorMetricLabel` (an empty ToR
  becomes `unspecified`), retains each summary in a ring of `windowBucket`s,
  and flags per-summary loss-ratio and p99-RTT violations in `evaluate`. The
  ring keeps the most recent `WindowRetention` windows
  (`analyzer_window_retention`, default 20) and at most
  `MaxSummariesPerWindow` summaries per window (default
  `DefaultMaxSummariesPerWindow` = 8192; not exposed as a controller config
  key). Excess summaries are dropped with a Debug log.
- **The ring does not record which agent sent a summary.** `agent_id` exists
  only on the `ProbeAnalysisReport` envelope, and `windowBucket.summaries` is a
  bare `[]*controller_agent.PathSummary`. The ring therefore cannot count
  distinct reporting agents, which is the cross-agent confidence signal.
  Closing this gap is a controller-internal change (see
  [Required retention change](#required-retention-change)).
- **Windows are shared across agents.** `PathAggregator.windowStart` floors
  the agent's wall-clock receive time to a multiple of the window length, and
  the ring is keyed and sorted by `window_start_unix_ns`. Summaries from
  different agents for the same real window land in the same bucket.
- **Reporting lag.** `AnalysisReporter` collects completed windows on a ticker
  of period `analysis_window_sec` (default 30 s) that is not aligned to window
  boundaries. A window therefore reaches the controller up to one window
  length plus RPC latency after it ends.
- **`PathSummary`** (`proto/controller_agent/controller_agent.proto`, fields
  1–15) carries `source_gid`, `source_tor_id`, `target_gid`, `target_tor_id`,
  `target_qpn`, window bounds, `probe_total`/`probe_success`/`probe_failed`,
  `invalid_rtt_count`, and RTT `min`/`max`/`p50`/`p99` in ns. The source ToR
  is the per-RNIC ToR stamped by the prober. RTT percentiles are agent-side
  estimates from the fixed ladder `rttBucketBoundariesNs` in
  `internal/probe/aggregator.go`; the bucket counts are not on the wire.
- **Topology.** The registry `rnics` table
  (`internal/controller/registry/registry.go`) has columns `rnic_gid, qpn,
  agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name,
  last_updated_epoch, plane_id`. The controller knows RNIC→ToR, ToR→RNICs, and
  each RNIC's plane (rail); inter-ToR pinglists stay within one plane. It knows
  nothing about aggregation or spine switches: there is no switch table, link
  table, or path→link mapping.
- **OTLP.** `analyzer/metrics.go` registers
  `rpingmesh.analyzer.path_summaries_total` and
  `rpingmesh.analyzer.sla_violations_total{network,source_tor,target_tor,kind}`.
  `setupAnalyzer` in `cmd/controller/main.go` creates the meter
  `rpingmesh.analyzer` on a provider tagged `service.name=rpingmesh-analyzer`
  and wires the analyzer with `svc.SetAnalyzer`. Phase 2 metrics register on
  the same meter.

Localization granularity is bounded by topology knowledge, and that knowledge
is ToR-flat today. The design therefore has a minimal pass that runs on
existing data and an advanced pass that requires a fabric model.

## Design

### Overview

A new **localizer** (`internal/controller/analyzer/localizer.go`) runs once
per **closed** window. It folds the window's summaries into ToR-pair edges,
scores suspect ToRs, and emits ranked findings as logs and OTLP gauges.

```
per-agent PathSummary (window W)
        │  (ingested and retained by Phase 1)
        ▼
window bucket W ──► Localize(W):
        1. fold summaries into ToR-pair edges (S_tor, T_tor)
        2. classify and score suspects (minimal heuristic)   [ships first]
        3. [gated] map edges to links, run set cover         [needs topology]
        4. rank, apply finding hysteresis, emit logs + OTLP
```

### Window close and late arrivals

Agents report a window asynchronously. A localizer that ran on every
`Ingest` call would see the first report for window W while most agents had
not reported yet. Edge totals, breadth fractions, and `agentsReporting` would
be under-counted, which produces spurious suspects and corrupts the
hysteresis state. The localizer therefore runs only on closed windows:

- A window with start `Ws` and duration `D` (from the summaries'
  `window_duration_ms`) ends at `We = Ws + D`. It closes at `We + grace`.
  Because of the reporting lag above, the default grace is one window plus a
  fixed margin (40 s for the default 30 s window).
- The analyzer tracks a monotonic **watermark**: the largest window start seen
  in any report. A window also closes once the watermark is at least two
  windows past `Ws`, so a busy cluster need not wait for the wall clock.
- A **sweeper** goroutine (period about one window) runs `Localize(W)` exactly
  once for the oldest closed, not-yet-localized window. `Ingest` stays a pure
  ingest/retain/SLA path. The sweeper needs Start/Stop wiring in
  `cmd/controller/main.go`; the Phase 1 analyzer has no goroutine today.
- **Late summaries** for an already-localized window are retained and still
  checked against the SLA, but they do not re-run localization. They increment
  `rpingmesh.analyzer.late_summaries_total` so `grace` can be tuned.
  Re-opening a window would make hysteresis order-dependent.

`WindowRetention` must exceed the number of windows that `grace` spans, or a
window can be evicted before it is localized. The sweeper logs a warning when
retention is too small for the configured grace.

### ToR-pair edge model

An **edge** is an ordered ToR pair `(S, T)`. For a closed window, every
summary with `(source_tor_id, target_tor_id) = (S, T)`, from any agent and any
GID, merges into one `EdgeStat`:

```
EdgeStat {
    S, T            string   // source ToR, target ToR
    probeTotal      uint64   // Σ probe_total
    probeFailed     uint64   // Σ probe_failed
    lossRatio       float64  // probeFailed / probeTotal
    rttP99Ns        uint64   // see "Cross-agent quantile synthesis"
    agentsReporting int      // distinct agent_id
    pathsReporting  int      // distinct (source_gid, target_gid)
    degraded        bool     // lossRatio > SLALossRatio OR rttP99Ns > SLANetworkRTTP99Ns
}
```

`S == T` is the **intra-ToR** edge (ToR-mesh probes). `S != T` is an
**inter-ToR** edge whose path crosses S's uplinks, one or more spine or
aggregation switches, and T's downlinks.

Edge folding uses the ToR IDs already on each summary, so it needs no registry
join. Summaries whose source or target ToR is `unspecified` cannot be
attributed to a switch and are excluded from localization. A read-only
registry snapshot (`TopologySnapshot()`, built from `ListAllRNICs`) is still
needed to tell a missing intra-ToR edge caused by a single-RNIC ToR from one
caused by missing reports.

The `degraded` flag reuses the Phase 1 thresholds (`Config.SLALossRatio`,
`Config.SLANetworkRTTP99Ns`), so an edge-level verdict agrees with the
per-path findings already logged.

#### Required retention change

`agentsReporting` cannot be computed from today's ring. The fix stays inside
the analyzer package: retain a wrapper instead of the bare summary.

```go
// Controller-internal; not a proto message.
type retainedSummary struct {
    AgentID string
    Summary *controller_agent.PathSummary
}
```

`windowBucket.summaries` becomes `[]*retainedSummary`, and `Ingest` passes
`report.GetAgentId()` to `retainLocked`. The wire messages do not change.

#### Per-window summary cap

The default cap of 8192 summaries per window is too small for large fleets:
1000 agents × 50 paths is 50,000 summaries per window. A capped window
silently under-counts edges. Phase 2 must expose the cap as a config key and
size it from the fleet, or count dropped summaries in a metric so a truncated
window is visible.

### Minimal localization: common-element heuristic

This pass runs on existing data. A shared fault degrades **every edge through
the faulty element** while edges that avoid it stay healthy. With only ToR
identity, a ToR takes part in three kinds of shared element:

- its **down side** (the switch and its host-facing links), exercised by every
  edge that targets the ToR and by its intra-ToR edge;
- its **up side** (uplinks to the spine), exercised by every inter-ToR edge
  that originates at the ToR;
- the **spine core** between two ToRs, exercised by one specific inter-ToR
  edge. Without a spine model this cannot be pinned on a single ToR.

For each ToR `X`:

```
inboundEdges(X)  = { (S,X) : S != X }
outboundEdges(X) = { (X,T) : T != X }
intra(X)         = EdgeStat(X,X)   (absent if X has fewer than 2 RNICs)

inFrac(X)   = degradedCount(inboundEdges(X))  / |inboundEdges(X)|
outFrac(X)  = degradedCount(outboundEdges(X)) / |outboundEdges(X)|
intraBad(X) = intra(X) present AND intra(X).degraded
```

Classification (thresholds come from config):

- **Down-side fault.** `inFrac(X) ≥ breadthFrac` and (`intraBad(X)` or intra
  absent). Traffic converging on X from many sources fails, and X's own mesh
  fails too, so the fault is local to X.
- **Up-side fault.** `outFrac(X) ≥ breadthFrac`, and the same target ToRs are
  mostly healthy when reached from other sources. Only traffic leaving X
  fails, so the fault is in X's uplinks.
- **Inter-ToR path fault.** A single `(S, T)` degrades while `outFrac(S)` and
  `inFrac(T)` are both low. This is reported as a path suspicion, not as a
  suspect ToR.

Score, used for ranking and for the hysteresis thresholds:

```
score(X) = ( w_breadth * max(inFrac(X), outFrac(X))
           + w_intra   * (intraBad(X) ? 1 : 0)
           + w_sev     * normalizedSeverity(X) )   // mean loss over degraded edges
           * confidence(X)                         // 1 - 1/(1 + agentsReporting)
```

`confidence` keeps a single agent's noise from opening a finding: a ToR seen
by only one agent gets a low multiplier even when its one edge is badly
degraded.

```text
function Localize(window):
    edges := buildEdgeStats(window.summaries)
    suspects := []
    for X in distinctToRs(edges):
        in, out, intra := inboundEdges(edges, X), outboundEdges(edges, X), intraEdge(edges, X)
        inFrac, outFrac := degradedFraction(in), degradedFraction(out)
        intraBad := intra != nil and intra.degraded

        kind := NONE
        if inFrac >= breadthFrac and (intraBad or intra == nil):
            kind := DOWNSIDE
        else if outFrac >= breadthFrac and targetsHealthyFromOthers(edges, out):
            kind := UPSIDE
        if kind != NONE:
            suspects.append(Suspect{
                tor: X, kind: kind,
                score: scoreOf(X, inFrac, outFrac, intraBad, in, out),
                confidence: 1 - 1/(1 + distinctAgents(in ∪ out)),
                evidence: summarize(in, out, intra),
            })

    pathSuspects := []
    for (S,T) in degradedInterTorEdges(edges):
        if outFrac(S) < breadthFrac and inFrac(T) < breadthFrac:
            pathSuspects.append(PathSuspect{S, T, edges[S,T]})

    return rank(suspects), pathSuspects
```

This heuristic is a **screening** localizer. It is reliable when a fault is
local to a ToR or to its uplinks and shows up as breadth. It does not claim
spine-core faults; it reports them as path suspicions. `breadthFrac`,
`confidence`, and hysteresis bound the false-positive rate.

### Advanced localization: set cover (topology-gated)

The paper treats each probe path as the set of links it traverses and looks
for the smallest set of components that covers all degraded paths and is
avoided by all healthy paths (a hitting-set problem, solved greedily):

```text
function LocalizeSetCover(window, fabric):
    suspectVotes := map[component]float64
    exonerated   := set[component]
    for path in window.paths:               # per (source_gid, target_gid, flow-label class)
        comps := fabric.componentsOn(path)
        if path.degraded:
            for c in comps: suspectVotes[c] += path.severity
        else:
            for c in comps: exonerated.add(c)
    candidates := { c : suspectVotes[c] > 0 and c not in exonerated }
    return greedyMinimalCover(candidates, degradedPaths)
```

This needs three things the system lacks:

1. **A fabric model**: switches and links as entities, with tiers.
2. **A path→component mapping**: which links a given (source RNIC, target
   RNIC, flow label) traverses. ECMP hashing is not invertible; the paper
   approximates it by covering many flow labels (the prober already rotates
   flow labels, sized by Eq. (1)) and by enumerating candidate links from the
   tiered topology.
3. **Flow-label identity in the summary.** `PathAggregator` keys on
   `(source GID, target GID)` and collapses all flow labels into one summary.
   Per-flow-label distinction needs a finer aggregation key or a separate
   reporting channel.

Build the minimal pass first. It delivers ToR-level localization, which is the
granularity the system may emit as metrics, without a schema migration. The
fabric model and set cover are a separate follow-up (P3-H.5).

### Cross-agent quantile synthesis

Per-agent p50/p99 values cannot be averaged into a ToR-pair percentile. Two
signals are available:

1. **Loss and the `degraded` flag** are exact: `probe_total` and
   `probe_failed` add across agents. This alone drives the minimal heuristic,
   whose primary signal is loss breadth, not tail latency.
2. **A merged RTT tail.** All agents share the fixed bucket ladder, so adding
   the bucket counts to `PathSummary` lets the controller sum them per ToR pair
   and compute an exact quantile at bucket resolution:

   ```proto
   repeated uint32 rtt_bucket_counts = 16;  // len(rttBucketBoundariesNs) + 1
   ```

Use option 1 for detection and option 2 for the emitted ToR-pair p99.

Do not adopt t-digest unless both hold: (a) the fixed bucket resolution is
too coarse for an SLO that operators actually set, and (b) operators need to
change RTT resolution per deployment without redeploying agents. Until then,
bucket-count summation is simpler, exact at bucket resolution, and reuses an
existing ladder. If t-digest is adopted later, its centroids replace the
bucket counts as the additive field.

### Optional rqlite persistence

Localization reads only the in-memory ring, so persistence is not required.
A new `path_summaries` table provides forensic retention and lets a future
standalone analyzer read history. It does not alter `rnics`.

```sql
CREATE TABLE IF NOT EXISTS path_summaries (
    window_start_unix_ns INTEGER NOT NULL,   -- aligned window start (join key across agents)
    agent_id             TEXT    NOT NULL,
    source_gid           TEXT    NOT NULL,
    source_tor_id        TEXT    NOT NULL,
    target_gid           TEXT    NOT NULL,
    target_tor_id        TEXT    NOT NULL,
    target_qpn           INTEGER NOT NULL,
    window_duration_ms   INTEGER NOT NULL,
    probe_total          INTEGER NOT NULL,
    probe_success        INTEGER NOT NULL,
    probe_failed         INTEGER NOT NULL,
    invalid_rtt_count    INTEGER NOT NULL,
    network_rtt_min_ns   INTEGER NOT NULL,
    network_rtt_max_ns   INTEGER NOT NULL,
    network_rtt_p50_ns   INTEGER NOT NULL,
    network_rtt_p99_ns   INTEGER NOT NULL,
    PRIMARY KEY (window_start_unix_ns, source_gid, target_gid)
);
CREATE INDEX IF NOT EXISTS idx_ps_window   ON path_summaries (window_start_unix_ns);
CREATE INDEX IF NOT EXISTS idx_ps_tor_pair ON path_summaries (source_tor_id, target_tor_id, window_start_unix_ns);
```

If field 16 is adopted, add an `rtt_bucket_counts TEXT` (JSON) column.

**Retention.** A periodic sweep in the style of `CleanupStaleEntries` deletes
rows older than `analyzer_persist_retention_sec` (default 6 h).

**Write rate.** `rows/s ≈ agents × pathsPerAgent / windowSec`; 1000 agents ×
50 paths / 30 s ≈ 1.7k rows/s. rqlite commits through Raft, so per-row inserts
are infeasible. Each `ProbeAnalysisReport` (at most 256 summaries,
`maxSummariesPerReport` in `internal/agent/analysis_reporter.go`) is written as
one multi-row parameterized transaction, about 7 transactions/s at that scale.
That is the largest new write load on rqlite, so persistence is off by default
(`analyzer_persist_enabled: false`).

### Output: ranking, OTLP, findings lifecycle

Each closed window yields a ranked list of
`Suspect{tor, kind, score, confidence, evidence}` and
`PathSuspect{S, T, ...}`. Ranking is a total order (ties broken by ToR ID) so
results are reproducible.

New instruments on the `rpingmesh.analyzer` meter (ToR granularity only):

| Metric | Type | Attributes | Meaning |
|--------|------|------------|---------|
| `rpingmesh.analyzer.suspect_tor` | Gauge (0/1) | `tor`, `kind` (`downside`/`upside`) | 1 while a ToR has an open finding |
| `rpingmesh.analyzer.suspect_tor_score` | Gauge | `tor`, `kind` | current score (0..1) of a suspected ToR |
| `rpingmesh.analyzer.inter_tor_path_suspect` | Gauge (0/1) | `source_tor`, `target_tor` | path suspicion not attributable to one ToR |
| `rpingmesh.analyzer.localization_runs_total` | Counter | none | closed windows processed |
| `rpingmesh.analyzer.late_summaries_total` | Counter | none | summaries that arrived after their window was localized |

No GID appears on a metric. GID-level evidence goes to findings logs, built
like `logFinding` in `analyzer.go`.

**Findings lifecycle.** Each `(tor, kind)` has a hysteresis state machine so
one noisy window neither opens nor closes a finding:

```
             score >= openThresh for K consecutive windows
   CLEARED ─────────────────────────────────────────────► OPEN
      ▲                                                     │
      │      score < closeThresh for M consecutive windows  │
      └─────────────────────────────────────────────────────┘
```

- **OPEN**: log a Warn finding with edge evidence and score, set
  `suspect_tor` to 1, and re-log at a throttled cadence while open.
- **CLEARED**: log the resolution and set the gauge to 0.
- `K`, `M`, `openThresh`, and `closeThresh` (`closeThresh < openThresh`) come
  from config. The state lives in the `Analyzer` under its existing mutex.

### Config additions (controller)

```yaml
analyzer_localization_enabled: true
analyzer_loc_grace_sec: 40            # window-close grace; >= agent analysis_window_sec + margin
analyzer_loc_breadth_frac: 0.6        # fraction of degraded edges that makes a side "broad"
analyzer_loc_open_score: 0.6          # score that opens a finding
analyzer_loc_close_score: 0.3         # score that clears it (hysteresis)
analyzer_loc_open_windows: 2          # K
analyzer_loc_close_windows: 3         # M
analyzer_max_summaries_per_window: 8192  # exposes Config.MaxSummariesPerWindow
analyzer_persist_enabled: false       # optional rqlite persistence
analyzer_persist_retention_sec: 21600 # 6 h; used only when persistence is on
```

## Alternatives Considered

- **Localize on the agent.** Rejected: an agent sees only its own RNICs and
  cannot separate its uplink from the target ToR. Localization must run where
  all agents' data meets.
- **Localize in the OTel collector.** Rejected: the collector has neither the
  topology nor the cross-agent join, and doing it there would work against the
  ToR-only cardinality design.
- **Average per-agent p99s.** Rejected as statistically invalid. Loss
  summation drives detection; bucket-count summation produces the tail.
- **Adopt t-digest now.** Rejected for the first round; see the criterion in
  [Cross-agent quantile synthesis](#cross-agent-quantile-synthesis).
- **Build the full set-cover localizer now.** Rejected as premature: it needs
  a fabric model, a path→link mapping, and per-flow-label summaries, none of
  which exist.
- **Persist every summary and localize from SQL.** Rejected: localization
  needs only recent windows, which are already in memory, and per-summary
  writes do not fit Raft's per-commit cost.

## Test Plan

Phase 2 logic is pure Go over retained summaries and a registry snapshot, so
it is deterministic and testable without RDMA, like the Phase 1 tests in
`internal/controller/analyzer/analyzer_test.go`.

- **Topology fixtures.** Small clusters (for example 4 ToRs × N RNICs) with
  hand-built summaries per fault scenario:
  - A, down-side fault: all inbound edges to X degraded from at least 3 source
    ToRs, and intra-X degraded. Expect X with `kind=downside` and no other
    suspect.
  - B, up-side fault: all outbound edges from Y degraded while the same
    targets are healthy from other sources. Expect Y with `kind=upside`.
  - C, spine path: one `(S, T)` degraded; S→others and others→T healthy.
    Expect no `suspect_tor` and one `inter_tor_path_suspect`.
  - D, noise: low loss below thresholds. Expect no suspects.
  - E, single-agent noise: one agent reports a badly degraded edge to X.
    Expect `confidence` to keep X below `openThresh`.
- **Cross-agent aggregation.** Two agents reporting the same window and ToR
  pair fold into one `EdgeStat` with summed totals and an exact loss ratio
  (and, with field 16, an exact merged p99).
- **Window close and late arrival.** With an injected clock (a `nowFn` seam
  like `AnalysisReporter.nowFn`): a window is localized exactly once, only
  after it closes; reports arriving before close do not trigger localization;
  the single run sees the full `agentsReporting`. A report after localization
  increments `late_summaries_total` and changes no finding.
- **Unspecified ToR.** Summaries with an `unspecified` ToR never produce a
  suspect.
- **Findings lifecycle.** K windows above `openThresh` open a finding (gauge
  1); M windows below `closeThresh` clear it (gauge 0); a single dip does not
  clear it.
- **Metric cardinality.** `suspect_tor` and `suspect_tor_score` carry only
  `tor` and `kind`. The analyzer has no metric tests yet; use an SDK
  `ManualReader` as `internal/telemetry/otel_metrics_test.go` does.
- **Persistence** (only if built): multi-row insert and retention sweep
  against the registry's `fakeConn` (`registry_test.go`); one transaction per
  report.
- **e2e (RDMA-free).** Extend `e2e/controller/analysis_e2e_test.go`: a
  pseudo-agent posts Scenario A as several agents. That stack runs no OTLP
  collector, so the test needs an observable signal for an opened finding (see
  [Open Questions](#open-questions)).

## Implementation Plan (PR breakdown)

Each PR is independently mergeable. Work that needs no schema change comes
first.

1. **P3-H.1: retention change, edge model, minimal localizer.** Retain
   `retainedSummary` (agent ID + summary) in the ring. Add `localizer.go` with
   `EdgeStat`, edge folding, the common-element heuristic, and ranking. Add
   the window-close sweeper with the watermark, the late-summary counter,
   `analyzer_loc_grace_sec`, the retention-vs-grace check, and a configurable
   per-window cap. Add `TopologySnapshot()` to the registry. Findings are
   logged only. Scenarios A–E as unit tests (E exercises the distinct-agent
   count).
2. **P3-H.2: findings lifecycle and OTLP.** Hysteresis state machine, the
   `suspect_tor`, `suspect_tor_score`, `inter_tor_path_suspect`, and
   `localization_runs_total` instruments, and their config keys. Lifecycle and
   cardinality tests; controller e2e test.
3. **P3-H.3: exact cross-agent tail.** Add `rtt_bucket_counts = 16` to
   `PathSummary`; expose the buckets from `pathAccumulator` and populate the
   field in `AnalysisReporter.toProto`. The controller sums buckets per ToR
   pair. Old agents omit the field; the controller then falls back to
   loss-only detection and `max(p99)`.
4. **P3-H.4 (optional): rqlite persistence.** `path_summaries` table, batched
   insert on ingest, retention sweep, all behind `analyzer_persist_enabled`.
5. **P3-H.5 (separate track): fabric model and set cover.** Switch and link
   tables, a path→component mapping, per-flow-label summary identity, and the
   set-cover localizer. Start only after H.1–H.3 prove out, only if per-link
   granularity is required, and only with an operator-provided topology.

## Open Questions

- **Topology source for set cover.** Agents cannot discover spine and
  aggregation switches. Should the fabric model come from an operator file,
  an LLDP/SNMP feed, or controller config? This gates P3-H.5. *(User input
  needed.)*
- **Is ToR granularity enough?** If ToR-level suspects satisfy the on-call
  workflow, H.5 may never be needed. *(User input needed.)*
- **Persistence target.** At about 1.7k rows/s for 1000 agents, rqlite
  persistence stays off by default. If forensic history is a hard requirement,
  an external TSDB or OLAP sink may fit better. *(User input needed.)*
- **e2e signal for an opened finding.** The controller e2e stack has no OTLP
  collector. `ProbeAnalysisAck` carries only `accepted` and `sla_violations`,
  and it is returned before the window closes, so it cannot report a
  localization result. Options: run a collector in that stack, assert on
  controller logs, or add a diagnostic RPC.
- **Threshold defaults.** `breadthFrac` and the score thresholds are first
  guesses; tune them against a real cluster's noise floor before trusting
  auto-opened findings.
- **Clock sync.** Window alignment assumes agent clocks are roughly
  synchronized. Large skew scatters one real window across adjacent buckets
  and weakens the intersection. Is NTP-level sync safe to assume?
