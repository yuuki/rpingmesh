# Analyzer Phase 2 — Topology-Aware Switch/Link Fault Localization

Status: Design only (P3-H). No implementation is proposed here; this document
specifies what a later implementation round will build on top of the Phase 1
analyzer merged in PR #36.

## Goals

- Turn the per-path SLA violations produced by Phase 1 into **actionable fault
  localization**: identify the specific ToR switch (and, as a topology-gated
  extension, the specific fabric link/spine) most likely responsible for a
  correlated set of degraded paths.
- Do this **across agents**: a single agent only sees its own probes and cannot
  tell "my uplink is bad" from "the target ToR is bad". Localization is
  inherently a cross-agent intersection problem, exactly as in the SIGCOMM 2024
  R-Pingmesh paper.
- Reuse the Phase 1 substrate unchanged where possible: the in-memory window
  ring in `internal/controller/analyzer/analyzer.go`, the ToR-granularity OTLP
  convention, and the `PathSummary` proto.
- Keep all metric output at **ToR granularity** (`source_tor` / `target_tor` /
  `suspect_tor`), consistent with the project-wide cardinality rule. GID detail
  stays in findings logs only.

## Non-Goals

- No new probing mechanism, no change to the 6-timestamp protocol or the
  agent-side `PathAggregator` windowing.
- No claim to localize below the granularity the available topology supports.
  With today's registry (a flat GID→ToR map) the achievable granularity is the
  **ToR switch and its adjacent link tier**. Per-spine / per-link localization
  is specified but explicitly gated on a topology model that does not exist yet
  (see "Topology extension").
- No real-time alerting/paging pipeline. Findings are emitted as structured logs
  and OTLP metrics; downstream alerting is out of scope.
- No historical/forensic query API. rqlite persistence is specified as an
  optional, additive capability, not a query surface.

## Current State (verified against code)

- **Phase 1 analyzer** (`internal/controller/analyzer/analyzer.go`): ingests
  `ProbeAnalysisReport` batches via `Analyzer.Ingest`, retains the most recent
  `WindowRetention` (default 20, `DefaultAnalyzerWindowRetention`) windows in an
  in-memory ring of `windowBucket{windowStartUnixNs, summaries}`, and flags
  per-summary SLA violations in `evaluate` (loss ratio and p99 RTT). It already
  keeps every summary of the retained windows around — the comment on
  `windowBucket` explicitly calls this "the substrate a future Phase 2
  cross-agent localization pass would read." Phase 2 is that pass.
- **Retention ring** is keyed and sorted by `windowStartUnixNs`. Because agent
  windows are wall-clock aligned (`PathAggregator.windowStart` floors to
  multiples of `windowNs`), summaries from different agents for the same real
  window land in the **same bucket** — this is what makes cross-agent
  intersection possible without extra bookkeeping.
- **`PathSummary`** (`proto/controller_agent/controller_agent.proto`) carries
  `source_gid`, `source_tor_id`, `target_gid`, `target_tor_id`, `target_qpn`,
  window bounds, `probe_total/success/failed`, `invalid_rtt_count`, and RTT
  `min/max/p50/p99` in ns. RTT percentiles are agent-side estimates from a fixed
  bucket ladder (`rttBucketBoundariesNs` in `internal/probe/aggregator.go`); the
  raw bucket histogram is **not** currently on the wire.
- **Topology source of truth** is the `rnics` table
  (`internal/controller/registry/registry.go`): columns `rnic_gid, qpn,
  agent_id, agent_ip, rnic_ip, tor_id, hostname, device_name,
  last_updated_epoch`. The controller therefore knows **GID→ToR** and
  **ToR→{GIDs}** for active RNICs, and nothing about the aggregation/spine tier:
  there is no switch table, no link table, no path→link mapping.
- **OTLP**: `analyzer/metrics.go` exposes `rpingmesh.analyzer.path_summaries_total`
  and `rpingmesh.analyzer.sla_violations_total{source_tor,target_tor,kind}`. The
  P1 design reserved `rpingmesh.analyzer.suspect_tor` for Phase 2.
- **Controller metrics wiring**: `cmd/controller/main.go setupAnalyzer` builds a
  `service.name=rpingmesh-analyzer` meter provider and calls `analyzer.New(...)`
  + `svc.SetAnalyzer(az)`. Phase 2 metrics register on the same meter.

The decisive consequence of the current state: **localization granularity is
bounded by topology knowledge, and today that knowledge is ToR-flat.** The
design below is split into a minimal pass that ships on the existing data and an
advanced pass that is correct only once a fabric model is added.

## Design

### Overview

Phase 2 adds a **localizer** that runs after each window is complete, reads the
retained window buckets, aggregates per-path summaries up to **ToR-pair**
granularity, applies a fault-localization pass, and emits ranked suspect ToRs
(and, when topology permits, suspect links) as findings + OTLP gauges. It is a
new file `internal/controller/analyzer/localizer.go` in the existing package;
`Analyzer` gains a post-window hook that invokes it.

```
per-agent PathSummary (window W)
        │  (already ingested + retained by Phase 1)
        ▼
window bucket W  ──► Localizer.Localize(W):
        1. join summaries with registry topology (GID→ToR)   [already known]
        2. fold to ToR-pair edges: loss/degraded per (S_tor,T_tor)
        3. classify + score suspects (minimal heuristic)      [ships now]
        4. [gated] map edges→links, run set-cover             [needs topology]
        5. rank, apply finding hysteresis, emit logs+OTLP
```

### Step 1–2: ToR-pair edge model

Define an **edge** as an ordered ToR pair `(S, T)`. For a completed window,
merge every summary whose `(source_tor_id, target_tor_id) = (S, T)` — possibly
from many agents and many GIDs — into an `EdgeStat`:

```
EdgeStat {
    S, T            string          // source ToR, target ToR
    probeTotal      uint64          // Σ probe_total
    probeFailed     uint64          // Σ probe_failed
    lossRatio       float64         // probeFailed / probeTotal
    rttP99Ns        uint64          // see "Cross-agent quantile synthesis"
    agentsReporting int             // distinct agent_id contributing
    pathsReporting  int             // distinct (source_gid,target_gid) contributing
    degraded        bool            // lossRatio > lossThresh OR rttP99Ns > rttThresh
}
```

`S == T` is the **intra-ToR** edge (ToR-mesh probes stay inside one ToR).
`S != T` is an **inter-ToR** edge whose physical path traverses S's uplinks, one
or more spine/agg switches, and T's downlinks.

Degradation reuses the Phase 1 thresholds (`Config.SLALossRatio`,
`Config.SLANetworkRTTP99Ns`) so a window "degraded" at the edge level is
consistent with the per-path violations already logged.

### Step 3: Minimal localization — common-element heuristic (ships on current data)

Intuition from the paper, reduced to what a ToR-flat topology can justify: a
shared fabric fault makes **all edges through the faulty element** degrade
together while edges avoiding it stay healthy. With only ToR identity we can
reason about three shared elements a ToR participates in:

- its **down side** (ToR↔host links + the ToR switch itself), exercised by every
  edge with that ToR as target and by its intra-ToR edge;
- its **up side** (ToR↔spine uplinks), exercised by every inter-ToR edge with
  that ToR as source;
- the **spine core** between two ToRs, exercised only by that specific inter-ToR
  edge (not attributable to a single ToR without a spine model).

For each ToR `X` over the set of edges in the window, compute:

```
inboundEdges(X)   = { (S,X) : S != X, EdgeStat exists }
outboundEdges(X)  = { (X,T) : T != X, EdgeStat exists }
intra(X)          = EdgeStat(X,X)  (may be absent if X has <2 RNICs)

inFrac(X)   = degradedCount(inboundEdges(X))  / |inboundEdges(X)|
outFrac(X)  = degradedCount(outboundEdges(X)) / |outboundEdges(X)|
intraBad(X) = intra(X) != nil AND intra(X).degraded
```

Classification and suspicion score (all thresholds config-driven):

- **DownSide/ToR fault** — `X` suspected when `inFrac(X) ≥ breadthFrac` AND
  (`intraBad(X)` OR intra absent). Rationale: nearly everything converging on
  `X` from distinct sources fails, and `X`'s own mesh fails too → the fault is
  local to `X` (switch or its host-facing links), not any one source's uplink.
- **UpSide fault** — `X` suspected when `outFrac(X) ≥ breadthFrac` AND those
  target ToRs are **healthy when reached from other sources** (i.e. their
  inbound-from-others is mostly healthy). Rationale: only traffic *originating*
  at `X` is bad → `X`'s uplinks/egress.
- **Spine/inter-ToR path fault** — a specific `(S,T)` degrades while
  `outFrac(S)` and `inFrac(T)` are both low (S→others and others→T are healthy).
  Not attributable to a single ToR; emitted as an inter-ToR *path* suspicion,
  not a `suspect_tor` gauge.

Suspicion score for ranking (monotone in breadth, evidence volume, and severity):

```
score(X) = w_breadth * max(inFrac(X), outFrac(X))
         + w_intra   * (intraBad(X) ? 1 : 0)
         + w_sev     * normalizedSeverity(X)      // mean loss over degraded edges
   weighted-down by low evidence:
         * confidence(X)                          // = 1 - 1/(1+agentsReporting)
```

`confidence` guards against declaring a suspect from a single agent's noise: a
ToR reached by only one agent gets a low multiplier even if that one edge is
badly degraded. This is the cross-agent requirement made explicit.

Pseudocode:

```text
function Localize(window):
    edges := buildEdgeStats(window.summaries, registrySnapshot)   # Step 1-2
    tors  := distinctToRs(edges)
    suspects := []
    for X in tors:
        in  := inboundEdges(edges, X)
        out := outboundEdges(edges, X)
        intra := intraEdge(edges, X)
        inFrac  := degradedFraction(in)
        outFrac := degradedFraction(out)
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
                confidence: 1 - 1/(1+distinctAgents(in ∪ out)),
                evidence: summarize(in, out, intra),
            })

    pathSuspects := []
    for (S,T) in degradedInterTorEdges(edges):
        if outFrac(S) < breadthFrac and inFrac(T) < breadthFrac:
            pathSuspects.append(PathSuspect{S, T, edges[S,T]})

    return rank(suspects), pathSuspects
```

Correctness envelope (stated honestly): this heuristic is a **screening**
localizer. It is right when faults are ToR-local or ToR-egress-local and shows
up as breadth; it deliberately refuses to over-claim on spine-core faults,
reporting them as path suspicions instead. False positives are bounded by
`breadthFrac`, `confidence`, and the finding hysteresis below.

### Advanced localization — set cover / hitting set (topology-gated)

The paper's precise localization treats each probe path as a *set of traversed
links* and finds the minimal set of components that **covers all degraded paths
while being avoided by all healthy paths** (a hitting-set / set-cover
formulation, in practice a greedy vote):

```text
function LocalizeSetCover(window, fabric):
    # fabric: switches (ToR/Agg/Spine) + links + path model
    suspectVotes := map[component]float64
    exonerated   := set[component]
    for path in window.paths:               # per (source_gid,target_gid,flow_label class)
        comps := fabric.componentsOn(path)  # link sequence for this ECMP class
        if path.degraded:
            for c in comps: suspectVotes[c] += path.severity
        else:
            for c in comps: exonerated.add(c)
    candidates := { c : suspectVotes[c] > 0 and c not in exonerated }
    return greedyMinimalCover(candidates, degradedPaths)   # fewest comps explaining all
```

This requires three things the rebuild does not have today:

1. **A fabric model**: switches and links as first-class entities, with tiers.
2. **A path→component mapping**: which links a given (src RNIC, dst RNIC,
   flow_label) actually traverses. ECMP hashing is generally not invertible
   exactly; the paper approximates it by covering many flow labels (the rebuild
   already rotates flow labels, sized by Eq.(1)) and by knowing the tiered
   topology so a path's *candidate* link set is enumerable.
3. **flow-label→path-class identity carried into the summary** so paths are
   distinguishable at the controller. Today `PathAggregator` collapses all flow
   labels of a (source,target) pair into one summary; per-flow-label
   distinction would need either finer aggregation keys or a separate reporting
   channel.

Recommendation: **do not build the set-cover pass in the first Phase 2 round.**
Ship the minimal heuristic (which needs no new data), and make the fabric model
+ path mapping a separately-scoped follow-up (see Implementation Plan). This is
the highest-leverage sequencing: the minimal pass delivers ToR-granularity
localization — which is exactly the metric granularity the system is allowed to
emit anyway — without a schema migration.

### Cross-agent quantile synthesis

Phase 1 ships per-agent, per-path `p50/p99` estimated from the **fixed** bucket
ladder `rttBucketBoundariesNs`. These per-agent percentiles **cannot be
averaged** to get a ToR-pair percentile. Two options:

1. **Loss and "degraded" flag**: exact by summation. `probe_total` and
   `probe_failed` add across agents with no error; the edge loss ratio is exact.
   This alone drives the minimal heuristic correctly, because the primary fault
   signal is loss/breadth, not the precise tail latency.
2. **Merged RTT tail**: to get a real ToR-pair p99, the recommended approach
   **exploits the fact that all agents already share the same fixed bucket
   ladder**. Add one additive field to `PathSummary` carrying the per-bucket
   counts (`repeated uint32 rtt_bucket_counts = 16;`, length =
   `len(rttBucketBoundariesNs)+1`). The controller then sums bucket counts per
   ToR-pair and computes an **exact bucket-resolution** merged quantile — no
   approximation-of-an-approximation, no per-agent percentile averaging.

**t-digest decision criterion.** Do NOT introduce t-digest unless *both*: (a)
the fixed bucket resolution is demonstrably too coarse for a latency SLO the
operator actually sets (e.g. an SLO that lands between two bucket edges near the
tail), AND (b) operators need to reconfigure RTT resolution per deployment
without redeploying agents. Until then, bucket-count summation is strictly
simpler, is exact at bucket resolution, requires no mergeable-sketch code on the
agent, and reuses a ladder that already exists. t-digest's only real advantage —
adaptive accuracy at the extreme tail — is not worth the agent-side complexity
for a ToR-pair screening metric. If adopted later, t-digest centroids would be
the new additive field instead of bucket counts, merged at the controller.

Phase 2's first round should adopt **option 1 for detection** and **option 2
(bucket-count histogram, additive field) for the emitted ToR-pair p99**, and
leave t-digest unbuilt.

### rqlite `path_summaries` table (additive, optional persistence)

Localization itself runs on the **in-memory** window ring (recent windows are
all it needs), so persistence is **not required** for Phase 2 to function. The
table below is specified for optional forensic retention and to let a future
standalone `rpingmesh-analyzer` binary read history. It is a **new table** — it
does not alter `rnics` — so it is a purely additive, backward-compatible schema
change.

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
CREATE INDEX IF NOT EXISTS idx_ps_window     ON path_summaries (window_start_unix_ns);
CREATE INDEX IF NOT EXISTS idx_ps_tor_pair   ON path_summaries (source_tor_id, target_tor_id, window_start_unix_ns);
```

If the bucket-count histogram (field 16) is adopted, persist it as a JSON/text
column `rtt_bucket_counts TEXT` appended to the table (again additive).

**Retention**: a periodic sweep mirroring `CleanupStaleEntries`
(`DELETE FROM path_summaries WHERE window_start_unix_ns < (now - retentionNs)`).
Default retention on the order of hours (e.g. 6h), config-driven
(`analyzer_persist_retention_sec`). Localization does not read beyond the
in-memory ring, so retention here is purely a forensic/disk-budget knob.

**Write-rate estimate** (the reason persistence is opt-in and batched):
`rows/s ≈ agents × pathsPerAgent × (1/windowSec)`.
For 1000 agents × 50 paths / 30 s ≈ **1.7k rows/s**. rqlite commits go through
Raft (an fsync per transaction), so per-row inserts are infeasible; each
`ProbeAnalysisReport` (already batched to ≤256 summaries by
`maxSummariesPerReport`) must be written as **one multi-row parameterized
transaction**, giving ≈7 report-transactions/s at that scale. This is
tolerable but is the dominant new write load on rqlite, which is why:
persistence is **disabled by default** (`analyzer_persist_enabled: false`),
localization never depends on it, and enabling it is an explicit operator
decision with the write-rate documented.

### Output: suspect ranking, OTLP, findings lifecycle

**Suspect ranking** is emitted per completed window as a sorted list of
`Suspect{tor, kind, score, confidence, evidence}` and `PathSuspect{S,T,...}`.

**OTLP metrics** (registered on the existing `rpingmesh.analyzer` meter, ToR
granularity only):

| metric | type | attributes | meaning |
|--------|------|-----------|---------|
| `rpingmesh.analyzer.suspect_tor` | ObservableGauge (0/1) or Gauge | `tor`, `kind` (downside/upside) | 1 while a ToR has an open suspicion finding |
| `rpingmesh.analyzer.suspect_tor_score` | Gauge | `tor`, `kind` | current suspicion score (0..1) for a suspected ToR |
| `rpingmesh.analyzer.localization_runs_total` | Counter | — | windows processed by the localizer |
| `rpingmesh.analyzer.inter_tor_path_suspect` | Gauge (0/1) | `source_tor`, `target_tor` | spine-path suspicion that is not attributable to one ToR |

No GID attribute ever appears on a metric; GID-level evidence goes to findings
logs (mirroring `logFinding` in `analyzer.go`).

**Findings lifecycle** (hysteresis to avoid flapping): a suspicion for a given
`(tor, kind)` is a state machine.

```
             score>=openThresh for K consecutive windows
   CLEARED ─────────────────────────────────────────────► OPEN
      ▲                                                     │
      │      score<closeThresh for M consecutive windows    │
      └─────────────────────────────────────────────────────┘
```

- **OPEN**: emit a Warn finding log (with GID/edge evidence and score) and set
  the `suspect_tor` gauge to 1. Re-log at a throttled cadence while open.
- **CLEARED**: emit a resolution log, set the gauge to 0.
- `K` (open confirmation windows, e.g. 2–3), `M` (clear windows, e.g. 3–5),
  `openThresh`, `closeThresh` (`closeThresh < openThresh` for hysteresis) are
  config-driven. State lives next to the window ring in the `Analyzer` under the
  existing mutex.

This lifecycle is what makes the ToR-granularity output trustworthy: a single
noisy window neither opens nor closes a finding.

### Config additions (controller)

Additive keys, defaults chosen conservatively:

```yaml
analyzer_localization_enabled: true
analyzer_loc_breadth_frac: 0.6        # fraction of edges degraded to call a side "broad"
analyzer_loc_open_score: 0.6          # score to open a suspicion
analyzer_loc_close_score: 0.3         # score to clear (hysteresis)
analyzer_loc_open_windows: 2          # K consecutive windows to open
analyzer_loc_close_windows: 3         # M consecutive windows to clear
analyzer_persist_enabled: false       # rqlite path_summaries persistence (opt-in)
analyzer_persist_retention_sec: 21600 # 6h; only meaningful when persist enabled
```

## Alternatives Considered

- **Localize on the agent.** Rejected on first principles: an agent sees only
  its own source RNICs and cannot separate "my uplink" from "the target ToR".
  Localization is a cross-agent intersection; it must be central. (This is the
  same conclusion the Phase 1 design reached for aggregation.)
- **Push localization into the OTel collector (OTTL/connector).** Rejected: the
  collector has neither the fabric topology nor the cross-agent join, and this
  would fight the deliberate ToR-only cardinality design. Localization belongs
  where the registry lives.
- **Average per-agent p99s for the ToR-pair tail.** Rejected as statistically
  invalid. Chose exact loss summation for detection + shared-bucket histogram
  summation for the emitted tail.
- **Adopt t-digest immediately for cross-agent quantiles.** Rejected for the
  first round: the fixed shared bucket ladder already permits exact
  bucket-resolution merging with far less code and no agent-side sketch. t-digest
  is held behind an explicit criterion.
- **Build the paper's full set-cover localizer now.** Rejected as premature: it
  requires a fabric model, a path→link mapping, and per-flow-label summary
  identity, none of which exist. The minimal heuristic reaches ToR granularity —
  the granularity the system may emit — without any of that. Set-cover is
  designed but explicitly deferred.
- **Persist every summary to rqlite and localize from SQL.** Rejected as the
  primary path: localization needs only recent windows already held in memory,
  and per-summary rqlite writes do not fit Raft's fsync-per-commit model.
  Persistence is optional, batched, and off by default.

## Test Plan

All Phase 2 logic is pure Go operating on `[]*controller_agent.PathSummary` and
a registry snapshot, so it is **deterministic and unit-testable without RDMA**,
matching the Phase 1 analyzer tests.

- **Topology fixtures**: define small deterministic clusters as fixtures — e.g.
  4 ToRs × N RNICs, with a GID→ToR map — and hand-build `PathSummary` sets that
  encode specific fault scenarios. Fixtures live beside `analyzer_test.go`.
  - Scenario A (down-side/ToR fault): all inbound edges to ToR X degraded across
    ≥3 source ToRs + intra-X degraded; assert X ranked suspect kind=downside,
    others not suspected.
  - Scenario B (up-side fault): all outbound edges from ToR Y degraded but the
    same target ToRs healthy from other sources; assert Y kind=upside.
  - Scenario C (spine path): single (S,T) degraded, S→others and others→T
    healthy; assert **no** `suspect_tor`, one `inter_tor_path_suspect`.
  - Scenario D (noise/no fault): random low loss below thresholds; assert no
    suspects (guards false positives).
  - Scenario E (single-agent noise): one agent reports a badly degraded edge to
    X; assert low confidence keeps X below `openThresh` (no finding opens).
- **Cross-agent aggregation**: two agents reporting summaries for the same
  aligned window and same ToR-pair must fold into one `EdgeStat` with summed
  totals; assert exact loss ratio and (with histogram field) exact merged p99.
- **Findings lifecycle**: drive K windows above `openThresh` → assert OPEN
  finding + gauge=1; then M windows below `closeThresh` → assert CLEARED +
  gauge=0; assert a single dip below threshold does not close (hysteresis).
- **Determinism**: ranking must be a total order (stable tie-break on ToR id) so
  tests are reproducible.
- **Metrics**: assert `suspect_tor` / `suspect_tor_score` carry only
  `tor`/`kind` attributes (cardinality regression guard), reusing the pattern in
  the Phase 1 metrics tests.
- **rqlite persistence** (only if that PR is built): unit-test the multi-row
  batch insert and the retention sweep against the `dbConn` fake already used by
  the registry tests; assert one transaction per report.
- **e2e (RDMA-free, controller path)**: extend the existing
  `e2e/probe_analysis_e2e_test.go` style — a pseudo-agent posts crafted
  `ProbeAnalysisReport`s encoding Scenario A across "multiple agents"; assert the
  controller opens a suspect-ToR finding and emits the gauge end-to-end.

## Implementation Plan (PR breakdown)

Each PR is independently reviewable/mergeable. Ordering maximizes value-per-risk
and keeps the schema-free work first.

1. **P3-H.1 — Edge model + minimal localizer (no proto/schema change).**
   `internal/controller/analyzer/localizer.go`: `EdgeStat`, edge folding from
   retained window buckets, the common-element heuristic, ranking. `Analyzer`
   gains a post-window hook (invoked when a window completes) that calls it.
   Registry gains a read-only `TopologySnapshot()` (GID→ToR, ToR→GIDs) built
   from `ListAllRNICs`. Findings logged only (no metrics yet). Fixtures +
   Scenarios A–E as unit tests. This PR delivers working ToR-granularity
   localization with zero migration.
2. **P3-H.2 — Findings lifecycle + OTLP.** Add the hysteresis state machine and
   the `suspect_tor` / `suspect_tor_score` / `inter_tor_path_suspect` /
   `localization_runs_total` instruments on the existing analyzer meter. Config
   keys for thresholds/windows. Lifecycle + metrics-cardinality tests. e2e
   controller-path test.
3. **P3-H.3 — Cross-agent exact tail (additive proto field).** Add
   `repeated uint32 rtt_bucket_counts = 16;` to `PathSummary`; have
   `pathAccumulator` expose its buckets and `analysis_reporter.toProto` populate
   the field; controller sums buckets per ToR-pair for an exact merged p99. Fully
   backward compatible (old agents simply omit the field; controller falls back
   to loss-only detection + max(p99)). Aggregation/merge unit tests.
4. **P3-H.4 (optional) — rqlite persistence.** `path_summaries` table +
   batched multi-row insert on ingest + retention sweep, all behind
   `analyzer_persist_enabled` (default false). Registry-fake unit tests.
5. **P3-H.5 (deferred / separate track) — Fabric topology model + set-cover.**
   New registry tables (switches, links) + a path→component mapping + per-flow
   summary identity + the set-cover localizer. Large; specified here but
   sequenced after H.1–H.3 prove out and only if per-link granularity is
   actually required. Explicitly gated on operator-provided topology.

## Open Questions

- **Topology source for the advanced pass.** Per-link localization needs a
  fabric model (spine/agg switches + links) that the agents cannot discover.
  Would this come from an operator-provided topology file, an SNMP/LLDP feed, or
  a controller config? This is a product decision that gates P3-H.5. *(User
  input needed.)*
- **Is ToR granularity sufficient for the operational goal?** If ToR-level
  suspects satisfy the on-call workflow, H.5 may never be needed. *(User input
  needed.)*
- **Enable rqlite persistence by default?** Given the ≈1.7k rows/s at 1000
  agents and Raft's fsync-per-commit, the recommendation is off-by-default. If
  forensic history is a hard requirement, an external TSDB/OLAP sink (rather than
  rqlite) may be the better target. *(User input needed.)*
- **`breadthFrac` / threshold defaults** are first guesses; they should be tuned
  against a real cluster's normal-noise floor before trusting auto-opened
  findings.
- **Window alignment across agents** assumes agent clocks are reasonably
  synchronized (windows are wall-clock floored). Large clock skew would scatter
  the same real window across adjacent buckets and weaken cross-agent
  intersection. Is NTP-level sync a safe assumption in the target fleet?
