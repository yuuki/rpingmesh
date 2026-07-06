# Grafana Dashboards for R-Pingmesh Telemetry

Status: Design + implementation spec (P4-observability). This document specifies
the operator-facing Grafana dashboards for the rebuild, the metric-name contract
between the OpenTelemetry pipeline and the dashboard JSON, and a self-contained
docker-compose observability stack used to validate and demo them. The
accompanying implementation lands `rebuild/dashboards/*.json`,
`rebuild/deploy/observability/`, and `rebuild/scripts/seed-demo-metrics.sh`.

## Goals

- **Give operators a mesh-to-pair drilldown.** The first screen answers "is the
  fabric healthy, and if not, which ToR pairs are degraded?" A second screen
  answers "for this specific ToR pair, what does the latency distribution and the
  failure breakdown look like?" The transition between the two is a single click.
- **Zero custom plugins.** Everything renders on Grafana's built-in panels
  (Table with the *Grouping to matrix* transformation, Heatmap, Time series,
  Stat). No panel-plugin build step, no plugin allow-listing in provisioning.
- **Dashboards as committed code.** The dashboard JSON lives in the repo and is
  provisioned into Grafana from disk, so the dashboards are reviewable, diffable,
  and reproducible without a Grafana instance in the loop.
- **A one-command demo.** `docker compose up` on the observability stack plus a
  seed script produces a populated set of dashboards with no RDMA hardware, so
  the visualization can be developed and reviewed independently of the agent.

## Non-Goals

- No alerting rules in the first round (the metric contract is designed to make
  them trivial to add later; see Future work).
- No Phase-2 localization / path-tracing views — those depend on data the
  analyzer does not yet emit (`analyzer-phase2-localization.md`).
- No dashboard-generation toolchain (Grafonnet / Foundation SDK). Committed JSON
  is the source of truth; codegen is called out only as future work.

## Context: the metric inventory (verified against code)

Two meters produce all telemetry, both exported over OTLP/gRPC via a periodic
reader flushing every **10 s** (`internal/telemetry/otel_metrics.go`,
`periodicReaderInterval`). The SDK uses the default **cumulative** temporality,
which is exactly what a Prometheus-style backend expects.

| Instrument (OTLP name) | Type | Labels | Meaning |
|---|---|---|---|
| `rpingmesh.network_rtt_ns` | Int64 Histogram | `source_tor`, `target_tor` | Network RTT `(T5-T2)-(T4-T3)` |
| `rpingmesh.prober_delay_ns` | Int64 Histogram | `source_tor`, `target_tor` | Prober-side delay `(T6-T1)-(T5-T2)` |
| `rpingmesh.responder_delay_ns` | Int64 Histogram | `source_tor`, `target_tor` | Responder-side delay `T4-T3` |
| `rpingmesh.probe_total` | Counter | `source_tor`, `target_tor` | Probes attempted |
| `rpingmesh.probe_success_total` | Counter | `source_tor`, `target_tor` | Probes with a valid RTT |
| `rpingmesh.probe_failed_total` | Counter | `source_tor`, `target_tor`, `reason` | Failures; `reason` ∈ {timeout, send_error, invalid_rtt, unknown} |
| `rpingmesh.agent.self_throttle` | Float64 ObservableGauge | (none) | Self-protection rate multiplier, 1.0 = unthrottled, floor 0.1 |
| `rpingmesh.event_ring_dropped_total` | ObservableCounter | `ring` ∈ {prober, responder} | Completion events dropped on a full ring |
| `rpingmesh.analyzer.path_summaries_total` | Counter | (none) | Per-path window summaries ingested |
| `rpingmesh.analyzer.sla_violations_total` | Counter | `source_tor`, `target_tor`, `kind` ∈ {loss, rtt} | SLA violations detected |

All three histograms share the same 11 explicit bucket boundaries in
nanoseconds: `100, 500, 1 000, 5 000, 10 000, 50 000, 100 000, 500 000,
1 000 000, 5 000 000, 10 000 000` (plus the implicit `+Inf`). Cardinality is
deliberately ToR-level only — GID detail is confined to debug logs.

Resource attribution: the agent meter is created on a provider with
`service.name = rpingmesh-agent`; the analyzer's with `rpingmesh-analyzer`.
After the OTLP → Prometheus conversion these become the `job` label on every
series (via the exporter's resource-to-`job` mapping), so agent and analyzer
series are distinguishable even where their metric names do not overlap.

## Decision 1: the OTLP → Prometheus name contract

This is the single most failure-prone part of the design, because the dashboard
JSON hard-codes metric names and those names are produced by the collector, not
by the Go code. The names must be pinned deterministically.

**Pipeline:** agent/analyzer → OTLP/gRPC → `otel-collector-contrib` →
`prometheusremotewrite` exporter → VictoriaMetrics `/api/v1/write`.

**The trap:** the OTLP metric names were authored to *already* carry Prometheus
conventions — counters end in `_total`, histograms end in `_ns` (their unit).
The prometheusremotewrite exporter, by default
(`translation_strategy: UnderscoreEscapingWithSuffixes`), *appends* type and unit
suffixes on top of the name. With the default strategy a counter named
`rpingmesh.probe_total` can become `rpingmesh_probe_total_total`, and a histogram
with unit `ns` risks an added unit suffix. That would silently break every panel.

**Decision:** set `translation_strategy: UnderscoreEscapingWithoutSuffixes` on the
exporter. This escapes `.` → `_` for Prometheus compatibility but appends **no**
type or unit suffix, so the Prometheus name is exactly the OTLP name with dots
replaced. The dashboard JSON and the exporter config are thereby locked to the
same fixed names:

| OTLP name | Prometheus series |
|---|---|
| `rpingmesh.network_rtt_ns` | `rpingmesh_network_rtt_ns_bucket` / `_sum` / `_count` (label `le` on `_bucket`) |
| `rpingmesh.prober_delay_ns` | `rpingmesh_prober_delay_ns_{bucket,sum,count}` |
| `rpingmesh.responder_delay_ns` | `rpingmesh_responder_delay_ns_{bucket,sum,count}` |
| `rpingmesh.probe_total` | `rpingmesh_probe_total` |
| `rpingmesh.probe_success_total` | `rpingmesh_probe_success_total` |
| `rpingmesh.probe_failed_total` | `rpingmesh_probe_failed_total` |
| `rpingmesh.agent.self_throttle` | `rpingmesh_agent_self_throttle` |
| `rpingmesh.event_ring_dropped_total` | `rpingmesh_event_ring_dropped_total` |
| `rpingmesh.analyzer.path_summaries_total` | `rpingmesh_analyzer_path_summaries_total` |
| `rpingmesh.analyzer.sla_violations_total` | `rpingmesh_analyzer_sla_violations_total` |

`_bucket`/`_sum`/`_count` are structural histogram series, not name suffixes, so
they are unaffected by the strategy choice. The seed script emits these exact
names, closing the loop: exporter, dashboards, and seed all agree.

## Decision 2: two dashboards, native panels only

Two dashboards, matching the two operator questions:

**"Mesh Overview"** (`uid: rpingmesh-mesh-overview`) — the fleet-wide entry
point:
- A **fleet-health stat row**: total probe rate, fleet success ratio, SLA-
  violation rate, worst agent self-throttle (`min(...self_throttle)`), and event-
  ring drop rate. These are the five numbers that say "call someone" vs "sleep".
- A **ToR × ToR loss matrix** — a Table panel whose instant, table-format query
  yields `(source_tor, target_tor, loss%)` rows, reshaped by the *Grouping to
  matrix* transformation (`rowField=source_tor`, `columnField=target_tor`,
  `valueField=Value`) and colored by threshold via a color-background cell type.
  This is the paper's "at a glance, where is the fabric broken" view.
- A **companion "Worst ToR pairs" table** (`topk` by loss%) carrying the
  drilldown data link. See Decision 3 for why the clickable path lives here and
  not on the matrix cells.
- **Failure and SLA time series**: failure rate by `reason`, SLA-violation rate
  by `kind`, and an instant SLA-by-pair table (also clickable).

**"ToR Pair Drilldown"** (`uid: rpingmesh-tor-pair`) — everything about one pair,
selected by `source_tor` / `target_tor` template variables
(`label_values(rpingmesh_probe_total, source_tor)` and the target chained on the
selected source):
- Pair stat row (success ratio, probe rate, current p50/p99 network RTT).
- **Network-RTT heatmap** from `rpingmesh_network_rtt_ns_bucket` (`le` buckets,
  `ns` y-unit) — the latency-distribution-over-time picture.
- p50/p90/p99 network-RTT time series via `histogram_quantile`.
- Failure rate by `reason` for the pair.
- Prober-delay and responder-delay percentiles (isolates "is it the network or
  an endpoint stalling?").

Rationale for **two** dashboards rather than one big board or many small ones:
the mesh view is intentionally dense and fleet-scoped (no per-pair template
variables), so it stays useful as a wall dashboard; the pair view is
variable-scoped and only meaningful once a pair is chosen. Splitting keeps each
board's queries cheap and its purpose single. A third Phase-2 localization board
is deferred (Future work).

## Decision 3: the drilldown mechanism (data links)

Drilldown is a Grafana **data link** from Overview → Pair Drilldown, passing
`var-source_tor` and `var-target_tor` on the URL and preserving the time range.

A subtlety worth recording: a matrix built with *Grouping to matrix* has
**dynamic column names** (each column header is a `target_tor` value) and its
first field is named `rowField\columnField`. Configuring a robust per-cell data
link that carries *both* coordinates is fragile because the URL template must
reference that backslash-named row-header field. Therefore the **guaranteed**
click path is the companion "Worst ToR pairs" table, whose rows have clean,
stably named `source_tor` and `target_tor` fields, making the link template
trivial and stable:

```
/d/rpingmesh-tor-pair/r-pingmesh-tor-pair-drilldown?var-source_tor=${__data.fields.source_tor}&var-target_tor=${__data.fields.target_tor}&${__url_time_range}
```

The matrix stays a color-only overview; the operator reads the hot cell, then
clicks the same pair in the adjacent table. Best-effort matrix-cell links are
described in the implementation spec but are not the contract.

## Alternatives considered

- **Native Table + Grouping to matrix vs ESnet Matrix panel vs a custom plugin.**
  Chosen: native. A ToR × ToR loss grid is exactly what *Grouping to matrix*
  plus color-background cells produces, with zero plugin dependency and full
  provisioning portability. The ESnet Matrix panel gives nicer cell interaction
  and a purpose-built look, but adds a plugin install to every Grafana and a
  version-compatibility surface; it is documented as an optional enhancement, not
  provisioned. A custom panel plugin was rejected outright — it is a build,
  release, and maintenance burden wildly out of proportion to a colored grid.
- **Committed JSON vs Grafonnet / Foundation SDK.** Chosen: committed JSON,
  because it needs no toolchain to review or provision and round-trips cleanly
  with Grafana's UI export. The cost is that hand-written JSON must be kept
  equivalent to what the UI would emit; the mitigation is to build/verify panels
  in the UI and export. Codegen is deferred until the dashboard count or
  duplication justifies it.
- **Prometheus-typed datasource pointing at VictoriaMetrics vs the VictoriaMetrics
  datasource plugin.** Chosen: Prometheus type (zero-plugin). VictoriaMetrics is
  Prometheus-API-compatible for querying, `label_values`, and instant/range
  queries — everything these dashboards use. The VM plugin adds MetricsQL niceties
  we do not need and another plugin to provision.
- **Collector via prometheusremotewrite vs VictoriaMetrics native OTLP ingest.**
  Chosen: the collector. VM can ingest OTLP directly at
  `/opentelemetry/v1/metrics`, but then metric naming is governed by VM flags
  (`-opentelemetry.usePrometheusNaming` and friends) whose default would *not*
  reproduce the already-Prometheus-styled names and would re-introduce the
  double-suffix risk. Routing through the collector keeps naming control in one
  explicit, reviewable place (`translation_strategy`) and matches the intended
  otel-collector-contrib stack. Direct OTLP ingest is a valid future
  simplification once naming is validated.
- **`histogram_quantile` over 11 explicit buckets vs analyzer-side percentiles.**
  The 11 boundaries mean percentile *resolution equals the bucket edges*: a p99
  that falls between 1 ms and 5 ms is linearly interpolated across a 4 ms-wide
  bucket and cannot be more precise than that. This is acceptable for a *shape*
  and *regression* view (the dashboards' job) but is **not** an accurate
  percentile. The design's stance: dashboards show distribution shape and coarse
  quantiles; authoritative percentiles are the analyzer's job (its per-path
  summaries and SLA evaluation), surfaced as counts, not recomputed on the
  dashboard. Panels label these as approximate.
- **Cardinality and query cost.** Series scale as O(ToR²): with `N` ToRs the
  probe counters are `~N²` series each and each histogram is `~N² × 12` bucket
  series. A cluster with 50 ToRs is ~2 500 pairs → ~30 000 bucket series per
  histogram — well within VictoriaMetrics, but the *matrix panel query* fans out
  over all pairs on every refresh. Mitigations baked into the design: the matrix
  uses an instant query over `$__range` (one evaluation, not a range fan-out); the
  companion table uses `topk` to bound rows; the heavy per-pair histogram queries
  live only on the drilldown board where they are constrained to a single pair by
  template variables. This keeps the always-on Overview cheap and pushes the
  expensive queries behind an explicit pair selection.

## Verification strategy

The stack is validated end to end without any RDMA hardware:

1. **Bring up the stack** — `docker compose` (on colima) starts VictoriaMetrics,
   otel-collector-contrib, and Grafana with provisioned datasource + dashboards.
2. **Seed synthetic mesh data** — `seed-demo-metrics.sh` backfills ~30 min of a
   4–6 ToR mesh into VictoriaMetrics via `/api/v1/import/prometheus` (per-line
   timestamps), including realistic histogram buckets, success/failure counters
   with a couple of deliberately degraded pairs, SLA-violation counters, and the
   self-throttle gauge. Timestamped backfill is required so `rate()` and
   `histogram_quantile()` have ≥2 points to work with.
3. **Assert Grafana health and provisioning** — `GET /api/health` is `ok`;
   `GET /api/search` lists both dashboards (provisioning succeeded).
4. **Assert every panel query returns data** — replay each panel's PromQL through
   `POST /api/ds/query` (or the datasource proxy) and assert HTTP 200 with a
   non-empty frame. This catches name-contract drift directly: if the exporter
   ever re-introduces a suffix, these queries return empty and the check fails.

Exact commands are in the implementation spec.

## Future work

- **ESnet Matrix panel** as an opt-in enhancement once its Grafana-version
  compatibility is pinned and plugin provisioning is acceptable — it would host
  richer cell interactions (including reliable per-cell drilldown, removing the
  companion-table workaround).
- **Phase-2 localization view**: a third dashboard over the analyzer's
  path/segment attribution once those metrics exist
  (`analyzer-phase2-localization.md`).
- **Alerting rules**: the metric contract already supports the obvious alerts —
  per-pair loss ratio, per-pair p99 breach, sustained self-throttle < 1, and any
  event-ring drops — as Grafana or vmalert rules.
- **Dashboards-as-code**: migrate the committed JSON to Grafonnet/Foundation SDK
  if the board count grows or duplication between Overview and Drilldown becomes
  a maintenance cost.
- **Direct OTLP ingest**: drop the collector once VM-side naming is validated to
  reproduce the pinned names.
