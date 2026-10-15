# Grafana Dashboards for R-Pingmesh Telemetry

Status: implemented. This document specifies the operator-facing Grafana
dashboards, the metric-name contract between the OpenTelemetry pipeline and
the dashboard JSON, the alert rules, and the docker-compose observability
stack used to validate and demo them. The implementation lives in:

- `dashboards/*.json`: the two dashboards;
- `deploy/observability/`: the compose stack, collector config, Grafana
  provisioning, and `alerts/rpingmesh.rules.yml`;
- `scripts/seed-demo-metrics.sh` and `scripts/verify-observability.sh`: demo
  data and end-to-end checks (`make obs-up`, `obs-seed`, `obs-verify`,
  `obs-down`; usage in `deploy/observability/README.md`).

## Goals

- **Mesh-to-pair drilldown.** The first screen answers "is the fabric healthy,
  and if not, which ToR pairs are degraded?" The second answers "for this ToR
  pair, what do the latency distribution and the failure breakdown look
  like?" One click moves from the first to the second.
- **Zero custom plugins.** Everything uses Grafana's built-in panels (Table
  with the *Grouping to matrix* transformation, Heatmap, Time series, Stat).
  There is no plugin build step and no plugin allow-listing in provisioning.
- **Dashboards as committed code.** The dashboard JSON lives in the repo and
  is provisioned from disk, so dashboards are reviewable, diffable, and
  reproducible without a Grafana instance in the loop.
- **A one-command demo.** The compose stack plus a seed script produces
  populated dashboards without RDMA hardware, so the visualization can be
  developed and reviewed independently of the agent.

## Non-Goals

- Phase 2 localization or path-tracing views. They depend on data the
  analyzer does not emit yet (`analyzer-phase2-localization.md`).
- A dashboard-generation toolchain (Grafonnet, Foundation SDK). Committed JSON
  is the source of truth.

## Metric inventory

Two meter providers produce all telemetry. Both export over OTLP/gRPC through
a periodic reader that flushes every **10 s** (`periodicReaderInterval` in
`internal/telemetry/otel_metrics.go`) with the SDK's default **cumulative**
temporality, which is what a Prometheus-style backend expects.

| Instrument (OTLP name) | Type | Attributes | Meaning |
|---|---|---|---|
| `rpingmesh.network_rtt_ns` | Int64 Histogram | `source_tor`, `target_tor`, `source_rdma_device`, `source_netdev` | Network RTT `(T5-T2)-(T4-T3)` |
| `rpingmesh.prober_delay_ns` | Int64 Histogram | same | Prober-side delay `(T6-T1)-(T5-T2)` |
| `rpingmesh.responder_delay_ns` | Int64 Histogram | same | Responder-side delay `T4-T3` |
| `rpingmesh.probe_total` | Int64 Counter | same | Probes attempted |
| `rpingmesh.probe_success_total` | Int64 Counter | same | Probes with a valid RTT |
| `rpingmesh.probe_failed_total` | Int64 Counter | same, plus `reason` ∈ {`timeout`, `send_error`, `invalid_rtt`, `unknown`} | Failed probes |
| `rpingmesh.agent.self_throttle` | Float64 ObservableGauge | none | Self-protection rate multiplier: 1.0 = unthrottled, floor 0.1 |
| `rpingmesh.event_ring_dropped_total` | Int64 ObservableCounter | `ring` ∈ {`prober`, `responder`} | Completion events dropped on a full ring |
| `rpingmesh.analyzer.path_summaries_total` | Int64 Counter | none | Per-path window summaries ingested by the analyzer |
| `rpingmesh.analyzer.sla_violations_total` | Int64 Counter | `source_tor`, `target_tor`, `kind` ∈ {`loss`, `rtt`} | SLA violations detected by the analyzer |

The three histograms share 29 explicit bucket boundaries in nanoseconds
(`rttBucketBoundaries`), densest in 1–10 µs where RoCEv2 network RTTs land:
`100, 250, 500`, then 500 ns steps from 1 µs to 5 µs, 1 µs steps to 10 µs, then
`12 500, 15 000, 20 000, 25 000, 50 000, 100 000, 250 000, 500 000,
1 000 000, 2 500 000, 5 000 000, 10 000 000`, plus the implicit `+Inf`. The
ladder is a superset of the analyzer's own bucket ladder
(`rttBucketBoundariesNs` in `internal/probe/aggregator.go`).

**Attribute contract.**

- Cardinality is ToR-level plus the local (source) RNIC. `source_rdma_device`
  (e.g. `mlx5_0`) and `source_netdev` (the netdev bound to the probing
  port/GID) map 1:1, so together they multiply series only by the RNICs per
  host. They distinguish a multi-rail host's RNICs that share a ToR and join
  with RDMA hardware counters and node_exporter `node_network_*{device=...}`.
- Destination-RNIC identity and GIDs never become attributes; they appear
  only in debug logs.
- Empty values are exported as the non-empty label `unspecified`: an unset
  `tor_id`, and a device or netdev that cannot be resolved (e.g. a bonded
  RNIC's netdev). Template variables and the ToR × ToR matrix therefore still
  render; an all-untagged mesh shows one `unspecified` × `unspecified` cell.
- Every bundled dashboard query and alert aggregates the source-RNIC labels
  and the agent identity away (`sum by (source_tor, target_tor)`,
  `sum by (le)`, and similar). Custom queries that should stay ToR-level must
  do the same.
- The analyzer's path aggregator fixes a path's target ToR when its window
  opens. If an agent switches to a real ToR ID mid-window, the analyzer's
  `sla_violations_total` labels can carry the previous target ToR until that
  window closes.

### Estimating the series count

The agent's probe-metric series count follows from the label tuples it can
emit. `source_rdma_device` and `source_netdev` are 1:1 and each RNIC has one
ToR, so `source_tor` adds no combinations once the source RNIC is known. Per
agent (one `instance` / `host.name`), the number of distinct
`(source RNIC, target_tor)` tuples is

```
P_agent = Σ_{r ∈ RNICs on the host} T(r)
```

where `T(r)` is the number of distinct `target_tor` values RNIC `r` has
probed: its own ToR (ToR-mesh) plus the foreign ToRs in its inter-ToR
pinglists (same plane only when a plane is set). The controller samples up to
`inter_tor_sample_size` (default 5) foreign ToRs per refresh, so at any moment
`T(r) ≤ 1 + inter_tor_sample_size`. The OTel SDK keeps every attribute set it
has seen for the life of the process, so as samples rotate the long-run bound
is the number of ToRs in the RNIC's plane. Untagged RNICs only see
`target_tor="unspecified"`, so `T(r) = 1` on an all-untagged fabric.

After OTLP → Prometheus conversion, each tuple becomes the following series
(29 boundaries → 30 `_bucket` series including `+Inf`, plus `_sum` and
`_count`):

| Metric | Prometheus series per tuple |
|---|---|
| 3 histograms (`network_rtt_ns`, `prober_delay_ns`, `responder_delay_ns`) | 3 × (30 + 2) = 96 |
| `probe_total`, `probe_success_total` | 2 |
| `probe_failed_total` | `R` = number of `reason` values seen (0–4) |
| **Total** | **98 + R ≤ 102** |

```
series_agent ≤ P_agent × 102
series_fleet = Σ_agents series_agent
```

Before the source-RNIC labels existed, the tuple was `(source_tor,
target_tor)`, so RNICs of a host that share a ToR collapsed into one tuple.
The growth factor from those labels is *RNICs per host ÷ distinct source ToRs
per host*: 1 when every RNIC has its own ToR, up to the RNIC count when all
RNICs share one ToR or are untagged.

Worked examples (fleet totals use the upper bound `R = 4`):

| Fabric | `T(r)` | `P_agent` before → after | Fleet series before → after |
|---|---|---|---|
| **A.** 128 hosts × 8 RNICs, rail-optimized: 8 planes × 4 leaves (32 ToRs), each RNIC on its own leaf | 1 own + 3 foreign in the plane = 4 | 32 → 32 | 417,792 → 417,792 (×1) |
| **B.** 64 hosts × 2 RNICs, both RNICs of a host on the same ToR, 8 ToRs, no planes | 1 own + up to 7 foreign = 8 (long-run) | 8 → 16 | 52,224 → 104,448 (×2) |
| **C.** 128 hosts × 8 RNICs, no `tor_id` (all untagged) | 1 (`unspecified`) | 1 → 8 | 13,056 → 104,448 (×8) |

Arithmetic for A: `P_agent = 8 × 4 = 32`, `series_agent = 32 × 102 = 3,264`,
fleet `= 3,264 × 128 = 417,792`. In B the instantaneous `T(r)` is
`1 + 5 = 6` with the default sample size; 8 is the bound once sampling has
visited every foreign ToR. Histogram buckets dominate (96 of 102 series per
tuple), so fewer bucket boundaries is the main lever if the total is too
high. Dropping the source-RNIC labels only helps in cases like B and C.

To check the real count in Prometheus:

```promql
count by (__name__) ({__name__=~"rpingmesh[._].*", job="rpingmesh-agent"})
count by (instance) ({__name__=~"rpingmesh[._].*", job="rpingmesh-agent"})
```

(With dotted names the agent identity may be `service.name` / `host.name`
instead of `job` / `instance`; see Decision 1.)

## Decision 1: the OTLP → Prometheus name contract

The dashboard JSON hard-codes metric names, but the collector, not the Go
code, produces the stored names. This is the most failure-prone part of the
design, so the names are pinned explicitly.

**Pipeline:** agent/analyzer → OTLP/gRPC → `otel-collector-contrib` →
`prometheus_remote_write` exporter (formerly `prometheusremotewrite`) →
VictoriaMetrics `/api/v1/write`.

**The trap.** The OTLP names already follow Prometheus conventions: counters
end in `_total` and histograms end in their unit (`_ns`). The exporter's
default `translation_strategy` (`UnderscoreEscapingWithSuffixes`) appends type
and unit suffixes on top, so `rpingmesh.probe_total` can become
`rpingmesh_probe_total_total` and a histogram with unit `ns` can gain a unit
suffix. Either change silently empties every panel.

**Decision:** set `translation_strategy: UnderscoreEscapingWithoutSuffixes`
(`deploy/observability/otel-collector/config.yaml`). The exporter escapes
`.` → `_` and appends no suffix, so the Prometheus name is the OTLP name with
dots replaced:

| OTLP name | Prometheus series |
|---|---|
| `rpingmesh.network_rtt_ns` | `rpingmesh_network_rtt_ns_{bucket,sum,count}` (label `le` on `_bucket`) |
| `rpingmesh.prober_delay_ns` | `rpingmesh_prober_delay_ns_{bucket,sum,count}` |
| `rpingmesh.responder_delay_ns` | `rpingmesh_responder_delay_ns_{bucket,sum,count}` |
| `rpingmesh.probe_total` | `rpingmesh_probe_total` |
| `rpingmesh.probe_success_total` | `rpingmesh_probe_success_total` |
| `rpingmesh.probe_failed_total` | `rpingmesh_probe_failed_total` |
| `rpingmesh.agent.self_throttle` | `rpingmesh_agent_self_throttle` |
| `rpingmesh.event_ring_dropped_total` | `rpingmesh_event_ring_dropped_total` |
| `rpingmesh.analyzer.path_summaries_total` | `rpingmesh_analyzer_path_summaries_total` |
| `rpingmesh.analyzer.sla_violations_total` | `rpingmesh_analyzer_sla_violations_total` |

`_bucket`, `_sum`, and `_count` are structural histogram series, not name
suffixes, so the strategy does not affect them. The seed script emits the
same names, so exporter, dashboards, and seed agree.

**Unescaped (dotted) names.** Not every pipeline escapes dots. A collector or
backend in UTF-8 mode stores the OTLP names unchanged
(`rpingmesh.probe_total`, `rpingmesh.network_rtt_ns_bucket`). On-hardware
verification found a production VictoriaMetrics doing exactly that, which left
every panel empty. Dashboards and alert rules therefore select metrics by a
`__name__` regex that accepts a dot or an underscore wherever the OTLP name
has a dot:

```
{__name__=~"rpingmesh[._]probe_total"}
{__name__=~"rpingmesh[._]agent[._]self_throttle"}
{__name__=~"rpingmesh[._]network_rtt_ns_bucket", source_tor="$source_tor"}
```

The suffix contract still applies (no `_total_total`); only the separator is
open. One backend must not hold both styles for the same series, because every
aggregation would count them twice. `scripts/seed-demo-metrics.sh` seeds
either style (`NAME_STYLE=underscore`, the default, or `dotted`), and
`make obs-verify` runs every dashboard query and alert rule against it.

**Identity contract: `job` and `instance`.** A metric name plus its
attributes does not identify a series across a deployment with more than one
agent. The exporter derives the Prometheus `job` label from the resource's
`service.name` and `instance` from `service.instance.id`. `buildResource()` in
`internal/telemetry/otel_metrics.go` sets:

- `service.name`: `rpingmesh-agent`, or `rpingmesh-analyzer` for the
  controller's analyzer;
- `service.instance.id`: `os.Hostname()`, or a random UUID if that fails;
- `host.name`: the hostname, for pipelines that drop `service.instance.id`
  and identify sources by `host.name` instead.

Without a per-process identity, all agents that report the same metric and
attribute set collapse onto one series. The attribute-free
`rpingmesh.agent.self_throttle` and `rpingmesh.event_ring_dropped_total{ring}`
are the obvious cases, but `rpingmesh.probe_total` collides too whenever two
agents cover the same ToR pair. Interleaved writers corrupt
`rate()`/`increase()`: spurious counter resets and double counting look like
real signal. Dashboard panels never group by `instance`, so once each agent's
series is well-formed, `sum by (...)` recombines them into correct fleet and
pair totals. The fix is entirely in series identity, not in the queries. This
was verified with real OTLP pushes through the Go SDK: `instance` carried the
pushing host's hostname, and two pushes with distinct `service.instance.id`
values produced two series that `sum by (source_tor, target_tor)` combined
correctly.

## Decision 2: two dashboards, native panels only

**Mesh Overview** (`uid: rpingmesh-mesh-overview`) is the fleet-wide entry
point:

- **Fleet-health stat row:** probe rate, success ratio, SLA-violation rate,
  worst agent self-throttle (`min(...self_throttle)`), and event-ring drop
  rate. These five numbers decide "call someone" versus "sleep".
- **ToR × ToR loss matrix:** a Table panel whose instant, table-format query
  over `$__range` yields `(source_tor, target_tor, Value)` rows. The
  *Grouping to matrix* transformation (`rowField=source_tor`,
  `columnField=target_tor`, `valueField=Value`) reshapes them, and
  color-background cells color them by threshold. This is the paper's "where
  is the fabric broken" view.
- **Worst ToR pairs:** a companion `topk(20, ...)` table by loss %, which
  carries the drilldown data link (see Decision 4).
- **Failures and SLA:** failure rate by `reason`, SLA-violation rate by
  `kind`, and an instant SLA-violations-by-pair table that also links to the
  drilldown.

All success-ratio and loss % queries divide by
`(sum(rate(<probe_total>[...])) > 0)` rather than `clamp_min(..., 1)`.
`rate()` is in probes per second, so a pair probed at less than 1/s (a low
`inter_tor_probe_rate_per_second`, or a self-throttled agent) would clamp to a
denominator of 1 and show a large, fabricated loss % even at 100 % success.
Filtering out zero denominators drops such pairs instead (a "no data" cell),
which is correct when there were no probes.

**ToR Pair Drilldown** (`uid: rpingmesh-tor-pair`) covers one pair, selected
by the `source_tor` and `target_tor` template variables
(`label_values({__name__=~"rpingmesh[._]probe_total"}, source_tor)`, with
`target_tor` chained on the selected source):

- Pair stat row: success ratio, probe rate, and approximate p50/p99 network
  RTT.
- **Network-RTT heatmap** from the `network_rtt_ns_bucket` series (`le`
  buckets, `ns` y-axis, log scale): the latency distribution over time.
- p50/p90/p99 network RTT via `histogram_quantile`.
- Failure rate by `reason`.
- Prober-delay and responder-delay p50/p99, which separate "the network is
  slow" from "an endpoint is stalling".
- SLA-violation rate by `kind`.

Why two dashboards rather than one large board or many small ones: the mesh
view is dense and fleet-scoped (no per-pair variables), so it works as a wall
dashboard. The pair view is variable-scoped and only meaningful once a pair is
chosen. Splitting keeps each board's queries cheap and its purpose single.

## Decision 3: alert rules

`deploy/observability/alerts/rpingmesh.rules.yml` is a vmalert/Prometheus rule
file. The demo stack's `vmalert` service evaluates it every 30 s, and any
Prometheus-compatible ruler that accepts regex `__name__` selectors and dotted
label names (VictoriaMetrics, Prometheus 3+) can use it as is.

| Alert | Severity | Signal |
|---|---|---|
| `RpingmeshTorPairLoss` / `RpingmeshTorPairLossCritical` | warning / critical | ACK-timeout ratio per ToR pair > 1 % for 5 min / > 10 % for 3 min |
| `RpingmeshTorPairNoSuccess` | critical | A pair is probed but nothing succeeds for 5 min (black hole) |
| `RpingmeshSLAViolation` | warning | The analyzer flagged loss or p99-RTT SLA windows in the last 10 min |
| `RpingmeshProbeSendErrors` | warning | An agent keeps failing to post probes (local RNIC or driver) |
| `RpingmeshEventRingDrops` | warning | An agent dropped completion events, so its loss may be an artifact |
| `RpingmeshAgentSelfThrottled` | warning | Self-protection held the probe rate below 1× for 15 min |
| `RpingmeshAgentStoppedReporting` | critical | An agent reported 10–70 min ago but not in the last 10 min |
| `RpingmeshNoTelemetry` | critical | No probe metrics at all for 15 min |
| `RpingmeshAnalyzerNotIngesting` | warning | Agents probe but the analyzer ingests no summaries |

Choices worth recording:

- **Loss means timeouts, not "not success".** `invalid_rtt` is clock noise and
  `send_error` is local, so neither counts as fabric loss; send errors have
  their own rule. The analyzer's loss SLA differs slightly: it also excludes
  invalid RTTs, but counts every failed probe (including send errors) as
  lost.
- **No direct RTT alert.** The analyzer owns the RTT SLA
  (`analyzer_sla_network_rtt_p99_ns` in the controller config) and
  `RpingmeshSLAViolation` surfaces it, so the threshold lives in one place.
- **Agent identity is normalized.** Depending on the pipeline, the agent
  appears as `instance` (from `service.instance.id`) or `host.name` (resource
  attributes promoted to labels). Per-agent rules build an `agent` label with
  `label_join(..., "agent", "", "instance", "host.name")`, which yields
  whichever exists.
- **Stopped agents are detected by disappearance.** A series that existed
  10–70 minutes ago and has no sample in the last 10 minutes fires
  `RpingmeshAgentStoppedReporting`. `RpingmeshNoTelemetry` covers a
  fleet-wide outage.

The demo stack runs vmalert with `-notifier.blackhole`; a deployment points
`-notifier.url` at its Alertmanager. VictoriaMetrics proxies vmalert's rules
API (`-vmalert.proxyURL`), so Grafana lists the rules and their state through
the existing datasource.

## Decision 4: drilldown via data links

Drilldown is a Grafana **data link** from Mesh Overview to ToR Pair
Drilldown. It passes `var-source_tor` and `var-target_tor` in the URL and
preserves the time range.

A matrix built with *Grouping to matrix* has **dynamic column names** (each
header is a `target_tor` value), and its first field is named
`source_tor\target_tor`. A per-cell link that carries both coordinates would
have to reference that backslash-named field, which is fragile. The click path
is therefore the companion "Worst ToR pairs" table (and the SLA-by-pair
table), whose rows have stable `source_tor` and `target_tor` fields:

```
/d/rpingmesh-tor-pair/r-pingmesh-tor-pair-drilldown?var-source_tor=${__data.fields.source_tor}&var-target_tor=${__data.fields.target_tor}&${__url_time_range}
```

The matrix carries no links. The operator spots the hot cell and clicks the
same pair in the adjacent table.

## Alternatives considered

- **Native Table + Grouping to matrix vs the ESnet Matrix panel vs a custom
  plugin.** Chosen: native. *Grouping to matrix* with color-background cells
  produces a ToR × ToR loss grid with no plugin dependency and full
  provisioning portability. The ESnet Matrix panel offers better cell
  interaction but adds a plugin install to every Grafana and a
  version-compatibility surface. A custom panel plugin was rejected: its
  build, release, and maintenance cost is out of proportion to a colored grid.
- **Committed JSON vs Grafonnet / Foundation SDK.** Chosen: committed JSON. It
  needs no toolchain to review or provision and round-trips with Grafana's UI
  export. The cost is that hand-written JSON must match what the UI would
  emit; the mitigation is to build panels in the UI and export them.
- **Prometheus-type datasource vs the VictoriaMetrics datasource plugin.**
  Chosen: the Prometheus type (no plugin). VictoriaMetrics is
  Prometheus-API-compatible for instant and range queries and `label_values`,
  which is all these dashboards use.
- **Collector with `prometheus_remote_write` vs VictoriaMetrics native OTLP
  ingest.** Chosen: the collector. VictoriaMetrics can ingest OTLP at
  `/opentelemetry/v1/metrics`, but naming is then governed by VictoriaMetrics
  flags (`-opentelemetry.usePrometheusNaming` and related), whose defaults do
  not reproduce the pinned names and reintroduce the double-suffix risk. The
  collector keeps naming control in one reviewable setting
  (`translation_strategy`).
- **Dashboard `histogram_quantile` vs analyzer percentiles.** Quantiles from
  explicit buckets are interpolated within a bucket, so their resolution is
  the bucket width: 500 ns–1 µs below 10 µs, but 1.5 ms between 1 ms and
  2.5 ms. That is adequate for distribution shape and regressions, which is
  the dashboards' job, so panels label quantiles as approximate. The analyzer
  also estimates per-path p50/p99 from fixed buckets, but it evaluates the
  SLA per path (one RNIC pair) rather than per aggregated ToR pair, and
  dashboards surface its verdicts as counts instead of recomputing them.
- **Cardinality and query cost.** Series grow with ToR pairs times source
  RNICs (see [Estimating the series count](#estimating-the-series-count)),
  and the matrix query fans out over every pair on each refresh. Mitigations:
  the matrix uses one instant query over `$__range` rather than a range
  query; the companion table bounds its rows with `topk`; the heavy
  per-histogram queries live only on the drilldown, where template variables
  restrict them to one pair. The always-on Overview stays cheap.

## Verification strategy

The stack is validated end to end without RDMA hardware:

1. **Bring up the stack** (`make obs-up`): VictoriaMetrics,
   otel-collector-contrib, vmalert, and Grafana with the provisioned
   datasource and dashboards.
2. **Seed synthetic data** (`make obs-seed`): `seed-demo-metrics.sh`
   backfills ~30 min of a 6-ToR mesh through `/api/v1/import/prometheus`
   with per-line timestamps, so `rate()` and `histogram_quantile()` have
   enough points. The seed includes histogram buckets, success and failure
   counters split across two synthetic agents (to exercise the identity
   contract), two lossy pairs, one high-RTT pair, SLA-violation counters,
   the self-throttle gauge, and ring drops.
3. **Check Grafana health and provisioning** (`make obs-verify`, which runs
   `scripts/verify-observability.sh`): `GET /api/health` reports the
   database `ok`, and `GET /api/search` lists both dashboards.
4. **Check every panel query.** The script extracts every panel target and
   template variable from the committed JSON and runs it against
   VictoriaMetrics. Name-contract drift (for example, a reintroduced suffix)
   makes a query return nothing and fails the check.
5. **Check the alert rules.** The script evaluates every rule expression
   against the seed. Exactly the alerts the seed was built to trigger
   (`RpingmeshTorPairLoss` on the two lossy pairs and `RpingmeshSLAViolation`)
   must return series, and every other rule must stay quiet. It then checks
   that vmalert loaded all rules without evaluation errors. Running the check
   once per `NAME_STYLE` covers both metric-name styles.

## Future work

- **ESnet Matrix panel** as an opt-in enhancement once its Grafana-version
  compatibility is pinned and plugin provisioning is acceptable. It would
  allow reliable per-cell drilldown and remove the companion-table
  workaround.
- **Phase 2 localization view:** a third dashboard over the analyzer's
  path/segment attribution once those metrics exist
  (`analyzer-phase2-localization.md`).
- **Dashboards as code:** migrate to Grafonnet or the Foundation SDK if the
  board count grows or duplication between the two boards becomes costly.
- **Direct OTLP ingest:** drop the collector once VictoriaMetrics-side naming
  is shown to reproduce the pinned names.
