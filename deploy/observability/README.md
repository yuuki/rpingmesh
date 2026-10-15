# R-Pingmesh Observability Stack

A self-contained Docker Compose stack for developing and demonstrating the
Grafana dashboards in `dashboards/` and the alert rules in `alerts/`, without
RDMA hardware. [`docs/design/grafana-dashboards.md`](../../docs/design/grafana-dashboards.md)
explains the design.

## Components

| Service | Role | Host port |
|---------|------|-----------|
| otel-collector-contrib | Receives OTLP metrics from agents and the analyzer and forwards them to VictoriaMetrics with `prometheus_remote_write` | 4317 (gRPC), 4318 (HTTP) |
| VictoriaMetrics | Stores the metrics and serves PromQL/MetricsQL queries | 8428 |
| vmalert | Evaluates `alerts/rpingmesh.rules.yml` every 30 s | 8880 |
| Grafana | Shows the two dashboards from the VictoriaMetrics data source, without custom plugins | 3000 |

vmalert sends notifications nowhere (`-notifier.blackhole`); point
`-notifier.url` at an Alertmanager in a real deployment. VictoriaMetrics proxies
the vmalert rules API, so Grafana can list the rules through its existing data
source.

## Quick start

From the repository root:

```bash
make obs-up       # start the stack; creates .env from .env.example if missing
make obs-seed     # load about 30 minutes of synthetic data for a 6-ToR mesh
make obs-verify   # check health, provisioning, every panel query, and the alert rules
make obs-logs     # follow the logs of all services
make obs-down     # stop the stack and delete its volumes
```

Open Grafana at <http://localhost:3000> (dashboards are in the "R-Pingmesh"
folder) and vmalert at <http://localhost:8880>.

The `admin`/`admin` Grafana login is for this local stack only. Image tags and
the Grafana credentials come from `.env`. `make obs-verify` reads the same
`.env` (located relative to the script, not the current directory), falls back
to `admin`/`admin`, and lets variables already exported in the shell take
precedence.

To send real telemetry to the stack, set `otel_collector_addr: localhost:4317`
in the agent configuration, and in the controller configuration for analyzer
metrics.

## Metric name contract

The dashboards and rules expect the OTLP instrument names with `.` replaced by
`_` and nothing appended. The instrument names already end in `_total` or a
unit (`rpingmesh.probe_total`, `rpingmesh.network_rtt_ns`), so an exporter that
adds its own suffixes produces names such as `rpingmesh_probe_total_total` and
every panel comes up empty.

The collector configuration (`otel-collector/config.yaml`) therefore sets
`translation_strategy: UnderscoreEscapingWithoutSuffixes` on the
`prometheus_remote_write` exporter. Collector releases older than that option
(for example 0.117.0) express the same behavior as `add_metric_suffixes:
false`, which is deprecated in the pinned 0.162.0. Never set both. The pinned
release also renamed the exporter type from `prometheusremotewrite`, which it
still accepts as a deprecated alias.

This contract was verified with a real OTLP/HTTP push, not only with the seed
script (which writes to VictoriaMetrics directly): `rpingmesh.probe_total`
arrived as `rpingmesh_probe_total`, and `job` was derived from the
`service.name` resource attribute.

`instance` is derived from the `service.instance.id` resource attribute, which
the agent sets to its hostname (`buildResource()` in
`internal/telemetry/otel_metrics.go`). Two agents that probe the same ToR pair
therefore produce separate series instead of one series whose `rate()` is
corrupted. See "Identity contract" in the design document.

## Dotted metric names

A pipeline that keeps OTLP names unescaped (UTF-8 mode) stores
`rpingmesh.probe_total` instead of `rpingmesh_probe_total`, and may label the
agent with `host.name` instead of `instance`. The dashboards and rules select
metrics with `{__name__=~"rpingmesh[._]..."}` and accept either agent label, so
they work unchanged. To test this locally, recreate the stack and seed it with
dotted names:

```bash
make obs-down && make obs-up
NAME_STYLE=dotted make obs-seed
```

Do not load both name styles into one VictoriaMetrics instance.
