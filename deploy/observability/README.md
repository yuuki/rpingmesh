# R-Pingmesh Observability Stack

A self-contained `docker compose` stack for developing and demoing the
Grafana dashboards in `dashboards/` without any RDMA hardware. See
`docs/design/grafana-dashboards.md` for the design rationale.

## Components

- **VictoriaMetrics** (`victoriametrics/victoria-metrics`) — Prometheus
  remote-write receiver and query backend.
- **otel-collector-contrib** — receives OTLP/gRPC metrics from the agent /
  analyzer and forwards them to VictoriaMetrics via `prometheus_remote_write`.
- **Grafana** — provisioned with the VictoriaMetrics datasource and the two
  `dashboards/*.json` dashboards (zero custom plugins).

## Metric name contract

The `prometheus_remote_write` exporter is pinned to
`translation_strategy: UnderscoreEscapingWithoutSuffixes`
(`otel-collector/config.yaml`). This escapes `.` to `_` in OTLP metric names
but does **not** append `_total`/unit suffixes — the OTel instruments already
carry them (e.g. `rpingmesh.probe_total`, `rpingmesh.network_rtt_ns`). Using
the exporter's default settings instead would double up suffixes (e.g.
`rpingmesh_probe_total_total`) and silently break every dashboard panel.

Collector releases before `translation_strategy` existed (e.g. 0.117.0) express
the same behavior as `add_metric_suffixes: false`; that option is deprecated in
the pinned version (`otel/opentelemetry-collector-contrib:0.162.0`), which also
renamed the exporter type from `prometheusremotewrite` (still accepted as a
deprecated alias). Never set both suffix options on the same exporter.

This was verified end-to-end, not just via the seed script's direct
`/api/v1/import/prometheus` bypass: a real OTLP/HTTP push of
`rpingmesh.probe_total` through this collector produced exactly
`rpingmesh_probe_total` in VictoriaMetrics (not `rpingmesh_probe_total_total`),
with `job` correctly derived from the `service.name` resource attribute.

`instance` is likewise derived from the OTel resource's `service.instance.id`
(`internal/telemetry/otel_metrics.go`'s `buildResource()` sets it to
`os.Hostname()`), so multiple agent processes covering the same ToR pair get
distinct series instead of colliding onto one and corrupting `rate()`. See
"Identity contract" in `docs/design/grafana-dashboards.md` for the
full rationale and verification.

## Quick start

```bash
cd /path/to/rpingmesh
make obs-up        # start VictoriaMetrics + otel-collector + Grafana (localhost:3000, admin/admin)
make obs-seed       # load ~30 min of synthetic 6-ToR mesh demo data
open http://localhost:3000  # dashboards live under the "R-Pingmesh" folder
make obs-verify     # (optional) assert health, provisioning, and panel queries
make obs-down       # stop the stack and remove volumes
```

`admin`/`admin` is the default Grafana credential for this local demo stack
only — **never use it in production**. Pin the image tags in
`.env` (copy from `.env.example`) before relying on this stack long-term.
If you change `GF_SECURITY_ADMIN_USER`/`GF_SECURITY_ADMIN_PASSWORD` in
`.env`, `make obs-verify` picks up the same values automatically —
`scripts/verify-observability.sh` reads `deploy/observability/.env` itself
(resolved from the script's own location, not the caller's cwd), falling
back to `admin`/`admin` if the file or the variables are absent. Env vars
already exported when you invoke the script take priority over `.env`.

## Connecting real telemetry

To point a real agent/analyzer at this stack instead of the seed script, set
`otel_collector_addr: localhost:4317` in `configs/agent.yaml` (or the
equivalent analyzer config) so OTLP/gRPC metrics land on this collector.
