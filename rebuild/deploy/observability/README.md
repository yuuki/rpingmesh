# R-Pingmesh Observability Stack

A self-contained `docker compose` stack for developing and demoing the
Grafana dashboards in `rebuild/dashboards/` without any RDMA hardware. See
`rebuild/docs/design/grafana-dashboards.md` for the design rationale.

## Components

- **VictoriaMetrics** (`victoriametrics/victoria-metrics`) — Prometheus
  remote-write receiver and query backend.
- **otel-collector-contrib** — receives OTLP/gRPC metrics from the agent /
  analyzer and forwards them to VictoriaMetrics via `prometheusremotewrite`.
- **Grafana** — provisioned with the VictoriaMetrics datasource and the two
  `rebuild/dashboards/*.json` dashboards (zero custom plugins).

## Metric name contract

The `prometheusremotewrite` exporter is pinned to `add_metric_suffixes: false`
(`otel-collector/config.yaml`). This escapes `.` to `_` in OTLP metric names
but does **not** append `_total`/unit suffixes — the OTel instruments already
carry them (e.g. `rpingmesh.probe_total`, `rpingmesh.network_rtt_ns`). Using
the exporter's default settings instead would double up suffixes (e.g.
`rpingmesh_probe_total_total`) and silently break every dashboard panel.

Newer collector builds expose the same behavior as
`translation_strategy: UnderscoreEscapingWithoutSuffixes` instead of
`add_metric_suffixes` — the pinned version here
(`otel/opentelemetry-collector-contrib:0.117.0`) predates that option (its
`prometheusremotewriteexporter` config schema only has `add_metric_suffixes`;
confirmed against the exporter's `config.go` for that release). If you
upgrade the pinned image, prefer `translation_strategy` and never set both
on the same exporter.

This was verified end-to-end, not just via the seed script's direct
`/api/v1/import/prometheus` bypass: a real OTLP/HTTP push of
`rpingmesh.probe_total` through this collector produced exactly
`rpingmesh_probe_total` in VictoriaMetrics (not `rpingmesh_probe_total_total`),
with `job` correctly derived from the `service.name` resource attribute.

## Quick start

```bash
cd rebuild
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
