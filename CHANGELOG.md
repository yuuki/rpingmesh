# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Changed

- Require Go 1.27.1 or later and Zig 0.17.0 (the Zig library now gets its C
  bindings from a build-system TranslateC step, since Zig 0.16 removed
  `@cImport`).
- Update Go module dependencies (OpenTelemetry 1.47.0, gRPC 1.84.0, and
  others), build/runtime images to Debian trixie, and the e2e rqlite image to
  10.5.2.
- Update the observability demo stack to Grafana 13.2.3, VictoriaMetrics
  1.153.0, and otel-collector-contrib 0.162.0; the collector config now uses
  the `prometheus_remote_write` exporter with `translation_strategy`.
- `make build-zig` builds `librdmabridge.a` in ReleaseSafe (previously Debug,
  because `preferred_optimize_mode` only applies with `--release`).
- The RTT/delay histograms use a denser bucket ladder in 1–10 µs, where
  RoCEv2 network RTTs typically land, and are a superset of the analyzer's
  aggregation buckets. Dashboards keep working; quantiles become finer.
- The OTel resource also carries `host.name`, so collector pipelines that drop
  `service.instance.id` still keep agents on distinct series.

### Fixed

- Release agent binaries are linked inside an Enterprise Linux 9 container, so
  they run on glibc 2.34+ (RHEL 9 family) instead of requiring the newer glibc
  of the CI runner. `make package-build-agent-el9` (or
  `AGENT_BUILDER=el9` with `make package`/`make archive`) builds the same
  portable binary, and the build fails if the glibc floor is exceeded.
- Link `librdmabridge.a` with older system linkers (e.g. GNU ld 2.35 on
  RHEL 9): always emit it through LLVM and bundle compiler-rt.
- The agent's default `otel_collector_addr` was `grpc://localhost:4317`, which
  the OTLP exporter cannot dial, so metrics were silently never exported
  without an explicit setting. The default is now `localhost:4317`, and both
  agent and controller reject an address with a URL scheme at startup.
- After a peer agent restarts (new responder QPN), probers no longer report
  100% loss to it until the next pinglist update (default 300 s): a streak of
  ACK timeouts to a target triggers an early, backed-off pinglist refresh, and
  an empty pinglist is retried early as well.

## [0.2.1] - 2026-08-24

### Changed

- Require Go 1.27.0 or later for building the agent and controller.

## [0.2.0] - 2026-08-24

### Changed

- `tor_id` is optional. Unset agents register into an empty-ToR virtual rack,
  emit the OTel/PathSummary label `unspecified`, and have their ToR-mesh capped
  by `unspecified_mesh_max_targets` (default 32). Agents refuse to start with
  the reserved `tor_id` `unspecified`. Upgrade the controller before agents;
  inventory any existing ToR actually named `unspecified` first. Rolling back
  the controller rejects empty `tor_id` again and also restores an uncapped
  empty-ToR mesh for remaining empty rows — drain untagged agents before
  rollback.

### Fixed

- Wait for prober loops after context cancel so Stop cannot destroy a queue
  while SendProbe or a ring poll is still running.
- Keep UD address handles until send completion, publish send-slot handles
  atomically, and skip destroying them if QP destroy fails.
- Cap analyzer summaries per window so a stuck `window_start` cannot grow
  without bound.
- Drop short or version-mismatched RDMA recv completions instead of parsing
  stale slot bytes.
- Read Zig `last_error` on the same OS thread as the failing Cgo call, and
  record an error when event-ring allocation fails.
- Fail startup when an explicit `--config` file is missing, and require
  `stale_threshold_sec >= active_threshold_sec`.
- Run Go unit tests with the race detector in CI, and fail RDMA e2e only when
  soft-RoCE actually loaded.

## [0.1.1] - 2026-07-28

### Added

- Linux/amd64 `.tar.gz` archives containing the agent and controller binaries
  for installations that do not use a system package manager; both are covered
  by the release `checksums.txt` file.

## [0.1.0] - 2026-07-28

### Added

- Initial public release of the R-Pingmesh RDMA network monitoring system.
- Controller-managed ToR-mesh and inter-ToR probe target distribution over gRPC.
- Linux system packages for the agent and controller in `.deb` and `.rpm` formats.
- OpenTelemetry metrics and Grafana dashboards for mesh health and probe analysis.

### Requirements

- The controller runs on Linux and requires access to its configured rqlite
  endpoint.
- The agent requires Linux, an RDMA-capable RoCE device or soft-RoCE device,
  and the runtime `libibverbs` and `librdmacm` libraries.
- The packaged agent service needs access to `/dev/infiniband/*` through the
  system `rdma` group.

### Known limitations

- GitHub-hosted runners cannot reliably load the soft-RoCE kernel module, so
  the RDMA end-to-end test remains best-effort in CI.
- Topology-aware Phase 2 fault localization and eBPF service tracing are not
  included in this release.
