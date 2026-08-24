# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

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
