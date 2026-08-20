# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Changed

- `tor_id` is optional. Unset agents register into an empty-ToR virtual rack,
  emit the OTel/PathSummary label `unspecified`, and have their ToR-mesh capped
  by `unspecified_mesh_max_targets` (default 32). Agents refuse to start with
  the reserved `tor_id` `unspecified`. Upgrade the controller before agents;
  inventory any existing ToR actually named `unspecified` first. Rolling back
  the controller rejects empty `tor_id` again and also restores an uncapped
  empty-ToR mesh for remaining empty rows — drain untagged agents before
  rollback.

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
