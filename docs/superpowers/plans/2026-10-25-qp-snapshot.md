# Existing QP Recovery Implementation Plan

> **For agentic workers:** Execute inline and verify each deliverable.

**Goal:** Inventory existing user QPs through RDMA netlink, recover supported mlx5 RoCEv2 address vectors and probe those connections after agent startup.

**Architecture:** Keep traced context/handle entries separate from snapshot device/QPN resources. Generic dumps identify resources; validated mlx5 raw dumps supply address vectors. Per-device event generations and conservative invalidation prevent late snapshots from reviving changed connections. Background refreshes keep firmware queries outside the event/timer loop.

**Tech Stack:** Go 1.27.3, existing x/sys/unix, OpenTelemetry, Linux RDMA netlink and mlx5 PRM_QUERY_QP.

**Spec:** Issue #109 and docs/design/ebpf-service-tracing.md.

## Global Constraints

- English code comments and documentation; leave legacy and the eBPF ABI unchanged.
- Never fabricate uverbs handles or infer identities from a PID/remote-QPN match.
- Generic inventory requires no extra capability. Optional raw recovery requires CAP_NET_ADMIN and supported firmware; package the capability grant as an example only.
- Unknown formats, mismatches, missing privilege and unsupported drivers remain unbound. Physical mlx5 validation is explicitly separate from synthetic fixture tests.

## Task 1: Snapshot collection

**Files:** snapshot.go, snapshot_linux.go, snapshot_other.go and tests under internal/agent/servicetrace.

- [x] Decode nested device/QP attributes with strict framing and field checks.
- [x] Implement multipart dumps and single-resource queries with sequence/sender validation, truncation/error/interruption checks and native-endian attributes.
- [x] Bound generic callers to five seconds; isolate socket ownership in a process-wide single-flight worker so stalled kernel callbacks do not block shutdown or accumulate workers.
- [x] Verify malformed messages, optional fields, partial-dump rejection and a collector that ignores cancellation.

## Task 2: mlx5 recovery

**Files:** mlx5_snapshot.go, recovery.go, recovery_linux.go, recovery_other.go and tests.

- [x] Gate raw queries on the mlx5_core sysfs driver and include device index, port and local QPN in each request.
- [x] Validate BE resource framing, command/resource QPN echoes, INFO version, termination and supported 272/464-byte query-QP outputs.
- [x] Decode primary GID/label/source index/port/traffic class/SL/hop limit; verify connected state, transport, remote QPN, port and reproducible RoCEv2 UDP source port.
- [x] Query the generic owner/type/state after each raw read to reject QPN reuse. Keep TID and resolved owner TGID distinct.
- [x] Bound the separate recovery phase to thirty seconds; return validated partial results on ordinary per-QP errors and retain generic inventory on timeout.

## Task 3: Connections and lifecycle

**Files:** table.go, service_monitor.go and tests.

- [x] Store copied recovered connection values with FromSnapshot and zero context/handle. Exclude unresolved resources from Connections and probe targets.
- [x] Supersede an exact snapshot QPN on create/open. Invalidate snapshot connections by device after unidentified lifecycle events, without assuming TID equals TGID or that contexts cannot be shared.
- [x] Reject affected-device results after relevant events during collection, accept unchanged devices independently and exclude known UD/raw/driver churn from generations.
- [x] Run one background refresh per monitor, cancel/join callers on shutdown, reap exited owners and rebuild recovered service targets with their flow labels.
- [x] Verify recovered targets, lifecycle removal while recovery is stalled, QPN reuse, snapshot races and owner thread groups.

## Task 4: Diagnostics, packaging and documentation

**Files:** telemetry/otel_metrics.go and tests, README.md, docs/design/ebpf-service-tracing.md, packaging/nfpm/nfpm-agent.yaml, packaging/systemd/rpingmesh-agent.service.d/20-qp-recovery.conf, e2e/service_tracing_e2e_test.go.

- [x] Export service_qps_unbound by device only; recovered connections use existing connection/flow metrics without fabricated event counters or service identity.
- [x] Ship optional CAP_NET_ADMIN example; preserve existing live unit capabilities.
- [x] Document driver/firmware/namespace requirements, worker deadlines, event correlation limits and same-device churn delays.
- [x] Add real soft-RoCE inventory coverage and opt-in physical mlx5 recovery coverage.

## Validation

- macOS: go test -race ./internal/agent/servicetrace/ ./internal/telemetry/ passed.
- Linux/arm64: go test -race ./internal/agent/... ./internal/telemetry/... passed.
- Linux/arm64: go vet ./... and go build -o /tmp/rpingmesh-agent-issue109 ./cmd/agent/ passed.
- Linux/arm64 soft-RoCE: RDMA_E2E_ENABLED=1 go test -count=1 -v -timeout 60s -run '^TestServiceTracing' ./e2e/ passed three tests; the physical mlx5 case skipped because no hardware targets were configured.
- Linux/amd64 service-tracing tests cross-compiled. git diff --check passed.
- Independent review verified the decoder's upstream framing/offsets and identified cancellation, TID/TGID and global-generation problems. These were fixed and follow-up review reported no blocking findings.
- Adversarial review found that a user QP can outlive its creator task and lose the netlink PID. Kernel-name attributes now identify kernel resources independently; PID-less user QPs stay eligible for recovery, and unresolved task IDs cannot trigger process-exit reaping. The regression failed before the fix and portable race tests passed after it.
- Physical mlx5 raw capture/firmware behavior remains unverified in this environment. Run TestServiceTracingRecoversMlx5Connections with the documented device/peer/GID environment settings on suitable hardware before claiming hardware validation.
