# AGENTS.md

## Rules
- No real environment identifiers (host, cluster or partition names, IPs, user names, local paths, allocation IDs) in any file, issue or PR; use synthetic ones.
- `legacy/` is a frozen, separate module: change it only when the task asks for legacy maintenance.
- Zig hands completions to Go only through the SPSC event ring, polled by its single Go consumer; never through Cgo callbacks.
- Keep the CQ arm-then-drain order in `zig/src/cq.zig` and the eventfd write in busy mode: a queue can fall back to busy while Go still waits on the fd.
- The responder never waits on a send completion (it would stall its event ring); a full event ring drops events, it never blocks.
- Metric attributes stay at ToR level plus the local RNIC; destination RNICs only on opt-in `rpingmesh.target_rnic.*`, service tracing on `rpingmesh.service.*`.
- Hardware and soft-RoCE tests skip without their hardware and tolerate failed probes; never make them required.
- As root without tracefs mounted, `TestTracerOpenClose` fails instead of skipping: mount tracefs or test unprivileged.

## Compatibility contracts
- Probe wire format: `zig/src/wire.zig` ↔ `SerializeProbePacket` in `internal/rdmabridge/bridge.go` (identical golden bytes).
- C ABI, no `bool`: `zig/include/rdma_bridge.h` ↔ `zig/src/main.zig` ↔ `internal/rdmabridge/bridge.go`.
- eBPF events: `struct qp_event` ↔ `DecodeEvent` (`internal/agent/servicetrace/event.go`); `servicetrace/bpf/uverbs_uapi.h` ↔ the kernel UAPI.
- gRPC API `proto/controller_agent/controller_agent.proto`: adjacent agent and controller versions interoperate.
- Registry schema, rqlite and PostgreSQL (`internal/controller/registry/`): columns are added by migration only (older controllers share the database).
- Metric names and attributes: `internal/telemetry/otel_metrics.go`, `internal/controller/analyzer/metrics.go`, queried by `dashboards/`.
- Configuration keys and defaults (`internal/config/`, `configs/`); `packaging/` (binary names, systemd units and capabilities, nfpm layout).

## Before opening a pull request
- `make check`; also `internal/agent/servicetrace/bpf/` → `make generate-bpf check-bpf`; `zig/` → `make build-zig test-zig build-agent`.
- `.proto` files → `make generate-proto`; parsers or decoders → `make test-fuzz FUZZTIME=1m`; dependencies → `make vuln`.
- Controller/agent gRPC path or registry → `make test-integration`, and the registry's PostgreSQL tests with `RPINGMESH_TEST_POSTGRES_URI` set; RDMA data path → `make test-e2e` (soft-RoCE).

## Git conventions
- Branches: `<type>/<issue>-<summary>` (`<type>/<summary>` without an issue); tools' `agent/*`, `claude/*`, `copilot/*`, `dependabot/*` keep their names.
- Commits and PR titles: Conventional Commits 1.0.0, types `feat` `fix` `perf` `refactor` `test` `docs` `build` `ci` `chore` `revert`; scopes: `agent`, `controller`, `servicetrace`, `rdmabridge`, `zig`, `telemetry`, `lldp`, `packaging`.
