# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language Standards

**All code comments and documentation must be in English.** This applies to `.go`, `.zig`, `.c`, `.md`, commit messages, and PR descriptions.

## Commands

All commands must be run from within the `rebuild/` directory. This is a separate Go module (`github.com/yuuki/rpingmesh/rebuild`).

### Building

```bash
make build           # Full pipeline: Zig library → protobuf codegen → Go binaries
make build-zig       # Build zig/zig-out/lib/librdmabridge.a only (requires Zig 0.16+)
make generate-proto  # Regenerate protobuf Go bindings
make build-controller  # CGO_ENABLED=0, no Zig link
make build-agent       # CGO_ENABLED=1, links librdmabridge.a
make clean           # Remove bin/ and zig-out/ .zig-cache/
```

After modifying `.proto` files: run `make generate-proto` (there is no eBPF; `make generate-bpf` does not exist here).
After modifying Zig source in `zig/src/`: run `make build-zig` before `make build-agent`.

### Testing

```bash
make test                                       # go test -v ./internal/probe/... (pure Go, no RDMA hardware needed)
go test -v ./internal/probe/... -run TestName  # Run a specific test
go test -race ./internal/probe/...             # Run with race detector
```

The `internal/probe/` package is the only package with tests that run without RDMA hardware. Tests requiring actual RDMA devices or soft-RoCE must be run on Linux with the appropriate hardware.

## Architecture

R-Pingmesh rebuild is a clean-room redesign of the SIGCOMM 2024 R-Pingmesh system. It keeps the paper's core concepts (6-timestamp probing, UD QP per RNIC, ToR-mesh/inter-ToR pinglists, ECMP via flow_label) but replaces the Go/Cgo RDMA data-path with a Zig static library. The Analyzer and eBPF components are out of scope.

**Components:**
- **Controller** (pure Go, `CGO_ENABLED=0`): manages agent registry in rqlite, distributes pinglists via gRPC.
- **Agent** (Go + Cgo, `CGO_ENABLED=1`): opens RDMA devices via the Zig bridge, runs the Prober and Responder, fetches pinglists from the controller, exports OTel metrics.

### Key Design Choices Requiring Cross-File Understanding

**Ring buffer event delivery** — Zig's CQ poller thread writes `rdma_completion_event_t` into a lock-free SPSC ring buffer. Go polls via `rdma_event_ring_poll()` in a goroutine — never as a Cgo callback. This is why `EventRing` must be created *before* `Queue` and passed into `rdma_create_queue()`. The ring is shared between the Zig producer and Go consumer across `internal/rdmabridge/bridge.go` ↔ `zig/src/ring.zig`.

**40-byte BigEndian wire format** — The probe packet uses explicit BigEndian serialization (no packed structs). The format is defined in `zig/src/packet.zig` and must stay in sync with `internal/probe/types.go`. Both sides implement independent `serialize`/`deserialize` functions. A version byte at offset 0 enables future format changes.

**Sequence number format** — `high 32 bits = random agentEpoch | low 32 bits = monotonic counter`. The epoch is randomised on startup to prevent ACK misrouting after agent restarts. Defined in `internal/agent/prober.go`.

**`ControllerClient` interface** — `internal/agent/cluster_monitor.go` depends on the interface, not the concrete gRPC client. The concrete `GRPCControllerClient` lives in `internal/agent/controller_client/`. This separation enables mock injection in tests.

**HW timestamp fallback** — `zig/src/queue.zig` first tries `IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK`; on `EOPNOTSUPP` it retries without it. The `uses_sw_timestamps` field in `rdma_queue_info_t` (uint8, not bool for ABI safety) signals the mode to Go.

### Zig Library (`zig/src/`)

The Zig library exposes a C-ABI defined in `zig/include/rdma_bridge.h`. The Go bridge in `internal/rdmabridge/bridge.go` calls it via Cgo.

| File | Responsibility |
|------|----------------|
| `types.zig` | Core types: `RdmaContext`, `RdmaDevice`, `UdQueue`, GID as `[16]u8` |
| `device.zig` | Device discovery, `ibv_open_device`, GID query, IP extraction |
| `queue.zig` | UD QP creation, INIT→RTR→RTS, AH via `ibv_create_ah()`, HW timestamp probe |
| `memory.zig` | Buffer allocation, `ibv_reg_mr()`, 32-slot tracking |
| `cq.zig` | CQ polling thread, `ibv_wc_read_completion_wallclock_ns`, SW fallback |
| `ring.zig` | Lock-free SPSC ring buffer for Zig→Go event delivery |
| `packet.zig` | Probe/ACK BigEndian serialization, send/recv, GRH parsing |
| `main.zig` | `@export` C-ABI entry points, thread-local error string |

### 6-Timestamp Protocol

| Timestamp | Source | Where captured |
|-----------|--------|----------------|
| T1 | Zig `clock_gettime(CLOCK_MONOTONIC)` just before `ibv_post_send` | `zig/src/packet.zig` |
| T2 | NIC HW send completion (SW fallback: MONOTONIC) | `zig/src/cq.zig` |
| T3 | Responder NIC HW recv completion | `zig/src/cq.zig` on responder |
| T4 | Responder NIC HW first-ACK send completion | `zig/src/cq.zig` on responder |
| T5 | Prober NIC HW first-ACK recv completion | `zig/src/cq.zig` on prober |
| T6 | Go `time.Now().UnixNano()` when second ACK is processed | `internal/agent/prober.go` |

Metrics: `NetworkRTT = (T5-T2)-(T4-T3)`, `ProberDelay = (T6-T1)-(T5-T2)`, `ResponderDelay = T4-T3`.

## Configuration

Default config files are in `configs/`. All components use Viper (YAML + env vars + CLI flags).

- `configs/agent.yaml`: `probe_interval_ms: 500`, `gid_index: 0`, `controller_addr: localhost:50051`, `otel_collector_addr: localhost:4317`
- `configs/controller.yaml`: `listen_addr: :50051`, `database_uri: http://localhost:4001`

Environment variables: `RQLITE_DB_URI` for controller database connection.

## Development Patterns

- Logging: `github.com/rs/zerolog` (not standard `log`). GID-level probe detail goes to Debug logs only — never as OTel metric attributes (cardinality).
- OTel metric attributes: `source_tor` and `target_tor` only (ToR-level aggregation, not per-GID).
- gRPC client: use `grpc.NewClient()` (not the deprecated `grpc.Dial`).
- C-ABI types: no `bool` — use `uint8_t` (0/1). GIDs are always `rdma_gid_t` (16-byte binary); string conversion only at display/config boundaries.
- ECMP path diversity: controlled via `flow_label` in `ibv_ah_attr.grh.flow_label`. The `source_port` field in `PingTarget` is metadata only — RoCEv2 UD UDP source port is driver-generated and cannot be set directly.

## Requirements

- Go 1.26+
- Zig 0.16+
- protoc, protoc-gen-go, protoc-gen-go-grpc
- libibverbs-dev, librdmacm-dev (Linux only; for agent build and RDMA testing)
- rqlite (for controller and integration tests)
