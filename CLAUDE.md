# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language Standards

**All code comments and documentation must be in English.** This applies to `.go`, `.zig`, `.c`, `.md`, commit messages, and PR descriptions.

## Commands

Run all active-development commands from the repository root. The canonical Go
module is `github.com/yuuki/rpingmesh`.

### Building

```bash
make build           # Full pipeline: Zig library → protobuf codegen → Go binaries
make build-zig       # Build zig/zig-out/lib/librdmabridge.a only (requires Zig 0.17.0)
make generate-proto  # Regenerate protobuf Go bindings
make build-controller  # CGO_ENABLED=0, no Zig link
make build-agent       # CGO_ENABLED=1, links librdmabridge.a
make clean           # Remove bin/, dist/, zig/zig-out/, zig/.zig-cache/
```

After modifying `.proto` files: run `make generate-proto`. Generated `*.pb.go` files are not committed, so a fresh checkout also needs it before `build-controller`/`build-agent`. There is no eBPF code and no `make generate-bpf`.
After modifying Zig source in `zig/src/`: run `make build-zig` before `make build-agent`.

### Testing

```bash
make test                                       # go test on every pure-Go package (no Cgo, no RDMA hardware)
go test -v ./internal/probe/... -run TestName  # Run a specific test
go test -race ./internal/probe/...             # Run with race detector
make vet                                        # go vet ./...
make test-zig                                   # zig build test (needs libibverbs headers, not hardware)
make test-scripts                               # Python tests for scripts/topology/
make test-all                                   # test-zig + go test on all packages except ./e2e/... (Linux, full Cgo/RDMA build env)
```

`make test` covers every pure-Go package (`internal/probe`, `internal/config`, `internal/telemetry`, `internal/lldp`, `internal/logging`, `internal/buildinfo`, `internal/controller/...`, `internal/agent/controller_client`, `cmd/controller`); the controller packages need `make generate-proto` first. `internal/rdmabridge`, `internal/agent`, and `cmd/agent` need Cgo, libibverbs, and `librdmabridge.a` (the Linux environment of `make test-all`). `./e2e/...` is excluded from `test-all`; run it with `make test-e2e-controller` (Docker + rqlite) or `make test-e2e` (privileged Docker with soft-RoCE; on macOS run `make setup-colima` once).

## Architecture

R-Pingmesh is a clean-room redesign of the SIGCOMM 2024 R-Pingmesh system. It
keeps the paper's core concepts (6-timestamp probing, UD QP per RNIC,
ToR-mesh/inter-ToR pinglists, ECMP via flow_label) but implements the RDMA
data path as a Zig static library. The Phase 1 Analyzer is implemented;
topology-aware Phase 2 fault localization and eBPF service tracing are out of
scope.

**Components:**
- **Controller** (pure Go, `CGO_ENABLED=0`): manages agent registry in rqlite, distributes pinglists via gRPC.
- **Agent** (Go + Cgo, `CGO_ENABLED=1`): opens RDMA devices via the Zig bridge and runs one Prober, Responder, and ClusterMonitor per device, plus a shared metrics exporter, analysis reporter, and optional watchdog (`internal/agent/agent.go`).

### Key Design Choices Requiring Cross-File Understanding

**Ring buffer event delivery** — Zig's CQ poller thread writes `rdma_completion_event_t` into a lock-free SPSC ring buffer. Go polls via `rdma_event_ring_poll()` in a goroutine — never as a Cgo callback. This is why `EventRing` must be created *before* `Queue` and passed into `rdma_create_queue()`. The ring is shared between the Zig producer and Go consumer across `internal/rdmabridge/bridge.go` ↔ `zig/src/ring.zig`.

**Event-driven waits (`cq_poll_mode`)** — In event mode the CQ poller arms the CQ (`ibv_req_notify_cq`) *before* draining it and then sleeps in `poll()` on the queue's completion channel (`zig/src/cq.zig`); after a drained batch it writes the ring's `eventfd`, and the Go consumer blocks on a dup of that fd via the netpoller (`RingWaiter` in `internal/rdmabridge/ring_waiter.go`, `newRingIdleWait` in `internal/agent/ring_wait.go`). Busy mode is the old poll-based design on both sides (~50 µs nanosleep in Zig, 100 µs timer in Go). `auto` = event with HW timestamps, busy with SW timestamps, because SW timestamps are taken at poll time and absorb wakeup latency. Keep the arm-then-drain order and keep notifying the eventfd in busy mode (a queue can fall back from event to busy at runtime while its Go consumer still waits on the fd).

**40-byte BigEndian wire format** — The probe packet uses explicit BigEndian serialization (no packed structs). Zig (`serializeProbePacket`/`deserializeProbePacket` in the leaf module `zig/src/wire.zig`, shared by `packet.zig` and `cq.zig`) and Go (`SerializeProbePacket`/`DeserializeProbePacket` in `internal/rdmabridge/bridge.go`) implement it independently, and `internal/agent/responder.go` interprets the decoded fields; keep all three in sync. A version byte at offset 0 enables future format changes.

**Asynchronous ACK pair** — The responder answers a probe with `rdma_send_ack_pair()` (`Queue.SendAckPair`), which stages both ACKs in one send slot (second ACK at `SECOND_ACK_SLOT_OFFSET`), posts the first, and returns. The slot's `SendSlotMode` (`zig/src/types.zig`) tells the CQ poller what to do on completion: `AsyncFirstAck` → stamp the completion timestamp as T4 into the staged second ACK (`WIRE_T4_OFFSET`) and post it on the same slot and AH after the poll session ends (`flushPendingSecondAcks` in `zig/src/cq.zig`); `AsyncSecondAck` → reclaim; `Sync` → the mailbox for `waitSendCompletion` (probes, and the synchronous `rdma_send_first_ack`/`rdma_send_second_ack` the raw e2e test uses). Async completions never touch the mailbox, so the single-sender mailbox contract still holds for synchronous sends. The CQ poller and the responder goroutine both call `ibv_post_send` on the responder QP, which relies on libibverbs' default thread safety (no thread domain, no provider single-thread mode). Never make the responder wait on a send completion again: a slow completion would stall its event ring.

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
| `memory.zig` | Buffer allocation, `ibv_reg_mr()`, recv posting, `postUdSend` (shared by packet.zig and the CQ poller's second ACK) |
| `cq.zig` | CQ poller thread (event mode via completion channel, busy-poll fallback), GRH parsing, `ibv_wc_read_completion_wallclock_ns`, SW fallback, second-ACK posting of async ACK pairs |
| `ring.zig` | Lock-free SPSC ring buffer for Zig→Go event delivery, eventfd consumer notification, max-occupancy high-water mark |
| `wire.zig` | Leaf module: the 40-byte BigEndian probe/ACK codec, field offsets, `MSG_TYPE_*`/`ACK_TYPE_*` |
| `packet.zig` | Probe and ACK sends (sync, and the async `sendAckPair`), send slots and the completion mailbox |
| `main.zig` | C-ABI entry points (`export fn`), test entry |
| `last_error.zig` | Thread-local last-error string returned by `rdma_get_last_error()` |
| `c.h` | C headers translated into the `c` module by `build.zig` (TranslateC; Zig 0.16+ has no `@cImport`) |

### 6-Timestamp Protocol

| Timestamp | Source | Where captured |
|-----------|--------|----------------|
| T1 | Zig `clock_gettime(CLOCK_MONOTONIC)` just before `ibv_post_send` | `zig/src/packet.zig` |
| T2 | NIC HW send completion (SW fallback: MONOTONIC) | `zig/src/cq.zig` |
| T3 | Responder NIC HW recv completion | `zig/src/cq.zig` on responder |
| T4 | Responder NIC HW first-ACK send completion | `zig/src/cq.zig` on responder |
| T5 | Prober NIC HW first-ACK recv completion | `zig/src/cq.zig` on prober |
| T6 | Go `CLOCK_MONOTONIC` via `unix.ClockGettime()` when second ACK is processed | `internal/agent/prober.go` |

Metrics: `NetworkRTT = (T5-T2)-(T4-T3)`, `ProberDelay = (T6-T1)-(T5-T2)`, `ResponderDelay = T4-T3`.

## Configuration

Default config files are in `configs/`. Both binaries use Viper with precedence CLI flag > env var > YAML > default; without `--config` they search `.`, `$HOME/.rpingmesh`, and `/etc/rpingmesh`. README.md documents every key.

- `configs/agent.yaml`: `probe_interval_ms: 500`, `gid_index: 0`, `cq_poll_mode: auto`, `event_ring_capacity: 1024`, `controller_addr: localhost:50051`, `otel_collector_addr: localhost:4317`
- `configs/controller.yaml`: `listen_addr: :50051`, `database_uri: http://localhost:4001`

Configuration fields can be overridden with the `RPINGMESH_` prefix and
uppercase, underscore-separated field names (for example,
`RPINGMESH_CONTROLLER_ADDR`, `RPINGMESH_DATABASE_URI`, and
`RPINGMESH_LOG_LEVEL`).

## Development Patterns

- Logging: `github.com/rs/zerolog` (not standard `log`). GID-level probe detail goes to Debug logs only — never as OTel metric attributes (cardinality).
- OTel metric attributes: `source_tor` and `target_tor` (ToR-level aggregation, not per-GID), plus the local RNIC on agent probe metrics (`source_rdma_device`, `source_netdev`; bounded by the RNICs per host). Destination-RNIC identity (`target_hostname`, `target_rdma_device`, `target_netdev`) goes only to the separate opt-in `rpingmesh.target_rnic.*` instruments (`metrics_target_rnic_labels`, `telemetry.WithTargetRnicLabels`), never to the default instruments, so their cardinality cannot overflow the ToR-level series. Never use GIDs or IPs as attributes.
- gRPC client: use `grpc.NewClient()` (not the deprecated `grpc.Dial`).
- C-ABI types: no `bool` — use `uint8_t` (0/1). GIDs are always `rdma_gid_t` (16-byte binary); string conversion only at display/config boundaries.
- ECMP path diversity: controlled via `flow_label` in `ibv_ah_attr.grh.flow_label`. The `source_port` field in `PingTarget` is metadata only — RoCEv2 UD UDP source port is driver-generated and cannot be set directly.
- `legacy/` is an archived, separate Go module. Do not modify it unless a task
  explicitly requests legacy maintenance.

## Requirements

- Go 1.27.2+
- Zig 0.17.0 (pinned in `mise.toml`, `.github/workflows/`, `Dockerfile.e2e`, `docker-compose.e2e.yml`)
- protoc, protoc-gen-go, protoc-gen-go-grpc
- libibverbs-dev, librdmacm-dev (Linux only; for agent build and RDMA testing)
- rqlite (for controller and integration tests)
