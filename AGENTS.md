# AGENTS.md

Guide for coding agents (and humans) working in this repository. It is the
canonical, tool-neutral source; `CLAUDE.md` only imports it. The user-facing
documentation is [README.md](README.md); design notes live in `docs/design/`.

**All code comments and documentation must be in English.** This applies to
`.go`, `.zig`, `.c`, `.py`, `.md`, commit messages and PR descriptions.

Never include real environment identifiers or machine-specific operational
details in code comments, documentation, issues or PRs: hostnames, IP
addresses, cluster or partition names, usernames, local paths, allocation IDs
and access routes. Use generic descriptions or synthetic examples; keep
actual validation-environment details out of Git.

## 1. Overview and architecture

R-Pingmesh is a clean-room redesign of the SIGCOMM 2024 R-Pingmesh system. It
keeps the paper's core concepts (6-timestamp probing, one UD QP per RNIC,
ToR-mesh/inter-ToR pinglists, ECMP via flow_label, eBPF service tracing) but
implements the RDMA data path as a Zig static library. The Phase 1 Analyzer
and service tracing are implemented; topology-aware Phase 2 fault
localization is out of scope (`docs/design/analyzer-phase2-localization.md`).
The canonical Go module is `github.com/yuuki/rpingmesh`.

Components:

- **Controller** (pure Go, `CGO_ENABLED=0`, `cmd/controller`): keeps the agent
  and RNIC registry in rqlite, distributes pinglists over gRPC, runs the
  Phase 1 analyzer on the agents' path summaries, and resolves the remote
  RNICs of traced service flows (`GetTargetRnicInfo`).
- **Agent** (Go + Cgo, `CGO_ENABLED=1`, `cmd/agent`): opens RDMA devices via the
  Zig bridge and runs one Prober, Responder and ClusterMonitor per device,
  plus a shared metrics exporter (OTLP), analysis reporter, optional watchdog
  (self-protection) and optional service monitor (`internal/agent/agent.go`).
- **Service tracing** (`internal/agent/servicetrace`,
  `internal/agent/service_monitor.go`; Linux only, opt-in via
  `service_tracing_enabled`): an eBPF tracer of application queue pairs whose
  connections become `SERVICE_TRACING` probe targets, each probed with the
  flow's own flow label (see "Service tracing" in section 7).
- **Zig RDMA bridge** (`zig/`): `librdmabridge.a` with the C ABI in
  `zig/include/rdma_bridge.h`, called from `internal/rdmabridge/bridge.go`.

Data flow: the controller's pinglists → each agent's ClusterMonitor → Prober
(UD probe via the Zig bridge) → remote Responder (ACK pair) → CQ poller thread
(Zig) → SPSC event ring → Go ring loop → `probe.ProbeResult` → metrics
(OTLP) and the analysis reporter → controller analyzer.

### 6-timestamp protocol

| Timestamp | Source | Where captured |
|-----------|--------|----------------|
| T1 | Zig `clock_gettime(CLOCK_MONOTONIC)` just before `ibv_post_send` | `zig/src/packet.zig` |
| T2 | NIC HW send completion (SW fallback: MONOTONIC) | `zig/src/cq.zig` |
| T3 | Responder NIC HW recv completion | `zig/src/cq.zig` on responder |
| T4 | Responder NIC HW first-ACK send completion | `zig/src/cq.zig` on responder |
| T5 | Prober NIC HW first-ACK recv completion | `zig/src/cq.zig` on prober |
| T6 | Go `CLOCK_MONOTONIC` via `unix.ClockGettime()` when the second ACK is processed | `internal/agent/prober.go` |

`NetworkRTT = (T5-T2)-(T4-T3)`, `ProberDelay = (T6-T1)-(T5-T2)`,
`ResponderDelay = T4-T3` (`probe.CalculateRTT`, which also rejects
missing, negative and implausibly large values).

### Key design choices requiring cross-file understanding

- **Ring buffer event delivery.** Zig's CQ poller thread writes
  `rdma_completion_event_t` into a lock-free SPSC ring buffer. Go polls via
  `rdma_event_ring_poll()` in a goroutine, never as a Cgo callback. This is
  why `EventRing` must be created *before* `Queue` and passed into
  `rdma_create_queue()`. The ring is shared between
  `internal/rdmabridge/bridge.go` and `zig/src/ring.zig`.
- **Event-driven waits (`cq_poll_mode`).** In event mode the CQ poller arms
  the CQ (`ibv_req_notify_cq`) *before* draining it and then sleeps in
  `poll()` on the queue's completion channel (`zig/src/cq.zig`); after a
  drained batch it writes the ring's `eventfd`, and the Go consumer blocks on
  a dup of that fd via the netpoller (`RingWaiter` in
  `internal/rdmabridge/ring_waiter.go`, `newRingIdleWait` in
  `internal/agent/ring_wait.go`). Busy mode is the poll-based design on both
  sides (~50 µs nanosleep in Zig, 100 µs timer in Go). `auto` = event with HW
  timestamps, busy with SW timestamps, because SW timestamps are taken at
  poll time and absorb wakeup latency. Keep the arm-then-drain order and keep
  notifying the eventfd in busy mode (a queue can fall back from event to
  busy at runtime while its Go consumer still waits on the fd).
- **Asynchronous ACK pair.** The responder answers a probe with
  `rdma_send_ack_pair()` (`Queue.SendAckPair`), which stages both ACKs in one
  send slot (second ACK at `SECOND_ACK_SLOT_OFFSET`), posts the first, and
  returns. The slot's `SendSlotMode` (`zig/src/types.zig`) tells the CQ
  poller what to do on completion: `AsyncFirstAck` → stamp the completion
  timestamp as T4 into the staged second ACK (`wire.OFFSET_T4`) and post it
  on the same slot and AH after the poll session ends
  (`flushPendingSecondAcks` in `zig/src/cq.zig`); `AsyncSecondAck` →
  reclaim; `Sync` → the mailbox for `waitSendCompletion` (probes;
  `rdma_send_probe` is the only synchronous send left). Async completions
  never touch the mailbox, so the single-sender mailbox contract still holds
  for probes. The CQ poller and the responder goroutine both call
  `ibv_post_send` on the responder QP, which relies on libibverbs' default
  thread safety (no thread domain, no provider single-thread mode). Never
  make the responder wait on a send completion again: a slow completion
  would stall its event ring.
- **Sequence numbers.** `high 32 bits = random agentEpoch | low 32 bits =
  monotonic counter` (`internal/agent/prober.go`). The epoch is randomised on
  startup to prevent ACK misrouting after agent restarts.
- **`ControllerClient` interface.** `internal/agent/cluster_monitor.go`
  depends on the interface, not the concrete gRPC client; the concrete
  `GRPCControllerClient` lives in `internal/agent/controller_client/`. This
  separation enables mock injection in tests.
- **HW timestamp fallback.** `zig/src/queue.zig` first tries
  `IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK`; on `EOPNOTSUPP` it retries
  without it. The `uses_sw_timestamps` field in `rdma_queue_info_t` (uint8,
  not bool, for ABI safety) signals the mode to Go.
- **ECMP path diversity** is controlled via `flow_label` in
  `ibv_ah_attr.grh.flow_label`. The `source_port` field of `PingTarget` is
  deprecated metadata: the RoCEv2 UD UDP source port is driver-generated and
  cannot be set directly.

## 2. Directory layout

- `cmd/agent`, `cmd/controller`: binary entry points (cobra + Viper).
  `cmd/dc-trace`: experimental, Linux-only, pure-Go DC submission diagnostics
  (`make build-dc-trace`); not packaged.
- `internal/`:
  - `agent/`: probing, responding, controller synchronization, analysis
    reporting, device watch, watchdog, service monitor;
    `agent/controller_client/` is the gRPC client; `agent/servicetrace/` is
    the eBPF tracer (programs under `bpf/`, committed bpf2go objects
    `*_bpfel.{go,o}`), the connection table and the kernel dump decoders.
  - `buildinfo/`: the version stamped at build time.
  - `config/`: YAML, environment and CLI configuration (Viper).
  - `controller/`: the gRPC service and input validation; `registry/`
    (rqlite), `pinglist/` (generation, ECMP flow labels), `analyzer/`
    (Phase 1 SLO analyzer).
  - `lldp/`: per-RNIC ToR IDs from LLDP neighbors (`lldpcli -f json0`).
  - `logging/`: zerolog setup.
  - `probe/`: probe results, RTT calculation, per-path aggregation, flow-label
    generation, rate limiting, GID parsing.
  - `rdmabridge/`: the Go/Cgo boundary to the Zig library.
  - `telemetry/`: OpenTelemetry metrics and the OTLP exporter.
  - `testutil/`: shared test helpers (OTel readers, OTLP test server, TLS
    certificates).
- `zig/`: the RDMA data-path library (`src/`, C ABI in `include/`).
- `proto/controller_agent/`: gRPC sources; generated `*.pb.go` files are
  written beside them and are not committed.
- `configs/`: example agent and controller configuration.
- `e2e/`: controller (Docker + rqlite) and RDMA (soft-RoCE) end-to-end tests.
- `packaging/`: nfpm definitions and systemd units (with drop-ins for service
  tracing and QP recovery).
- `dashboards/`, `deploy/observability/`: Grafana dashboards and the local
  observability stack.
- `scripts/`: e2e, observability, release, glibc-floor, and multi-rail
  topology and QoS facts helpers (`scripts/topology/`, stdlib-only Python).
- `docs/design/`: design documentation.
- `legacy/`: the archived first-generation implementation, a separate, frozen
  Go module (own `go.mod`, covered by `legacy-test.yml`).

### Zig library (`zig/src/`)

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

## 3. Build

Run every command from the repository root. Requirements: Go 1.27.3 (go.mod;
`mise.toml`), Zig 0.17.0 (pinned in `mise.toml`, `.github/workflows/`,
`Dockerfile.e2e`, `Dockerfile.agent-el9` and `docker-compose.e2e.yml`),
`protoc` with `protoc-gen-go` and `protoc-gen-go-grpc` (`make
install-protoc-plugins` installs the pinned plugins), and on Linux
`libibverbs-dev` and `librdmacm-dev`. `make generate-bpf`/`make check-bpf`
need clang 14+ with the BPF backend; on macOS set
`BPF2GO_CC=/opt/homebrew/opt/llvm/bin/clang BPF2GO_STRIP=/opt/homebrew/opt/llvm/bin/llvm-strip`.
The controller is pure Go and has no RDMA dependency; it needs rqlite at
runtime (and for the controller integration tests). Agent builds need Linux,
Cgo, libibverbs and librdmacm; running the agent and the RDMA e2e tests
additionally needs RDMA hardware or privileged soft-RoCE.

```sh
make build             # Zig library → protobuf codegen → both binaries
make build-zig         # zig/zig-out/lib/librdmabridge.a only
make generate-proto    # protobuf/gRPC bindings (not committed)
make build-controller  # CGO_ENABLED=0, no Zig link
make build-agent       # CGO_ENABLED=1, links librdmabridge.a (Linux)
make generate-bpf      # recompile the eBPF programs with bpf2go
make clean             # remove bin/, dist/, zig/zig-out/, zig/.zig-cache/
make package           # .deb/.rpm for agent and controller (needs nfpm)
make archive           # binary .tar.gz archives (AGENT_BUILDER=el9 for releases)
make obs-up | obs-seed | obs-verify | obs-logs | obs-down  # local observability stack
```

- After modifying `.proto` files run `make generate-proto`; a fresh checkout
  also needs it before `build-controller`/`build-agent`, `make lint` and any
  test of the controller packages.
- After modifying Zig source in `zig/src/` run `make build-zig` before
  `make build-agent`.
- After modifying anything under `internal/agent/servicetrace/bpf/` run
  `make generate-bpf` and commit the regenerated `uverbs_*`, `kernel_*` and
  `dc_*` `_bpfel.{go,o}` files; `make build-agent` never needs clang.
- Release builds use `AGENT_BUILDER=el9` (`Dockerfile.agent-el9`) so the agent
  runs on glibc ≥ 2.34; `scripts/check-glibc-compat.sh` enforces the floor.

## 4. Test

| Command | What | Needs |
|---|---|---|
| `make test` | Go tests of every pure-Go package (`internal/probe`, `config`, `telemetry`, `lldp`, `logging`, `buildinfo`, `controller/...`, `agent/controller_client`, `agent/servicetrace`, `cmd/controller`) | generated protobuf code; any OS |
| `make test-race` | Go tests with `-race`; on Linux every package except `./e2e/...`, elsewhere the pure-Go set | Linux: Zig, libibverbs/librdmacm headers (builds `librdmabridge.a`), protoc |
| `make test-all` | `test-zig` + every non-e2e Go package (no `-race`) | as `test-race` |
| `make test-zig` | Zig unit tests (`zig build test`) | libibverbs headers, no hardware |
| `make test-scripts` | Python tests of `scripts/topology/` | python3 (stdlib only) |
| `make test-fuzz` | every Go fuzz target for `FUZZTIME` (default 30s; `FUZZFLAGS=-parallel=2` on a shared host) | as `test-race` |
| `make bench` | benchmarks into `bench.txt` (gitignored; compare with `benchstat`), `BENCH_COUNT` runs | as `test-race` |
| `make test-integration` | alias of `make test-e2e-controller`: agent-to-controller e2e against rqlite | Docker |
| `make test-e2e` | RDMA e2e in a privileged container with two soft-RoCE devices | privileged Docker, host `rdma_rxe` (macOS: `make setup-colima` once) |

- Run one test: `go test -v ./internal/probe/... -run TestCalculateRTT`.
  Internal/agent, internal/rdmabridge and cmd/agent need Cgo, libibverbs and
  `librdmabridge.a` (the Linux environment of `make test-race`).
- Root-only tests skip when unprivileged: the eBPF tracer load/attach tests
  (`TestTracerOpenClose`, `TestKernelTracerOpenClose`) need root, kernel BTF,
  tracefs and `ib_uverbs`; the RDMA netlink request tests
  (`TestRequestRDMARejects...`) need `CAP_NET_ADMIN`. CI runs them under sudo
  (see the last step of the `unit` job). As root on a host without tracefs
  mounted, `TestTracerOpenClose` fails instead of skipping; mount tracefs
  (e.g. in a private mount namespace) or run unprivileged.
- `TestServiceTracing` (soft-RoCE e2e, traces `ibv_rc_pingpong`) and the
  hardware tests (`*_hardware_test.go`, mlx5 DC/UCX) skip without their
  hardware. Never make hardware tests required.
- `TestProbeToOTelMetrics` in `make test-e2e` tolerates runs in which no probe
  succeeds (soft-RoCE does not complete every exchange).
- Fuzz targets: probe/ACK wire layout (`internal/rdmabridge`), tracer events,
  netlink QP dumps, mlx5 QP dumps and DC WQEs, flow-label arithmetic
  (`internal/agent/servicetrace`), GID parsing and RTT calculation
  (`internal/probe`), lldpcli JSON (`internal/lldp`), metric labels of host
  names (`internal/telemetry`) and RegisterAgent validation
  (`internal/controller`). A crasher lands in the package's
  `testdata/fuzz/FuzzXxx/`; commit it as a regression seed with the fix.
- Packages that start goroutines verify with `go.uber.org/goleak`
  (`leak_test.go`) that their tests leave none behind.
- Go tests live in `*_test.go` files with `TestXxx` names; tests use fakes and
  interfaces (`ControllerClient`, `dbConn`, fake probers, bufconn gRPC
  servers, TCP listeners that never answer or reset) instead of real
  hardware or services.

## 5. Static analysis

```sh
make lint          # golangci-lint (.golangci.yml) + go mod tidy -diff (generates protobuf code first)
make fmt           # apply gofmt via golangci-lint fmt
make lint-actions  # actionlint + zizmor on .github/ (offline unless GH_TOKEN is set)
make vuln          # govulncheck ./...
make vet           # go vet ./...
make check-bpf     # eBPF programs compile and committed bindings are current
make complexity    # cccc ranking (needs cccc; CI tracks the scores with octocov)
```

Tool versions are pinned in the Makefile and in the workflows; bump them
together. The `go run` tools are built with the module's toolchain
(`GO_TOOLCHAIN`); an installed binary can be used instead, e.g. `make lint
GOLANGCI_LINT=golangci-lint`. `legacy/` is a separate module and is not
linted or scanned. With `GH_TOKEN` set but the GitHub API unreachable, run
`env -u GH_TOKEN make lint-actions`.

## 6. Coding conventions

- Standard Go style, `gofmt`; comments say why, in English.
- Logging: `github.com/rs/zerolog` (not the standard `log`). GID-level probe
  detail goes to Debug logs only, never into OTel metric attributes.
- Errors: wrap with `%w`; check with `errors.Is`/`errors.As`. Deliberate
  exceptions are annotated (`//nolint:<linter> // reason`).
- gRPC client: `grpc.NewClient()` (not the deprecated `grpc.Dial`).
- Names read from the kernel (host, RDMA device and netdev names) may hold
  bytes that are not valid UTF-8. Protobuf strings (gRPC and OTLP) must be
  valid UTF-8, or the whole message fails to marshal, so such names are
  converted with `strings.ToValidUTF8` where they leave the agent
  (`buildRegistrationRequest`, `telemetry.deviceMetricLabel`); keep the raw
  name for sysfs lookups.
- C-ABI types: no `bool`; use `uint8_t` (0/1). GIDs are always `rdma_gid_t`
  (16-byte binary); string conversion only at display/config boundaries.
- Do not edit generated files by hand (`proto/controller_agent/*.pb.go`,
  `internal/agent/servicetrace/*_bpfel.{go,o}`).
- Prefer simple, systematic solutions; update documentation (README, this
  file, `docs/design/`, `CHANGELOG.md`) with behaviour or workflow changes.
- Commits: Conventional Commits (`feat:`, `fix(agent):`, `docs:`, `ci:`,
  `build:`, `test:`).

## 7. Compatibility contracts

Changing any of these silently breaks deployed agents, controllers,
dashboards or the kernel interface. Call such a change out in the PR.

- **40-byte BigEndian probe wire format** (explicit serialization, no packed
  structs; version byte at offset 0). Zig `serializeProbePacket`/
  `deserializeProbePacket` in the leaf module `zig/src/wire.zig` (shared by
  `packet.zig` and `cq.zig`) and Go `SerializeProbePacket` in
  `internal/rdmabridge/bridge.go` implement it independently;
  `internal/agent/responder.go` rebuilds a received probe from the decoded
  event fields for the ACK path. Received packets are decoded only in Zig
  and reach Go as `rdma_completion_event_t` fields. The golden bytes of
  `TestSerializeProbePacketLayout` (Go) and the layout test in `wire.zig`
  must stay identical.
- **C ABI**: `zig/include/rdma_bridge.h`, the Zig exports in `main.zig`, and
  `internal/rdmabridge/bridge.go` change together (no `bool`; struct sizes
  are tested on the Zig side).
- **eBPF event structs**: `struct qp_event` (112 bytes, little-endian) ↔
  `DecodeEvent` in `internal/agent/servicetrace/event.go`; kernel events
  append a 64-byte device name (`kernel_trace.bpf.c`); the `EV_*`/`SRC_*`
  constants ↔ `Kind`/`Source`; the UAPI offsets in `bpf/uverbs_uapi.h` ↔ the
  kernel's `include/uapi/rdma/*.h`; the DC structs (`dc_batch`, ...) are
  bpf2go-generated types. `make check-bpf` keeps the flags of `generate.go`
  and the Makefile in sync.
- **gRPC API**: `proto/controller_agent/controller_agent.proto`. Add fields,
  never renumber; deprecated fields (`source_port`, `priority`) are still
  filled for older agents. Agents and controllers of adjacent versions
  interoperate (e.g. `per_rnic_tor_id`, `Unimplemented` for
  `GetTargetRnicInfo`).
- **Metrics** (OTLP; names under `rpingmesh.*`, defined in
  `internal/telemetry/otel_metrics.go` and
  `internal/controller/analyzer/metrics.go`, documented in README
  "Observability", used by `dashboards/`). Attributes: `source_tor` and
  `target_tor` (ToR-level aggregation, not per GID), plus the local RNIC on
  agent probe metrics (`source_rdma_device`, `source_netdev`; bounded by the
  RNICs per host). Destination-RNIC identity (`target_hostname`,
  `target_rdma_device`, `target_netdev`) goes only to the separate opt-in
  `rpingmesh.target_rnic.*` instruments (`metrics_target_rnic_labels`,
  `telemetry.WithTargetRnicLabels`), never to the default instruments, so
  their cardinality cannot overflow the ToR-level series. Service-tracing
  results are recorded on `rpingmesh.service.*` only and skipped by the
  analysis tee. Never use GIDs or IPs as attributes. `probe.InvalidKind` and
  `probe.FailureReason` are closed sets used as attribute values.
- **Configuration keys** (`internal/config/`; README "Configuration"
  documents every key). Both binaries use Viper with precedence CLI flag >
  env var > YAML > default; without `--config` they search `.`,
  `$HOME/.rpingmesh` and `/etc/rpingmesh`. Env vars use the `RPINGMESH_`
  prefix and the upper-cased key (`RPINGMESH_CONTROLLER_ADDR`,
  `RPINGMESH_DATABASE_URI`, `RPINGMESH_LOG_LEVEL`); a flag is the key with
  `_` replaced by `-`. Defaults in `configs/`: agent `probe_interval_ms: 500`,
  `gid_index: 0`, `cq_poll_mode: auto`, `event_ring_capacity: 1024`,
  `controller_addr: localhost:50051`, `otel_collector_addr: localhost:4317`;
  controller `listen_addr: :50051`, `database_uri: http://localhost:4001`.
- **Registry schema**: the rqlite `rnics` table
  (`internal/controller/registry/registry.go`); columns are added with
  migrations so older controllers sharing the database keep working.
- **Packaging**: binary names, systemd units and drop-ins under
  `packaging/systemd/`, the capabilities they grant, and the nfpm file
  layout.

### Service tracing (eBPF)

`bpf/uverbs_trace.bpf.c` attaches kprobes/kretprobes to `ib_uverbs_ioctl`,
`ib_uverbs_write` and `ib_uverbs_close` and parses the **uverbs user-space
ABI** (`uverbs_uapi.h`: QP create/modify/destroy commands via `write(2)`,
ioctl `INVOKE_WRITE`, and the ioctl-native `QP_CREATE`/`QP_DESTROY`), so it
needs no BTF for the RDMA modules (out-of-tree stacks ship none); only
`struct file -> f_inode -> i_rdev` is CO-RE relocated against vmlinux.
Commands are staged per task at entry and emitted at return on success;
every entry discards the task's previous staging (missed kretprobes).
`EnableKernelULP` adds `ib_core` probes for kernel-owned QPs
(`kernel_trace.bpf.c`, needs module BTF; failure does not disable the uverbs
tracer). The opt-in DC collector (`dc_trace.bpf.c`, `cmd/dc-trace`) is
diagnostics only. The pure-Go `Table` joins events by (context, handle) into
connections; `ServiceMonitor` groups them per device into flows keyed by
(remote GID, `EffectiveFlowLabel`, which mirrors the kernel's
`rdma_get_udp_sport` arithmetic), resolves remotes through
`GetTargetRnicInfo`, reconciles against `/proc` and RDMA netlink QP dumps for
lost events, and pushes targets to the Prober's third pass, which has its own
generation (`serviceGen`), an aggregate per-RNIC rate and a shuffled order;
single-label targets never touch the per-GID flow-label rotation. See
`docs/design/ebpf-service-tracing.md`.

## 8. Concurrency and resource management

- Prober, Responder and ClusterMonitor share `lifecycle`
  (`internal/agent/lifecycle.go`): a running flag, a stop channel recreated
  on every start, and a WaitGroup that `stop` always joins before the caller
  tears down the RDMA resources the goroutines use. Stop components before
  destroying their queues and rings.
- Each RNIC's ring loop is the single consumer of its SPSC ring; the Zig CQ
  poller thread is the single producer. Never consume a ring from two
  goroutines.
- Results fan in through one goroutine per prober (`createResultsFanIn`).
  `stopResultsFanIn` requires every prober to be destroyed first (closing
  `Results()`); the analysis tee is non-blocking so a slow aggregator never
  stalls metrics.
- Every controller RPC is bounded by `rpcTimeout` (10s) and the caller's
  context; `ClusterMonitor.Stop` waits for an in-flight fetch. RPC failures
  are logged and retried on the next cycle; analysis reports are dropped,
  not retried.
- External commands use `exec.CommandContext` with `WaitDelay`
  (`internal/lldp`); kernel QP dumps run at most one at a time and are
  bounded (`boundedQPCollection`), and a stalled worker must not retain the
  caller's state.
- Close what you open: eBPF links/objects/readers (`Tracer.Close` is
  idempotent), fds, gRPC connections, the MeterProvider (`Shutdown` flushes).

## 9. Performance constraints

- The per-probe path (probe send, ring poll, ACK matching, `CalculateRTT`,
  `RecordProbeResult`, `PathAggregator.AddResult`) runs for every probe of
  every target on every RNIC: no blocking calls, no per-probe logging above
  Debug, no unbounded maps. `make bench` covers these paths.
- Busy CQ polling costs ~1% of a CPU per queue; event mode costs nothing
  while idle. The README "CPU budget" section documents the agent's budget,
  and the watchdog throttles probing under memory/CPU pressure but never
  stops it.
- The event ring drops events when full (`rpingmesh.event_ring_dropped_total`);
  size `event_ring_capacity` rather than adding blocking.
- Metric cardinality is bounded by design (section 7); the controller bounds
  every unauthenticated input (`internal/controller/validate.go`).

## 10. Before opening a PR

Run `make check` (on Linux: `lint`, `lint-actions`, `test-race`, `test-zig`,
`test-scripts`). Also run, when you touch:

- `internal/agent/servicetrace/bpf/`: `make generate-bpf` and `make check-bpf`.
- `zig/`: `make build-zig test-zig`, and `make build-agent`.
- `.proto` files: `make generate-proto`, then `make check`.
- parsers or decoders: `make test-fuzz FUZZTIME=1m` for the affected targets.
- the controller/agent gRPC path or the registry: `make test-integration`.
- the RDMA data path: `make test-e2e` where soft-RoCE is available.
- dependencies: `make vuln`.

PRs state their purpose, impact and the commands run, and explicitly
document breaking changes, required privileges, kernel constraints and RDMA
dependencies (see `.github/pull_request_template.md`).

## 11. Rules for AI agents

Forbidden:

- disabling, skipping, deleting or weakening tests, fuzz targets, lint rules
  or CI checks to get green (no `|| true`, `continue-on-error`, blanket
  excludes, loosened assertions);
- editing generated files by hand (`*.pb.go`, `*_bpfel.{go,o}`);
- modifying `legacy/` unless the task explicitly requests legacy maintenance;
- adding dependencies without a stated justification;
- changing a compatibility contract (section 7) without calling it out;
- loosening workflow permissions, unpinning actions or adding
  `pull_request_target`/`workflow_run` triggers;
- committing secrets, real environment identifiers or machine-specific
  details;
- rewriting published history, force-pushing, tagging or publishing releases.

## 12. Changes that need human review

Even with green CI, ask for a human review of: workflow and release files
(`.github/`), permissions, secrets and systemd capabilities; privileged or
security-sensitive code paths (eBPF programs, kernel dump and netlink
decoders, the controller's input validation, TLS configuration); the wire
format, C ABI, gRPC API, metric names/attributes and config keys; dependency
additions or major upgrades; and large refactors.
