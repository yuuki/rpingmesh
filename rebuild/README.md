# R-Pingmesh Rebuild

A ground-up reimplementation of R-Pingmesh, a service-aware RoCE network monitoring
system based on the SIGCOMM 2024 paper by Liu et al. This rebuild uses **Zig** for
the RDMA data-path library and **Go** for agent orchestration, controller logic,
and telemetry. The system performs end-to-end probing across RDMA (RoCEv2) fabrics
and computes sub-microsecond network RTT using a 6-timestamp protocol.

## Architecture

```
                    +-------------------+
                    |    Controller     |
                    | (Go, gRPC server) |
                    +--------+----------+
                             |
              +--------------+--------------+
              |  gRPC (registration,        |
              |  pinglist distribution)      |
              |                             |
     +--------v----------+       +----------v--------+
     |      Agent A       |       |      Agent B       |
     | +----------------+ |       | +----------------+ |
     | | Prober         | |       | | Prober         | |
     | | Responder(s)   | |       | | Responder(s)   | |
     | | ClusterMonitor | |       | | ClusterMonitor | |
     | | OTel Telemetry | |       | | OTel Telemetry | |
     | +-------+--------+ |       | +-------+--------+ |
     |         |           |       |         |           |
     | +-------v--------+ |       | +-------v--------+ |
     | | Zig RDMA Lib   | |       | | Zig RDMA Lib   | |
     | | (librdmabridge) | |       | | (librdmabridge) | |
     | +----------------+ |       | +----------------+ |
     +--------------------+       +--------------------+
              |                             |
              +-------- RDMA Fabric --------+
                    (RoCEv2, UD QPs)

     Controller stores RNIC registry in rqlite (distributed SQLite).
     Agents export OTLP metrics to an OpenTelemetry collector (Grafana).
```

**Controller** -- Central coordination service. Manages agent registration and
distributes pinglists (probe target assignments). Stores RNIC information in
rqlite. Pure Go; no RDMA dependency.

**Agent** -- Deployed on each RDMA host. Opens RDMA devices, runs a Responder per
device (answers incoming probes with ACKs), a single Prober (sends probes to
assigned targets), a ClusterMonitor (fetches pinglists from the controller), and a
MetricsCollector (exports OTLP metrics).

**Zig RDMA Library** -- Static library (`librdmabridge.a`) that handles all
libibverbs operations: device enumeration, QP creation, CQ polling, packet
serialization, and send/receive. Exposes a C-ABI that Go calls via Cgo.

> **Note:** The Analyzer component and eBPF service tracing from the original
> implementation are out of scope for this rebuild.

## 6-Timestamp Probing Protocol

The protocol measures network RTT while eliminating endpoint processing delays:

```
Prober                          Responder
  |                                |
  |--- T1: send probe ----------->|
  |          T2: send completion   |
  |                                |--- T3: recv completion
  |          T4: first ACK send    |
  |<-- first ACK (T1, T3) --------|
  |--- T5: first ACK recv         |
  |                                |
  |<-- second ACK (T1, T3, T4) ---|
  |--- T6: second ACK recv        |
```

### Timestamp Sources

| Timestamp | Source | Clock |
|-----------|--------|-------|
| T1 | Zig, just before `ibv_post_send` | `CLOCK_MONOTONIC` |
| T2 | NIC send completion (CQ) | HW wallclock (fallback: SW) |
| T3 | NIC recv completion (CQ) | HW wallclock (fallback: SW) |
| T4 | NIC send completion (CQ) | HW wallclock (fallback: SW) |
| T5 | NIC recv completion (CQ) | HW wallclock (fallback: SW) |
| T6 | Go, upon processing second ACK | `time.Now()` (Go monotonic) |

HW timestamp support is detected at device open time via `ibv_query_device_ex`.
When HW timestamps are unavailable (`EOPNOTSUPP`), software timestamps from
`CLOCK_MONOTONIC` are used as a fallback.

### RTT Calculations

```
NetworkRTT     = (T5 - T2) - (T4 - T3)    // Pure network round-trip time
ProberDelay    = (T6 - T1) - (T5 - T2)    // Prober-side processing overhead
ResponderDelay = T4 - T3                   // Responder-side processing time
```

`NetworkRTT` subtracts the responder processing delay from the observed round-trip,
isolating the actual network latency. Negative values indicate clock domain issues
and are flagged as invalid.

## Directory Structure

```
rebuild/
  Makefile                                  Build orchestration
  go.mod                                    Go module definition
  configs/
    agent.yaml                              Default agent configuration
    controller.yaml                         Default controller configuration
  cmd/
    agent/main.go                           Agent entry point (cobra CLI)
    controller/main.go                      Controller entry point (cobra CLI)
  internal/
    agent/
      agent.go                              Agent lifecycle orchestrator
      prober.go                             Probe sender and ACK processor
      responder.go                          Probe receiver and ACK responder
      cluster_monitor.go                    Periodic pinglist fetcher
      controller_client/
        controller_client.go                gRPC client for controller
    config/
      agent_config.go                       Agent configuration (Viper)
      controller_config.go                  Controller configuration (Viper)
    controller/
      service.go                            gRPC service implementation
      registry/
        registry.go                         RNIC registry (rqlite)
      pinglist/
        pinglist.go                         Pinglist generation logic
    probe/
      probe.go                              Probe result types, RTT calculation
      probe_test.go                         Unit tests for RTT logic
    rdmabridge/
      bridge.go                             Go-Zig Cgo bridge (16 functions)
    telemetry/
      otel_metrics.go                       OpenTelemetry metrics collector
  proto/
    controller_agent/
      controller_agent.proto                gRPC service definition
      generate.go                           go:generate directive for protoc
  zig/
    build.zig                               Zig build configuration
    include/
      rdma_bridge.h                         C-ABI header (source of truth)
    src/
      main.zig                              Root module, exports, test entry
      types.zig                             Core types, constants, GID helpers
      ring.zig                              Lock-free SPSC ring buffer
      device.zig                            RDMA device lifecycle
      memory.zig                            Buffer allocation, MR registration
      queue.zig                             UD QP creation, AH management
      cq.zig                                CQ poller thread, GRH parsing
      packet.zig                            Wire format, send operations
```

## Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Go | 1.24.3+ | Agent and controller binaries |
| Zig | 0.13+ | RDMA data-path library |
| protoc | 3.x | Protocol buffer compilation |
| protoc-gen-go | latest | Go protobuf codegen |
| protoc-gen-go-grpc | latest | Go gRPC codegen |
| libibverbs-dev | any | RDMA verbs API |
| librdmacm-dev | any | RDMA CM (linking only) |
| rqlite | 8.x | Distributed SQLite for controller |
| Linux kernel | 5.4+ | RDMA support (5.8+ for ring buffer) |

RDMA-capable hardware (e.g., Mellanox ConnectX) or soft-RoCE (`rxe` driver) is
required for agent operation. The controller runs without RDMA hardware.

## Building

All commands are run from the `rebuild/` directory.

```sh
# Full build: Zig library -> proto codegen -> Go binaries
make build

# Individual stages
make build-zig          # Build zig/zig-out/lib/librdmabridge.a
make generate-proto     # Generate proto/controller_agent/*.pb.go
make build-controller   # Build bin/rpingmesh-controller (CGO_ENABLED=0)
make build-agent        # Build bin/rpingmesh-agent (CGO_ENABLED=1)

# Resolve Go dependencies (first time only)
go mod tidy

# Clean all artifacts
make clean
```

The controller binary does not link against any C libraries (`CGO_ENABLED=0`).
The agent binary links against `librdmabridge.a`, `libibverbs`, and `librdmacm`
via Cgo (`CGO_ENABLED=1`).

## Configuration

### Agent (`configs/agent.yaml`)

| Field | Default | Description |
|-------|---------|-------------|
| `agent_id` | hostname | Unique agent identifier |
| `tor_id` | *(required)* | Top-of-Rack switch identifier |
| `controller_addr` | `localhost:50051` | Controller gRPC address |
| `probe_interval_ms` | `500` | Milliseconds between probe rounds |
| `target_probe_rate_per_second` | `10` | Max probes per second |
| `pinglist_update_interval_sec` | `300` | Seconds between pinglist refreshes |
| `gid_index` | `0` | GID table index on RDMA devices |
| `allowed_device_names` | `[]` | Device filter (empty = all devices) |
| `metrics_enabled` | `true` | Enable OpenTelemetry export |
| `otel_collector_addr` | `localhost:4317` | OTLP gRPC collector endpoint |
| `log_level` | `info` | Log level: debug, info, warn, error |

### Controller (`configs/controller.yaml`)

| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `:50051` | gRPC listen address |
| `database_uri` | `http://localhost:4001` | rqlite connection URI |
| `log_level` | `info` | Log level |

### Environment Variable Overrides

All configuration fields can be overridden with environment variables using the
`RPINGMESH_` prefix. Dots and dashes in field names become underscores:

```sh
export RPINGMESH_CONTROLLER_ADDR="controller.internal:50051"
export RPINGMESH_TOR_ID="tor-a1"
export RPINGMESH_LOG_LEVEL="debug"
```

### CLI Flag Overrides

```sh
rpingmesh-agent --controller-addr controller.internal:50051 --tor-id tor-a1
rpingmesh-controller --listen-addr :9090 --database-uri http://rqlite:4001
```

## Running

### 1. Start rqlite

```sh
rqlited -node-id 1 ~/rqlite-data
```

### 2. Start the Controller

```sh
./bin/rpingmesh-controller --config configs/controller.yaml
```

### 3. Start Agent(s)

```sh
# On each RDMA host:
./bin/rpingmesh-agent \
    --config configs/agent.yaml \
    --agent-id host01 \
    --tor-id tor-a1 \
    --controller-addr controller.internal:50051
```

The agent will:
1. Initialize RDMA devices and create UD Queue Pairs
2. Register its RNICs with the controller
3. Fetch ToR-mesh and inter-ToR pinglists
4. Begin probing targets and exporting metrics

## Wire Format

Probe packets use a 40-byte explicit big-endian serialization format. Packed
structs are intentionally avoided for portability across Zig, C, and Go (per
design review).

| Offset | Size | Field | Encoding |
|--------|------|-------|----------|
| 0 | 1 | `version` | uint8 (currently `1`) |
| 1 | 1 | `msg_type` | uint8 (`0`=probe, `1`=ACK) |
| 2 | 1 | `ack_type` | uint8 (`0`=N/A, `1`=first, `2`=second) |
| 3 | 1 | `flags` | uint8 (reserved) |
| 4 | 8 | `sequence_num` | uint64 big-endian |
| 12 | 8 | `t1` | uint64 big-endian (nanoseconds) |
| 20 | 8 | `t3` | uint64 big-endian (nanoseconds) |
| 28 | 8 | `t4` | uint64 big-endian (nanoseconds) |
| 36 | 4 | reserved | zero |

Total: 40 bytes (`RDMA_PROBE_PACKET_SIZE`).

Sequence numbers use an epoch prefix (high 32 bits = random per-agent epoch,
low 32 bits = monotonic counter) to prevent collisions across agent restarts.

## Key Design Decisions

### Zig for the RDMA Data Path

All libibverbs calls, CQ polling, buffer management, and packet
serialization/deserialization are implemented in Zig. Zig provides:
- Deterministic memory management without a garbage collector
- Direct C interop with libibverbs via `@cImport`
- Compile-time safety checks for struct layout and alignment
- Thread-safe CQ polling without GC pause interference

The Zig library is compiled to a static archive (`librdmabridge.a`) and linked
into the Go agent binary via Cgo.

### SPSC Ring Buffer for Event Delivery

Completion events are delivered from the Zig CQ poller thread to Go via a
lock-free Single-Producer Single-Consumer ring buffer, rather than using direct
Cgo callbacks. This avoids:
- Thread safety issues with Go's runtime and Cgo
- The overhead of crossing the FFI boundary per-event
- Potential deadlocks from Go goroutine scheduling during Cgo calls

The ring uses cache-line-padded atomic head/tail pointers with acquire/release
memory ordering.

### `ibv_create_ah()` for Address Handles

Address Handles are created with `ibv_create_ah()`, not `rdma_create_ah()`.
The latter requires a Connection Manager context that is unnecessary for UD
(Unreliable Datagram) operations. `librdmacm` is linked only for its utility
functions.

### `flow_label` for ECMP Path Diversity

RoCEv2 UD mode does not allow control over the UDP source port (it is
driver-generated). Instead, the IPv6 flow label field in `ibv_ah_attr.grh` is
used for ECMP path selection. The `source_port` field in `PingTarget` is
metadata only and is not enforced at the RDMA layer.

Flow labels are generated deterministically using FNV-1a hashing of
`(requester_gid, target_gid)`, masked to 20 bits.

### ToR-Level Metric Cardinality

OpenTelemetry histogram attributes use ToR IDs (`source_tor`, `target_tor`)
rather than individual GIDs. In a large fabric with thousands of RNICs, using
GIDs as metric labels would cause cardinality explosion. Per-GID detail is
available in structured debug logs.

### Integer Epoch for Staleness Tracking

The rqlite `rnics` table uses `last_updated_epoch INTEGER` (Unix seconds)
instead of text-formatted timestamps. This enables efficient staleness queries
with simple integer arithmetic (`strftime('%s','now') - 300`) and benefits from
B-tree index scans.

## Observability

### Metrics

The agent exports the following OTLP metrics:

| Metric | Type | Unit | Description |
|--------|------|------|-------------|
| `rpingmesh.network_rtt_ns` | Histogram | ns | Pure network round-trip time |
| `rpingmesh.prober_delay_ns` | Histogram | ns | Prober-side processing overhead |
| `rpingmesh.responder_delay_ns` | Histogram | ns | Responder processing time |
| `rpingmesh.probe_success_total` | Counter | | Successful probe count |
| `rpingmesh.probe_failed_total` | Counter | | Failed probe count |
| `rpingmesh.probe_total` | Counter | | Total probe attempts |

All metrics carry two attributes: `source_tor` and `target_tor`.

Histogram bucket boundaries (nanoseconds):
```
100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, 10000000
```

This covers the 100 ns to 10 ms range typical of datacenter RDMA networks.

### Grafana Setup

1. Deploy an OpenTelemetry Collector with an OTLP gRPC receiver on port 4317.
2. Configure a Prometheus remote-write exporter or use the Prometheus receiver
   to scrape the collector.
3. Point the agent's `otel_collector_addr` to the collector.
4. In Grafana, create dashboards querying `rpingmesh_network_rtt_ns` histograms,
   grouped by `source_tor` and `target_tor`.

### Logging

Structured JSON logging via zerolog. Log levels:
- `debug` -- Per-probe detail including GIDs, all 6 timestamps, sequence numbers
- `info` -- Startup, registration, pinglist updates, periodic summaries
- `warn` -- Non-critical errors (ACK send failures, unknown sequence numbers)
- `error` -- Component initialization failures, gRPC errors

## Testing

```sh
# Run Go unit tests (pure Go, no RDMA hardware needed)
make test

# Run Zig unit tests (requires libibverbs headers, not hardware)
cd zig && zig build test

# Run a specific Go test
go test -v ./internal/probe/... -run TestCalculateRTT
```

RDMA integration tests require either actual RDMA hardware or soft-RoCE:

```sh
# Set up soft-RoCE for testing
sudo rdma link add rxe0 type rxe netdev eth0

# Then run the agent against a local controller and rqlite instance
```

## Development

### Modifying the Zig Library

1. Edit files under `zig/src/`.
2. If the C-ABI changes, update `zig/include/rdma_bridge.h` first.
3. Run `make build-zig` to rebuild `librdmabridge.a`.
4. Update `internal/rdmabridge/bridge.go` if function signatures changed.
5. Run `make build-agent` to rebuild the agent.

### Adding New gRPC RPCs

1. Edit `proto/controller_agent/controller_agent.proto`.
2. Run `make generate-proto`.
3. Implement the new RPC in `internal/controller/service.go`.
4. Update the client in `internal/agent/controller_client/controller_client.go`.

### Adding New Metrics

1. Add the instrument to `internal/telemetry/otel_metrics.go` in the
   `NewMetricsCollector` function.
2. Record values in `RecordProbeResult` or a new recording method.
3. Use only low-cardinality attributes (ToR-level, not GID-level).

## Limitations and Future Work

- **Analyzer not implemented.** The data aggregation and analysis component from
  the original design is out of scope. Probe results are exported as OTLP metrics
  for external analysis.

- **eBPF service tracing not implemented.** The original R-Pingmesh uses eBPF to
  monitor RDMA QP lifecycle events for service-aware monitoring. This rebuild
  focuses on the probing infrastructure.

- **Single prober per agent.** The current design creates one Prober on the first
  RDMA device. Multi-prober support (one per device) could be added for hosts
  with multiple RNICs on different fabrics.

- **No TLS on gRPC.** Controller-agent communication uses plaintext gRPC, assuming
  a trusted internal network. mTLS can be added via gRPC transport credentials.

- **No rate limiting on probe sends.** The `target_probe_rate_per_second` config
  field is defined but not enforced with a token bucket. The probe interval
  provides coarse rate control.

## References

- Liu et al., "R-Pingmesh: A Service-Aware RoCE Network Monitoring and Diagnostic
  System," SIGCOMM 2024.
- libibverbs API: [rdma-core documentation](https://github.com/linux-rdma/rdma-core)
- Zig language: [ziglang.org](https://ziglang.org)
- OpenTelemetry Go SDK: [opentelemetry.io](https://opentelemetry.io/docs/languages/go/)
