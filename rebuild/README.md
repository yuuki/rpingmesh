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

**Agent** -- Deployed on each RDMA host. Opens RDMA devices, and runs one
Responder, one Prober (sends probes to assigned targets), and one ClusterMonitor
(fetches pinglists from the controller) per opened device -- so every RNIC on a
multi-rail host actively probes, not just the first -- plus a single
MetricsCollector (exports OTLP metrics) shared across all of them.

**Zig RDMA Library** -- Static library (`librdmabridge.a`) that handles all
libibverbs operations: device enumeration, QP creation, CQ polling, packet
serialization, and send/receive. Exposes a C-ABI that Go calls via Cgo.

> **Note:** A Phase 1 Analyzer is implemented: agents aggregate probe results
> per path over fixed windows and report `PathSummary` batches to the controller
> via `ReportProbeAnalysis`, where an in-process analyzer detects per-path SLA
> violations (loss ratio and p99 network-RTT thresholds). Topology-aware
> switch/link fault localization (Phase 2) and eBPF service tracing remain out
> of scope for this rebuild.

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
| T6 | Go, upon processing second ACK | `CLOCK_MONOTONIC` via `unix.ClockGettime()` |

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
| Go | 1.26.0+ | Agent and controller binaries |
| Zig | 0.15.2 | RDMA data-path library (the version verified in e2e/CI; see `build.zig`, `Dockerfile.e2e`) |
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
| `hostname` | auto-detected | Hostname reported to the controller on registration (falls back to `os.Hostname()` if empty) |
| `tor_id` | *(required)* | Top-of-Rack switch identifier |
| `controller_addr` | `localhost:50051` | Controller gRPC address |
| `probe_interval_ms` | `500` | Milliseconds between probe rounds |
| `target_probe_rate_per_second` | `10` | Legacy **uniform** per-target probe-rate cap. Used as the fallback for whichever per-type cap below is `0`, so a config that only sets this keeps a single uniform rate (a target's ECMP flow labels share this budget) |
| `tor_mesh_probe_rate_per_second` | `0`† | Per-target probe-rate cap for **ToR-mesh** targets (`0` = inherit `target_probe_rate_per_second`) |
| `inter_tor_probe_rate_per_second` | `0`† | Per-target probe-rate cap for **inter-ToR** targets (`0` = inherit `target_probe_rate_per_second`) |
| `pinglist_update_interval_sec` | `300` | Seconds between pinglist refreshes |
| `flow_label_rotation_period_sec` | `3600` | Period over which the rotating ~20% of each target's ECMP flow-label set is refreshed |
| `gid_index` | `0` | GID table index on RDMA devices (0-255; see note below) |
| `service_level` | `0` | Service Level (SL, PFC priority) applied to every Address Handle (0-7) |
| `traffic_class` | `0` | GRH traffic class octet applied to every Address Handle (0-255). RoCEv2 DSCP occupies the upper 6 bits of this octet: to use DSCP value `N`, set `traffic_class = N << 2` |
| `allowed_device_names` | `[]` | Device filter (empty = all devices) |
| `metrics_enabled` | `true` | Enable OpenTelemetry export |
| `otel_collector_addr` | `localhost:4317` | OTLP gRPC collector endpoint |
| `analysis_report_enabled` | `true` | Aggregate probe results per path and report `PathSummary` batches to the controller's analyzer (best-effort; never blocks probing) |
| `analysis_window_sec` | `30` | Per-path aggregation window length in seconds |
| `self_protection_enabled` | `false` | Opt-in resource watchdog: throttles the probe send rate (fail-slow) under local CPU/memory pressure (see [Self-protection](#self-protection)) |
| `watchdog_interval_sec` | `5` | How often the watchdog samples resource usage (seconds) |
| `max_memory_mb` | `0` | Soft runtime memory limit in MiB (`GOMEMLIMIT` via `debug.SetMemoryLimit`; `0` = disabled). Also the reference budget for memory throttling. Applied whenever `> 0`, independent of `self_protection_enabled` |
| `max_procs` | `0` | Cap `runtime.GOMAXPROCS` to this many cores (`0` = Go default: all cores). Applied whenever `> 0`, independent of `self_protection_enabled` |
| `throttle_memory_ratio` | `0.9` | Fraction of `max_memory_mb` at which memory throttling engages (`0`-`1`). Only active when `max_memory_mb > 0` |
| `throttle_cpu_percent` | `90` | Percentage of available CPU capacity (`GOMAXPROCS` cores) at which CPU throttling engages (`0`-`100`) |
| `log_level` | `info` | Log level: debug, info, warn, error |
| `tls_mode` | `disabled` | gRPC transport security for the controller connection: `disabled` \| `tls` \| `mtls` (see [TLS/mTLS for controller-agent gRPC](#tlsmtls-for-controller-agent-grpc)) |
| `tls_cert_file` | `""` | Client certificate file (required when `tls_mode=mtls`) |
| `tls_key_file` | `""` | Client private key file (required when `tls_mode=mtls`) |
| `tls_ca_file` | `""` | CA file used to verify the controller's certificate (required when `tls_mode` is `tls` or `mtls`) |
| `tls_server_name` | `""` | Overrides the name used for TLS SNI/verification; needed when `controller_addr` is an IP literal that doesn't match the server certificate's subject |

† The built-in default for both per-type rates is `0`, which inherits
`target_probe_rate_per_second` (effectively `10`) so an upgrade preserves the
prior uniform behavior. The shipped `configs/agent.yaml` overrides them with the
paper-style differentiated caps (ToR-mesh `10`, inter-ToR `1`).

`gid_index` selects which entry of the RNIC's GID table to use for RDMA
traffic; the correct value depends on the device and is not portable across
machines (e.g. real Mellanox NICs commonly place a RoCE v1 entry at index 0
and the interoperable RoCE v2 entry at a higher index — check with
`ibv_devinfo -d <dev> -v`). `Validate()` only rejects an obviously-bogus
value (negative or > 255) at config-load time; the actual per-device
range/existence check happens when the agent opens the RDMA device. If
`gid_index` does not resolve to a usable GID, the agent fails to start with
a specific error identifying the device, port, and GID table size (e.g.
`gid_index=100 is invalid or not present on device mlx5_0 port 1 (GID table
size 3)`), rather than a generic "no usable GID found" message that could be
mistaken for the port itself being down.

### Controller (`configs/controller.yaml`)

| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `:50051` | gRPC listen address |
| `database_uri` | `http://localhost:4001` | rqlite connection URI |
| `active_threshold_sec` | `300` | Window (seconds) within which an RNIC entry is considered active for pinglist generation |
| `stale_threshold_sec` | `900` | Window (seconds) after which an inactive RNIC entry is considered stale and removed |
| `inter_tor_sample_size` | `5` | Distinct ToRs sampled per inter-ToR pinglist |
| `ecmp_paths_assumed` | `16` | Assumed ECMP fabric width (m) for Eq.(1) flow-label coverage sizing |
| `ecmp_coverage_probability` | `0.9` | Target probability (p, in (0,1)) that generated flow labels cover all ECMP paths |
| `ecmp_max_flow_labels` | `64` | Hard cap on flow labels per target (bounds probe amplification) |
| `analyzer_enabled` | `true` | Enable the Phase 1 analyzer: ingest agent-reported summaries and detect SLA violations |
| `analyzer_sla_loss_ratio` | `0.02` | Per-path loss ratio (0..1) above which a window is flagged as a loss SLA violation |
| `analyzer_sla_network_rtt_p99_ns` | `500000` | Per-path p99 network-RTT (ns) above which a window is flagged as an RTT SLA violation (0 disables the check) |
| `analyzer_window_retention` | `20` | Number of recent windows the analyzer retains in memory |
| `otel_collector_addr` | `localhost:4317` | OTLP gRPC endpoint for analyzer metrics (`service.name=rpingmesh-analyzer`) |
| `log_level` | `info` | Log level |
| `tls_mode` | `disabled` | gRPC transport security for the listener: `disabled` \| `tls` \| `mtls` (see [TLS/mTLS for controller-agent gRPC](#tlsmtls-for-controller-agent-grpc)) |
| `tls_cert_file` | `""` | Server certificate file (required when `tls_mode` is `tls` or `mtls`) |
| `tls_key_file` | `""` | Server private key file (required when `tls_mode` is `tls` or `mtls`) |
| `tls_ca_file` | `""` | CA file used to verify client certificates (required when `tls_mode=mtls`) |
| `tls_server_name` | `""` | Present for config-key symmetry with the agent; unused by the controller (server) role |

### TLS/mTLS for controller-agent gRPC

By default (`tls_mode: disabled`), controller-agent gRPC is plaintext, matching the
original behavior; the controller and every `GRPCControllerClient` log a warning once
at startup when running in this mode. Two opt-in modes are available, selected
symmetrically via the `tls_mode` key on both sides:

- `tls`: the agent verifies the controller's certificate; the controller does not
  authenticate the agent. Controller needs `tls_cert_file`/`tls_key_file`; agent needs
  `tls_ca_file`.
- `mtls`: mutual authentication. Both sides need `tls_cert_file`, `tls_key_file`, and
  `tls_ca_file` (the controller's `tls_ca_file` is the CA that signs agent client
  certificates; the agent's is the CA that signs the controller's server certificate;
  a single CA can serve both roles). This is the recommended mode for production
  deployments.

`tls_server_name` on the agent overrides the name used for TLS server-name
verification, which is required when `controller_addr` is an IP literal rather than a
DNS name matching the controller certificate's subject. `Validate()` fails fast at
config-load time if a mode's required certificate files are missing or unreadable,
rather than deferring the failure to the first gRPC handshake. `InsecureSkipVerify` is
never used; there is deliberately no way to disable server certificate verification
other than falling back to `tls_mode: disabled`. Certificate loading is static (no
hot-reload): rotating certificates requires a restart.

### Self-protection

The agent can guard its own host footprint with an opt-in watchdog
(`self_protection_enabled: true`). Every `watchdog_interval_sec` it samples this
process's memory (via `runtime/metrics`, the same accounting as `GOMEMLIMIT`) and
CPU time (via `getrusage`), and applies a **fail-slow** throttle: when either
resource crosses its threshold it steps a probe-rate multiplier down the ladder
`1.0 → 0.5 → 0.25 → 0.1` (one step per interval), and steps it back up as usage
recovers. The multiplier scales every prober's per-target send rate on top of the
configured per-type caps. It is deliberately floored at `0.1` and **never reaches
`0`**: self-protection slows probing but never stops it, since a silent agent is a
monitoring blind spot (fail-slow, not fail-closed).

- **Memory throttling** engages at `throttle_memory_ratio × max_memory_mb` and is
  active only when `max_memory_mb > 0`. Setting `max_memory_mb` also installs a
  soft `GOMEMLIMIT` (via `debug.SetMemoryLimit`) so the Go runtime GCs harder to
  stay under the budget while the watchdog sheds probe load before it is reached.
- **CPU throttling** engages at `throttle_cpu_percent` of the process's available
  CPU capacity (its `GOMAXPROCS` cores), so `90` means the agent is saturating
  nearly all the cores it is allowed to use.
- A **hysteresis band** (recovery requires usage to fall to 75% of the engage
  threshold) plus the one-step-per-interval ramp keeps the multiplier from
  flapping when usage hovers at a threshold.
- `max_procs` and `max_memory_mb` are honored as plain runtime caps whenever set,
  independent of `self_protection_enabled`.

Engaging and fully releasing the throttle are logged at `warn`; the live
multiplier is exported as the `rpingmesh.agent.self_throttle` OTLP gauge
(`1.0` = unthrottled). CPU utilization is measured via `getrusage` rather than the
`runtime/metrics` `/cpu/classes` counters because the latter only advance during a
GC cycle, which would leave a low-allocation agent's CPU reading stale.

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

## Deployment (systemd)

For long-running deployments, both binaries ship with systemd unit files
(`packaging/systemd/`) and nfpm packaging definitions
(`packaging/nfpm/`) that build `.deb`/`.rpm` packages.

### Manual install (no package manager)

```sh
# 1. Build the binaries. Use the package-build-* targets (not plain
#    build-controller/build-agent) even for a manual install: they force
#    GOOS=linux GOARCH=$(NFPM_ARCH) explicitly, so the result is always a
#    Linux binary for the target host's architecture -- plain `go build` (as
#    build-controller/build-agent use) targets whatever OS/arch you run
#    `make` on, which silently produces a binary that fails with "exec
#    format error" on the target host if you build on e.g. macOS and copy it
#    over.
make package-build-controller   # controller: cross-compiles cleanly from any host (CGO_ENABLED=0)
make package-build-agent        # agent: must be run ON the target Linux/RDMA host itself (CGO_ENABLED=1, Cgo can't cross-compile against libibverbs)

# 2. Install the binary, unit file, and a starting config on the target host.
sudo install -m 0755 bin/rpingmesh-controller /usr/bin/rpingmesh-controller
sudo install -m 0644 packaging/systemd/rpingmesh-controller.service \
    /usr/lib/systemd/system/rpingmesh-controller.service
sudo mkdir -p /etc/rpingmesh
sudo install -m 0644 configs/controller.yaml /etc/rpingmesh/controller.yaml
# (repeat with rpingmesh-agent / agent.yaml / rpingmesh-agent.service on agent hosts)

# 3. Edit /etc/rpingmesh/*.yaml for the host (tor_id, controller_addr, etc.),
#    then create the system user/group and RDMA group membership expected by
#    the unit files (the nfpm packages below do this automatically).
sudo groupadd --system rpingmesh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
    --gid rpingmesh rpingmesh
# Agent hosts only: grant access to /dev/infiniband/* (see the capability
# note at the top of rpingmesh-agent.service for why CAP_NET_RAW is
# deliberately *not* granted, and why CAP_IPC_LOCK + LimitMEMLOCK=infinity
# are). The unit declares SupplementaryGroups=rdma unconditionally, so the
# group must exist even if your distro's rdma-core hasn't created it yet
# (systemd refuses to start a unit whose SupplementaryGroups name doesn't
# resolve) -- the nfpm packages' postinstall script does this automatically.
sudo groupadd --system rdma 2>/dev/null || true   # no-op if rdma-core already created it
sudo usermod -a -G rdma rpingmesh

# 4. Enable and start.
sudo systemctl daemon-reload
sudo systemctl enable --now rpingmesh-controller.service   # or rpingmesh-agent.service
```

### Building `.deb`/`.rpm` packages with nfpm

```sh
# Install nfpm (https://nfpm.goreleaser.com/install/), e.g.:
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

# From the rebuild/ directory:
make package              # builds both agent and controller .deb + .rpm into dist/
make package-agent         # agent only (Linux/CGO_ENABLED=1 build host required)
make package-controller    # controller only (cross-compiles to GOOS=linux automatically -- safe to run from macOS)

# Override the package version (default: "0.0.0+git.<short sha>", or the
# exact tag if HEAD is tagged):
make package VERSION=1.2.3
```

Both `package-agent`/`package-controller` build with `GOOS=linux GOARCH=$(NFPM_ARCH)` explicitly (see the `package-build-*` targets in the Makefile), regardless of the host `make` runs on, so the packaged binary's platform always matches what the `.deb`/`.rpm` declares. The controller is pure Go (`CGO_ENABLED=0`) and cross-compiles cleanly from any host; the agent is `CGO_ENABLED=1` and links libibverbs/librdmacm via Cgo, so it still requires a matching Linux host to actually produce a working binary.

Each package installs the binary to `/usr/bin/`, the unit file to
`/usr/lib/systemd/system/`, and a sample config to
`/etc/rpingmesh/{agent,controller}.yaml.example` (not the live config --
copy and edit it to `agent.yaml`/`controller.yaml` before starting, since
required fields like `tor_id` have no default). The package's postinstall
script creates the `rpingmesh` system user/group and reloads systemd, but
deliberately does not enable or start the service. Install with
`dpkg -i dist/rpingmesh-agent_*.deb` / `rpm -i dist/rpingmesh-agent-*.rpm` (or
your distro's equivalents), then follow step 3-4 above.

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

### `flow_label` for ECMP Path Coverage

RoCEv2 UD mode does not allow control over the UDP source port (it is
driver-generated). Instead, the IPv6 flow label field in `ibv_ah_attr.grh` is
used for ECMP path selection. The `source_port` field in `PingTarget` is
metadata only and is not enforced at the RDMA layer. The flow label reaches the
NIC per send via a fresh `ibv_create_ah()` in the Zig bridge, so it can vary
from one probe to the next with no per-QP state.

Rather than probing each `(source, target)` pair with a single deterministic
flow label — which always pins the same ECMP path and leaves silent drops on
other links invisible — the controller sizes a **set** of distinct flow labels
per target so the target's ECMP paths are covered with a configured
probability, and the agent rotates through that set.

**Coverage sizing (R-Pingmesh Eq.(1), coupon-collector).** To cover all `m`
equal-probability ECMP paths with probability at least `p`, model each probe as
drawing one of `m` paths uniformly. Let `q = (m-1)/m` be the per-probe miss
probability for a given path; after `n` draws that path is uncovered with
probability `q^n`. Treating the `m` paths' coverage as independent (a standard,
slightly conservative closed form) gives `P(cover all) ≈ (1 - q^n)^m ≥ p`,
which solves to:

```
n = ceil( ln(1 - p^(1/m)) / ln((m-1)/m) )
```

This agrees to within one probe with the strict union bound
`P(cover all) ≥ 1 - m·q^n`. The controller computes `n` once from
`ecmp_paths_assumed` (m), `ecmp_coverage_probability` (p), and the
`ecmp_max_flow_labels` cap (which bounds probe amplification), and stamps
`flow_label_count = n` and a full 32-bit `flow_label_seed` into every
`PingTarget` (seed + count is far smaller than a repeated label list). The
legacy `flow_label` field remains populated (the low 20 bits of the seed) and
is used verbatim when `flow_label_count ≤ 1`, preserving backward compatibility.

**Agent expansion and rotation.** The agent derives label `i` deterministically
from `hash(seed, i, rotationEpoch)` masked to 20 bits, and sends probes
**round-robin** across the set (successive probes to a target use successive
labels). The set of labels shares the target's probe budget:
`target_probe_rate_per_second` is a per-**target** cap and is *not* multiplied
by `n`, so enabling coverage bounds probe amplification rather than accelerating
it. Every `flow_label_rotation_period_sec` (default 1h), the rotating subset
(~20%, every 5th label index) folds in `rotationEpoch = floor(unixTime /
period)` and shifts, catching a wider set of paths over time while the other
~80% stay stable for time-series continuity. (Wall-clock time here only selects
labels; it never enters a measurement timestamp.)

The actual flow label used for each probe is reported in `ProbeResult` and in
debug logs, but deliberately **not** as an OTel metric attribute — per-label
cardinality would explode the metric space, so aggregate metrics stay
ToR-level.

### Differentiated per-pinglist-type probe rates

R-Pingmesh probes the ToR-mesh more aggressively than inter-ToR. The controller
knows which pinglist a target belongs to, so it stamps `pinglist_type` into
every `PingTarget` (`GenerateTorMeshPinglist` / `GenerateInterTorPinglist`). The
agent merges the two lists into one target list but keeps the stamp, and the
Prober holds **one rate limiter per type**: each limiter's aggregate rate is
`rate_type × (number of targets of that type)`, recomputed on every pinglist
update so the per-target cadence survives churn. `sendProbes` selects the
limiter matching each target's `pinglist_type`.

The rates are configured with `tor_mesh_probe_rate_per_second` and
`inter_tor_probe_rate_per_second`; either left at `0` inherits the legacy
uniform `target_probe_rate_per_second`, so existing single-rate deployments are
unaffected on upgrade.

The two limiters cap their types independently. Note that probes are still sent
from a single per-round loop, so in the (uncommon) regime where the caps
actually bind — i.e. `probe_interval_ms` is short enough that a round would
otherwise exceed the caps — the per-round pacing of the two types is sequential
rather than concurrent. At the default `probe_interval_ms: 500` the caps do not
bind (the interval, not the cap, sets the cadence), so this coupling is not
observable; fully decoupling it would require a separate send loop per type and
is deferred.

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
| `rpingmesh.agent.self_throttle` | Gauge | | Self-protection rate multiplier (`1.0` = unthrottled, down to `0.1`); emitted only when `self_protection_enabled` |

The probe metrics carry two attributes: `source_tor` and `target_tor`. The
`self_throttle` gauge is attribute-free (a single process-wide value).

The controller-side analyzer (Phase 1) exports the following OTLP metrics under
`service.name=rpingmesh-analyzer`:

| Metric | Type | Attributes | Description |
|--------|------|-----------|-------------|
| `rpingmesh.analyzer.path_summaries_total` | Counter | — | Per-path window summaries ingested |
| `rpingmesh.analyzer.sla_violations_total` | Counter | `source_tor`, `target_tor`, `kind` (`loss`/`rtt`) | SLA violations detected |

Analyzer metric attributes are ToR-level only, matching the agent convention;
per-path GID detail appears only in findings logs, never as a metric attribute.

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

> **Note:** `TestProbeToOTelMetrics` (the full probe-to-OTel e2e test, see
> `make test-e2e`) asserts on the *shape* of the recorded metrics rather than
> requiring every probe to succeed (`probeSuccess == 0` is tolerated). Under
> soft-RoCE, software timestamps and the shared-namespace veth topology used
> in CI are not guaranteed to produce a fully successful probe/ACK round
> trip on every run, so this test does not guarantee the success path is
> always exercised end-to-end.

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

- **Analyzer is Phase 1 only (SLA detection, no fault localization).** Agents
  aggregate probe results per path over fixed windows and report `PathSummary`
  batches to the controller, where an in-process analyzer flags per-path SLA
  violations (loss ratio and p99 network-RTT thresholds) to logs and OTLP
  metrics. Topology-aware cross-agent switch/link fault *localization* (Phase 2)
  is future work: it needs a topology join and cross-agent quantile synthesis
  built on the summaries this phase already collects. Summaries are held
  in-memory (a bounded recent-window ring); durable storage is not yet wired up.

- **eBPF service tracing not implemented.** The original R-Pingmesh uses eBPF to
  monitor RDMA QP lifecycle events for service-aware monitoring. This rebuild
  focuses on the probing infrastructure.

- **TLS/mTLS on gRPC is opt-in, not default.** Controller-agent communication
  supports `tls`/`mtls` transport security (see
  [TLS/mTLS for controller-agent gRPC](#tlsmtls-for-controller-agent-grpc)), but the
  default `tls_mode: disabled` still uses plaintext gRPC for backward compatibility.
  Production deployments should set `tls_mode: mtls` on both sides. Certificate
  loading is static (no hot-reload) and rotation is not a goal of this implementation.

- **Inter-ToR *ToR selection* is a fixed-size random sample.** ECMP *path*
  coverage per target is now sized probabilistically via Eq.(1) (see
  [`flow_label` for ECMP Path Coverage](#flow_label-for-ecmp-path-coverage)),
  but the choice of *which* remote ToRs an agent probes for its inter-ToR
  pinglist is still a fixed, configurable random sample of `inter_tor_sample_size`
  ToRs, not itself derived from a coverage-probability target.

- **Analyzer fault localization and Service Tracing remain out of scope.** As
  noted above, the analyzer detects SLA violations (Phase 1) but does not yet
  perform topology-aware switch/link fault localization or priority ranking
  (Phase 2); eBPF-based service tracing from the original design is also not
  part of this rebuild.

- **Agent self-protection is fail-slow and CPU/memory only (opt-in).** The
  watchdog (`self_protection_enabled`, see [Self-protection](#self-protection))
  throttles the probe send rate under local CPU/memory pressure and can install a
  soft `GOMEMLIMIT`/`GOMAXPROCS` cap, but it deliberately never stops probing
  (no fail-closed) and does not react to error rates or downstream backpressure.
  Throttling is coarse (a four-step multiplier) and thresholds are static; there
  is no adaptive control loop.

- **Address Handle `sl` / `traffic_class` are a single agent-wide value, not
  per-target.** `service_level` and `traffic_class` (see Configuration
  above) are applied to every Address Handle the agent creates, on every
  device it opens. There is no way to give individual `PingTarget`s (e.g.
  by `priority`) a different SL/DSCP; that would require per-send AH
  parameterization, which is left for future work. Also note: on rxe
  (soft-RoCE, used by the e2e test suite) the kernel driver does not
  implement PFC or DSCP-based queuing, so the `sl`/`traffic_class` values
  are carried on the wire but their real-world effect (priority-queue
  placement) cannot be verified in that environment — only on real RDMA
  hardware with a PFC/DSCP-aware fabric.

- **No automatic recovery from RDMA device runtime failures.** If an RDMA
  device fails or is removed after the agent has started, there is no
  detection/re-initialization path; the affected Prober/Responder simply
  stops functioning until the agent is restarted.

- **No systemd unit or OS packaging.** Deployment artifacts (systemd units,
  .deb/.rpm packages, etc.) are not provided. There is intentionally no
  Agent Dockerfile: the agent binary requires `CGO_ENABLED=1` and a real (or
  soft-RoCE) RDMA device, which is impractical to containerize generically;
  only the Controller (`Dockerfile.controller`) and test-only images
  (`Dockerfile.e2e`, `Dockerfile.e2e-controller`) are provided.

## References

- Liu et al., "R-Pingmesh: A Service-Aware RoCE Network Monitoring and Diagnostic
  System," SIGCOMM 2024.
- libibverbs API: [rdma-core documentation](https://github.com/linux-rdma/rdma-core)
- Zig language: [ziglang.org](https://ziglang.org)
- OpenTelemetry Go SDK: [opentelemetry.io](https://opentelemetry.io/docs/languages/go/)
