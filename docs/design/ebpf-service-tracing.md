# eBPF Service Tracing

Status: design only, not implemented (tracking ID P3-J). This document
specifies how the agent uses eBPF to trace the lifecycle of application RDMA
QPs, so probe results can be attributed to the services using each RNIC: the
"service-aware monitoring" of the SIGCOMM 2024 R-Pingmesh paper.

## Goals

- **Correlate probe results with services.** Knowing which processes create
  and use QPs on each local RNIC lets the agent answer "which application's
  traffic shares the path a degraded probe just measured", turning a ToR-pair
  anomaly into a service-impact statement.
- **Prepare for service-aware probing.** The same signal shows which RNICs
  actively carry traffic, so probing can later favor the RNIC pairs that
  matter. The first round does not act on it, but the data model must support
  it.
- **Leave the data path alone.** The eBPF subsystem must be separable from the
  Zig/Cgo RDMA bridge and must not affect the build or runtime on non-Linux or
  eBPF-incapable hosts.

## Non-Goals

- No packet or payload inspection. Only QP lifecycle metadata (create, modify,
  destroy, and the owning process and cgroup) is traced.
- No change to the probe protocol, the Zig library, or analyzer
  localization. Service attribution is an enrichment layer.
- No dependency on eBPF for probing. Without eBPF the agent runs exactly as
  today.
- The first round does not implement service-aware prioritization or
  controller-side aggregation of service data.

## Current State (verified against code)

- **No eBPF exists.** There is no eBPF code, no `cilium/ebpf` dependency, and
  no `generate-bpf` Makefile target. eBPF service tracing is listed as out of
  scope in `README.md`.
- **Agent build.** The agent builds with `CGO_ENABLED=1` and links
  `zig/zig-out/lib/librdmabridge.a` through the Cgo directives in
  `internal/rdmabridge/bridge.go`. The controller is pure Go
  (`CGO_ENABLED=0`). eBPF goes in the agent only and must not add a second C
  link step alongside the Zig one.
- **Controller RPCs.** `ControllerService` has `RegisterAgent`, `GetPinglist`,
  and `ReportProbeAnalysis(ProbeAnalysisReport) returns (ProbeAnalysisAck)`
  (`proto/controller_agent/controller_agent.proto`). `AnalysisReporter`
  (`internal/agent/analysis_reporter.go`) aggregates locally, batches, and
  reports best-effort without blocking probing. A service reporter would
  follow the same pattern.
- **Registry QPNs are rpingmesh's own.** The `rnics` table stores, per RNIC,
  the agent's **responder** QPN (`responder.GetQueueInfo()` in
  `buildRegistrationRequest`), not application QPs. Service tracing observes a
  different QP population and adds to registry data rather than changing it.
- **The agent's systemd unit is hardened.**
  `packaging/systemd/rpingmesh-agent.service` runs as user `rpingmesh` with
  `CapabilityBoundingSet=CAP_IPC_LOCK`, `AmbientCapabilities=CAP_IPC_LOCK`,
  `NoNewPrivileges=yes`, `SystemCallFilter=@system-service`,
  `SystemCallErrorNumber=EPERM`, `ProtectKernelTunables=yes`,
  `ProtectKernelModules=yes`, `ProtectControlGroups=yes`,
  `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`,
  `LockPersonality=yes`, and
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`. Several of
  these affect eBPF loading (see
  [Security and systemd impact](#security-and-systemd-impact)).
- **Packaging.** `packaging/nfpm/nfpm-agent.yaml` ships the binary, the unit,
  and an example config. It ships no kernel or BTF assets.

## Design

### What "service" means

A process creates a QP through libibverbs, which issues `ib_uverbs` ioctls
handled by the kernel `ib_uverbs`/`ib_core` layer. Hooking QP create, modify,
and destroy captures, per QP:

- **Owner**: `pid`, `tgid`, `comm`, and `cgroup_id`. The cgroup ID is the
  stable service key under systemd or Kubernetes; `comm` and `pid` are not.
- **Local QP**: the QPN and the local device and port.
- **Remote endpoint**: destination QPN and GID, taken from the transition to
  RTR on connected (RC/UC) QPs. This ties a local service to a remote RNIC and
  therefore to a ToR pair that probes also traverse.
- **Lifecycle**: create and destroy timestamps.

The agent keeps an in-memory **QP→service table** keyed by
**`(device, QPN)`**. A QPN is unique only within one device. On a multi-RNIC
host (the agent already runs one Prober and Responder per device) two RNICs
can assign the same QPN to different applications, and keying on the QPN
alone would attribute a service to the wrong RNIC and ToR pair. The eBPF
program therefore reports a device discriminator (the `ib_device` identity and
port) with each QPN, and userspace resolves it to the local RNIC's GID.

The table joins back to probe results: a probe path
`(source_gid, target_gid)` shares fabric with an application QP whose
`(local device GID, remote GID)` maps to the same ToR pair. rpingmesh's own
probe QPs are UD and never bind a single remote, so they fall out naturally.

### Loader: cilium/ebpf

Use **`github.com/cilium/ebpf`**, a pure-Go loader, with `bpf2go` to generate
CO-RE objects.

- **No second C runtime.** `libbpfgo` links libbpf through Cgo. The agent
  already uses Cgo for Zig, but libbpf would add an unrelated C link and a
  library to ship. `cilium/ebpf` parses ELF and calls `bpf()` directly, so the
  loader has no link-time coupling with the Zig bridge.
- **No clang at runtime.** `bpf2go` compiles the eBPF C at build time into a
  CO-RE object embedded with `go:embed`. The host needs only kernel BTF
  (`/sys/kernel/btf/vmlinux`).
- **Maturity.** `cilium/ebpf` is the de facto pure-Go loader (Cilium,
  Tetragon) and supports ring buffers and CO-RE well.

### Attach points and kernel requirements

In order of preference:

1. **`fentry`/`fexit` on `ib_core` functions**, for example
   `ib_create_qp_user`, `ib_destroy_qp_user`, and `_ib_modify_qp` (the RTR
   transition carries the remote). `fentry` is cheaper than a kprobe and gives
   typed BTF access, but needs BPF trampolines (5.5+) and an attachable
   symbol.
2. **`kprobe`/`kretprobe`** on the same functions where `fentry` cannot
   attach. These function names are not a stable ABI, so the loader must
   tolerate missing symbols.
3. **Tracepoints** would be the most stable, but the RDMA tracepoints do not
   cover create/modify/destroy with the remote endpoint, so they are not the
   primary mechanism.

At startup the loader probes which symbols are attachable and whether BTF has
the required struct fields, and disables tracing if not.

**Minimum kernel: Linux 5.8.** The BPF ring buffer and the
`CAP_BPF`/`CAP_PERFMON` split both landed in 5.8, and CO-RE needs kernel BTF
(`CONFIG_DEBUG_INFO_BTF=y`). On older kernels tracing is disabled and the
agent is otherwise unaffected.

### Agent integration

- **New package** `internal/agent/servicetrace/` (Linux only): the embedded
  CO-RE object generated by `bpf2go`, the loader, a ring-buffer reader
  goroutine, and the QP→service table.
- **Build-tag isolation.** eBPF files carry `//go:build linux`; a
  `//go:build !linux` stub provides a no-op `Tracer`, so macOS development
  builds are unchanged. The clang→BPF compile never shares a translation unit
  or link step with the Cgo/Zig build.
- **Graceful degradation.** When `service_tracing_enabled` is true, the
  tracer checks kernel version, BTF, capabilities, and attach points. Any
  failure logs a warning and the agent continues without tracing, the way
  `createMetricsCollector` continues without metrics.
- **Lifecycle.** Create the tracer in `Agent.Initialize` behind the config
  gate. Start its ring-buffer reader goroutine in `Start`. In `Stop`, detach
  the programs, close the maps, and join the goroutine. The RDMA teardown is
  untouched.

### Data model

```go
// Linux only. One record per observed application QP.

// QPKey is (device, QPN), never the QPN alone: QPNs are unique only within
// one device, so two RNICs on a host can reuse the same value.
type QPKey struct {
    DeviceGID [16]byte // local RNIC, resolved from the device discriminator
    LocalQPN  uint32
}

type QPRecord struct {
    Key         QPKey
    RemoteQPN   uint32   // 0 until the RTR transition is observed
    RemoteGID   [16]byte // zero until RTR is observed (stays zero for UD)
    PID         uint32
    CgroupID    uint64   // service key
    Comm        string
    CreatedNs   uint64
    DestroyedNs uint64   // 0 while live
}
```

GIDs are 16-byte binary values, as in `probe.PathKey`; they become strings
only for logs.

The kernel program writes fixed-layout create, modify-to-RTR, and destroy
events to the ring buffer. Each event carries the device discriminator and
port with the QPN. The Go reader resolves the discriminator to `DeviceGID` and
folds events into a `map[QPKey]*QPRecord`. Reporting aggregates QPs to
**service (cgroup) × remote ToR**, so no GID or PID reaches a metric.

### Reporting to the controller

**First round: no controller reporting.** The table stays local and is
exposed only through low-cardinality OTLP metrics. This proves the tracer with
the least surface area and no proto change.

**Second round: a new RPC**, `ReportServiceTracing(ServiceTracingReport)
returns (ServiceTracingAck)`, following the `AnalysisReporter` best-effort
pattern. Extending `ReportProbeAnalysis` is rejected: service data has a
different shape, a lower and event-driven cadence, and a different consumer
(service-impact correlation, not SLA detection or localization).

### OTLP metrics (first round)

Registered on the agent's `rpingmesh.agent` meter, next to
`rpingmesh.agent.self_throttle`:

| Metric | Type | Attributes | Meaning |
|--------|------|------------|---------|
| `rpingmesh.agent.service_trace_enabled` | Gauge (0/1) | none | tracer active or degraded |
| `rpingmesh.agent.active_qps` | Gauge | none | live application QPs observed |
| `rpingmesh.agent.qp_events_total` | Counter | `kind` (`create`/`modify`/`destroy`) | traced lifecycle events |

Per-service and per-remote-ToR attributes wait for the second round, when a
bounded service key (a cgroup→service-name mapping) exists. PID and GID
attributes are unbounded and never allowed. The local RNIC
(`source_rdma_device`) is bounded and may be added if per-device counts are
needed.

## Security and systemd Impact

On 5.8+, loading programs and maps needs **`CAP_BPF`**, and attaching
kprobe/fentry programs needs **`CAP_PERFMON`**. Older kernels need
`CAP_SYS_ADMIN`, which this design does not support. The agent also needs
read access to `/sys/kernel/btf/vmlinux`.

The base unit changes only when tracing is enabled:

- **Capabilities.** Add `CAP_BPF CAP_PERFMON` to `CapabilityBoundingSet` and
  `AmbientCapabilities`, keeping `CAP_IPC_LOCK`. Do not add `CAP_SYS_ADMIN`.
- **Syscall filter.** `@system-service` may not include `bpf()` and
  `perf_event_open()` on every systemd version. Add them explicitly, for
  example with a second `SystemCallFilter=bpf perf_event_open` line.
  Otherwise loading fails with `EPERM`.
- **`MemoryDenyWriteExecute=yes`** restricts userspace W+X mappings, not the
  in-kernel BPF JIT, so it should not block loading. Verify on the target
  kernel.
- **`RestrictNamespaces=yes`, `LockPersonality=yes`**: expected to be
  compatible; verify.
- **`ProtectKernelTunables=yes`** makes parts of `/sys` read-only but still
  readable, so reading BTF should work; verify the path is visible.
- **`ProtectControlGroups=yes`** makes the cgroup tree read-only. Reading it
  to map cgroup IDs to names should still work; verify.
- **Kernel lockdown.** In lockdown "confidentiality" mode the kernel blocks
  BPF regardless of capabilities. The agent can only detect this and degrade.

**Packaging.** Keep the base unit at `CAP_IPC_LOCK` and ship an opt-in
systemd drop-in (`rpingmesh-agent.service.d/10-ebpf.conf`) that operators
enable together with tracing. The nfpm package can include it as an example
file. Least privilege stays the default, and enabling tracing is an explicit,
auditable capability grant.

## Alternatives Considered

- **libbpfgo.** Rejected: a libbpf C dependency and a second C link next to
  Zig. Its only advantage is closer parity with upstream libbpf helpers.
- **Runtime compilation (BCC style).** Rejected: needs clang and kernel
  headers on every host. CO-RE needs only BTF.
- **Extend `ReportProbeAnalysis`.** Rejected; see
  [Reporting to the controller](#reporting-to-the-controller).
- **RDMA netlink instead of eBPF.** `rdma resource show qp` lists QPs with
  their owning PID, needs no eBPF or `CAP_BPF`, and uses `AF_NETLINK`, which
  the unit already allows. It is a valid way to ship a live-QP count first.
  But it is a polled snapshot: it misses short-lived QPs and does not give
  lifecycle events or a reliable RTR-time remote binding. If the first round
  needs only a liveness count, netlink polling is simpler; eBPF is warranted
  once event-accurate lifecycle and remote binding are required. See
  [Open Questions](#open-questions).
- **Trace in the mlx5 driver.** Rejected as vendor-specific; `ib_core` is
  vendor-neutral.
- **Loosen the base unit for everyone.** Rejected; the drop-in keeps
  capabilities opt-in.

## Test Plan

eBPF needs a real Linux kernel with BTF, so most logic is designed to be
testable without loading a program.

- **Pure Go (no kernel).** Table folding (create → RTR → destroy, device→GID
  resolution, cgroup keying) driven by synthetic events, and the degradation
  decision (old kernel, no BTF, missing capability) with injected
  feature-probe results. The `!linux` stub builds and does nothing.
- **Composite-key regression.** Two create events with the same QPN on two
  devices must produce two `QPKey` entries mapped to their own services.
- **Loader/verifier (Linux CI).** The embedded CO-RE object loads and passes
  the verifier against the CI kernel's BTF. `cilium/ebpf` can load without
  attaching, so no QP traffic is needed.
- **Integration (Linux + rxe).** Create an application RC QP on soft-RoCE
  (for example with an `ibv_rc_pingpong`-style helper) and assert the tracer
  sees create, modify, and destroy. Run it as a privileged Linux-only test,
  like `make test-e2e`.
- **systemd.** `systemd-analyze verify` on the base unit and the drop-in.
  With the drop-in, loading succeeds; without it, the agent logs `EPERM` and
  continues.
- **Cardinality.** First-round metrics carry no PID or GID attributes.

## Implementation Plan (PR breakdown)

1. **P3-J.1: skeleton and degradation (nothing attached).** Add
   `cilium/ebpf` and `bpf2go` to the agent build, the `servicetrace` package
   with the Linux/`!linux` split, feature detection, the
   `service_tracing_enabled` config key, and the `service_trace_enabled`
   gauge. Proves the loader coexists with the Zig/Cgo build at no risk to
   probing.
2. **P3-J.2: QP-lifecycle program and local table.** CO-RE program for create
   and destroy (plus modify-to-RTR), ring-buffer reader, QP→service table,
   `active_qps` and `qp_events_total`. Loader/verifier CI test and rxe
   integration test. **This is the minimal useful deliverable.** If loader
   work slips, ship the netlink poll here first.
3. **P3-J.3: systemd drop-in and packaging.** `10-ebpf.conf`
   (`CAP_BPF`/`CAP_PERFMON`, syscall filter), nfpm inclusion as an opt-in
   example, and a note in the README "Deployment" section.
4. **P3-J.4 (second round): controller reporting and service-impact join.**
   `ReportServiceTracing` RPC, a best-effort reporter modeled on
   `AnalysisReporter`, a controller-side join of service × remote ToR against
   localization findings (see `analyzer-phase2-localization.md`), and a
   bounded service label.
5. **P3-J.5 (later): service-aware probe prioritization.** Use QP liveness to
   bias pinglists or probe rates toward pairs that carry traffic. Depends on
   J.4.

## Open Questions

- **eBPF or netlink for the first slice?** If the immediate goal is only "how
  many application QPs are live per host", `rdma resource show qp` is much
  simpler. Are event-accurate lifecycle and RTR-time remote binding required
  from day one? This decides whether J.2 uses eBPF or netlink. *(User input
  needed.)*
- **Service identity.** Can cgroup IDs be resolved to service names in the
  target environment (systemd slice, Kubernetes pod), and who owns that
  mapping (agent config, a sidecar, the controller)? This gates the bounded
  service label. *(User input needed.)*
- **Fleet kernel versions.** Tracing is off below 5.8. Is that acceptable for
  the fleet? The answer also sets how many attach-point candidates the loader
  must carry. *(User input helpful.)*
- **Capability posture.** Is granting `CAP_BPF` and `CAP_PERFMON` acceptable
  to the security owners? The drop-in keeps it opt-in, but the policy decision
  is theirs. *(User input needed.)*
