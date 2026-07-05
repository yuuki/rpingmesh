# eBPF Service Tracing

Status: Design only (P3-J). No implementation is proposed here. This document
specifies how the agent should use eBPF to trace RDMA QP lifecycle so probe
results can be attributed to the services actually using each RNIC — the
"service-aware monitoring" of the SIGCOMM 2024 R-Pingmesh paper.

## Goals

- **Correlate probe results with services.** By observing which processes create
  and use RDMA QPs on each local RNIC, the agent can answer "which application's
  traffic shares the fabric path that a degraded probe just measured", turning a
  ToR-pair anomaly into a service-impact statement.
- **Enable service-aware probing later.** The same QP-lifecycle signal
  identifies which RNICs are *actively serving* traffic, so probing effort can be
  prioritized toward RNIC pairs that matter (a paper concept; out of scope to
  *act* on in the first round, but the data model must support it).
- **Do this without disturbing the data path.** The eBPF subsystem must be
  cleanly separable from the Zig/Cgo RDMA bridge and must not affect the agent's
  build or runtime on non-Linux / eBPF-incapable hosts.

## Non-Goals

- No packet-level or payload inspection. Only QP **lifecycle** metadata
  (create/modify/destroy + owning process/cgroup) is traced.
- No change to the probe protocol, the Zig library, or the analyzer's
  localization. Service attribution is an *enrichment* layer.
- No dependency on eBPF for core probing. If eBPF is unavailable the agent runs
  exactly as today (graceful degradation).
- First round does **not** implement service-aware probe prioritization or
  controller-side aggregation of service data — those are explicitly later
  scopes. The first round proves the tracer and exposes local signal.

## Current State (verified against code)

- **No eBPF anywhere.** `rebuild/CLAUDE.md` states the eBPF component is out of
  scope; the Makefile confirms it ("there is no eBPF; `make generate-bpf` does
  not exist"). The legacy top-level tree had eBPF ambitions but the rebuild has
  none.
- **Agent build**: `CGO_ENABLED=1 go build ./cmd/agent/` linking the Zig static
  library `zig/zig-out/lib/librdmabridge.a` via Cgo LDFLAGS in
  `internal/rdmabridge/bridge.go`. Controller is `CGO_ENABLED=0` pure Go. Any
  eBPF addition must not perturb this: it goes in the agent only, and must not
  add a second C-toolchain coupling that fights the existing Zig/Cgo link.
- **Reporting RPCs**: `ControllerService` has `RegisterAgent`, `GetPinglist`,
  and `ReportProbeAnalysis(ProbeAnalysisReport) -> ProbeAnalysisAck`
  (`proto/controller_agent/controller_agent.proto`). The analysis-reporting
  pattern — agent aggregates locally, batches, ships best-effort, never blocks
  probing (`internal/agent/analysis_reporter.go`) — is the template a service
  reporter would follow.
- **Registry** maps GID→ToR and stores QPN per RNIC (`rnics` table). The QPN it
  stores is the agent's **responder** QPN (from `responder.GetQueueInfo()` in
  `buildRegistrationRequest`), i.e. rpingmesh's own probe QPs — *not* the
  application QPs eBPF would trace. Service tracing observes a different QP
  population (the workloads'), so it is additive, not a modification of registry
  data.
- **systemd unit** (`packaging/systemd/rpingmesh-agent.service`) is
  deliberately hardened and grants only `CAP_IPC_LOCK`:
  `CapabilityBoundingSet=CAP_IPC_LOCK`, `AmbientCapabilities=CAP_IPC_LOCK`,
  `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`,
  `ProtectKernelModules=yes`, `ProtectKernelTunables=yes`,
  `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`,
  `LockPersonality=yes`, `RestrictAddressFamilies=... AF_NETLINK`. **Every one of
  these interacts with eBPF loading** and must be revisited (see Security).
- **nfpm packaging** (`packaging/nfpm/nfpm-agent.yaml`) ships the binary,
  systemd unit, config; no kernel/BTF assets.

## Design

### Purpose model: what "service" means here

An RDMA QP is created by a process via the userspace verbs library, which issues
`ib_uverbs` ioctls handled in the kernel `ib_uverbs`/`ib_core` layer. By hooking
the QP create/modify/destroy path, an eBPF program captures, per QP:

- **owner identity**: `pid`, `tgid`, `comm`, and `cgroup_id` (the cgroup id is
  the robust service key under systemd/k8s — `comm`/`pid` alone are not stable
  service identities);
- **local QP**: assigned `qpn`, and the local device/port;
- **remote endpoint** (from `modify_qp` to RTR for connected QPs): destination
  QPN and destination GID (`dgid`) — this is what ties a *local service* to a
  *remote RNIC*, and thus to a ToR-pair that probes also traverse;
- **lifecycle**: create timestamp, destroy timestamp → QP liveness.

The agent maintains an in-memory **QP→service table** keyed by local QPN,
enriched with the remote GID/QPN. That table is the join key back to probe
results: a probe path `(source_gid, target_gid)` shares fabric with an
application QP whose `(local device gid, dgid)` matches the same ToR-pair. Note
UD (rpingmesh's own QPs) never modify to a single remote, so rpingmesh's probe
QPs are naturally excluded/ignorable; the workloads' RC/UC QPs carry a remote.

### Technology choice: cilium/ebpf (recommended) vs libbpf-go

Recommendation: **`github.com/cilium/ebpf`** (pure-Go loader) with `bpf2go` for
CO-RE object generation.

Reasoning, from first principles against this codebase's constraints:

- **Keep the eBPF subsystem free of a second C runtime.** `libbpf-go`
  (`github.com/aquasecurity/libbpfgo`) requires CGO to link libbpf (a C library).
  The agent is already `CGO_ENABLED=1` for Zig, so CGO per se is not blocked —
  but adding a *libbpf* C dependency means a second, unrelated C link and a
  runtime `.so`/static libbpf to ship, entangled with the Zig link. `cilium/ebpf`
  is **pure Go**: it parses ELF and calls `bpf()` via syscalls directly, so the
  eBPF loader has **zero** C-link coupling with the Zig bridge. That separation
  is the whole point of the "non-interfering with CGO/Zig" requirement.
- **CO-RE without a runtime clang.** `bpf2go` compiles the eBPF C **at build
  time** with clang into a CO-RE object embedded via `go:embed`; the running
  agent needs only kernel BTF (`/sys/kernel/btf/vmlinux`) to relocate, not a
  clang on the target host. This keeps the *runtime* dependency to "a modern
  kernel with BTF", nothing else.
- **Maturity/ecosystem.** `cilium/ebpf` is the de-facto standard pure-Go loader
  (used by Cilium, Tetragon), actively maintained, with good ring-buffer and
  CO-RE support.

libbpf-go's only real edge is closer parity with upstream libbpf helpers; not
worth the C-link entanglement here.

### Attach points and kernel requirements

QP lifecycle is reachable in the kernel RDMA stack. Options, in order of
preference:

1. **`fentry`/`fexit` on `ib_core` functions** (e.g. the QP create/destroy paths
   such as `ib_create_qp_user` / `ib_destroy_qp_user`, and `_ib_modify_qp` for
   the RTR transition that carries the remote). `fentry` is lower-overhead than
   kprobe and gives typed access via BTF, but requires a kernel new enough for
   BPF trampolines (5.5+) and the symbol to be attachable.
2. **`kprobe`/`kretprobe`** on the same functions as a fallback where `fentry`
   isn't attachable. Broadest availability; function names are **not** a stable
   ABI, so the program must tolerate missing symbols and select at load time.
3. **Tracepoints** would be most stable, but the RDMA subsystem's tracepoints do
   not cleanly cover the create/modify/destroy-with-remote data the model needs,
   so they are not the primary mechanism.

Because attach-point function names vary across kernels, the loader must **probe
availability at startup** (is the symbol attachable? does BTF have the needed
struct fields?) and degrade gracefully if not.

**Kernel version requirement**: target **Linux 5.8+**. Rationale: BPF ring buffer
(the event channel to userspace) landed in 5.8; `CAP_BPF`/`CAP_PERFMON` split
landed in 5.8; CO-RE needs kernel BTF (`CONFIG_DEBUG_INFO_BTF=y`), common on
distro kernels 5.4+ but reliably present alongside the 5.8 features. Below 5.8,
service tracing is simply disabled (graceful degradation), agent unaffected.

### Agent integration

- **New package** `internal/agent/servicetrace/` (Linux-only), containing:
  the embedded CO-RE object (`bpf_bpfel.go` etc. from `bpf2go`), the loader, a
  ring-buffer reader goroutine, and the QP→service table.
- **Build-tag isolation.** All eBPF-touching Go files carry `//go:build linux`.
  A parallel `//go:build !linux` stub provides a no-op `Tracer` so the agent
  compiles and runs on macOS/dev unchanged. The `bpf2go`-generated object and
  its `go:embed` are also Linux-tagged. This guarantees **no build or runtime
  impact off Linux** and keeps the eBPF C compile (clang→BPF) entirely separate
  from the host Cgo/Zig compile — they never share a translation unit or linker
  invocation.
- **Runtime feature detection + graceful degradation.** At agent start, if
  `service_tracing_enabled` is true, the tracer attempts: verify kernel ≥5.8 +
  BTF present + required capability + attach points resolvable. Any failure →
  **log a warning and continue without tracing** (mirroring how
  `createMetricsCollector` degrades to no-metrics on failure). Tracing is never
  load-bearing for probing.
- **Lifecycle.** The tracer is created in `Initialize` (behind the config gate),
  started in `Start` (its own goroutine reading the ring buffer, same
  poll-in-a-goroutine spirit as the completion/async rings), and stopped in
  `Stop` (detach programs, close maps, join goroutine) — slotting into the
  existing ordered startup/shutdown without touching the RDMA teardown.

### Collected data model

```go
// Linux-only. One row per observed application QP.
type QPRecord struct {
    LocalQPN    uint32
    DeviceGID   string   // local RNIC GID (mapped from device/port)
    RemoteQPN   uint32   // 0 until RTR modify observed
    RemoteGID   string   // "" until RTR modify observed (UD stays empty)
    PID         uint32
    CgroupID    uint64   // service key
    Comm        string
    CreatedNs   uint64
    DestroyedNs uint64   // 0 while live
}
```

The kernel program emits compact fixed-layout events into the ring buffer
(create / modify-RTR / destroy); the Go reader folds them into the table and
resolves `DeviceGID` from the device/port index. Aggregation for reporting rolls
QPs up to **service (cgroup) × remote ToR**, so nothing GID-level or PID-level
reaches a metric.

### Reporting path to the controller

**Recommendation: a new RPC, not an extension of `ReportProbeAnalysis`.**
Rationale: service data has a different shape, a different cadence (QP lifecycle
is event-driven and far lower volume than probe windows), and a different
consumer (it feeds service-impact correlation, not SLA/localization). Overloading
`ProbeAnalysisReport` would couple two independent concerns and bloat a hot
message. A separate `ReportServiceTracing(ServiceTracingReport) ->
ServiceTracingAck` mirrors the existing best-effort reporter pattern.

However, for the **first round, defer controller reporting entirely.** The
minimal first PR keeps the QP→service table **local** and exposes it only as
low-cardinality OTLP (e.g. `rpingmesh.agent.active_qps{}` — a count of live
application QPs, no per-service attribute until a bounded service label is
agreed). This proves the tracer end-to-end with the least surface area and no
proto change. Controller reporting and service-impact join are the second round.

### OTLP (first round, low cardinality)

| metric | type | attributes | meaning |
|--------|------|-----------|---------|
| `rpingmesh.agent.service_trace_enabled` | Gauge (0/1) | — | tracer active vs degraded |
| `rpingmesh.agent.active_qps` | UpDownCounter/Gauge | — | live application QPs observed |
| `rpingmesh.agent.qp_events_total` | Counter | `kind` (create/modify/destroy) | traced lifecycle events |

Per-service / per-remote-ToR attributes are withheld until the second round when
a bounded service key (cgroup→service-name mapping) is defined; unbounded PID or
GID attributes would violate the cardinality rule.

## Security / privileges (and systemd impact)

Loading eBPF programs and attaching fentry/kprobe requires elevated capability.
On 5.8+: **`CAP_BPF`** (load programs/maps) **+ `CAP_PERFMON`** (attach
kprobe/fentry via perf); pre-5.8 it collapses to `CAP_SYS_ADMIN`. Reading kernel
BTF from `/sys/kernel/btf/vmlinux` needs read access to that path.

The current hardened unit must change **only when tracing is enabled**. Concrete
impacts on `packaging/systemd/rpingmesh-agent.service`:

- **Capabilities**: add `CAP_BPF CAP_PERFMON` to `CapabilityBoundingSet` and
  `AmbientCapabilities` (keeping `CAP_IPC_LOCK`). Do **not** add
  `CAP_SYS_ADMIN` on 5.8+.
- **Syscall filter**: `SystemCallFilter=@system-service` must permit `bpf()` and
  `perf_event_open()`. These are not guaranteed in `@system-service` on all
  systemd versions; add them explicitly (e.g. append a second
  `SystemCallFilter=bpf perf_event_open` line, or use systemd's `@bpf` set where
  available). Without this, the load fails with EPERM.
- **`MemoryDenyWriteExecute=yes`**: this restricts *userspace* W^X mappings, not
  the in-kernel BPF JIT, so it should not block loading — but it must be verified
  on the target kernel; if a specific loader path trips it, MDWX may need
  relaxing under the tracing profile.
- **`RestrictNamespaces=yes` / `LockPersonality=yes`**: generally compatible with
  eBPF loading; verify.
- **`ProtectKernelTunables=yes`**: makes `/proc/sys` and parts of `/sys`
  read-only but still readable — BTF read at `/sys/kernel/btf/vmlinux` is a read,
  so it should be fine; verify the path is not hidden.
- **kernel lockdown**: on a kernel with Lockdown LSM in "confidentiality" mode,
  BPF is blocked outright regardless of capabilities — this is a host policy the
  agent can only detect and degrade against, not override.

**Packaging**: gate all of the above behind a **separate hardening profile** so
the default (tracing-off) unit keeps its minimal `CAP_IPC_LOCK` posture. Options:
ship a systemd **drop-in** (`rpingmesh-agent.service.d/10-ebpf.conf`) that the
operator enables when turning tracing on, rather than loosening the base unit for
everyone. The nfpm package can include the drop-in as a disabled/example file.
This keeps least-privilege the default and makes enabling tracing an explicit,
auditable capability grant.

## Alternatives Considered

- **libbpf-go instead of cilium/ebpf.** Rejected: it adds a libbpf C dependency
  and a second C-link entangled with the Zig/Cgo build, contradicting the
  "non-interfering" requirement. cilium/ebpf is pure Go and keeps the eBPF loader
  C-free.
- **Compile eBPF on the target with clang at runtime (BCC-style).** Rejected:
  requires clang + kernel headers on every agent host, heavy and fragile. CO-RE +
  `go:embed` needs only BTF at runtime.
- **Extend `ReportProbeAnalysis` with service fields.** Rejected: couples two
  independent concerns with different cadence/volume/consumers; a dedicated RPC
  (in the second round) is cleaner and matches the existing reporter pattern.
- **Parse `/sys/class/infiniband/*/ports/*/...` or netlink RDMA (`rdma
  resource`) instead of eBPF.** Considered as a lighter alternative for QP
  enumeration: `rdma resource show qp` (RDMA netlink) can list QPs with owning
  PID and does not need eBPF/CAP_BPF. It is a legitimate **fallback for the
  minimal "active QP count"** signal and could ship first with zero eBPF. But it
  is a *poll* snapshot, misses short-lived QPs, and does not give create/destroy
  events or the RTR-time remote binding as reliably. Recommendation: if the first
  round's goal is only a liveness count, the RDMA-netlink poll is a strictly
  simpler starting point; eBPF is warranted once event-accurate lifecycle and
  remote binding are needed. This trade-off is called out as an Open Question.
- **Trace at the mlx5 driver level.** Rejected as vendor-specific; the
  `ib_uverbs`/`ib_core` path is vendor-neutral.
- **Loosen the base systemd unit for everyone.** Rejected: keep least-privilege
  default; gate capabilities behind an opt-in drop-in.

## Test Plan

eBPF is the least CI-friendly component (needs a real Linux kernel with BTF), so
the plan is staged with most logic testable without loading a program.

- **Pure-Go unit tests (no kernel)**: the QP→service table folding (create →
  modify(RTR) → destroy transitions, device→GID resolution, cgroup keying) driven
  by synthetic event structs; the graceful-degradation decision logic (kernel
  too old / no BTF / no cap → disabled) with injected feature-probe results. The
  `!linux` stub compiles and is a no-op.
- **Loader/verifier test (Linux CI)**: assert the embedded CO-RE object **loads
  and verifies** against the CI kernel's BTF (`cilium/ebpf` can load without
  attaching). This catches verifier regressions without needing to generate real
  QP traffic.
- **Integration (Linux + rxe)**: on the soft-RoCE CI env, create an application
  RC QP (a tiny rdma-core `ibv_rc_pingpong`-style helper, or `rdma resource`
  cross-check), and assert the tracer observes create/modify/destroy and the
  QP→service table reflects it. Gate as a Linux/privileged-only test, like the
  existing `test-e2e`.
- **systemd verification**: `systemd-analyze verify` on the base unit and the
  eBPF drop-in; a manual/CI check that with the drop-in the load succeeds and
  without it the agent degrades gracefully (EPERM handled, not crashed).
- **Cardinality guard**: assert first-round metrics carry no per-PID/per-GID
  attributes.

## Implementation Plan (PR breakdown)

Minimal first slice is explicit and small; controller integration is later.

1. **P3-J.1 — Tracer skeleton + graceful degradation (no attach).** Add
   `cilium/ebpf` + `bpf2go` to the build (agent only), the `servicetrace` package
   with Linux/`!linux` split, feature detection (kernel/BTF/cap probing), the
   `service_tracing_enabled` config gate, and the `service_trace_enabled` gauge.
   No program attached yet — this lands the build plumbing and the
   degrade-to-off path with zero risk to probing, and proves cilium/ebpf coexists
   with the Zig/Cgo build.
2. **P3-J.2 — Minimal QP-lifecycle program + local table.** The CO-RE eBPF C for
   create/destroy (+ RTR modify for remote), ring-buffer reader, QP→service
   table, and `active_qps` / `qp_events_total` metrics. Loader/verifier CI test +
   rxe integration test. **This is the minimal useful first deliverable.**
   Optionally, ship the **RDMA-netlink poll fallback** here first if the loader
   work slips (see Alternatives).
3. **P3-J.3 — systemd eBPF drop-in + packaging.** The
   `rpingmesh-agent.service.d/10-ebpf.conf` drop-in (CAP_BPF/CAP_PERFMON, syscall
   filter additions), nfpm inclusion as an opt-in example, README "Deployment
   (systemd)" note. `systemd-analyze verify`.
4. **P3-J.4 (second round) — Controller reporting + service-impact join.** New
   `ReportServiceTracing` RPC, best-effort reporter mirroring
   `analysis_reporter.go`, and the controller-side join of service (cgroup ×
   remote ToR) against localization findings. Bounded service label for metrics.
5. **P3-J.5 (later) — Service-aware probe prioritization.** Use QP liveness to
   bias pinglist/rate toward actively-served RNIC pairs (a paper concept). Depends
   on J.4's data reaching the controller/pinglist generation.

## Open Questions

- **eBPF vs RDMA-netlink poll for the first slice.** If the immediate goal is
  only "how many application QPs are live per host", `rdma resource show qp`
  (netlink, no CAP_BPF, no eBPF) is dramatically simpler and could ship first. Is
  event-accurate lifecycle + RTR-time remote binding required from day one, or is
  a poll-based liveness count an acceptable v1? *(User input needed — this decides
  whether J.2 is eBPF or netlink.)*
- **Service identity key.** Is cgroup id → service name resolvable in the target
  environment (systemd slice / k8s pod), and who owns that mapping (agent config,
  a sidecar, the controller)? This gates the bounded service label for metrics
  and reporting. *(User input needed.)*
- **Minimum kernel across the fleet.** The design targets 5.8+. If a meaningful
  fraction of hosts run older kernels, service tracing is simply off there —
  acceptable? *(User input helpful.)*
- **Capability posture.** Is granting `CAP_BPF`+`CAP_PERFMON` to the agent
  acceptable to the security owners, given the base unit's deliberately minimal
  `CAP_IPC_LOCK`? The drop-in keeps it opt-in, but the policy call is theirs.
  *(User input needed.)*
- **Attach-point stability.** `ib_core` function names are not a stable ABI; the
  loader must select/degrade per kernel. Which kernel versions must be supported
  concretely determines how many attach candidates to carry. *(User input
  helpful.)*
