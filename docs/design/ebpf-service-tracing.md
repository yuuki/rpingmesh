# eBPF Service Tracing

Status: implemented (`internal/agent/servicetrace`,
`internal/agent/service_monitor.go`, the `GetTargetRnicInfo` RPC). This
document records the design and the reasons behind its departures from the
first draft, which planned to trace `ib_core` functions with CO-RE.

## Goal

The SIGCOMM 2024 paper (section 4.2.2) traces the kernel's `modify_qp` and
`destroy_qp` with eBPF to learn the 5-tuples of the RDMA connections a
service opens, then probes the paths those 5-tuples take so the service
network's RTT and loss are measured on the paths the service uses. This
implementation does the same: an eBPF tracer reports queue pair lifecycle
events, the agent folds them into live connections, resolves the remote
RNICs through the controller, and probes each flow with the flow's own flow
label through its existing UD queue.

## Design

### What the tracer reads

The tracer attaches kprobes and kretprobes to the entry points of the uverbs
character device, `ib_uverbs_ioctl` and `ib_uverbs_write`, plus a kprobe on
`ib_uverbs_close`, and parses the command buffers libibverbs passes to the
kernel:

| Command | Path | What is read |
|---------|------|--------------|
| `CREATE_QP`, `EX_CREATE_QP`, `OPEN_QP` | `write(2)`, or ioctl `INVOKE_WRITE` | the QP type from the request; the handle and QPN from the response, after the kernel wrote it |
| ioctl `QP_CREATE` method | ioctl | the type from the `CREATE_QP_TYPE` attribute; the handle the kernel writes back into the `CREATE_QP_HANDLE` attribute and the QPN behind `RESP_QP_NUM` |
| `MODIFY_QP`, `EX_MODIFY_QP` | `write(2)` or `INVOKE_WRITE` | `attr_mask`, `qp_state`, `dest_qp_num`, and the address vector: `dgid`, `flow_label`, `sgid_index`, `port_num`, `hop_limit`, `traffic_class`, `sl` |
| `DESTROY_QP`, ioctl `QP_DESTROY` | either | the handle |
| file release | `ib_uverbs_close` | the context identity: every QP of the context is gone |

Commands are staged in a per-task map at entry and emitted from the return
probe only when the kernel returned success, so a failed RTR never becomes a
connection. Every entry probe first discards the task's previous staging:
return probes can be missed (kretprobe `maxactive` exhaustion), and a stale
entry must not be completed by the next, unrelated command's success. Each event carries the context identity (the `struct file`
pointer, unique per `ibv_open_device`), the device number of the uverbs node
the context was opened on (`struct file -> f_inode -> i_rdev`, the only
kernel-internal reads, relocated with CO-RE against the vmlinux BTF), the
calling process (pid, comm, cgroup id) and the command's fields. Events go to
user space through a 1 MiB BPF ring buffer; drops and parse failures are
counted in a stats map.

The Go side (`servicetrace.Table`) joins creates, modifies and destroys by
(context, handle) into connections: a create records the QPN and type; an
RTR transition with an address vector on an RC, UC or XRC QP makes a
connection; a reset, a destroy or the context's release ends it. UD, raw
packet and driver-specific QPs (the agent's own probing queues among them)
never form connections.

### Why the uverbs ABI and not `ib_core`

The first draft planned `fentry`/`kprobe` programs on `ib_modify_qp_with_udata`
and `ib_destroy_qp_user`, reading `struct ib_qp` and `struct ib_qp_attr` with
CO-RE. That needs BTF for the module that defines those structures. On the
GPU clusters this project targets, the RDMA modules come from an out-of-tree
stack (`mlnx-ofa_kernel`) and ship without BTF, and their structure layouts
differ from the in-tree kernel's, so CO-RE has nothing to relocate against.
The uverbs user-space ABI (`include/uapi/rdma/ib_user_verbs.h`,
`ib_user_ioctl_cmds.h`) is stable by definition, every libibverbs relies on
it, and it carries everything the paper's tracing needs. The entry points
are local symbols of `ib_uverbs` but are present in kallsyms on both
in-tree and out-of-tree stacks, and kprobes attach to them by name without
BTF.

The default tracer cannot see kernel ULPs (NVMe-oF, NFS over RDMA, Lustre),
which do not go through uverbs. The optional module-BTF extension below
handles their new connections. The trace sees commands, not QPs that
already existed; supported user QPs can be recovered through snapshots.

### Optional kernel ULP tracing

Set `service_tracing_kernel_ulp_enabled: true` together with
`service_tracing_enabled: true` to load a separate CO-RE object. The same
setting is exposed as `--service-tracing-kernel-ulp-enabled` and
`RPINGMESH_SERVICE_TRACING_KERNEL_ULP_ENABLED`. It is disabled by default.
It requires `/sys/kernel/btf/ib_core`, in addition to the default tracer's
vmlinux BTF, ring buffer and capability requirements. Missing/unreadable
module BTF, incompatible types, or probe attachment failures produce a
warning and leave uverbs tracing active. No guessed OFED offsets are used.

The extension attaches entry/return probes to `ib_modify_qp` and
`ib_destroy_qp_user` (the non-inline implementation behind `ib_destroy_qp`).
It reads individual fields of `ib_qp`, `ib_qp_attr`, `rdma_ah_attr` and
`ib_device` using module BTF. QPs with `uobject != NULL`, UD/raw/driver QPs,
and non-RoCE address vectors are excluded. Events are staged per task and
published only on successful return; every entry clears old staging. The
destroy return probe never reads the potentially freed QP. The separate
object shares the uverbs ring buffer and drop/parse counters.

A successful RTR with a complete global address vector establishes a
connection directly, without inventing a uverbs create or handle. Its
identity is the `ib_qp` pointer in a separate namespace. The monitor maps
the kernel device name to the same sysfs device number used for uverbs.
Unknown names are discarded; the published device map is refreshed on each
inventory cycle. Reset, error and successful destroy remove the connection.
Successful netlink inventories also remove missing, disconnected or
detectably reused kernel QPs, with the same per-device generation check
that protects user snapshots from concurrent events. Failed inventories
leave connections intact. Reconciliation only removes connections on the
successfully inventoried devices, including devices whose QP list is empty;
connections on devices outside that scope retain their diagnostic counts.
Reuse with identical QPN/type/remote QPN after
lost lifecycle events cannot be distinguished by the generic inventory.

Kernel workers' PID and cgroup are not service ownership. Kernel connections
have zero process/cgroup identity and use the existing `_unspecified` label
when service labels are enabled. They are not reaped when a worker exits.
Only connections established after attachment are discovered; this option
does not recover pre-existing kernel QPs, attribute them to individual
NVMe/NFS mounts, or observe changes that bypass these core entry points.
As with user tracing, source GID mismatches and driver UDP-port behavior
limit exact ECMP equivalence. Soft-RoCE is not hardware port-equivalence
validation.

### Flow labels and the UDP source port

A RoCEv2 driver sets a connected QP's UDP source port from
`rdma_get_udp_sport(flow_label, lqpn, rqpn)`: the application's flow label if
non-zero, else the symmetric `rdma_calc_flow_label(lqpn, rqpn)`, folded into
a 14-bit port by `rdma_flow_label_to_udp_sport`. `servicetrace.EffectiveFlowLabel`
reproduces the selection, so a probe sent with that label through the
agent's UD address handle gets the same UDP source port and, on an
IPv4-encapsulated fabric, the same 5-tuple except for what the responder's
UD queue dictates (destination QPN inside the payload, not in the headers).
Soft-RoCE derives the port from a hash of the local QPN instead, so the e2e
suite can validate the tracing and the probe path but not the port
equivalence; that needs hardware NICs.

If the application's source GID index differs from the agent's `gid_index`
(same device, different port address), the probe shares the flow's
destination and UDP source port but not its source address. The monitor
reads the flow's GID from sysfs and warns once per device and index.

### Agent integration

- `Agent.createServiceTracing` (gated by `service_tracing_enabled`) opens the
  tracer; a failure (not Linux, no BTF, no ring buffers, `EPERM`, `ib_uverbs`
  not loaded) is logged at warn level and the agent continues with
  `rpingmesh.agent.service_trace_active = 0`.
- `ServiceMonitor` applies events to the table on the tracer's reader
  goroutine, rebuilds targets about one second after the connection set
  changed (coalescing a job start that opens thousands of QPs) and every
  `pinglist_update_interval_sec`. A rebuild groups each monitored device's
  connections into flows keyed by (remote GID, effective flow label), asks
  the controller for the remotes it has not resolved yet (or all of them on
  the periodic refresh; unregistered remotes are retried after a minute by
  a timer of their own, so the retry does not wait for the next connection
  event), and pushes one `SERVICE_TRACING` `PingTarget` per flow, with
  `flow_label` set to the flow's label and `flow_label_count` 1, to the
  device's prober. Connections on devices the agent does not probe from are
  ignored. Before each rebuild the monitor reconciles the table against
  `/proc`: the ring buffer can drop events under load, and a lost context
  close would otherwise keep an exited process's connections forever, so
  contexts whose owning process is gone are dropped (a lost create or
  destroy is bounded by the process's lifetime the same way); drops are
  logged.
- The prober keeps the service targets apart from the pinglist targets and
  schedules a third pass for them, paced by an aggregate per-RNIC rate
  (`service_tracing_probe_rate_per_second`) and a pass interval
  (`service_tracing_probe_interval_ms`), visiting the flows in a new random
  order each pass. The two lists have separate generations, so service
  churn restarts only the service pass and never starves the pinglist
  targets at the end of a slow pass, and single-label targets do not
  advance the per-GID flow-label rotation the pinglist target of the same
  remote relies on for ECMP coverage. Results carry
  `ProbeResult.PinglistType` (`PinglistServiceTracing`).
- Telemetry records such results on the `rpingmesh.service.*` instruments
  with the usual ToR-level attributes, and exposes the tracer through
  `rpingmesh.agent.service_trace_active`, `service_connections`,
  `service_flows`, `service_qps_unbound`, `service_trace_events_total` and
  `service_trace_dropped_total`. The results fan-in tees them to the
  analysis reporter as well, once the controller has reported
  `service_path_summaries` at registration (see below).

### QPs that predate the agent

After event consumption starts, the monitor inventories existing user QPs
through RDMA netlink (`RDMA_NLDEV_CMD_GET` and `RES_QP_GET`). It repeats on
the normal full-refresh interval, and after an unidentified lifecycle event
invalidates recovered connections. Generic entries include device, local
and remote QPN, type, state, port and owner task ID. The kernel-name
attribute identifies kernel-owned QPs; missing PID alone does not, because
a user QP can outlive its creator task. Kernel-owned QPs are used only to
reconcile the optional kernel tracer's live connections; they and
UD/raw/driver QPs are excluded from raw address-vector recovery.
A generic entry without an address vector
remains unbound and never becomes a probe target.

For `mlx5_core` devices the monitor then attempts `RES_QP_GET_RAW` on
untraced RTR/RTS QPs. The decoder reads the driver's PRM_QUERY_QP resource
dump: big-endian INFO/COMMAND/RESOURCE/TERMINATE segments, with the resource
ID selected by the command echo. It accepts complete 272-byte query-QP
outputs and the 464-byte form with a QP context extension. It validates the
command/resource QPN, state, transport, remote QPN and port, then reads the
primary remote GID, flow label, source GID index, traffic class, SL and hop
limit. The hardware UDP source port must equal the port the existing prober
will derive from that label and the QPNs. Unknown layouts, errors, incomplete
or aggregated segments, IB/RoCEv1 paths and port overrides stay unbound.
The generic owner/type/state are queried again after each raw read to reject
QPN reuse; no resource bytes or addresses are guessed.

Raw queries require **CAP_NET_ADMIN**, in addition to the tracer's
CAP_BPF/CAP_PERFMON. The optional example
`packaging/systemd/rpingmesh-agent.service.d/20-qp-recovery.conf` grants it;
the package ships this as documentation and never enables it automatically.
The generic snapshot needs no additional capability and no `rdma` executable.
Firmware must support the PRM_QUERY_QP resource-dump segment; unsupported
devices, missing privilege or unsupported firmware preserve generic entries
and live tracing. There is no new configuration flag.

A generic call waits at most five seconds; the separate raw-recovery call
waits at most thirty seconds. Refreshes run off the monitor's event/timer
loop, so a slow driver cannot delay removal of an invalidated probe target.
Each kernel socket belongs to its worker: a send/receive can execute a
synchronous driver query even on a nonblocking socket. At most one kernel
worker runs process-wide; later calls wait for its slot within their own
deadline rather than accumulating stalled queries. Shutdown cancels callers
without waiting for a stalled syscall; the worker closes its own socket
when the kernel returns. Late results are discarded. A generic dump failure
preserves the previous inventory; a raw failure retains generic unresolved
entries and any successfully validated partial recovery.

Recovered connections use `(device, local QPN)` and set `FromSnapshot`;
context and handle remain zero. The generic ABI and mlx5 dump provide no
uverbs context/handle, so a QPN is never treated as a uverbs handle. A traced
create/open supersedes the exact device/QPN and subsequent tracer events
use the usual identity. An unknown modify/destroy or a context close
conservatively invalidates the device's snapshot connections and schedules
a debounced resnapshot. This also handles owners that create QPs on a
non-leader thread: netlink reports a TID, whereas tracer events carry a
TGID. The monitor resolves `/proc/<tid>/status` for process-exit reaping.
An exited creator thread can remove the netlink PID without destroying the
QP; such resources remain eligible for recovery with an unknown owner.
Unresolved owner identities are checked through subsequent netlink
refreshes, rather than reaped from a missing TID. Old owner identities are
never copied to a new snapshot based only on a device/QPN match. Recovered
connections have no cgroup/service attribution.
`unknown_qp` still counts events without a known uverbs identity, including
ones whose QPs have driver-recovered connections.

Collection captures per-device lifecycle generations. Results for a device
that changed during collection are rejected and retried; other devices are
accepted. Known UD/raw/driver queue activity does not advance the generation.
An actively changing connected-QP set on the same device can delay recovery
until a snapshot completes without such events. Successful refreshes replace
snapshot resources without overwriting traced connections, and process-exit
reconciliation reaps recovered connections as well. Netlink is an observation,
not an atomic lifecycle history: dropped events and PID/QPN reuse can still
leave data stale until a refresh. The host RDMA devices and PID namespace
must be visible to the agent, as for the existing tracer.

`rpingmesh.agent.service_qps_unbound{source_rdma_device}` counts only entries
without a recovered address vector. Recovered connections contribute to the
normal connection/flow gauges and SERVICE_TRACING targets; they do not invent
create/connect events. No task ID, QPN, GID or raw bytes become metric labels.
Physical mlx5 validation is opt-in (`TestServiceTracingRecoversMlx5Connections`);
the portable fixtures are synthetic PRM layouts, not hardware captures.

ABI references: Linux [mlx5_ifc.h](https://github.com/torvalds/linux/blob/master/include/linux/mlx5/mlx5_ifc.h),
[mlx5 restrack](https://github.com/torvalds/linux/blob/master/drivers/infiniband/hw/mlx5/restrack.c),
[QP path conversion](https://github.com/torvalds/linux/blob/master/drivers/infiniband/hw/mlx5/qp.c)
and [RDMA netlink](https://github.com/torvalds/linux/blob/master/drivers/infiniband/core/nldev.c).

### Bounded service identity

`service_tracing_service_labels` is an opt-in agent YAML list of
`{cgroup_path, service}` mappings. Its configured service names form the
allow-list, so the label set is bounded across job churn, not only within
one collection. The empty default preserves all existing metric attributes.
For a nonempty list, the `service` attribute is present on every
`rpingmesh.service.*` instrument and the `service_connections` and
`service_flows` gauges. Unresolved identities use `_unspecified`; names
starting with `_` are reserved.
`RPINGMESH_SERVICE_TRACING_SERVICE_LABELS` accepts a JSON array with the
same fields and overrides YAML; `[]` disables attribution.

At each target rebuild the monitor resolves the connected QPs' cgroup IDs
under `/sys/fs/cgroup`. It uses the full kernfs file handle ID, matches the
longest configured directory prefix, and discards its resolution snapshot
after rebuilding. Removed or unreadable cgroups and ID zero remain
unresolved. The host cgroup v2 hierarchy must be visible and searchable;
no extra capabilities are needed. Kubernetes pod or namespace names are
configured explicitly rather than discovered through the Kubernetes API.
The filesystem type is checked before reading each ID: cgroup v1 and other
kernfs mounts can produce the same handle format and numeric IDs, but belong
to different hierarchies and must remain unresolved.

Grouping still uses (remote GID, effective flow label), so a shared flow is
probed once at the existing aggregate rate. A local side table associates
each target with its distinct services; the prober snapshots that table
with each service pass and captures the services in its pending measurement.
Target refreshes therefore cannot reattribute an in-flight success, send
failure, or timeout. Telemetry records the result once per distinct service
and applies the allow-list again. Connection gauges count QPs per service;
flow gauges count each flow once per owning service and resolution state.
Summing over services can therefore count shared flows more than once.

No PID, comm, raw cgroup ID, path, or GID is exported as a service attribute.
The mapping and labels never travel to the controller; its summaries and
SLIs remain per-path. The OTel SDK cardinality limit still applies to the
complete cross-product of service, device, ToR and outcome attributes.

### Service network SLOs

The paper's Analyzer evaluates the cluster network and the service network
separately. Service probes are sent at the service-tracing rate along the
flows' own labels, so folding them into the cluster summary of the same
target RNIC would skew the cluster SLIs; keeping them out of the analyzer
altogether, as the first implementation did, left the service network
without controller-side evaluation. The analyzer now evaluates both, apart:

- `ProbeResult.PinglistType` (a `probe` enum equal by value to the proto
  `PinglistType`) records the pinglist a target came from, and the
  `PathAggregator` keys its windows by (source GID, target GID, pinglist
  type). A service flow to an RNIC that is also a pinglist target therefore
  gets a window summary of its own, reported with
  `PathSummary.pinglist_type = SERVICE_TRACING`.
- The controller's analyzer evaluates `SERVICE_TRACING` summaries against
  `analyzer_service_slo_loss_ratio` and
  `analyzer_service_slo_network_rtt_p99_ns` (independent settings whose
  defaults equal the cluster defaults) and the other summaries against the
  cluster thresholds. Findings carry `network` (`cluster` or `service`) in
  the log and as an attribute of `rpingmesh.analyzer.slo_violations_total`;
  summing over `network` gives the series the counter carried before.
  `ProbeAnalysisAck.slo_violations` counts both.
- Per-server, not per-ToR. The paper reports service-network SLIs per server
  and does not aggregate them hierarchically by ToR, because the samples are
  spread unevenly: how many probes a path gets depends on how many flows the
  application opened, so a ToR-level ratio would be dominated by the busiest
  servers. The analyzer therefore judges each service path window on its own
  and logs the finding with `agent_id`, `source_gid` and `target_gid`; the
  `source_tor`/`target_tor` attributes on the counter only bound its
  cardinality and are not a service SLI. Dashboards should read the agent's
  `rpingmesh.service.*` instruments per agent instance (one per server)
  rather than summed over the ToR attributes.
- Rollout. `AgentRegistrationResponse.service_path_summaries` tells the
  agent that the controller evaluates service summaries apart. A controller
  that predates it ignores `pinglist_type` and would judge service paths as
  cluster paths, so the agent tees service results into the analysis branch
  only while the flag is set (re-read at every heartbeat re-registration)
  and warns once when it is not; upgrade the controller first. The reporter
  checks the flag again when it sends, so summaries aggregated before a
  heartbeat learned of a downgrade are dropped rather than sent.
- Reporter back-pressure. Service results arrive at up to
  `service_tracing_probe_rate_per_second` per RNIC on top of the cluster
  results, and the fan-in's tee into the analysis branch is non-blocking
  (a full channel drops). The reporter therefore sends its periodic reports
  on a goroutine of their own and keeps draining input during the RPC; a
  tick that finds a send still in flight leaves the completed windows in
  the aggregator for the next one.
- Metric cardinality. `network` doubles the series
  `rpingmesh.analyzer.slo_violations_total` can carry (up to
  `4 × T × (T−1)` for T ToRs, all at once in a wide outage); the controller
  raises the OTel SDK's per-instrument cap with
  `analyzer_metrics_cardinality_limit` (default 20000, about 70 ToRs).
- Dashboards. The ToR pair drilldown has a service-network row built on
  `rpingmesh.service.*`, so a `network="service"` violation clicked in the
  overview table lands on the SLIs of the service paths, not only on the
  cluster ones.
- The controller's `GetTargetRnicInfo` looks each GID up in the registry and
  applies the pinglist generator's self and same-host exclusion. The request
  is capped at 4096 GIDs; the agent batches at 1024.

### Build and packaging

The programs are compiled by `bpf2go` (a `go.mod` tool) for `amd64` and
`arm64` into committed `uverbs_*_bpfel.{go,o}` and `kernel_*_bpfel.{go,o}` files, so `make build-agent`
needs no clang; `make generate-bpf` regenerates them and `make check-bpf`
(run in CI) verifies the program still compiles and the Go bindings are
current. The libbpf headers it includes are vendored under
`bpf/include/` with their BSD-2-Clause license. The BPF program itself is
dual-licensed GPL-2.0 or BSD-2-Clause, as the kernel requires a
GPL-compatible license for the helpers it uses.

Loading needs `CAP_BPF` and `CAP_PERFMON` (Linux 5.8+). The hardened
systemd unit grants only `CAP_IPC_LOCK`; the drop-in
`packaging/systemd/rpingmesh-agent.service.d/10-service-tracing.conf` adds
the two capabilities and the `bpf`/`perf_event_open` system calls, and the
agent package ships it as an example rather than installing it.

## Tests

- Pure Go (any OS): event decoding against the C layout, the table
  (create/RTR/reset/destroy/close, handle reuse, context scoping, QP types),
  the kernel flow-label arithmetic, the sysfs lookups, the service monitor
  with a fake tracer and controller, the prober's service pass scheduling,
  the telemetry instruments, config validation, the controller RPC, the
  aggregator's per-pinglist-type keying, the reporter's `pinglist_type`
  mapping, the fan-in's gating on `service_path_summaries`, and the
  analyzer's per-network thresholds and `network` attribute.
- Snapshot tests cover nested netlink decoding, malformed/interrupted dumps,
  snapshot/live-event ordering, failure retention, periodic refresh and
  shutdown cancellation. `TestServiceTracingSnapshotsExistingQP` (soft-RoCE
  e2e) creates a user QP before taking the snapshot and checks its inventory
  and eventual removal without inventing a connection.
- `TestTracerOpenClose` (Linux, root): loads and attaches the committed
  objects into the running kernel; CI runs it under `sudo`.
- `TestKernelTracerOpenClose` (Linux, root, ib_core BTF): verifies default
  isolation, CO-RE loading, all four optional probe attachments, shared
  counters, repeated enabling and idempotent cleanup. Portable tests cover
  kernel event decoding, separate identity namespaces, worker-independent
  lifetime, reset/error/destroy, inventory races and device-to-probe routing.
  These checks do not substitute for an NVMe/NFS/Lustre workload test or
  mlx5 hardware verification of UDP source ports.
- `TestServiceTracingTracesRCApplication` (soft-RoCE e2e): traces
  `ibv_rc_pingpong` between the two rxe devices and checks that each side's
  RTR carries the other's GID and QPN, that the table sees two connections
  with one effective flow label, and that nothing was dropped.
  `TestServiceTracingProbePath` sends a `SERVICE_TRACING` probe with an
  explicit label through the prober and checks the result.

## DC transport investigation (#111)

DC is not integrated into the normal service-probe source. The opt-in
`cmd/dc-trace` collector observes supported send submissions separately;
a QP or an allocated address handle alone is not an observed service flow. The existing raw decoder
explicitly rejects driver/DC transports, including synthetic DCI/DCT
contexts with plausible-looking remote address fields.

The investigated observation points have different limitations:

| Observation point | Finding | Decision |
|-------------------|---------|----------|
| Kernel mlx5 post-send | Userspace providers and UCX write WQEs and ring doorbells without entering this kernel path. | Cannot cover userspace DC traffic. |
| Userspace DC setter / AH creation | rdma-core's `mlx5_send_wr_set_dc_addr` copies an AH and remote DCT into the current WQE. AH creation alone has neither proof of a send nor the DCI/DCT pairing; a setter can precede an aborted batch. | Needs a version-specific send/commit observation point and lifecycle tracking. |
| UCX direct mlx5 path | UCX's `uct_dc_mlx5_set_dgram_seg` constructs the datagram segment directly from its endpoint AV. | A libmlx5-only uprobe would miss this path; instrumenting UCX requires a separate adapter. |
| RDMA netlink raw QP | mlx5 `fill_res_qp_entry_raw` requests `MLX5_SGMT_TYPE_PRM_QUERY_QP` for one QPN. It is a QP context, not an enumeration of committed per-send AVs or DCI streams. | Do not infer a persistent remote from a DCI QP snapshot. |

Sources: [rdma-core mlx5 send implementation](https://github.com/linux-rdma/rdma-core/blob/master/providers/mlx5/qp.c),
[UCX direct DC WQE construction](https://github.com/openucx/ucx/blob/master/src/uct/ib/mlx5/dc/dc_mlx5_ep.c),
and [Linux mlx5 resource dump implementation](https://github.com/torvalds/linux/blob/v6.12/drivers/infiniband/hw/mlx5/restrack.c).

### Experimental DC submission collector

`cmd/dc-trace` is a Linux-only, opt-in diagnostic collector for libmlx5
submissions and UCX direct DC sends. It validates the provider and optional
UCX ELF/DWARF layouts and build IDs, pins the target process and library
identities, and attaches before DCI creation. Unsupported layouts fail
closed. It requires BPF/uprobe privileges, readable matching debug data,
RDMA device access and a supported mlx5 RoCEv2 path. The normal connected-QP
tracer is independent of this collector.

The libmlx5 adapter observes completed submission batches. The UCX adapter
supports AM short, short-iov, bcopy and zcopy; RMA put/get; 32/64-bit atomic
post, fetch and compare-and-swap; and tag eager/rendezvous submission entry
points. UCX DevX and DCI streams are separate opt-ins. Each adapter validates
successful return semantics, the published WQE and the live DCI lifecycle;
nested or unsupported submissions are rejected conservatively.

`servicetrace/mlx5_dc.go` decodes the mlx5 control/extended-AV prefix for
supported send, RMA and atomic layouts. It checks the DCI QPN, segment count,
extended AV, DCT, opcode/modifier, stream channel and remote GID. Capture
excludes immediate values, DC keys, remote virtual addresses/keys, atomic operands,
tag headers and payloads. The CLI emits aggregate statistics rather than
flow or process/device identities.

The AV UDP source port and application flow label are separate fields. A
zero flow label does **not** invoke the RC/UC/XRC QPN-derived fallback:
libmlx5 may have selected a random AV source port when creating the AH.
This candidate port is not proof of the actual wire port or probe ECMP
path equivalence.

`servicetrace/dc_flows.go` retains multiple destinations/streams per DCI,
with inactivity expiry, bounded LRU capacity, lifecycle retirement and
capture-loss reset. Lifetime tokens prevent PID/QPN/pointer reuse from
preserving stale flows. Process exit/exec and DCI teardown invalidate the
corresponding observations.

Synthetic integration tests cover the adapters and lifecycle/error paths.
Hardware loopback tests have verified libmlx5 submissions and UCX AM/RMA
submissions, plus atomic submissions through DevX and streams. Verbs atomic
hardware coverage remains incomplete. Tag synthetic tracking and attachment
to the real UCX library have passed, but tag hardware sends remain unverified:
the tested interfaces did not advertise the required capability, and all
hardware tag cases skipped. Successful loopback validation does not establish
wire UDP ports, network path coverage or ECMP equivalence.

## Follow-ups

- **Additional startup recovery drivers.** mlx5 PRM query-QP recovery is
  implemented with strict layout checks; other drivers/formats remain
  unbound. No supported snapshot supplies a uverbs context/handle, so
  unknown-event correlation remains conservative and snapshot-based.
- **DC transport.** Validate wire UDP ports and ECMP equivalence before
  integrating the experimental collector into the service-probe source.
  Complete tag and verbs atomic hardware coverage on capable interfaces.
