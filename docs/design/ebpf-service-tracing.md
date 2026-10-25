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

The cost is scope: kernel ULPs (NVMe-oF, NFS over RDMA, Lustre) do not go
through uverbs and are not traced, and the trace sees commands, not QPs that
already existed. The paper's service (user-space DML over NCCL) is covered.

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
  `service_flows`, `service_trace_events_total` and
  `service_trace_dropped_total`. The results fan-in tees them to the
  analysis reporter as well, once the controller has reported
  `service_path_summaries` at registration (see below).

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
  the log and as an attribute of `rpingmesh.analyzer.sla_violations_total`;
  summing over `network` gives the series the counter carried before.
  `ProbeAnalysisAck.sla_violations` counts both.
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
  `rpingmesh.analyzer.sla_violations_total` can carry (up to
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

The program is compiled by `bpf2go` (a `go.mod` tool) for `amd64` and
`arm64` into committed `uverbs_*_bpfel.{go,o}` files, so `make build-agent`
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
- `TestTracerOpenClose` (Linux, root): loads and attaches the committed
  objects into the running kernel; CI runs it under `sudo`.
- `TestServiceTracingTracesRCApplication` (soft-RoCE e2e): traces
  `ibv_rc_pingpong` between the two rxe devices and checks that each side's
  RTR carries the other's GID and QPN, that the table sees two connections
  with one effective flow label, and that nothing was dropped.
  `TestServiceTracingProbePath` sends a `SERVICE_TRACING` probe with an
  explicit label through the prober and checks the result.

## Follow-ups

- **Existing connections.** A snapshot from RDMA netlink
  (`rdma resource show qp`) at startup would seed the table with QPs that
  predate the agent, which the trace alone cannot see.
- **DC transport.** mlx5's dynamically connected transport binds the remote
  per work request, not at RTR, and is invisible to this tracer.
