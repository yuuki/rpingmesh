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
connection. Each event carries the context identity (the `struct file`
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
  the periodic refresh; unregistered remotes are retried after a minute),
  and pushes one `SERVICE_TRACING` `PingTarget` per flow, with
  `flow_label` set to the flow's label and `flow_label_count` 1, to the
  device's prober. Connections on devices the agent does not probe from are
  ignored.
- The prober keeps the service targets apart from the pinglist targets and
  schedules a third pass for them, paced by an aggregate per-RNIC rate
  (`service_tracing_probe_rate_per_second`) and a pass interval
  (`service_tracing_probe_interval_ms`), visiting the flows in a new random
  order each pass. Results carry `ProbeResult.ServiceTracing`.
- Telemetry records such results on the `rpingmesh.service.*` instruments
  with the usual ToR-level attributes, and exposes the tracer through
  `rpingmesh.agent.service_trace_active`, `service_connections`,
  `service_flows`, `service_trace_events_total` and
  `service_trace_dropped_total`. The results fan-in skips them for the
  analysis reporter.
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
  the telemetry instruments, config validation, and the controller RPC.
- `TestTracerOpenClose` (Linux, root): loads and attaches the committed
  objects into the running kernel; CI runs it under `sudo`.
- `TestServiceTracingTracesRCApplication` (soft-RoCE e2e): traces
  `ibv_rc_pingpong` between the two rxe devices and checks that each side's
  RTR carries the other's GID and QPN, that the table sees two connections
  with one effective flow label, and that nothing was dropped.
  `TestServiceTracingProbePath` sends a `SERVICE_TRACING` probe with an
  explicit label through the prober and checks the result.

## Follow-ups

- **Controller-side service SLAs.** Service results are not reported to the
  analyzer. A `pinglist_type` on `PathSummary` and a separate evaluation of
  service paths would let the controller flag service-network violations
  (the paper's Analyzer evaluates the two networks separately).
- **Existing connections.** A snapshot from RDMA netlink
  (`rdma resource show qp`) at startup would seed the table with QPs that
  predate the agent, which the trace alone cannot see.
- **Service identity.** Events carry the cgroup id and comm; mapping them to
  a bounded service label (a systemd slice or a Kubernetes pod) would allow
  per-service attribution without unbounded metric attributes.
- **DC transport.** mlx5's dynamically connected transport binds the remote
  per work request, not at RTR, and is invisible to this tracer.
