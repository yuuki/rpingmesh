# Experimental DC submission collector

`rpingmesh-dc-trace` is an opt-in Linux diagnostic collector for the libmlx5
extended-WR send path. It observes DCI creation, QP state changes and the
`mlx5_send_wr_complete` entry/return boundary. It copies a bounded WQE batch
before submission and publishes it only after the provider returns success.
This is submission evidence, not a completion or packet-delivery guarantee.

The collector is separate from the agent and does not generate probe targets.
UCX direct WQE construction, legacy `ibv_post_send`, pre-existing DCIs and
stream-enabled DCIs (including stream zero) are unsupported. Full matching
provider DWARF and symbols are required; compressed mini-debug symbols alone
are insufficient. Build-ID and layout checks establish binary/layout identity,
not compatibility with arbitrary provider implementations. Provider control
flow still needs validation for each supported implementation.

## Requirements and limits

- Linux amd64 or arm64, little endian, with BPF, uprobes, uretprobes, ring buffers,
  the `sched_process_exec` and `sched_process_exit` raw tracepoints and pidfds. This collector uses BPF ISA
  v3 atomics and `bpf_for_each_map_elem`, requiring Linux 5.13 or later (or the
  corresponding vendor backports). Availability also depends on kernel policy.
- Loading/attaching requires appropriate BPF/perf privileges, commonly root.
  All commands requiring `sudo` below are intended for the user to execute.
- The synthetic integration test needs a C compiler and binutils, but no RDMA
  hardware, libibverbs headers, RDMA kernel modules or kernel BTF.
- Actual collection needs a RoCE v2 device, a readable uverbs descriptor and
  GID attributes in sysfs, plus a matching full debug ELF for the loaded library.
- Attach before creating DCIs. A selected provider must already be mapped by
  the target process. Use an application-side gate to delay DCI creation until
  the collector emits its first JSON statistics record. The CLI does not launch
  or pause the workload. Run the collector where the process's mapped library
  and sysfs identities are visible.
- Uprobes are attached across tasks so worker threads are covered. BPF filters
  the selected process TGID before reading data; unrelated processes are not
  recorded, but calls to the same library can incur probe overhead.
- Capture is limited to 16 WRs per submitted batch, 4,096 registered DCIs and
  256 concurrent calls per tracked function. Unsupported or incomplete batches
  are discarded as a whole. Supported WQEs are SEND, SEND with immediate,
  RDMA WRITE, WRITE with immediate and RDMA READ, with an extended AV.
- Destroy, reset/error, UDP-port override and exposed DevX QP modification
  attempts retire tracking. Any QP modification attempted after RTS also
  retires tracking, including failed modifications. Recreate the DCI to resume.
  Raw DevX commands outside the hooked provider API are unsupported; do not use
  this collector to infer addresses for workloads that mutate QPs that way.
- Lifetime tokens use an atomic sequence. Exec invalidates queued old events
  and clears the registry before the new image starts. Leader exit disables the process filter before PID reuse; this also
  conservatively stops capture if the leader exits while workers survive.
  Process exit ends collection. Map/read/ring errors clear retained flow state; TTL and capacity
  also bound it. A quiet statistics interval does not establish full coverage.
- The capture omits the DC access-key bytes. The CLI emits aggregate counters,
  without QPNs, GIDs, MAC addresses, hostnames, device names or library IDs.
  The AV UDP source-port field remains a candidate: neither its wire value nor
  ECMP equivalence has been established by this collector.

## User-run synthetic integration test

From a Linux repository checkout, compile without privileges:

```sh
go test -c -o /tmp/rpingmesh-dc-tests ./internal/agent/servicetrace
```

Then execute the privileged test yourself:

```sh
(
  cd internal/agent/servicetrace
  sudo env RPINGMESH_DC_UPROBE_TEST=1 /tmp/rpingmesh-dc-tests \
    -test.run '^TestDCUprobeIntegration$' -test.count=1 -test.v
)
```

The test attaches to its own synthetic child process. It checks successful and
failed submission, abort, oversized/invalid batches, key redaction, pointer/QPN
reuse, streams, reset, overrides, worker-thread calls, teardown, and registry
reclamation across exec, and disabling capture on process exit or worker exec.
Explicit enablement causes load, verifier or attach errors to fail the test;
it does not silently skip. Without the environment variable it is skipped.

## User-run application capture

Set `DC_LIBRARY`, `DC_DEBUG`, `DC_PID`, `DC_DEVICE` and `DC_PORT` locally. Keep
those values and any environment-specific output out of commits, issues and PRs.
Use the exact library mapped by the target and its matching full debug ELF.

```sh
make build-dc-trace
./bin/rpingmesh-dc-trace -check -library "$DC_LIBRARY" -debug "$DC_DEBUG"
```

The check above validates ELF/DWARF without loading BPF. Then execute:

```sh
sudo ./bin/rpingmesh-dc-trace \
  -library "$DC_LIBRARY" -debug "$DC_DEBUG" \
  -pid "$DC_PID" -device "$DC_DEVICE" -port "$DC_PORT" -duration 30s
```

Release the application's DCI-creation gate after the first statistics record.
The CLI prints aggregate JSON statistics once per second. `accepted_sends`
counts decoded submitted WRs; `active_flows` counts distinct retained
DCI/address flows. Shutdown clears retained flows, so the final active count
is zero. Error/loss counters and `rejected_records` should be checked alongside
accepted counts. A successful synthetic test does not qualify a real provider
or establish network-path equivalence.

## Validation status

Portable unit tests, non-privileged Linux ELF/layout tests, cross compilation,
and BPF object generation are automated development checks. The privileged
integration test, kernel verifier acceptance, real uprobe attachment and
application collection remain user-run validation steps. They have not been
executed as part of this implementation. Public reports should contain only
sanitized outcomes and aggregate counters, never raw deployment details or
unreviewed verifier logs containing paths.
