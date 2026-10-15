# Verifying the mlx5 Traffic Class Override for UD Probes

Status: desk research done, packet-level experiment pending
([#71](https://github.com/yuuki/rpingmesh/issues/71)).

This document answers, as far as source code can, whether the MLNX_OFED/DOCA
mlx5 traffic class override
(`/sys/class/infiniband/<dev>/tc/<port>/traffic_class`, e.g.
`Global tclass=106`) also applies to the UD Address Handles (AHs) that the
agent creates, and gives a runbook for confirming the answer on real RoCE
hardware.

## Question

The agent sends probes and ACKs on a UD QP. Each send uses an AH built by
`createAddressHandle` in `zig/src/queue.zig`, which sets
`ah_attr.grh.traffic_class` from the agent's `traffic_class` setting (default
`0`). If the driver override also rewrote UD sends, probes with the default
`traffic_class: 0` would already travel in the overridden (usually lossless)
class. If it does not, probes use exactly the configured value.

## Desk research

Conclusion: **in the driver and library source, the override does not reach
UD sends.** It is applied only to the address path stored in a QP context
(connected QPs and DCT), and a UD QP has none. The traffic class of a UD send
comes from an address vector that userspace builds from
`ah_attr.grh.traffic_class` and copies into every send WQE. Prediction: a UD
probe with `traffic_class: 0` leaves the NIC with DSCP 0 even when
`Global tclass=106` is set.

Confidence: high for the software path, which was read end to end in the
current sources and spot-checked in older MLNX_OFED releases. The remaining
uncertainty is the closed firmware: nothing in the sources asks the firmware
to rewrite a UD WQE's traffic class, but only a packet-level test can rule
out firmware behavior. That is what the runbook below is for.

### Userspace: rdma-core mlx5 provider

At upstream rdma-core
[`bd3282a`](https://github.com/linux-rdma/rdma-core/tree/bd3282a1cf1025c7869a8664c2d54266a4dded44):

- [`mlx5_create_ah`](https://github.com/linux-rdma/rdma-core/blob/bd3282a1cf1025c7869a8664c2d54266a4dded44/providers/mlx5/verbs.c#L3490-L3580)
  builds the address vector in userspace and copies
  `attr->grh.traffic_class` into `av.tclass` verbatim
  ([L3547-L3549](https://github.com/linux-rdma/rdma-core/blob/bd3282a1cf1025c7869a8664c2d54266a4dded44/providers/mlx5/verbs.c#L3547-L3549)).
  For RoCE it calls into the kernel only to resolve the destination MAC
  ([L3557-L3571](https://github.com/linux-rdma/rdma-core/blob/bd3282a1cf1025c7869a8664c2d54266a4dded44/providers/mlx5/verbs.c#L3557-L3571)).
- The kernel's reply,
  [`struct mlx5_ib_create_ah_resp`](https://github.com/linux-rdma/rdma-core/blob/bd3282a1cf1025c7869a8664c2d54266a4dded44/kernel-headers/rdma/mlx5-abi.h#L431-L435),
  carries only `dmac`. The kernel has no channel to change the userspace
  address vector's traffic class.
- On a UD send,
  [`set_datagram_seg`](https://github.com/linux-rdma/rdma-core/blob/bd3282a1cf1025c7869a8664c2d54266a4dded44/providers/mlx5/qp.c#L256-L271)
  `memcpy`s that address vector into the WQE's datagram segment
  ([UD send path](https://github.com/linux-rdma/rdma-core/blob/bd3282a1cf1025c7869a8664c2d54266a4dded44/providers/mlx5/qp.c#L1000-L1003)).
- The rdma-core shipped in the DOCA 3.5.0 MLNX_OFED source bundle
  (`MLNX_OFED_SRC-26.07-0.7.7.0`, `rdma-core-2607.0.8`) has the same
  `mlx5_create_ah` and `_set_datagram_seg`, and its mlx5 provider contains no
  other traffic class or DSCP handling.

### Kernel: MLNX_OFED/DOCA mlx5_ib

Upstream Linux has no `tc/<port>/traffic_class` sysfs; it exists only in
NVIDIA's out-of-tree `mlnx-ofa_kernel`. The links below point to a public
change-tracking mirror of the official source tarballs at
[`5bff9d3`](https://github.com/knneth/mlnx-ofa_kernel/tree/5bff9d3fa9bd515b5bc204cb1f04f1d485577714)
(DOCA 3.5.0, OFED 26.07-0.7.7.0). The cited files were checked byte for byte
against `mlnx-ofa_kernel-2607.0.100` from the official
`MLNX_OFED_SRC-26.07-0.7.7.0` bundle.

- Writing the sysfs file
  ([`traffic_class_store`](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/main_ext.c#L620-L662))
  stores the global value or a match rule, then calls
  [`tclass_update_qps`](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/main_ext.c#L561-L619).
  That function rewrites the DSCP in the QP context (`RTS2RTS`,
  `primary_address_path.dscp`) of existing QPs that are in RTS **and** have a
  GRH address in their QP context (`mqp->ah`).
- New QPs pick up the value in
  [`mlx5_ib_qp_set_tclass`](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/qp.c#L4963-L4997),
  called from
  [`mlx5_ib_modify_qp`](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/qp.c#L5053).
  It returns early unless the modify carries `IB_QP_AV`
  ([L4975](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/qp.c#L4975)).
  The result is written into the QP context's address path in
  [`mlx5_set_path`](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/qp.c#L3779-L3784).
  DCT targets get it separately
  ([L4870-L4871](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/qp.c#L4870-L4871)).
- `IB_QP_AV` is never a valid attribute for a UD QP: the core state table in
  upstream Linux
  ([`qp_state_table`](https://github.com/torvalds/linux/blob/0fcb05b72344f40806cbe810de8872f1698bf053/drivers/infiniband/core/verbs.c#L1464-L1763))
  lists it only for UC, RC and XRC transitions. A UD QP therefore never
  stores the override, and `tclass_update_qps` skips it.
- Kernel AH creation
  ([`create_ib_ah`](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/ah.c#L53-L107))
  does not consult the override either. It only matters for kernel ULPs,
  since userspace builds its own address vector.
- Hint from DCI: for DC initiators, which also take their address from each
  WQE, the driver sets a QP-context "force DSCP" bit (`f_dscp`) next to the
  overridden DSCP
  ([L3781-L3782](https://github.com/knneth/mlnx-ofa_kernel/blob/5bff9d3fa9bd515b5bc204cb1f04f1d485577714/drivers/infiniband/hw/mlx5/qp.c#L3781-L3782)).
  This suggests that the firmware uses the per-WQE traffic class unless told
  otherwise. The driver never sets that bit for UD QPs.
- The same structure is present in OFED 25.04, 23.10 and 5.9 in the mirror
  (in 5.9 the lookup sits inside `mlx5_set_path`, again only for QPs with
  `IB_QP_AV`).
- NVIDIA's
  [Force DSCP documentation](https://networking-docs.nvidia.com/doca/archive/3-5-0/rdma-over-converged-ethernet#force-dscp)
  scopes the feature to RC QPs, which is consistent with the code.

## Experiment runbook

The goal is to observe the DSCP and ECN that UD probes actually carry on the
wire when the override is present, with the agent configured to a value that
differs from the override.

### Prerequisites

- **Two hosts that are not in production use**, one test RNIC each, ideally
  under the same ToR switch so that no ECMP is involved. Background traffic
  on these RNICs should be idle or low and steady.
- **The same driver, kernel and firmware stack** as the fleet the result is
  meant for. Record privately: `ofed_info -s`, `uname -r`, and
  `ethtool -i <netdev>` (`firmware-version`).
- **The override already present** on both test RNICs:
  `cat /sys/class/infiniband/<dev>/tc/<port>/traffic_class` shows e.g.
  `Global tclass=106`. Do not write to this file or change NIC/switch QoS
  configuration for the test. Note: `<port>` is the port number, usually `1`.
- **A RoCE v2 GID index** for `<dev>`:
  `cat /sys/class/infiniband/<dev>/ports/<port>/gid_attrs/types/<idx>` prints
  `RoCE v2`. Use the same index type on both hosts.
- **A dedicated controller and rqlite** that only these two agents register
  with, so the pinglists contain only the peer. Do not point the test agents
  at a production controller.
- **A capture method that sees offloaded RoCE.** Ordinary `tcpdump` on the
  netdev does not see RDMA traffic that bypasses the kernel. Use one or both
  of:
  - A switch port mirror (SPAN/ERSPAN) of the host-facing ports. This shows
    the packets as they are on the wire, including any switch re-marking.
  - NVIDIA's
    [Offloaded Traffic Sniffer](https://networking-docs.nvidia.com/doca/sdk/offloaded-traffic-sniffer):
    `tcpdump` with libpcap 1.9 or later, run on the RDMA device instead of
    the netdev (`tcpdump -D` lists it, then `tcpdump -i <dev> ...`). NVIDIA
    also publishes a `mellanox/tcpdump-rdma` container image for hosts
    without a suitable libpcap. NVIDIA notes that enabling the sniffer can
    slow down kernel-bypass traffic, so use it only on the test pair. Capture
    on the receiving host too: the receive side shows what arrived over the
    wire, while a sender-side copy may come from inside the NIC.

### Agent and controller configuration

Controller (dedicated instance), on top of `configs/controller.yaml`:

```yaml
listen_addr: ":50051"
database_uri: "http://<test-rqlite>:4001"
# One flow label per (prober, target) pair: no ECMP label set, no rotation.
ecmp_max_flow_labels: 1
analyzer_enabled: false
```

With `ecmp_max_flow_labels: 1` every target gets `FlowLabelCount = 1`, and
the agent then uses the controller's single deterministic label for that
pair, unchanged across the rotation period, so each probe direction keeps one
fixed 5-tuple. ACKs reuse the flow label parsed from the probe's GRH. With
IPv4 RoCE v2 GIDs that label is `0`, and the mlx5 provider then picks a
random UDP source port for each ACK, so ACKs may spread over ECMP paths.
This is why the two hosts should share a ToR; otherwise mirror the
host-facing ports, which every path passes through.

Agents (both hosts), on top of `configs/agent.yaml`:

```yaml
controller_addr: "<test-controller>:50051"
tor_id: "verify-tor"            # same value on both: ToR-mesh pinglist
allowed_device_names: ["<dev>"] # one test RNIC per host
gid_index: <roce-v2-index>      # same GID type on both hosts
service_level: 0                # fixed across all runs
traffic_class: 0                # per run, identical on both agents (see below)
probe_interval_ms: 100
tor_mesh_probe_rate_per_second: 10
metrics_enabled: false          # keep test data out of production telemetry
analysis_report_enabled: false
log_level: "info"
```

This gives 10 probes/s per direction, i.e. about 30 packets/s sent per host
(its own probes plus two ACKs per peer probe), about 110 bytes each. Each
setting can also be passed as an environment variable, e.g.
`RPINGMESH_TRAFFIC_CLASS=106`. `traffic_class` is read only when the device
is opened, so restart both agents between runs.

Runs (set the **same** `traffic_class` on both agents, since ACKs use the
responder's own value):

| Run | `traffic_class` | Purpose |
|-----|-----------------|---------|
| B | agents stopped | Baseline for counter deltas |
| 1 | `0` | Main question: does the override lift TC 0 to its value? |
| 2 | override value, e.g. `106` | Positive control: the expected class and queue |
| 3 (optional) | `104` | Same DSCP as `106`, Not-ECT: what ECN does the NIC emit? |

Keep `service_level`, `gid_index`, the host pair and the controller config
identical across runs. Let each run reach a steady state (check the agent
log for probe results), then measure for a fixed window, e.g. 120 s.

### Observing DSCP and ECN

Capture RoCE v2 (UDP destination port 4791) between the two test GIDs during
each run, e.g. with the sniffer:

```bash
tcpdump -i <dev> -w run1-<host>.pcap 'udp dst port 4791'
```

Then read the DSCP and ECN of the probe packets:

```bash
tshark -r run1-<host>.pcap -Y 'udp.dstport == 4791' -T fields -e ip.src -e ip.dst -e ip.dsfield.dscp -e ip.dsfield.ecn -e infiniband.bth.opcode
```

For IPv6 GIDs, use `ipv6.tclass.dscp` and `ipv6.tclass.ecn` instead of the
`ip.dsfield.*` fields. Probes and ACKs are UD SEND packets (BTH opcode 100)
with a 40-byte payload whose first byte is the wire format version. If other
RoCE traffic is present, keep only UD SEND packets between the two test IPs.
Record the observed values for both directions; do not infer ECN from the
configured value.

### Per-priority counter deltas

Sample the per-priority port counters on both hosts at the start and end of
each window (baseline included):

```bash
ethtool -S <netdev> | grep -E '(rx|tx)_prio[0-7]_packets'
```

If the read-only helper from
[#70](https://github.com/yuuki/rpingmesh/issues/70)
(`scripts/topology/collect_qos_facts.py`) is available, it can collect the
same per-priority deltas together with the trust mode and DSCP map.
Optionally add the switch's per-queue counters for both host-facing ports.

For each run, subtract the baseline rate from the run's rate per priority.
The probes should account for about 30 packets/s more TX on the sender's
priority and the same RX on the peer's. Check both directions: host A TX
against host B RX, and host B TX against host A RX. Aggregate per-priority
bytes alone do not identify the probes' queue when other traffic is
present; the capture is the primary evidence and the counters confirm the
queue the packets were mapped to.

### Results template

| Run | `traffic_class` | Direction | Observed DSCP | Observed ECN | Priority with probe delta (TX / peer RX) | Switch queue (optional) |
|-----|-----------------|-----------|---------------|--------------|------------------------------------------|-------------------------|
| 1 | 0 | A → B | | | | |
| 1 | 0 | B → A | | | | |
| 2 | 106 | A → B | | | | |
| 2 | 106 | B → A | | | | |
| 3 | 104 | A → B | | | | |
| 3 | 104 | B → A | | | | |

Interpretation:

- Run 1 shows DSCP 0 and the default priority: the override does **not**
  apply to UD (the predicted outcome). `traffic_class` must be set
  explicitly.
- Run 1 shows the override's DSCP and the workload's priority: the override
  **does** apply to UD on this stack, likely in firmware.
- Run 3 shows how the NIC treats the ECN bits of a UD AH with this stack.

### Updating the README

Update "Choosing `traffic_class` and `service_level`", step 2 ("Check for a
NIC-level traffic class override"), in `README.md`:

- Replace "has **not been verified**" with the observed result, and keep the
  advice to set `traffic_class` explicitly in either case.
- Name the stack only in generic terms, e.g. "MLNX_OFED/DOCA <version> with a
  <major>.x kernel". Do not include hostnames, addresses, device names, hardware
  models, or counts.
- If run 3 was done, add the observed ECN behavior to step 4 ("Map to config
  values").
- Mark this document's status as verified, link the issue, and close
  [#71](https://github.com/yuuki/rpingmesh/issues/71).
