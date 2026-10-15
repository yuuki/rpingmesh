# ToR Mapping on Multi-Rail (Rail-Optimized) Hosts

Status:

- Implemented: per-RNIC ToR IDs (`device_tor_ids`, optional LLDP discovery)
  and the plane (rail) restriction of pinglists (`plane_id` /
  `device_plane_ids`, see
  [policy C](#c-pinglist-policy-once-rnics-have-per-leaf-tors)).
- Open: which mapping source to standardize on (see
  [Verification plan](#verification-plan)).

## Problem

R-Pingmesh organizes probing around the ToR switch. The **ToR-mesh** pinglist
probes every RNIC under the same ToR (host, RNIC, and cable faults). The
**inter-ToR** pinglist samples RNICs under other ToRs (fabric faults). OTel
metrics and analyzer findings are aggregated by `(source_tor, target_tor)`.

GPU clusters commonly use a *rail-optimized* fabric. A host has N RNICs
(rails), and rail *r* of every host in a group (scalable unit, pod) is cabled
to the same leaf switch. A host's N RNICs therefore sit under N **different**
leaves. With a single agent-wide `tor_id`:

- If `tor_id` is a host or rack name, the "ToR" is not a switch. The ToR-mesh
  mixes all rails of a rack, most of its pairs cross the spine, and the metric
  labels cannot point at a leaf.
- If `tor_id` is unset, every RNIC lands in one virtual rack. The ToR-mesh is
  a random sample capped by `unspecified_mesh_max_targets`, there is no
  inter-ToR list, and all metrics collapse into one `unspecified` cell.

Neither localizes a problem to a leaf, which is the point of ToR-level
aggregation.

## What "ToR" should mean

The ToR ID of an RNIC identifies **the switch its port is cabled to** (the
leaf). Rack, host, and rail are proxies that are correct only in some
topologies. In a rail-optimized group the leaf is exactly `(group, rail)`.

## Starting point

The data model was already per RNIC: `RnicInfo.tor_id` in the proto, one
rqlite registry row per RNIC, pinglist requests per RNIC (`requester_gid` +
`tor_id`), and `PathSummary.source_tor_id` per path. Same-host exclusion
(issue #39) already covered RNICs of one host registered under different
ToRs. Two pieces were missing: the controller overwrote every RNIC's `tor_id`
with the request-wide value, and the agent had no way to express a per-device
ToR. The [Mechanism](#mechanism) section describes how both were added.

## Options

### A. Where the per-RNIC ToR is decided

| | Option | Pros | Cons |
|---|---|---|---|
| A1 | Agent-wide `tor_id` only | Simple | Wrong on rail-optimized hosts (see above) |
| A2 | **Per-device map in the agent config** (`device_tor_ids`, implemented) | No proto change; works with any mapping source; the agent knows its own ToR for metric labels | The map must be generated and distributed per host by config management |
| A3 | Controller-side topology file or inventory overriding agent values | One source of truth; no per-host config; reusable by Phase 2 localization | Needs a reload story; the agent must learn its ToR for metric labels (registration response or pinglist), i.e. a proto change |
| A4 | Controller derives the requester's ToR from its registered GID instead of trusting `PinglistRequest.tor_id` | Removes one consistency hazard of A2 | Only meaningful together with A3 |

A2 is the smallest step that makes the rest testable. A3 (with A4) is the
follow-up if distributing per-host maps becomes operationally painful. The two
can coexist: A3 can override what A2 reports.

### B. Where the mapping comes from

| | Source | Fidelity | Requirements / risks |
|---|---|---|---|
| B1 | Cabling plan / DCIM inventory | High if maintained | Drifts silently after re-cabling |
| B2 | LLDP neighbor of each RNIC netdev (`lldpd`/`lldpad`) | Highest: names the actual switch | Needs an LLDP agent on hosts; NIC firmware may consume LLDP frames (firmware DCBX/LLDP modes) so the host sees nothing; the switch must send LLDP on host ports |
| B3 | Per-leaf host subnet (RNIC IPv4 network at a given prefix) | High when each leaf owns a subnet | Useless when one subnet spans a whole rail |
| B4 | `(group, rail)`: group from Slurm topology or scalable-unit membership, rail from the RNIC's rail subnet or device name | Exact for rail-optimized groups | A group source must exist; device names must be consistent across hosts if used as the rail key |
| B5 | Empirical: cluster RNIC pairs by measured network RTT (one switch hop vs three) | Inventory-independent | Gives groups, not switch names; needs HW timestamps and enough probe coverage |
| B6 | Empirical: IPv4 TTL / hop limit in the received GRH | Exact hop count per pair | Needs a C-ABI change to export it from the CQ poller; L2-bridged hops do not decrement it |
| B7 | Switch-side data (LLDP/MAC tables via SNMP/gNMI) | High | Requires access to the network management plane |

B2, B3, and B4 produce names; B5 (and later B6) validate them independently.
`scripts/topology/` covers B2, B3, and B4 (`build_device_tor_map.py
--strategy lldp|subnet|group-rail`) and B5 (`rtt_tor_check.py`). The agent can
also apply B2 directly at startup (`lldp_tor_discovery`, see
[Mechanism](#mechanism)).

### C. Pinglist policy once RNICs have per-leaf ToRs

- **ToR-mesh** becomes "same leaf, other hosts", matching the paper.
- **Inter-ToR** without a restriction samples `inter_tor_sample_size` foreign
  ToRs among *all* leaves, so most samples cross rails. On fabrics without
  cross-rail connectivity those probes fail by construction. On fully
  connected fabrics they are valid but exercise paths that rail-local
  collective traffic rarely uses.

**Decision: restrict pinglists to the requester's plane (implemented).** On a
production rail-optimized GPU fabric whose rails are not routed to each other,
every probe between RNICs of different rails timed out, while same-rail probes
succeeded. With 8 rails, 7 of 8 unrestricted inter-ToR samples were false
loss, and so were 7 of 8 targets of the untagged (empty ToR) mesh, which
samples all RNICs. Each RNIC therefore carries an optional *plane*: the set of
RNICs it can reach (on a rail-isolated fabric, its rail).

- **Agent.** `plane_id` sets a host-wide plane; `device_plane_ids` maps device
  names to planes with the same rules as `device_tor_ids` (case-insensitive
  keys, trimmed non-empty values, the per-device entry wins). Each RNIC
  registers its plane (`RnicInfo.plane_id`) and sends it with its pinglist
  requests (`PinglistRequest.plane_id`). Map entries that name excluded,
  not-allowed, or absent devices produce a startup warning, not an error, so
  one fleet-wide map can coexist with per-host device filters.
- **Controller.** Planes are stored in the rqlite `rnics.plane_id` column
  (`NOT NULL DEFAULT ''`; added by `ALTER TABLE` at startup when an older
  table lacks it, so an older controller can still share the database). When
  the requester has a plane, the controller keeps only same-plane RNICs as
  **inter-ToR** candidates (before choosing one representative per ToR) and
  in the **untagged mesh** (before the `unspecified_mesh_max_targets` cap).
  The **ToR-mesh** of a named ToR is not restricted: a leaf belongs to one
  plane, so a ToR whose RNICs report several non-empty planes is logged as a
  configuration error.
- **Requester plane.** The controller uses the plane registered for
  `requester_gid` when it is non-empty, otherwise the request's `plane_id`.
  The registry wins because targets are filtered by their registered planes:
  both sides of the comparison come from one source, and an agent cannot
  claim a plane it did not register. The request value covers a requester
  that is not registered yet, or whose row was written by an older controller
  and not yet refreshed by a heartbeat.
- **Compatibility.** An empty plane means "unknown" and keeps the old
  behavior. A requester without a plane is paired with every RNIC. A requester
  with a plane is not paired with plane-less RNICs (registered by older
  agents), since nothing says they are reachable. Old agents never send a
  plane, so a new controller changes nothing for them. A new agent against an
  old controller still works, but its pinglists are not restricted. The
  controller advertises support with `per_rnic_plane_id` in the registration
  response, and the agent warns once when it is missing. Upgrade the
  controller first.
- **Observability.** No metric carries the plane (cardinality). It appears in
  the registration and pinglist logs only.

**Choosing `plane_id` values.** A plane names the *largest* set of RNICs that
can reach each other, not the leaf. On a rail-optimized fabric where rail *r*
spans every group through per-rail spines, that set is the rail. The value
must not include the group: `<group>-<rail>` equals the leaf and leaves the
inter-ToR list empty. Where device names identify rails (see
[Field observations](#field-observations)), use `<zone>-<rail>` or
`<zone>-<device>` per device:

```yaml
device_plane_ids:
  mlx5_0: zone1-rail0   # or zone1-mlx5_0
  mlx5_1: zone1-rail1
```

`<zone>` separates independent fabrics that share one controller. On a fully
connected fabric, leave the plane empty.

### D. Alternatives that avoid per-RNIC ToRs

| | Alternative | Result |
|---|---|---|
| D1 | Stay untagged | Works, but no ToR-level localization and a capped random mesh |
| D2 | `tor_id` = rail (same value for rail *r* on every host) | ToR-mesh becomes the whole rail: O(N²) high-rate probes per rail across leaves |
| D3 | `tor_id` = group (agent-wide) | ToR-mesh mixes all rails of the group: mostly cross-spine pairs |

None of them reproduces "same leaf"; they are fallbacks only.

## Mechanism

- **Agent, static map.** `device_tor_ids` maps device names to ToR IDs. Keys
  match case-insensitively; values must be non-empty and must not be the
  reserved `unspecified`. Unlisted devices use `tor_id`. Each device
  registers, requests pinglists, and labels its probe results with its own
  ToR. Keys that match no opened device produce a startup warning.
- **Agent, LLDP discovery** (`lldp_tor_discovery: true`, source B2 without a
  generated map). At startup the agent maps each RDMA device to the netdev of
  its RoCE GID (`ports/<port>/gid_attrs/ndevs/<gid_index>` in sysfs, else the
  device's only PCI netdev), runs `lldpcli -f json0 show neighbors`
  (`lldpcli_path`), and uses the neighbor's system name or chassis ID
  (`lldp_tor_id_field`) as the device's ToR.
  - Precedence per device: `device_tor_ids` entry, then LLDP, then `tor_id`.
    A map can pin exceptions while LLDP covers the rest.
  - The agent re-queries until every device has a neighbor or
    `lldp_discovery_timeout_sec` (default 60; 0 = query once) expires.
    Unresolved devices fall back to `tor_id` with a warning. An LLDP failure
    never stops the agent.
  - Discovery runs once, so re-cabling needs an agent restart.
  - The resolved ToR and its source are logged per device ("Resolved device
    ToR").
- **Controller.** An RNIC's own `tor_id` wins over the request-wide one. Old
  agents send the same value in both places, so they are unaffected.
- **Metrics and analysis.** Each prober stamps its device's ToR on every
  result (`SourceTorID`). The metrics consumer and the analysis reporter
  prefer it over their agent-wide default.
- **Rollout: upgrade the controller first.** An old controller registers
  every RNIC under the agent-wide `tor_id` and still reports success, so
  per-device pinglist requests would match nothing and ToR-meshes would
  silently go empty. The new controller sets `per_rnic_tor_id` in the
  registration response. An agent with per-device ToRs (`device_tor_ids` or
  LLDP) that does not see the flag logs an error and falls back to `tor_id`
  for every device until it restarts against an upgraded controller. If the
  controller is downgraded under a running agent, the agent only logs an
  error (once, from the heartbeat), because its monitors already hold
  per-device ToRs.

## Field observations

Step 1 of the [verification plan](#verification-plan) ran
`collect_rnic_facts.py` on two production GPU environments with different
fabric designs:

- **LLDP (B2) was not usable in either.** An LLDP daemon runs on the hosts,
  but its control socket is root/group-only, and even as root it reports no
  neighbor on the RoCE ports (the frames are presumably consumed by NIC
  firmware or not sent by the switch). B2 cannot be the default source, so
  `lldp_tor_discovery` is opt-in for fabrics where hosts do see their leaf
  over LLDP.
- **Device naming is consistent across hosts** in both environments: a given
  device name always sits on the same rail. `--rail-key device` is therefore a
  sound rail key once storage/management rails and InfiniBand ports are
  excluded (`--devices`).
- **Subnet layouts differ:**
  - one environment uses one /24 per rail spanning every group, so the subnet
    identifies the rail, not the leaf;
  - the other assigns a small per-host, per-rail subnet (routed to the host
    port), so the subnet identifies neither.

  B3 holds in neither environment, and B4 needs a group source.
- **No Slurm topology plugin** is configured, so `scontrol show topology` is
  empty. Partition names may still encode groups (e.g. one partition per pod)
  and can feed `--host-groups`.

Consequence: in these environments the only inventory-free way to learn which
RNICs share a leaf is RTT clustering (B5, step 2). The practical naming source
is B4 with a group list taken from the cabling plan or the partition layout,
validated by B5.

## Verification plan

All steps are read-only or use the agent's normal probing; no switch or host
configuration changes.

1. **Facts.** Run `scripts/topology/collect_rnic_facts.py` on a sample of
   hosts covering at least two groups. Check: does an LLDP agent see a
   neighbor per RNIC (B2)? Do device names map to the same rail on every host?
   Is there one subnet per rail or per leaf (B3/B4)? Does
   `scontrol show topology` describe groups (B4)?
2. **Baseline with RTT clustering.** Run agents untagged with
   `log_level: debug` and `log_format: json`. On a rail-isolated fabric, also
   set `device_plane_ids` so the untagged mesh samples only same-rail RNICs.
   Wait until several pinglist refreshes have sampled most pairs, then run
   `scripts/topology/rtt_tor_check.py --logs ... --facts ...` without a
   mapping. Expect clearly separated RTT modes and inferred groups whose
   members share one device/rail and one host group.
3. **Candidate maps.** Build a map with every available strategy
   (`scripts/topology/build_device_tor_map.py`). For the correct map, expect
   no "several RNICs of the same host" warning from the builder, and zero
   contradictions from `rtt_tor_check.py --mapping` (which takes the
   builder's `--format json` output).
4. **Per-device ToR run.** Deploy the chosen map via `device_tor_ids`
   (controller first). Check that registry rows carry per-RNIC ToRs, that each
   RNIC's ToR-mesh contains only same-leaf RNICs of other hosts, that
   `source_tor`/`target_tor` series match the leaves, that intra-ToR RTT stays
   in the low mode, and whether cross-rail inter-ToR probes succeed. (This
   step decided policy C: they did not, so planes are configured.)
5. **Decide.** Record which source (B2/B3/B4) matched, whether a plane
   restriction is needed, and whether A3 (central topology) is worth building.

Success criteria: a mapping with no RTT contradictions, ToR-mesh lists that
never cross leaves, no sustained probe failures caused by the mapping, and
metric cardinality bounded by the number of leaves.
