# ToR Mapping on Multi-Rail (Rail-Optimized) Hosts

Status: mechanism implemented (`device_tor_ids`, per-RNIC ToR in the
controller). Inter-ToR policy decided: plane (rail) restriction implemented
(`plane_id` / `device_plane_ids`, see [policy C](#c-pinglist-policy-once-rnics-have-per-leaf-tors)),
based on the on-hardware observation that cross-rail probes always time out
on a rail-isolated fabric. The choice of mapping source is still pending
verification (see [Verification plan](#verification-plan)).

## Problem

R-Pingmesh organizes probing around the ToR switch: the **ToR-mesh** pinglist
probes every RNIC under the same ToR (host/RNIC/cable faults), and the
**inter-ToR** pinglist samples RNICs under other ToRs (fabric faults). OTel
metrics and analyzer findings are aggregated by `(source_tor, target_tor)`.

GPU clusters commonly use a *rail-optimized* fabric: a host has N RNICs
(rails), and rail *r* of every host in a group (scalable unit, pod) is cabled
to the same leaf switch, so a host's N RNICs sit under N **different** leaves.
Until now an agent had a single `tor_id`, so on such hosts:

- With `tor_id` set to a host or rack name, the "ToR" is not a switch at all:
  the ToR-mesh mixes all rails of a rack, most of its pairs cross the spine,
  and the metric labels cannot point at a leaf.
- With `tor_id` unset, every RNIC lands in one virtual rack and the ToR-mesh is
  a random sample capped by `unspecified_mesh_max_targets`; there is no
  inter-ToR list and all metrics collapse into one `unspecified` cell.

Neither localizes a problem to a leaf, which is the point of ToR-level
aggregation.

## What "ToR" should mean

The ToR ID of an RNIC should identify **the switch its port is cabled to**
(the leaf). Rack, host, and rail are proxies that are only correct in some
topologies. In a rail-optimized group the leaf is exactly `(group, rail)`.

## Current state of the code

- The proto already carries `tor_id` per RNIC (`RnicInfo.tor_id`), the rqlite
  registry stores it per RNIC, pinglists are requested per RNIC
  (`requester_gid` + `tor_id`), and `PathSummary` carries `source_tor_id` per
  path. Same-host exclusion (issue #39) already covers RNICs of one host that
  register under different ToRs.
- What was missing: the controller overwrote every RNIC's `tor_id` with the
  request-wide value, and the agent had no way to express a per-device ToR.
  Metrics and the analysis reporter used one agent-wide source ToR.

This change adds the mechanism; it does not decide where the mapping comes
from.

## Options

### A. Where the per-RNIC ToR is decided

| | Option | Pros | Cons |
|---|---|---|---|
| A1 | Agent-wide `tor_id` (status quo) | Simple | Wrong on rail-optimized hosts (see above) |
| A2 | **Per-device map in the agent config** (`device_tor_ids`, this change) | No proto change; works with any mapping source; agent knows its own ToR for metric labels | Map must be generated and distributed per host by config management |
| A3 | Controller-side topology file / inventory overriding agent values | One source of truth; no per-host config; reusable by Phase 2 localization | Needs a reload story; agent must learn its ToR for metric labels (registration response or pinglist), i.e. a proto change |
| A4 | Controller derives the requester's ToR from its registered GID instead of trusting `PinglistRequest.tor_id` | Removes one consistency hazard of A2 | Only meaningful together with A3 |

A2 is the smallest step that makes the rest testable; A3 (+A4) is the natural
follow-up if distributing per-host maps turns out to be operationally painful.
Both coexist: A3 can override what A2 reports.

### B. Where the mapping comes from

| | Source | Fidelity | Requirements / risks |
|---|---|---|---|
| B1 | Cabling plan / DCIM inventory | High if maintained | Drifts silently after re-cabling |
| B2 | LLDP neighbor of each RNIC netdev (`lldpd`/`lldpad`) | Highest: names the actual switch | LLDP agent on hosts; NIC firmware may consume LLDP frames (firmware DCBX/LLDP modes) so the host sees nothing; switch must send LLDP on host ports |
| B3 | Per-leaf host subnet (RNIC IPv4 network at a given prefix) | High when each leaf owns a subnet | Useless when one subnet spans a whole rail |
| B4 | `(group, rail)`: group from Slurm topology / scalable-unit membership, rail from the RNIC's rail subnet or device name | Exact for rail-optimized groups | Group source must exist; device names must be consistent across hosts if used as the rail key |
| B5 | Empirical: cluster RNIC pairs by measured network RTT (one switch hop vs three) | Inventory-independent | Gives groups, not switch names; needs HW timestamps and enough probe coverage |
| B6 | Empirical: IPv4 TTL / hop limit in the received GRH | Exact hop count per pair | Needs a C-ABI change to export it from the CQ poller; L2-bridged hops do not decrement |
| B7 | Switch-side data (LLDP/MAC tables via SNMP/gNMI) | High | Requires access to the network management plane |

B2/B3/B4 produce names; B5 (and later B6) validate them independently. The
tooling in `scripts/topology/` covers B2, B3, B4 and B5.

### C. Pinglist policy once RNICs have per-leaf ToRs

- **ToR-mesh** becomes "same leaf, other hosts", matching the paper.
- **Inter-ToR** used to sample `inter_tor_sample_size` foreign ToRs among
  *all* leaves, so most samples cross rails. In fabrics without cross-rail
  connectivity those probes fail by construction; in fully connected fabrics
  they are valid but exercise paths that rail-local collective traffic rarely
  uses.

**Decision: restrict to the requester's plane (implemented).** On a
rail-optimized fabric whose rails are not routed to each other, every probe
between RNICs of different rails times out, while same-rail probes succeed.
With N rails, (N-1)/N of unrestricted inter-ToR samples are therefore false
loss, and so are (N-1)/N of the targets of the untagged (empty ToR) mesh,
which samples all RNICs. An RNIC now carries an optional *plane*: the set of RNICs
it can reach (on a rail-isolated fabric, its rail).

- Agent: `plane_id` (host-wide) and `device_plane_ids` (device name → plane,
  same rules as `device_tor_ids`: case-insensitive keys, trimmed non-empty
  values; per-device entry wins over `plane_id`). Each RNIC registers its
  plane (`RnicInfo.plane_id`) and sends it with its pinglist requests
  (`PinglistRequest.plane_id`). Map entries for devices that are excluded,
  not allowed, or absent are warned about at startup instead of failing it,
  so one fleet-wide map can meet per-host device filters.
- Controller: rqlite `rnics.plane_id` column (added by `ALTER TABLE` on
  startup when an older table lacks it; `DEFAULT ''`, so an older controller
  sharing or reusing the database keeps working). When the requester has a
  plane, **inter-ToR** candidates and ToR representatives, and the
  **untagged mesh** (before its cap), are limited to RNICs registered on the
  same plane. **ToR-mesh** of a named ToR is unchanged; a leaf belongs to one
  plane, so a ToR whose RNICs report several non-empty planes is logged as a
  configuration error.
- Requester plane: the plane registered for `requester_gid` when non-empty,
  else the request's `plane_id`. The registry is preferred because targets
  are filtered by their registered planes, so both sides of the comparison
  come from one source and an agent cannot claim a plane it did not register.
  The request value covers the window in which the requester is not
  registered yet, or its row was written by an older controller and not yet
  refreshed by a heartbeat.
- Backward compatibility: an empty plane means "unknown" and keeps the old
  behavior. A requester without a plane is paired with every RNIC, as before;
  a requester with a plane is not paired with plane-less RNICs (registered by
  older agents), since nothing says they are reachable. Old agents never send
  a plane, so with a new controller nothing changes for them. A new agent
  against an old controller still works (the field is ignored), but its
  pinglists are not restricted; the controller signals support with
  `per_rnic_plane_id` in the registration response and the agent warns once
  when it is missing. Upgrade the controller first.
- No metric carries the plane (cardinality); it appears in the registration
  and pinglist logs only.

**Recommended `plane_id` values.** A plane must name the *largest* set of
RNICs that can reach each other, not the leaf: on a rail-optimized fabric
whose rail *r* spans every group through per-rail spines, that is the rail,
so the value must not include the group (`<group>-<rail>` would equal the
leaf and leave inter-ToR empty). Where device names identify rails (see the
[observations](#observations-step-1-of-the-plan) below), use `<zone>-<device>` per device, e.g.

```yaml
device_plane_ids:
  mlx5_0: zone-a-rail0   # or zone-a-mlx5_0
  mlx5_1: zone-a-rail1
```

where `<zone>` separates independent fabrics that share one controller. On a
fully connected fabric leave the plane empty.

### D. Alternatives that avoid per-RNIC ToRs

| | Alternative | Result |
|---|---|---|
| D1 | Stay untagged | Works, but no ToR-level localization and a capped random mesh |
| D2 | `tor_id` = rail (same value for rail *r* on every host) | ToR-mesh becomes the whole rail: O(N²) high-rate probes per rail across leaves |
| D3 | `tor_id` = group (agent-wide) | ToR-mesh mixes all rails of the group: mostly cross-spine pairs |

None of them reproduces "same leaf"; they are fallbacks only.

## Mechanism (this change)

- Agent: `device_tor_ids` (device name → ToR ID, case-insensitive keys,
  non-empty values). Unlisted devices use `tor_id`. Each device registers,
  requests pinglists, and labels its probe results with its own ToR. Unmatched
  keys are warned about at startup.
- Agent, LLDP (`lldp_tor_discovery: true`): at startup the agent maps each
  RDMA device to its RoCE netdev (`ports/<port>/gid_attrs/ndevs/<gid_index>`
  in sysfs, else the device's only PCI netdev), runs
  `lldpcli -f json0 show neighbors`, and uses the neighbor's system name (or
  chassis ID, `lldp_tor_id_field`) as the device's ToR. This is source B2
  without a generated map. Precedence per device: `device_tor_ids` entry, then
  LLDP, then `tor_id`, so a map can pin exceptions while LLDP covers the rest.
  The agent re-queries until every device has a neighbor or
  `lldp_discovery_timeout_sec` expires; unresolved devices fall back to
  `tor_id` with a warning, and an LLDP failure never stops the agent.
  Discovery runs once, so re-cabling needs an agent restart. The resolved ToR
  and its source are logged per device ("Resolved device ToR").
- Controller: an RNIC's own `tor_id` wins over the request-wide one. Old agents
  send the same value in both places, so they are unaffected.
- Metrics/analysis: the prober stamps `SourceTorID` on each result; the
  metrics consumer and the analysis reporter prefer it over their default.
- Rollout: upgrade the controller first. An old controller registers every
  RNIC under the agent-wide `tor_id` and still reports success, so per-device
  pinglist requests would match nothing and ToR-meshes would silently go
  empty. The new controller therefore sets `per_rnic_tor_id` in the
  registration response; an agent using per-device ToRs (`device_tor_ids` or
  LLDP) that does not see it logs an error and falls back to `tor_id` for
  every device until it is restarted against an upgraded controller. A
  controller downgraded under a running agent is only reported (once, from
  the heartbeat), since the monitors already hold per-device ToRs.

## Observations (step 1 of the plan)

Facts collected with `collect_rnic_facts.py` on rail-optimized fabrics of
different designs:

- **LLDP (B2) was not usable.** Hosts reported no LLDP neighbor on their RoCE
  ports (the frames may be consumed by NIC firmware or not sent by the
  switch), so B2 cannot be the default source. `lldp_tor_discovery` is
  therefore opt-in, for fabrics where hosts do see their leaf over LLDP.
- **Device naming was consistent across hosts:** a given device name always
  sat on the same rail, so `--rail-key device` is a sound rail key once
  storage/management rails and InfiniBand ports are excluded.
- **Subnets did not identify the leaf** (a subnet spanned a whole rail, or was
  smaller than a leaf), so B3 does not hold there. B4 needs a group source.
- **No Slurm topology plugin** was configured, so `scontrol show topology`
  was empty and B4 needs an external group list (e.g. from the cabling plan
  or the scheduler's partition layout, fed to `--host-groups`).

Consequence: on such fabrics the only inventory-free way to learn which
RNICs share a leaf is the RTT clustering of step 2 (B5); B4 with a group list
taken from the cabling plan or partition layout is the practical naming
source, validated by B5.

## Verification plan

All steps are read-only or use the agent's normal probing; no switch or host
configuration is changed.

1. **Facts.** Run `scripts/topology/collect_rnic_facts.py` on a sample of
   hosts covering at least two groups. Check: is an LLDP agent present and does
   it see a neighbor per RNIC (B2)? Are device names → rails consistent across
   hosts? Is there one subnet per rail or per leaf (B3/B4)? Does
   `scontrol show topology` describe groups (B4)?
2. **Baseline (untagged) with RTT clustering.** Run agents untagged with
   `log_level: debug` and `log_format: json` (and, on a rail-isolated fabric,
   `device_plane_ids` so the untagged mesh samples only reachable same-rail
   RNICs) for long enough that several pinglist refreshes have sampled most
   pairs, then run `scripts/topology/rtt_tor_check.py` without a
   mapping. Expect clearly separated RTT modes and inferred groups whose
   members share one device/rail and one host group.
3. **Candidate maps.** Build maps with every available strategy
   (`scripts/topology/build_device_tor_map.py`) and check each against the
   baseline with `rtt_tor_check.py --mapping`. Expect zero contradictions and
   no "several RNICs of the same host" warnings for the correct map.
4. **Per-device ToR run.** Deploy the chosen map via `device_tor_ids`
   (controller first). Check that the registry rows carry per-RNIC ToRs, that
   each RNIC's ToR-mesh contains only same-leaf RNICs of other hosts, that
   `source_tor`/`target_tor` series match the leaves, that intra-ToR RTT stays
   in the low mode, and whether cross-rail inter-ToR probes succeed (this
   decided policy C: they did not, so planes are configured).
5. **Decide.** Record which source (B2/B3/B4) matched, whether a plane
   restriction is needed, and whether A3 (central topology) is worth building.

Success criteria: a mapping with no RTT contradictions, ToR-mesh lists that
never cross leaves, no sustained probe failures caused by the mapping, and
metric cardinality bounded by the number of leaves.
