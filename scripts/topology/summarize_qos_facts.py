#!/usr/bin/env python3
"""Summarize collect_qos_facts.py output from many hosts and suggest values.

    python3 summarize_qos_facts.py qos-*.json [--json]

Reads one JSON object per file (one per host) and reports, over every RDMA
port that has a netdev:

  - the PFC-enabled (lossless) priority or priorities and the DSCPs that map
    to them;
  - candidate `traffic_class` values: any NIC-level override value verbatim
    (what the workload actually emits) and `DSCP << 2` for each DSCP mapping
    to a PFC-enabled priority (the low 2 bits are ECN: +0 is Not-ECT, +2 is
    ECT(0)), plus a `service_level` hint from the trust mode;
  - whether trust mode, PFC priorities, DSCP map and override agree across
    hosts and devices, listing the ports that differ from the majority (e.g.
    a rail whose per-device override setup was missed);
  - which priority carried the bytes observed between the two ethtool -S
    samples. These counters include all traffic in that priority, not only
    RoCE, and pause counters move only under congestion.

It only suggests: confirm the choice with the README section "Choosing
`traffic_class` and `service_level`" and with the network team (switch
classification and re-marking are not visible from the hosts). Nothing is
written to any config.
"""

import argparse
import collections
import json
import sys

ECN = {0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE"}


def short(host):
    return (host or "?").split(".")[0]


def load_ports(paths):
    """Flatten collect_qos_facts.py files into one record per RDMA port."""
    ports = []
    for path in paths:
        with open(path) as f:
            facts = json.load(f)
        host = short(facts.get("hostname"))
        for dev in facts.get("devices") or []:
            for p in dev.get("ports") or []:
                if not p.get("netdev"):
                    continue
                qos = p.get("qos") or {}
                pfc = qos.get("pfc_enabled")
                dmap = qos.get("dscp_prio")
                ov = p.get("tc_override") or {}
                cnt = p.get("counters") or {}
                ports.append({
                    "id": f"{host}/{dev.get('device')}:{p.get('port')}",
                    "host": host,
                    "netdev": p.get("netdev"),
                    "trust": qos.get("trust"),
                    "pfc": tuple(sorted(pfc)) if pfc is not None else None,
                    "dscp_prio": ({int(k): int(v) for k, v in dmap.items()}
                                  if dmap is not None else None),
                    "override": ov.get("tclass"),
                    "override_status": ov.get("status"),
                    "counters": cnt.get("prio") if cnt.get("status") == "ok" else None,
                    "interval_s": cnt.get("interval_s"),
                    "gid_indices": tuple(sorted(g["index"] for g in p.get("rocev2_gids") or [])),
                })
    return ports


def tally(ports, key, known=lambda v: v is not None):
    """Majority value of key among ports whose value is known; ports with a
    different known value are outliers, the rest are unknown."""
    counts = collections.Counter(key(p) for p in ports if known(key(p)))
    majority = counts.most_common(1)[0][0] if counts else None
    outliers = [(p["id"], key(p)) for p in ports
                if known(key(p)) and key(p) != majority]
    unknown = [p["id"] for p in ports if not known(key(p))]
    return {"majority": majority, "counts": counts, "outliers": outliers,
            "unknown": unknown}


def dscps_by_prio(dmap):
    res = collections.defaultdict(list)
    for d, prio in sorted((dmap or {}).items()):
        res[prio].append(d)
    return res


def summarize(ports):
    trust = tally(ports, lambda p: p["trust"])
    pfc = tally(ports, lambda p: p["pfc"])
    dmap = tally(ports, lambda p: tuple(sorted(p["dscp_prio"].items()))
                 if p["dscp_prio"] is not None else None)
    # None is a meaningful override value (not set / not exposed), so every
    # port takes part.
    override = tally(ports, lambda p: p["override"], known=lambda v: True)
    gids = tally(ports, lambda p: p["gid_indices"] or None)

    lossless = list(pfc["majority"] or ())
    majority_map = dict(dmap["majority"] or ())
    by_prio = dscps_by_prio(majority_map)
    lossless_dscps = {p: by_prio.get(p, []) for p in lossless}

    candidates = []
    seen = set()
    for value, n in override["counts"].most_common():
        if value is None:
            continue
        dscp, prio = value >> 2, majority_map.get(value >> 2)
        candidates.append({
            "traffic_class": value, "dscp": dscp, "ecn": ECN[value & 3],
            "priority": prio, "pfc_enabled": prio in lossless if prio is not None else None,
            "source": f"NIC override on {n} port(s)"})
        seen.add(value)
    for prio in lossless:
        for d in lossless_dscps[prio]:
            if d << 2 not in seen:
                candidates.append({
                    "traffic_class": d << 2, "dscp": d, "ecn": ECN[0], "priority": prio,
                    "pfc_enabled": True, "source": "DSCP << 2"})

    if trust["majority"] == "pcp":
        sl = {"candidates": lossless,
              "note": "trust pcp: SL maps to the PCP only for VLAN-tagged RoCE; "
                      "DSCP (traffic_class) does not select the queue"}
    elif trust["majority"] == "dscp":
        sl = {"candidates": [0], "note": "trust dscp: SL does not select the queue"}
    else:
        sl = {"candidates": [], "note": "trust mode unknown"}

    # Traffic between the two counter samples, summed over every port.
    traffic = collections.defaultdict(lambda: collections.Counter())
    top_per_port = collections.Counter()
    busiest = {}  # port id -> priority with the most bytes on that port
    with_counters = 0
    intervals = set()
    for p in ports:
        if not p["counters"]:
            continue
        with_counters += 1
        intervals.add(p["interval_s"])
        port_bytes = {}
        for prio, c in p["counters"].items():
            b = (c.get("rx_bytes") or 0) + (c.get("tx_bytes") or 0)
            port_bytes[int(prio)] = b
            traffic[int(prio)]["bytes"] += b
            traffic[int(prio)]["pause"] += (c.get("rx_pause") or 0) + (c.get("tx_pause") or 0)
        if port_bytes and max(port_bytes.values()) > 0:
            busiest[p["id"]] = max(port_bytes, key=lambda k: port_bytes[k])
            top_per_port[busiest[p["id"]]] += 1
    total = sum(t["bytes"] for t in traffic.values())
    top = max(traffic, key=lambda k: traffic[k]["bytes"]) if total else None

    return {
        "hosts": len({p["host"] for p in ports}),
        "ports": len(ports),
        "trust": trust,
        "pfc_enabled": pfc,
        "dscp_map": dmap,
        "override": override,
        "rocev2_gid_indices": gids,
        "lossless_priorities": lossless,
        "lossless_dscps": lossless_dscps,
        "candidates": candidates,
        "service_level": sl,
        "traffic": {
            "ports_with_counters": with_counters,
            "interval_s": sorted(i for i in intervals if i is not None),
            "by_priority": {k: dict(v) for k, v in sorted(traffic.items())},
            "total_bytes": total,
            "top_priority": top,
            "top_priority_per_port": dict(top_per_port),
            "ports_busiest_elsewhere": [{"port": pid, "priority": prio}
                                        for pid, prio in busiest.items() if prio != top],
        },
    }


def ranges(nums):
    """[24, 25, 26, 27, 40] -> "24-27,40"."""
    runs = []
    for n in sorted(nums):
        if runs and n == runs[-1][1] + 1:
            runs[-1][1] = n
        else:
            runs.append([n, n])
    return ",".join(f"{a}-{b}" if b > a else str(a) for a, b in runs) or "-"


def fmt_value(name, v):
    if name == "pfc_enabled":
        return "none" if v == () else ",".join(map(str, v))
    if name == "dscp_map":
        by = dscps_by_prio(dict(v))
        return " ".join(f"p{p}:{ranges(ds)}" for p, ds in sorted(by.items())) or "empty"
    if name == "rocev2_gid_indices":
        return ",".join(map(str, v))
    return "not set" if v is None else str(v)


def render(s, out):
    w = out.write
    w(f"{s['hosts']} hosts, {s['ports']} RDMA ports with a netdev\n\n")

    w("Consistency (majority / outliers):\n")
    for name, label in (("trust", "trust mode"), ("pfc_enabled", "PFC priorities"),
                        ("dscp_map", "DSCP->prio map"), ("override", "tclass override"),
                        ("rocev2_gid_indices", "RoCE v2 GID idx")):
        t = s[name]
        n_known = sum(t["counts"].values())
        state = ("no data" if not n_known else "consistent" if not t["outliers"]
                 else f"{len(t['outliers'])} differ")
        maj = "unknown" if not t["counts"] else fmt_value(name, t["majority"])
        w(f"  {label:<16}: {maj}  ({t['counts'][t['majority']] if t['counts'] else 0}/{n_known} ports, {state}"
          f"{', ' + str(len(t['unknown'])) + ' unknown' if t['unknown'] else ''})\n")
        for pid, v in t["outliers"]:
            w(f"      outlier {pid}: {fmt_value(name, v)}\n")
        if t["unknown"] and len(t["unknown"]) <= 10:
            w(f"      unknown: {', '.join(t['unknown'])}\n")
    w("\n")

    if s["lossless_priorities"]:
        w("PFC-enabled priorities and the DSCPs mapping to them:\n")
        for prio, ds in s["lossless_dscps"].items():
            w(f"  priority {prio}: DSCP {ranges(ds) if ds else '(none in the DSCP map)'}\n")
        if s["trust"]["majority"] == "pcp":
            w("  (trust pcp: the queue is selected by the VLAN PCP, not by DSCP)\n")
    else:
        w("No PFC-enabled priority found (or PFC state unavailable).\n")
    w("\n")

    w("Candidate traffic_class values (suggestions, not a decision):\n")
    if not s["candidates"]:
        w("  none: no override and no DSCP mapping to a PFC-enabled priority\n")
    for c in s["candidates"]:
        prio = "?" if c["priority"] is None else c["priority"]
        lossless = {True: "PFC on", False: "PFC OFF", None: "PFC ?"}[c["pfc_enabled"]]
        w(f"  {c['traffic_class']:>3}  DSCP {c['dscp']:>2} {c['ecn']:<7} -> priority {prio} ({lossless})"
          f"  [{c['source']}]\n")
    w("  The low 2 bits are ECN: DSCP<<2 is Not-ECT, +2 is ECT(0). Prefer the value the\n"
      "  workload emits (e.g. an override verbatim) and verify the ECN on the wire.\n")
    sl = s["service_level"]
    w(f"service_level: {', '.join(map(str, sl['candidates'])) or '?'} ({sl['note']})\n\n")

    t = s["traffic"]
    if not t["ports_with_counters"]:
        w("Traffic: no per-priority counter deltas (collected with --interval 0, or ethtool unavailable).\n")
    else:
        w(f"Traffic over {'/'.join(f'{i:g}' for i in t['interval_s'])} s on "
          f"{t['ports_with_counters']} ports (rx+tx bytes, pause frames):\n")
        for prio, v in t["by_priority"].items():
            share = 100.0 * v.get("bytes", 0) / t["total_bytes"] if t["total_bytes"] else 0.0
            if v.get("bytes") or v.get("pause"):
                w(f"  priority {prio}: {v.get('bytes', 0):>16} bytes ({share:5.1f}%)  pause {v.get('pause', 0)}\n")
        if t["top_priority"] is not None:
            per = ", ".join(f"p{k}: {n}" for k, n in sorted(t["top_priority_per_port"].items()))
            w(f"  most bytes: priority {t['top_priority']} (busiest priority per port: {per})\n")
            for e in t["ports_busiest_elsewhere"]:
                w(f"      {e['port']}: most bytes in priority {e['priority']}\n")
        w("  These counters include all traffic in a priority, not only RoCE; pause\n"
          "  counters move only under congestion, so zero does not prove a priority is unused.\n")


def to_json(s):
    def conv(t):
        return {"majority": t["majority"],
                "counts": [{"value": k, "ports": n} for k, n in t["counts"].most_common()],
                "outliers": [{"port": pid, "value": v} for pid, v in t["outliers"]],
                "unknown": t["unknown"]}
    out = dict(s)
    for k in ("trust", "pfc_enabled", "dscp_map", "override", "rocev2_gid_indices"):
        out[k] = conv(s[k])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("facts", nargs="+", help="collect_qos_facts.py output files")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = ap.parse_args(argv)
    s = summarize(load_ports(args.facts))
    if args.json:
        json.dump(to_json(s), sys.stdout, indent=1, sort_keys=True, default=list)
        sys.stdout.write("\n")
    else:
        render(s, sys.stdout)


if __name__ == "__main__":
    main()
