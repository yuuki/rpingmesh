#!/usr/bin/env python3
"""Collect read-only QoS facts about this host's RDMA NICs as one JSON object.

Used to choose the agent's `traffic_class` / `service_level` so probes share
the queue (switch/NIC priority) of the workload, e.g. NCCL (see the README
section "Choosing `traffic_class` and `service_level`"). Like
collect_rnic_facts.py it needs no privileges, changes nothing and uses only
the Python standard library:

    python3 scripts/topology/collect_qos_facts.py > qos-$(hostname -s).json
    python3 scripts/topology/summarize_qos_facts.py qos-*.json

Per RDMA device port and its netdev it records:

  - the trust mode (dscp/pcp), the DSCP -> priority map and the PFC-enabled
    priorities, from `mlnx_qos -i <netdev>` (MLNX_OFED/DOCA) when available,
    otherwise from iproute2 `dcb -j apptrust/app/pfc show dev <netdev>`;
  - the NIC-level traffic class override, if the driver exposes
    /sys/class/infiniband/<dev>/tc/<port>/traffic_class;
  - per-priority byte, packet and PFC pause counter deltas from
    `ethtool -S <netdev>`, sampled twice --interval seconds apart while the
    workload runs (--interval 0 skips sampling);
  - the RoCE v2 GID index candidates (from collect_rnic_facts.py).

The raw tool output is kept next to every parsed field (under "raw") so a
parsing mistake can be corrected offline. Every probe is best-effort: a
missing tool, file or permission yields null / "unavailable", never an error.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect_rnic_facts as rnic  # noqa: E402  (read, port_netdev, gid_table)

NUM_PRIO = 8


def probe(cmd, timeout=10):
    """Run cmd and return {"cmd", "status", "stdout"}; status is "ok",
    "unavailable" (tool not installed) or "failed" (non-zero exit, timeout)."""
    rec = {"cmd": " ".join(cmd), "status": "unavailable", "stdout": None}
    if shutil.which(cmd[0]) is None:
        return rec
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        rec["status"] = "failed"
        return rec
    rec["stdout"] = out.stdout
    if out.returncode != 0:
        rec["status"] = "failed"
        rec["stderr"] = out.stderr.strip()[:500]
        return rec
    rec["status"] = "ok"
    return rec


# --- parsers (pure functions; covered by test_qos_facts.py) ---------------

def parse_mlnx_qos(text):
    """Parse `mlnx_qos -i <netdev>` (mlnx-tools python/mlnx_qos pretty_print).

    Returns {"trust", "dscp_prio", "pfc_enabled"}; a field is None when the
    output does not contain it (dscp2prio is only printed with trust dscp)."""
    res: dict = {"trust": None, "dscp_prio": None, "pfc_enabled": None}
    if not text:
        return res
    m = re.search(r"^\s*Priority trust (?:state|mode):\s*(\S+)", text, re.M)
    if m:
        res["trust"] = m.group(1).lower()
    in_map = False
    dscp_prio = {}
    for line in text.splitlines():
        if re.match(r"^\s*dscp2prio mapping:", line):
            in_map = True
            continue
        if in_map:
            m = re.match(r"^\s*prio:\s*(\d+)\s+dscp:\s*([\d,\s]*)$", line)
            if not m:
                in_map = False
                continue
            for d in m.group(2).split(","):
                if d.strip():
                    dscp_prio[str(int(d))] = int(m.group(1))
    if dscp_prio or res["trust"] == "dscp":
        res["dscp_prio"] = dscp_prio
    m = re.search(r"^\s*priority((?:\s+\d)+)\s*\n\s*enabled((?:\s+\d)+)", text, re.M)
    if m:
        prios = [int(p) for p in m.group(1).split()]
        flags = [int(f) for f in m.group(2).split()]
        res["pfc_enabled"] = [p for p, f in zip(prios, flags) if f]
    return res


def _json(text):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def parse_dcb_apptrust(text):
    """`dcb -j apptrust show dev <netdev> order` -> (trust, order).

    iproute2 prints {"order": ["dscp", "pcp", ...]} (highest precedence
    first). The trust mode is the first of dscp/pcp in that order; an empty
    or missing order yields None (the driver default applies)."""
    data = _json(text)
    if not isinstance(data, dict) or not isinstance(data.get("order"), list):
        return None, None
    order = [str(s) for s in data["order"]]
    for sel in order:
        if sel in ("dscp", "pcp"):
            return sel, order
    return None, order


def parse_dcb_app_dscp(text):
    """`dcb -j app show dev <netdev> dscp-prio` -> {"<dscp>": prio}.

    iproute2 prints {"dscp_prio": [[<dscp>, <prio>, " "], ...]} (the inner
    arrays carry a trailing separator string) or {} with no DSCP entries."""
    data = _json(text)
    if not isinstance(data, dict):
        return None
    res = {}
    for entry in data.get("dscp_prio") or []:
        nums = [v for v in entry if isinstance(v, int) and not isinstance(v, bool)] \
            if isinstance(entry, list) else []
        if len(nums) >= 2:
            res[str(nums[0])] = nums[1]
    return res


def parse_dcb_pfc(text):
    """`dcb -j pfc show dev <netdev> prio-pfc` -> [enabled priorities].

    iproute2 prints {"prio_pfc": [false, false, false, true, ...]}, one
    boolean per priority; "on"/"off" strings and 0/1 are accepted too."""
    data = _json(text)
    if not isinstance(data, dict) or not isinstance(data.get("prio_pfc"), list):
        return None
    return [i for i, v in enumerate(data["prio_pfc"]) if v in (True, 1, "on")]


def parse_tc_override(text):
    """Parse /sys/class/infiniband/<dev>/tc/<port>/traffic_class.

    MLNX_OFED shows e.g. "Global tclass=106"; the global value is preferred,
    otherwise the first tclass=N found. Returns the value or None."""
    if not text:
        return None
    m = re.search(r"Global\s+tclass\s*=\s*(\d+)", text, re.I) or \
        re.search(r"tclass\s*=\s*(\d+)", text, re.I)
    return int(m.group(1)) if m else None


_PRIO_COUNTER = re.compile(
    r"^\s*(rx|tx)_prio(\d)_(bytes|packets|pause|pause_duration)\s*:\s*(\d+)\s*$")


def parse_ethtool_prio(text):
    """Per-priority counters from `ethtool -S <netdev>` (mlx5 naming,
    e.g. rx_prio3_bytes, tx_prio3_pause) -> ({"rx_prio3_bytes": n}, lines)."""
    counters, lines = {}, []
    for line in (text or "").splitlines():
        m = _PRIO_COUNTER.match(line)
        if m:
            counters[f"{m.group(1)}_prio{m.group(2)}_{m.group(3)}"] = int(m.group(4))
            lines.append(line.strip())
    return counters, lines


def counter_deltas(before, after, interval):
    """{"<prio>": {"rx_bytes": d, ...}} for counters present in both samples;
    a negative delta (counter reset) becomes None."""
    res = {}
    for name, v1 in after.items():
        if name not in before:
            continue
        m = re.match(r"(rx|tx)_prio(\d)_(\w+)$", name)
        if not m:
            continue
        d = v1 - before[name]
        res.setdefault(m.group(2), {})[f"{m.group(1)}_{m.group(3)}"] = d if d >= 0 else None
    return {"interval_s": interval, "prio": res}


# --- collection ------------------------------------------------------------

def netdev_qos(ndev):
    """Trust / DSCP map / PFC for a netdev, field by field: mlnx_qos first,
    then dcb for whatever mlnx_qos did not provide."""
    raw: dict = {}
    qos: dict = {"trust": None, "dscp_prio": None, "pfc_enabled": None}
    sources = {}
    raw["mlnx_qos"] = probe(["mlnx_qos", "-i", ndev])
    if raw["mlnx_qos"]["status"] == "ok":
        for k, v in parse_mlnx_qos(raw["mlnx_qos"]["stdout"]).items():
            if v is not None:
                qos[k], sources[k] = v, "mlnx_qos"
    # MLNX_OFED also exposes the trust state in sysfs.
    raw["sysfs_trust"] = rnic.read(f"/sys/class/net/{ndev}/qos/trust")
    if qos["trust"] is None and raw["sysfs_trust"] in ("dscp", "pcp"):
        qos["trust"], sources["trust"] = raw["sysfs_trust"], "sysfs"
    dcb = [
        ("trust", "dcb_apptrust", ["dcb", "-j", "apptrust", "show", "dev", ndev, "order"],
         lambda t: parse_dcb_apptrust(t)[0]),
        ("dscp_prio", "dcb_app", ["dcb", "-j", "app", "show", "dev", ndev, "dscp-prio"],
         parse_dcb_app_dscp),
        ("pfc_enabled", "dcb_pfc", ["dcb", "-j", "pfc", "show", "dev", ndev, "prio-pfc"],
         parse_dcb_pfc),
    ]
    for field, key, cmd, parse in dcb:
        if qos[field] is not None:
            continue
        raw[key] = probe(cmd)
        if raw[key]["status"] == "ok":
            v = parse(raw[key]["stdout"])
            if v is not None:
                qos[field], sources[field] = v, "dcb"
    qos["sources"] = sources
    qos["raw"] = raw
    return qos


def tc_override(dev, port):
    path = os.path.join(rnic.SYS_IB, dev, "tc", str(port), "traffic_class")
    if not os.path.exists(path):
        return {"status": "absent", "raw": None, "tclass": None}
    text = rnic.read(path)
    if text is None:
        return {"status": "unreadable", "raw": None, "tclass": None}
    tclass = parse_tc_override(text)
    return {"status": "set" if tclass is not None else "unset", "raw": text,
            "tclass": tclass}


def sample_counters(netdevs):
    out = {}
    for nd in netdevs:
        rec = probe(["ethtool", "-S", nd])
        counters, lines = parse_ethtool_prio(rec["stdout"] if rec["status"] == "ok" else "")
        out[nd] = {"status": rec["status"], "counters": counters, "lines": lines}
    return out


def collect(interval):
    try:
        devices = sorted(os.listdir(rnic.SYS_IB))
    except OSError:
        devices = []
    ports = []  # (dev, port_id, netdev)
    for dev in devices:
        try:
            port_ids = sorted(os.listdir(os.path.join(rnic.SYS_IB, dev, "ports")), key=int)
        except (OSError, ValueError):
            port_ids = []
        for p in port_ids:
            ports.append((dev, p, rnic.port_netdev(dev, p)))

    netdevs = sorted({nd for _, _, nd in ports if nd})
    qos = {nd: netdev_qos(nd) for nd in netdevs}
    counters = {}
    if interval > 0 and netdevs:
        first = sample_counters(netdevs)
        time.sleep(interval)
        second = sample_counters(netdevs)
        for nd in netdevs:
            a, b = first[nd], second[nd]
            if a["counters"] and b["counters"]:
                c = counter_deltas(a["counters"], b["counters"], interval)
                c["status"] = "ok"
            else:
                c = {"status": b["status"] if b["status"] != "ok" else "no_prio_counters",
                     "interval_s": interval, "prio": None}
            c["raw"] = {"before": a["lines"], "after": b["lines"]}
            counters[nd] = c

    out_devs = {}
    for dev, p, nd in ports:
        base = os.path.join(rnic.SYS_IB, dev, "ports", p)
        gids = [g for g in rnic.gid_table(dev, p)
                if (g.get("type") or "").lower().startswith("roce v2")]
        entry = {
            "port": int(p),
            "state": rnic.read(os.path.join(base, "state")),
            "link_layer": rnic.read(os.path.join(base, "link_layer")),
            "netdev": nd,
            "rocev2_gids": gids,
            "tc_override": tc_override(dev, p),
            "qos": qos.get(nd),
            "counters": counters.get(nd) if nd else None,
        }
        if interval <= 0:
            entry["counters"] = {"status": "skipped"}
        out_devs.setdefault(dev, []).append(entry)

    return {
        "hostname": socket.gethostname(),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tools": {t: shutil.which(t) is not None for t in ("mlnx_qos", "dcb", "ethtool")},
        "devices": [{"device": d, "ports": ps} for d, ps in sorted(out_devs.items())],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interval", type=float, default=5.0,
                    help="seconds between the two ethtool -S samples (0 = skip; default 5)")
    args = ap.parse_args(argv)
    json.dump(collect(max(args.interval, 0.0)), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
