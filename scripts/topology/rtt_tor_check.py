#!/usr/bin/env python3
"""Cross-check an RNIC -> ToR mapping against measured network RTTs.

On a leaf-spine fabric, a probe between two RNICs under the same leaf crosses
one switch, while a probe between leaves crosses at least three, so with HW
timestamps the per-pair network RTT separates into clear modes. This script
uses that to validate a candidate mapping (or to infer one) without trusting
any inventory:

  1. Run agents with log_level: debug for a while (an untagged run is fine:
     every RNIC then probes a random sample of the others, refreshed on each
     pinglist update) and collect their logs (zerolog JSON lines, e.g.
     `journalctl -u rpingmesh-agent -o cat`).
  2. python3 rtt_tor_check.py --logs agent-*.log --facts facts/*.json \\
         [--mapping map.json] [--cluster-threshold-ns 5000]

It computes the median network RTT, (T5-T2)-(T4-T3), of every observed
(source RNIC, target RNIC) pair from "Probe result recorded" debug lines and:

  --mapping  (JSON {hostname: {device: tor}} from build_device_tor_map.py
             --format json) reports the RTT distribution of same-ToR vs
             cross-ToR pairs and lists the pairs that contradict the mapping
             (same-ToR pairs slower than the threshold, cross-ToR pairs
             faster than it).
  --cluster-threshold-ns T
             links every pair whose median RTT is below T and prints the
             connected components: the inferred "same leaf" groups.

When no threshold is given, it is placed in the widest gap of the sorted pair
medians (between the intra-leaf and inter-leaf modes).
"""

import argparse
import collections
import ipaddress
import json
import statistics
import sys


def norm_gid(g):
    try:
        return ipaddress.IPv6Address(g).exploded
    except ValueError:
        return None


def load_gid_index(fact_paths):
    """GID (exploded) -> "host/device" from collect_rnic_facts.py output."""
    index = {}
    for path in fact_paths:
        with open(path) as f:
            facts = json.load(f)
        host = facts["hostname"].split(".")[0]
        for dev in facts.get("devices", []):
            for port in dev.get("ports", []):
                for g in port.get("gids") or []:
                    key = norm_gid(g.get("gid", ""))
                    if key:
                        index[key] = (host, dev["device"])
    return index


def load_pair_rtts(log_paths):
    rtts = collections.defaultdict(list)
    lines = bad = 0
    for path in log_paths:
        with open(path, errors="replace") as f:
            for line in f:
                start = line.find("{")
                if start < 0 or "Probe result recorded" not in line:
                    continue
                try:
                    rec = json.loads(line[start:])
                except ValueError:
                    continue
                lines += 1
                if not rec.get("success"):
                    continue
                try:
                    t2, t3, t4, t5 = (int(rec[k]) for k in ("t2", "t3", "t4", "t5"))
                except (KeyError, ValueError):
                    bad += 1
                    continue
                rtt = (t5 - t2) - (t4 - t3)
                if rtt <= 0 or rtt > 10_000_000:
                    bad += 1
                    continue
                src, tgt = norm_gid(rec.get("source_gid", "")), norm_gid(rec.get("target_gid", ""))
                if not src or not tgt or src.strip("0:") == "":
                    bad += 1
                    continue
                rtts[(src, tgt)].append(rtt)
    sys.stderr.write(f"{lines} probe records, {bad} unusable, {len(rtts)} pairs\n")
    return {pair: statistics.median(v) for pair, v in rtts.items()}


def widest_gap_threshold(values):
    vals = sorted(values)
    if len(vals) < 2:
        return None
    best = max(range(len(vals) - 1), key=lambda i: vals[i + 1] - vals[i])
    return (vals[best] + vals[best + 1]) / 2


def describe(vals):
    if not vals:
        return "n=0"
    vals = sorted(vals)
    q = lambda p: vals[min(len(vals) - 1, int(p * len(vals)))]
    return (f"n={len(vals)} min={vals[0]:.0f} p10={q(0.1):.0f} p50={q(0.5):.0f} "
            f"p90={q(0.9):.0f} max={vals[-1]:.0f} ns")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", nargs="+", required=True)
    ap.add_argument("--facts", nargs="+", required=True)
    ap.add_argument("--mapping", help="JSON {hostname: {device: tor}}")
    ap.add_argument("--cluster-threshold-ns", type=float)
    ap.add_argument("--max-listed", type=int, default=30)
    args = ap.parse_args()

    gid_index = load_gid_index(args.facts)
    medians = load_pair_rtts(args.logs)
    named = {}
    unknown = set()
    for (src, tgt), rtt in medians.items():
        if src in gid_index and tgt in gid_index:
            named[(gid_index[src], gid_index[tgt])] = rtt
        else:
            unknown.update(g for g in (src, tgt) if g not in gid_index)
    if unknown:
        sys.stderr.write(f"WARNING: {len(unknown)} GIDs not found in the facts files\n")
    if not named:
        sys.exit("no usable pairs")

    threshold = args.cluster_threshold_ns or widest_gap_threshold(named.values())
    print(f"all pairs: {describe(list(named.values()))}")
    print(f"threshold: {threshold:.0f} ns" + ("" if args.cluster_threshold_ns else " (widest gap)"))

    if args.mapping:
        with open(args.mapping) as f:
            raw = json.load(f)
        tor_of = {(h.split(".")[0], d): t for h, devs in raw.items() for d, t in devs.items()}
        same, cross, contradictions, unmapped = [], [], [], 0
        for (a, b), rtt in named.items():
            ta, tb = tor_of.get(a), tor_of.get(b)
            if ta is None or tb is None:
                unmapped += 1
                continue
            if ta == tb:
                same.append(rtt)
                if rtt > threshold:
                    contradictions.append((rtt, a, b, "same ToR but slow", ta, tb))
            else:
                cross.append(rtt)
                if rtt < threshold:
                    contradictions.append((rtt, a, b, "cross ToR but fast", ta, tb))
        print(f"same-ToR pairs : {describe(same)}")
        print(f"cross-ToR pairs: {describe(cross)}")
        print(f"unmapped pairs : {unmapped}")
        print(f"contradictions : {len(contradictions)}")
        for rtt, a, b, why, ta, tb in sorted(contradictions)[: args.max_listed]:
            print(f"  {why}: {a[0]}/{a[1]} ({ta}) -> {b[0]}/{b[1]} ({tb}) median {rtt:.0f} ns")

    if args.cluster_threshold_ns or not args.mapping:
        parent = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for (a, b), rtt in named.items():
            find(a)
            find(b)
            if rtt < threshold:
                parent[find(a)] = find(b)
        groups = collections.defaultdict(list)
        for node in parent:
            groups[find(node)].append(node)
        print(f"inferred groups (pairs below {threshold:.0f} ns linked): {len(groups)}")
        for members in sorted(groups.values(), key=len, reverse=True):
            devs = collections.Counter(d for _, d in members)
            print(f"  {len(members)} RNICs, devices {dict(devs)}: "
                  + ", ".join(f"{h}/{d}" for h, d in sorted(members)[: args.max_listed]))


if __name__ == "__main__":
    main()
