#!/usr/bin/env python3
"""Derive per-host agent `device_tor_ids` from collected RNIC facts.

Input is one or more JSON files written by collect_rnic_facts.py (one per
host). A strategy decides the ToR ID of each RNIC:

  lldp        The LLDP neighbor's system name (the leaf switch itself).
              Most faithful; requires an LLDP agent on the hosts and LLDP
              frames reaching the host (NIC firmware may consume them).
  subnet      The RNIC's IPv4 network at --prefixlen (e.g. a per-leaf /26).
              Works when every leaf owns its own host subnet.
  group-rail  "<group>-<rail>": <group> comes from --host-groups (a CSV of
              hostname,group, e.g. one group per scalable unit / pod taken
              from Slurm topology or the cabling plan), <rail> is the RNIC's
              IPv4 network at --rail-prefixlen (one subnet per rail) or, with
              --rail-key device, its device name. In a rail-optimized fabric
              the leaf of rail r in group g is exactly (g, r).

Only RNICs that are up and have a RoCE v2 IPv4 GID are mapped; --devices
restricts the set (e.g. to exclude storage rails). Output (stdout) is YAML
with one `device_tor_ids` block per host, followed by a summary on stderr
listing every ToR's members and consistency warnings:

    python3 build_device_tor_map.py --strategy group-rail \\
        --host-groups groups.csv --rail-prefixlen 24 facts/*.json > map.yaml

Use `--format json` to get {hostname: {device: tor}} for other tooling
(e.g. rtt_tor_check.py).
"""

import argparse
import collections
import csv
import ipaddress
import json
import sys


def ipv4_of(port):
    for a in port.get("addrs") or []:
        if a.get("family") == "inet" and a.get("local"):
            return ipaddress.ip_interface(f"{a['local']}/{a.get('prefixlen', 32)}")
    return None


def has_rocev2_ipv4_gid(port):
    for g in port.get("gids") or []:
        if (g.get("type") or "").lower().startswith("roce v2") and \
                g.get("gid", "").startswith("0000:0000:0000:0000:0000:ffff:"):
            return True
    return False


def rnics(facts, allowed):
    """Yield (hostname, device, port_dict) for usable RoCE v2 IPv4 RNICs."""
    for dev in facts.get("devices", []):
        name = dev["device"]
        if allowed and name not in allowed:
            continue
        for port in dev.get("ports", []):
            if not (port.get("state") or "").endswith("ACTIVE"):
                continue
            if not has_rocev2_ipv4_gid(port):
                continue
            yield facts["hostname"], name, port


def short(host):
    return host.split(".")[0]


def load_host_groups(path):
    """Short hostname -> group from a CSV of hostname,group ('#' rows are comments)."""
    groups = {}
    with open(path) as f:
        for row in csv.reader(f):
            if len(row) >= 2 and not row[0].startswith("#"):
                groups[short(row[0].strip())] = row[1].strip()
    return groups


def lldp_tor(host, dev, port, warnings):
    tor = (port.get("lldp") or {}).get("system_name")
    if not tor:
        warnings.append(f"{host}/{dev}: no LLDP neighbor ({(port.get('lldp') or {}).get('source')})")
    return tor


def subnet_tor(host, dev, port, prefixlen, warnings):
    ip = ipv4_of(port)
    if not ip:
        warnings.append(f"{host}/{dev}: no IPv4 address on {port.get('netdev')}")
        return None
    return str(ipaddress.ip_network(f"{ip.ip}/{prefixlen}", strict=False))


def group_rail_tor(host, dev, port, args, groups, warnings):
    group = groups.get(short(host))
    if group is None:
        warnings.append(f"{host}: not in --host-groups")
        return None
    if args.rail_key == "device":
        return f"{group}-{dev}"
    rail = subnet_tor(host, dev, port, args.rail_prefixlen, warnings)
    if rail is None:
        return None
    return f"{group}-{rail}"


def rnic_tor(host, dev, port, args, groups, warnings):
    """The ToR ID of one RNIC under args.strategy, or a false value (with a
    warning) when the strategy cannot place it."""
    if args.strategy == "lldp":
        return lldp_tor(host, dev, port, warnings)
    if args.strategy == "subnet":
        return subnet_tor(host, dev, port, args.prefixlen, warnings)
    return group_rail_tor(host, dev, port, args, groups, warnings)


def map_rnics(args, allowed, groups, warnings):
    """host -> {device: tor} in input order, and tor -> ["host/device"]."""
    mapping = collections.OrderedDict()   # host -> {device: tor}
    members = collections.defaultdict(list)  # tor -> ["host/device"]
    for path in args.facts:
        with open(path) as f:
            facts = json.load(f)
        for host, dev, port in rnics(facts, allowed):
            tor = rnic_tor(host, dev, port, args, groups, warnings)
            if not tor:
                continue
            mapping.setdefault(host, collections.OrderedDict())[dev] = tor
            members[tor].append(f"{short(host)}/{dev}")
    return mapping, members


def consistency_warnings(members):
    """A ToR that holds two RNICs of one host contradicts a rail-optimized
    layout; a single-member ToR gets an empty ToR-mesh."""
    warnings = []
    for tor, ms in sorted(members.items()):
        hosts = collections.Counter(m.split("/")[0] for m in ms)
        dup = [h for h, n in hosts.items() if n > 1]
        if dup:
            warnings.append(f"ToR {tor}: several RNICs of the same host ({', '.join(sorted(dup))})")
        if len(ms) == 1:
            warnings.append(f"ToR {tor}: only one RNIC ({ms[0]}); its ToR-mesh will be empty")
    return warnings


def write_mapping(mapping, fmt):
    if fmt == "json":
        json.dump(mapping, sys.stdout, indent=1)
        sys.stdout.write("\n")
        return
    for host, devs in mapping.items():
        sys.stdout.write(f"# --- {host} ---\ndevice_tor_ids:\n")
        for dev, tor in devs.items():
            sys.stdout.write(f'  {dev}: "{tor}"\n')


def write_summary(mapping, members, warnings):
    sys.stderr.write(f"{len(members)} ToRs, {sum(len(m) for m in members.values())} RNICs on {len(mapping)} hosts\n")
    for tor, ms in sorted(members.items()):
        sys.stderr.write(f"  {tor}: {len(ms)} RNICs\n")
    for w in warnings:
        sys.stderr.write(f"WARNING: {w}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("facts", nargs="+", help="collect_rnic_facts.py output files")
    ap.add_argument("--strategy", required=True, choices=["lldp", "subnet", "group-rail"])
    ap.add_argument("--prefixlen", type=int, help="subnet: per-leaf prefix length")
    ap.add_argument("--host-groups", help="group-rail: CSV of hostname,group")
    ap.add_argument("--rail-key", choices=["subnet", "device"], default="subnet",
                    help="group-rail: derive the rail from the RNIC subnet or device name")
    ap.add_argument("--rail-prefixlen", type=int, default=24,
                    help="group-rail with --rail-key subnet: per-rail prefix length")
    ap.add_argument("--devices", help="comma-separated device names to include")
    ap.add_argument("--format", choices=["yaml", "json"], default="yaml")
    args = ap.parse_args()

    allowed = set(args.devices.split(",")) if args.devices else None
    groups = {}
    if args.strategy == "group-rail":
        if not args.host_groups:
            ap.error("--host-groups is required for group-rail")
        groups = load_host_groups(args.host_groups)
    if args.strategy == "subnet" and not args.prefixlen:
        ap.error("--prefixlen is required for subnet")

    warnings = []
    mapping, members = map_rnics(args, allowed, groups, warnings)
    warnings.extend(consistency_warnings(members))
    write_mapping(mapping, args.format)
    write_summary(mapping, members, warnings)


if __name__ == "__main__":
    main()
