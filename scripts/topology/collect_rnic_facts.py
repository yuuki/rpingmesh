#!/usr/bin/env python3
"""Collect read-only facts about this host's RDMA NICs as one JSON object.

Used to decide and validate how RNICs map to ToR (leaf) switches on
multi-rail hosts (see docs/design/multi-rail-tor-mapping.md). It needs no
privileges, changes nothing, and uses only the Python standard library so it
runs on a stock RHEL 9-family or Debian/Ubuntu host:

    python3 scripts/topology/collect_rnic_facts.py > facts-$(hostname -s).json

Per RDMA device it records the port state/rate, the associated netdev, the
RoCE v2 GID table entries, the netdev's IPv4/IPv6 addresses, PCI address and
NUMA node, and -- when an LLDP agent is running -- the LLDP neighbor (switch
name and port). Host-level context (Slurm topology for this node, whether an
LLDP agent is present) is recorded too. Every probe is best-effort: a missing
tool or file yields null/"unavailable", never an error.
"""

import json
import os
import shutil
import socket
import subprocess
import sys

SYS_IB = "/sys/class/infiniband"


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def run(cmd, timeout=10):
    """Run cmd and return stdout, or None if it is unavailable or fails."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def port_netdev(dev, port):
    """Netdev bound to a RoCE port: prefer the GID ndev of index 0, then the
    PCI function's net/ directory (which may list several for bonds)."""
    ndev = read(os.path.join(SYS_IB, dev, "ports", port, "gid_attrs", "ndevs", "0"))
    if ndev:
        return ndev
    net_dir = os.path.join(SYS_IB, dev, "device", "net")
    try:
        names = sorted(os.listdir(net_dir))
    except OSError:
        return None
    return names[0] if names else None


def gid_table(dev, port):
    """Non-zero GID entries with their type and netdev."""
    base = os.path.join(SYS_IB, dev, "ports", port)
    try:
        indices = sorted(os.listdir(os.path.join(base, "gids")), key=int)
    except OSError:
        return []
    entries = []
    for idx in indices:
        gid = read(os.path.join(base, "gids", idx))
        if not gid or gid.replace(":", "").strip("0") == "":
            continue
        entries.append({
            "index": int(idx),
            "gid": gid,
            "type": read(os.path.join(base, "gid_attrs", "types", idx)),
            "ndev": read(os.path.join(base, "gid_attrs", "ndevs", idx)),
        })
    return entries


def netdev_addrs(ndev):
    out = run(["ip", "-j", "addr", "show", "dev", ndev])
    if not out:
        return None
    try:
        data = json.loads(out)
    except ValueError:
        return None
    addrs = []
    for link in data:
        for a in link.get("addr_info", []):
            if a.get("scope") == "link":
                continue
            addrs.append({"family": a.get("family"), "local": a.get("local"),
                          "prefixlen": a.get("prefixlen")})
    return addrs


def lldp_neighbor(ndev):
    """LLDP neighbor from lldpd (lldpcli) or lldpad (lldptool), if running."""
    out = run(["lldpcli", "-f", "json0", "show", "neighbors", "ports", ndev])
    if out:
        try:
            data = json.loads(out)
            for iface in data.get("lldp", [{}])[0].get("interface", []):
                chassis = (iface.get("chassis") or [{}])[0]
                port = (iface.get("port") or [{}])[0]
                name = ((chassis.get("name") or [{}])[0]).get("value")
                cid = ((chassis.get("id") or [{}])[0]).get("value")
                pid = ((port.get("id") or [{}])[0]).get("value")
                pdescr = ((port.get("descr") or [{}])[0]).get("value")
                return {"source": "lldpd", "system_name": name, "chassis_id": cid,
                        "port_id": pid, "port_descr": pdescr}
        except (ValueError, IndexError, AttributeError):
            pass
        return {"source": "lldpd", "system_name": None}
    out = run(["lldptool", "-t", "-n", "-i", ndev, "-V", "sysName"])
    if out:
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return {"source": "lldpad", "system_name": lines[-1] if lines else None}
    return {"source": "unavailable"}


def device_facts(dev):
    ports = []
    try:
        port_ids = sorted(os.listdir(os.path.join(SYS_IB, dev, "ports")), key=int)
    except OSError:
        port_ids = []
    for port in port_ids:
        base = os.path.join(SYS_IB, dev, "ports", port)
        ndev = port_netdev(dev, port)
        ports.append({
            "port": int(port),
            "state": read(os.path.join(base, "state")),
            "phys_state": read(os.path.join(base, "phys_state")),
            "rate": read(os.path.join(base, "rate")),
            "link_layer": read(os.path.join(base, "link_layer")),
            "netdev": ndev,
            "addrs": netdev_addrs(ndev) if ndev else None,
            "lldp": lldp_neighbor(ndev) if ndev else None,
            "gids": gid_table(dev, port),
        })
    pci = os.path.realpath(os.path.join(SYS_IB, dev, "device"))
    return {
        "device": dev,
        "pci": os.path.basename(pci) if os.path.exists(pci) else None,
        "numa_node": read(os.path.join(SYS_IB, dev, "device", "numa_node")),
        "fw_ver": read(os.path.join(SYS_IB, dev, "fw_ver")),
        "node_guid": read(os.path.join(SYS_IB, dev, "node_guid")),
        "ports": ports,
    }


def main():
    host = socket.gethostname()
    short = host.split(".")[0]
    try:
        devices = sorted(os.listdir(SYS_IB))
    except OSError:
        devices = []
    facts = {
        "hostname": host,
        "lldp_agent": ("lldpd" if shutil.which("lldpcli") else
                       "lldpad" if shutil.which("lldptool") else None),
        "slurm_topology": run(["scontrol", "show", "topology", short]),
        "devices": [device_facts(d) for d in devices],
    }
    json.dump(facts, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
