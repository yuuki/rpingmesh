#!/usr/bin/env python3
"""Tests for build_device_tor_map.py.

The facts files are written in the shape collect_rnic_facts.py emits: host-a
has two usable RNICs plus one that is down and one without a RoCE v2 IPv4
GID, host-b has one RNIC without an IPv4 address or LLDP neighbor, and host-c
has no LLDP data and is not in the host-groups CSV.

Run with: python3 -m unittest discover -s scripts/topology -p 'test_*.py'
"""

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_file_location("build_device_tor_map", os.path.join(HERE, "build_device_tor_map.py"))
tormap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tormap)


def port(netdev, ip, gid, lldp=None, state="4: ACTIVE", gid_type="RoCE v2"):
    addrs = [{"family": "inet6", "local": "fe80::1", "prefixlen": 64}]
    if ip:
        addrs.append({"family": "inet", "local": ip, "prefixlen": 24})
    return {"port": 1, "state": state, "netdev": netdev, "addrs": addrs, "lldp": lldp,
            "gids": [{"index": 0, "gid": "fe80:0000:0000:0000:0000:0000:0000:0001", "type": "RoCE v2"},
                     {"index": 3, "gid": "0000:0000:0000:0000:0000:ffff:" + gid, "type": gid_type}]}


def lldp(name):
    return {"source": "lldpd", "system_name": name}


FACTS = {
    "host-a.json": {"hostname": "host-a.example.internal", "devices": [
        {"device": "mlx5_0", "ports": [port("ens1f0", "10.0.0.1", "0a00:0001", lldp("leaf-r0"))]},
        {"device": "mlx5_1", "ports": [port("ens1f1", "10.1.0.1", "0a01:0001", lldp("leaf-r1"))]},
        {"device": "mlx5_2", "ports": [port("ens2f0", "10.2.0.1", "0a02:0001", lldp("leaf-r2"), state="1: DOWN")]},
        {"device": "mlx5_3", "ports": [port("ens2f1", "10.3.0.1", "0a03:0001", lldp("leaf-r3"), gid_type="RoCE v1")]},
    ]},
    "host-b.json": {"hostname": "host-b.example.internal", "devices": [
        {"device": "mlx5_0", "ports": [port("ens1f0", "10.0.0.2", "0a00:0002", lldp("leaf-r0"))]},
        {"device": "mlx5_1", "ports": [port("ens1f1", None, "0a01:0002", lldp(None))]},
    ]},
    "host-c.json": {"hostname": "host-c", "devices": [
        {"device": "mlx5_0", "ports": [port("ens1f0", "10.0.0.3", "0a00:0003")]},
    ]},
}


class MainTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.facts = []
        for name, facts in sorted(FACTS.items()):
            path = os.path.join(d.name, name)
            with open(path, "w") as f:
                json.dump(facts, f)
            self.facts.append(path)
        self.groups = os.path.join(d.name, "groups.csv")
        with open(self.groups, "w") as f:
            f.write("# hostname,group\nhost-a.example.internal,su1\nhost-b, su1\n")

    def run_main(self, *args, status=None):
        out, err = io.StringIO(), io.StringIO()
        old = sys.argv
        sys.argv = ["build_device_tor_map.py", *args, *self.facts]
        code = None
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                tormap.main()
        except SystemExit as e:
            code = e.code
        finally:
            sys.argv = old
        self.assertEqual(code, status, err.getvalue())
        return out.getvalue(), err.getvalue()

    def test_lldp(self):
        out, err = self.run_main("--strategy", "lldp")
        self.assertEqual(out, '# --- host-a.example.internal ---\ndevice_tor_ids:\n'
                              '  mlx5_0: "leaf-r0"\n  mlx5_1: "leaf-r1"\n'
                              '# --- host-b.example.internal ---\ndevice_tor_ids:\n  mlx5_0: "leaf-r0"\n')
        self.assertEqual(err, "2 ToRs, 3 RNICs on 2 hosts\n"
                              "  leaf-r0: 2 RNICs\n"
                              "  leaf-r1: 1 RNICs\n"
                              "WARNING: host-b.example.internal/mlx5_1: no LLDP neighbor (lldpd)\n"
                              "WARNING: host-c/mlx5_0: no LLDP neighbor (None)\n"
                              "WARNING: ToR leaf-r1: only one RNIC (host-a/mlx5_1); its ToR-mesh will be empty\n")

    def test_devices_filter(self):
        out, err = self.run_main("--strategy", "lldp", "--devices", "mlx5_1,mlx5_3")
        self.assertEqual(out, '# --- host-a.example.internal ---\ndevice_tor_ids:\n  mlx5_1: "leaf-r1"\n')
        self.assertEqual(err, "1 ToRs, 1 RNICs on 1 hosts\n"
                              "  leaf-r1: 1 RNICs\n"
                              "WARNING: host-b.example.internal/mlx5_1: no LLDP neighbor (lldpd)\n"
                              "WARNING: ToR leaf-r1: only one RNIC (host-a/mlx5_1); its ToR-mesh will be empty\n")

    def test_subnet_json(self):
        out, err = self.run_main("--strategy", "subnet", "--prefixlen", "16", "--format", "json")
        self.assertEqual(out, json.dumps({
            "host-a.example.internal": {"mlx5_0": "10.0.0.0/16", "mlx5_1": "10.1.0.0/16"},
            "host-b.example.internal": {"mlx5_0": "10.0.0.0/16"},
            "host-c": {"mlx5_0": "10.0.0.0/16"},
        }, indent=1) + "\n")
        self.assertEqual(err, "2 ToRs, 4 RNICs on 3 hosts\n"
                              "  10.0.0.0/16: 3 RNICs\n"
                              "  10.1.0.0/16: 1 RNICs\n"
                              "WARNING: host-b.example.internal/mlx5_1: no IPv4 address on ens1f1\n"
                              "WARNING: ToR 10.1.0.0/16: only one RNIC (host-a/mlx5_1); its ToR-mesh will be empty\n")

    def test_subnet_several_rnics_of_one_host(self):
        out, err = self.run_main("--strategy", "subnet", "--prefixlen", "8")
        self.assertEqual(out, '# --- host-a.example.internal ---\ndevice_tor_ids:\n'
                              '  mlx5_0: "10.0.0.0/8"\n  mlx5_1: "10.0.0.0/8"\n'
                              '# --- host-b.example.internal ---\ndevice_tor_ids:\n  mlx5_0: "10.0.0.0/8"\n'
                              '# --- host-c ---\ndevice_tor_ids:\n  mlx5_0: "10.0.0.0/8"\n')
        self.assertEqual(err, "1 ToRs, 4 RNICs on 3 hosts\n"
                              "  10.0.0.0/8: 4 RNICs\n"
                              "WARNING: host-b.example.internal/mlx5_1: no IPv4 address on ens1f1\n"
                              "WARNING: ToR 10.0.0.0/8: several RNICs of the same host (host-a)\n")

    def test_group_rail_subnet(self):
        out, err = self.run_main("--strategy", "group-rail", "--host-groups", self.groups, "--rail-prefixlen", "16")
        self.assertEqual(out, '# --- host-a.example.internal ---\ndevice_tor_ids:\n'
                              '  mlx5_0: "su1-10.0.0.0/16"\n  mlx5_1: "su1-10.1.0.0/16"\n'
                              '# --- host-b.example.internal ---\ndevice_tor_ids:\n  mlx5_0: "su1-10.0.0.0/16"\n')
        self.assertEqual(err, "2 ToRs, 3 RNICs on 2 hosts\n"
                              "  su1-10.0.0.0/16: 2 RNICs\n"
                              "  su1-10.1.0.0/16: 1 RNICs\n"
                              "WARNING: host-b.example.internal/mlx5_1: no IPv4 address on ens1f1\n"
                              "WARNING: host-c: not in --host-groups\n"
                              "WARNING: ToR su1-10.1.0.0/16: only one RNIC (host-a/mlx5_1); its ToR-mesh will be empty\n")

    def test_group_rail_device_json(self):
        out, err = self.run_main("--strategy", "group-rail", "--host-groups", self.groups,
                                 "--rail-key", "device", "--format", "json")
        self.assertEqual(json.loads(out), {
            "host-a.example.internal": {"mlx5_0": "su1-mlx5_0", "mlx5_1": "su1-mlx5_1"},
            "host-b.example.internal": {"mlx5_0": "su1-mlx5_0", "mlx5_1": "su1-mlx5_1"},
        })
        self.assertEqual(err, "2 ToRs, 4 RNICs on 2 hosts\n"
                              "  su1-mlx5_0: 2 RNICs\n"
                              "  su1-mlx5_1: 2 RNICs\n"
                              "WARNING: host-c: not in --host-groups\n")

    def test_missing_strategy_arguments(self):
        for args, message in ((["--strategy", "group-rail"], "--host-groups is required for group-rail"),
                              (["--strategy", "subnet"], "--prefixlen is required for subnet"),
                              (["--strategy", "subnet", "--prefixlen", "0"], "--prefixlen is required for subnet")):
            out, err = self.run_main(*args, status=2)
            self.assertEqual(out, "")
            self.assertTrue(err.endswith(f"error: {message}\n"), err)


if __name__ == "__main__":
    unittest.main()
