#!/usr/bin/env python3
"""Fixture-based tests for collect_qos_facts.py and summarize_qos_facts.py.

testdata/qos/ holds hand-written tool output in the documented formats:
mlnx_qos text as printed by mlnx-tools' python/mlnx_qos (pretty_print), dcb
JSON as printed by iproute2 dcb/dcb_{apptrust,app,pfc}.c, the MLNX_OFED
traffic_class sysfs file and `ethtool -S` per-priority counters (mlx5 naming,
see the kernel's mlx5 counters.rst). The qos-host-*.json files are collector
output for invented hosts.

Run with: python3 -m unittest discover -s scripts/topology -p 'test_*.py'
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(HERE, "testdata", "qos")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


qos = load("collect_qos_facts")
summ = load("summarize_qos_facts")


def fixture(name):
    with open(os.path.join(TESTDATA, name)) as f:
        return f.read()


def hosts(*names):
    return [os.path.join(TESTDATA, n) for n in names]


class ParserTest(unittest.TestCase):
    def test_mlnx_qos_trust_dscp(self):
        res = qos.parse_mlnx_qos(fixture("mlnx_qos-trust-dscp.txt"))
        self.assertEqual(res["trust"], "dscp")
        self.assertEqual(res["pfc_enabled"], [3])
        self.assertEqual(len(res["dscp_prio"]), 64)
        self.assertEqual(res["dscp_prio"]["26"], 3)
        self.assertEqual(res["dscp_prio"]["0"], 0)
        self.assertEqual(res["dscp_prio"]["63"], 7)

    def test_mlnx_qos_trust_pcp_has_no_dscp_map(self):
        res = qos.parse_mlnx_qos(fixture("mlnx_qos-trust-pcp.txt"))
        self.assertEqual(res["trust"], "pcp")
        self.assertIsNone(res["dscp_prio"])
        self.assertEqual(res["pfc_enabled"], [3])

    def test_mlnx_qos_wrapped_dscp_lines(self):
        # mlnx_qos wraps a priority's DSCP list every 8 entries.
        text = ("Priority trust state: dscp\ndscp2prio mapping:\n"
                "\tprio:0 dscp:00,01,02,03,04,05,06,07,\n"
                "\tprio:0 dscp:08,09,\n"
                "\tprio:3 dscp:26,\n"
                "Cable len: 7\n")
        res = qos.parse_mlnx_qos(text)
        self.assertEqual(res["dscp_prio"], {**{str(d): 0 for d in range(10)}, "26": 3})
        self.assertIsNone(res["pfc_enabled"])

    def test_mlnx_qos_garbage(self):
        self.assertEqual(qos.parse_mlnx_qos("error: no such device\n"),
                         {"trust": None, "dscp_prio": None, "pfc_enabled": None})
        self.assertEqual(qos.parse_mlnx_qos(None)["trust"], None)

    def test_dcb_apptrust(self):
        self.assertEqual(qos.parse_dcb_apptrust(fixture("dcb-apptrust-order.json")),
                         ("dscp", ["dscp", "pcp"]))
        self.assertEqual(qos.parse_dcb_apptrust('{"order":["pcp"]}'), ("pcp", ["pcp"]))
        self.assertEqual(qos.parse_dcb_apptrust('{"order":[]}'), (None, []))
        self.assertEqual(qos.parse_dcb_apptrust("not json"), (None, None))

    def test_dcb_app_dscp_prio(self):
        res = qos.parse_dcb_app_dscp(fixture("dcb-app-dscp-prio.json"))
        self.assertEqual(res["26"], 3)
        self.assertEqual(res["46"], 5)
        self.assertEqual(len(res), 9)
        # No DSCP entries: iproute2 prints an empty object.
        self.assertEqual(qos.parse_dcb_app_dscp("{}"), {})
        self.assertIsNone(qos.parse_dcb_app_dscp(""))

    def test_dcb_pfc(self):
        self.assertEqual(qos.parse_dcb_pfc(fixture("dcb-pfc-prio-pfc.json")), [3])
        self.assertEqual(qos.parse_dcb_pfc('{"prio_pfc":["off","on",0,1]}'), [1, 3])
        self.assertIsNone(qos.parse_dcb_pfc('{"pfc_cap":8}'))

    def test_tc_override(self):
        self.assertEqual(qos.parse_tc_override(fixture("tc-traffic_class.txt")), 106)
        self.assertEqual(qos.parse_tc_override("tclass=104\n"), 104)
        self.assertIsNone(qos.parse_tc_override(""))
        self.assertIsNone(qos.parse_tc_override("Global tclass not set\n"))

    def test_ethtool_counters_and_deltas(self):
        before, lines = qos.parse_ethtool_prio(fixture("ethtool-S-before.txt"))
        after, _ = qos.parse_ethtool_prio(fixture("ethtool-S-after.txt"))
        self.assertIn("rx_prio3_pause", before)
        self.assertNotIn("rx_bytes", before)                 # not per-priority
        self.assertNotIn("rx_prio0_discards", before)        # not collected
        self.assertNotIn("rx_prio3_pause_transition", before)
        self.assertIn("rx_prio3_bytes: 400000000", lines)
        d = qos.counter_deltas(before, after, 5)
        self.assertEqual(d["interval_s"], 5)
        self.assertEqual(d["prio"]["3"]["rx_bytes"], 300000000)
        self.assertEqual(d["prio"]["3"]["tx_bytes"], 300000000)
        self.assertEqual(d["prio"]["3"]["rx_pause"], 2)
        self.assertEqual(d["prio"]["3"]["tx_pause"], 0)
        self.assertEqual(d["prio"]["0"]["rx_bytes"], 100000)
        # A counter that went backwards (reset) is not reported as a delta.
        self.assertIsNone(qos.counter_deltas({"rx_prio1_bytes": 9},
                                             {"rx_prio1_bytes": 1}, 5)["prio"]["1"]["rx_bytes"])


class CollectTest(unittest.TestCase):
    """collect() over a fake sysfs tree with stubbed tools."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.sys_ib = d.name
        for dev, nd, tc in (("mlx5_0", "eth0", "Global tclass=106\n"), ("mlx5_1", "eth1", None)):
            port = os.path.join(self.sys_ib, dev, "ports", "1")
            for sub in ("gids", "gid_attrs/types", "gid_attrs/ndevs"):
                os.makedirs(os.path.join(port, sub))
            self.write(port, "state", "4: ACTIVE")
            self.write(port, "link_layer", "Ethernet")
            for idx, gid, typ in (("0", "fe80:0000:0000:0000:0000:0000:0000:0001", "IB/RoCE v1"),
                                  ("3", "0000:0000:0000:0000:0000:ffff:0a00:0001", "RoCE v2")):
                self.write(port, f"gids/{idx}", gid)
                self.write(port, f"gid_attrs/types/{idx}", typ)
                self.write(port, f"gid_attrs/ndevs/{idx}", nd)
            if tc is not None:
                os.makedirs(os.path.join(self.sys_ib, dev, "tc", "1"))
                self.write(os.path.join(self.sys_ib, dev, "tc", "1"), "traffic_class", tc)

    def write(self, base, rel, text):
        with open(os.path.join(base, rel), "w") as f:
            f.write(text)

    def run_collect(self, outputs, interval):
        calls = {}

        def fake_probe(cmd, timeout=10):
            key = " ".join(cmd)
            calls[key] = calls.get(key, 0) + 1
            out = outputs.get(cmd[0])
            if callable(out):
                out = out(cmd, calls[key])
            if out is None:
                return {"cmd": key, "status": "unavailable", "stdout": None}
            return {"cmd": key, "status": "ok", "stdout": out}

        with mock.patch.object(qos.rnic, "SYS_IB", self.sys_ib), \
                mock.patch.object(qos, "probe", fake_probe), \
                mock.patch.object(qos.time, "sleep", lambda s: None), \
                mock.patch.object(qos.rnic, "read", self.read_no_net(qos.rnic.read)):
            return qos.collect(interval)

    @staticmethod
    def read_no_net(real):
        # Keep the host's own /sys/class/net out of the test.
        return lambda path: None if path.startswith("/sys/class/net/") else real(path)

    def test_mlnx_qos_with_counters(self):
        ethtool = lambda cmd, n: fixture("ethtool-S-before.txt" if n == 1 else "ethtool-S-after.txt")
        facts = self.run_collect({"mlnx_qos": fixture("mlnx_qos-trust-dscp.txt"),
                                  "ethtool": ethtool}, interval=5)
        ports = {d["device"]: d["ports"][0] for d in facts["devices"]}
        p0 = ports["mlx5_0"]
        self.assertEqual(p0["netdev"], "eth0")
        self.assertEqual([g["index"] for g in p0["rocev2_gids"]], [3])
        self.assertEqual(p0["tc_override"], {"status": "set", "raw": "Global tclass=106", "tclass": 106})
        self.assertEqual(p0["qos"]["trust"], "dscp")
        self.assertEqual(p0["qos"]["pfc_enabled"], [3])
        self.assertEqual(p0["qos"]["sources"]["trust"], "mlnx_qos")
        self.assertIn("Priority trust state: dscp", p0["qos"]["raw"]["mlnx_qos"]["stdout"])
        self.assertNotIn("dcb_app", p0["qos"]["raw"])   # mlnx_qos answered everything
        self.assertEqual(p0["counters"]["prio"]["3"]["rx_bytes"], 300000000)
        self.assertEqual(ports["mlx5_1"]["tc_override"]["status"], "absent")

    def test_dcb_fallback(self):
        def dcb(cmd, n):
            return {"apptrust": fixture("dcb-apptrust-order.json"),
                    "app": fixture("dcb-app-dscp-prio.json"),
                    "pfc": fixture("dcb-pfc-prio-pfc.json")}[cmd[2]]
        facts = self.run_collect({"dcb": dcb}, interval=0)
        q = facts["devices"][0]["ports"][0]["qos"]
        self.assertEqual(q["raw"]["mlnx_qos"]["status"], "unavailable")
        self.assertEqual((q["trust"], q["pfc_enabled"], q["dscp_prio"]["26"]), ("dscp", [3], 3))
        self.assertEqual(set(q["sources"].values()), {"dcb"})
        self.assertEqual(facts["devices"][0]["ports"][0]["counters"], {"status": "skipped"})

    def test_no_tools(self):
        facts = self.run_collect({}, interval=1)
        p = facts["devices"][0]["ports"][0]
        self.assertEqual(p["qos"]["trust"], None)
        self.assertEqual(p["counters"]["status"], "unavailable")
        json.dumps(facts)  # serializable

    def test_main_without_rdma(self):
        out = io.StringIO()
        with mock.patch.object(qos.rnic, "SYS_IB", os.path.join(self.sys_ib, "missing")), \
                contextlib.redirect_stdout(out):
            qos.main(["--interval", "0"])
        self.assertEqual(json.loads(out.getvalue())["devices"], [])


class SummarizeTest(unittest.TestCase):
    def summarize(self, *names):
        return summ.summarize(summ.load_ports(hosts(*names)))

    def render(self, *names, json_out=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            summ.main(hosts(*names) + (["--json"] if json_out else []))
        return out.getvalue()

    def test_consistent_fleet(self):
        s = self.summarize("qos-host-a.json", "qos-host-b.json")
        self.assertEqual((s["hosts"], s["ports"]), (2, 4))
        for k in ("trust", "pfc_enabled", "dscp_map", "override", "rocev2_gid_indices"):
            self.assertEqual(s[k]["outliers"], [], k)
        self.assertEqual(s["lossless_priorities"], [3])
        self.assertEqual(s["lossless_dscps"][3], list(range(24, 32)))
        tcs = [c["traffic_class"] for c in s["candidates"]]
        self.assertEqual(tcs[0], 106)                      # override first, verbatim
        self.assertEqual(s["candidates"][0]["ecn"], "ECT(0)")
        self.assertIn(104, tcs)                            # DSCP 26 << 2
        self.assertEqual(s["service_level"]["candidates"], [0])
        self.assertEqual(s["traffic"]["top_priority"], 3)
        self.assertEqual(s["traffic"]["ports_busiest_elsewhere"], [])
        text = self.render("qos-host-a.json", "qos-host-b.json")
        self.assertIn("priority 3: DSCP 24-31", text)
        self.assertIn("include all traffic in a priority, not only RoCE", text)

    def test_outlier_device_missing_override(self):
        s = self.summarize("qos-host-a.json", "qos-host-b.json", "qos-host-c-no-override.json")
        self.assertEqual(s["override"]["majority"], 106)
        self.assertEqual(s["override"]["outliers"], [("host-c/mlx5_1:1", None)])
        self.assertEqual(s["trust"]["outliers"], [])
        self.assertEqual(s["traffic"]["ports_busiest_elsewhere"],
                         [{"port": "host-c/mlx5_1:1", "priority": 0}])
        text = self.render("qos-host-a.json", "qos-host-b.json", "qos-host-c-no-override.json")
        self.assertIn("outlier host-c/mlx5_1:1: not set", text)
        data = json.loads(self.render("qos-host-a.json", "qos-host-b.json",
                                      "qos-host-c-no-override.json", json_out=True))
        self.assertEqual(data["override"]["outliers"], [{"port": "host-c/mlx5_1:1", "value": None}])

    def test_trust_pcp(self):
        s = self.summarize("qos-host-p-trust-pcp.json")
        self.assertEqual(s["trust"]["majority"], "pcp")
        self.assertEqual(s["candidates"], [])
        self.assertEqual(s["service_level"]["candidates"], [3])
        self.assertIn("trust pcp", self.render("qos-host-p-trust-pcp.json"))

    def test_trust_outlier_in_mixed_fleet(self):
        s = self.summarize("qos-host-a.json", "qos-host-b.json", "qos-host-p-trust-pcp.json")
        self.assertEqual(s["trust"]["majority"], "dscp")
        self.assertEqual(sorted(pid for pid, _ in s["trust"]["outliers"]),
                         ["host-p/mlx5_0:1", "host-p/mlx5_1:1"])
        self.assertEqual(sorted(s["dscp_map"]["unknown"]), ["host-p/mlx5_0:1", "host-p/mlx5_1:1"])

    def test_render_mixed_fleet(self):
        self.assertEqual(self.render("qos-host-a.json", "qos-host-b.json", "qos-host-c-no-override.json",
                                     "qos-host-p-trust-pcp.json"), """\
4 hosts, 8 RDMA ports with a netdev

Consistency (majority / outliers):
  trust mode      : dscp  (6/8 ports, 2 differ)
      outlier host-p/mlx5_0:1: pcp
      outlier host-p/mlx5_1:1: pcp
  PFC priorities  : 3  (8/8 ports, consistent)
  DSCP->prio map  : p0:0-7 p1:8-15 p2:16-23 p3:24-31 p4:32-39 p5:40-47 p6:48-55 p7:56-63  \
(6/6 ports, consistent, 2 unknown)
      unknown: host-p/mlx5_0:1, host-p/mlx5_1:1
  tclass override : 106  (5/8 ports, 3 differ)
      outlier host-c/mlx5_1:1: not set
      outlier host-p/mlx5_0:1: not set
      outlier host-p/mlx5_1:1: not set
  RoCE v2 GID idx : 3  (8/8 ports, consistent)

PFC-enabled priorities and the DSCPs mapping to them:
  priority 3: DSCP 24-31

Candidate traffic_class values (suggestions, not a decision):
  106  DSCP 26 ECT(0)  -> priority 3 (PFC on)  [NIC override on 5 port(s)]
   96  DSCP 24 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  100  DSCP 25 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  104  DSCP 26 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  108  DSCP 27 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  112  DSCP 28 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  116  DSCP 29 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  120  DSCP 30 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  124  DSCP 31 Not-ECT -> priority 3 (PFC on)  [DSCP << 2]
  The low 2 bits are ECN: DSCP<<2 is Not-ECT, +2 is ECT(0). Prefer the value the
  workload emits (e.g. an override verbatim) and verify the ECN on the wire.
service_level: 0 (trust dscp: SL does not select the queue)

Traffic over 5 s on 8 ports (rx+tx bytes, pause frames):
  priority 0:        501050000 bytes ( 11.0%)  pause 0
  priority 3:       4050000000 bytes ( 89.0%)  pause 12
  most bytes: priority 3 (busiest priority per port: p0: 1, p3: 7)
      host-c/mlx5_1:1: most bytes in priority 0
  These counters include all traffic in a priority, not only RoCE; pause
  counters move only under congestion, so zero does not prove a priority is unused.
""")

    def test_render_trust_pcp_without_dscp_map(self):
        text = self.render("qos-host-p-trust-pcp.json")
        self.assertIn("  DSCP->prio map  : unknown  (0/0 ports, no data, 2 unknown)\n"
                      "      unknown: host-p/mlx5_0:1, host-p/mlx5_1:1\n", text)
        self.assertIn("  priority 3: DSCP (none in the DSCP map)\n"
                      "  (trust pcp: the queue is selected by the VLAN PCP, not by DSCP)\n", text)
        self.assertIn("  none: no override and no DSCP mapping to a PFC-enabled priority\n", text)

    @staticmethod
    def sparse_ports(n, counters):
        """Ports without trust, PFC or GID data, alternating DSCP maps and
        overrides that map to a non-PFC priority (4) or to no priority (200)."""
        return [{"id": f"host-{i}/mlx5_0:1", "host": f"host-{i}", "netdev": "eth0", "trust": None, "pfc": (),
                 "dscp_prio": {0: 0, 1: 1} if i % 2 else None, "override": (4, 200, None)[i % 3],
                 "override_status": None, "counters": counters(i), "interval_s": 2 if i % 2 else 2.5,
                 "gid_indices": ()} for i in range(n)]

    def render_summary(self, ports):
        out = io.StringIO()
        summ.render(summ.summarize(ports), out)
        return out.getvalue()

    def test_render_without_pfc_or_traffic(self):
        # Counters with pause frames but no bytes: no priority carries the most bytes.
        def counters(i):
            if i % 4 == 3:
                return None
            return {"0": {"rx_bytes": 0, "tx_bytes": 0}, "5": {"rx_pause": i, "tx_pause": None}, "6": {}}
        text = self.render_summary(self.sparse_ports(12, counters))
        self.assertIn("  trust mode      : unknown  (0/0 ports, no data, 12 unknown)\n"
                      "  PFC priorities  : none  (12/12 ports, consistent)\n", text)
        self.assertIn("  RoCE v2 GID idx : unknown  (0/0 ports, no data, 12 unknown)\n\n", text)
        self.assertIn("\nNo PFC-enabled priority found (or PFC state unavailable).\n\n", text)
        self.assertIn("    4  DSCP  1 Not-ECT -> priority 1 (PFC OFF)  [NIC override on 4 port(s)]\n"
                      "  200  DSCP 50 Not-ECT -> priority ? (PFC ?)  [NIC override on 4 port(s)]\n", text)
        self.assertIn("service_level: ? (trust mode unknown)\n\n", text)
        self.assertIn("Traffic over 2/2.5 s on 9 ports (rx+tx bytes, pause frames):\n"
                      "  priority 5:                0 bytes (  0.0%)  pause 45\n"
                      "  These counters include", text)
        self.assertNotIn("most bytes", text)

    def test_render_busiest_priority_per_port(self):
        def counters(i):
            return {"0": {"rx_bytes": 10 * i, "tx_bytes": None}, "2": {"rx_bytes": 30, "tx_bytes": 5, "rx_pause": 1}}
        text = self.render_summary(self.sparse_ports(7, counters))
        self.assertIn("  priority 0:              210 bytes ( 46.2%)  pause 0\n"
                      "  priority 2:              245 bytes ( 53.8%)  pause 7\n"
                      "  most bytes: priority 2 (busiest priority per port: p0: 3, p2: 4)\n"
                      "      host-4/mlx5_0:1: most bytes in priority 0\n"
                      "      host-5/mlx5_0:1: most bytes in priority 0\n"
                      "      host-6/mlx5_0:1: most bytes in priority 0\n", text)

    def test_render_without_counters_or_ports(self):
        text = self.render_summary(self.sparse_ports(3, lambda i: None))
        self.assertIn("Traffic: no per-priority counter deltas (collected with --interval 0, "
                      "or ethtool unavailable).\n", text)
        self.assertTrue(self.render_summary([]).startswith(
            "0 hosts, 0 RDMA ports with a netdev\n\n"
            "Consistency (majority / outliers):\n"
            "  trust mode      : unknown  (0/0 ports, no data)\n"))


if __name__ == "__main__":
    unittest.main()
