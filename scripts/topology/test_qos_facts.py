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
            if isinstance(out, dict):  # a whole probe record, e.g. a failure
                return {"cmd": key, **out}
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

    def add_port(self, dev, port, ndev=None):
        """A port directory with one RoCE v2 GID; ndev names the GID's netdev."""
        base = os.path.join(self.sys_ib, dev, "ports", port)
        for sub in ("gids", "gid_attrs/types", "gid_attrs/ndevs"):
            os.makedirs(os.path.join(base, sub), exist_ok=True)
        self.write(base, "state", "4: ACTIVE")
        self.write(base, "link_layer", "Ethernet")
        self.write(base, "gids/1", "0000:0000:0000:0000:0000:ffff:0a00:0101")
        self.write(base, "gid_attrs/types/1", "RoCE v2")
        if ndev:
            self.write(base, "gid_attrs/ndevs/0", ndev)

    def collect_tree(self, interval, ethtool):
        """collect() over an edge-case tree with netdev_qos stubbed out."""
        self.add_port("mlx5_0", "2", "eth0")     # shares eth0 with port 1
        self.add_port("mlx5_0", "10")            # no netdev; sorts after 2
        os.makedirs(os.path.join(self.sys_ib, "mlx5_2", "ports", "x"))  # unsortable ports
        os.makedirs(os.path.join(self.sys_ib, "mlx5_3"))                 # no ports directory
        self.add_port("mlx5_4", "1")
        for nd in ("eth4b", "eth4a"):            # netdev from the PCI function's net/
            os.makedirs(os.path.join(self.sys_ib, "mlx5_4", "device", "net", nd))
        self.write(self.sys_ib, "README", "")    # a file, not a device
        qos_calls = []

        def fake_qos(nd):
            qos_calls.append(nd)
            return {"netdev": nd}

        gmtime = qos.time.struct_time((2026, 2, 3, 4, 5, 6, 1, 34, 0))
        with mock.patch.object(qos, "netdev_qos", fake_qos), \
                mock.patch.object(qos.socket, "gethostname", lambda: "node-1"), \
                mock.patch.object(qos.time, "gmtime", lambda: gmtime), \
                mock.patch.object(qos.shutil, "which", lambda t: "/usr/sbin/dcb" if t == "dcb" else None):
            facts = self.run_collect({"ethtool": ethtool}, interval)
        return facts, qos_calls

    @staticmethod
    def ethtool_lines(*lines):
        return "NIC statistics:\n" + "".join(f"     {line}\n" for line in lines)

    def expected_ports(self, counters):
        gid = {"index": 1, "gid": "0000:0000:0000:0000:0000:ffff:0a00:0101", "type": "RoCE v2", "ndev": None}
        tc_absent = {"status": "absent", "raw": None, "tclass": None}

        def entry(port, nd, gids, tc=tc_absent):
            return {"port": port, "state": "4: ACTIVE", "link_layer": "Ethernet", "netdev": nd, "rocev2_gids": gids,
                    "tc_override": tc, "qos": {"netdev": nd} if nd else None, "counters": counters(nd)}

        v2 = [{"index": 3, "gid": "0000:0000:0000:0000:0000:ffff:0a00:0001", "type": "RoCE v2", "ndev": "eth0"}]
        return [
            {"device": "mlx5_0", "ports": [
                entry(1, "eth0", v2, {"status": "set", "raw": "Global tclass=106", "tclass": 106}),
                entry(2, "eth0", [gid]),
                entry(10, None, [gid]),
            ]},
            {"device": "mlx5_1", "ports": [entry(1, "eth1", [dict(v2[0], ndev="eth1")])]},
            {"device": "mlx5_4", "ports": [entry(1, "eth4a", [gid])]},
        ]

    def test_collect_tree_with_counter_failures(self):
        before = self.ethtool_lines("rx_prio3_bytes: 100", "tx_prio3_bytes: 50", "rx_prio3_pause: 7")
        after = self.ethtool_lines("rx_prio3_bytes: 160", "tx_prio3_bytes: 40", "rx_prio5_bytes: 9")

        def ethtool(cmd, n):
            nd = cmd[2]
            if nd == "eth0":
                return before if n == 1 else after
            if nd == "eth1":
                return self.ethtool_lines("rx_bytes: 1")  # no per-priority counters
            return before if n == 1 else {"status": "failed", "stdout": "", "stderr": "boom"}

        facts, qos_calls = self.collect_tree(5, ethtool)
        lines = {"before": ["rx_prio3_bytes: 100", "tx_prio3_bytes: 50", "rx_prio3_pause: 7"],
                 "after": ["rx_prio3_bytes: 160", "tx_prio3_bytes: 40", "rx_prio5_bytes: 9"]}
        counters = {
            "eth0": {"interval_s": 5, "prio": {"3": {"rx_bytes": 60, "tx_bytes": None}}, "status": "ok", "raw": lines},
            "eth1": {"status": "no_prio_counters", "interval_s": 5, "prio": None, "raw": {"before": [], "after": []}},
            "eth4a": {"status": "failed", "interval_s": 5, "prio": None, "raw": {"before": lines["before"], "after": []}},
            None: None,
        }
        self.assertEqual(facts, {
            "hostname": "node-1",
            "collected_at": "2026-02-03T04:05:06Z",
            "tools": {"mlnx_qos": False, "dcb": True, "ethtool": False},
            "devices": self.expected_ports(counters.get),
        })
        self.assertEqual(qos_calls, ["eth0", "eth1", "eth4a"])

    def test_collect_tree_without_sampling(self):
        def ethtool(cmd, n):
            raise AssertionError("sampled counters with --interval 0")

        facts, qos_calls = self.collect_tree(0, ethtool)
        self.assertEqual(facts["devices"], self.expected_ports(lambda nd: {"status": "skipped"}))
        self.assertEqual(qos_calls, ["eth0", "eth1", "eth4a"])

    def test_main_without_rdma(self):
        out = io.StringIO()
        with mock.patch.object(qos.rnic, "SYS_IB", os.path.join(self.sys_ib, "missing")), \
                contextlib.redirect_stdout(out):
            qos.main(["--interval", "0"])
        self.assertEqual(json.loads(out.getvalue())["devices"], [])


class LoadPortsTest(unittest.TestCase):
    def write_facts(self, *docs):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        paths = []
        for i, doc in enumerate(docs):
            paths.append(os.path.join(d.name, f"qos-{i}.json"))
            with open(paths[-1], "w") as f:
                f.write(doc if isinstance(doc, str) else json.dumps(doc))
        return paths

    def test_records_and_defaults(self):
        full = {"port": 1, "netdev": "eth0",
                "qos": {"trust": "dscp", "pfc_enabled": [5, 3], "dscp_prio": {"26": 3, "0": "0"}},
                "tc_override": {"tclass": 106, "status": "set"},
                "counters": {"status": "ok", "prio": {"3": {"rx_bytes": 1}}, "interval_s": 5},
                "rocev2_gids": [{"index": 7}, {"index": 3}]}
        paths = self.write_facts(
            {"hostname": "node-1.example.test", "devices": [
                {"device": "mlx5_0", "ports": [
                    full,
                    {"port": 2, "netdev": None, "qos": {"trust": "pcp"}},
                    {"port": 3, "netdev": ""},
                    {"port": 4, "netdev": "eth4", "qos": None, "tc_override": None, "rocev2_gids": None,
                     "counters": {"status": "unavailable", "prio": {"0": {}}, "interval_s": 5}},
                    {"port": 5, "netdev": "eth5", "qos": {"pfc_enabled": [], "dscp_prio": {}}},
                ]},
                {"device": "mlx5_1", "ports": None},
                {"device": "mlx5_2"},
            ]},
            {"devices": None},
            {"hostname": "", "devices": [{"ports": [{"netdev": "eth9"}]}]},
            {},
        )
        empty = {"trust": None, "pfc": None, "dscp_prio": None, "override": None, "override_status": None,
                 "counters": None, "interval_s": None, "gid_indices": ()}
        self.assertEqual(summ.load_ports(paths), [
            {"id": "node-1/mlx5_0:1", "host": "node-1", "netdev": "eth0", "trust": "dscp", "pfc": (3, 5),
             "dscp_prio": {26: 3, 0: 0}, "override": 106, "override_status": "set",
             "counters": {"3": {"rx_bytes": 1}}, "interval_s": 5, "gid_indices": (3, 7)},
            {**empty, "id": "node-1/mlx5_0:4", "host": "node-1", "netdev": "eth4", "interval_s": 5},
            {**empty, "id": "node-1/mlx5_0:5", "host": "node-1", "netdev": "eth5", "pfc": (), "dscp_prio": {}},
            {**empty, "id": "?/None:None", "host": "?", "netdev": "eth9"},
        ])

    def test_malformed_input_raises(self):
        for doc, exc in (("not json", ValueError), ("[]", AttributeError),
                         ({"devices": [{"ports": [{"netdev": "eth0", "rocev2_gids": [{}]}]}]}, KeyError),
                         ({"devices": [{"ports": [{"netdev": "eth0", "qos": {"dscp_prio": {"x": 1}}}]}]}, ValueError),
                         ({"devices": [{"ports": [{"netdev": "eth0", "qos": {"pfc_enabled": 3}}]}]}, TypeError)):
            with self.subTest(doc=doc), self.assertRaises(exc):
                summ.load_ports(self.write_facts(doc))
        with self.assertRaises(FileNotFoundError):
            summ.load_ports([os.path.join(TESTDATA, "missing.json")])


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

    @staticmethod
    def port(i, **fields):
        p = {"id": f"h{i % 3}/mlx5_{i}:1", "host": f"h{i % 3}", "netdev": "eth0", "trust": "dscp", "pfc": (3, 4),
             "dscp_prio": {1: 0, 24: 3, 26: 3, 63: 7}, "override": None, "override_status": None,
             "counters": None, "interval_s": None, "gid_indices": (3,)}
        p.update(fields)
        return p

    def test_summary_candidates_and_tallies(self):
        ports = [self.port(0, override=106), self.port(1, override=104, trust="pcp"), self.port(2, override=106),
                 self.port(3, override=7, pfc=(3,), gid_indices=()), self.port(4, override=255, dscp_prio=None),
                 self.port(5, trust=None, gid_indices=(1, 3), dscp_prio={63: 7, 26: 3, 24: 3, 1: 0}),
                 self.port(6, override=200)]
        dmap = ((1, 0), (24, 3), (26, 3), (63, 7))
        s = summ.summarize(ports)
        self.assertEqual(s.pop("traffic"), {"ports_with_counters": 0, "interval_s": [], "by_priority": {},
                                            "total_bytes": 0, "top_priority": None, "top_priority_per_port": {},
                                            "ports_busiest_elsewhere": []})
        self.assertEqual(s, {
            "hosts": 3, "ports": 7,
            "trust": {"majority": "dscp", "counts": {"dscp": 5, "pcp": 1},
                      "outliers": [("h1/mlx5_1:1", "pcp")], "unknown": ["h2/mlx5_5:1"]},
            "pfc_enabled": {"majority": (3, 4), "counts": {(3, 4): 6, (3,): 1},
                            "outliers": [("h0/mlx5_3:1", (3,))], "unknown": []},
            "dscp_map": {"majority": dmap, "counts": {dmap: 6}, "outliers": [], "unknown": ["h1/mlx5_4:1"]},
            "override": {"majority": 106, "counts": {106: 2, 104: 1, 7: 1, 255: 1, None: 1, 200: 1},
                         "outliers": [("h1/mlx5_1:1", 104), ("h0/mlx5_3:1", 7), ("h1/mlx5_4:1", 255), ("h2/mlx5_5:1", None),
                                      ("h0/mlx5_6:1", 200)],
                         "unknown": []},
            "rocev2_gid_indices": {"majority": (3,), "counts": {(3,): 5, (1, 3): 1},
                                   "outliers": [("h2/mlx5_5:1", (1, 3))], "unknown": ["h0/mlx5_3:1"]},
            "lossless_priorities": [3, 4],
            "lossless_dscps": {3: [24, 26], 4: []},
            "candidates": [
                {"traffic_class": 106, "dscp": 26, "ecn": "ECT(0)", "priority": 3, "pfc_enabled": True,
                 "source": "NIC override on 2 port(s)"},
                {"traffic_class": 104, "dscp": 26, "ecn": "Not-ECT", "priority": 3, "pfc_enabled": True,
                 "source": "NIC override on 1 port(s)"},
                {"traffic_class": 7, "dscp": 1, "ecn": "CE", "priority": 0, "pfc_enabled": False,
                 "source": "NIC override on 1 port(s)"},
                {"traffic_class": 255, "dscp": 63, "ecn": "CE", "priority": 7, "pfc_enabled": False,
                 "source": "NIC override on 1 port(s)"},
                {"traffic_class": 200, "dscp": 50, "ecn": "Not-ECT", "priority": None, "pfc_enabled": None,
                 "source": "NIC override on 1 port(s)"},
                {"traffic_class": 96, "dscp": 24, "ecn": "Not-ECT", "priority": 3, "pfc_enabled": True,
                 "source": "DSCP << 2"},
            ],
            "service_level": {"candidates": [0], "note": "trust dscp: SL does not select the queue"},
        })

    def test_summary_service_level_by_trust(self):
        for trust, sl in (("pcp", {"candidates": [3, 4], "note": "trust pcp: SL maps to the PCP only for VLAN-tagged "
                                   "RoCE; DSCP (traffic_class) does not select the queue"}),
                          ("dscp", {"candidates": [0], "note": "trust dscp: SL does not select the queue"}),
                          ("both", {"candidates": [], "note": "trust mode unknown"}),
                          (None, {"candidates": [], "note": "trust mode unknown"})):
            with self.subTest(trust=trust):
                s = summ.summarize([self.port(0, trust=trust)])
                self.assertEqual(s["service_level"], sl)
        s = summ.summarize([self.port(0, pfc=None, dscp_prio=None)])
        self.assertEqual((s["lossless_priorities"], s["lossless_dscps"], s["candidates"]), ([], {}, []))

    def test_summary_traffic(self):
        ports = [
            # A tie keeps the first priority of the port.
            self.port(0, interval_s=5, counters={"3": {"rx_bytes": 5, "tx_bytes": None, "tx_pause": 2},
                                                 "0": {"rx_bytes": 5}}),
            self.port(1, interval_s=None, counters={"0": {"rx_bytes": 0, "tx_bytes": 0, "rx_pause": 4}}),
            self.port(2, counters={}),  # an empty sample is not a port with counters
            self.port(3, interval_s=2.5, counters={"0": {"tx_bytes": 9}, "5": {"rx_bytes": 1, "rx_pause": None}}),
            self.port(4, interval_s=5, counters={"5": {"rx_bytes": 10}, "3": {"rx_bytes": 10}}),
        ]
        self.assertEqual(summ.summarize(ports)["traffic"], {
            "ports_with_counters": 4,
            "interval_s": [2.5, 5],
            "by_priority": {0: {"bytes": 14, "pause": 4}, 3: {"bytes": 15, "pause": 2}, 5: {"bytes": 11, "pause": 0}},
            "total_bytes": 40,
            "top_priority": 3,
            "top_priority_per_port": {3: 1, 0: 1, 5: 1},
            "ports_busiest_elsewhere": [{"port": "h0/mlx5_3:1", "priority": 0}, {"port": "h1/mlx5_4:1", "priority": 5}],
        })
        # Equal totals: the priority seen first carries the most bytes.
        tie = summ.summarize([self.port(0, counters={"5": {"rx_bytes": 3}}), self.port(1, counters={"2": {"tx_bytes": 3}})])
        self.assertEqual((tie["traffic"]["top_priority"], tie["traffic"]["ports_busiest_elsewhere"]),
                         (5, [{"port": "h1/mlx5_1:1", "priority": 2}]))
        # Pause frames without bytes: no priority carries the most bytes.
        idle = summ.summarize([self.port(0, counters={"4": {"rx_pause": 3, "rx_bytes": 0}})])
        self.assertEqual(idle["traffic"], {"ports_with_counters": 1, "interval_s": [],
                                           "by_priority": {4: {"bytes": 0, "pause": 3}}, "total_bytes": 0,
                                           "top_priority": None, "top_priority_per_port": {},
                                           "ports_busiest_elsewhere": []})

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
