#!/usr/bin/env python3
"""Fixture-based tests for rtt_tor_check.py.

testdata/agent-journal.jsonl mimics `journalctl -u rpingmesh-agent -o cat`
from an agent running with log_format: json and log_level: debug. Its
"Probe result recorded" records have exactly the keys the agent emits; the Go
test internal/telemetry/probe_log_json_test.go fails if they drift apart.

Run with: python3 -m unittest discover -s scripts/topology -p 'test_*.py'
"""

import contextlib
import glob
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(HERE, "testdata")
JOURNAL = os.path.join(TESTDATA, "agent-journal.jsonl")
FACTS = sorted(glob.glob(os.path.join(TESTDATA, "facts-*.json")))
MAPPING = os.path.join(TESTDATA, "mapping.json")

_spec = importlib.util.spec_from_file_location("rtt_tor_check", os.path.join(HERE, "rtt_tor_check.py"))
rtt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rtt)


def gid(last):
    return rtt.norm_gid("::ffff:" + last)


class LoadPairRTTsTest(unittest.TestCase):
    def load(self, paths):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            medians = rtt.load_pair_rtts(paths)
        return medians, err.getvalue()

    def test_reads_json_journal(self):
        medians, err = self.load([JOURNAL])
        # 10 probe records: 9 successful, 1 timeout (skipped, not "unusable").
        self.assertIn("10 probe records, 0 unusable, 4 pairs", err)
        self.assertEqual(medians[(gid("10.0.0.1"), gid("10.0.0.2"))], 2000)
        self.assertEqual(medians[(gid("10.1.0.2"), gid("10.1.0.1"))], 2250)
        self.assertEqual(medians[(gid("10.0.0.1"), gid("10.1.0.2"))], 6050)
        self.assertEqual(medians[(gid("10.0.0.2"), gid("10.1.0.1"))], 5900)
        # The failed probe contributes no pair.
        self.assertNotIn((gid("10.1.0.1"), gid("10.0.0.2")), medians)

    def test_ignores_console_format(self):
        # ConsoleWriter output (log_format: console) carries no JSON object,
        # so it yields no records instead of crashing.
        path = os.path.join(self.tmpdir(), "console.log")
        with open(path, "w") as f:
            f.write("7:00AM DBG Probe result recorded component=telemetry "
                    "source_gid=0000:0000:0000:0000:0000:ffff:0a00:0001 success=true t2=1\n")
        medians, err = self.load([path])
        self.assertEqual(medians, {})
        self.assertIn("0 probe records", err)

    def tmpdir(self):
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return d.name


class MainTest(unittest.TestCase):
    def run_main(self, *args, facts=FACTS):
        argv = ["rtt_tor_check.py", "--logs", JOURNAL, "--facts", *facts, *args]
        out, err = io.StringIO(), io.StringIO()
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rtt.main()
        finally:
            sys.argv = old
            self.stderr = err.getvalue()
        return out.getvalue()

    def write_json(self, name, data):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, name)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def host_b_mlx5_0_facts(self):
        with open(FACTS[1]) as f:
            facts = json.load(f)
        facts["devices"] = facts["devices"][:1]
        return self.write_json("facts-host-b0.json", facts)

    def test_mapping_check(self):
        out = self.run_main("--mapping", MAPPING)
        self.assertIn("same-ToR pairs : n=2", out)
        self.assertIn("cross-ToR pairs: n=2", out)
        self.assertIn("contradictions : 0", out)

    def test_clustering(self):
        out = self.run_main("--cluster-threshold-ns", "4000")
        self.assertIn("inferred groups (pairs below 4000 ns linked): 2", out)
        self.assertIn("host-a/mlx5_0, host-b/mlx5_0", out)
        self.assertIn("host-a/mlx5_1, host-b/mlx5_1", out)

    def test_mapping_contradictions(self):
        swapped = self.write_json("swapped.json", {"host-a.example.internal": {"mlx5_0": "leaf-x", "mlx5_1": "leaf-y"},
                                                   "host-b": {"mlx5_0": "leaf-y", "mlx5_1": "leaf-x"}})
        out = self.run_main("--mapping", swapped, "--max-listed", "3")
        self.assertEqual(out, "all pairs: n=4 min=2000 p10=2000 p50=5900 p90=6050 max=6050 ns\n"
                              "threshold: 4075 ns (widest gap)\n"
                              "same-ToR pairs : n=2 min=5900 p10=5900 p50=6050 p90=6050 max=6050 ns\n"
                              "cross-ToR pairs: n=2 min=2000 p10=2000 p50=2250 p90=2250 max=2250 ns\n"
                              "unmapped pairs : 0\n"
                              "contradictions : 4\n"
                              "  cross ToR but fast: host-a/mlx5_0 (leaf-x) -> host-b/mlx5_0 (leaf-y) median 2000 ns\n"
                              "  cross ToR but fast: host-b/mlx5_1 (leaf-x) -> host-a/mlx5_1 (leaf-y) median 2250 ns\n"
                              "  same ToR but slow: host-b/mlx5_0 (leaf-y) -> host-a/mlx5_1 (leaf-y) median 5900 ns\n")

    def test_mapping_unmapped_pairs(self):
        partial = self.write_json("partial.json", {"host-a": {"mlx5_0": "leaf-r0", "mlx5_1": "leaf-r1"},
                                                   "host-b": {"mlx5_0": "leaf-r0"}})
        out = self.run_main("--mapping", partial)
        self.assertIn("same-ToR pairs : n=1 min=2000", out)
        self.assertIn("cross-ToR pairs: n=1 min=5900", out)
        self.assertIn("unmapped pairs : 2\n", out)
        self.assertNotIn("inferred groups", out)

    def test_mapping_and_clustering(self):
        out = self.run_main("--mapping", MAPPING, "--cluster-threshold-ns", "6000", "--max-listed", "1")
        self.assertEqual(out, "all pairs: n=4 min=2000 p10=2000 p50=5900 p90=6050 max=6050 ns\n"
                              "threshold: 6000 ns\n"
                              "same-ToR pairs : n=2 min=2000 p10=2000 p50=2250 p90=2250 max=2250 ns\n"
                              "cross-ToR pairs: n=2 min=5900 p10=5900 p50=6050 p90=6050 max=6050 ns\n"
                              "unmapped pairs : 0\n"
                              "contradictions : 1\n"
                              "  cross ToR but fast: host-b/mlx5_0 (leaf-r0) -> host-a/mlx5_1 (leaf-r1) median 5900 ns\n"
                              "inferred groups (pairs below 6000 ns linked): 1\n"
                              "  4 RNICs, devices {'mlx5_0': 2, 'mlx5_1': 2}: host-a/mlx5_0\n")

    def test_widest_gap_clustering(self):
        # A zero threshold is "unset": the widest gap applies.
        for args in ((), ("--cluster-threshold-ns", "0")):
            out = self.run_main(*args)
            self.assertEqual(out, "all pairs: n=4 min=2000 p10=2000 p50=5900 p90=6050 max=6050 ns\n"
                                  "threshold: 4075 ns (widest gap)\n"
                                  "inferred groups (pairs below 4075 ns linked): 2\n"
                                  "  2 RNICs, devices {'mlx5_0': 2}: host-a/mlx5_0, host-b/mlx5_0\n"
                                  "  2 RNICs, devices {'mlx5_1': 2}: host-a/mlx5_1, host-b/mlx5_1\n")

    def test_unknown_gids(self):
        out = self.run_main(facts=[FACTS[0], self.host_b_mlx5_0_facts()])
        self.assertIn("WARNING: 1 GIDs not found in the facts files\n", self.stderr)
        self.assertIn("all pairs: n=2 min=2000", out)
        self.assertIn("threshold: 3950 ns (widest gap)\n", out)
        self.assertIn("  1 RNICs, devices {'mlx5_1': 1}: host-a/mlx5_1\n", out)

    def test_no_usable_pairs(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_main(facts=[FACTS[0]])
        self.assertEqual(raised.exception.code, "no usable pairs")
        self.assertIn("WARNING: 2 GIDs not found in the facts files\n", self.stderr)


if __name__ == "__main__":
    unittest.main()
