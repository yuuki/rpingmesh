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
import os
import sys
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
    def run_main(self, *args):
        argv = ["rtt_tor_check.py", "--logs", JOURNAL, "--facts", *FACTS, *args]
        out, err = io.StringIO(), io.StringIO()
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rtt.main()
        finally:
            sys.argv = old
        return out.getvalue()

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


if __name__ == "__main__":
    unittest.main()
