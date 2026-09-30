"""End-to-end scans against the on-disk fixtures.

Locks: the adversarial fixture must fire every rule (12/12); the
healthy fixture must fire nothing; sort order must be file, line,
column, rule id.
"""

import io
import json
import os
import unittest

from approvchainlint.rules import all_rule_ids
from approvchainlint.scanner import scan_file
from approvchainlint.types import Options, Severity


HERE = os.path.dirname(__file__)
FIXTURES = os.path.join(HERE, "fixtures")


class TestFullFixtureCoverage(unittest.TestCase):
    def test_weak_fires_every_rule(self):
        weak = os.path.join(FIXTURES, "weak_config.json")
        findings, errs = scan_file(weak, Options(include_info=True))
        self.assertEqual(errs, [])
        got_ids = set(f.rule_id for f in findings)
        expected_ids = set(all_rule_ids())
        missing = expected_ids - got_ids
        self.assertEqual(missing, set(),
                         f"missing rules on adversarial fixture: {sorted(missing)}")

    def test_weak_severity_counts(self):
        weak = os.path.join(FIXTURES, "weak_config.json")
        findings, _errs = scan_file(weak, Options(include_info=True))
        highs = sum(1 for f in findings if f.severity is Severity.HIGH)
        mediums = sum(1 for f in findings if f.severity is Severity.MEDIUM)
        infos = sum(1 for f in findings if f.severity is Severity.INFO)
        self.assertGreater(highs, 0)
        self.assertGreater(mediums, 0)
        self.assertGreater(infos, 0)

    def test_healthy_fires_nothing(self):
        healthy = os.path.join(FIXTURES, "healthy_config.json")
        findings, errs = scan_file(healthy, Options(include_info=True))
        self.assertEqual(errs, [])
        self.assertEqual(findings, [])

    def test_sort_is_stable_across_two_runs(self):
        weak = os.path.join(FIXTURES, "weak_config.json")
        f1, _ = scan_file(weak, Options())
        f2, _ = scan_file(weak, Options())
        keys1 = [f.sort_key() for f in sorted(f1, key=lambda f: f.sort_key())]
        keys2 = [f.sort_key() for f in sorted(f2, key=lambda f: f.sort_key())]
        self.assertEqual(keys1, keys2)


class TestJsonRoundtripDeterminism(unittest.TestCase):
    def test_json_stable(self):
        from approvchainlint.report import render_json
        from approvchainlint.scanner import scan_paths
        from approvchainlint.verdict import compute_verdict
        opts = Options()
        weak = os.path.join(FIXTURES, "weak_config.json")
        r = scan_paths([weak], opts)
        v = compute_verdict(r, opts)
        a, b = io.StringIO(), io.StringIO()
        render_json(r, v, opts, a, io.StringIO())
        render_json(r, v, opts, b, io.StringIO())
        self.assertEqual(a.getvalue(), b.getvalue())
        doc = json.loads(a.getvalue())
        self.assertEqual(doc["tool"], "approvchainlint")


if __name__ == "__main__":
    unittest.main()
