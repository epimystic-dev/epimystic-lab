"""End-to-end fixture-driven tests.

One test per fixture-shape verdict, plus JSON round-trip determinism.
"""

import json
import os
import unittest

from oraclecheck.config import Config
from oraclecheck.report import build_report, render_json
from oraclecheck.scanner import scan_path
from oraclecheck.types import Verdict


HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


def _run(subdir, strict=False, include_info=False, sut=None):
    root = os.path.join(FIXTURES, subdir)
    cfg = Config(strict=strict, include_info=include_info, sut_module=sut)
    results = scan_path(root, cfg)
    return build_report(results, strict=strict, include_info=include_info)


class TestFixtures(unittest.TestCase):

    def test_healthy_fixture_healthy_verdict(self):
        report = _run("healthy")
        self.assertEqual(report["verdict"], Verdict.HEALTHY.value)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["findings_total"], 0)

    def test_healthy_fixture_stays_healthy_under_strict_and_info(self):
        report = _run("healthy", strict=True, include_info=True)
        self.assertEqual(report["verdict"], Verdict.HEALTHY.value)

    def test_anchored_fixture_unhealthy(self):
        report = _run("anchored")
        self.assertEqual(report["verdict"], Verdict.UNHEALTHY.value)
        self.assertEqual(report["exit_code"], 2)
        rule_ids = {f["rule_id"] for f in report["findings"]}
        # At least ORACLE-001 (self-comparison) and ORACLE-002 (direct anchor)
        # should be present; ORACLE-003 too.
        self.assertIn("ORACLE-001", rule_ids)
        self.assertIn("ORACLE-002", rule_ids)
        self.assertIn("ORACLE-003", rule_ids)
        self.assertIn("ORACLE-004", rule_ids)

    def test_identity_fixture_unhealthy(self):
        report = _run("identity")
        self.assertEqual(report["verdict"], Verdict.UNHEALTHY.value)
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("ORACLE-005", rule_ids)
        self.assertIn("ORACLE-006", rule_ids)

    def test_swallow_fixture_unhealthy(self):
        report = _run("swallow")
        self.assertEqual(report["verdict"], Verdict.UNHEALTHY.value)
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("ORACLE-009", rule_ids)

    def test_mock_fixture_needs_attention(self):
        report = _run("mock")
        # ORACLE-008 is MEDIUM only -> needs-attention
        self.assertEqual(report["verdict"], Verdict.NEEDS_ATTENTION.value)
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("ORACLE-008", rule_ids)

    def test_vacuous_fixture_healthy_by_default(self):
        report = _run("vacuous")
        # INFO-only, default settings hide -> healthy exit 0
        self.assertEqual(report["verdict"], Verdict.HEALTHY.value)
        # But findings_total should count them
        self.assertGreater(report["findings_total"], 0)

    def test_vacuous_fixture_needs_attention_under_strict(self):
        report = _run("vacuous", strict=True, include_info=True)
        self.assertEqual(report["verdict"], Verdict.NEEDS_ATTENTION.value)

    def test_unknown_fixture(self):
        report = _run("unknown")
        self.assertEqual(report["verdict"], Verdict.UNKNOWN.value)
        self.assertEqual(report["exit_code"], 1)
        report_strict = _run("unknown", strict=True)
        self.assertEqual(report_strict["exit_code"], 2)

    def test_json_roundtrip_deterministic_on_anchored(self):
        a = render_json(_run("anchored"))
        b = render_json(_run("anchored"))
        self.assertEqual(a, b)
        parsed = json.loads(a)
        # Sanity re-serialize keys are sorted (json.dumps(sort_keys=True))
        for key in ("verdict", "exit_code", "findings", "files_scanned"):
            self.assertIn(key, parsed)


if __name__ == "__main__":
    unittest.main()
