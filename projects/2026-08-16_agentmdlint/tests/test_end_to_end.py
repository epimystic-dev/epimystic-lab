"""End-to-end fixture tests: one repo per verdict class."""

import io
import json
import os
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import date

from agentmdlint.cli import main
from agentmdlint.config import Config
from agentmdlint.scanner import scan_path
from agentmdlint.verdict import compute_verdict
from agentmdlint.types import Verdict


FIXTURES_ROOT = os.path.join(os.path.dirname(__file__), "fixtures")


def _run_cli(argv):
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        code = main(argv)
    return code, out_buf.getvalue(), err_buf.getvalue()


class TestFixtureHealthy(unittest.TestCase):
    def test_healthy_scan_yields_healthy(self):
        root = os.path.join(FIXTURES_ROOT, "healthy")
        # Use a fresh --today far enough back to avoid drift; the healthy
        # fixture has no dates.
        cfg = Config(today=date(2026, 8, 16))
        report = scan_path(root, cfg)
        verdict, exit_code = compute_verdict(report, cfg)
        self.assertEqual(verdict, Verdict.HEALTHY, msg=str([str(f) for f in report.all_findings()]))
        self.assertEqual(exit_code, 0)

    def test_healthy_cli_exit_zero(self):
        root = os.path.join(FIXTURES_ROOT, "healthy")
        code, _, _ = _run_cli([root, "--today", "2026-08-16"])
        self.assertEqual(code, 0)


class TestFixtureBloated(unittest.TestCase):
    def test_bloated_yields_needs_attention(self):
        # Tighten thresholds so the fixture triggers 002 without needing an
        # enormous file. The fixture has 12 imperative lines.
        cfg = Config(soft_instructions=5, hard_instructions=1000, today=date(2026, 8, 16))
        report = scan_path(os.path.join(FIXTURES_ROOT, "bloated"), cfg)
        rule_ids = {f.rule_id for f in report.all_findings()}
        self.assertIn("AGENTMD-002", rule_ids)
        self.assertIn("AGENTMD-010", rule_ids)


class TestFixtureDuplicates(unittest.TestCase):
    def test_duplicates_triggers_003(self):
        cfg = Config(duplicate_threshold=0.7, today=date(2026, 8, 16))
        report = scan_path(os.path.join(FIXTURES_ROOT, "duplicates"), cfg)
        rule_ids = {f.rule_id for f in report.all_findings()}
        self.assertIn("AGENTMD-003", rule_ids)


class TestFixtureContradictions(unittest.TestCase):
    def test_contradictions_triggers_008_and_unhealthy(self):
        cfg = Config(today=date(2026, 8, 16))
        report = scan_path(os.path.join(FIXTURES_ROOT, "contradictions"), cfg)
        rule_ids = {f.rule_id for f in report.all_findings()}
        self.assertIn("AGENTMD-008", rule_ids)
        v, e = compute_verdict(report, cfg)
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertEqual(e, 2)


class TestFixtureStale(unittest.TestCase):
    def test_stale_triggers_007_and_006(self):
        cfg = Config(stale_days=30, today=date(2026, 8, 16))
        report = scan_path(os.path.join(FIXTURES_ROOT, "stale"), cfg)
        rule_ids = {f.rule_id for f in report.all_findings()}
        self.assertIn("AGENTMD-007", rule_ids)
        self.assertIn("AGENTMD-006", rule_ids)


class TestFixtureUnknown(unittest.TestCase):
    def test_unknown_returns_unknown_verdict(self):
        report = scan_path(os.path.join(FIXTURES_ROOT, "unknown"), Config())
        v, e = compute_verdict(report, Config())
        self.assertEqual(v, Verdict.UNKNOWN)
        self.assertEqual(e, 1)

    def test_unknown_strict_exit_two(self):
        report = scan_path(os.path.join(FIXTURES_ROOT, "unknown"), Config())
        _, e = compute_verdict(report, Config(), strict=True)
        self.assertEqual(e, 2)


class TestJsonRoundTrip(unittest.TestCase):
    def test_bloated_json_is_deterministic(self):
        cfg_args = [os.path.join(FIXTURES_ROOT, "bloated"), "--json",
                    "--soft-instructions", "5", "--today", "2026-08-16"]
        _, out1, _ = _run_cli(cfg_args)
        _, out2, _ = _run_cli(cfg_args)
        self.assertEqual(out1, out2)
        payload = json.loads(out1)
        self.assertIn("AGENTMD-002", {f["rule_id"] for f in payload["findings"]})


if __name__ == "__main__":
    unittest.main()
