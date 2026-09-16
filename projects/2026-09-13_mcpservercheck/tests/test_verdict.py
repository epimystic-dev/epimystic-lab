"""Tests for mcpservercheck.verdict."""

import json
import unittest

from mcpservercheck.report import format_json, format_text
from mcpservercheck.types import Finding, ScanResult, Severity, Verdict
from mcpservercheck.verdict import compute_verdict, counts, exit_code_for


def _r(*findings, files=1, errors=()):
    return ScanResult(files_scanned=files, findings=tuple(findings), errors=tuple(errors))


HIGH_F = Finding("MSC-001", Severity.HIGH, "p", 1, 1, "m", "s")
MED_F = Finding("MSC-006", Severity.MEDIUM, "p", 1, 1, "m", "s")
INFO_F = Finding("MSC-010", Severity.INFO, "p", 1, 1, "m", "s")


class VerdictRollupTests(unittest.TestCase):
    def test_no_files_default_unknown(self):
        self.assertEqual(compute_verdict(_r(files=0)), Verdict.UNKNOWN)

    def test_no_files_strict_unknown_still(self):
        self.assertEqual(compute_verdict(_r(files=0), strict=True), Verdict.UNKNOWN)

    def test_high_yields_unhealthy(self):
        self.assertEqual(compute_verdict(_r(HIGH_F)), Verdict.UNHEALTHY)

    def test_medium_yields_needs_attention(self):
        self.assertEqual(compute_verdict(_r(MED_F)), Verdict.NEEDS_ATTENTION)

    def test_high_beats_medium(self):
        self.assertEqual(compute_verdict(_r(MED_F, HIGH_F)), Verdict.UNHEALTHY)

    def test_info_only_default_healthy(self):
        self.assertEqual(compute_verdict(_r(INFO_F)), Verdict.HEALTHY)

    def test_info_only_strict_needs_attention(self):
        self.assertEqual(compute_verdict(_r(INFO_F), strict=True), Verdict.NEEDS_ATTENTION)

    def test_no_findings_healthy(self):
        self.assertEqual(compute_verdict(_r()), Verdict.HEALTHY)


class ExitCodeTests(unittest.TestCase):
    def test_healthy_zero(self):
        self.assertEqual(exit_code_for(Verdict.HEALTHY), 0)

    def test_needs_attention_one(self):
        self.assertEqual(exit_code_for(Verdict.NEEDS_ATTENTION), 1)

    def test_unhealthy_two(self):
        self.assertEqual(exit_code_for(Verdict.UNHEALTHY), 2)

    def test_unknown_default_one(self):
        self.assertEqual(exit_code_for(Verdict.UNKNOWN), 1)

    def test_unknown_strict_two(self):
        self.assertEqual(exit_code_for(Verdict.UNKNOWN, strict=True), 2)


class CountsTests(unittest.TestCase):
    def test_all_zero(self):
        self.assertEqual(counts(_r()), (0, 0, 0))

    def test_mixed(self):
        self.assertEqual(counts(_r(HIGH_F, HIGH_F, MED_F, INFO_F)), (2, 1, 1))


class ReportTextTests(unittest.TestCase):
    def test_verdict_line(self):
        out = format_text(_r(HIGH_F))
        self.assertIn("verdict: unhealthy", out)

    def test_totals_line(self):
        out = format_text(_r(HIGH_F, MED_F, INFO_F))
        self.assertIn("findings_total=3", out)
        self.assertIn("high=1 medium=1 info=1", out)

    def test_hides_info_by_default(self):
        out = format_text(_r(INFO_F))
        self.assertNotIn("MSC-010", out)

    def test_shows_info_with_include(self):
        out = format_text(_r(INFO_F), include_info=True)
        self.assertIn("MSC-010", out)

    def test_lists_errors(self):
        r = _r(errors=("read-error: foo",))
        out = format_text(r)
        self.assertIn("ERROR read-error: foo", out)


class ReportJsonTests(unittest.TestCase):
    def test_parseable_and_shape(self):
        payload = json.loads(format_json(_r(HIGH_F)))
        self.assertEqual(payload["verdict"], "unhealthy")
        self.assertEqual(payload["exit_code"], 2)
        self.assertEqual(payload["counts"]["high"], 1)
        self.assertEqual(len(payload["findings"]), 1)

    def test_deterministic(self):
        r = _r(HIGH_F, MED_F, INFO_F)
        a = format_json(r)
        b = format_json(r)
        self.assertEqual(a, b)

    def test_omits_info_by_default(self):
        payload = json.loads(format_json(_r(INFO_F)))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["counts"]["info"], 1)

    def test_includes_info_when_configured(self):
        payload = json.loads(format_json(_r(INFO_F), include_info=True))
        self.assertEqual(len(payload["findings"]), 1)

    def test_errors_field(self):
        payload = json.loads(format_json(_r(errors=("e1",))))
        self.assertEqual(payload["errors"], ["e1"])


if __name__ == "__main__":
    unittest.main()
