import json
import unittest

from delegcheck.report import format_json, format_text
from delegcheck.types import Finding, ScanResult, Severity, Verdict
from delegcheck.verdict import compute_verdict, counts, exit_code_for


def _f(sev):
    return Finding(
        rule_id="DEL-001", severity=sev, path="a.json",
        line=1, column=1, message="m", snippet="s",
    )


def _r(findings=(), files=1, errors=()):
    return ScanResult(files_scanned=files, findings=tuple(findings), errors=tuple(errors))


class TestVerdictRollup(unittest.TestCase):

    def test_no_files_unknown(self):
        self.assertEqual(compute_verdict(_r(files=0)), Verdict.UNKNOWN)

    def test_no_files_strict_still_unknown(self):
        self.assertEqual(compute_verdict(_r(files=0), strict=True), Verdict.UNKNOWN)

    def test_high_unhealthy(self):
        self.assertEqual(compute_verdict(_r([_f(Severity.HIGH)])), Verdict.UNHEALTHY)

    def test_medium_needs_attention(self):
        self.assertEqual(compute_verdict(_r([_f(Severity.MEDIUM)])), Verdict.NEEDS_ATTENTION)

    def test_high_beats_medium(self):
        r = _r([_f(Severity.HIGH), _f(Severity.MEDIUM)])
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_info_default_healthy(self):
        self.assertEqual(compute_verdict(_r([_f(Severity.INFO)])), Verdict.HEALTHY)

    def test_info_strict_needs_attention(self):
        self.assertEqual(compute_verdict(_r([_f(Severity.INFO)]), strict=True), Verdict.NEEDS_ATTENTION)

    def test_no_findings_healthy(self):
        self.assertEqual(compute_verdict(_r([])), Verdict.HEALTHY)


class TestExitCode(unittest.TestCase):

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


class TestCounts(unittest.TestCase):

    def test_counts(self):
        r = _r([_f(Severity.HIGH), _f(Severity.HIGH), _f(Severity.MEDIUM), _f(Severity.INFO)])
        self.assertEqual(counts(r), (2, 1, 1))


class TestTextReport(unittest.TestCase):

    def test_verdict_line(self):
        out = format_text(_r([_f(Severity.HIGH)]))
        self.assertIn("verdict: unhealthy", out)

    def test_totals_line(self):
        out = format_text(_r([_f(Severity.HIGH), _f(Severity.MEDIUM)]))
        self.assertIn("findings_total=2", out)
        self.assertIn("high=1", out)
        self.assertIn("medium=1", out)

    def test_hides_info_by_default(self):
        out = format_text(_r([_f(Severity.INFO)]))
        self.assertNotIn("DEL-001 a.json", out)
        self.assertIn("info=1", out)

    def test_shows_info_with_include_info(self):
        out = format_text(_r([_f(Severity.INFO)]), include_info=True)
        self.assertIn("DEL-001", out)

    def test_lists_errors(self):
        out = format_text(_r([], errors=("read-error: x",)))
        self.assertIn("ERROR read-error: x", out)


class TestJsonReport(unittest.TestCase):

    def test_parseable(self):
        out = format_json(_r([_f(Severity.HIGH)]))
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "unhealthy")
        self.assertEqual(payload["exit_code"], 2)
        self.assertEqual(payload["counts"]["high"], 1)

    def test_deterministic(self):
        r = _r([_f(Severity.HIGH), _f(Severity.MEDIUM)])
        self.assertEqual(format_json(r), format_json(r))

    def test_omits_info_by_default(self):
        r = _r([_f(Severity.INFO)])
        payload = json.loads(format_json(r))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["counts"]["info"], 1)

    def test_includes_info_when_configured(self):
        r = _r([_f(Severity.INFO)])
        payload = json.loads(format_json(r, include_info=True))
        self.assertEqual(len(payload["findings"]), 1)

    def test_errors_field(self):
        payload = json.loads(format_json(_r([], errors=("x",))))
        self.assertEqual(payload["errors"], ["x"])


if __name__ == "__main__":
    unittest.main()
