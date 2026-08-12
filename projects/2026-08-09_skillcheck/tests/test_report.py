"""Report formatter + exit-code contract tests."""

from __future__ import annotations

import json
import unittest

from skillcheck.report import (
    EXIT_SAFE,
    EXIT_SUSPICIOUS,
    EXIT_UNKNOWN_DEFAULT,
    EXIT_UNKNOWN_STRICT,
    EXIT_UNSAFE,
    exit_code_for,
    report_to_json,
    report_to_text,
)
from skillcheck.verdict import Finding, Report, Severity, Verdict


def _mk_finding(rule="SKILLCHECK-001", sev=Severity.CRITICAL, line=1, col=1):
    return Finding(
        rule_id=rule,
        severity=sev,
        file="a.md",
        line=line,
        column=col,
        excerpt="rm -rf /",
        message="destructive shell",
    )


class TestExitCode(unittest.TestCase):
    def test_safe_is_0(self):
        r = Report(verdict=Verdict.SAFE)
        self.assertEqual(exit_code_for(r), EXIT_SAFE)

    def test_unsafe_is_2(self):
        r = Report(verdict=Verdict.UNSAFE)
        self.assertEqual(exit_code_for(r), EXIT_UNSAFE)

    def test_suspicious_is_1(self):
        r = Report(verdict=Verdict.SUSPICIOUS)
        self.assertEqual(exit_code_for(r), EXIT_SUSPICIOUS)

    def test_unknown_default_is_1(self):
        r = Report(verdict=Verdict.UNKNOWN)
        self.assertEqual(exit_code_for(r), EXIT_UNKNOWN_DEFAULT)

    def test_unknown_strict_is_2(self):
        r = Report(verdict=Verdict.UNKNOWN)
        self.assertEqual(exit_code_for(r, strict=True), EXIT_UNKNOWN_STRICT)


class TestJsonFormatter(unittest.TestCase):
    def test_json_parseable(self):
        r = Report(verdict=Verdict.UNSAFE, findings=[_mk_finding()], files_scanned=["a.md"])
        parsed = json.loads(report_to_json(r))
        self.assertEqual(parsed["verdict"], "unsafe")
        self.assertEqual(len(parsed["findings"]), 1)

    def test_json_deterministic(self):
        r = Report(verdict=Verdict.UNSAFE, findings=[_mk_finding()], files_scanned=["a.md"])
        self.assertEqual(report_to_json(r), report_to_json(r))

    def test_include_info_toggle(self):
        info = _mk_finding(rule="SKILLCHECK-009", sev=Severity.INFO)
        crit = _mk_finding()
        r = Report(verdict=Verdict.UNSAFE, findings=[crit, info], files_scanned=["a.md"])
        default = json.loads(report_to_json(r))
        with_info = json.loads(report_to_json(r, include_info=True))
        self.assertEqual(len(default["findings"]), 1)
        self.assertEqual(len(with_info["findings"]), 2)

    def test_summary_present(self):
        r = Report(verdict=Verdict.UNSAFE, findings=[_mk_finding()], files_scanned=["a.md"])
        parsed = json.loads(report_to_json(r))
        self.assertIn("summary", parsed)
        self.assertEqual(parsed["summary"]["by_severity"]["critical"], 1)


class TestTextFormatter(unittest.TestCase):
    def test_text_has_verdict_line(self):
        r = Report(verdict=Verdict.SAFE, files_scanned=["a.md"])
        out = report_to_text(r)
        self.assertIn("verdict: safe", out)

    def test_text_lists_findings(self):
        r = Report(verdict=Verdict.UNSAFE, findings=[_mk_finding()], files_scanned=["a.md"])
        out = report_to_text(r)
        self.assertIn("SKILLCHECK-001", out)
        self.assertIn("critical", out)

    def test_text_hides_info_by_default(self):
        info = _mk_finding(rule="SKILLCHECK-009", sev=Severity.INFO)
        r = Report(verdict=Verdict.UNKNOWN, findings=[info], files_scanned=["a.md"])
        out = report_to_text(r)
        self.assertNotIn("SKILLCHECK-009", out)

    def test_text_shows_info_with_flag(self):
        info = _mk_finding(rule="SKILLCHECK-009", sev=Severity.INFO)
        r = Report(verdict=Verdict.UNKNOWN, findings=[info], files_scanned=["a.md"])
        out = report_to_text(r, include_info=True)
        self.assertIn("SKILLCHECK-009", out)

    def test_text_shows_errors(self):
        r = Report(verdict=Verdict.UNKNOWN, errors=["bad thing happened"])
        out = report_to_text(r)
        self.assertIn("bad thing happened", out)


if __name__ == "__main__":
    unittest.main()
