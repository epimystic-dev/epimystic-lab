"""Verdict rollup + report shape tests."""

import json
import unittest

from oraclecheck.report import build_report, render_json, render_text
from oraclecheck.types import Finding, ScanResult, Severity, Verdict
from oraclecheck.verdict import rollup_verdict


def _finding(rule="ORACLE-001", sev=Severity.HIGH, path="a.py", line=1, col=0, msg="x"):
    return Finding(rule_id=rule, severity=sev, path=path, line=line, column=col, message=msg)


def _result(path="a.py", findings=None, error=None):
    return ScanResult(path=path, findings=findings or [], error=error)


class TestRollup(unittest.TestCase):

    def test_no_files_unknown(self):
        verdict, code = rollup_verdict(0, [], strict=False)
        self.assertEqual(verdict, Verdict.UNKNOWN)
        self.assertEqual(code, 1)

    def test_no_files_strict_exit_2(self):
        verdict, code = rollup_verdict(0, [], strict=True)
        self.assertEqual(verdict, Verdict.UNKNOWN)
        self.assertEqual(code, 2)

    def test_healthy_no_findings(self):
        verdict, code = rollup_verdict(3, [], strict=False)
        self.assertEqual(verdict, Verdict.HEALTHY)
        self.assertEqual(code, 0)

    def test_high_unhealthy(self):
        verdict, code = rollup_verdict(1, [_finding(sev=Severity.HIGH)], strict=False)
        self.assertEqual(verdict, Verdict.UNHEALTHY)
        self.assertEqual(code, 2)

    def test_medium_needs_attention(self):
        verdict, code = rollup_verdict(1, [_finding(sev=Severity.MEDIUM)], strict=False)
        self.assertEqual(verdict, Verdict.NEEDS_ATTENTION)
        self.assertEqual(code, 1)

    def test_info_default_healthy(self):
        verdict, code = rollup_verdict(1, [_finding(sev=Severity.INFO)], strict=False)
        self.assertEqual(verdict, Verdict.HEALTHY)
        self.assertEqual(code, 0)

    def test_info_strict_needs_attention(self):
        verdict, code = rollup_verdict(1, [_finding(sev=Severity.INFO)], strict=True)
        self.assertEqual(verdict, Verdict.NEEDS_ATTENTION)
        self.assertEqual(code, 1)

    def test_high_beats_medium(self):
        findings = [_finding(sev=Severity.HIGH), _finding(sev=Severity.MEDIUM)]
        verdict, code = rollup_verdict(1, findings, strict=False)
        self.assertEqual(verdict, Verdict.UNHEALTHY)
        self.assertEqual(code, 2)


class TestReport(unittest.TestCase):

    def test_json_is_parseable_and_deterministic(self):
        results = [_result(findings=[_finding()])]
        report_a = build_report(results, strict=False, include_info=False)
        text_a = render_json(report_a)
        text_b = render_json(build_report(results, strict=False, include_info=False))
        self.assertEqual(text_a, text_b)
        parsed = json.loads(text_a)
        self.assertEqual(parsed["verdict"], "unhealthy")
        self.assertEqual(parsed["exit_code"], 2)

    def test_report_includes_totals_and_visibility_split(self):
        results = [
            _result(findings=[
                _finding(rule="ORACLE-001", sev=Severity.HIGH),
                _finding(rule="ORACLE-010", sev=Severity.INFO),
            ])
        ]
        report = build_report(results, strict=False, include_info=False)
        self.assertEqual(report["findings_total"], 2)
        self.assertEqual(report["findings_visible"], 1)
        # Toggle include_info -> both visible
        report2 = build_report(results, strict=False, include_info=True)
        self.assertEqual(report2["findings_visible"], 2)

    def test_report_lists_errors(self):
        results = [_result(path="bad.py", error="syntax error")]
        report = build_report(results, strict=False, include_info=False)
        self.assertEqual(report["files_scanned"], 0)
        self.assertEqual(report["files_errored"], 1)
        self.assertEqual(report["errors"][0]["path"], "bad.py")

    def test_text_render_contains_verdict_line(self):
        results = [_result(findings=[_finding()])]
        report = build_report(results, strict=False, include_info=False)
        text = render_text(report)
        self.assertIn("verdict:", text)
        self.assertIn("unhealthy", text)

    def test_text_hides_info_by_default_but_still_counts_them(self):
        results = [_result(findings=[_finding(sev=Severity.INFO)])]
        report = build_report(results, strict=False, include_info=False)
        text = render_text(report)
        self.assertNotIn("ORACLE-001", text)  # info entry not visible in text
        self.assertEqual(report["findings_total"], 1)

    def test_findings_visible_sorted_by_severity(self):
        results = [_result(findings=[
            _finding(rule="ORACLE-010", sev=Severity.INFO, line=1),
            _finding(rule="ORACLE-001", sev=Severity.HIGH, line=5),
            _finding(rule="ORACLE-003", sev=Severity.MEDIUM, line=10),
        ])]
        report = build_report(results, strict=False, include_info=True)
        severities = [f["severity"] for f in report["findings"]]
        # HIGH first, then MEDIUM, then INFO
        self.assertEqual(severities, ["HIGH", "MEDIUM", "INFO"])


if __name__ == "__main__":
    unittest.main()
