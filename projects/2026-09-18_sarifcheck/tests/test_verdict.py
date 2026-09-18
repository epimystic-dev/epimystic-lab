"""Verdict rollup and exit-code contract."""

from __future__ import annotations

import unittest

from sarifcheck.types import Finding, ScanResult, Severity, Verdict
from sarifcheck.verdict import compute_verdict, counts, exit_code_for


def finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="SRF-001",
        severity=severity,
        path="a.sarif",
        prop="version",
        line=1,
        column=1,
        message="m",
    )


def result(*severities, **kwargs) -> ScanResult:
    return ScanResult(
        files_scanned=kwargs.pop("files_scanned", 1),
        findings=tuple(finding(s) for s in severities),
        errors=tuple(kwargs.pop("errors", ())),
        partial=kwargs.pop("partial", False),
    )


class RollupTests(unittest.TestCase):
    def test_no_files_is_unknown(self):
        self.assertEqual(compute_verdict(result(files_scanned=0)), Verdict.UNKNOWN)

    def test_no_findings_is_healthy(self):
        self.assertEqual(compute_verdict(result()), Verdict.HEALTHY)

    def test_high_is_unhealthy(self):
        self.assertEqual(compute_verdict(result(Severity.HIGH)), Verdict.UNHEALTHY)

    def test_medium_is_needs_attention(self):
        self.assertEqual(
            compute_verdict(result(Severity.MEDIUM)), Verdict.NEEDS_ATTENTION
        )

    def test_info_alone_is_healthy_by_default(self):
        self.assertEqual(compute_verdict(result(Severity.INFO)), Verdict.HEALTHY)

    def test_info_alone_is_needs_attention_under_strict(self):
        self.assertEqual(
            compute_verdict(result(Severity.INFO), strict=True),
            Verdict.NEEDS_ATTENTION,
        )

    def test_high_beats_medium_and_info(self):
        self.assertEqual(
            compute_verdict(result(Severity.INFO, Severity.MEDIUM, Severity.HIGH)),
            Verdict.UNHEALTHY,
        )

    def test_medium_beats_info(self):
        self.assertEqual(
            compute_verdict(result(Severity.INFO, Severity.MEDIUM)),
            Verdict.NEEDS_ATTENTION,
        )

    def test_errors_make_a_clean_scan_unknown(self):
        self.assertEqual(
            compute_verdict(result(errors=("read-error: x",))), Verdict.UNKNOWN
        )

    def test_errors_do_not_mask_a_high_finding(self):
        self.assertEqual(
            compute_verdict(result(Severity.HIGH, errors=("read-error: x",))),
            Verdict.UNHEALTHY,
        )

    def test_partial_scan_cannot_be_healthy(self):
        self.assertEqual(compute_verdict(result(partial=True)), Verdict.UNKNOWN)

    def test_partial_scan_with_medium_reports_the_medium(self):
        self.assertEqual(
            compute_verdict(result(Severity.MEDIUM, partial=True)),
            Verdict.NEEDS_ATTENTION,
        )

    def test_strict_does_not_change_a_clean_scan(self):
        self.assertEqual(compute_verdict(result(), strict=True), Verdict.HEALTHY)


class ExitCodeTests(unittest.TestCase):
    def test_healthy_is_zero(self):
        self.assertEqual(exit_code_for(Verdict.HEALTHY), 0)

    def test_needs_attention_is_one(self):
        self.assertEqual(exit_code_for(Verdict.NEEDS_ATTENTION), 1)

    def test_unhealthy_is_two(self):
        self.assertEqual(exit_code_for(Verdict.UNHEALTHY), 2)

    def test_unknown_is_one_by_default(self):
        self.assertEqual(exit_code_for(Verdict.UNKNOWN), 1)

    def test_unknown_is_two_under_strict(self):
        self.assertEqual(exit_code_for(Verdict.UNKNOWN, strict=True), 2)

    def test_hard_error_is_two_even_without_strict(self):
        self.assertEqual(exit_code_for(Verdict.UNKNOWN, hard_error=True), 2)

    def test_hard_error_does_not_change_a_healthy_verdict(self):
        self.assertEqual(exit_code_for(Verdict.HEALTHY, hard_error=True), 0)

    def test_strict_does_not_escalate_needs_attention(self):
        self.assertEqual(exit_code_for(Verdict.NEEDS_ATTENTION, strict=True), 1)


class CountsTests(unittest.TestCase):
    def test_counts_are_per_severity(self):
        high, medium, info = counts(
            result(Severity.HIGH, Severity.HIGH, Severity.MEDIUM, Severity.INFO)
        )
        self.assertEqual((high, medium, info), (2, 1, 1))

    def test_counts_on_empty_result(self):
        self.assertEqual(counts(result()), (0, 0, 0))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
