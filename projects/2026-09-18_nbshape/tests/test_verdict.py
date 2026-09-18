"""Verdict rollup precedence and the exit-code contract."""

from __future__ import annotations

import unittest

from nbshape.types import Finding, ScanResult, Severity, Verdict
from nbshape.verdict import compute_verdict, counts, exit_code_for


def f(sev, rule_id="NBK-001"):
    return Finding(
        rule_id=rule_id, severity=sev, path="a.ipynb", cell=0,
        line=1, column=1, message="m", snippet="s",
    )


def result(findings=(), scanned=1, scored=None, unknown=None):
    scored = scanned if scored is None else scored
    unknown = scanned - scored if unknown is None else unknown
    return ScanResult(
        files_scanned=scanned,
        files_scored=scored,
        files_unknown=unknown,
        findings=tuple(findings),
    )


class RollupTests(unittest.TestCase):
    def test_no_files_scanned_is_unknown(self):
        self.assertEqual(compute_verdict(result(scanned=0, scored=0)), Verdict.UNKNOWN)

    def test_no_findings_is_healthy(self):
        self.assertEqual(compute_verdict(result()), Verdict.HEALTHY)

    def test_a_high_finding_is_unhealthy(self):
        self.assertEqual(compute_verdict(result([f(Severity.HIGH)])), Verdict.UNHEALTHY)

    def test_a_medium_finding_is_needs_attention(self):
        self.assertEqual(
            compute_verdict(result([f(Severity.MEDIUM)])), Verdict.NEEDS_ATTENTION
        )

    def test_an_info_finding_is_healthy_by_default(self):
        self.assertEqual(compute_verdict(result([f(Severity.INFO)])), Verdict.HEALTHY)

    def test_an_info_finding_is_needs_attention_under_strict(self):
        self.assertEqual(
            compute_verdict(result([f(Severity.INFO)]), strict=True),
            Verdict.NEEDS_ATTENTION,
        )

    def test_high_outranks_medium(self):
        r = result([f(Severity.MEDIUM), f(Severity.HIGH)])
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_medium_outranks_info(self):
        r = result([f(Severity.INFO), f(Severity.MEDIUM)])
        self.assertEqual(compute_verdict(r), Verdict.NEEDS_ATTENTION)

    def test_strict_does_not_downgrade_a_high(self):
        r = result([f(Severity.HIGH)])
        self.assertEqual(compute_verdict(r, strict=True), Verdict.UNHEALTHY)

    def test_files_opened_but_none_scored_is_unknown(self):
        self.assertEqual(
            compute_verdict(result(scanned=2, scored=0, unknown=2)), Verdict.UNKNOWN
        )

    def test_an_unscorable_file_does_not_mask_a_high_elsewhere(self):
        r = result([f(Severity.HIGH)], scanned=2, scored=1, unknown=1)
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_an_unscorable_file_does_not_mask_a_medium_elsewhere(self):
        r = result([f(Severity.MEDIUM)], scanned=2, scored=1, unknown=1)
        self.assertEqual(compute_verdict(r), Verdict.NEEDS_ATTENTION)

    def test_a_gated_file_with_only_its_info_finding_is_unknown_not_healthy(self):
        r = result([f(Severity.INFO, "NBK-010")], scanned=1, scored=0, unknown=1)
        self.assertEqual(compute_verdict(r), Verdict.UNKNOWN)

    def test_one_scored_clean_file_beside_one_unknown_is_healthy(self):
        r = result([f(Severity.INFO, "NBK-010")], scanned=2, scored=1, unknown=1)
        self.assertEqual(compute_verdict(r), Verdict.HEALTHY)


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

    def test_strict_does_not_change_healthy(self):
        self.assertEqual(exit_code_for(Verdict.HEALTHY, strict=True), 0)

    def test_strict_does_not_change_unhealthy(self):
        self.assertEqual(exit_code_for(Verdict.UNHEALTHY, strict=True), 2)

    def test_the_zero_exit_code_belongs_only_to_healthy(self):
        nonzero = [v for v in Verdict if v != Verdict.HEALTHY]
        for v in nonzero:
            self.assertNotEqual(exit_code_for(v), 0, v)


class CountTests(unittest.TestCase):
    def test_counts_are_zero_for_an_empty_result(self):
        self.assertEqual(counts(result()), (0, 0, 0))

    def test_counts_split_by_severity(self):
        r = result([f(Severity.HIGH), f(Severity.HIGH), f(Severity.MEDIUM),
                    f(Severity.INFO)])
        self.assertEqual(counts(r), (2, 1, 1))

    def test_counts_include_hidden_info_findings(self):
        r = result([f(Severity.INFO), f(Severity.INFO)])
        self.assertEqual(counts(r)[2], 2)


if __name__ == "__main__":
    unittest.main()
