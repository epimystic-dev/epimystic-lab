"""Verdict rollup tests."""

from __future__ import annotations

import unittest

from renovatelint.types import Finding, Options, Severity, Verdict
from renovatelint.verdict import compute_verdict, exit_code


def _f(sev: Severity) -> Finding:
    return Finding(
        rule_id="RNV-001", severity=sev, message="x", pointer="x",
        path="x", hint="",
    )


class ComputeVerdictTests(unittest.TestCase):
    def test_no_files_scanned_is_unknown(self):
        self.assertEqual(
            compute_verdict([], 0, Options()),
            Verdict.UNKNOWN,
        )

    def test_no_findings_scanned_is_healthy(self):
        self.assertEqual(
            compute_verdict([], 1, Options()),
            Verdict.HEALTHY,
        )

    def test_high_finding_is_unhealthy(self):
        self.assertEqual(
            compute_verdict([_f(Severity.HIGH)], 1, Options()),
            Verdict.UNHEALTHY,
        )

    def test_medium_finding_is_needs_attention(self):
        self.assertEqual(
            compute_verdict([_f(Severity.MEDIUM)], 1, Options()),
            Verdict.NEEDS_ATTENTION,
        )

    def test_info_only_is_healthy_by_default(self):
        self.assertEqual(
            compute_verdict([_f(Severity.INFO)], 1, Options()),
            Verdict.HEALTHY,
        )

    def test_info_only_is_needs_attention_under_strict(self):
        self.assertEqual(
            compute_verdict([_f(Severity.INFO)], 1, Options(strict=True)),
            Verdict.NEEDS_ATTENTION,
        )


class ExitCodeTests(unittest.TestCase):
    def test_healthy_is_zero(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Options()), 0)

    def test_needs_attention_is_one(self):
        self.assertEqual(exit_code(Verdict.NEEDS_ATTENTION, Options()), 1)

    def test_unhealthy_is_two(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Options()), 2)

    def test_unknown_defaults_to_one_strict_to_two(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options()), 1)
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options(strict=True)), 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
