"""Verdict rollup and exit-code mapping."""

from __future__ import annotations

import unittest

from mcptoolcheck.types import Finding, Options, Severity, Verdict
from mcptoolcheck.verdict import compute_verdict, exit_code


def _f(sev: Severity, rid: str = "MTC-X") -> Finding:
    return Finding(
        rule_id=rid, severity=sev, message="m", tool_name="t", pointer="p"
    )


class ComputeVerdictTests(unittest.TestCase):
    def test_no_files_scanned_is_unknown(self):
        self.assertIs(
            compute_verdict([], 0, Options()), Verdict.UNKNOWN
        )

    def test_no_findings_is_healthy(self):
        self.assertIs(
            compute_verdict([], 1, Options()), Verdict.HEALTHY
        )

    def test_any_high_is_unhealthy(self):
        self.assertIs(
            compute_verdict(
                [_f(Severity.HIGH), _f(Severity.MEDIUM)], 1, Options()
            ),
            Verdict.UNHEALTHY,
        )

    def test_medium_only_is_needs_attention(self):
        self.assertIs(
            compute_verdict(
                [_f(Severity.MEDIUM)], 1, Options()
            ),
            Verdict.NEEDS_ATTENTION,
        )

    def test_info_only_default_is_healthy(self):
        self.assertIs(
            compute_verdict([_f(Severity.INFO)], 1, Options()),
            Verdict.HEALTHY,
        )

    def test_info_only_strict_is_needs_attention(self):
        self.assertIs(
            compute_verdict(
                [_f(Severity.INFO)], 1, Options(strict=True)
            ),
            Verdict.NEEDS_ATTENTION,
        )


class ExitCodeTests(unittest.TestCase):
    def test_healthy_zero(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Options()), 0)

    def test_needs_attention_one(self):
        self.assertEqual(exit_code(Verdict.NEEDS_ATTENTION, Options()), 1)

    def test_unhealthy_two(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Options()), 2)

    def test_unknown_default_one(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options()), 1)

    def test_unknown_strict_two(self):
        self.assertEqual(
            exit_code(Verdict.UNKNOWN, Options(strict=True)), 2
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
