"""Verdict rollup and exit-code mapping tests."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from agentmemcheck.types import Finding, Options, Severity, Verdict
from agentmemcheck.verdict import compute_verdict, exit_code


def _f(sev: Severity) -> Finding:
    return Finding(
        rule_id="AMC-x", severity=sev, message="",
        entry_id="", pointer="",
    )


class ComputeVerdictTests(unittest.TestCase):
    def test_high_dominates(self):
        v = compute_verdict([_f(Severity.HIGH)], 1, Options())
        self.assertIs(v, Verdict.UNHEALTHY)

    def test_medium_only(self):
        v = compute_verdict([_f(Severity.MEDIUM)], 1, Options())
        self.assertIs(v, Verdict.NEEDS_ATTENTION)

    def test_info_only_default_healthy(self):
        v = compute_verdict([_f(Severity.INFO)], 1, Options())
        self.assertIs(v, Verdict.HEALTHY)

    def test_info_only_strict_needs_attention(self):
        v = compute_verdict(
            [_f(Severity.INFO)], 1, Options(strict=True)
        )
        self.assertIs(v, Verdict.NEEDS_ATTENTION)

    def test_no_findings_healthy(self):
        v = compute_verdict([], 1, Options())
        self.assertIs(v, Verdict.HEALTHY)

    def test_no_files_unknown(self):
        v = compute_verdict([], 0, Options())
        self.assertIs(v, Verdict.UNKNOWN)

    def test_high_overrides_no_files(self):
        v = compute_verdict([_f(Severity.HIGH)], 0, Options())
        self.assertIs(v, Verdict.UNHEALTHY)


class ExitCodeTests(unittest.TestCase):
    def test_healthy_zero(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Options()), 0)

    def test_needs_attention_one(self):
        self.assertEqual(
            exit_code(Verdict.NEEDS_ATTENTION, Options()), 1,
        )

    def test_unhealthy_two(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Options()), 2)

    def test_unknown_default_one_strict_two(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options()), 1)
        self.assertEqual(
            exit_code(Verdict.UNKNOWN, Options(strict=True)), 2,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
