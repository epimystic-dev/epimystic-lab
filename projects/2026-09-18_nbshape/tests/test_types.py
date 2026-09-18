"""Behaviour of the nbshape vocabulary types."""

from __future__ import annotations

import unittest

from nbshape.types import (
    NOTEBOOK_LEVEL,
    Finding,
    ScanResult,
    Severity,
    Verdict,
    severity_rank,
)


def mk(rule_id="NBK-001", sev=Severity.HIGH, path="a.ipynb", cell=0, line=1, col=1):
    return Finding(
        rule_id=rule_id,
        severity=sev,
        path=path,
        cell=cell,
        line=line,
        column=col,
        message="m",
        snippet="s",
    )


class SeverityTests(unittest.TestCase):
    def test_severity_values_are_the_three_documented_tiers(self):
        self.assertEqual(
            sorted(s.value for s in Severity), ["HIGH", "INFO", "MEDIUM"]
        )

    def test_severity_is_a_str_enum_so_json_round_trips(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertIsInstance(Severity.HIGH, str)

    def test_high_ranks_before_medium_before_info(self):
        self.assertLess(severity_rank(Severity.HIGH), severity_rank(Severity.MEDIUM))
        self.assertLess(severity_rank(Severity.MEDIUM), severity_rank(Severity.INFO))


class VerdictTests(unittest.TestCase):
    def test_verdict_values_are_the_four_documented_states(self):
        self.assertEqual(
            sorted(v.value for v in Verdict),
            ["healthy", "needs-attention", "unhealthy", "unknown"],
        )

    def test_verdict_is_a_str_enum(self):
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")
        self.assertIsInstance(Verdict.UNKNOWN, str)


class FindingTests(unittest.TestCase):
    def test_sort_key_orders_high_before_info_regardless_of_position(self):
        high = mk(sev=Severity.HIGH, line=999)
        info = mk(sev=Severity.INFO, line=1)
        self.assertLess(high.sort_key(), info.sort_key())

    def test_sort_key_orders_by_cell_within_one_severity(self):
        first = mk(cell=1)
        second = mk(cell=7)
        self.assertLess(first.sort_key(), second.sort_key())

    def test_sort_key_puts_notebook_level_before_cell_level(self):
        whole = mk(cell=NOTEBOOK_LEVEL)
        celled = mk(cell=0)
        self.assertLess(whole.sort_key(), celled.sort_key())

    def test_notebook_level_is_negative_so_it_cannot_collide_with_a_cell_index(self):
        self.assertLess(NOTEBOOK_LEVEL, 0)

    def test_to_dict_exposes_every_public_field(self):
        d = mk().to_dict()
        self.assertEqual(
            sorted(d.keys()),
            ["cell", "column", "line", "message", "path", "rule_id", "severity", "snippet"],
        )

    def test_to_dict_serialises_severity_as_a_plain_string(self):
        self.assertEqual(mk(sev=Severity.MEDIUM).to_dict()["severity"], "MEDIUM")

    def test_finding_is_frozen_so_a_reporter_cannot_mutate_a_result(self):
        f = mk()
        with self.assertRaises(Exception):
            f.rule_id = "NBK-999"

    def test_findings_are_hashable_so_duplicates_can_be_deduped(self):
        self.assertEqual(len({mk(), mk()}), 1)


class ScanResultTests(unittest.TestCase):
    def test_defaults_are_an_empty_scan(self):
        r = ScanResult()
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.files_scored, 0)
        self.assertEqual(r.files_unknown, 0)
        self.assertEqual(r.findings, tuple())
        self.assertEqual(r.errors, tuple())

    def test_default_containers_are_not_shared_between_instances(self):
        a = ScanResult()
        b = ScanResult()
        a.findings = (mk(),)
        self.assertEqual(b.findings, tuple())

    def test_scored_plus_unknown_is_the_caller_s_responsibility_not_enforced_here(self):
        r = ScanResult(files_scanned=3, files_scored=1, files_unknown=2)
        self.assertEqual(r.files_scored + r.files_unknown, r.files_scanned)


if __name__ == "__main__":
    unittest.main()
