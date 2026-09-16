"""Tests for mcpservercheck.types."""

import unittest
from dataclasses import FrozenInstanceError

from mcpservercheck.types import Finding, ScanResult, Severity, Verdict, severity_rank


class SeverityEnumTests(unittest.TestCase):
    def test_high_medium_info_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_membership(self):
        self.assertEqual({s.value for s in Severity}, {"HIGH", "MEDIUM", "INFO"})

    def test_severity_rank_order(self):
        self.assertLess(severity_rank(Severity.HIGH), severity_rank(Severity.MEDIUM))
        self.assertLess(severity_rank(Severity.MEDIUM), severity_rank(Severity.INFO))


class VerdictEnumTests(unittest.TestCase):
    def test_all_four_verdicts(self):
        self.assertEqual(
            {v.value for v in Verdict},
            {"healthy", "needs-attention", "unhealthy", "unknown"},
        )


class FindingTests(unittest.TestCase):
    def test_is_frozen(self):
        f = Finding("MSC-001", Severity.HIGH, "p", 1, 2, "m", "s")
        with self.assertRaises(FrozenInstanceError):
            f.rule_id = "MSC-999"

    def test_sort_key_severity_first(self):
        high = Finding("MSC-999", Severity.HIGH, "z", 99, 99, "", "")
        info = Finding("MSC-001", Severity.INFO, "a", 1, 1, "", "")
        medium = Finding("MSC-500", Severity.MEDIUM, "m", 10, 10, "", "")
        results = sorted([info, medium, high], key=lambda f: f.sort_key())
        self.assertEqual([r.severity for r in results],
                         [Severity.HIGH, Severity.MEDIUM, Severity.INFO])

    def test_sort_key_full_tuple(self):
        f = Finding("MSC-002", Severity.HIGH, "p", 3, 4, "m", "s")
        k = f.sort_key()
        self.assertEqual(k[0], severity_rank(Severity.HIGH))
        self.assertEqual(k[1], "p")
        self.assertEqual(k[2], 3)
        self.assertEqual(k[3], 4)
        self.assertEqual(k[4], "MSC-002")

    def test_sort_tiebreak_by_path_then_line_then_col_then_rule(self):
        a = Finding("MSC-002", Severity.HIGH, "a.json", 10, 5, "", "")
        b = Finding("MSC-001", Severity.HIGH, "a.json", 10, 5, "", "")
        c = Finding("MSC-001", Severity.HIGH, "a.json", 10, 6, "", "")
        d = Finding("MSC-001", Severity.HIGH, "a.json", 11, 1, "", "")
        e = Finding("MSC-001", Severity.HIGH, "b.json", 1, 1, "", "")
        results = sorted([e, d, c, b, a], key=lambda f: f.sort_key())
        self.assertEqual([r.rule_id + ":" + r.path + ":" + str(r.line) + ":" + str(r.column) for r in results],
                         ["MSC-001:a.json:10:5", "MSC-002:a.json:10:5",
                          "MSC-001:a.json:10:6", "MSC-001:a.json:11:1",
                          "MSC-001:b.json:1:1"])


class ScanResultTests(unittest.TestCase):
    def test_defaults(self):
        r = ScanResult()
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.findings, ())
        self.assertEqual(r.errors, ())

    def test_construct_with_values(self):
        f = Finding("MSC-001", Severity.HIGH, "p", 1, 1, "m", "s")
        r = ScanResult(files_scanned=2, findings=(f,), errors=("e",))
        self.assertEqual(r.files_scanned, 2)
        self.assertEqual(r.findings, (f,))
        self.assertEqual(r.errors, ("e",))


if __name__ == "__main__":
    unittest.main()
