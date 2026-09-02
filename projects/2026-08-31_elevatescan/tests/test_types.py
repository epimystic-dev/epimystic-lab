import json
import unittest

from elevatescan.types import Finding, ScanResult, Severity, Verdict, SEVERITY_RANK


class TestTypes(unittest.TestCase):
    def test_severity_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_severity_rank_order(self):
        self.assertLess(SEVERITY_RANK[Severity.HIGH], SEVERITY_RANK[Severity.MEDIUM])
        self.assertLess(SEVERITY_RANK[Severity.MEDIUM], SEVERITY_RANK[Severity.INFO])

    def test_verdict_values(self):
        self.assertEqual(Verdict.HEALTHY.value, "healthy")
        self.assertEqual(Verdict.NEEDS_ATTENTION.value, "needs-attention")
        self.assertEqual(Verdict.UNHEALTHY.value, "unhealthy")
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")

    def test_finding_is_frozen(self):
        f = Finding("ESC-001", Severity.HIGH, "a.md", 1, 1, "m", "ev")
        with self.assertRaises(Exception):
            f.rule_id = "other"  # type: ignore

    def test_sort_key_severity_first(self):
        h = Finding("ESC-001", Severity.HIGH, "z.md", 9, 9, "m", "ev")
        m = Finding("ESC-002", Severity.MEDIUM, "a.md", 1, 1, "m", "ev")
        i = Finding("ESC-003", Severity.INFO, "a.md", 1, 1, "m", "ev")
        arr = sorted([i, m, h], key=lambda x: x.sort_key())
        self.assertEqual([x.severity for x in arr], [Severity.HIGH, Severity.MEDIUM, Severity.INFO])

    def test_sort_key_path_then_line_then_col_then_rule(self):
        a = Finding("ESC-002", Severity.HIGH, "a.md", 1, 1, "m", "ev")
        b = Finding("ESC-001", Severity.HIGH, "a.md", 1, 1, "m", "ev")
        arr = sorted([a, b], key=lambda x: x.sort_key())
        self.assertEqual([x.rule_id for x in arr], ["ESC-001", "ESC-002"])

    def test_scanresult_defaults(self):
        r = ScanResult()
        self.assertEqual(r.findings, [])
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.errors, [])


if __name__ == "__main__":
    unittest.main()
