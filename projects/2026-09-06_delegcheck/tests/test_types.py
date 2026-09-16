import unittest

from delegcheck.types import Finding, ScanResult, Severity, Verdict, severity_rank


class TestSeverityEnum(unittest.TestCase):

    def test_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_rank_order(self):
        self.assertLess(severity_rank(Severity.HIGH), severity_rank(Severity.MEDIUM))
        self.assertLess(severity_rank(Severity.MEDIUM), severity_rank(Severity.INFO))


class TestVerdictEnum(unittest.TestCase):

    def test_values(self):
        self.assertEqual(Verdict.HEALTHY.value, "healthy")
        self.assertEqual(Verdict.NEEDS_ATTENTION.value, "needs-attention")
        self.assertEqual(Verdict.UNHEALTHY.value, "unhealthy")
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")


class TestFinding(unittest.TestCase):

    def _f(self, **kw):
        base = dict(
            rule_id="DEL-001", severity=Severity.HIGH, path="a.json",
            line=2, column=3, message="m", snippet="s",
        )
        base.update(kw)
        return Finding(**base)

    def test_finding_is_frozen(self):
        f = self._f()
        with self.assertRaises(Exception):
            f.rule_id = "DEL-002"

    def test_sort_key_severity_first(self):
        high = self._f(severity=Severity.HIGH)
        med = self._f(severity=Severity.MEDIUM)
        info = self._f(severity=Severity.INFO)
        keys = [high.sort_key(), med.sort_key(), info.sort_key()]
        self.assertEqual(keys, sorted(keys))

    def test_sort_key_path_then_line_then_col_then_rule(self):
        a1 = self._f(path="a.json", line=1, column=1, rule_id="DEL-001")
        a2 = self._f(path="a.json", line=1, column=1, rule_id="DEL-002")
        b1 = self._f(path="b.json", line=1, column=1, rule_id="DEL-001")
        a1_l2 = self._f(path="a.json", line=2, column=1, rule_id="DEL-001")
        a1_c2 = self._f(path="a.json", line=1, column=2, rule_id="DEL-001")
        keys = [a1.sort_key(), a2.sort_key(), a1_c2.sort_key(),
                a1_l2.sort_key(), b1.sort_key()]
        self.assertEqual(keys, sorted(keys))


class TestScanResultDefaults(unittest.TestCase):

    def test_defaults(self):
        r = ScanResult()
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.findings, tuple())
        self.assertEqual(r.errors, tuple())


if __name__ == "__main__":
    unittest.main()
