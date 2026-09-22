import unittest

from pjhookcheck.types import (
    Finding, Options, ScanResult, Severity, Verdict, severity_rank,
)


class TestEnums(unittest.TestCase):
    def test_severity_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_verdict_values(self):
        self.assertEqual(Verdict.HEALTHY.value, "healthy")
        self.assertEqual(Verdict.NEEDS_ATTENTION.value, "needs-attention")
        self.assertEqual(Verdict.UNHEALTHY.value, "unhealthy")
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")

    def test_severity_rank_ordering(self):
        self.assertLess(severity_rank(Severity.HIGH), severity_rank(Severity.MEDIUM))
        self.assertLess(severity_rank(Severity.MEDIUM), severity_rank(Severity.INFO))


class TestFinding(unittest.TestCase):
    def _make(self, **kw):
        base = dict(
            rule_id="PJH-001", severity=Severity.HIGH, path="p.json",
            prop="scripts.install", line=3, column=5, message="msg",
        )
        base.update(kw)
        return Finding(**base)

    def test_finding_is_frozen(self):
        f = self._make()
        with self.assertRaises(Exception):
            f.rule_id = "PJH-999"  # type: ignore

    def test_sort_key_shape(self):
        f = self._make()
        key = f.sort_key()
        self.assertEqual(len(key), 5)
        self.assertEqual(key[0], "p.json")
        self.assertEqual(key[1], 3)
        self.assertEqual(key[2], 5)
        self.assertEqual(key[3], "PJH-001")

    def test_sort_key_orders_by_file_then_line(self):
        a = self._make(path="a.json", line=10)
        b = self._make(path="a.json", line=2)
        c = self._make(path="b.json", line=1)
        result = sorted([a, b, c], key=Finding.sort_key)
        self.assertEqual([f.line for f in result[:2]], [2, 10])
        self.assertEqual(result[2].path, "b.json")

    def test_sort_tiebreak_rule_id(self):
        a = self._make(rule_id="PJH-005")
        b = self._make(rule_id="PJH-001")
        result = sorted([a, b], key=Finding.sort_key)
        self.assertEqual([f.rule_id for f in result], ["PJH-001", "PJH-005"])


class TestScanResultDefault(unittest.TestCase):
    def test_default_empty(self):
        r = ScanResult()
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.findings, ())
        self.assertEqual(r.errors, ())


class TestOptionsDefault(unittest.TestCase):
    def test_default_options(self):
        o = Options()
        self.assertEqual(o.disabled, frozenset())
        self.assertFalse(o.strict)
        self.assertFalse(o.include_info)
        self.assertGreater(o.max_files, 0)
        self.assertGreater(o.max_bytes, 0)


if __name__ == "__main__":
    unittest.main()
