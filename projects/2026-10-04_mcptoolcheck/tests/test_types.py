"""Shape tests for mcptoolcheck.types."""

from __future__ import annotations

import unittest

from mcptoolcheck.types import (
    Finding,
    Options,
    ScanResult,
    Severity,
    Verdict,
)


class SeverityTests(unittest.TestCase):
    def test_members(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_ordered_set(self):
        self.assertEqual(
            {Severity.HIGH, Severity.MEDIUM, Severity.INFO},
            set(Severity),
        )


class VerdictTests(unittest.TestCase):
    def test_members(self):
        self.assertEqual(Verdict.HEALTHY.value, "healthy")
        self.assertEqual(Verdict.NEEDS_ATTENTION.value, "needs-attention")
        self.assertEqual(Verdict.UNHEALTHY.value, "unhealthy")
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")


class FindingTests(unittest.TestCase):
    def test_to_dict_roundtrip(self):
        f = Finding(
            rule_id="MTC-001",
            severity=Severity.HIGH,
            message="m",
            tool_name="t",
            pointer="p",
            path="x.json",
            hint="h",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "MTC-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["tool_name"], "t")
        self.assertEqual(d["pointer"], "p")
        self.assertEqual(d["path"], "x.json")
        self.assertEqual(d["hint"], "h")

    def test_frozen(self):
        f = Finding(
            rule_id="MTC-001", severity=Severity.HIGH, message="m",
            tool_name="t", pointer="p",
        )
        with self.assertRaises(Exception):
            f.rule_id = "MTC-002"  # type: ignore


class OptionsTests(unittest.TestCase):
    def test_default_enables_everything(self):
        o = Options()
        self.assertTrue(o.rule_enabled("MTC-001"))
        self.assertTrue(o.rule_enabled("MTC-012"))

    def test_disabled(self):
        o = Options(disabled=("MTC-003",))
        self.assertFalse(o.rule_enabled("MTC-003"))
        self.assertTrue(o.rule_enabled("MTC-004"))

    def test_only(self):
        o = Options(only=("MTC-001",))
        self.assertTrue(o.rule_enabled("MTC-001"))
        self.assertFalse(o.rule_enabled("MTC-002"))

    def test_only_overrides_disable_absence(self):
        o = Options(only=("MTC-001",), disabled=("MTC-002",))
        self.assertTrue(o.rule_enabled("MTC-001"))
        self.assertFalse(o.rule_enabled("MTC-002"))

    def test_only_and_disable_on_same_rule(self):
        o = Options(only=("MTC-001",), disabled=("MTC-001",))
        self.assertFalse(o.rule_enabled("MTC-001"))


class ScanResultTests(unittest.TestCase):
    def test_default_shape(self):
        r = ScanResult()
        self.assertEqual(r.findings, [])
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.tools_scanned, 0)
        self.assertIs(r.verdict, Verdict.UNKNOWN)
        self.assertIsNone(r.error)

    def test_to_dict_includes_verdict(self):
        r = ScanResult()
        d = r.to_dict()
        self.assertIn("verdict", d)
        self.assertIn("findings", d)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
