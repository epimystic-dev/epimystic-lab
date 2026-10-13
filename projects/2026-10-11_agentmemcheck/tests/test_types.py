"""Shape tests on the public datatypes."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from agentmemcheck.types import (
    Finding, Options, ScanResult, Severity, Verdict,
)


class SeverityTests(unittest.TestCase):
    def test_three_members(self):
        self.assertEqual(
            {s.value for s in Severity},
            {"HIGH", "MEDIUM", "INFO"},
        )


class VerdictTests(unittest.TestCase):
    def test_four_members(self):
        self.assertEqual(
            {v.value for v in Verdict},
            {"healthy", "needs-attention", "unhealthy", "unknown"},
        )


class FindingTests(unittest.TestCase):
    def test_to_dict_round_trip(self):
        f = Finding(
            rule_id="AMC-001",
            severity=Severity.HIGH,
            message="msg",
            entry_id="mem-1",
            pointer="memories[0]",
            path="x.json",
            hint="h",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "AMC-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["entry_id"], "mem-1")


class ScanResultTests(unittest.TestCase):
    def test_defaults(self):
        r = ScanResult()
        self.assertEqual(r.findings, [])
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.entries_scanned, 0)
        self.assertIs(r.verdict, Verdict.UNKNOWN)
        self.assertIsNone(r.error)

    def test_to_dict_shape(self):
        r = ScanResult()
        d = r.to_dict()
        self.assertIn("verdict", d)
        self.assertIn("files_scanned", d)
        self.assertIn("entries_scanned", d)
        self.assertIn("findings", d)
        self.assertIn("error", d)


class OptionsTests(unittest.TestCase):
    def test_rule_enabled_default(self):
        o = Options()
        self.assertTrue(o.rule_enabled("AMC-001"))

    def test_disable(self):
        o = Options(disabled=("AMC-001",))
        self.assertFalse(o.rule_enabled("AMC-001"))
        self.assertTrue(o.rule_enabled("AMC-002"))

    def test_only(self):
        o = Options(only=("AMC-003",))
        self.assertFalse(o.rule_enabled("AMC-001"))
        self.assertTrue(o.rule_enabled("AMC-003"))

    def test_external_sources_defaults(self):
        o = Options()
        self.assertIn("web", o.external_sources)
        self.assertIn("tool", o.external_sources)
        self.assertIn("retrieval", o.external_sources)

    def test_elevated_roles_defaults(self):
        o = Options()
        self.assertIn("system", o.elevated_roles)
        self.assertIn("instruction", o.elevated_roles)
        self.assertIn("persistent", o.elevated_roles)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
