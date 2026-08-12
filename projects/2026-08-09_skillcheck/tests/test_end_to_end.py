"""End-to-end fixture smoke tests: verdict-per-fixture-repo shape."""

from __future__ import annotations

import io
import os
import unittest

from skillcheck.cli import main
from skillcheck.scanner import scan_path
from skillcheck.verdict import Verdict


HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


class TestFixtureVerdicts(unittest.TestCase):
    def test_safe_skill_verdict(self):
        r = scan_path(os.path.join(FIXTURES, "safe_skill"))
        self.assertEqual(r.verdict, Verdict.SAFE)
        self.assertEqual(r.findings, [])

    def test_shell_skill_verdict(self):
        r = scan_path(os.path.join(FIXTURES, "shell_skill"))
        self.assertEqual(r.verdict, Verdict.UNSAFE)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("SKILLCHECK-001", rule_ids)
        self.assertIn("SKILLCHECK-002", rule_ids)

    def test_exfil_skill_verdict(self):
        r = scan_path(os.path.join(FIXTURES, "exfil_skill"))
        self.assertEqual(r.verdict, Verdict.UNSAFE)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertTrue(
            {"SKILLCHECK-003", "SKILLCHECK-008"} & rule_ids,
            f"expected exfil rules to fire, got {rule_ids}",
        )

    def test_obfus_skill_verdict(self):
        r = scan_path(os.path.join(FIXTURES, "obfus_skill"))
        self.assertEqual(r.verdict, Verdict.UNSAFE)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("SKILLCHECK-005", rule_ids)
        self.assertIn("SKILLCHECK-007", rule_ids)

    def test_injection_skill_verdict(self):
        r = scan_path(os.path.join(FIXTURES, "injection_skill"))
        self.assertEqual(r.verdict, Verdict.SUSPICIOUS)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("SKILLCHECK-006", rule_ids)

    def test_unknown_skill_verdict(self):
        r = scan_path(os.path.join(FIXTURES, "unknown_skill"))
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("SKILLCHECK-009", rule_ids)


class TestFixtureCLI(unittest.TestCase):
    def _run(self, args):
        out, err = io.StringIO(), io.StringIO()
        code = main(args, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_safe_exit_0(self):
        code, out, err = self._run([os.path.join(FIXTURES, "safe_skill")])
        self.assertEqual(code, 0)

    def test_unsafe_exit_2(self):
        code, out, err = self._run([os.path.join(FIXTURES, "shell_skill")])
        self.assertEqual(code, 2)

    def test_unknown_default_exit_1(self):
        code, out, err = self._run([os.path.join(FIXTURES, "unknown_skill")])
        self.assertEqual(code, 1)

    def test_unknown_strict_exit_2(self):
        code, out, err = self._run([os.path.join(FIXTURES, "unknown_skill"), "--strict"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
