"""End-to-end fixture smoke tests. Ensures the whole pipeline
(discover -> read -> rules -> rollup -> format) is coherent on each of
the shipped fixture repos.
"""

import unittest
from pathlib import Path

from aicontribcheck.cli import scan_repo
from aicontribcheck.report import exit_code, format_json, format_text
from aicontribcheck.types import Verdict


FIXTURES = Path(__file__).parent / "fixtures"


class EndToEndTests(unittest.TestCase):
    def test_ban_repo(self):
        r = scan_repo(str(FIXTURES / "ban_repo"))
        self.assertEqual(r.verdict, Verdict.BANNED)
        self.assertEqual(exit_code(r), 2)
        self.assertTrue(format_json(r).startswith("{"))
        self.assertIn("banned", format_text(r))

    def test_allow_repo(self):
        r = scan_repo(str(FIXTURES / "allow_repo"))
        self.assertEqual(r.verdict, Verdict.ALLOWED)
        self.assertEqual(exit_code(r), 0)

    def test_conditional_repo(self):
        r = scan_repo(str(FIXTURES / "conditional_repo"))
        self.assertEqual(r.verdict, Verdict.CONDITIONAL)
        self.assertEqual(exit_code(r), 1)
        self.assertTrue(r.required_disclosures)

    def test_unknown_repo(self):
        r = scan_repo(str(FIXTURES / "unknown_repo"))
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(exit_code(r), 1)

    def test_conflict_repo(self):
        r = scan_repo(str(FIXTURES / "conflict_repo"))
        self.assertEqual(r.verdict, Verdict.CONFLICT)
        self.assertEqual(exit_code(r), 2)


if __name__ == "__main__":
    unittest.main()
