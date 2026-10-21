"""End-to-end sanity: healthy and weak fixtures through scan_paths."""

from __future__ import annotations

import os
import unittest

from devcontainercheck.scanner import scan_paths
from devcontainercheck.types import Options, Verdict


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX = os.path.join(PKG_DIR, "examples")


class EndToEndHealthyTests(unittest.TestCase):
    def test_healthy_default(self):
        r = scan_paths(
            [os.path.join(EX, "healthy_devcontainer.json")], Options()
        )
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.findings, [])

    def test_healthy_strict_include_info(self):
        r = scan_paths(
            [os.path.join(EX, "healthy_devcontainer.json")],
            Options(strict=True, include_info=True),
        )
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.findings, [])


class EndToEndWeakTests(unittest.TestCase):
    def test_weak_default(self):
        r = scan_paths(
            [os.path.join(EX, "weak_devcontainer.json")], Options()
        )
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        ids = {f.rule_id for f in r.findings}
        for expected in (
            "DC-001", "DC-002", "DC-003", "DC-006", "DC-007",
            "DC-008", "DC-009", "DC-010",
        ):
            self.assertIn(expected, ids, "expected " + expected + " to fire")

    def test_weak_include_info_adds_dc011(self):
        r = scan_paths(
            [os.path.join(EX, "weak_devcontainer.json")],
            Options(include_info=True),
        )
        ids = {f.rule_id for f in r.findings}
        self.assertIn("DC-011", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
