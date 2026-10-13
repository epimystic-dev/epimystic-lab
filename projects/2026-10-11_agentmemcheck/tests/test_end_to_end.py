"""End-to-end: the shipped example files behave as documented."""

from __future__ import annotations

import os
import unittest

from tests import support

from agentmemcheck.scanner import scan_file
from agentmemcheck.types import Options, Verdict


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


class ShippedExamplesTests(unittest.TestCase):
    def test_healthy_example_is_healthy_default(self):
        path = os.path.join(EXAMPLES, "healthy_memstore.json")
        self.assertTrue(os.path.isfile(path))
        r = scan_file(path, Options())
        self.assertIs(r.verdict, Verdict.HEALTHY, r.findings)

    def test_healthy_example_is_healthy_strict(self):
        path = os.path.join(EXAMPLES, "healthy_memstore.json")
        r = scan_file(path, Options(strict=True, include_info=True))
        # schema_version is present, no oversize, so even under
        # --strict --include-info the file must remain healthy.
        self.assertIs(r.verdict, Verdict.HEALTHY, r.findings)

    def test_weak_example_is_unhealthy(self):
        path = os.path.join(EXAMPLES, "weak_memstore.json")
        self.assertTrue(os.path.isfile(path))
        r = scan_file(path, Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY, r.findings)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("AMC-001", rule_ids)

    def test_weak_example_fires_the_documented_rules(self):
        path = os.path.join(EXAMPLES, "weak_memstore.json")
        r = scan_file(path, Options(strict=True, include_info=True))
        rule_ids = {f.rule_id for f in r.findings}
        # Minimum set the fixture is designed to fire. Documented in
        # the README.
        for rid in ("AMC-001", "AMC-002", "AMC-003", "AMC-006",
                    "AMC-007", "AMC-008", "AMC-012"):
            self.assertIn(rid, rule_ids,
                          "expected " + rid + " on weak_memstore.json; "
                          + "got " + repr(rule_ids))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
