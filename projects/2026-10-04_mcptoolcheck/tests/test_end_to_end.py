"""End-to-end coverage against the shipped example fixtures and
realistic descriptor shapes."""

from __future__ import annotations

import json
import os
import unittest

from mcptoolcheck.scanner import scan_file
from mcptoolcheck.types import Options, Verdict

from tests.support import rule_ids


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


class ShippedExampleTests(unittest.TestCase):
    def test_healthy_example_scans_clean_under_strict(self):
        p = os.path.join(EXAMPLES_DIR, "healthy_tooldesc.json")
        r = scan_file(p, Options(strict=True, include_info=True))
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.findings, [])

    def test_weak_example_is_unhealthy_with_tag_anchor(self):
        p = os.path.join(EXAMPLES_DIR, "weak_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertIn("MTC-001", rule_ids(r.findings))

    def test_weak_example_also_fires_annotation_mismatch(self):
        # delete_record has readOnlyHint=true in the example - MTC-007.
        p = os.path.join(EXAMPLES_DIR, "weak_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIn("MTC-007", rule_ids(r.findings))

    def test_weak_example_also_fires_missing_pin(self):
        p = os.path.join(EXAMPLES_DIR, "weak_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIn("MTC-006", rule_ids(r.findings))

    def test_weak_example_also_fires_zero_width(self):
        p = os.path.join(EXAMPLES_DIR, "weak_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIn("MTC-003", rule_ids(r.findings))

    def test_weak_example_fires_schema_additional_properties(self):
        p = os.path.join(EXAMPLES_DIR, "weak_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIn("MTC-009", rule_ids(r.findings))


class RealisticShapeTests(unittest.TestCase):
    def test_mcp_tools_list_response_shape(self):
        resp = {
            "tools": [
                {
                    "name": "search",
                    "description": "Full text search.",
                    "annotations": {"readOnlyHint": True,
                                    "destructiveHint": False},
                    "inputSchema": {
                        "type": "object",
                        "properties": {"q": {"type": "string"}},
                        "required": ["q"],
                        "additionalProperties": False,
                    },
                }
            ],
            "version": "1.0.0",
        }
        from mcptoolcheck.scanner import scan_text
        r = scan_text(json.dumps(resp), "resp.json", Options())
        self.assertIs(r.verdict, Verdict.HEALTHY)

    def test_bare_array_shape(self):
        from mcptoolcheck.scanner import scan_text
        payload = [
            {
                "name": "ping", "description": "Return pong.",
                "annotations": {"readOnlyHint": True,
                                "destructiveHint": False},
                "inputSchema": {"type": "object",
                                "properties": {},
                                "additionalProperties": False},
                "version": "0.1.0",
            }
        ]
        r = scan_text(json.dumps(payload), "a.json", Options())
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.tools_scanned, 1)

    def test_dict_keyed_shape(self):
        from mcptoolcheck.scanner import scan_text
        payload = {
            "version": "1.0.0",
            "my_tool": {
                "description": "Does a thing.",
                "annotations": {"readOnlyHint": True,
                                "destructiveHint": False},
                "inputSchema": {"type": "object",
                                "properties": {},
                                "additionalProperties": False},
            },
        }
        r = scan_text(json.dumps(payload), "a.json", Options())
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.tools_scanned, 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
