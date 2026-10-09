"""End-to-end scanner tests at the file level."""

from __future__ import annotations

import json
import os
import unittest

from mcptoolcheck.scanner import scan_file, scan_paths, scan_text
from mcptoolcheck.types import Options, Verdict

from tests.support import (
    build_doc,
    build_tool,
    rule_ids,
    tag_char,
    write_temp,
)


class ScanTextTests(unittest.TestCase):
    def test_invalid_json_yields_mtc_000(self):
        r = scan_text("{bad json", "x.json", Options())
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].rule_id, "MTC-000")
        self.assertIs(r.verdict, Verdict.UNHEALTHY)

    def test_clean_document_is_healthy(self):
        doc = build_doc([build_tool()])
        r = scan_text(json.dumps(doc), "x.json", Options())
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.findings, [])

    def test_tool_count(self):
        doc = build_doc([build_tool(), build_tool(name="read_file2")])
        r = scan_text(json.dumps(doc), "x.json", Options())
        self.assertEqual(r.tools_scanned, 2)


class ScanFileTests(unittest.TestCase):
    def test_missing_file_is_unhealthy(self):
        r = scan_file("/no/such/path/x.json", Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].rule_id, "MTC-000")

    def test_shipped_healthy_example(self):
        here = os.path.abspath(os.path.dirname(__file__))
        root = os.path.abspath(os.path.join(here, ".."))
        p = os.path.join(root, "examples", "healthy_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIs(r.verdict, Verdict.HEALTHY)

    def test_shipped_weak_example_fires_tag_block(self):
        here = os.path.abspath(os.path.dirname(__file__))
        root = os.path.abspath(os.path.join(here, ".."))
        p = os.path.join(root, "examples", "weak_tooldesc.json")
        r = scan_file(p, Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertIn("MTC-001", rule_ids(r.findings))


class ScanPathsTests(unittest.TestCase):
    def test_directory_walk(self):
        d, _p1 = write_temp(
            build_doc([build_tool(
                description="hello" + tag_char() + " world and beyond"
            )]),
            name="a.json",
        )
        # Second file in the same dir.
        p2 = os.path.join(d, "b.json")
        with open(p2, "w", encoding="utf-8") as f:
            json.dump(build_doc([build_tool()]), f)
        r = scan_paths([d], Options())
        self.assertEqual(r.files_scanned, 2)
        self.assertIn("MTC-001", rule_ids(r.findings))

    def test_merged_verdict_follows_worst(self):
        # Two files, one clean, one UNHEALTHY: merged is UNHEALTHY.
        d1, p1 = write_temp(build_doc([build_tool()]), name="good.json")
        d2, p2 = write_temp(
            build_doc([build_tool(
                description="hello" + tag_char() + " world and beyond"
            )]),
            name="bad.json",
        )
        r = scan_paths([p1, p2], Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(r.files_scanned, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
