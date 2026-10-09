"""Text/JSON output formatting."""

from __future__ import annotations

import io
import json
import unittest

from mcptoolcheck.report import write_json, write_text
from mcptoolcheck.scanner import scan_text
from mcptoolcheck.types import Options

from tests.support import build_doc, build_tool, tag_char


def _run_clean():
    return scan_text(
        json.dumps(build_doc([build_tool()])), "x.json", Options()
    )


def _run_dirty():
    return scan_text(
        json.dumps(build_doc([build_tool(
            description="hello" + tag_char() + " world and beyond"
        )])),
        "x.json",
        Options(),
    )


class TextOutputTests(unittest.TestCase):
    def test_clean_text_output_includes_verdict(self):
        buf = io.StringIO()
        write_text(_run_clean(), buf)
        self.assertIn("healthy", buf.getvalue())
        self.assertIn("findings=0", buf.getvalue())

    def test_dirty_text_output_includes_rule_anchor(self):
        buf = io.StringIO()
        write_text(_run_dirty(), buf)
        self.assertIn("MTC-001", buf.getvalue())
        self.assertIn("unhealthy", buf.getvalue())
        self.assertIn("hint:", buf.getvalue())


class JsonOutputTests(unittest.TestCase):
    def test_clean_json_shape(self):
        buf = io.StringIO()
        write_json(_run_clean(), buf)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["verdict"], "healthy")
        self.assertEqual(doc["files_scanned"], 1)
        self.assertEqual(doc["findings"], [])

    def test_dirty_json_shape(self):
        buf = io.StringIO()
        write_json(_run_dirty(), buf)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["verdict"], "unhealthy")
        ids = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("MTC-001", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
