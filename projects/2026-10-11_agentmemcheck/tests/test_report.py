"""Report formatting tests (text + JSON)."""

from __future__ import annotations

import io
import json
import unittest

from tests import support
from tests.support import build_entry, build_store, scan_dict, tag_char

from agentmemcheck.report import write_json, write_text
from agentmemcheck.scanner import scan_text
from agentmemcheck.types import (
    Finding, Options, ScanResult, Severity, Verdict,
)


def _result_with_hidden_finding() -> ScanResult:
    # The entry_id and the message both carry a raw non-ASCII codepoint
    # so the _visible path has something to transform. A real AMC-001
    # finding describes the TAG by codepoint number (plain ASCII) in
    # the message; here we force a raw TAG into the message directly to
    # exercise the reporter's render path.
    f = Finding(
        rule_id="AMC-001",
        severity=Severity.HIGH,
        message="matched raw " + tag_char() + " inside content",
        entry_id="mem-" + chr(0x0430),
        pointer="memories[0]",
        path="x.json",
        hint="hint",
    )
    r = ScanResult(
        findings=[f], files_scanned=1, entries_scanned=1,
        verdict=Verdict.UNHEALTHY,
    )
    return r


class WriteTextTests(unittest.TestCase):
    def test_hidden_chars_rendered_as_u_plus(self):
        buf = io.StringIO()
        write_text(_result_with_hidden_finding(), buf)
        out = buf.getvalue()
        self.assertIn("<U+E0001>", out)
        self.assertIn("<U+0430>", out)
        self.assertIn("AMC-001", out)
        self.assertIn("hint:", out)

    def test_empty_findings_summary_line(self):
        r = ScanResult(
            findings=[], files_scanned=2, entries_scanned=3,
            verdict=Verdict.HEALTHY,
        )
        buf = io.StringIO()
        write_text(r, buf)
        self.assertIn("files=2", buf.getvalue())
        self.assertIn("entries=3", buf.getvalue())
        self.assertIn("findings=0", buf.getvalue())


class WriteJsonTests(unittest.TestCase):
    def test_json_shape(self):
        buf = io.StringIO()
        write_json(_result_with_hidden_finding(), buf)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed["verdict"], "unhealthy")
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["rule_id"], "AMC-001")

    def test_json_mode_can_round_trip_hidden_character_values(self):
        buf = io.StringIO()
        write_json(_result_with_hidden_finding(), buf)
        parsed = json.loads(buf.getvalue())
        # entry_id contains U+0430 - json default escapes non-ASCII, so
        # the parsed string restores the raw codepoint.
        self.assertEqual(parsed["findings"][0]["entry_id"],
                         "mem-" + chr(0x0430))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
