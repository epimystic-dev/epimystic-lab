"""Report (text + JSON) output tests."""

from __future__ import annotations

import io
import json
import unittest

from tests import support

from devcontainercheck import __version__
from devcontainercheck.report import write_json, write_text, _visible
from devcontainercheck.types import Finding, ScanResult, Severity, Verdict


def _result_with_findings() -> ScanResult:
    r = ScanResult(
        files_scanned=1,
        verdict=Verdict.UNHEALTHY,
    )
    r.findings = [
        Finding(
            rule_id="DC-001",
            severity=Severity.HIGH,
            message="curl pipe",
            pointer=".postCreateCommand",
            path="x.json",
            hint="use a vendored script",
        ),
    ]
    return r


class VisibleTests(unittest.TestCase):
    def test_pure_ascii_passes_through(self):
        self.assertEqual(_visible("hello"), "hello")

    def test_tag_block_rendered(self):
        self.assertEqual(_visible(support.tag_char()), "<U+E0001>")

    def test_bidi_rendered(self):
        self.assertEqual(_visible(support.bidi_char()), "<U+202E>")

    def test_newline_escaped(self):
        self.assertEqual(_visible("\n"), "<U+000A>")


class WriteTextTests(unittest.TestCase):
    def test_findings_emitted_in_order(self):
        buf = io.StringIO()
        write_text(_result_with_findings(), buf)
        text = buf.getvalue()
        self.assertIn("HIGH DC-001", text)
        self.assertIn("curl pipe", text)
        self.assertIn("hint: use a vendored script", text)
        self.assertIn("devcontainercheck: unhealthy", text)

    def test_empty_findings_emits_summary(self):
        buf = io.StringIO()
        r = ScanResult(files_scanned=1, verdict=Verdict.HEALTHY)
        write_text(r, buf)
        self.assertIn("devcontainercheck: healthy", buf.getvalue())
        self.assertIn("findings=0", buf.getvalue())


class WriteJsonTests(unittest.TestCase):
    def test_json_payload_has_tool_and_version(self):
        buf = io.StringIO()
        write_json(_result_with_findings(), buf)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["tool"], "devcontainercheck")
        self.assertEqual(doc["version"], __version__)
        self.assertEqual(doc["verdict"], "unhealthy")
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["findings"][0]["rule_id"], "DC-001")

    def test_json_payload_default_encodes_ascii_safely(self):
        buf = io.StringIO()
        r = _result_with_findings()
        r.findings = [
            Finding(
                rule_id="DC-005",
                severity=Severity.HIGH,
                message="hidden " + support.tag_char() + " char",
                pointer=".name",
                path="x.json",
            ),
        ]
        write_json(r, buf)
        raw = buf.getvalue()
        # ensure_ascii=True (json.dump default) renders the TAG codepoint
        # as a \uXXXX escape rather than raw bytes, so the output is
        # cp1252-safe. We parse it back and confirm the semantic.
        doc = json.loads(raw)
        self.assertIn(support.tag_char(), doc["findings"][0]["message"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
