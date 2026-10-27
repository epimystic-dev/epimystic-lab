"""Report tests for renovatelint.report."""

from __future__ import annotations

import io
import json
import unittest

from renovatelint import __version__
from renovatelint.report import write_json, write_text
from renovatelint.types import Finding, ScanResult, Severity, Verdict


def _result_with_findings(*findings):
    r = ScanResult(files_scanned=1)
    r.findings.extend(findings)
    r.verdict = Verdict.UNHEALTHY if any(
        f.severity is Severity.HIGH for f in findings
    ) else Verdict.NEEDS_ATTENTION if findings else Verdict.HEALTHY
    return r


class WriteTextTests(unittest.TestCase):
    def test_clean_result_renders_single_line(self):
        r = ScanResult(files_scanned=1, verdict=Verdict.HEALTHY)
        buf = io.StringIO()
        write_text(r, buf)
        self.assertIn("renovatelint", buf.getvalue())
        self.assertIn("findings=0", buf.getvalue())

    def test_findings_rendered_with_rule_id_and_message(self):
        r = _result_with_findings(Finding(
            rule_id="RNV-001",
            severity=Severity.HIGH,
            message="disabled",
            pointer=".enabled",
            path="x.json",
            hint="use branch protection instead",
        ))
        buf = io.StringIO()
        write_text(r, buf)
        text = buf.getvalue()
        self.assertIn("RNV-001", text)
        self.assertIn("HIGH", text)
        self.assertIn("disabled", text)
        self.assertIn("hint:", text)

    def test_findings_sorted_high_then_medium_then_info(self):
        r = _result_with_findings(
            Finding("RNV-011", Severity.INFO, "info", "<root>", "x", ""),
            Finding("RNV-001", Severity.HIGH, "high", ".enabled", "x", ""),
            Finding("RNV-006", Severity.MEDIUM, "medium", ".x", "x", ""),
        )
        buf = io.StringIO()
        write_text(r, buf)
        text = buf.getvalue()
        high_idx = text.index("RNV-001")
        med_idx = text.index("RNV-006")
        info_idx = text.index("RNV-011")
        self.assertLess(high_idx, med_idx)
        self.assertLess(med_idx, info_idx)

    def test_non_ascii_rendered_as_escape(self):
        r = _result_with_findings(Finding(
            rule_id="RNV-006",
            severity=Severity.MEDIUM,
            message="string value contains TAG block at offset 0",
            pointer=".timezone",
            path="x" + chr(0xE0041),
            hint="",
        ))
        buf = io.StringIO()
        write_text(r, buf)
        text = buf.getvalue()
        # The actual Plane-14 character must not appear in output.
        self.assertNotIn(chr(0xE0041), text)
        self.assertIn("<U+E0041>", text)


class WriteJSONTests(unittest.TestCase):
    def test_includes_tool_and_version(self):
        r = ScanResult(files_scanned=1, verdict=Verdict.HEALTHY)
        buf = io.StringIO()
        write_json(r, buf)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["tool"], "renovatelint")
        self.assertEqual(doc["version"], __version__)
        self.assertEqual(doc["verdict"], "healthy")
        self.assertEqual(doc["files_scanned"], 1)

    def test_findings_serialised(self):
        r = _result_with_findings(Finding(
            rule_id="RNV-001",
            severity=Severity.HIGH,
            message="disabled",
            pointer=".enabled",
            path="x.json",
            hint="",
        ))
        buf = io.StringIO()
        write_json(r, buf)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["findings"][0]["rule_id"], "RNV-001")
        self.assertEqual(doc["findings"][0]["severity"], "HIGH")

    def test_json_ensure_ascii_default(self):
        """A finding carrying a Plane-14 TAG codepoint should still be
        JSON-encoded ASCII-safely by json.dump's default behavior."""
        r = _result_with_findings(Finding(
            rule_id="RNV-006",
            severity=Severity.MEDIUM,
            message="see char " + chr(0xE0041),
            pointer=".x",
            path="x",
            hint="",
        ))
        buf = io.StringIO()
        write_json(r, buf)
        text = buf.getvalue()
        # json.dump default is ensure_ascii=True, so Plane-14 is
        # escaped rather than written raw.
        self.assertNotIn(chr(0xE0041), text)
        self.assertIn("\\udb40", text.lower())  # the surrogate pair for E0041


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
