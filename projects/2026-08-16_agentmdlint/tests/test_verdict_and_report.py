import json
import os
import shutil
import tempfile
import unittest
from datetime import date

from agentmdlint.config import Config
from agentmdlint.report import format_json, format_text
from agentmdlint.scanner import scan_path
from agentmdlint.types import ScanReport, FileReport, Finding, Severity, Verdict
from agentmdlint.verdict import compute_verdict


class TempRepo:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="agentmdlint_vr_")

    def write(self, rel, content):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full) or self.root, exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content.encode("utf-8"))
        return full

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _mk_report(findings, files_scanned=1):
    fr = FileReport(path="t.md", findings=list(findings), bytes_read=100, read_error=None)
    scan = ScanReport(root=".", file_reports=[fr] if files_scanned else [])
    return scan


class TestVerdictRollup(unittest.TestCase):
    def test_healthy(self):
        v, e = compute_verdict(_mk_report([]), Config())
        self.assertEqual(v, Verdict.HEALTHY)
        self.assertEqual(e, 0)

    def test_medium_needs_attention(self):
        f = Finding("AGENTMD-003", Severity.MEDIUM, "dup", "t.md", 1, 0, "")
        v, e = compute_verdict(_mk_report([f]), Config())
        self.assertEqual(v, Verdict.NEEDS_ATTENTION)
        self.assertEqual(e, 1)

    def test_high_unhealthy(self):
        f = Finding("AGENTMD-008", Severity.HIGH, "contradiction", "t.md", 1, 0, "")
        v, e = compute_verdict(_mk_report([f]), Config())
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertEqual(e, 2)

    def test_info_default_healthy(self):
        f = Finding("AGENTMD-004", Severity.INFO, "no rationale", "t.md", 1, 0, "")
        v, e = compute_verdict(_mk_report([f]), Config())
        self.assertEqual(v, Verdict.HEALTHY)
        self.assertEqual(e, 0)

    def test_info_strict_needs_attention(self):
        f = Finding("AGENTMD-004", Severity.INFO, "no rationale", "t.md", 1, 0, "")
        v, e = compute_verdict(_mk_report([f]), Config(), strict=True)
        self.assertEqual(v, Verdict.NEEDS_ATTENTION)
        self.assertEqual(e, 1)

    def test_no_files_unknown(self):
        empty = ScanReport(root=".", file_reports=[])
        v, e = compute_verdict(empty, Config())
        self.assertEqual(v, Verdict.UNKNOWN)
        self.assertEqual(e, 1)

    def test_no_files_strict_exit_2(self):
        empty = ScanReport(root=".", file_reports=[])
        v, e = compute_verdict(empty, Config(), strict=True)
        self.assertEqual(v, Verdict.UNKNOWN)
        self.assertEqual(e, 2)

    def test_high_overrides_medium(self):
        h = Finding("AGENTMD-008", Severity.HIGH, "x", "t.md", 1, 0, "")
        m = Finding("AGENTMD-003", Severity.MEDIUM, "y", "t.md", 2, 0, "")
        v, e = compute_verdict(_mk_report([h, m]), Config())
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertEqual(e, 2)


class TestReportFormatters(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_json_parseable_and_deterministic(self):
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nAgent guide.\n\nYou must use HTTPS.\n",
        )
        r1 = scan_path(self.repo.root, Config())
        r2 = scan_path(self.repo.root, Config())
        j1 = format_json(r1, Config())
        j2 = format_json(r2, Config())
        self.assertEqual(j1, j2)
        payload = json.loads(j1)
        self.assertEqual(payload["tool"], "agentmdlint")
        self.assertIn("verdict", payload)
        self.assertIn("findings", payload)

    def test_text_contains_verdict_line(self):
        f = Finding("AGENTMD-003", Severity.MEDIUM, "dup", "t.md", 1, 0, "")
        out = format_text(_mk_report([f]), Config())
        self.assertIn("verdict:", out)
        self.assertIn("needs-attention", out)
        self.assertIn("AGENTMD-003", out)

    def test_text_hides_info_by_default(self):
        f = Finding("AGENTMD-004", Severity.INFO, "no rationale", "t.md", 1, 0, "")
        out = format_text(_mk_report([f]), Config(), include_info=False)
        self.assertNotIn("AGENTMD-004", out)

    def test_text_shows_info_when_requested(self):
        f = Finding("AGENTMD-004", Severity.INFO, "no rationale", "t.md", 1, 0, "")
        out = format_text(_mk_report([f]), Config(), include_info=True)
        self.assertIn("AGENTMD-004", out)

    def test_json_always_includes_info(self):
        f = Finding("AGENTMD-004", Severity.INFO, "no rationale", "t.md", 1, 0, "")
        j = format_json(_mk_report([f]), Config())
        payload = json.loads(j)
        rule_ids = {ff["rule_id"] for ff in payload["findings"]}
        self.assertIn("AGENTMD-004", rule_ids)

    def test_verdict_line_shows_exit_code(self):
        out = format_text(_mk_report([]), Config())
        self.assertIn("(exit 0)", out)


if __name__ == "__main__":
    unittest.main()
