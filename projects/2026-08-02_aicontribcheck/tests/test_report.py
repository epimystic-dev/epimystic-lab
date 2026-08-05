"""Tests for the report formatters."""

import json
import unittest

from aicontribcheck.report import exit_code, format_json, format_text
from aicontribcheck.rules import rollup, run_rules
from aicontribcheck.types import FileScan, RepoReport, Verdict


def _report(text, kind="contributing", path="MEM"):
    r = RepoReport(root="MEM")
    fs = FileScan(path=path, kind=kind)
    run_rules(fs, text)
    r.files_scanned.append(fs)
    rollup(r)
    return r


class FormatTextTests(unittest.TestCase):
    def test_includes_verdict(self):
        r = _report("AI-generated contributions are welcome.")
        text = format_text(r)
        self.assertIn("verdict", text)
        self.assertIn("allowed", text)

    def test_no_findings_marker(self):
        r = _report("Nothing at all.")
        text = format_text(r)
        # Unknown reports include the AICONTRIB-009 synthetic finding
        # so we should NOT see "(no findings)".
        self.assertIn("AICONTRIB-009", text)

    def test_empty_report_shows_no_findings(self):
        r = RepoReport(root="EMPTY")
        rollup(r)
        # rollup on an empty report yields UNKNOWN but no synthetic finding
        # (no files to attach it to).
        text = format_text(r)
        self.assertIn("no findings", text)


class FormatJsonTests(unittest.TestCase):
    def test_parses_as_json(self):
        r = _report("AI-generated contributions are welcome.")
        parsed = json.loads(format_json(r))
        self.assertEqual(parsed["verdict"], "allowed")
        self.assertIn("summary", parsed)
        self.assertIn("files", parsed)

    def test_summary_has_counts(self):
        r = _report("This project does not accept AI-generated code.")
        parsed = json.loads(format_json(r))
        self.assertIn("counts_by_severity", parsed["summary"])
        self.assertIn("counts_by_rule", parsed["summary"])
        self.assertGreaterEqual(
            parsed["summary"]["counts_by_severity"]["error"], 1
        )

    def test_deterministic(self):
        r = _report("AI-generated contributions are welcome.")
        self.assertEqual(format_json(r), format_json(r))


class ExitCodeTests(unittest.TestCase):
    def test_allowed_is_zero(self):
        r = _report("AI-generated contributions are welcome.")
        self.assertEqual(exit_code(r), 0)

    def test_banned_is_two(self):
        r = _report("This project does not accept AI-generated code.")
        self.assertEqual(exit_code(r), 2)

    def test_conflict_is_two(self):
        r = RepoReport(root="X")
        fs1 = FileScan(path="a", kind="readme")
        run_rules(fs1, "AI-generated contributions are welcome.")
        fs2 = FileScan(path="b", kind="contributing")
        run_rules(fs2, "This project does not accept AI-generated code.")
        r.files_scanned = [fs1, fs2]
        rollup(r)
        self.assertEqual(r.verdict, Verdict.CONFLICT)
        self.assertEqual(exit_code(r), 2)

    def test_conditional_is_one(self):
        r = _report(
            "AI-generated contributions must be disclosed in the PR body."
        )
        self.assertEqual(exit_code(r), 1)

    def test_unknown_default_is_one(self):
        r = _report("Nothing here.")
        self.assertEqual(exit_code(r), 1)

    def test_unknown_with_strict_is_two(self):
        r = _report("Nothing here.")
        self.assertEqual(exit_code(r, strict=True), 2)

    def test_allowed_with_strict_stays_zero(self):
        r = _report("AI-generated contributions are welcome.")
        self.assertEqual(exit_code(r, strict=True), 0)


if __name__ == "__main__":
    unittest.main()
