import io
import json
import unittest

from approvchainlint.report import render_json, render_text
from approvchainlint.types import Finding, Options, ScanResult, Severity, Verdict


def _mk_scan(findings, files=1, errors=()):
    return ScanResult(files_scanned=files, findings=tuple(findings), errors=tuple(errors))


def _finding(rid, sev, prop="permissions.allow[0]", msg="m"):
    return Finding(rule_id=rid, severity=sev, path="p.json", prop=prop,
                   line=1, column=1, message=msg, snippet="snip")


class TestRenderText(unittest.TestCase):
    def test_findings_on_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-001", Severity.HIGH)])
        render_text(r, Verdict.UNHEALTHY, Options(), out, err)
        text = out.getvalue()
        self.assertIn("AC-001", text)
        self.assertIn("HIGH", text)
        self.assertIn("permissions.allow[0]", text)

    def test_summary_on_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-001", Severity.HIGH)])
        render_text(r, Verdict.UNHEALTHY, Options(), out, err)
        e = err.getvalue()
        self.assertIn("approvchainlint:", e)
        self.assertIn("verdict=unhealthy", e)
        self.assertIn("high=1", e)

    def test_info_hidden_by_default(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-011", Severity.INFO)])
        render_text(r, Verdict.HEALTHY, Options(), out, err)
        self.assertNotIn("AC-011", out.getvalue())

    def test_info_shown_with_include_info(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-011", Severity.INFO)])
        render_text(r, Verdict.NEEDS_ATTENTION, Options(include_info=True), out, err)
        self.assertIn("AC-011", out.getvalue())

    def test_errors_listed(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([], files=0, errors=("boom",))
        render_text(r, Verdict.UNHEALTHY, Options(), out, err)
        self.assertIn("boom", err.getvalue())


class TestRenderJson(unittest.TestCase):
    def test_valid_json(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-001", Severity.HIGH)])
        render_json(r, Verdict.UNHEALTHY, Options(), out, err)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["tool"], "approvchainlint")
        self.assertEqual(doc["verdict"], "unhealthy")
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["findings"][0]["rule"], "AC-001")

    def test_deterministic(self):
        out1, err1 = io.StringIO(), io.StringIO()
        out2, err2 = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-001", Severity.HIGH),
                      _finding("AC-002", Severity.HIGH)])
        render_json(r, Verdict.UNHEALTHY, Options(), out1, err1)
        render_json(r, Verdict.UNHEALTHY, Options(), out2, err2)
        self.assertEqual(out1.getvalue(), out2.getvalue())

    def test_info_hidden_by_default(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-011", Severity.INFO)])
        render_json(r, Verdict.HEALTHY, Options(), out, err)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["findings"], [])

    def test_info_shown_with_include_info(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-011", Severity.INFO)])
        render_json(r, Verdict.NEEDS_ATTENTION, Options(include_info=True), out, err)
        doc = json.loads(out.getvalue())
        self.assertEqual(len(doc["findings"]), 1)

    def test_errors_field(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([], files=0, errors=("boom",))
        render_json(r, Verdict.UNHEALTHY, Options(), out, err)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["errors"], ["boom"])

    def test_json_has_version(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-001", Severity.HIGH)])
        render_json(r, Verdict.UNHEALTHY, Options(), out, err)
        doc = json.loads(out.getvalue())
        self.assertIn("version", doc)

    def test_json_has_summary(self):
        out, err = io.StringIO(), io.StringIO()
        r = _mk_scan([_finding("AC-001", Severity.HIGH),
                      _finding("AC-006", Severity.MEDIUM)])
        render_json(r, Verdict.UNHEALTHY, Options(), out, err)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["summary"]["high"], 1)
        self.assertEqual(doc["summary"]["medium"], 1)


if __name__ == "__main__":
    unittest.main()
