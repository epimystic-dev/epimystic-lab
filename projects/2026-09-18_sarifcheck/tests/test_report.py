"""Reporter shape, redaction, and determinism."""

from __future__ import annotations

import json
import unittest

from sarifcheck.report import (
    DISCLAIMER,
    format_findings_text,
    format_json,
    format_summary_text,
    visible_findings,
)
from sarifcheck.types import Finding, ScanResult, Severity

from tests.support import base_doc, base_result, base_run, scan_doc


def finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="SRF-004",
        severity=Severity.HIGH,
        path="a.sarif",
        prop="runs[0].results[0].message.text",
        line=7,
        column=3,
        message="an absolute uri",
        snippet="/home/devuser/a.py",
        run_index=0,
        result_index=0,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def result_with(*findings, **kwargs) -> ScanResult:
    return ScanResult(
        files_scanned=kwargs.pop("files_scanned", 1),
        findings=tuple(findings),
        errors=tuple(kwargs.pop("errors", ())),
        notes=tuple(kwargs.pop("notes", ())),
        partial=kwargs.pop("partial", False),
    )


class VisibilityTests(unittest.TestCase):
    def test_info_is_hidden_by_default(self):
        result = result_with(finding(severity=Severity.INFO))
        self.assertEqual(visible_findings(result, include_info=False), [])

    def test_info_is_shown_on_request(self):
        result = result_with(finding(severity=Severity.INFO))
        self.assertEqual(len(visible_findings(result, include_info=True)), 1)

    def test_high_and_medium_are_always_visible(self):
        result = result_with(
            finding(severity=Severity.HIGH), finding(severity=Severity.MEDIUM)
        )
        self.assertEqual(len(visible_findings(result, include_info=False)), 2)


class TextFindingsTests(unittest.TestCase):
    def test_empty_result_prints_nothing_on_stdout(self):
        self.assertEqual(format_findings_text(result_with()), "")

    def test_line_carries_severity_code_path_position_and_property(self):
        text = format_findings_text(result_with(finding()))
        self.assertTrue(text.startswith("HIGH SRF-004 a.sarif:7:3 "))
        self.assertIn("runs[0].results[0].message.text", text)

    def test_match_is_redacted_by_default(self):
        text = format_findings_text(result_with(finding()))
        self.assertNotIn("devuser", text)

    def test_match_is_printed_with_show_matches(self):
        text = format_findings_text(result_with(finding()), show_matches=True)
        self.assertIn("match=", text)
        self.assertIn("devuser", text)

    def test_one_line_per_finding(self):
        text = format_findings_text(result_with(finding(), finding()))
        self.assertEqual(len(text.strip().split("\n")), 2)


class SummaryTests(unittest.TestCase):
    def test_summary_leads_with_the_disclaimer(self):
        text = format_summary_text(result_with())
        self.assertTrue(text.startswith(DISCLAIMER))

    def test_disclaimer_denies_schema_validation_and_acceptance(self):
        self.assertIn("not a JSON Schema validator", DISCLAIMER)
        self.assertIn("not a promise", DISCLAIMER)

    def test_summary_names_the_verdict(self):
        self.assertIn("verdict: healthy", format_summary_text(result_with()))

    def test_summary_counts_by_severity(self):
        text = format_summary_text(
            result_with(finding(), finding(severity=Severity.INFO))
        )
        self.assertIn("findings_total=2", text)
        self.assertIn("high=1", text)
        self.assertIn("info=1", text)

    def test_summary_reports_hidden_count(self):
        text = format_summary_text(result_with(finding(severity=Severity.INFO)))
        self.assertIn("findings_hidden=1", text)

    def test_summary_lists_profiles(self):
        text = format_summary_text(result_with(), profiles=["ingest", "spec"])
        self.assertIn("profiles: ingest,spec", text)

    def test_summary_flags_a_partial_scan(self):
        text = format_summary_text(result_with(partial=True))
        self.assertIn("partial:", text)

    def test_summary_prints_errors(self):
        text = format_summary_text(result_with(errors=("read-error: x",)))
        self.assertIn("ERROR read-error: x", text)

    def test_summary_prints_notes(self):
        text = format_summary_text(result_with(notes=("duplicate-keys: x",)))
        self.assertIn("NOTE duplicate-keys: x", text)

    def test_summary_never_reprints_a_match(self):
        text = format_summary_text(result_with(finding()))
        self.assertNotIn("devuser", text)


class JsonReportTests(unittest.TestCase):
    def payload(self, result, **kwargs):
        return json.loads(
            format_json(result, tool="sarifcheck", version="0.1.0", **kwargs)
        )

    def test_top_level_keys(self):
        payload = self.payload(result_with(finding()))
        for key in (
            "tool", "version", "disclaimer", "verdict", "exit_code",
            "files_scanned", "partial", "profiles", "limits", "counts",
            "findings", "errors", "notes",
        ):
            self.assertIn(key, payload)

    def test_finding_keys(self):
        payload = self.payload(result_with(finding()))
        entry = payload["findings"][0]
        for key in (
            "rule_id", "severity", "path", "property", "line", "column",
            "message", "run_index", "result_index",
        ):
            self.assertIn(key, entry)

    def test_match_is_absent_by_default(self):
        payload = self.payload(result_with(finding()))
        self.assertNotIn("match", payload["findings"][0])

    def test_match_is_present_with_show_matches(self):
        payload = self.payload(result_with(finding()), show_matches=True)
        self.assertEqual(payload["findings"][0]["match"], "/home/devuser/a.py")

    def test_serialised_json_never_contains_the_match_by_default(self):
        text = format_json(result_with(finding()), tool="t", version="0.1.0")
        self.assertNotIn("devuser", text)

    def test_exit_code_is_embedded(self):
        payload = self.payload(result_with(finding()))
        self.assertEqual(payload["exit_code"], 2)

    def test_counts_block(self):
        payload = self.payload(
            result_with(finding(), finding(severity=Severity.INFO))
        )
        self.assertEqual(payload["counts"]["total"], 2)
        self.assertEqual(payload["counts"]["hidden"], 1)
        self.assertEqual(payload["counts"]["visible"], 1)

    def test_limits_are_echoed(self):
        payload = self.payload(result_with(), limits={"max_runs_per_file": 20})
        self.assertEqual(payload["limits"]["max_runs_per_file"], 20)

    def test_keys_are_sorted_for_diffability(self):
        text = format_json(result_with(finding()), tool="t", version="0.1.0")
        first_line_keys = [
            line.strip().split('"')[1]
            for line in text.split("\n")
            if line.startswith("  \"")
        ]
        self.assertEqual(first_line_keys, sorted(first_line_keys))

    def test_output_is_byte_identical_across_calls(self):
        first = format_json(result_with(finding()), tool="t", version="0.1.0")
        second = format_json(result_with(finding()), tool="t", version="0.1.0")
        self.assertEqual(first, second)

    def test_output_is_stable_against_dict_insertion_order(self):
        doc_a = base_doc()
        doc_a["version"] = "2.1"
        doc_b = base_doc()
        doc_b["version"] = "2.1"
        # Rebuild the run dict with the keys in a different insertion order.
        run = base_run(doc_b)
        doc_b["runs"][0] = dict(reversed(list(run.items())))
        text_a = format_json(scan_doc(doc_a), tool="t", version="0.1.0")
        text_b = format_json(scan_doc(doc_b), tool="t", version="0.1.0")
        codes_a = [f["rule_id"] for f in json.loads(text_a)["findings"]]
        codes_b = [f["rule_id"] for f in json.loads(text_b)["findings"]]
        self.assertEqual(codes_a, codes_b)

    def test_trailing_newline(self):
        text = format_json(result_with(), tool="t", version="0.1.0")
        self.assertTrue(text.endswith("\n"))


class ReporterAgainstRealScanTests(unittest.TestCase):
    def test_real_scan_renders_without_the_matched_path(self):
        doc = base_doc()
        base_result(doc)["message"] = {"text": "sink at /home/devuser/a.py"}
        result = scan_doc(doc)
        text = format_findings_text(result)
        self.assertIn("SRF-006", text)
        self.assertNotIn("devuser", text)

    def test_real_scan_renders_the_match_on_request(self):
        doc = base_doc()
        base_result(doc)["message"] = {"text": "sink at /home/devuser/a.py"}
        text = format_findings_text(scan_doc(doc), show_matches=True)
        self.assertIn("devuser", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
