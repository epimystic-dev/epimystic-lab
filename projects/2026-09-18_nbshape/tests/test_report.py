"""Reporter shapes and the stdout / stderr split."""

from __future__ import annotations

import json
import unittest

from nbshape.report import format_findings, format_json, format_summary, visible_findings
from nbshape.types import Finding, ScanResult, Severity


def f(sev, rule_id="NBK-001", cell=0, path="a.ipynb"):
    return Finding(
        rule_id=rule_id, severity=sev, path=path, cell=cell,
        line=3, column=5, message="a message", snippet="a snippet",
    )


def result(findings=(), scanned=1, scored=1, unknown=0, errors=()):
    return ScanResult(
        files_scanned=scanned, files_scored=scored, files_unknown=unknown,
        findings=tuple(findings), errors=tuple(errors),
    )


class VisibilityTests(unittest.TestCase):
    def test_high_and_medium_are_visible_by_default(self):
        r = result([f(Severity.HIGH), f(Severity.MEDIUM)])
        self.assertEqual(len(visible_findings(r, include_info=False)), 2)

    def test_info_is_hidden_by_default(self):
        r = result([f(Severity.INFO, "NBK-004")])
        self.assertEqual(visible_findings(r, include_info=False), [])

    def test_info_appears_with_include_info(self):
        r = result([f(Severity.INFO, "NBK-004")])
        self.assertEqual(len(visible_findings(r, include_info=True)), 1)

    def test_the_gate_rule_stays_visible_even_though_it_is_info(self):
        r = result([f(Severity.INFO, "NBK-010")])
        self.assertEqual(len(visible_findings(r, include_info=False)), 1)


class TextFindingTests(unittest.TestCase):
    def test_a_clean_result_produces_no_stdout_at_all(self):
        self.assertEqual(format_findings(result()), "")

    def test_a_hidden_info_only_result_produces_no_stdout(self):
        self.assertEqual(format_findings(result([f(Severity.INFO, "NBK-004")])), "")

    def test_a_finding_line_carries_severity_rule_path_and_position(self):
        out = format_findings(result([f(Severity.HIGH, "NBK-002")]))
        self.assertIn("HIGH", out)
        self.assertIn("NBK-002", out)
        self.assertIn("a.ipynb:3:5", out)
        self.assertIn("a message", out)

    def test_a_cell_level_finding_names_its_cell(self):
        out = format_findings(result([f(Severity.HIGH, cell=4)]))
        self.assertIn("[cell 4]", out)

    def test_a_notebook_level_finding_says_notebook(self):
        out = format_findings(result([f(Severity.HIGH, cell=-1)]))
        self.assertIn("[notebook]", out)

    def test_every_finding_gets_its_own_line(self):
        out = format_findings(result([f(Severity.HIGH), f(Severity.MEDIUM)]))
        self.assertEqual(len([ln for ln in out.splitlines() if ln.strip()]), 2)

    def test_the_output_ends_with_a_newline(self):
        self.assertTrue(format_findings(result([f(Severity.HIGH)])).endswith("\n"))


class SummaryTests(unittest.TestCase):
    def test_the_summary_leads_with_the_verdict(self):
        self.assertTrue(format_summary(result()).startswith("verdict: healthy"))

    def test_the_summary_reports_the_file_split(self):
        out = format_summary(result(scanned=3, scored=2, unknown=1))
        self.assertIn("files_scanned=3", out)
        self.assertIn("files_scored=2", out)
        self.assertIn("files_unknown=1", out)

    def test_the_summary_counts_hidden_findings(self):
        out = format_summary(result([f(Severity.INFO, "NBK-004")]))
        self.assertIn("info=1", out)
        self.assertIn("hidden=1", out)

    def test_the_summary_reports_each_diagnostic(self):
        out = format_summary(result(errors=("read-error: x", "unparseable: y")))
        self.assertIn("read-error: x", out)
        self.assertIn("unparseable: y", out)

    def test_strict_changes_the_verdict_line(self):
        r = result([f(Severity.INFO, "NBK-004")])
        self.assertIn("healthy", format_summary(r).splitlines()[0])
        self.assertIn("needs-attention", format_summary(r, strict=True).splitlines()[0])


class JsonTests(unittest.TestCase):
    def test_the_payload_is_valid_json(self):
        json.loads(format_json(result([f(Severity.HIGH)])))

    def test_the_payload_names_the_tool(self):
        self.assertEqual(json.loads(format_json(result()))["tool"], "nbshape")

    def test_the_payload_carries_the_documented_top_level_keys(self):
        doc = json.loads(format_json(result()))
        for key in ("tool", "verdict", "exit_code", "files_scanned", "files_scored",
                    "files_unknown", "counts", "findings", "errors"):
            self.assertIn(key, doc)

    def test_the_exit_code_in_the_payload_matches_the_verdict(self):
        doc = json.loads(format_json(result([f(Severity.HIGH)])))
        self.assertEqual(doc["verdict"], "unhealthy")
        self.assertEqual(doc["exit_code"], 2)

    def test_each_finding_carries_the_documented_fields(self):
        doc = json.loads(format_json(result([f(Severity.HIGH)])))
        for key in ("rule_id", "severity", "path", "cell", "line", "column",
                    "message", "snippet"):
            self.assertIn(key, doc["findings"][0])

    def test_hidden_info_findings_are_counted_but_not_listed(self):
        doc = json.loads(format_json(result([f(Severity.INFO, "NBK-004")])))
        self.assertEqual(doc["counts"]["info"], 1)
        self.assertEqual(doc["findings"], [])

    def test_include_info_lists_them(self):
        doc = json.loads(
            format_json(result([f(Severity.INFO, "NBK-004")]), include_info=True)
        )
        self.assertEqual(len(doc["findings"]), 1)

    def test_the_payload_is_deterministic_across_calls(self):
        r = result([f(Severity.HIGH), f(Severity.MEDIUM)])
        self.assertEqual(format_json(r), format_json(r))

    def test_the_payload_keys_are_sorted_so_diffs_are_stable(self):
        text = format_json(result())
        keys = [ln.strip().split('"')[1] for ln in text.splitlines()
                if ln.startswith('  "')]
        self.assertEqual(keys, sorted(keys))

    def test_strict_is_reflected_in_the_payload_exit_code(self):
        r = result([f(Severity.INFO, "NBK-004")])
        self.assertEqual(json.loads(format_json(r))["exit_code"], 0)
        self.assertEqual(json.loads(format_json(r, strict=True))["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
