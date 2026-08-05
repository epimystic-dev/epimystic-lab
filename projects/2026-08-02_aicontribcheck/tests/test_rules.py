"""Tests for the rule engine and rollup logic."""

import unittest

from aicontribcheck import patterns
from aicontribcheck.rules import (
    rollup,
    rule_allow,
    rule_attribution,
    rule_ban,
    rule_disclosure,
    rule_noncommercial,
    rule_review,
    rule_testing,
    rule_tools,
    run_rules,
)
from aicontribcheck.types import FileScan, RepoReport, Severity, Verdict


def _fs(text_kind="contributing", path="MEM"):
    return FileScan(path=path, kind=text_kind)


class RuleBanTests(unittest.TestCase):
    def test_positive_case(self):
        fs = _fs()
        rule_ban(fs, "This project does not accept AI-generated code.")
        self.assertEqual(len(fs.findings), 1)
        f = fs.findings[0]
        self.assertEqual(f.rule, "AICONTRIB-001")
        self.assertEqual(f.severity, Severity.ERROR)
        self.assertEqual(f.verdict, Verdict.BANNED)
        self.assertEqual(f.line, 1)

    def test_negative_case_clean(self):
        fs = _fs()
        rule_ban(fs, "We build AI systems. The build is green.")
        self.assertEqual(fs.findings, [])

    def test_multiline_finds_first_hit_only(self):
        fs = _fs()
        text = (
            "Line one, nothing.\n"
            "We do not accept AI-generated PRs here.\n"
            "AI-generated code is prohibited entirely.\n"
        )
        rule_ban(fs, text)
        # Multiple patterns can each match once; ensure at least one hit and
        # each pattern contributes at most one finding.
        self.assertGreaterEqual(len(fs.findings), 1)
        self.assertTrue(all(f.rule == "AICONTRIB-001" for f in fs.findings))


class RuleAllowTests(unittest.TestCase):
    def test_positive(self):
        fs = _fs()
        rule_allow(fs, "AI-generated contributions are welcome here.")
        self.assertEqual(len(fs.findings), 1)
        self.assertEqual(fs.findings[0].rule, "AICONTRIB-002")
        self.assertEqual(fs.findings[0].verdict, Verdict.ALLOWED)

    def test_negative(self):
        fs = _fs()
        rule_allow(fs, "Please contribute code.")
        self.assertEqual(fs.findings, [])


class RuleDisclosureTests(unittest.TestCase):
    def test_positive(self):
        fs = _fs()
        rule_disclosure(
            fs, "AI-generated contributions must be disclosed in the PR."
        )
        self.assertEqual(len(fs.findings), 1)
        self.assertEqual(fs.findings[0].rule, "AICONTRIB-003")

    def test_negative(self):
        fs = _fs()
        rule_disclosure(fs, "Please write clear commit messages.")
        self.assertEqual(fs.findings, [])


class RuleAttributionTests(unittest.TestCase):
    def test_dco_positive(self):
        fs = _fs()
        rule_attribution(fs, "DCO required for all commits.")
        self.assertTrue(any(f.rule == "AICONTRIB-004" for f in fs.findings))

    def test_cla_positive(self):
        fs = _fs()
        rule_attribution(fs, "Signed CLA required to contribute.")
        self.assertTrue(any(f.rule == "AICONTRIB-004" for f in fs.findings))

    def test_copyright_assignment_positive(self):
        fs = _fs()
        rule_attribution(
            fs, "Contributors must transfer copyright to the project."
        )
        self.assertTrue(any(f.rule == "AICONTRIB-004" for f in fs.findings))

    def test_negative(self):
        fs = _fs()
        rule_attribution(fs, "Licensed under Apache-2.0.")
        self.assertEqual(fs.findings, [])

    def test_dedupes_repeated_tokens(self):
        fs = _fs()
        rule_attribution(
            fs,
            "DCO required.\nDCO required also on subsequent PRs.\n"
            "Signed-off-by must appear.",
        )
        # At most 2 findings even though DCO appears twice.
        toks = {f.message for f in fs.findings if f.rule == "AICONTRIB-004"}
        self.assertLessEqual(len(fs.findings), len(toks) + 1)


class RuleReviewTests(unittest.TestCase):
    def test_positive(self):
        fs = _fs()
        rule_review(fs, "Human review required before merge.")
        self.assertEqual(len(fs.findings), 1)
        self.assertEqual(fs.findings[0].rule, "AICONTRIB-005")

    def test_negative(self):
        fs = _fs()
        rule_review(fs, "Automated CI must pass.")
        self.assertEqual(fs.findings, [])


class RuleTestingTests(unittest.TestCase):
    def test_positive(self):
        fs = _fs()
        rule_testing(fs, "Tests are required for all new code.")
        self.assertEqual(len(fs.findings), 1)
        self.assertEqual(fs.findings[0].rule, "AICONTRIB-006")
        self.assertEqual(fs.findings[0].severity, Severity.INFO)

    def test_negative(self):
        fs = _fs()
        rule_testing(fs, "Please open an issue first.")
        self.assertEqual(fs.findings, [])


class RuleToolsTests(unittest.TestCase):
    """AICONTRIB-007 names only the products the caller registered (vendor-neutral by default)."""

    def setUp(self):
        patterns.clear_tool_names()
        patterns.register_tool_names(["helperbot", "codewright"])

    def tearDown(self):
        patterns.clear_tool_names()

    def test_registered_tool_found(self):
        fs = _fs()
        rule_tools(fs, "We use helperbot heavily in this project.")
        self.assertTrue(
            any(f.rule == "AICONTRIB-007" and "helperbot" in f.message for f in fs.findings)
        )

    def test_multiple_distinct_tools_deduped(self):
        fs = _fs()
        rule_tools(
            fs,
            "helperbot and helperbot and helperbot and codewright and codewright.",
        )
        tools = {f.message.split(":", 1)[-1].strip() for f in fs.findings}
        self.assertEqual(tools, {"helperbot", "codewright"})

    def test_unregistered_tool_not_named(self):
        # A product the caller did not register is not reported -- no baked-in vendor list.
        fs = _fs()
        rule_tools(fs, "We use someotherassistant heavily in this project.")
        self.assertEqual(fs.findings, [])

    def test_no_tool_names(self):
        fs = _fs()
        rule_tools(fs, "Nothing to see here.")
        self.assertEqual(fs.findings, [])


class RuleNonCommercialTests(unittest.TestCase):
    def test_positive_on_license_only(self):
        fs = FileScan(path="LICENSE", kind="license")
        rule_noncommercial(
            fs, "This work is licensed CC-BY-NC-4.0 (non-commercial)."
        )
        self.assertEqual(len(fs.findings), 1)
        self.assertEqual(fs.findings[0].rule, "AICONTRIB-008")

    def test_skips_non_license_files(self):
        fs = FileScan(path="README.md", kind="readme")
        rule_noncommercial(fs, "Please do not use for commercial purposes.")
        self.assertEqual(fs.findings, [])

    def test_negative_on_permissive_license(self):
        fs = FileScan(path="LICENSE", kind="license")
        rule_noncommercial(fs, "MIT License. Permission is hereby granted...")
        self.assertEqual(fs.findings, [])


class RunRulesTests(unittest.TestCase):
    def test_runs_all_rules_without_error(self):
        fs = _fs()
        run_rules(fs, "Nothing relevant here at all.")
        self.assertEqual(fs.findings, [])

    def test_all_rules_produce_valid_finding_shape(self):
        fs = _fs()
        text = (
            "AI-generated contributions are welcome. "
            "AI usage must be disclosed. "
            "DCO required. "
            "Human review required. "
            "Tests are required. "
            "An AI assistant is fine to use."
        )
        run_rules(fs, text)
        for f in fs.findings:
            self.assertTrue(f.rule.startswith("AICONTRIB-"))
            self.assertIn(f.severity, list(Severity))
            self.assertIn(f.verdict, list(Verdict))
            self.assertGreater(f.line, 0)


class RollupTests(unittest.TestCase):
    def _build_report(self, per_file_findings):
        report = RepoReport(root="MEM")
        for path, kind, text in per_file_findings:
            fs = FileScan(path=path, kind=kind)
            run_rules(fs, text)
            report.files_scanned.append(fs)
        rollup(report)
        return report

    def test_ban_dominates(self):
        r = self._build_report(
            [
                (
                    "CONTRIBUTING.md",
                    "contributing",
                    "This project does not accept AI-generated code.",
                ),
            ]
        )
        self.assertEqual(r.verdict, Verdict.BANNED)

    def test_allow_when_no_ban(self):
        r = self._build_report(
            [
                (
                    "CONTRIBUTING.md",
                    "contributing",
                    "AI-generated contributions are welcome.",
                ),
            ]
        )
        self.assertEqual(r.verdict, Verdict.ALLOWED)

    def test_conditional_when_only_conditional_signals(self):
        r = self._build_report(
            [
                (
                    "AI_POLICY.md",
                    "ai-policy",
                    "AI-generated contributions must be disclosed.",
                ),
            ]
        )
        self.assertEqual(r.verdict, Verdict.CONDITIONAL)

    def test_unknown_when_no_signals(self):
        r = self._build_report(
            [
                ("README.md", "readme", "Just a project. Nothing here."),
            ]
        )
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertTrue(
            any(f.rule == "AICONTRIB-009" for f in r.all_findings())
        )

    def test_conflict_when_ban_and_allow_in_different_files(self):
        r = self._build_report(
            [
                (
                    "README.md",
                    "readme",
                    "AI-generated contributions are welcome.",
                ),
                (
                    "CONTRIBUTING.md",
                    "contributing",
                    "This project does not accept AI-generated code.",
                ),
            ]
        )
        self.assertEqual(r.verdict, Verdict.CONFLICT)
        self.assertTrue(
            any(f.rule == "AICONTRIB-010" for f in r.all_findings())
        )

    def test_tools_named_populated(self):
        patterns.clear_tool_names()
        patterns.register_tool_names(["helperbot", "codewright", "acme-assistant"])
        try:
            r = self._build_report(
                [
                    (
                        "README.md",
                        "readme",
                        "We use helperbot and codewright sometimes; acme-assistant too.",
                    ),
                ]
            )
            self.assertEqual(
                r.tools_named, sorted(["helperbot", "codewright", "acme-assistant"])
            )
        finally:
            patterns.clear_tool_names()

    def test_disclosures_collected(self):
        r = self._build_report(
            [
                (
                    "AI_POLICY.md",
                    "ai-policy",
                    "AI-generated contributions must be disclosed clearly.",
                ),
            ]
        )
        self.assertTrue(r.required_disclosures)


if __name__ == "__main__":
    unittest.main()
