"""Domain-type invariants."""

from __future__ import annotations

import unittest

from sarifcheck.types import (
    DocIndex,
    Finding,
    Options,
    Profile,
    RunIndex,
    ScanResult,
    Severity,
    Verdict,
    severity_rank,
)


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="SRF-001",
        severity=Severity.HIGH,
        path="a.sarif",
        prop="version",
        line=1,
        column=1,
        message="m",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class SeverityTests(unittest.TestCase):
    def test_three_severities_only(self):
        self.assertEqual(
            sorted(s.value for s in Severity), ["HIGH", "INFO", "MEDIUM"]
        )

    def test_severity_is_str_enum(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(str(Severity.MEDIUM.value), "MEDIUM")

    def test_rank_orders_high_first(self):
        self.assertLess(severity_rank(Severity.HIGH), severity_rank(Severity.MEDIUM))
        self.assertLess(severity_rank(Severity.MEDIUM), severity_rank(Severity.INFO))


class VerdictTests(unittest.TestCase):
    def test_four_verdicts(self):
        self.assertEqual(
            sorted(v.value for v in Verdict),
            ["healthy", "needs-attention", "unhealthy", "unknown"],
        )

    def test_verdict_values_are_lowercase_hyphenated(self):
        for verdict in Verdict:
            self.assertEqual(verdict.value, verdict.value.lower())
            self.assertNotIn(" ", verdict.value)


class ProfileTests(unittest.TestCase):
    def test_three_profiles(self):
        self.assertEqual(
            sorted(p.value for p in Profile), ["hygiene", "ingest", "spec"]
        )


class FindingTests(unittest.TestCase):
    def test_finding_is_frozen(self):
        finding = make_finding()
        with self.assertRaises(Exception):
            finding.rule_id = "SRF-002"

    def test_defaults_mark_unattached_findings(self):
        finding = make_finding()
        self.assertEqual(finding.run_index, -1)
        self.assertEqual(finding.result_index, -1)
        self.assertEqual(finding.snippet, "")

    def test_sort_key_orders_by_run_then_result(self):
        first = make_finding(run_index=0, result_index=1)
        second = make_finding(run_index=1, result_index=0)
        self.assertLess(first.sort_key(), second.sort_key())

    def test_sort_key_orders_by_rule_code_within_a_result(self):
        first = make_finding(rule_id="SRF-004", run_index=0, result_index=0)
        second = make_finding(rule_id="SRF-005", run_index=0, result_index=0)
        self.assertLess(first.sort_key(), second.sort_key())

    def test_sort_key_orders_by_property_path_within_a_rule(self):
        first = make_finding(prop="a", run_index=0, result_index=0)
        second = make_finding(prop="b", run_index=0, result_index=0)
        self.assertLess(first.sort_key(), second.sort_key())

    def test_sort_key_ignores_severity(self):
        high = make_finding(severity=Severity.HIGH, rule_id="SRF-009")
        info = make_finding(severity=Severity.INFO, rule_id="SRF-001")
        # SRF-001 sorts before SRF-009 even though it is the lower severity:
        # emission order is positional so two commits stay diffable.
        self.assertLess(info.sort_key(), high.sort_key())

    def test_sort_key_orders_by_file_first(self):
        first = make_finding(path="a.sarif", run_index=9)
        second = make_finding(path="b.sarif", run_index=0)
        self.assertLess(first.sort_key(), second.sort_key())


class ScanResultTests(unittest.TestCase):
    def test_defaults_are_empty(self):
        result = ScanResult()
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.errors, ())
        self.assertEqual(result.notes, ())
        self.assertFalse(result.partial)

    def test_findings_tuple_is_not_shared_between_instances(self):
        first = ScanResult()
        second = ScanResult()
        self.assertIsNot(first.errors, None)
        self.assertEqual(first.findings, second.findings)


class OptionsTests(unittest.TestCase):
    def test_default_options_enable_every_profile(self):
        options = Options()
        self.assertEqual(options.profiles, frozenset(("spec", "ingest", "hygiene")))

    def test_default_options_disable_nothing(self):
        options = Options()
        self.assertEqual(options.disabled, frozenset())
        self.assertFalse(options.allow_path_in_message)
        self.assertFalse(options.show_matches)

    def test_limits_dict_is_per_instance(self):
        first = Options()
        second = Options()
        first.limits["x"] = 1
        self.assertNotIn("x", second.limits)


class IndexTypeTests(unittest.TestCase):
    def test_run_index_defaults(self):
        run_index = RunIndex()
        self.assertEqual(run_index.rules, [])
        self.assertFalse(run_index.has_rule_metadata)
        self.assertFalse(run_index.has_external_property_files)

    def test_doc_index_defaults(self):
        doc_index = DocIndex()
        self.assertEqual(doc_index.runs, [])
        self.assertEqual(doc_index.run_count, 0)
        self.assertFalse(doc_index.any_external_property_files)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
