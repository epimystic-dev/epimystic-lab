import json
import unittest

from elevatescan.config import Config
from elevatescan.report import render_json, render_text
from elevatescan.types import Finding, ScanResult, Severity, Verdict
from elevatescan.verdict import compute_verdict, exit_code


def _res(files_scanned=1, findings=None, errors=None):
    return ScanResult(
        findings=list(findings or []),
        files_scanned=files_scanned,
        errors=list(errors or []),
    )


def _f(sev, rule="ESC-999"):
    return Finding(rule, sev, "a.md", 1, 1, "m", "ev")


class TestVerdictRollup(unittest.TestCase):
    def test_no_files_is_unknown(self):
        self.assertEqual(compute_verdict(_res(0), Config()), Verdict.UNKNOWN)

    def test_high_is_unhealthy(self):
        r = _res(1, [_f(Severity.HIGH)])
        self.assertEqual(compute_verdict(r, Config()), Verdict.UNHEALTHY)

    def test_medium_no_high_is_needs_attention(self):
        r = _res(1, [_f(Severity.MEDIUM)])
        self.assertEqual(compute_verdict(r, Config()), Verdict.NEEDS_ATTENTION)

    def test_high_beats_medium(self):
        r = _res(1, [_f(Severity.MEDIUM), _f(Severity.HIGH)])
        self.assertEqual(compute_verdict(r, Config()), Verdict.UNHEALTHY)

    def test_info_only_default_is_healthy(self):
        r = _res(1, [_f(Severity.INFO)])
        self.assertEqual(compute_verdict(r, Config()), Verdict.HEALTHY)

    def test_info_only_strict_is_needs_attention(self):
        r = _res(1, [_f(Severity.INFO)])
        self.assertEqual(compute_verdict(r, Config(strict=True)), Verdict.NEEDS_ATTENTION)

    def test_no_findings_is_healthy(self):
        r = _res(1, [])
        self.assertEqual(compute_verdict(r, Config()), Verdict.HEALTHY)


class TestExitCode(unittest.TestCase):
    def test_unhealthy_is_2(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Config()), 2)

    def test_needs_attention_is_1(self):
        self.assertEqual(exit_code(Verdict.NEEDS_ATTENTION, Config()), 1)

    def test_unknown_default_is_1(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Config()), 1)

    def test_unknown_strict_is_2(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Config(strict=True)), 2)

    def test_healthy_is_0(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Config()), 0)


class TestRenderText(unittest.TestCase):
    def test_contains_verdict_line(self):
        r = _res(1, [_f(Severity.HIGH)])
        out = render_text(r, Verdict.UNHEALTHY, Config())
        self.assertIn("verdict: unhealthy", out)

    def test_contains_totals(self):
        r = _res(2, [_f(Severity.HIGH), _f(Severity.MEDIUM)])
        out = render_text(r, Verdict.UNHEALTHY, Config())
        self.assertIn("files_scanned=2", out)
        self.assertIn("findings_total=2", out)
        self.assertIn("high=1", out)
        self.assertIn("medium=1", out)

    def test_hides_info_by_default(self):
        r = _res(1, [_f(Severity.INFO)])
        out = render_text(r, Verdict.HEALTHY, Config())
        self.assertNotIn("INFO ", out)  # visible listing omitted
        self.assertIn("info=1", out)     # still counted

    def test_shows_info_with_include_info(self):
        r = _res(1, [_f(Severity.INFO)])
        out = render_text(r, Verdict.HEALTHY, Config(include_info=True))
        self.assertIn("INFO ", out)

    def test_lists_errors(self):
        r = _res(1, [], errors=[("/x/y.md", "read-error: perm")])
        out = render_text(r, Verdict.UNHEALTHY, Config())
        self.assertIn("errors: 1", out)
        self.assertIn("/x/y.md", out)


class TestRenderJson(unittest.TestCase):
    def test_parseable_and_deterministic(self):
        r = _res(1, [_f(Severity.MEDIUM), _f(Severity.HIGH)])
        j1 = render_json(r, Verdict.UNHEALTHY, Config())
        j2 = render_json(r, Verdict.UNHEALTHY, Config())
        self.assertEqual(j1, j2)
        obj = json.loads(j1)
        self.assertEqual(obj["verdict"], "unhealthy")
        self.assertEqual(obj["files_scanned"], 1)
        self.assertEqual(obj["counts"]["HIGH"], 1)
        self.assertEqual(obj["counts"]["MEDIUM"], 1)

    def test_json_omits_info_by_default(self):
        r = _res(1, [_f(Severity.INFO)])
        obj = json.loads(render_json(r, Verdict.HEALTHY, Config()))
        self.assertEqual(len(obj["findings"]), 0)
        self.assertEqual(obj["counts"]["INFO"], 1)

    def test_json_includes_info_when_configured(self):
        r = _res(1, [_f(Severity.INFO)])
        obj = json.loads(render_json(r, Verdict.HEALTHY, Config(include_info=True)))
        self.assertEqual(len(obj["findings"]), 1)

    def test_json_errors_field(self):
        r = _res(1, [], errors=[("/x/y.md", "read-error")])
        obj = json.loads(render_json(r, Verdict.UNHEALTHY, Config()))
        self.assertEqual(len(obj["errors"]), 1)
        self.assertEqual(obj["errors"][0]["path"], "/x/y.md")


if __name__ == "__main__":
    unittest.main()
