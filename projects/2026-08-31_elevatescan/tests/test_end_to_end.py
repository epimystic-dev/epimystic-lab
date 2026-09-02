import json
import unittest
from pathlib import Path

from elevatescan.config import Config
from elevatescan.report import render_json
from elevatescan.scanner import scan_path
from elevatescan.verdict import compute_verdict, exit_code
from elevatescan.types import Verdict

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def _scan(fx, **kwargs):
    cfg = Config(**kwargs)
    r = scan_path(FIXTURE_ROOT / fx, cfg)
    v = compute_verdict(r, cfg)
    return r, v, cfg


class TestFixtures(unittest.TestCase):
    def test_healthy_verdict(self):
        r, v, cfg = _scan("healthy")
        self.assertEqual(v, Verdict.HEALTHY)
        self.assertEqual(exit_code(v, cfg), 0)
        self.assertGreater(r.files_scanned, 0)
        self.assertEqual(r.findings, [])

    def test_healthy_stays_healthy_under_strict_and_info(self):
        r, v, cfg = _scan("healthy", strict=True, include_info=True)
        self.assertEqual(v, Verdict.HEALTHY)

    def test_override_verdict_unhealthy_and_esc002(self):
        r, v, _ = _scan("override")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "ESC-002" for f in r.findings))

    def test_role_marker_verdict_unhealthy_and_esc001(self):
        r, v, _ = _scan("role_marker")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "ESC-001" for f in r.findings))

    def test_persistent_goal_verdict_unhealthy_and_esc003(self):
        r, v, _ = _scan("persistent_goal")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "ESC-003" for f in r.findings))

    def test_scheduled_task_verdict_unhealthy_and_esc004(self):
        r, v, _ = _scan("scheduled_task")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "ESC-004" for f in r.findings))

    def test_elevated_authority_verdict_unhealthy_and_esc005(self):
        r, v, _ = _scan("elevated_authority")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "ESC-005" for f in r.findings))

    def test_tool_output_verdict_needs_attention_or_worse(self):
        r, v, _ = _scan("tool_output")
        self.assertIn(v, {Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY})
        self.assertTrue(any(f.rule_id == "ESC-006" for f in r.findings))

    def test_url_smuggle_verdict_needs_attention_or_worse(self):
        r, v, _ = _scan("url_smuggle")
        self.assertIn(v, {Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY})
        self.assertTrue(any(f.rule_id == "ESC-007" for f in r.findings))

    def test_hidden_marker_verdict_needs_attention_or_worse(self):
        r, v, _ = _scan("hidden_marker")
        self.assertIn(v, {Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY})
        self.assertTrue(any(f.rule_id == "ESC-008" for f in r.findings))

    def test_code_fence_verdict_needs_attention_or_worse(self):
        r, v, _ = _scan("code_fence")
        self.assertIn(v, {Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY})
        self.assertTrue(any(f.rule_id == "ESC-009" for f in r.findings))

    def test_unknown_fixture_verdict_unknown(self):
        r, v, cfg = _scan("unknown")
        self.assertEqual(v, Verdict.UNKNOWN)
        self.assertEqual(exit_code(v, cfg), 1)

    def test_unknown_strict_exit_2(self):
        r, v, cfg = _scan("unknown", strict=True)
        self.assertEqual(exit_code(v, cfg), 2)

    def test_json_roundtrip_deterministic_on_override(self):
        r1, v1, cfg1 = _scan("override")
        j1 = render_json(r1, v1, cfg1)
        r2, v2, cfg2 = _scan("override")
        j2 = render_json(r2, v2, cfg2)
        self.assertEqual(j1, j2)
        obj = json.loads(j1)
        self.assertEqual(obj["verdict"], "unhealthy")

    def test_findings_across_fixtures_are_sorted(self):
        r, _, _ = _scan("override")
        keys = [f.sort_key() for f in r.findings]
        self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()
