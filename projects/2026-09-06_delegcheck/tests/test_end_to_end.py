import json
import os
import tempfile
import unittest

from delegcheck.report import format_json, format_text
from delegcheck.scanner import scan_path
from delegcheck.types import Verdict
from delegcheck.verdict import compute_verdict


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _v(name, strict=False, extra_globs=()):
    root = os.path.join(FIXTURES, name)
    r = scan_path(root)
    return r, compute_verdict(r, strict=strict)


def _rule_ids(result):
    return sorted({f.rule_id for f in result.findings})


class TestFixtureVerdicts(unittest.TestCase):

    def test_healthy(self):
        r, v = _v("healthy")
        self.assertEqual(v, Verdict.HEALTHY, msg="unexpected findings: " + str(_rule_ids(r)))

    def test_healthy_under_strict_include_info(self):
        r, v = _v("healthy", strict=True)
        self.assertEqual(v, Verdict.HEALTHY)

    def test_del001_unbounded_scope(self):
        r, v = _v("del001_unbounded_scope")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertIn("DEL-001", _rule_ids(r))

    def test_del002_no_principal(self):
        r, v = _v("del002_no_principal")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertIn("DEL-002", _rule_ids(r))

    def test_del003_auth_in_model(self):
        r, v = _v("del003_auth_in_model")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertIn("DEL-003", _rule_ids(r))

    def test_del004_parent_cred_reuse(self):
        r, v = _v("del004_parent_cred_reuse")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertIn("DEL-004", _rule_ids(r))

    def test_del005_recursive_no_cap(self):
        r, v = _v("del005_recursive_no_cap")
        self.assertEqual(v, Verdict.UNHEALTHY)
        self.assertIn("DEL-005", _rule_ids(r))

    def test_del006_wildcard_agent(self):
        r, v = _v("del006_wildcard_agent")
        self.assertIn(v, (Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY))
        self.assertIn("DEL-006", _rule_ids(r))

    def test_del007_no_expiry(self):
        r, v = _v("del007_no_expiry")
        self.assertIn(v, (Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY))
        self.assertIn("DEL-007", _rule_ids(r))

    def test_del008_boundary_mismatch(self):
        r, v = _v("del008_boundary_mismatch")
        self.assertIn(v, (Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY))
        self.assertIn("DEL-008", _rule_ids(r))

    def test_del009_cycle(self):
        r, v = _v("del009_cycle")
        self.assertIn(v, (Verdict.NEEDS_ATTENTION, Verdict.UNHEALTHY))
        self.assertIn("DEL-009", _rule_ids(r))

    def test_unknown_default_exit_1(self):
        r, v = _v("unknown")
        self.assertEqual(v, Verdict.UNKNOWN)
        self.assertEqual(r.files_scanned, 0)

    def test_unknown_strict_exit_2_via_verdict(self):
        r, v = _v("unknown", strict=True)
        self.assertEqual(v, Verdict.UNKNOWN)


class TestDEL010OnGeneratedFixture(unittest.TestCase):

    def _long_token(self):
        parts = ("a1B2c3D4e5F6g7H8", "i9J0k1L2m3N4o5P6", "Q7r8S9t0U1v2W3x4")
        return "".join(parts)

    def test_fires_on_generated(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            obj = {"credentials": [{"name": "t", "type": "bearer", "value": self._long_token(), "scope": "read:x", "expires_at": "2026-10-01"}]}
            with open(os.path.join(d, "a.json"), "w", encoding="utf-8") as f:
                f.write(json.dumps(obj, indent=2))
            r = scan_path(d)
            self.assertEqual({f.rule_id for f in r.findings}, {"DEL-010"})
            v = compute_verdict(r)
            self.assertEqual(v, Verdict.HEALTHY)


class TestDeterminism(unittest.TestCase):

    def test_json_roundtrip_deterministic(self):
        r1, _ = _v("del001_unbounded_scope")
        r2, _ = _v("del001_unbounded_scope")
        self.assertEqual(format_json(r1), format_json(r2))

    def test_findings_sorted(self):
        r, _ = _v("del001_unbounded_scope")
        keys = [f.sort_key() for f in r.findings]
        self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()
