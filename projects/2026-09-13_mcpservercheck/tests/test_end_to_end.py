"""End-to-end tests over the fixture directory tree."""

import json
import os
import tempfile
import unittest

from mcpservercheck.report import format_json
from mcpservercheck.scanner import scan_path
from mcpservercheck.verdict import compute_verdict, exit_code_for
from mcpservercheck.types import Verdict


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _scan(name):
    return scan_path(os.path.join(FIXTURES, name))


class HealthyFixtureTests(unittest.TestCase):
    def test_no_findings(self):
        r = _scan("healthy")
        self.assertEqual(len(r.findings), 0)
        self.assertEqual(compute_verdict(r), Verdict.HEALTHY)
        self.assertEqual(exit_code_for(compute_verdict(r)), 0)


class TenAdversarialFixturesTests(unittest.TestCase):
    def test_msc001_fires(self):
        r = _scan("msc001_shell_eval")
        self.assertTrue(any(f.rule_id == "MSC-001" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_msc002_fires(self):
        r = _scan("msc002_plaintext_transport")
        self.assertTrue(any(f.rule_id == "MSC-002" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_msc003_fires(self):
        r = _scan("msc003_inline_bearer")
        self.assertTrue(any(f.rule_id == "MSC-003" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_msc004_fires(self):
        r = _scan("msc004_remote_fetch")
        self.assertTrue(any(f.rule_id == "MSC-004" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_msc005_fires(self):
        r = _scan("msc005_incomplete")
        self.assertTrue(any(f.rule_id == "MSC-005" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.UNHEALTHY)

    def test_msc006_fires(self):
        r = _scan("msc006_unpinned_pkg")
        self.assertTrue(any(f.rule_id == "MSC-006" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.NEEDS_ATTENTION)

    def test_msc007_fires(self):
        r = _scan("msc007_cred_env")
        self.assertTrue(any(f.rule_id == "MSC-007" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.NEEDS_ATTENTION)

    def test_msc008_fires(self):
        r = _scan("msc008_wildcard")
        self.assertTrue(any(f.rule_id == "MSC-008" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.NEEDS_ATTENTION)

    def test_msc009_fires(self):
        r = _scan("msc009_temp_dir")
        self.assertTrue(any(f.rule_id == "MSC-009" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.NEEDS_ATTENTION)

    def test_msc010_fires_and_default_verdict_healthy(self):
        r = _scan("msc010_bare_binary")
        self.assertTrue(any(f.rule_id == "MSC-010" for f in r.findings))
        self.assertEqual(compute_verdict(r), Verdict.HEALTHY)  # INFO default
        self.assertEqual(compute_verdict(r, strict=True), Verdict.NEEDS_ATTENTION)


class UnknownFixtureTests(unittest.TestCase):
    def test_no_files_scanned(self):
        r = _scan("unknown")
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(compute_verdict(r), Verdict.UNKNOWN)


class JsonRoundtripDeterminismTests(unittest.TestCase):
    def test_two_runs_identical(self):
        r = _scan("msc001_shell_eval")
        a = format_json(r)
        b = format_json(r)
        self.assertEqual(a, b)


class GeneratedAtRuntimeSecretFixtureTests(unittest.TestCase):
    """Assemble a >=32-char high-entropy token from sub-16-char parts at
    runtime, write to a temp file, and verify MSC-003 fires exactly once
    with default verdict UNHEALTHY. This protects the shipped source tree
    from carrying any verbatim >=16-char token literal."""

    def test_generated_token_fires_msc_003(self):
        parts = (
            "a1B2c3D4e5F6g7H8",
            "i9J0k1L2m3N4o5P6",
            "Q7r8S9t0U1v2W3x4",
        )
        token = "".join(parts)
        cfg = {"mcpServers": {"gen": {"command": "/usr/local/bin/server",
                                       "env": {"HANDLE": token}}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        try:
            from mcpservercheck.scanner import scan_file
            findings, err = scan_file(path)
            self.assertIsNone(err)
            msc003 = [x for x in findings if x.rule_id == "MSC-003"]
            self.assertEqual(len(msc003), 1)
        finally:
            os.unlink(path)


class FindingsSortInvariantTests(unittest.TestCase):
    def test_findings_sorted_globally(self):
        r = scan_path(FIXTURES)
        keys = [f.sort_key() for f in r.findings]
        self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()
