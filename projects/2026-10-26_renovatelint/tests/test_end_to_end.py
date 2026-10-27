"""End-to-end tests: fixture-driven subprocess runs that exercise the
full pipeline (discover -> parse -> rules -> verdict -> report)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PROJECT_ROOT, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "renovatelint", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class HealthyFixtureEndToEndTests(unittest.TestCase):
    def test_healthy_fixture_rc_zero(self):
        r = _run(os.path.join(EXAMPLES_DIR, "healthy_renovate.json"))
        self.assertEqual(r.returncode, 0,
                         "stdout=" + r.stdout + "\nstderr=" + r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertIn("healthy", r.stderr)

    def test_healthy_fixture_json_mode(self):
        r = _run("--json", os.path.join(EXAMPLES_DIR, "healthy_renovate.json"))
        self.assertEqual(r.returncode, 0)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["verdict"], "healthy")
        self.assertEqual(doc["findings"], [])


class WeakFixtureEndToEndTests(unittest.TestCase):
    def test_weak_fixture_covers_expected_rules(self):
        r = _run("--json", os.path.join(EXAMPLES_DIR, "weak_renovate.json"))
        self.assertEqual(r.returncode, 2, r.stdout + "\n" + r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["verdict"], "unhealthy")
        ids = {f["rule_id"] for f in doc["findings"]}
        # The weak fixture is designed to exercise most of the HIGH
        # and MEDIUM rules.
        for expected in (
            "RNV-001", "RNV-003", "RNV-004", "RNV-005",
            "RNV-007", "RNV-008", "RNV-009", "RNV-010",
        ):
            self.assertIn(expected, ids, (
                "weak fixture did not fire " + expected
                + "; got " + repr(sorted(ids))
            ))

    def test_weak_fixture_text_mode_rule_id_on_stdout(self):
        r = _run(os.path.join(EXAMPLES_DIR, "weak_renovate.json"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RNV-001", r.stdout)
        self.assertIn("renovatelint:", r.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
