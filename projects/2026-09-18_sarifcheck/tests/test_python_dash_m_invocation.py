"""Verify the `python -m sarifcheck` subprocess entry point.

These are the only tests that shell out. They exist because a broken
__main__.py is invisible to every in-process test in this suite: main()
would still be importable and callable while `python -m sarifcheck` failed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env():
    env = os.environ.copy()
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "sarifcheck", *args],
        cwd=ROOT, env=_env(), capture_output=True, text=True, timeout=60,
    )


class DashMInvocationTests(unittest.TestCase):
    def test_version(self):
        result = _run("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("sarifcheck", result.stdout + result.stderr)

    def test_version_format_is_tool_space_semver(self):
        result = _run("--version")
        printed = (result.stdout + result.stderr).strip()
        self.assertRegex(printed, r"^sarifcheck \d+\.\d+\.\d+$")

    def test_help(self):
        result = _run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("sarifcheck", result.stdout)

    def test_help_leads_with_the_subset_disclaimer(self):
        result = _run("--help")
        # argparse re-wraps the description, so compare on collapsed
        # whitespace rather than on the exact line breaks it chose.
        flattened = " ".join(result.stdout.split())
        self.assertIn("not a JSON Schema validator", flattened)
        self.assertIn("a clean run is not a promise", flattened)

    def test_unknown_flag_is_rc_two(self):
        result = _run("--nope")
        self.assertEqual(result.returncode, 2)

    def test_list_rules(self):
        result = _run("--list-rules")
        self.assertEqual(result.returncode, 0)
        for n in range(1, 28):
            self.assertIn("SRF-" + str(n).zfill(3), result.stdout)

    def test_show_limits(self):
        result = _run("--show-limits")
        self.assertEqual(result.returncode, 0)
        self.assertIn("max_results_per_run", result.stdout)

    def test_healthy_fixture_exits_zero(self):
        result = _run(os.path.join(ROOT, "tests", "fixtures", "healthy"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("verdict: healthy", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_weak_example_exits_two_with_findings_on_stdout(self):
        result = _run(os.path.join(ROOT, "examples", "weak_results.sarif"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("SRF-001", result.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
