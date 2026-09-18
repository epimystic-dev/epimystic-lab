"""Verify the real `python -m nbshape` subprocess entry point.

These tests spawn the interpreter, so they catch anything that only breaks when
the package is loaded as __main__ - a missing __main__.py, an import cycle, an
exit code the in-process tests would not see.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env():
    env = os.environ.copy()
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", "nbshape"] + list(args),
        cwd=ROOT,
        env=_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )


class DashMInvocationTests(unittest.TestCase):
    def test_help_exits_zero(self):
        r = run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nbshape", r.stdout)

    def test_version_exits_zero_and_prints_name_and_version(self):
        r = run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex((r.stdout + r.stderr).strip(), r"nbshape \d+\.\d+\.\d+")

    def test_an_unknown_flag_exits_two(self):
        r = run("--no-such-flag")
        self.assertEqual(r.returncode, 2)

    def test_list_rules_exits_zero_and_lists_every_rule(self):
        r = run("--list-rules")
        self.assertEqual(r.returncode, 0, r.stderr)
        for i in range(1, 19):
            self.assertIn("NBK-" + str(i).zfill(3), r.stdout)

    def test_the_healthy_fixture_exits_zero_with_empty_stdout(self):
        r = run(os.path.join("tests", "fixtures", "healthy"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertIn("verdict: healthy", r.stderr)

    def test_a_high_severity_fixture_exits_two(self):
        r = run(os.path.join("tests", "fixtures", "nbk005_local_path"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("NBK-005", r.stdout)

    def test_a_missing_path_exits_two(self):
        r = run(os.path.join("no", "such", "path"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("path does not exist", r.stderr)

    def test_json_mode_emits_only_json_on_stdout(self):
        r = run(os.path.join("tests", "fixtures", "nbk005_local_path"), "--json")
        doc = json.loads(r.stdout)
        self.assertEqual(doc["tool"], "nbshape")

    def test_the_module_never_writes_a_traceback_on_a_malformed_file(self):
        r = run(os.path.join("tests", "fixtures", "unknown"))
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn(r.returncode, (1, 2))


if __name__ == "__main__":
    unittest.main()
