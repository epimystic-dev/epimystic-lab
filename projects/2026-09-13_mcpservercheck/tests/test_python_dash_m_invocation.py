"""Verify `python -m mcpservercheck --version` and --list-rules invocations."""

import os
import subprocess
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))


def _env():
    env = os.environ.copy()
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


class DashMInvocationTests(unittest.TestCase):
    def test_version(self):
        r = subprocess.run(
            [sys.executable, "-m", "mcpservercheck", "--version"],
            cwd=ROOT, env=_env(), capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("mcpservercheck", r.stdout + r.stderr)

    def test_list_rules(self):
        r = subprocess.run(
            [sys.executable, "-m", "mcpservercheck", "--list-rules"],
            cwd=ROOT, env=_env(), capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        for i in range(1, 11):
            self.assertIn("MSC-" + str(i).zfill(3), r.stdout)

    def test_healthy_fixture_exit_zero(self):
        r = subprocess.run(
            [sys.executable, "-m", "mcpservercheck",
             os.path.join(ROOT, "tests", "fixtures", "healthy")],
            cwd=ROOT, env=_env(), capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("verdict: healthy", r.stdout)


if __name__ == "__main__":
    unittest.main()
