"""Validate `python -m approvchainlint` behaves as expected under
subprocess. Cheap smoke tests that lock the module-invocation surface
so a broken __main__.py cannot ship green.
"""

import os
import subprocess
import sys
import unittest


HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")


def _run(args, env=None):
    e = os.environ.copy()
    e["PYTHONPATH"] = ROOT + os.pathsep + e.get("PYTHONPATH", "")
    if env:
        e.update(env)
    p = subprocess.run(
        [sys.executable, "-m", "approvchainlint", *args],
        capture_output=True, text=True, env=e, cwd=ROOT,
    )
    return p.returncode, p.stdout, p.stderr


class TestPythonDashM(unittest.TestCase):
    def test_version(self):
        rc, out, _err = _run(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("approvchainlint", out)

    def test_list_rules(self):
        rc, out, _err = _run(["--list-rules"])
        self.assertEqual(rc, 0)
        self.assertIn("AC-001", out)
        self.assertIn("AC-012", out)

    def test_help_exit_zero(self):
        rc, out, _err = _run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("approvchainlint", out)


if __name__ == "__main__":
    unittest.main()
