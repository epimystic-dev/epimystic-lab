"""Validate `python -m pjhookcheck` behaves as expected under subprocess.

These are cheap smoke tests but they lock the module-invocation surface
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
    """Run the tool as a subprocess. Returns (rc, stdout, stderr)."""
    e = os.environ.copy()
    # Ensure the project root is on sys.path so subprocess can import.
    e["PYTHONPATH"] = ROOT + os.pathsep + e.get("PYTHONPATH", "")
    if env:
        e.update(env)
    p = subprocess.run(
        [sys.executable, "-m", "pjhookcheck", *args],
        capture_output=True, text=True, env=e, cwd=ROOT,
    )
    return p.returncode, p.stdout, p.stderr


class TestPythonDashM(unittest.TestCase):
    def test_version(self):
        rc, out, _err = _run(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("pjhookcheck", out)

    def test_list_rules(self):
        rc, out, _err = _run(["--list-rules"])
        self.assertEqual(rc, 0)
        self.assertIn("PJH-001", out)
        self.assertIn("PJH-012", out)

    def test_healthy_exit_zero(self):
        rc, _out, _err = _run([os.path.join(FIXTURES, "healthy_package.json")])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
