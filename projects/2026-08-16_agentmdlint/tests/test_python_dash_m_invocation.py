"""Locks the shared-lab invariant that every linter is invokable as ``python -m <tool>``.

Documented in ``docs/CONVENTIONS.md`` under "Invocation". The invariant only
holds if the package ships an ``__main__.py`` module; without it, the
interpreter raises ``No module named agentmdlint.__main__; 'agentmdlint' is a
package and cannot be directly executed`` and returns a nonzero exit code.

These tests spawn a real subprocess (not ``main(argv)``) because the failure
mode they guard against is the module-resolution step in the Python launcher,
which an in-process call to ``main`` cannot exercise.
"""

import os
import subprocess
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run_module(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "agentmdlint", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=PROJECT_ROOT,
    )


class PythonDashMInvocation(unittest.TestCase):
    def test_help_returns_zero(self):
        r = _run_module("--help")
        self.assertEqual(
            r.returncode,
            0,
            msg="python -m agentmdlint --help must exit 0; "
            "got rc={} stderr={!r}".format(r.returncode, r.stderr),
        )
        self.assertIn("agentmdlint", r.stdout)

    def test_version_returns_zero(self):
        r = _run_module("--version")
        self.assertEqual(
            r.returncode,
            0,
            msg="python -m agentmdlint --version must exit 0; "
            "got rc={} stderr={!r}".format(r.returncode, r.stderr),
        )
        self.assertIn("agentmdlint", r.stdout)

    def test_missing_path_returns_two(self):
        r = _run_module(os.path.join(PROJECT_ROOT, "does_not_exist_xyz"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("does not exist", r.stderr)


if __name__ == "__main__":
    unittest.main()
