"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for envcheck by asserting them
directly against the ``python -m envcheck`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty commands are the same
ones CONVENTIONS.md cites in its evidence table
(``examples/template.env examples/template.env`` for clean;
``examples/template.env examples/local.env`` for dirty), so a regression to
either fixture also trips.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "envcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        # Invariant 1: --help must exit 0 so shell wrappers can probe the
        # tool without triggering their own error branches.
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("envcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. Comparing the
        # template file against itself is the clean-input command
        # documented in docs/CONVENTIONS.md for envcheck.
        template = os.path.join(EXAMPLES_DIR, "template.env")
        self.assertTrue(
            os.path.isfile(template),
            "examples/template.env is a documented artifact; missing here "
            "means the example fixture regressed and the README examples "
            "no longer run.",
        )
        r = _run(template, template, "--quiet")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # envcheck-shaped output on stdout so a Python-launcher rc=1 (e.g.
        # a missing __main__.py) cannot pass this test by accident: D001
        # is an envcheck-specific diagnostic code that can only appear if
        # the tool actually ran and produced its documented drift finding.
        template = os.path.join(EXAMPLES_DIR, "template.env")
        local = os.path.join(EXAMPLES_DIR, "local.env")
        for path, label in ((template, "template.env"), (local, "local.env")):
            self.assertTrue(
                os.path.isfile(path),
                f"examples/{label} is a documented artifact; missing here "
                "means the example fixture regressed and the README examples "
                "no longer run.",
            )
        r = _run(template, local, "--quiet")
        self.assertNotEqual(
            r.returncode,
            0,
            "envcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "D001",
            r.stdout,
            "expected envcheck to emit the D001 drift diagnostic for the "
            "REDIS_URL key that template.env documents but local.env omits; "
            "instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
