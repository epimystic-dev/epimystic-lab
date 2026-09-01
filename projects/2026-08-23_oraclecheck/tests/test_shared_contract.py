"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for oraclecheck by asserting
them directly against the ``python -m oraclecheck`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty inputs are the shipped
demonstration fixtures (``examples/healthy_test.py`` /
``examples/unhealthy_test.py``), so a regression to those fixtures also
trips.
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
        [sys.executable, "-m", "oraclecheck", *args],
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
        self.assertIn("oraclecheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy
        # example asserts against hand-written literals only, so no
        # oraclecheck rule can fire regardless of the SUT-inference hint
        # or system clock - the assertion stays stable without pinning.
        path = os.path.join(EXAMPLES_DIR, "healthy_test.py")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_test.py is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # oraclecheck-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: ORACLE-001 is an
        # oraclecheck-specific rule code that can only appear if the tool
        # actually ran and produced its documented self-comparison
        # diagnostic against the paired `mymod.compute(3), mymod.compute(3)`
        # assertion at unhealthy_test.py:17. ORACLE-001 is severity=HIGH
        # under oraclecheck's Convention B tiering, so its presence also
        # anchors the rc=2 outcome to the specific rule rather than to
        # argparse noise. It is also structural-AST-only (no time or SUT
        # inference), so it fires independent of --today or filename-
        # derived SUT hints, keeping the assertion stable across
        # environments. The shared-contract test asserts only the weaker
        # CONVENTIONS.md-shared "rc != 0 iff findings" invariant so a
        # future move onto (or off) Convention B does not need to touch
        # this file; the tighter oraclecheck-specific rc=2 assertion on
        # the anchored-oracle fixtures is already exercised by
        # tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "unhealthy_test.py")
        self.assertTrue(
            os.path.isfile(path),
            "examples/unhealthy_test.py is a documented artifact; "
            "missing here means the example fixture regressed and the "
            "README's demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "oraclecheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "ORACLE-001",
            r.stdout,
            "expected oraclecheck to emit the ORACLE-001 diagnostic for "
            "the paired mymod.compute(3), mymod.compute(3) self-comparison "
            "in unhealthy_test.py; instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
