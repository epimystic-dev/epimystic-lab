"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for delegcheck by asserting
them directly against the ``python -m delegcheck`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty inputs are the shipped
demonstration fixtures (``examples/healthy_delegation.json`` /
``examples/weak_delegation.json``), so a regression to those fixtures also
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
        [sys.executable, "-m", "delegcheck", *args],
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
        self.assertIn("delegcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy
        # delegation example declares scoped credentials with explicit
        # expiries, tools with named principals, delegation edges with
        # narrowed scope and depth caps, and an external authorization
        # mode, so no delegcheck rule can fire against it regardless of
        # the default or --strict configuration - the assertion stays
        # stable without any per-run pinning.
        path = os.path.join(EXAMPLES_DIR, "healthy_delegation.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_delegation.json is a documented artifact; "
            "missing here means the example fixture regressed and the "
            "README's demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # delegcheck-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: DEL-001 is a
        # delegcheck-specific rule code that can only appear if the tool
        # actually ran and produced its documented unbounded-scope
        # diagnostic against the `scope: '*'` bearer credential at
        # weak_delegation.json:8. DEL-001 is severity=HIGH under
        # delegcheck's Convention B tiering, so its presence also anchors
        # the rc=2 outcome to the specific rule rather than to argparse
        # noise. It is also a purely lexical scope-token match with no
        # time, environment, or filename dependency, so it fires
        # deterministically across environments. The shared-contract
        # test asserts only the weaker CONVENTIONS.md-shared "rc != 0
        # iff findings" invariant so a future move onto (or off)
        # Convention B does not need to touch this file; the tighter
        # delegcheck-specific rc=2 assertion on the anchored-shape
        # fixtures is already exercised by tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "weak_delegation.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/weak_delegation.json is a documented artifact; "
            "missing here means the example fixture regressed and the "
            "README's demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "delegcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "DEL-001",
            r.stdout,
            "expected delegcheck to emit the DEL-001 diagnostic for the "
            "unbounded-scope bearer credential in weak_delegation.json; "
            "instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
