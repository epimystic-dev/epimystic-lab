"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for reqcheck by asserting them
directly against the ``python -m reqcheck`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty commands are the same
ones CONVENTIONS.md cites in its evidence table for reqcheck
(``examples/ok.txt`` for clean; ``examples/bad.txt`` for dirty), so a
regression to either fixture also trips.
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
        [sys.executable, "-m", "reqcheck", *args],
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
        self.assertIn("reqcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. examples/ok.txt
        # is the clean-input command documented in docs/CONVENTIONS.md
        # for reqcheck.
        path = os.path.join(EXAMPLES_DIR, "ok.txt")
        self.assertTrue(
            os.path.isfile(path),
            "examples/ok.txt is a documented artifact; missing here means "
            "the example fixture regressed and the README/CONVENTIONS.md "
            "example command no longer runs.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # reqcheck-shaped output on stdout so a Python-launcher rc=2 (e.g.
        # a missing __main__.py, or argparse rejecting an unknown flag)
        # cannot pass this test by accident: REQ-A005 is a reqcheck-specific
        # rule code that can only appear if the tool actually ran and
        # produced its documented --trusted-host diagnostic against bad.txt.
        # REQ-A005 is severity=error under reqcheck's Convention B tiering
        # (see docs/CONVENTIONS.md), so its presence also anchors the rc=2
        # outcome to the specific rule rather than to argparse noise.
        path = os.path.join(EXAMPLES_DIR, "bad.txt")
        self.assertTrue(
            os.path.isfile(path),
            "examples/bad.txt is a documented artifact; missing here means "
            "the example fixture regressed and the README/CONVENTIONS.md "
            "example command no longer runs.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "reqcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "REQ-A005",
            r.stdout,
            "expected reqcheck to emit the REQ-A005 diagnostic for the "
            "--trusted-host line in bad.txt; instead stdout was: "
            + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
