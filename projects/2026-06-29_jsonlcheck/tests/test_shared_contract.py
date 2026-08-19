"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for jsonlcheck by asserting them
directly against the ``python -m jsonlcheck`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty inputs are the same
fixtures the README example commands cite (``examples/ok.jsonl`` /
``examples/bad.jsonl``), so a regression to those fixtures also trips.
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
        [sys.executable, "-m", "jsonlcheck", *args],
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
        self.assertIn("jsonlcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge.
        path = os.path.join(EXAMPLES_DIR, "ok.jsonl")
        self.assertTrue(
            os.path.isfile(path),
            "examples/ok.jsonl is a documented artifact; missing here means the "
            "example fixture regressed and the README examples no longer run.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # jsonlcheck-shaped output on stderr so a Python-launcher rc=1 (e.g.
        # a missing __main__.py) cannot pass this test by accident.
        path = os.path.join(EXAMPLES_DIR, "bad.jsonl")
        self.assertTrue(
            os.path.isfile(path),
            "examples/bad.jsonl is a documented artifact; missing here means the "
            "example fixture regressed and the README examples no longer run.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "jsonlcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "bad.jsonl",
            r.stderr,
            "expected jsonlcheck to name the offending file in its stderr "
            "diagnostic; instead stderr was: " + repr(r.stderr),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
