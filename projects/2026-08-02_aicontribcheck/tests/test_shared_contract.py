"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for aicontribcheck by asserting
them directly against the ``python -m aicontribcheck`` subprocess entry
point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

aicontribcheck follows Convention C (verdict-based) rather than the
severity-blind Convention A or the severity-tiered Convention B. Under
Convention C, rc 0 requires an explicit ALLOWED verdict, so
``tests/fixtures/allow_repo`` (an explicit-allow CONTRIBUTING.md) is the
correct known-clean input rather than an empty repo (which would exit rc 1
under the UNKNOWN verdict). CONVENTIONS.md calls this out explicitly in the
"What CI consumers can rely on today" section as the "aicontribcheck
verdict caveat".

These invariants are exercised indirectly by other files in this suite,
but this file collects them in one named contract test so any regression
against CONVENTIONS.md surfaces here first. The clean/dirty fixture paths
are the same ones ``examples/demo.sh`` uses, so a regression to either
fixture also trips a named test here.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(PKG_DIR, "tests", "fixtures")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "aicontribcheck", *args],
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
        self.assertIn("aicontribcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. Under
        # aicontribcheck's Convention C verdict encoding, rc 0 requires
        # an explicit ALLOWED verdict; tests/fixtures/allow_repo carries
        # a CONTRIBUTING.md with an explicit-allow statement that resolves
        # to verdict=allowed and rc=0.
        path = os.path.join(FIXTURES_DIR, "allow_repo")
        self.assertTrue(
            os.path.isdir(path),
            "tests/fixtures/allow_repo is a documented artifact "
            "(examples/demo.sh runs against it); missing here means the "
            "fixture regressed and the demo command no longer runs.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # aicontribcheck-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: AICONTRIB-001 is an
        # aicontribcheck-specific rule code that can only appear if the
        # tool actually ran and produced its documented explicit-ban
        # diagnostic against ban_repo (CONTRIBUTING.md line 7 declares
        # "does not accept AI-generated contributions"). Under
        # Convention C the ban verdict pins rc to 2, but the shared-
        # contract test asserts only the weaker CONVENTIONS.md-shared
        # "rc != 0 iff findings" invariant so a future recategorisation
        # of the tool's exit convention does not need to touch this file;
        # the tighter aicontribcheck-specific rc=2 assertion is already
        # exercised by tests/test_cli.py::ExitCodeTests.
        path = os.path.join(FIXTURES_DIR, "ban_repo")
        self.assertTrue(
            os.path.isdir(path),
            "tests/fixtures/ban_repo is a documented artifact "
            "(examples/demo.sh runs against it); missing here means the "
            "fixture regressed and the demo command no longer runs.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "aicontribcheck exited 0 on a known-dirty input; the "
            "CI-consumer contract in docs/CONVENTIONS.md requires a "
            "non-zero rc here.",
        )
        self.assertIn(
            "AICONTRIB-001",
            r.stdout,
            "expected aicontribcheck to emit the AICONTRIB-001 diagnostic "
            "for the explicit-ban line in ban_repo/CONTRIBUTING.md; "
            "instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
