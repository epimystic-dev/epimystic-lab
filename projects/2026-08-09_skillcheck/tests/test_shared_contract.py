"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for skillcheck by asserting
them directly against the ``python -m skillcheck`` subprocess entry
point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

skillcheck follows Convention C (verdict-based) rather than the
severity-blind Convention A or the severity-tiered Convention B. Under
Convention C, rc 0 requires an explicit SAFE verdict, so
``tests/fixtures/safe_skill`` (a SKILL.md with a declared allowed_tools
list and no suspicious content) is the correct known-clean input rather
than an empty repo (which would exit rc 1 under the UNKNOWN verdict).
CONVENTIONS.md calls this out explicitly in the evidence table footnote
as the "skillcheck verdict caveat" (clean rc annotated as 1* because
most inputs land in UNKNOWN, not SAFE).

These invariants are exercised indirectly by other files in this suite,
but this file collects them in one named contract test so any regression
against CONVENTIONS.md surfaces here first. The clean/dirty fixture paths
are the same ones ``tests/test_end_to_end.py`` uses, so a regression to
either fixture also trips a named test here.
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
        [sys.executable, "-m", "skillcheck", *args],
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
        self.assertIn("skillcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. Under
        # skillcheck's Convention C verdict encoding, rc 0 requires an
        # explicit SAFE verdict; tests/fixtures/safe_skill carries a
        # SKILL.md with a declared allowed_tools list and no suspicious
        # content, which resolves to verdict=safe and rc=0.
        path = os.path.join(FIXTURES_DIR, "safe_skill")
        self.assertTrue(
            os.path.isdir(path),
            "tests/fixtures/safe_skill is a documented artifact "
            "(tests/test_end_to_end.py runs against it); missing here "
            "means the fixture regressed and the shared contract can no "
            "longer be asserted.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # skillcheck-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: SKILLCHECK-001 is a
        # skillcheck-specific rule code that can only appear if the tool
        # actually ran and produced its documented destructive-shell
        # diagnostic against shell_skill (SKILL.md body contains
        # `sudo rm -rf /var/tmp/workspace` on line 13, which trips both
        # SKILLCHECK-001 destructive-shell and SKILLCHECK-002 privilege-
        # escalation; asserting the -001 rule specifically anchors the
        # non-zero rc to the destructive-shell pattern, not to argparse
        # noise). Under Convention C the UNSAFE verdict
        # pins rc to 2, but the shared-contract test asserts only the
        # weaker CONVENTIONS.md-shared "rc != 0 iff findings" invariant so
        # a future recategorisation of the tool's exit convention does not
        # need to touch this file; the tighter skillcheck-specific rc=2
        # assertion is already exercised by
        # tests/test_cli.py::TestCLIExitCodes.test_unsafe_repo_exit_2.
        path = os.path.join(FIXTURES_DIR, "shell_skill")
        self.assertTrue(
            os.path.isdir(path),
            "tests/fixtures/shell_skill is a documented artifact "
            "(tests/test_end_to_end.py runs against it); missing here "
            "means the fixture regressed and the shared contract can no "
            "longer be asserted.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "skillcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "SKILLCHECK-001",
            r.stdout,
            "expected skillcheck to emit the SKILLCHECK-001 diagnostic "
            "for the destructive-shell line in shell_skill/SKILL.md; "
            "instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
