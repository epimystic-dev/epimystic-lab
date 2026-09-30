"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for agentmdlint by asserting
them directly against the ``python -m agentmdlint`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty inputs are the shipped
demonstration fixtures (``examples/healthy_AGENTS.md`` /
``examples/unhealthy_AGENTS.md``), so a regression to those fixtures also
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
        [sys.executable, "-m", "agentmdlint", *args],
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
        self.assertIn("agentmdlint", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy
        # example carries no dated fragments, so AGENTMD-007 cannot drift
        # into firing as system time advances - the assertion stays stable
        # without a --today pin.
        path = os.path.join(EXAMPLES_DIR, "healthy_AGENTS.md")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_AGENTS.md is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_clean_text_run_writes_nothing_to_stdout(self):
        # Invariant 4 (docs/CONVENTIONS.md Stdout / stderr discipline):
        # a silent rc=0 text-mode run must produce zero bytes on stdout,
        # so a `jq` / `test -s` / `| head` CI wrapper piping the tool's
        # stdout can rely on empty stdout meaning "nothing to look at".
        # agentmdlint follows Convention B (severity-tiered), so rc=0
        # means no medium/high/critical findings and no unknown verdict.
        # examples/healthy_AGENTS.md carries no dated fragments (so
        # AGENTMD-007 cannot drift into firing as system time advances)
        # and no medium/high signal, which resolves to verdict=healthy
        # and rc=0. The verdict-and-counts block must land on stderr,
        # not stdout. --json mode is exempt from this invariant (JSON
        # output goes to stdout regardless of rc); the JSON path is
        # exercised by tests/test_cli.py's --json tests.
        path = os.path.join(EXAMPLES_DIR, "healthy_AGENTS.md")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_AGENTS.md is a documented artifact; "
            "missing here means the example fixture regressed.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout,
            "",
            "agentmdlint emitted bytes on stdout for a rc=0 text-mode "
            "run; docs/CONVENTIONS.md Stdout / stderr discipline "
            "requires the verdict-and-counts block to route to stderr "
            "in this case. stdout was: " + repr(r.stdout),
        )
        self.assertIn(
            "verdict: healthy",
            r.stderr,
            "expected the verdict line on stderr for a rc=0 text-mode "
            "run; stderr was: " + repr(r.stderr),
        )

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # agentmdlint-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: AGENTMD-008 is an
        # agentmdlint-specific rule code that can only appear if the tool
        # actually ran and produced its documented contradiction diagnostic
        # against the paired "must always use tabs" / "should never use
        # tabs" lines in unhealthy_AGENTS.md. AGENTMD-008 is severity=HIGH
        # under agentmdlint's Convention B tiering, so its presence also
        # anchors the rc=2 outcome to the specific rule rather than to
        # argparse noise. The shared-contract test asserts only the weaker
        # CONVENTIONS.md-shared "rc != 0 iff findings" invariant so a
        # future move onto (or off) Convention B does not need to touch
        # this file; the tighter agentmdlint-specific rc=2 assertion on
        # the contradictions fixture is already exercised by
        # tests/test_end_to_end.py::TestFixtureContradictions.
        path = os.path.join(EXAMPLES_DIR, "unhealthy_AGENTS.md")
        self.assertTrue(
            os.path.isfile(path),
            "examples/unhealthy_AGENTS.md is a documented artifact; "
            "missing here means the example fixture regressed and the "
            "README's demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "agentmdlint exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "AGENTMD-008",
            r.stdout,
            "expected agentmdlint to emit the AGENTMD-008 diagnostic for "
            "the paired must/never-tabs contradiction in "
            "unhealthy_AGENTS.md; instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
