"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents three invariants that CI consumers rely on across
every lab linter. This file locks the three for reqcheck by asserting them
directly against the ``python -m reqcheck`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.

A fourth invariant locked here since 0.3.0 (post the JSON top-level shape
convergence campaign closed by this tool): the ``--json`` payload is a
wrapping object stamped with ``tool`` / ``version`` / ``source`` /
``findings`` / ``summary``, so a CI consumer aggregating JSON across
several lab linters can identify the tool without out-of-band knowledge.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty commands are the same
ones CONVENTIONS.md cites in its evidence table for reqcheck
(``examples/ok.txt`` for clean; ``examples/bad.txt`` for dirty), so a
regression to either fixture also trips.
"""

from __future__ import annotations

import json
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

    def test_clean_text_run_writes_nothing_to_stdout(self):
        # docs/CONVENTIONS.md Stdout / stderr discipline: a silent rc=0
        # text-mode run must produce zero bytes on stdout, so downstream
        # `jq` / `test -s` / `| head` consumers can rely on empty stdout
        # meaning "nothing to look at". The "no findings" summary is
        # diagnostic prose and belongs on stderr. Regression-locks the
        # 2026-09-24 move of the text-mode summary from stdout to stderr;
        # a future revert would surface here first.
        path = os.path.join(EXAMPLES_DIR, "ok.txt")
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout,
            "",
            "clean text-mode run leaked to stdout: " + repr(r.stdout),
        )
        # Summary must still be produced somewhere so operators reading
        # the terminal know the tool ran; stderr is the target channel.
        self.assertIn("no findings", r.stderr)

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

    def test_json_mode_top_level_shape(self):
        # Fourth invariant: --json emits the lab-wide wrapping object
        # `{tool, version, source, findings, summary}` documented in
        # docs/CONVENTIONS.md Structured output. Locked here as part of the
        # 0.3.0 JSON convergence (reqcheck is the last of the ten
        # severity-based linters to converge; a regression to the pre-0.3.0
        # bare-array shape would surface here first). Clean fixture so the
        # findings list is empty and the identity stamping is still exercised.
        from reqcheck import __version__
        path = os.path.join(EXAMPLES_DIR, "ok.txt")
        r = _run("--json", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["tool"], "reqcheck")
        self.assertEqual(payload["version"], __version__)
        self.assertTrue(
            payload["source"].endswith("ok.txt"),
            "source should name the fixture that was scanned; got "
            + repr(payload["source"]),
        )
        self.assertIsInstance(payload["findings"], list)
        self.assertEqual(payload["findings"], [])
        summary = payload["summary"]
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["files_scanned"], 1)
        self.assertIsInstance(summary["by_severity"], dict)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
