"""Shared CI-consumer contract test (see epimystic-lab/docs/CONVENTIONS.md).

CONVENTIONS.md documents four invariants that CI consumers rely on across
every lab linter. This file locks the four for elevatescan by asserting
them directly against the ``python -m elevatescan`` subprocess entry point:

  1. ``python -m <tool> --help`` returns rc 0.
  2. ``python -m <tool>`` on a known-clean input returns rc 0.
  3. ``python -m <tool>`` on a known-dirty input returns non-zero.
  4. ``python -m <tool> --json`` emits a top-level wrapping object
     carrying ``tool``, ``version``, ``source``, ``findings``, and
     ``summary`` keys per the JSON-top-level-shape convergence target
     documented in docs/CONVENTIONS.md Structured output.

These invariants are exercised indirectly by other files in this suite, but
this file collects them in one named contract test so any regression against
CONVENTIONS.md surfaces here first. The clean/dirty inputs are the shipped
demonstration fixtures (``examples/healthy_notes.md`` /
``examples/malicious_notes.md``), so a regression to those fixtures also
trips.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

import elevatescan


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "elevatescan", *args],
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
        self.assertIn("elevatescan", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy
        # example is a plain-prose retrospective note with no role
        # markers, override directives, persistent-goal writes, scheduled
        # tasks, authority claims, or tool-output shapes, so no
        # elevatescan rule can fire against it regardless of the default
        # or --strict configuration - the assertion stays stable without
        # any per-run pinning.
        #
        # Additionally lock docs/CONVENTIONS.md Stdout / stderr discipline:
        # a rc=0 text-mode run must produce zero bytes on stdout so a
        # `jq` / `test -s` / `| head` CI wrapper piping the tool's stdout
        # can rely on empty stdout meaning "nothing to look at". The
        # three-line verdict / counts / visibility summary must land on
        # stderr, not stdout. --json mode is exempt from this invariant
        # (JSON output goes to stdout regardless of rc); the JSON path is
        # exercised by tests/test_cli.py's --json tests.
        path = os.path.join(EXAMPLES_DIR, "healthy_notes.md")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_notes.md is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout,
            "",
            "elevatescan emitted bytes on stdout for a rc=0 text-mode "
            "run; docs/CONVENTIONS.md Stdout / stderr discipline "
            "requires the verdict summary to route to stderr in this "
            "case. stdout was: " + repr(r.stdout),
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
        # elevatescan-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: ESC-001 is an
        # elevatescan-specific rule code that can only appear if the tool
        # actually ran and produced its documented role-impersonation
        # diagnostic against the paired `<|im_start|>system` /
        # `<|im_end|>` chatml markers at malicious_notes.md:9 and
        # malicious_notes.md:12. ESC-001 is severity=HIGH under
        # elevatescan's Convention B tiering, so its presence also
        # anchors the rc=2 outcome to the specific rule rather than to
        # argparse noise. It is also a purely lexical regex match with
        # no time, environment, or filename dependency, so it fires
        # deterministically across environments. The shared-contract
        # test asserts only the weaker CONVENTIONS.md-shared "rc != 0
        # iff findings" invariant so a future move onto (or off)
        # Convention B does not need to touch this file; the tighter
        # elevatescan-specific rc=2 assertion on the anchored-role-marker
        # fixtures is already exercised by tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "malicious_notes.md")
        self.assertTrue(
            os.path.isfile(path),
            "examples/malicious_notes.md is a documented artifact; "
            "missing here means the example fixture regressed and the "
            "README's demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "elevatescan exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "ESC-001",
            r.stdout,
            "expected elevatescan to emit the ESC-001 diagnostic for the "
            "chatml role-marker shapes in malicious_notes.md; instead "
            "stdout was: " + repr(r.stdout),
        )

    def test_json_mode_top_level_shape(self):
        # Invariant 4: --json emits a wrapping object matching the
        # JSON-top-level-shape convergence target documented in
        # docs/CONVENTIONS.md Structured output. A CI consumer that
        # aggregates JSON payloads from several lab linters must be able
        # to read `tool`, `version`, `source`, `findings`, and `summary`
        # at the top level with the same shape across every converged
        # linter without per-tool special-casing. The pre-0.3.0 keys
        # that have shipped in elevatescan since first publication
        # (`verdict`, `files_scanned`, `findings_total`,
        # `findings_visible`, `counts`, `errors`) are additionally
        # asserted so a future consumer that reads them continues to
        # work after this convergence pass. The clean fixture
        # `examples/healthy_notes.md` is used so the assertion stays
        # stable without per-run pinning: `findings` is a list (may be
        # empty), `summary` is a dict with the three target keys
        # (`total_findings`, `files_scanned`, `by_severity`), and
        # `by_severity` carries all three severity buckets regardless
        # of whether any finding fell in them.
        path = os.path.join(EXAMPLES_DIR, "healthy_notes.md")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_notes.md is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run("--json", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["tool"], "elevatescan")
        self.assertEqual(payload["version"], elevatescan.__version__)
        self.assertTrue(
            payload["source"].endswith("healthy_notes.md"),
            "expected `source` to echo the scanned path; got: "
            + repr(payload.get("source")),
        )
        self.assertIsInstance(payload["findings"], list)
        self.assertIsInstance(payload["summary"], dict)
        self.assertIn("total_findings", payload["summary"])
        self.assertIn("files_scanned", payload["summary"])
        self.assertIn("by_severity", payload["summary"])
        self.assertIn("HIGH", payload["summary"]["by_severity"])
        self.assertIn("MEDIUM", payload["summary"]["by_severity"])
        self.assertIn("INFO", payload["summary"]["by_severity"])
        # Pre-0.3.0 keys retained -- additive-only convergence.
        for pre_key in (
            "verdict",
            "files_scanned",
            "findings_total",
            "findings_visible",
            "counts",
            "errors",
        ):
            self.assertIn(
                pre_key,
                payload,
                "pre-0.3.0 top-level key `"
                + pre_key
                + "` is missing from the --json payload; the convergence "
                "pass must be additive-only and must not drop any key.",
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
