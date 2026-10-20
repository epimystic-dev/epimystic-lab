"""Shared contract tests for mcpservercheck.

Two contracts are locked here:

1. Package-surface invariants (PackageSurfaceTests) - the public API surface
   this module exports (`__version__`, `Severity`, `Verdict`, `Finding`,
   `ScanResult`, `ALL_RULES`, `Rule`, and a callable `main`), plus the
   MSC-* rule-ID convention.

2. CI-consumer invariants (SharedContractInvariants) - the three invariants
   from epimystic-lab/docs/CONVENTIONS.md that every lab linter locks
   against its ``python -m <tool>`` subprocess entry point:

     a. ``python -m mcpservercheck --help`` returns rc 0.
     b. ``python -m mcpservercheck`` on a known-clean input returns rc 0.
     c. ``python -m mcpservercheck`` on a known-dirty input returns non-zero,
        with the MSC-001 diagnostic anchored on stdout.

   The ``test_json_mode_top_level_shape`` invariant below additionally
   locks the 0.3.0 JSON top-level shape convergence target documented in
   CONVENTIONS.md Structured output: ``tool``, ``version``, ``source``,
   ``findings``, and ``summary`` top-level keys, with every pre-0.3.0 key
   retained alongside (additive-only convergence).

   These CI-consumer invariants are exercised indirectly by other files in
   this suite via ``main(argv)`` calls, but this class collects them in one
   named contract test so any regression against CONVENTIONS.md surfaces
   here first. The clean/dirty inputs are the shipped demonstration
   fixtures (``examples/healthy_mcp.json`` / ``examples/weak_mcp.json``),
   so a regression to those fixtures also trips.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

import mcpservercheck
from mcpservercheck.cli import main
from mcpservercheck.rules import ALL_RULES


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "mcpservercheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(mcpservercheck.__version__, str)
        self.assertRegex(mcpservercheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult", "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(mcpservercheck, name), name)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_form_msc_prefix(self):
        for r in ALL_RULES:
            self.assertTrue(r.id.startswith("MSC-"))


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        # Invariant 1: --help must exit 0 so shell wrappers can probe the
        # tool without triggering their own error branches.
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mcpservercheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy MCP
        # example declares servers with pinned commands, https transports,
        # env-var references (no inline credentials), narrowed allowedTools,
        # and no world-writable paths, so no mcpservercheck rule can fire
        # against it regardless of the default or --strict configuration -
        # the assertion stays stable without any per-run pinning.
        #
        # Additionally lock docs/CONVENTIONS.md Stdout / stderr discipline:
        # a rc=0 text-mode run must produce zero bytes on stdout so a
        # `jq` / `test -s` / `| head` CI wrapper piping the tool's
        # stdout can rely on empty stdout meaning "nothing to look at".
        # The three-line verdict / counts / visibility summary must
        # land on stderr, not stdout. --json mode is exempt from this
        # invariant (JSON output goes to stdout regardless of rc); the
        # JSON path is exercised by tests/test_cli.py's --json tests.
        path = os.path.join(EXAMPLES_DIR, "healthy_mcp.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_mcp.json is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout,
            "",
            "mcpservercheck emitted bytes on stdout for a rc=0 text-mode "
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

    def test_json_mode_top_level_shape(self):
        # 0.3.0 convergence lock (docs/CONVENTIONS.md Structured output).
        # The target wrapping-object shape is
        # `{"tool", "version", "source", "findings": [...], "summary": {...}}`
        # with pre-0.3.0 keys (`verdict`, `exit_code`, `files_scanned`,
        # `counts`, `errors`) additionally retained for backward
        # compatibility. We assert on the clean-input case so neither the
        # include-info toggle nor verdict-rollup state is in the way; the
        # empty-findings list still has to be a list, not an absent key.
        path = os.path.join(EXAMPLES_DIR, "healthy_mcp.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_mcp.json is a documented artifact; missing "
            "here means the example fixture regressed.",
        )
        r = _run("--json", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload.get("tool"), "mcpservercheck")
        # Match the package's own __version__ so a future bump keeps the
        # lock aligned without a manual edit here.
        self.assertEqual(payload.get("version"), mcpservercheck.__version__)
        self.assertIn("source", payload)
        self.assertTrue(
            payload["source"].endswith("healthy_mcp.json")
            or payload["source"] == path,
            "expected source to echo the scanned path; got: "
            + repr(payload.get("source")),
        )
        self.assertIsInstance(payload.get("findings"), list)
        self.assertIsInstance(payload.get("summary"), dict)
        summary = payload["summary"]
        for key in ("total_findings", "files_scanned", "by_severity"):
            self.assertIn(
                key,
                summary,
                "summary is missing '" + key + "'; see "
                "docs/CONVENTIONS.md Structured output for the target "
                "summary shape.",
            )
        self.assertIsInstance(summary["by_severity"], dict)
        for sev in ("HIGH", "MEDIUM", "INFO"):
            self.assertIn(
                sev,
                summary["by_severity"],
                "summary.by_severity is missing '" + sev + "'; the "
                "converged shape keys all three severities so a CI "
                "consumer can gate on any one without defensive gets.",
            )
        # Pre-0.3.0 keys must still be present (additive-only convergence).
        for pre_key in ("verdict", "exit_code", "files_scanned", "counts", "errors"):
            self.assertIn(
                pre_key,
                payload,
                "pre-0.3.0 top-level key '" + pre_key + "' missing; the "
                "convergence must be additive-only (see "
                "docs/CONVENTIONS.md Structured output).",
            )

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same
        # CI gate above actually catches something. We additionally require
        # mcpservercheck-shaped output on stdout so a Python-launcher rc=2
        # (e.g. a missing __main__.py, or argparse rejecting an unknown
        # flag) cannot pass this test by accident: MSC-001 is a
        # mcpservercheck-specific rule code that can only appear if the
        # tool actually ran and produced its documented eval-interpreter
        # diagnostic against the `shell-eval` server at weak_mcp.json:3.
        # MSC-001 is severity=HIGH under mcpservercheck's Convention B
        # tiering, so its presence also anchors the rc=2 outcome to the
        # specific rule rather than to argparse noise. It is also a purely
        # lexical command+args match with no time, environment, or
        # filename dependency, so it fires deterministically across
        # environments. The shared-contract test asserts only the weaker
        # CONVENTIONS.md-shared "rc != 0 iff findings" invariant so a
        # future move onto (or off) Convention B does not need to touch
        # this file; the tighter mcpservercheck-specific rc=2 assertion
        # on the anchored-shape fixtures is already exercised by
        # tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "weak_mcp.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/weak_mcp.json is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "mcpservercheck exited 0 on a known-dirty input; the "
            "CI-consumer contract in docs/CONVENTIONS.md requires a "
            "non-zero rc here.",
        )
        self.assertIn(
            "MSC-001",
            r.stdout,
            "expected mcpservercheck to emit the MSC-001 diagnostic for "
            "the shell-eval interpreter server in weak_mcp.json; instead "
            "stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
