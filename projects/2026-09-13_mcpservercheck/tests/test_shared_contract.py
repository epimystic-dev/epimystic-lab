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

   These CI-consumer invariants are exercised indirectly by other files in
   this suite via ``main(argv)`` calls, but this class collects them in one
   named contract test so any regression against CONVENTIONS.md surfaces
   here first. The clean/dirty inputs are the shipped demonstration
   fixtures (``examples/healthy_mcp.json`` / ``examples/weak_mcp.json``),
   so a regression to those fixtures also trips.
"""

from __future__ import annotations

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
        path = os.path.join(EXAMPLES_DIR, "healthy_mcp.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_mcp.json is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

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
