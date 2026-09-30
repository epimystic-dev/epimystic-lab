"""Shared contract tests for approvchainlint.

Two contracts are locked here:

1. Package-surface invariants (PackageSurfaceTests) - the public API
   surface this module exports (``__version__``, ``Severity``,
   ``Verdict``, ``Finding``, ``ScanResult``, ``ALL_RULES``, ``Rule``,
   and a callable ``main``), plus the AC-* rule-ID convention.

2. CI-consumer invariants (SharedContractInvariants) - the three
   invariants from epimystic-lab/docs/CONVENTIONS.md that every lab
   linter locks against its ``python -m <tool>`` subprocess entry:

     a. ``python -m approvchainlint --help`` returns rc 0.
     b. ``python -m approvchainlint`` on a known-clean input returns rc 0.
     c. ``python -m approvchainlint`` on a known-dirty input returns
        non-zero, with the AC-001 diagnostic anchored on stdout.

   These are exercised indirectly elsewhere in this suite via
   ``main(argv)`` calls, but are collected here as one named contract
   test so a regression against CONVENTIONS.md surfaces here first.
   The clean/dirty inputs are the shipped demonstration fixtures
   (``examples/healthy_config.json`` / ``examples/weak_config.json``),
   so a regression to those fixtures also trips.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401  (import for the tempdir redirect)

import approvchainlint
from approvchainlint.cli import main
from approvchainlint.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "approvchainlint", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(approvchainlint.__version__, str)
        self.assertRegex(approvchainlint.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(approvchainlint, name), name)

    def test_shared_rule_table_alias_is_the_internal_registry(self):
        # ALL_RULES is the lab-wide spelling; REGISTRY is this tool's
        # internal one. They must stay the same object or a consumer
        # reading the shared surface would silently see a different
        # rule set.
        self.assertIs(approvchainlint.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_form_ac_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("AC-"), r.id)


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("approvchainlint", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # The healthy example is defensibly-scoped and fires no rule
        # under either the default or the --strict configuration.
        path = os.path.join(EXAMPLES_DIR, "healthy_config.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_config.json is a documented artifact",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # AC-001 is an approvchainlint-specific rule that fires
        # deterministically on the wildcard `Bash(*)` scope in
        # weak_config.json. It has no time, environment, or filename
        # dependency, so it fires everywhere.
        path = os.path.join(EXAMPLES_DIR, "weak_config.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/weak_config.json is a documented artifact",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "approvchainlint exited 0 on a known-dirty input",
        )
        self.assertIn(
            "AC-001",
            r.stdout,
            "expected approvchainlint to emit the AC-001 diagnostic "
            "against the wildcard Bash(*) scope; stdout was: "
            + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
