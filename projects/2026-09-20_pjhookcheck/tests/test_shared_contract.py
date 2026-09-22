"""Shared contract tests for pjhookcheck.

Two contracts are locked here:

1. Package-surface invariants (PackageSurfaceTests) - the public API surface
   this module exports (``__version__``, ``Severity``, ``Verdict``,
   ``Finding``, ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable
   ``main``), plus the PJH-* rule-ID convention.

2. CI-consumer invariants (SharedContractInvariants) - the three invariants
   from epimystic-lab/docs/CONVENTIONS.md that every lab linter locks
   against its ``python -m <tool>`` subprocess entry point:

     a. ``python -m pjhookcheck --help`` returns rc 0.
     b. ``python -m pjhookcheck`` on a known-clean input returns rc 0.
     c. ``python -m pjhookcheck`` on a known-dirty input returns non-zero,
        with the PJH-001 diagnostic anchored on stdout.

   These are exercised indirectly elsewhere in this suite via ``main(argv)``
   calls, but are collected here as one named contract test so a regression
   against CONVENTIONS.md surfaces in this file first. The clean/dirty
   inputs are the shipped demonstration fixtures
   (``examples/healthy_package.json`` / ``examples/weak_package.json``), so a
   regression to those fixtures also trips.

This module is deliberately invoked as ``tests.test_shared_contract`` so the
package ``__init__`` runs and applies the tempdir redirect described in
tests/support.py.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401  (import for the tempdir redirect)

import pjhookcheck
from pjhookcheck.cli import main
from pjhookcheck.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "pjhookcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(pjhookcheck.__version__, str)
        self.assertRegex(pjhookcheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(pjhookcheck, name), name)

    def test_shared_rule_table_alias_is_the_internal_registry(self):
        # ALL_RULES is the lab-wide spelling; REGISTRY is this tool's internal
        # one. They must stay the same object, or a consumer reading the
        # shared surface would silently see a different rule set.
        self.assertIs(pjhookcheck.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_form_pjh_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("PJH-"), r.id)


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        # Invariant 1: --help must exit 0 so shell wrappers can probe the
        # tool without tripping their own error branches.
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pjhookcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` need no per-tool knowledge. The healthy example
        # declares pinned dependencies, no lifecycle hooks that fetch or
        # evaluate, no url or file specifiers, and no credential echoes, so
        # no pjhookcheck rule can fire against it under either the default
        # or the --strict configuration - the assertion stays stable
        # without any per-run pinning.
        path = os.path.join(EXAMPLES_DIR, "healthy_package.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_package.json is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same CI
        # gate actually catches something. We additionally require
        # pjhookcheck-shaped output on stdout so a Python-launcher rc=2
        # (a missing __main__.py, or argparse rejecting an unknown flag)
        # cannot pass this test by accident: PJH-001 is a pjhookcheck-
        # specific rule code that can only appear if the tool actually ran
        # and produced its documented fetch-and-execute diagnostic against
        # the `preinstall` hook in weak_package.json. PJH-001 is a purely
        # lexical match over the hook body with no time, environment, or
        # filename dependency, so it fires deterministically everywhere.
        # This test asserts only the weaker CONVENTIONS.md-shared
        # "rc != 0 iff findings" invariant so a future change of exit-code
        # convention does not need to touch this file; the tighter rc=2
        # assertion lives in tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "weak_package.json")
        self.assertTrue(
            os.path.isfile(path),
            "examples/weak_package.json is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "pjhookcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "PJH-001",
            r.stdout,
            "expected pjhookcheck to emit the PJH-001 diagnostic for the "
            "fetch-and-execute preinstall hook in weak_package.json; "
            "instead stdout was: " + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
