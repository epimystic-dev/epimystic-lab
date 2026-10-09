"""Shared contract tests for mcptoolcheck.

Two contracts are locked here:

1. Package-surface invariants - the public API this module exports
   (``__version__``, ``Severity``, ``Verdict``, ``Finding``,
   ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable ``main``),
   plus the MTC-* rule-ID convention.

2. CI-consumer invariants from epimystic-lab/docs/CONVENTIONS.md
   locked against the ``python -m <tool>`` subprocess entry:

     a. ``python -m mcptoolcheck --help`` returns rc 0.
     b. ``python -m mcptoolcheck`` on a known-clean input returns rc 0.
     c. ``python -m mcptoolcheck`` on a known-dirty input returns
        non-zero with the MTC-001 anchor on stdout.

   The clean / dirty inputs are the shipped demonstration fixtures
   (examples/healthy_tooldesc.json and examples/weak_tooldesc.json),
   so a regression there trips first.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401  (import for tempdir redirect)

import mcptoolcheck
from mcptoolcheck.cli import main
from mcptoolcheck.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "mcptoolcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(mcptoolcheck.__version__, str)
        self.assertRegex(mcptoolcheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(mcptoolcheck, name), name)

    def test_shared_rule_table_alias_is_internal_registry(self):
        self.assertIs(mcptoolcheck.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_use_mtc_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("MTC-"), r.id)


class SharedContractInvariants(unittest.TestCase):
    def test_version_returns_zero_without_a_path(self):
        # `paths` is a required positional, so a naive --version flag would
        # make argparse exit 2 for "the following arguments are required".
        # The shared contract requires --version to answer on its own.
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "mcptoolcheck " + mcptoolcheck.__version__)

    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mcptoolcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_tooldesc.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # MTC-001 fires deterministically on the TAG character embedded
        # in the first tool's description in weak_tooldesc.json. No
        # time, environment, or filename dependency; it fires everywhere.
        path = os.path.join(EXAMPLES_DIR, "weak_tooldesc.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "mcptoolcheck exited 0 on a known-dirty input",
        )
        self.assertIn(
            "MTC-001", r.stdout,
            "expected MTC-001 diagnostic against TAG block; stdout: "
            + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
