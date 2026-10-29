"""Shared contract tests for agentmemcheck.

Two contracts are locked here:

1. Package-surface invariants - the public API this module exports
   (``__version__``, ``Severity``, ``Verdict``, ``Finding``,
   ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable ``main``),
   plus the AMC-* rule-ID convention.

2. CI-consumer invariants (from epimystic-lab/docs/CONVENTIONS.md)
   locked against the ``python -m <tool>`` subprocess entry:

     a. ``python -m agentmemcheck --help`` returns rc 0.
     b. ``python -m agentmemcheck`` on a known-clean input returns
        rc 0.
     c. ``python -m agentmemcheck`` on a known-dirty input returns
        non-zero with the AMC-001 anchor on stdout.

   The clean / dirty inputs are the shipped demonstration fixtures
   (examples/healthy_memstore.json and examples/weak_memstore.json),
   so a regression there trips first.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401  (import for tempdir redirect)

import agentmemcheck
from agentmemcheck.cli import main
from agentmemcheck.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "agentmemcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(agentmemcheck.__version__, str)
        self.assertRegex(agentmemcheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(agentmemcheck, name), name)

    def test_shared_rule_table_alias_is_internal_registry(self):
        self.assertIs(agentmemcheck.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_use_amc_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("AMC-"), r.id)


class SharedContractInvariants(unittest.TestCase):
    def test_version_returns_zero_without_a_path(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(),
            "agentmemcheck " + agentmemcheck.__version__,
        )

    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("agentmemcheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_memstore.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Lock docs/CONVENTIONS.md Stdout / stderr discipline: a rc=0
        # text-mode run must produce zero bytes on stdout so a `jq` /
        # `test -s` / `| head` CI wrapper piping the tool's stdout can
        # rely on empty stdout meaning "nothing to look at". The
        # one-line verdict / counts summary must land on stderr, not
        # stdout. --json mode is exempt (JSON output goes to stdout
        # regardless of rc); the JSON path is exercised by test_cli.py.
        self.assertEqual(
            r.stdout,
            "",
            "agentmemcheck emitted bytes on stdout for a rc=0 text-mode "
            "run; docs/CONVENTIONS.md Stdout / stderr discipline requires "
            "the verdict summary to route to stderr. stdout was: "
            + repr(r.stdout),
        )
        self.assertIn(
            "healthy",
            r.stderr,
            "expected the verdict line on stderr for a rc=0 text-mode "
            "run; stderr was: " + repr(r.stderr),
        )

    def test_known_dirty_input_returns_nonzero(self):
        # AMC-001 fires deterministically on the TAG character embedded
        # in the first memory entry's content in weak_memstore.json.
        # No time, environment, or filename dependency; it fires
        # everywhere.
        path = os.path.join(EXAMPLES_DIR, "weak_memstore.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "agentmemcheck exited 0 on a known-dirty input",
        )
        self.assertIn(
            "AMC-001", r.stdout,
            "expected AMC-001 diagnostic against TAG block; stdout: "
            + repr(r.stdout),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
