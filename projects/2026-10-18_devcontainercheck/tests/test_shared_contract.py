"""Shared contract tests for devcontainercheck.

Two contracts are locked here:

1. Package-surface invariants - the public API this module exports
   (``__version__``, ``Severity``, ``Verdict``, ``Finding``,
   ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable ``main``),
   plus the DC-* rule-ID convention.

2. CI-consumer invariants (from epimystic-lab/docs/CONVENTIONS.md)
   locked against the ``python -m <tool>`` subprocess entry:

     a. ``python -m devcontainercheck --help`` returns rc 0.
     b. ``python -m devcontainercheck`` on a known-clean input returns
        rc 0.
     c. ``python -m devcontainercheck`` on a known-dirty input returns
        non-zero with the DC-001 anchor on stdout.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401  (import for tempdir redirect)

import devcontainercheck
from devcontainercheck.cli import main
from devcontainercheck.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "devcontainercheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(devcontainercheck.__version__, str)
        self.assertRegex(devcontainercheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(devcontainercheck, name), name)

    def test_shared_rule_table_alias_is_internal_registry(self):
        self.assertIs(devcontainercheck.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_use_dc_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("DC-"), r.id)


class SharedContractInvariants(unittest.TestCase):
    def test_version_returns_zero_without_a_path(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(),
            "devcontainercheck " + devcontainercheck.__version__,
        )

    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("devcontainercheck", r.stdout)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_devcontainer.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        path = os.path.join(EXAMPLES_DIR, "weak_devcontainer.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "devcontainercheck exited 0 on a known-dirty input",
        )
        self.assertIn(
            "DC-001", r.stdout,
            "expected DC-001 diagnostic; stdout: " + repr(r.stdout),
        )


class RuleRegistryDocumentationTests(unittest.TestCase):
    """Every rule in the registry must appear in the project README."""

    def test_every_rule_id_appears_in_readme(self):
        readme = os.path.join(PKG_DIR, "README.md")
        self.assertTrue(os.path.isfile(readme), readme)
        with open(readme, "r", encoding="utf-8") as f:
            text = f.read()
        missing = [r.id for r in REGISTRY if r.id not in text]
        self.assertEqual(
            missing, [],
            "rule ids missing from README: " + repr(missing),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
