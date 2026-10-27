"""Shared contract tests for renovatelint.

Three contracts are locked here:

1. Package-surface invariants - the public API this module exports
   (``__version__``, ``Severity``, ``Verdict``, ``Finding``,
   ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable ``main``),
   plus the RNV-* rule-ID convention.

2. CI-consumer invariants (from epimystic-lab/docs/CONVENTIONS.md)
   locked against the ``python -m <tool>`` subprocess entry:

     a. ``python -m renovatelint --help`` returns rc 0.
     b. ``python -m renovatelint`` on a known-clean input returns rc 0.
     c. ``python -m renovatelint`` on a known-dirty input returns
        non-zero with the RNV-001 anchor on stdout.

3. JSON top-level shape - ``--json`` must emit the lab-wide
   convergence shape ``{"tool", "version", "source", "findings",
   "summary"}``, with ``summary`` carrying ``total_findings``,
   ``files_scanned``, and ``by_severity`` keyed HIGH/MEDIUM/INFO.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401

import renovatelint
from renovatelint.cli import main
from renovatelint.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "renovatelint", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(renovatelint.__version__, str)
        self.assertRegex(renovatelint.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(renovatelint, name), name)

    def test_shared_rule_table_alias_is_internal_registry(self):
        self.assertIs(renovatelint.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_use_rnv_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("RNV-"), r.id)

    def test_rule_table_count(self):
        # The published surface is 12 rules; adding or removing one
        # is a shape change that should land as a documented
        # release-note item, not a silent drift.
        self.assertEqual(len(REGISTRY), 12)


class SharedContractInvariants(unittest.TestCase):
    def test_version_returns_zero_without_a_path(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(),
            "renovatelint " + renovatelint.__version__,
        )

    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("renovatelint", r.stdout)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_renovate.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr + "\n--\n" + r.stdout)

    def test_known_dirty_input_returns_nonzero(self):
        path = os.path.join(EXAMPLES_DIR, "weak_renovate.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "renovatelint exited 0 on a known-dirty input",
        )
        self.assertIn(
            "RNV-001", r.stdout,
            "expected RNV-001 diagnostic; stdout: " + repr(r.stdout),
        )


class JsonModeTopLevelShapeTests(unittest.TestCase):
    """Lab-wide JSON convergence shape (added 0.2.0, 2026-10-27)."""

    def test_clean_input_emits_identity_stamped_wrapping_object(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_renovate.json")
        r = _run("--json", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["tool"], "renovatelint")
        self.assertEqual(payload["version"], renovatelint.__version__)
        self.assertTrue(payload["source"].endswith("healthy_renovate.json"))
        self.assertEqual(payload["findings"], [])
        self.assertIsInstance(payload["summary"], dict)
        self.assertEqual(payload["summary"]["total_findings"], 0)
        self.assertEqual(payload["summary"]["files_scanned"], 1)
        self.assertEqual(
            set(payload["summary"]["by_severity"].keys()),
            {"HIGH", "MEDIUM", "INFO"},
        )

    def test_dirty_input_summary_matches_full_finding_set(self):
        path = os.path.join(EXAMPLES_DIR, "weak_renovate.json")
        r = _run("--json", path)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["tool"], "renovatelint")
        self.assertEqual(payload["version"], renovatelint.__version__)
        self.assertTrue(payload["source"].endswith("weak_renovate.json"))
        self.assertGreater(len(payload["findings"]), 0)
        by_sev = payload["summary"]["by_severity"]
        self.assertEqual(
            payload["summary"]["total_findings"], len(payload["findings"]),
        )
        self.assertEqual(
            by_sev["HIGH"] + by_sev["MEDIUM"] + by_sev["INFO"],
            payload["summary"]["total_findings"],
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
