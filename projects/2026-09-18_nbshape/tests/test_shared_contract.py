"""Shared contract tests for nbshape.

Two contracts are locked here:

1. Package-surface invariants (PackageSurfaceTests) - the public API this
   module exports (``__version__``, ``Severity``, ``Verdict``, ``Finding``,
   ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable ``main``), plus the
   NBK-* rule-ID convention.

2. CI-consumer invariants (SharedContractInvariants) - the three invariants
   from epimystic-lab/docs/CONVENTIONS.md that every lab linter locks against
   its ``python -m <tool>`` subprocess entry point:

     a. ``python -m nbshape --help`` returns rc 0.
     b. ``python -m nbshape`` on a known-clean input returns rc 0.
     c. ``python -m nbshape`` on a known-dirty input returns non-zero, with the
        NBK-001 diagnostic anchored on stdout.

   These are exercised indirectly elsewhere in this suite via ``main(argv)``
   calls, but this class collects them in one named contract test so any
   regression against CONVENTIONS.md surfaces here first. The clean and dirty
   inputs are the shipped demonstration fixtures
   (``examples/healthy_notebook.ipynb`` / ``examples/weak_notebook.ipynb``), so
   a regression to those fixtures also trips.

   A fourth class locks the stdout / stderr split, which CONVENTIONS.md states
   as a separate shared rule: findings and structured output on stdout,
   diagnostics and summary lines on stderr.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

import nbshape
from nbshape.cli import main
from nbshape.rules import ALL_RULES


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "nbshape"] + list(args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(nbshape.__version__, str)
        self.assertRegex(nbshape.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult", "ALL_RULES",
                     "Rule", "RuleConfig"):
            self.assertTrue(hasattr(nbshape, name), name)

    def test_dunder_all_matches_what_is_exported(self):
        for name in nbshape.__all__:
            self.assertTrue(hasattr(nbshape, name), name)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_form_nbk_prefix(self):
        for r in ALL_RULES:
            self.assertTrue(r.id.startswith("NBK-"), r.id)

    def test_the_package_imports_nothing_outside_the_standard_library(self):
        # A zero-dependency promise is only worth anything if it is checked.
        import ast
        stdlib_names = getattr(sys, "stdlib_module_names", None)
        if stdlib_names is None:  # pragma: no cover - Python 3.9 only
            self.skipTest("sys.stdlib_module_names needs Python 3.10 or newer")
        allowed_relative_roots = {"nbshape"}
        stdlib_only = True
        offenders = []
        pkg_dir = os.path.join(PKG_DIR, "nbshape")
        for fn in sorted(os.listdir(pkg_dir)):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(pkg_dir, fn), "r", encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root not in stdlib_names:
                            stdlib_only = False
                            offenders.append(fn + ": " + alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    root = (node.module or "").split(".")[0]
                    if root and root not in stdlib_names:
                        if root not in allowed_relative_roots:
                            stdlib_only = False
                            offenders.append(fn + ": " + str(node.module))
        self.assertTrue(stdlib_only, "non-stdlib imports: " + ", ".join(offenders))


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        # Invariant 1: --help must exit 0 so shell wrappers can probe the tool
        # without triggering their own error branches.
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nbshape", r.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy example
        # has strictly increasing execution counters, outputs whose own
        # counters match their cells, a seeded sampler, relative paths only,
        # coherent kernelspec / language_info, and a valid unique id on every
        # cell, so no nbshape rule can fire against it under the default or the
        # --strict configuration - the assertion stays stable without any
        # per-run pinning.
        path = os.path.join(EXAMPLES_DIR, "healthy_notebook.ipynb")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_notebook.ipynb is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same CI
        # gate above actually catches something. We additionally require
        # nbshape-shaped output on stdout so a Python-launcher rc=2 (a missing
        # __main__.py, or argparse rejecting an unknown flag) cannot pass this
        # test by accident: NBK-001 is an nbshape-specific rule code that can
        # only appear if the tool actually ran and produced its documented
        # execution-order diagnostic against the counters stored in
        # weak_notebook.ipynb. It is a purely arithmetic comparison over
        # integers read from the file, with no time, environment, locale, or
        # filename dependency, so it fires deterministically everywhere. The
        # shared-contract test asserts only the weaker CONVENTIONS.md-shared
        # "rc != 0 iff findings" invariant so a future move off Convention B
        # would not need to touch this file; the tighter nbshape-specific rc=2
        # assertion is already exercised by tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "weak_notebook.ipynb")
        self.assertTrue(
            os.path.isfile(path),
            "examples/weak_notebook.ipynb is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        r = _run(path)
        self.assertNotEqual(
            r.returncode,
            0,
            "nbshape exited 0 on a known-dirty input; the CI-consumer contract "
            "in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "NBK-001",
            r.stdout,
            "expected nbshape to emit the NBK-001 diagnostic for the "
            "out-of-order execution counters in weak_notebook.ipynb; instead "
            "stdout was: " + repr(r.stdout),
        )

    def test_version_flag_prints_tool_and_version_then_exits_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nbshape " + nbshape.__version__, r.stdout + r.stderr)

    def test_unknown_flag_returns_two_via_argparse(self):
        self.assertEqual(_run("--not-a-real-flag").returncode, 2)


class StreamContractTests(unittest.TestCase):
    """CONVENTIONS.md: findings on stdout, human chatter on stderr."""

    def test_a_clean_run_writes_nothing_to_stdout(self):
        r = _run(os.path.join(EXAMPLES_DIR, "healthy_notebook.ipynb"))
        self.assertEqual(r.stdout, "")

    def test_a_clean_run_still_summarises_on_stderr(self):
        r = _run(os.path.join(EXAMPLES_DIR, "healthy_notebook.ipynb"))
        self.assertIn("verdict: healthy", r.stderr)

    def test_the_verdict_line_never_appears_on_stdout(self):
        r = _run(os.path.join(EXAMPLES_DIR, "weak_notebook.ipynb"))
        self.assertNotIn("verdict:", r.stdout)

    def test_json_output_on_stdout_parses_cleanly_with_no_chatter(self):
        r = _run(os.path.join(EXAMPLES_DIR, "weak_notebook.ipynb"), "--json")
        doc = json.loads(r.stdout)
        self.assertEqual(doc["tool"], "nbshape")


if __name__ == "__main__":
    unittest.main()
