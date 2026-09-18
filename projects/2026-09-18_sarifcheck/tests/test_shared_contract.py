"""Shared contract tests for sarifcheck.

Two contracts are locked here:

1. Package-surface invariants (PackageSurfaceTests) - the public API this
   module exports (`__version__`, `Severity`, `Verdict`, `Finding`,
   `ScanResult`, `ALL_RULES`, `Rule`, and a callable `main`), plus the
   SRF-* rule-ID convention.

2. CI-consumer invariants (SharedContractInvariants) - the three invariants
   from epimystic-lab/docs/CONVENTIONS.md that every lab linter locks
   against its ``python -m <tool>`` subprocess entry point:

     a. ``python -m sarifcheck --help`` returns rc 0.
     b. ``python -m sarifcheck`` on a known-clean input returns rc 0.
     c. ``python -m sarifcheck`` on a known-dirty input returns non-zero,
        with the SRF-001 diagnostic anchored on stdout.

   These are exercised indirectly elsewhere in the suite via ``main(argv)``
   calls, but this file collects them in one named contract test so any
   regression against CONVENTIONS.md surfaces here first. The clean and
   dirty inputs are the shipped demonstration fixtures
   (``examples/healthy_results.sarif`` / ``examples/weak_results.sarif``),
   so a regression to those fixtures also trips.

One documented divergence from the published siblings: sarifcheck writes
findings to stdout and the verdict / summary block to stderr, per the
"Stdout / stderr discipline" section of CONVENTIONS.md. Several earlier
tools print the verdict line on stdout. The invariants asserted below are
the shared ones and hold either way.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

import sarifcheck
from sarifcheck.cli import main
from sarifcheck.rules import ALL_RULES


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "sarifcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(sarifcheck.__version__, str)
        self.assertRegex(sarifcheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in (
            "Severity", "Verdict", "Profile", "Finding", "ScanResult",
            "Options", "ALL_RULES", "Rule",
        ):
            self.assertTrue(hasattr(sarifcheck, name), name)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_form_srf_prefix(self):
        for rule in ALL_RULES:
            self.assertTrue(rule.id.startswith("SRF-"), rule.id)

    def test_rule_ids_are_zero_padded_to_three_digits(self):
        for rule in ALL_RULES:
            self.assertRegex(rule.id, r"^SRF-\d{3}$")

    def test_no_third_party_import_in_the_package(self):
        # stdlib-only is a shipping constraint, not a preference. This walks
        # the real source files rather than trusting a docstring.
        allowed = {
            "argparse", "dataclasses", "enum", "fnmatch", "json", "os", "re",
            "sys", "typing", "urllib", "zlib", "__future__",
        }
        package_dir = os.path.join(PKG_DIR, "sarifcheck")
        for name in sorted(os.listdir(package_dir)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(package_dir, name), "r", encoding="utf-8") as handle:
                for line in handle:
                    stripped = line.strip()
                    if stripped.startswith("import ") and not stripped.startswith("import ."):
                        module = stripped[len("import "):].split()[0].split(".")[0]
                        self.assertIn(module, allowed, name + ": " + stripped)
                    elif stripped.startswith("from ") and " import " in stripped:
                        module = stripped[len("from "):].split()[0]
                        if module.startswith("."):
                            continue
                        self.assertIn(module.split(".")[0], allowed, name + ": " + stripped)


class AsciiDisciplineTests(unittest.TestCase):
    """Published text is plain ASCII, machine-checked."""

    def _files(self):
        for root, dirnames, filenames in os.walk(PKG_DIR):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for name in sorted(filenames):
                if name.endswith((".py", ".md", ".toml", ".json", ".sarif", ".txt")) \
                        or name == "LICENSE":
                    yield os.path.join(root, name)

    def test_every_shipped_file_is_plain_ascii(self):
        offenders = []
        for path in self._files():
            with open(path, "rb") as handle:
                raw = handle.read()
            for index, byte in enumerate(raw):
                if byte > 127:
                    offenders.append(
                        os.path.relpath(path, PKG_DIR) + " at byte " + str(index)
                    )
                    break
        self.assertEqual(offenders, [], "non-ASCII bytes in: " + ", ".join(offenders))

    def test_no_file_carries_a_utf8_bom(self):
        for path in self._files():
            with open(path, "rb") as handle:
                self.assertNotEqual(handle.read(3), b"\xef\xbb\xbf", path)


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        # Invariant 1: --help must exit 0 so shell wrappers can probe the
        # tool without triggering their own error branches.
        result = _run("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sarifcheck", result.stdout)

    def test_known_clean_input_returns_zero(self):
        # Invariant 2: a clean run must exit 0 so CI jobs that gate on
        # `test $? -eq 0` do not need per-tool knowledge. The healthy example
        # declares version 2.1.0, a recognised $schema, relative artifact
        # uris under a defined and absolute uriBaseId, complete rule
        # descriptors, message text, locations, partialFingerprints, 1-based
        # regions, and provenance metadata, so no sarifcheck rule can fire
        # against it under any profile or under --strict. The assertion stays
        # stable without any per-run pinning.
        path = os.path.join(EXAMPLES_DIR, "healthy_results.sarif")
        self.assertTrue(
            os.path.isfile(path),
            "examples/healthy_results.sarif is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        result = _run(path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        # Invariant 3: a run with findings must exit non-zero so the same CI
        # gate above actually catches something. We additionally require
        # sarifcheck-shaped output on stdout so a Python-launcher rc=2 (a
        # missing __main__.py, or argparse rejecting an unknown flag) cannot
        # pass this test by accident: SRF-001 is a sarifcheck-specific rule
        # code that can only appear if the tool actually ran and produced its
        # documented version diagnostic against the "2.1" version string at
        # weak_results.sarif:3. SRF-001 is severity=HIGH under sarifcheck's
        # Convention B tiering, so its presence also anchors the rc=2 outcome
        # to that specific rule rather than to argparse noise. It is a purely
        # lexical comparison of one top-level string with no time,
        # environment, filename, or limit dependency, so it fires
        # deterministically across environments. This file asserts only the
        # weaker CONVENTIONS.md-shared "rc != 0 iff findings" invariant so a
        # future move onto (or off) Convention B does not need to touch it;
        # the tighter rc=2 assertions on the anchored fixtures live in
        # tests/test_end_to_end.py.
        path = os.path.join(EXAMPLES_DIR, "weak_results.sarif")
        self.assertTrue(
            os.path.isfile(path),
            "examples/weak_results.sarif is a documented artifact; missing "
            "here means the example fixture regressed and the README's "
            "demonstration input no longer exists.",
        )
        result = _run(path)
        self.assertNotEqual(
            result.returncode,
            0,
            "sarifcheck exited 0 on a known-dirty input; the CI-consumer "
            "contract in docs/CONVENTIONS.md requires a non-zero rc here.",
        )
        self.assertIn(
            "SRF-001",
            result.stdout,
            "expected sarifcheck to emit the SRF-001 diagnostic for the "
            "\"2.1\" version string in weak_results.sarif; instead stdout "
            "was: " + repr(result.stdout),
        )

    def test_structured_output_is_alone_on_stdout(self):
        # CONVENTIONS.md: structured output on stdout, diagnostics on stderr.
        import json

        result = _run("--json", os.path.join(EXAMPLES_DIR, "weak_results.sarif"))
        payload = json.loads(result.stdout)
        self.assertEqual(payload["tool"], "sarifcheck")
        self.assertTrue(result.stderr.strip())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
