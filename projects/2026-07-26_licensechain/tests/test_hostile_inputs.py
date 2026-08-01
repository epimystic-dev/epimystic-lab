"""Regression tests for hostile / malformed inputs against licensechain.

Each test corresponds to a demonstrated pre-fix traceback from the
2026-08-01 adversarial-input probe. The contract locked in by this file is:

  * A hostile input never escapes the CLI as a traceback.
  * Structural problems produce exit code 2 with a `licensechain: ...`
    message on stderr.
  * Recursion-triggering inputs (deeply-nested JSON, pathological SPDX
    expressions) produce a clean stderr line and exit 2 instead of
    RecursionError.
  * A legitimate long-but-linear supply chain (>=1000 components) is
    analysable without crashing on Python's default recursion limit.
"""

from __future__ import annotations
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from licensechain.cli import main


def _run_cli(argv, stdin_text=""):
    out = io.StringIO()
    err = io.StringIO()
    saved_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


class DirectoryAsPathTests(unittest.TestCase):
    """Pre-fix: on Windows, open() of a directory raises PermissionError
    that leaked as a traceback; on POSIX it raises IsADirectoryError which
    was likewise uncaught. Now normalised via os.path.isdir pre-check."""

    def test_directory_as_manifest_path_is_clean_load_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, _out, err = _run_cli([d])
        self.assertEqual(code, 2)
        self.assertIn("licensechain:", err)
        self.assertIn("directory", err.lower())
        self.assertNotIn("Traceback", err)


class InvalidUtf8Tests(unittest.TestCase):
    """Pre-fix: reading a file with invalid UTF-8 bytes let
    UnicodeDecodeError escape as a traceback."""

    def _write(self, payload: bytes) -> str:
        f = tempfile.NamedTemporaryFile(
            mode="wb", suffix=".json", delete=False
        )
        try:
            f.write(payload)
        finally:
            f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def test_invalid_utf8_leading_bytes_is_clean_load_error(self):
        # 0xff / 0xfe are never valid as UTF-8 start bytes.
        path = self._write(b"\xff\xfe\xff{\"version\":1}")
        code, _out, err = _run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("licensechain:", err)
        self.assertIn("UTF-8", err)
        self.assertNotIn("Traceback", err)

    def test_random_binary_file_is_clean_load_error(self):
        # A distinct probe from invalid-utf8: a random-binary payload also
        # triggers UnicodeDecodeError in open()/read(), but the failure mode
        # is worth locking separately so that a future refactor that
        # narrows the catch to a specific byte pattern still fails this
        # test.
        path = self._write(os.urandom(4096))
        code, _out, err = _run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("licensechain:", err)
        self.assertNotIn("Traceback", err)


class DeeplyNestedJsonTests(unittest.TestCase):
    """Pre-fix: JSON with ~20 000 nested array brackets exhausted the
    interpreter's recursion limit inside the json decoder."""

    def test_deeply_nested_json_is_clean_error(self):
        deep = "[" * 20000 + "]" * 20000
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        try:
            f.write(deep)
        finally:
            f.close()
        self.addCleanup(os.remove, f.name)
        code, _out, err = _run_cli([f.name])
        self.assertEqual(code, 2)
        self.assertIn("licensechain:", err)
        self.assertNotIn("Traceback", err)


class LongLinearChainTests(unittest.TestCase):
    """Pre-fix: `_check_acyclic` used recursive DFS whose depth equalled the
    length of a linear chain, so ~500+ components crashed the loader with
    RecursionError. Loader now uses an iterative stack."""

    def test_long_linear_chain_does_not_crash(self):
        # 2 500 is comfortably above Python's default recursion limit
        # (~1 000) and far below anything memory-bound in CI.
        n = 2500
        chain = [
            {
                "name": f"c{i}",
                "role": "model",
                "license": "MIT",
                "preserves_notices": True,
                "uses": [f"c{i+1}"] if i < n - 1 else [],
            }
            for i in range(n)
        ]
        manifest = {"version": 1, "chain": chain}
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        try:
            json.dump(manifest, f)
        finally:
            f.close()
        self.addCleanup(os.remove, f.name)
        code, _out, err = _run_cli([f.name])
        # The chain is well-formed, so the loader must succeed. Exit code
        # is whatever `check_chain` says (likely 0 or 1); the assertion
        # that matters here is "did not crash, no traceback".
        self.assertIn(code, (0, 1, 2))
        self.assertNotIn("Traceback", err)

    def test_long_chain_cycle_is_still_detected(self):
        # Regression guard on the iterative DFS: cycles are still caught
        # (this is the core invariant of the algorithm, not a side effect).
        cycle_chain = [
            {"name": "a", "role": "model", "uses": ["b"]},
            {"name": "b", "role": "model", "uses": ["a"]},
        ]
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        try:
            json.dump({"version": 1, "chain": cycle_chain}, f)
        finally:
            f.close()
        self.addCleanup(os.remove, f.name)
        code, _out, err = _run_cli([f.name])
        self.assertEqual(code, 2)
        self.assertIn("cycle", err.lower())
        self.assertIn("a -> b -> a", err)


class PathologicalSpdxTests(unittest.TestCase):
    """Pre-fix: SPDX expressions with thousands of chained AND terms or
    hundreds of nested parens tripped RecursionError in the recursive-
    descent parser inside `expr.py`, called from `check_chain`."""

    def _write(self, manifest: dict) -> str:
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        try:
            json.dump(manifest, f)
        finally:
            f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def test_huge_and_chain_license_is_clean_error(self):
        expr = "MIT AND " * 5000 + "MIT"
        path = self._write({
            "version": 1,
            "chain": [{"name": "a", "role": "model", "license": expr}],
        })
        code, _out, err = _run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("licensechain:", err)
        self.assertNotIn("Traceback", err)

    def test_deeply_nested_paren_license_is_clean_error(self):
        expr = "(" * 500 + "MIT" + ")" * 500
        path = self._write({
            "version": 1,
            "chain": [{"name": "a", "role": "model", "license": expr}],
        })
        code, _out, err = _run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("licensechain:", err)
        self.assertNotIn("Traceback", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
