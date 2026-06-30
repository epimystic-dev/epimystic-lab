"""End-to-end CLI tests using subprocess.

These exercise the ``python -m jsonlcheck`` entry point in a child process,
so they cover argument parsing, file I/O, and exit codes."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "jsonlcheck", *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class CliExitCodes(unittest.TestCase):
    def test_clean_input_returns_zero(self):
        r = _run("-", stdin='{"a":1}\n{"b":2}\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr, "")

    def test_parse_error_returns_one(self):
        r = _run("-", stdin='not json\n')
        self.assertEqual(r.returncode, 1)
        self.assertIn("parse-error", r.stderr)

    def test_warning_only_returns_zero(self):
        # missing-newline is a warning, not an error
        r = _run("-", stdin='{"a":1}')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no-final-newline", r.stderr)

    def test_quiet_suppresses_output(self):
        r = _run("-", "--quiet", stdin='not json\n')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stderr, "")


class CliFileInput(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        for n in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, n))
        os.rmdir(self.tmp)

    def test_file_with_findings(self):
        p = os.path.join(self.tmp, "f.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"a":1}\nnope\n{"b":2}\n')
        r = _run(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"{p}:2:", r.stderr)
        self.assertIn("parse-error", r.stderr)

    def test_multiple_files_all_checked(self):
        p1 = os.path.join(self.tmp, "a.jsonl")
        p2 = os.path.join(self.tmp, "b.jsonl")
        with open(p1, "w", encoding="utf-8") as f:
            f.write('{"a":1}\n')
        with open(p2, "w", encoding="utf-8") as f:
            f.write('not json\n')
        r = _run(p1, p2)
        self.assertEqual(r.returncode, 1)
        self.assertIn("b.jsonl:1:", r.stderr)


class CliFlags(unittest.TestCase):
    def test_homogeneous_flag(self):
        r = _run("-", "--homogeneous", stdin='{"a":1}\n[1,2,3]\n')
        self.assertEqual(r.returncode, 1)
        self.assertIn("heterogeneous", r.stderr)

    def test_require_key_flag(self):
        r = _run("-", "--require-key", "id", "--require-key", "text", stdin='{"id":1}\n')
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing-keys", r.stderr)
        self.assertIn("text", r.stderr)

    def test_allow_nan_suppresses_finding(self):
        r = _run("-", "--allow-nan", stdin='{"x":NaN}\n')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_version(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("jsonlcheck", r.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
