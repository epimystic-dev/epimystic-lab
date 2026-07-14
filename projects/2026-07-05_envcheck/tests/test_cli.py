"""CLI-level tests for envcheck."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from envcheck.cli import main


class CLIFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="envcheck_")
        self.cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.cwd)
        for p in Path(self.tmp).glob("*"):
            p.unlink()
        os.rmdir(self.tmp)

    def _write(self, name: str, body: str) -> str:
        p = Path(self.tmp) / name
        p.write_text(body, encoding="utf-8", newline="")
        return str(p)


class CLIBehavior(CLIFixture):
    def test_clean_files_return_zero(self):
        self._write(".env.example", "A=1\nB=2\n")
        self._write(".env", "A=1\nB=2\n")
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            rc = main([".env.example", ".env", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf_out.getvalue(), "")

    def test_drift_returns_one(self):
        self._write(".env.example", "A=1\nB=2\n")
        self._write(".env", "A=1\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", ".env", "--quiet"])
        self.assertEqual(rc, 1)
        self.assertIn("D001", buf.getvalue())

    def test_missing_template_returns_two(self):
        buf = io.StringIO()
        with redirect_stderr(buf), redirect_stdout(io.StringIO()):
            rc = main(["does-not-exist.example"])
        self.assertEqual(rc, 2)
        self.assertIn("template not found", buf.getvalue())

    def test_missing_env_arg_returns_two(self):
        self._write(".env.example", "A=1\n")
        buf = io.StringIO()
        with redirect_stderr(buf), redirect_stdout(io.StringIO()):
            rc = main([".env.example", "does-not-exist"])
        self.assertEqual(rc, 2)

    def test_default_env_used_when_present(self):
        self._write(".env.example", "A=1\n")
        self._write(".env", "A=1\nEXTRA=x\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main(["--quiet"])
        self.assertEqual(rc, 1)
        self.assertIn("D002", buf.getvalue())

    def test_default_env_absent_only_runs_template_checks(self):
        self._write(".env.example", "A=1\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main(["--quiet"])
        self.assertEqual(rc, 0)

    def test_json_format_emits_ndjson(self):
        self._write(".env.example", "A=1\n")
        self._write(".env", "EXTRA=x\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", ".env", "--format", "json", "--quiet"])
        self.assertEqual(rc, 1)
        records = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        codes = {r["code"] for r in records}
        self.assertIn("D001", codes)
        self.assertIn("D002", codes)
        for r in records:
            self.assertIn("file", r)
            self.assertIn("line", r)
            self.assertIn("column", r)

    def test_no_secrets_flag_skips_secret_pattern(self):
        self._write(".env.example", "KEY=AKIA" + "A" * 16 + "\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", "--no-secrets", "--quiet"])
        self.assertEqual(rc, 0)

    def test_env_parse_error_attributed_to_env_file(self):
        # CRLF in the env file should be labeled as an env-file finding,
        # not a template finding.
        self._write(".env.example", "A=1\n")
        env_path = self._write_bytes(".env", b"A=1\r\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", ".env", "--format", "json", "--quiet"])
        records = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        crlf = [r for r in records if r["code"] == "E007"]
        self.assertTrue(crlf, "expected E007 in output")
        for r in crlf:
            self.assertTrue(r["file"].endswith(".env"), r)

    def _write_bytes(self, name: str, data: bytes) -> str:
        p = Path(self.tmp) / name
        p.write_bytes(data)
        return str(p)


if __name__ == "__main__":
    unittest.main()
