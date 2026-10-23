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

    def test_json_format_emits_wrapping_object(self):
        # Breaking-restructure convergence (v0.2.0): the payload is now a
        # single wrapping object `{tool, version, source, findings, summary}`
        # on stdout rather than one JSON record per line (NDJSON). See
        # docs/CONVENTIONS.md Structured output.
        self._write(".env.example", "A=1\n")
        self._write(".env", "EXTRA=x\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", ".env", "--format", "json", "--quiet"])
        self.assertEqual(rc, 1)
        payload = json.loads(buf.getvalue())
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["tool"], "envcheck")
        from envcheck import __version__
        self.assertEqual(payload["version"], __version__)
        self.assertEqual(payload["source"], ".env.example,.env")
        records = payload["findings"]
        self.assertIsInstance(records, list)
        codes = {r["code"] for r in records}
        self.assertIn("D001", codes)
        self.assertIn("D002", codes)
        for r in records:
            self.assertIn("file", r)
            self.assertIn("line", r)
            self.assertIn("column", r)
        summary = payload["summary"]
        self.assertEqual(summary["total_findings"], len(records))
        self.assertEqual(summary["files_scanned"], 2)
        self.assertEqual(summary["by_code"].get("D001", 0), 1)
        self.assertEqual(summary["by_code"].get("D002", 0), 1)

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
        payload = json.loads(buf.getvalue())
        records = payload["findings"]
        crlf = [r for r in records if r["code"] == "E007"]
        self.assertTrue(crlf, "expected E007 in output")
        for r in crlf:
            self.assertTrue(r["file"].endswith(".env"), r)

    def _write_bytes(self, name: str, data: bytes) -> str:
        p = Path(self.tmp) / name
        p.write_bytes(data)
        return str(p)


class JsonAliasFlag(CLIFixture):
    """`--json` is a boolean shortcut for `--format json`. Convergence step
    toward the single flag name documented in docs/CONVENTIONS.md; before
    this change argparse would reject `--json` with SystemExit(2)."""

    def test_json_alias_produces_wrapping_object_on_findings(self):
        self._write(".env.example", "A=1\n")
        self._write(".env", "EXTRA=x\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", ".env", "--json", "--quiet"])
        self.assertEqual(rc, 1)
        payload = json.loads(buf.getvalue())
        codes = {r["code"] for r in payload["findings"]}
        self.assertIn("D001", codes)
        self.assertIn("D002", codes)

    def test_json_alias_clean_input_returns_zero_with_empty_findings(self):
        # Convergence (v0.2.0): a clean --json run now emits the wrapping
        # object with an empty `findings` list, not zero bytes. The CLI
        # output discipline for text mode (no bytes on stdout when clean)
        # is deliberately NOT inherited here: a CI consumer gating on
        # `summary.total_findings` must still see the identity stamp so
        # it can confirm which tool wrote the payload.
        self._write(".env.example", "A=1\nB=2\n")
        self._write(".env", "A=1\nB=2\n")
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            rc = main([".env.example", ".env", "--json", "--quiet"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf_out.getvalue())
        self.assertEqual(payload["tool"], "envcheck")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"]["total_findings"], 0)
        self.assertEqual(payload["summary"]["files_scanned"], 2)
        self.assertEqual(payload["summary"]["by_code"], {})

    def test_json_alias_output_matches_format_json_byte_for_byte(self):
        self._write(".env.example", "A=1\nREDIS_URL=redis://x\n")
        self._write(".env", "A=1\nEXTRA=x\n")
        buf_alias, buf_legacy = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_alias), redirect_stderr(io.StringIO()):
            rc_alias = main([".env.example", ".env", "--json", "--quiet"])
        with redirect_stdout(buf_legacy), redirect_stderr(io.StringIO()):
            rc_legacy = main([".env.example", ".env", "--format", "json", "--quiet"])
        self.assertEqual(rc_alias, rc_legacy)
        self.assertEqual(buf_alias.getvalue(), buf_legacy.getvalue())

    def test_json_wins_when_conflicting_format_text_also_given(self):
        # `--json` is the more specific, targeted intent; when both flags
        # are given, JSON must win so `--json` is safe to pass in a wrapper
        # that also inherits a legacy `--format text` default.
        self._write(".env.example", "A=1\n")
        self._write(".env", "EXTRA=x\n")
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main([".env.example", ".env", "--json", "--format", "text", "--quiet"])
        self.assertEqual(rc, 1)
        # The whole stdout now parses as a single JSON wrapping object;
        # a text formatter would emit colon-separated lines that would
        # fail json.loads.
        json.loads(buf.getvalue())


class VersionFlag(unittest.TestCase):
    """Parity with jsonlcheck / jwtcheck / licensechain / aicontribcheck /
    skillcheck: `--version` prints `envcheck <version>` on stdout and exits 0.
    CI consumers that log tool versions rely on this."""

    def test_version_prints_name_and_version_and_exits_zero(self):
        from envcheck import __version__
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(buf_out.getvalue().strip(), f"envcheck {__version__}")


if __name__ == "__main__":
    unittest.main()
