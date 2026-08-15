"""End-to-end CLI tests for reqcheck."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from reqcheck.cli import main, EXIT_CLEAN, EXIT_WARN, EXIT_ERROR


OK_REQS = """\
# clean sample
requests==2.31.0
numpy==1.26.0
pyyaml==6.0.1
"""

BAD_REQS = """\
# a variety of issues
requsts==1.0
foo>=1.0
--trusted-host internal.example.com
git+https://example.com/foo/bar.git@main#egg=bar
-e ./local
foo==2.0
"""


class CliOnFixtureTests(unittest.TestCase):
    def _write(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_ok_fixture_exits_clean(self):
        path = self._write(OK_REQS)
        out = io.StringIO()
        err = io.StringIO()
        code = main([path], stdout=out, stderr=err)
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("no findings", out.getvalue())

    def test_bad_fixture_exits_error(self):
        path = self._write(BAD_REQS)
        out = io.StringIO()
        err = io.StringIO()
        code = main([path], stdout=out, stderr=err)
        # --trusted-host raises severity to error.
        self.assertEqual(code, EXIT_ERROR)
        # Warning rules should still be reported.
        text = out.getvalue()
        for rule in ("REQ-A001", "REQ-A003", "REQ-A004", "REQ-A005", "REQ-A006", "REQ-A008"):
            self.assertIn(rule, text, f"{rule} missing from output:\n{text}")

    def test_json_output_shape(self):
        path = self._write(BAD_REQS)
        out = io.StringIO()
        code = main([path, "--format", "json"], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out.getvalue())
        self.assertIsInstance(payload, list)
        for row in payload:
            for key in ("rule", "severity", "file", "line", "column", "message"):
                self.assertIn(key, row)

    def test_missing_file_reports_and_exits_error(self):
        out = io.StringIO()
        err = io.StringIO()
        code = main(["/nonexistent/path/xxx.txt"], stdout=out, stderr=err)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no such file", err.getvalue())

    def test_strict_promotes_warn_to_error(self):
        path = self._write("foo>=1.0\n")
        out = io.StringIO()
        code = main([path, "--strict"], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("ERROR REQ-A001", out.getvalue())

    def test_include_info_shows_a009(self):
        path = self._write("--index-url https://pypi.example.com/simple\n")
        out = io.StringIO()
        code = main([path, "--include-info"], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_WARN)  # info is severity 'info' -> warn exit code
        self.assertIn("REQ-A009", out.getvalue())

    def test_info_hidden_by_default(self):
        path = self._write("--index-url https://pypi.example.com/simple\n")
        out = io.StringIO()
        code = main([path], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_CLEAN)
        self.assertNotIn("REQ-A009", out.getvalue())

    def test_multi_file(self):
        p1 = self._write("foo==1.0\n")
        p2 = self._write("bar>=2.0\n")
        out = io.StringIO()
        code = main([p1, p2], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_WARN)
        text = out.getvalue()
        self.assertIn(p2, text)


class HostileInputTests(unittest.TestCase):
    """Regression coverage for boundary inputs that previously raised
    tracebacks out of the CLI. Each test corresponds to a demonstrated
    pre-fix crash captured by the 2026-07-31 hostile-input probe."""

    def _write_bytes(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.unlink, path)
        return path

    def test_directory_path_is_reported_not_traceback(self):
        # On Windows, open() of a directory raises PermissionError, not
        # IsADirectoryError; the POSIX-only handler would leak a traceback.
        d = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, d)
        out = io.StringIO()
        err = io.StringIO()
        code = main([d], stdout=out, stderr=err)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("is a directory", err.getvalue())
        self.assertIn(d, err.getvalue())

    def test_invalid_utf8_is_reported_not_traceback(self):
        # An 0xff byte in the middle of the file previously bubbled a
        # UnicodeDecodeError from fh.read().
        path = self._write_bytes(b"foo==1.0\n\xff\xfe\x00bar==2.0\n")
        out = io.StringIO()
        err = io.StringIO()
        code = main([path], stdout=out, stderr=err)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not valid UTF-8", err.getvalue())
        self.assertIn(path, err.getvalue())

    def test_random_binary_is_reported_not_traceback(self):
        # A 4 KB blob of random bytes almost always trips utf-8 decoding.
        # Choose a deterministic non-UTF-8 payload for CI reproducibility.
        payload = bytes(range(256)) * 16  # 4096 bytes, includes 0xff, 0xfe etc.
        path = self._write_bytes(payload)
        out = io.StringIO()
        err = io.StringIO()
        code = main([path], stdout=out, stderr=err)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not valid UTF-8", err.getvalue())


class ExampleFileTests(unittest.TestCase):
    """The example fixtures under examples/ are documented in README; make
    sure they behave the way the README claims."""

    def _examples_dir(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(here, "examples")

    def test_examples_ok_exits_clean(self):
        path = os.path.join(self._examples_dir(), "ok.txt")
        if not os.path.exists(path):
            self.skipTest("examples/ok.txt not shipped in this run")
        out = io.StringIO()
        code = main([path], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_CLEAN, out.getvalue())

    def test_examples_bad_exits_error(self):
        path = os.path.join(self._examples_dir(), "bad.txt")
        if not os.path.exists(path):
            self.skipTest("examples/bad.txt not shipped in this run")
        out = io.StringIO()
        code = main([path], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_ERROR, out.getvalue())


class JsonAliasFlagTests(unittest.TestCase):
    """`--json` is a boolean shortcut for `--format json`. Third and final
    tool to converge on the single flag name documented in
    docs/CONVENTIONS.md (envcheck 2026-08-13, jwtcheck 2026-08-14). Before
    this change argparse would reject `--json` with SystemExit(2)."""

    def _write(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_json_alias_produces_json_array_on_findings(self):
        path = self._write(BAD_REQS)
        out = io.StringIO()
        code = main([path, "--json"], stdout=out, stderr=io.StringIO())
        # BAD_REQS contains --trusted-host (REQ-A005 error) so rc==EXIT_ERROR.
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out.getvalue())
        self.assertIsInstance(payload, list)
        rules = {row["rule"] for row in payload}
        self.assertIn("REQ-A005", rules)

    def test_json_alias_clean_input_returns_zero_with_empty_array(self):
        path = self._write(OK_REQS)
        out = io.StringIO()
        code = main([path, "--json"], stdout=out, stderr=io.StringIO())
        self.assertEqual(code, EXIT_CLEAN)
        # reqcheck's JSON shape is a single array (not envcheck's NDJSON);
        # the shape-convergence work is a separate open backlog item, so
        # this test locks the current shape honestly rather than papering
        # over the divergence.
        payload = json.loads(out.getvalue())
        self.assertEqual(payload, [])

    def test_json_alias_output_matches_format_json_byte_for_byte(self):
        # The alias must be a faithful shortcut, not a parallel-but-diverging
        # code path. Proven by byte-for-byte identity on the same input.
        path = self._write(BAD_REQS)
        buf_alias, buf_legacy = io.StringIO(), io.StringIO()
        rc_alias = main([path, "--json"], stdout=buf_alias, stderr=io.StringIO())
        rc_legacy = main(
            [path, "--format", "json"], stdout=buf_legacy, stderr=io.StringIO()
        )
        self.assertEqual(rc_alias, rc_legacy)
        self.assertEqual(buf_alias.getvalue(), buf_legacy.getvalue())

    def test_json_wins_when_conflicting_format_text_also_given(self):
        # `--json` is the more explicit intent; when both flags are given
        # JSON must win so `--json` is safe to pass in a wrapper that also
        # inherits a legacy `--format text` default. (Matches envcheck /
        # jwtcheck last-wins-by-specificity semantics.)
        path = self._write(BAD_REQS)
        buf = io.StringIO()
        code = main(
            [path, "--json", "--format", "text"], stdout=buf, stderr=io.StringIO()
        )
        self.assertEqual(code, EXIT_ERROR)
        # Text formatter would produce a "REQ-A005:" prefixed line, not JSON.
        json.loads(buf.getvalue())  # would raise if text formatter had run


class VersionFlagTests(unittest.TestCase):
    """Parity with jsonlcheck / jwtcheck / licensechain / aicontribcheck /
    skillcheck: `--version` prints `reqcheck <version>` on stdout and exits 0.
    CI consumers that log tool versions rely on this."""

    def test_version_prints_name_and_version_and_exits_zero(self):
        # argparse's action="version" writes to sys.stdout directly, bypassing
        # the stdout= argument main() accepts. redirect_stdout patches sys.stdout
        # itself, so this captures argparse's write.
        from reqcheck import __version__
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(buf.getvalue().strip(), f"reqcheck {__version__}")


if __name__ == "__main__":
    unittest.main()
