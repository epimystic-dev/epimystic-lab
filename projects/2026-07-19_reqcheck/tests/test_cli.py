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
