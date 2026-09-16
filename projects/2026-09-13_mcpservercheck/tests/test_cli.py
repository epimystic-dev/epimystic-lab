"""Tests for mcpservercheck.cli end-to-end via main(argv=...)."""

import io
import json
import os
import tempfile
import unittest

from mcpservercheck.cli import main


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _run(*argv):
    out = io.StringIO()
    err = io.StringIO()
    code = main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class CliVersionTests(unittest.TestCase):
    def test_version_exits_zero(self):
        out = io.StringIO()
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"], stdout=out, stderr=err)
        self.assertEqual(ctx.exception.code, 0)


class CliListRulesTests(unittest.TestCase):
    def test_lists_all_ten(self):
        code, out, err = _run("--list-rules")
        self.assertEqual(code, 0)
        for i in range(1, 11):
            self.assertIn("MSC-" + str(i).zfill(3), out)


class CliPathTests(unittest.TestCase):
    def test_missing_path(self):
        code, out, err = _run(os.path.join(tempfile.gettempdir(), "nope-xyz-9999"))
        self.assertEqual(code, 2)
        self.assertIn("path does not exist", err)

    def test_healthy_dir_exit_zero(self):
        code, out, err = _run(os.path.join(FIXTURES, "healthy"))
        self.assertEqual(code, 0)
        self.assertIn("verdict: healthy", out)

    def test_unhealthy_dir_exit_two(self):
        code, out, err = _run(os.path.join(FIXTURES, "msc001_shell_eval"))
        self.assertEqual(code, 2)
        self.assertIn("verdict: unhealthy", out)


class CliNoFilesTests(unittest.TestCase):
    def test_no_files_default_exit_one(self):
        code, out, err = _run(os.path.join(FIXTURES, "unknown"))
        self.assertEqual(code, 1)
        self.assertIn("verdict: unknown", out)

    def test_no_files_strict_exit_two(self):
        code, out, err = _run("--strict", os.path.join(FIXTURES, "unknown"))
        self.assertEqual(code, 2)


class CliJsonTests(unittest.TestCase):
    def test_json_parseable(self):
        code, out, err = _run("--json", os.path.join(FIXTURES, "healthy"))
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "healthy")

    def test_include_info_shows_msc_010(self):
        code, out, err = _run("--include-info", "--json",
                              os.path.join(FIXTURES, "msc010_bare_binary"))
        payload = json.loads(out)
        ids = [f["rule_id"] for f in payload["findings"]]
        self.assertIn("MSC-010", ids)


class CliDisableTests(unittest.TestCase):
    def test_disable_flips_verdict(self):
        # a HIGH dir with --disable of that rule becomes healthy
        code_before, _, _ = _run(os.path.join(FIXTURES, "msc001_shell_eval"))
        self.assertEqual(code_before, 2)
        code_after, out, _ = _run("--disable", "MSC-001",
                                  os.path.join(FIXTURES, "msc001_shell_eval"))
        self.assertEqual(code_after, 0)
        self.assertIn("verdict: healthy", out)


class CliBoundsTests(unittest.TestCase):
    def test_max_files_zero_errors(self):
        code, out, err = _run("--max-files", "0", os.path.join(FIXTURES, "healthy"))
        self.assertEqual(code, 2)
        self.assertIn("--max-files", err)

    def test_max_bytes_zero_errors(self):
        code, out, err = _run("--max-bytes", "0", os.path.join(FIXTURES, "healthy"))
        self.assertEqual(code, 2)
        self.assertIn("--max-bytes", err)


class CliGlobExtensionTests(unittest.TestCase):
    def test_glob_extends_default(self):
        d = tempfile.mkdtemp()
        try:
            # unusual extension not in defaults
            with open(os.path.join(d, "server.mcp"), "w") as f:
                json.dump({"mcpServers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}, f)
            code_default, _, _ = _run(d)
            code_glob, _, _ = _run("--glob", "*.mcp", d)
            self.assertEqual(code_default, 1)   # nothing scanned -> unknown
            self.assertEqual(code_glob, 2)      # scanned -> unhealthy
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)


if __name__ == "__main__":
    unittest.main()
