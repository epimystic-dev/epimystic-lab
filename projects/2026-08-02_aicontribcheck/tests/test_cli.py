"""Tests for the CLI (argparse contract, exit codes, output formats)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aicontribcheck import patterns
from aicontribcheck.cli import main


HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"


class _IsolatedRegistry(unittest.TestCase):
    """Base for CLI tests: --extra-tool-name mutates module state, so reset around each case."""

    def setUp(self):
        patterns.clear_tool_names()

    def tearDown(self):
        patterns.clear_tool_names()


def _run(argv):
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


class ExitCodeTests(_IsolatedRegistry):
    def test_ban_repo_exits_2(self):
        code, _out, _err = _run([str(FIXTURES / "ban_repo")])
        self.assertEqual(code, 2)

    def test_allow_repo_exits_0(self):
        code, _out, _err = _run([str(FIXTURES / "allow_repo")])
        self.assertEqual(code, 0)

    def test_conditional_repo_exits_1(self):
        code, _out, _err = _run([str(FIXTURES / "conditional_repo")])
        self.assertEqual(code, 1)

    def test_unknown_repo_exits_1_by_default(self):
        code, _out, _err = _run([str(FIXTURES / "unknown_repo")])
        self.assertEqual(code, 1)

    def test_unknown_repo_strict_exits_2(self):
        code, _out, _err = _run(
            [str(FIXTURES / "unknown_repo"), "--strict"]
        )
        self.assertEqual(code, 2)

    def test_conflict_repo_exits_2(self):
        code, _out, _err = _run([str(FIXTURES / "conflict_repo")])
        self.assertEqual(code, 2)


class OutputTests(_IsolatedRegistry):
    def test_json_output_parses(self):
        code, out, _err = _run(
            [str(FIXTURES / "conditional_repo"), "--json"]
        )
        parsed = json.loads(out)
        self.assertEqual(parsed["verdict"], "conditional")
        self.assertTrue(parsed["required_disclosures"])

    def test_text_output_default_suppresses_info(self):
        _code, out, _err = _run([str(FIXTURES / "allow_repo")])
        # AICONTRIB-002 is INFO severity, filtered by default.
        self.assertNotIn("[INFO ]", out)

    def test_text_output_include_info_shows_info(self):
        _code, out, _err = _run(
            [str(FIXTURES / "allow_repo"), "--include-info"]
        )
        self.assertIn("[INFO ]", out)

    def test_json_names_no_tools_without_registration(self):
        # Vendor-neutral by default: no product is named unless the caller asks for it.
        _code, out, _err = _run([str(FIXTURES / "allow_repo"), "--json"])
        parsed = json.loads(out)
        self.assertEqual(parsed["tools_named"], [])

    def test_extra_tool_name_flag_populates_named_tools(self):
        _code, out, _err = _run(
            [
                str(FIXTURES / "allow_repo"),
                "--json",
                "--extra-tool-name", "helperbot",
                "--extra-tool-name", "codewright",
            ]
        )
        parsed = json.loads(out)
        self.assertIn("helperbot", parsed["tools_named"])
        self.assertIn("codewright", parsed["tools_named"])


class ArgumentTests(_IsolatedRegistry):
    def test_missing_path_exits_2_with_stderr(self):
        code, _out, err = _run(["/no/such/path-xyzzy-999"])
        self.assertEqual(code, 2)
        self.assertIn("no such path", err.lower())

    def test_default_path_is_current_dir(self):
        # Just ensure it does not raise; the actual verdict depends on cwd.
        with tempfile.TemporaryDirectory() as td:
            cwd = os.getcwd()
            try:
                os.chdir(td)
                code, _out, _err = _run([])
                # Empty temp dir => UNKNOWN => exit 1
                self.assertEqual(code, 1)
            finally:
                os.chdir(cwd)

    def test_version_flag_exits_zero(self):
        code, out, _err = _run(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("aicontribcheck", out)

    def test_single_file_scan(self):
        code, _out, _err = _run(
            [str(FIXTURES / "ban_repo" / "CONTRIBUTING.md")]
        )
        self.assertEqual(code, 2)

    def test_json_flag_produces_valid_json(self):
        _code, out, _err = _run([str(FIXTURES / "ban_repo"), "--json"])
        parsed = json.loads(out)
        self.assertEqual(parsed["verdict"], "banned")


class DeterminismTests(_IsolatedRegistry):
    def test_same_input_same_json_output(self):
        _c1, o1, _ = _run([str(FIXTURES / "ban_repo"), "--json"])
        _c2, o2, _ = _run([str(FIXTURES / "ban_repo"), "--json"])
        self.assertEqual(o1, o2)


if __name__ == "__main__":
    unittest.main()
