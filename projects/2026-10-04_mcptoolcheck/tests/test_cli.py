"""argparse / CLI-wiring tests. Subprocess coverage lives in
test_python_dash_m_invocation to exercise the real __main__ path."""

from __future__ import annotations

import io
import json
import os
import unittest

from mcptoolcheck.cli import main

from tests.support import (
    build_doc,
    build_tool,
    run_cli,
    tag_char,
    write_temp,
)


class ArgparseTests(unittest.TestCase):
    def test_help_returns_zero(self):
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        try:
            rc = main(["--help"], stdout=buf_out, stderr=buf_err)
        except SystemExit as e:
            rc = e.code
        self.assertEqual(rc, 0)

    def test_unknown_flag_returns_two(self):
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        try:
            rc = main(["--not-a-real-flag"], stdout=buf_out, stderr=buf_err)
        except SystemExit as e:
            rc = e.code
        self.assertEqual(rc, 2)


class ExitCodeTests(unittest.TestCase):
    def test_healthy_input_returns_zero(self):
        d, p = write_temp(build_doc([build_tool()]))
        rc, out, _err = run_cli([p])
        self.assertEqual(rc, 0)
        self.assertIn("healthy", out)

    def test_unhealthy_input_returns_two(self):
        d, p = write_temp(build_doc([build_tool(
            description="hello" + tag_char() + " world and beyond"
        )]))
        rc, out, _err = run_cli([p])
        self.assertEqual(rc, 2)
        self.assertIn("MTC-001", out)
        self.assertIn("unhealthy", out)

    def test_json_mode(self):
        d, p = write_temp(build_doc([build_tool(
            description="hello" + tag_char() + " world and beyond"
        )]))
        rc, out, _err = run_cli([p, "--json"])
        self.assertEqual(rc, 2)
        doc = json.loads(out)
        self.assertEqual(doc["verdict"], "unhealthy")

    def test_disable_flag(self):
        d, p = write_temp(build_doc([build_tool(
            description="hello" + tag_char() + " world and beyond"
        )]))
        rc, out, _err = run_cli([p, "--disable", "MTC-001"])
        # MTC-001 was the only HIGH finding; disabling drops to clean.
        self.assertEqual(rc, 0)

    def test_only_flag(self):
        d, p = write_temp(build_doc([build_tool(
            name="delete_record",
            annotations={"readOnlyHint": True, "destructiveHint": False},
            description="hello" + tag_char() + " world long enough",
        )]))
        rc, out, _err = run_cli([p, "--only", "MTC-007"])
        self.assertNotIn("MTC-001", out)
        self.assertIn("MTC-007", out)

    def test_strict_promotes_info_only_to_rc1(self):
        tool = build_tool(description="")
        d, p = write_temp(build_doc([tool]))
        rc, out, _err = run_cli([p, "--strict"])
        self.assertEqual(rc, 1)
        self.assertIn("MTC-012", out)

    def test_include_info_shows_info_without_promoting(self):
        tool = build_tool(description="")
        d, p = write_temp(build_doc([tool]))
        rc, out, _err = run_cli([p, "--include-info"])
        self.assertEqual(rc, 0)
        self.assertIn("MTC-012", out)


class MissingFileTests(unittest.TestCase):
    def test_missing_file_returns_two(self):
        rc, _out, _err = run_cli(["/no/such/path.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
