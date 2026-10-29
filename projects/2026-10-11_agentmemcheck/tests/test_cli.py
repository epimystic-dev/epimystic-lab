"""CLI-layer tests (argparse surface + in-process main)."""

from __future__ import annotations

import json
import shutil
import unittest

from tests import support
from tests.support import (
    build_entry, build_store, run_cli, tag_char, write_temp,
)


class CLIBasicTests(unittest.TestCase):
    def test_help_returns_zero(self):
        try:
            rc, out, _err = run_cli(["--help"])
            self.fail("argparse should raise SystemExit")
        except SystemExit as e:
            self.assertEqual(e.code, 0)

    def test_version_returns_zero(self):
        try:
            run_cli(["--version"])
            self.fail("argparse should raise SystemExit")
        except SystemExit as e:
            self.assertEqual(e.code, 0)


class CLIScanTests(unittest.TestCase):
    def test_clean_file_rc_zero(self):
        d, p = write_temp(build_store([build_entry()]))
        try:
            rc, out, err = run_cli([p])
            self.assertEqual(rc, 0, err)
            # docs/CONVENTIONS.md Stdout / stderr discipline (0.2.0):
            # rc=0 text-mode runs route the verdict summary to stderr
            # so a `jq` / `test -s` wrapper piping stdout sees nothing.
            self.assertEqual(out, "")
            self.assertIn("healthy", err)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dirty_file_rc_two(self):
        bad = build_entry(content="hi " + tag_char() + " there")
        d, p = write_temp(build_store([bad]))
        try:
            rc, out, _err = run_cli([p])
            self.assertEqual(rc, 2, out)
            self.assertIn("AMC-001", out)
            self.assertIn("unhealthy", out)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_json_output_shape(self):
        d, p = write_temp(build_store([build_entry()]))
        try:
            rc, out, _err = run_cli(["--json", p])
            parsed = json.loads(out)
            self.assertEqual(parsed["verdict"], "healthy")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strict_promotes_info_only(self):
        # schema_version=None generates AMC-012 (INFO). Default verdict
        # is HEALTHY; under --strict it becomes NEEDS_ATTENTION.
        d, p = write_temp(
            build_store([build_entry()], schema_version=None),
        )
        try:
            rc, out, _err = run_cli([p])
            self.assertEqual(rc, 0, out)
            rc_s, out_s, _err_s = run_cli(["--strict", p])
            self.assertEqual(rc_s, 1, out_s)
            self.assertIn("AMC-012", out_s)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_disable_rule(self):
        bad = build_entry(content="hi " + tag_char() + " there")
        d, p = write_temp(build_store([bad]))
        try:
            rc, out, _err = run_cli(["--disable", "AMC-001", p])
            # AMC-001 is suppressed so there's no HIGH -> no "unhealthy".
            self.assertNotIn("AMC-001", out)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class CLIErrorTests(unittest.TestCase):
    def test_missing_path_unhealthy(self):
        rc, out, _err = run_cli(["/no/such/path/nonexistent.json"])
        self.assertEqual(rc, 2)
        self.assertIn("AMC-000", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
