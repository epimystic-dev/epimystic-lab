"""CLI tests for renovatelint - argparse surface, flags, exit codes."""

from __future__ import annotations

import json
import os
import unittest

from tests.support import run_cli, write_temp


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PROJECT_ROOT, "examples")
HEALTHY = os.path.join(EXAMPLES_DIR, "healthy_renovate.json")
WEAK = os.path.join(EXAMPLES_DIR, "weak_renovate.json")


class HelpAndVersionTests(unittest.TestCase):
    def test_help_prints_and_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            run_cli(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_version_prints_and_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            run_cli(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_unknown_flag_rc2(self):
        with self.assertRaises(SystemExit) as cm:
            run_cli(["--not-a-flag", "x"])
        self.assertEqual(cm.exception.code, 2)


class CleanAndDirtyExitCodeTests(unittest.TestCase):
    def test_clean_exits_zero(self):
        rc, out, err = run_cli([HEALTHY])
        self.assertEqual(rc, 0, out + "\n--\n" + err)
        # Convention: silent-clean = empty stdout; summary on stderr.
        self.assertEqual(out, "")
        self.assertIn("renovatelint", err)

    def test_dirty_exits_nonzero(self):
        rc, out, _err = run_cli([WEAK])
        self.assertEqual(rc, 2)
        self.assertIn("RNV-001", out)


class JSONModeTests(unittest.TestCase):
    def test_json_mode_clean(self):
        rc, out, _err = run_cli(["--json", HEALTHY])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "renovatelint")
        self.assertEqual(doc["verdict"], "healthy")
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["files_scanned"], 1)

    def test_json_mode_dirty(self):
        rc, out, _err = run_cli(["--json", WEAK])
        self.assertEqual(rc, 2)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "renovatelint")
        self.assertEqual(doc["verdict"], "unhealthy")
        ids = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("RNV-001", ids)
        self.assertIn("RNV-003", ids)
        self.assertIn("RNV-004", ids)
        self.assertIn("RNV-005", ids)
        self.assertIn("RNV-007", ids)
        self.assertIn("RNV-008", ids)
        self.assertIn("RNV-009", ids)
        self.assertIn("RNV-010", ids)


class DisableAndOnlyTests(unittest.TestCase):
    def test_disable_rule_hides_finding(self):
        rc, _out, _err = run_cli(["--json", "--disable", "RNV-001", WEAK])
        self.assertEqual(rc, 2)
        doc = json.loads(_out)
        ids = {f["rule_id"] for f in doc["findings"]}
        self.assertNotIn("RNV-001", ids)

    def test_only_rule_filters_to_single(self):
        rc, _out, _err = run_cli(["--json", "--only", "RNV-001", WEAK])
        doc = json.loads(_out)
        ids = {f["rule_id"] for f in doc["findings"]}
        self.assertEqual(ids, {"RNV-001"})
        self.assertEqual(rc, 2)


class StrictAndIncludeInfoTests(unittest.TestCase):
    def test_include_info_surfaces_rnv011_rnv012(self):
        d, p = write_temp({})
        try:
            rc, _out, _err = run_cli(["--json", "--include-info", p])
            doc = json.loads(_out)
            ids = {f["rule_id"] for f in doc["findings"]}
            # RNV-011 (no $schema) and RNV-012 (no timezone) should
            # fire on an empty document under include-info.
            self.assertIn("RNV-011", ids)
            self.assertIn("RNV-012", ids)
            # verdict stays healthy because include-info does not
            # upgrade severity.
            self.assertEqual(doc["verdict"], "healthy")
            self.assertEqual(rc, 0)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_strict_upgrades_info_to_needs_attention(self):
        d, p = write_temp({})
        try:
            rc, _out, _err = run_cli(["--json", "--strict", p])
            doc = json.loads(_out)
            self.assertEqual(doc["verdict"], "needs-attention")
            self.assertEqual(rc, 1)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class MinQuarantineDaysFlagTests(unittest.TestCase):
    def test_custom_floor_fires_against_14_days(self):
        d, p = write_temp({
            "$schema": "https://docs.renovatebot.com/renovate-schema.json",
            "timezone": "UTC",
            "extends": ["config:recommended"],
            "minimumReleaseAge": "14 days",
        })
        try:
            rc, out, _err = run_cli([
                "--json", "--min-quarantine-days", "30", p,
            ])
            doc = json.loads(out)
            ids = {f["rule_id"] for f in doc["findings"]}
            self.assertIn("RNV-010", ids)
            self.assertEqual(rc, 1)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class StdoutStderrDisciplineTests(unittest.TestCase):
    def test_rc_zero_text_mode_empty_stdout(self):
        rc, out, err = run_cli([HEALTHY])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertIn("findings=0", err)

    def test_rc_nonzero_text_mode_findings_to_stdout(self):
        rc, out, _err = run_cli([WEAK])
        self.assertNotEqual(rc, 0)
        self.assertIn("RNV-001", out)

    def test_json_mode_always_stdout(self):
        rc, out, _err = run_cli(["--json", HEALTHY])
        self.assertEqual(rc, 0)
        # JSON payload goes to stdout even on rc=0.
        self.assertTrue(out.strip().startswith("{"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
