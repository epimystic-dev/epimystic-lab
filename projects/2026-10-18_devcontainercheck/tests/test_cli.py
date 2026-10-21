"""In-process CLI tests."""

from __future__ import annotations

import json
import os
import unittest

from tests import support


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX = os.path.join(PKG_DIR, "examples")


class ArgparseTests(unittest.TestCase):
    def test_no_args_errors(self):
        # argparse exits 2 with no positional on required nargs="+".
        with self.assertRaises(SystemExit) as cm:
            support.run_cli([])
        self.assertEqual(cm.exception.code, 2)

    def test_unknown_flag_errors(self):
        with self.assertRaises(SystemExit) as cm:
            support.run_cli(["--nope", "x"])
        self.assertEqual(cm.exception.code, 2)


class HealthyRunTests(unittest.TestCase):
    def test_healthy_fixture_rc_zero_and_empty_stdout(self):
        rc, out, err = support.run_cli(
            [os.path.join(EX, "healthy_devcontainer.json")]
        )
        self.assertEqual(rc, 0, err)
        # Post-2026-10-09 lab stdout/stderr discipline: silent clean
        # run produces 0 bytes on stdout.
        self.assertEqual(out, "")
        self.assertIn("devcontainercheck: healthy", err)

    def test_healthy_fixture_json_payload_on_stdout(self):
        rc, out, err = support.run_cli(
            [os.path.join(EX, "healthy_devcontainer.json"), "--json"]
        )
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["verdict"], "healthy")
        self.assertEqual(doc["findings"], [])


class WeakRunTests(unittest.TestCase):
    def test_weak_fixture_rc_nonzero_and_findings_on_stdout(self):
        rc, out, err = support.run_cli(
            [os.path.join(EX, "weak_devcontainer.json")]
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("DC-001", out)
        # Summary line on stdout for non-zero runs.
        self.assertIn("devcontainercheck:", out)

    def test_weak_fixture_json_payload(self):
        rc, out, err = support.run_cli(
            [os.path.join(EX, "weak_devcontainer.json"), "--json"]
        )
        self.assertNotEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(doc["verdict"], "unhealthy")
        self.assertTrue(doc["findings"])
        ids = {f["rule_id"] for f in doc["findings"]}
        for expected in ("DC-001", "DC-003", "DC-006", "DC-007", "DC-010"):
            self.assertIn(expected, ids)


class RuleEnablementTests(unittest.TestCase):
    def test_disable_suppresses(self):
        rc, out, err = support.run_cli(
            [
                os.path.join(EX, "weak_devcontainer.json"),
                "--disable", "DC-001",
            ]
        )
        self.assertNotEqual(rc, 0)
        # The DC-001 finding line starts with "HIGH DC-001 ". A looser
        # "DC-001" probe would hit the hint prose of DC-007 which
        # back-references the DC-001 rule by id.
        self.assertNotIn("HIGH DC-001 ", out)

    def test_only_restricts(self):
        rc, out, err = support.run_cli(
            [
                os.path.join(EX, "weak_devcontainer.json"),
                "--only", "DC-010",
            ]
        )
        # Only DC-010 (MEDIUM) fires -> rc=1.
        self.assertEqual(rc, 1)
        self.assertIn("DC-010", out)
        self.assertNotIn("DC-001", out)


class StrictAndIncludeInfoTests(unittest.TestCase):
    def test_include_info_surfaces_info_rules(self):
        rc, out, err = support.run_cli(
            [
                os.path.join(EX, "weak_devcontainer.json"),
                "--include-info",
            ]
        )
        self.assertNotEqual(rc, 0)
        # weak_devcontainer.json has no remoteUser -> DC-011 should fire.
        self.assertIn("DC-011", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
