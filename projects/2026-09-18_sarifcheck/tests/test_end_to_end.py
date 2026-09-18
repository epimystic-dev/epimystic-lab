"""End-to-end: every shipped fixture and example, through the real CLI.

Each adversarial fixture directory is a one-mutation file that must fire
exactly its own rule and nothing else. That "and nothing else" assertion is
what catches a rule that has quietly started over-firing.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from tests.support import FIXTURES_DIR, codes, example, fixture, run_cli, scan_doc, base_doc


# (fixture directory, rule code it must fire, expected exit code)
FIXTURE_MATRIX = (
    ("srf001_bad_version", "SRF-001", 2),
    ("srf002_old_version", "SRF-002", 2),
    ("srf003_missing_schema", "SRF-003", 1),
    ("srf004_absolute_uri", "SRF-004", 2),
    ("srf005_bad_uri_reference", "SRF-005", 2),
    ("srf006_path_in_message", "SRF-006", 1),
    ("srf007_home_in_base_uri", "SRF-007", 1),
    ("srf008_no_rule_reference", "SRF-008", 1),
    ("srf009_dangling_rule_id", "SRF-009", 1),
    ("srf010_no_rule_metadata", "SRF-010", 0),
    ("srf011_bad_rule_index", "SRF-011", 2),
    ("srf012_unresolvable_message", "SRF-012", 2),
    ("srf013_empty_locations", "SRF-013", 1),
    ("srf014_zero_region", "SRF-014", 2),
    ("srf015_kind_level_conflict", "SRF-015", 2),
    ("srf016_hard_limit", "SRF-016", 2),
    ("srf017_soft_limit", "SRF-017", 1),
    ("srf018_no_fingerprints", "SRF-018", 1),
    ("srf019_thin_rule_docs", "SRF-019", 1),
    ("srf020_undefined_base_id", "SRF-020", 1),
    ("srf021_broken_base_chain", "SRF-021", 2),
    ("srf022_no_automation_id", "SRF-022", 1),
    ("srf024_fragile_shapes", "SRF-024", 1),
    ("srf025_token_shape", "SRF-025", 0),
    ("srf026_thin_metadata", "SRF-026", 0),
    ("srf027_external_props", "SRF-027", 1),
)


def json_scan(argv):
    rc, out, err = run_cli(["--json", "--include-info"] + list(argv))
    return rc, json.loads(out), err


class FixtureMatrixTests(unittest.TestCase):
    def test_every_fixture_fires_its_own_rule(self):
        for name, code, _rc in FIXTURE_MATRIX:
            with self.subTest(fixture=name):
                _rc_actual, payload, _err = json_scan([fixture(name)])
                found = set(f["rule_id"] for f in payload["findings"])
                self.assertIn(code, found)

    def test_every_fixture_fires_nothing_else(self):
        for name, code, _rc in FIXTURE_MATRIX:
            with self.subTest(fixture=name):
                _rc_actual, payload, _err = json_scan([fixture(name)])
                found = set(f["rule_id"] for f in payload["findings"])
                self.assertEqual(found, {code})

    def test_every_fixture_has_the_documented_exit_code(self):
        for name, _code, expected_rc in FIXTURE_MATRIX:
            with self.subTest(fixture=name):
                rc, _out, _err = run_cli([fixture(name)])
                self.assertEqual(rc, expected_rc)

    def test_disabling_the_target_rule_clears_each_fixture(self):
        for name, code, _rc in FIXTURE_MATRIX:
            with self.subTest(fixture=name):
                _rc_actual, payload, _err = json_scan(["--disable", code, fixture(name)])
                self.assertEqual(payload["findings"], [])

    def test_there_is_a_fixture_directory_for_every_rule_code(self):
        from sarifcheck.rules import ALL_RULES

        present = set(
            name[:6].upper().replace("SRF", "SRF-")
            for name in os.listdir(FIXTURES_DIR)
            if name.startswith("srf")
        )
        for rule in ALL_RULES:
            self.assertIn(rule.id, present, rule.id)

    def test_every_fixture_directory_appears_in_the_matrix_or_is_size_gated(self):
        listed = set(name for name, _c, _r in FIXTURE_MATRIX)
        on_disk = set(
            name for name in os.listdir(FIXTURES_DIR) if name.startswith("srf")
        )
        # srf023 is exercised with a lowered ceiling rather than by committing
        # a 10 MB file, so it is the one directory not in the matrix.
        self.assertEqual(on_disk - listed, {"srf023_compressed_size"})


class Srf023SizeGateTests(unittest.TestCase):
    def test_lowered_ceiling_fires_the_rule(self):
        rc, payload, _err = json_scan([
            "--limit", "max_compressed_bytes=1", fixture("srf023_compressed_size")
        ])
        self.assertEqual(
            set(f["rule_id"] for f in payload["findings"]), {"SRF-023"}
        )
        self.assertEqual(rc, 2)

    def test_documented_ceiling_does_not_fire(self):
        rc, payload, _err = json_scan([fixture("srf023_compressed_size")])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(rc, 0)


class HealthyFixtureTests(unittest.TestCase):
    def test_healthy_fixture_is_clean(self):
        rc, payload, _err = json_scan([fixture("healthy")])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "healthy")
        self.assertEqual(rc, 0)

    def test_healthy_fixture_is_clean_under_strict(self):
        rc, _out, _err = run_cli(["--strict", fixture("healthy")])
        self.assertEqual(rc, 0)

    def test_healthy_fixture_is_clean_in_every_profile(self):
        for profile in ("spec", "ingest", "hygiene", "all"):
            with self.subTest(profile=profile):
                rc, _out, _err = run_cli(["--profile", profile, fixture("healthy")])
                self.assertEqual(rc, 0)


class UnknownFixtureTests(unittest.TestCase):
    def test_unknown_directory_reports_unknown(self):
        _rc, payload, _err = json_scan([fixture("unknown")])
        self.assertEqual(payload["verdict"], "unknown")
        self.assertEqual(payload["files_scanned"], 0)

    def test_unknown_is_not_confused_with_healthy(self):
        _rc, healthy, _e1 = json_scan([fixture("healthy")])
        _rc2, unknown, _e2 = json_scan([fixture("unknown")])
        self.assertNotEqual(healthy["verdict"], unknown["verdict"])


class ShippedExampleTests(unittest.TestCase):
    def test_healthy_example_exists(self):
        self.assertTrue(os.path.isfile(example("healthy_results.sarif")))

    def test_weak_example_exists(self):
        self.assertTrue(os.path.isfile(example("weak_results.sarif")))

    def test_healthy_example_is_clean(self):
        rc, payload, _err = json_scan([example("healthy_results.sarif")])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(rc, 0)

    def test_healthy_example_is_clean_under_strict(self):
        rc, _out, _err = run_cli(["--strict", example("healthy_results.sarif")])
        self.assertEqual(rc, 0)

    def test_weak_example_is_unhealthy(self):
        rc, payload, _err = json_scan([example("weak_results.sarif")])
        self.assertEqual(payload["verdict"], "unhealthy")
        self.assertEqual(rc, 2)

    def test_weak_example_anchors_srf001_on_stdout(self):
        _rc, out, _err = run_cli([example("weak_results.sarif")])
        self.assertIn("SRF-001", out)

    def test_weak_example_exercises_many_rules(self):
        _rc, payload, _err = json_scan([example("weak_results.sarif")])
        found = set(f["rule_id"] for f in payload["findings"])
        self.assertGreaterEqual(len(found), 12)

    def test_weak_example_never_reprints_a_host_path(self):
        _rc, out, err = run_cli(["--include-info", example("weak_results.sarif")])
        self.assertNotIn("devuser", out)
        self.assertNotIn("devuser", err)

    def test_weak_example_reprints_on_request(self):
        _rc, out, _err = run_cli(["--show-matches", example("weak_results.sarif")])
        self.assertIn("devuser", out)

    def test_examples_directory_holds_exactly_two_files(self):
        names = sorted(os.listdir(os.path.dirname(example("healthy_results.sarif"))))
        self.assertEqual(names, ["healthy_results.sarif", "weak_results.sarif"])


class GeneratedSecretShapedFixtureTests(unittest.TestCase):
    """A credential-shaped fixture assembled at runtime.

    No committed file in this repository carries a verbatim secret-shaped
    literal. The parts below are each under sixteen characters and are joined
    here so the detection path is still exercised end to end.
    """

    TOKEN = "".join(("8Xk2vJ9pQ3wRnT5", "yBz7cLmD4hG6sVa", "0F1eU8oPiY2rXc"))
    PEM_HEADER = "-----BEGIN PRIV" + "ATE KEY-----"

    def test_assembled_token_is_detected_as_a_shape(self):
        doc = base_doc()
        doc["runs"][0]["results"][0]["message"] = {
            "text": "echoed " + self.TOKEN + " into the report"
        }
        self.assertIn("SRF-025", codes(scan_doc(doc)))

    def test_assembled_token_is_not_reprinted(self):
        doc = base_doc()
        doc["runs"][0]["results"][0]["message"] = {"text": "echoed " + self.TOKEN}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "results.sarif")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(doc, handle)
            _rc, out, err = run_cli(["--include-info", path])
        self.assertIn("SRF-025", out)
        self.assertNotIn(self.TOKEN, out)
        self.assertNotIn(self.TOKEN, err)

    def test_pem_header_in_a_message_is_not_misread_as_a_path(self):
        doc = base_doc()
        doc["runs"][0]["results"][0]["message"] = {
            "text": "found " + self.PEM_HEADER + " in the file"
        }
        self.assertNotIn("SRF-006", codes(scan_doc(doc)))


class DirectoryScanTests(unittest.TestCase):
    def test_scanning_the_whole_fixtures_tree_does_not_crash(self):
        rc, payload, _err = json_scan([FIXTURES_DIR])
        self.assertIn(rc, (0, 1, 2))
        self.assertGreater(payload["files_scanned"], 20)

    def test_whole_tree_scan_is_deterministic(self):
        _rc1, first, _e1 = json_scan([FIXTURES_DIR])
        _rc2, second, _e2 = json_scan([FIXTURES_DIR])
        self.assertEqual(first["findings"], second["findings"])

    def test_whole_tree_scan_reports_every_rule_that_has_a_fixture(self):
        _rc, payload, _err = json_scan([FIXTURES_DIR])
        found = set(f["rule_id"] for f in payload["findings"])
        for _name, code, _rc2 in FIXTURE_MATRIX:
            self.assertIn(code, found)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
