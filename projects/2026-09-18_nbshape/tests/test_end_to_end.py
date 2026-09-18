"""End-to-end verification against the committed fixtures and demonstration examples.

Each fixture directory is an anchored input: a fixed file on disk, a fixed rule
id, and a fixed exit code. If a rule stops firing on its own fixture, or starts
firing on the false-positive guard beside it, these tests fail.
"""

from __future__ import annotations

import io
import json
import os
import unittest

from nbshape.cli import main
from nbshape.rules import ALL_RULES


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
NEGATIVES = os.path.join(FIXTURES, "negatives")
EXAMPLES = os.path.join(ROOT, "examples")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def fixture(name):
    return os.path.join(FIXTURES, name)


#: fixture directory -> (rule id it must emit, expected exit code, extra flags)
CASES = {
    "nbk001_execution_order": ("NBK-001", 1, []),
    "nbk002_orphan_output": ("NBK-002", 2, []),
    "nbk003_duplicate_counts": ("NBK-003", 2, []),
    "nbk004_counter_overrun": ("NBK-004", 0, ["--include-info"]),
    "nbk005_local_path": ("NBK-005", 2, []),
    "nbk006_credential_literal": ("NBK-006", 2, []),
    "nbk007_unpinned_install": ("NBK-007", 1, []),
    "nbk008_missing_seed": ("NBK-008", 1, []),
    "nbk009_kernel_metadata": ("NBK-009", 1, []),
    "nbk010_not_a_notebook": ("NBK-010", 1, []),
    "nbk011_payload_bloat": ("NBK-011", 0, ["--include-info", "--max-output-bytes", "4096"]),
    "nbk012_hidden_state": ("NBK-012", 1, []),
    "nbk013_counter_mismatch": ("NBK-013", 2, []),
    "nbk014_widgets_no_state": ("NBK-014", 0, ["--include-info"]),
    "nbk015_unparseable_cell": ("NBK-015", 0, ["--include-info"]),
    "nbk016_hosted_path": ("NBK-016", 0, ["--include-info"]),
    "nbk017_cell_ids": ("NBK-017", 1, []),
    "nbk018_stripped": ("NBK-018", 0, ["--include-info"]),
}


class FixtureCoverageTests(unittest.TestCase):
    def test_every_rule_has_a_committed_fixture(self):
        covered = {rid for rid, _rc, _flags in CASES.values()}
        self.assertEqual(covered, {r.id for r in ALL_RULES})

    def test_every_fixture_directory_on_disk_is_in_the_case_table(self):
        on_disk = {
            d for d in os.listdir(FIXTURES)
            if os.path.isdir(os.path.join(FIXTURES, d))
            and d not in ("healthy", "unknown", "negatives", "families")
        }
        self.assertEqual(on_disk, set(CASES))

    def test_every_rule_has_a_negative_fixture_beside_it(self):
        want = {r.id.lower().replace("-", "") + "_clean.ipynb" for r in ALL_RULES}
        self.assertTrue(want.issubset(set(os.listdir(NEGATIVES))))


class PositiveFixtureTests(unittest.TestCase):
    def test_each_fixture_emits_its_own_rule(self):
        for name, (rid, _rc, flags) in sorted(CASES.items()):
            with self.subTest(fixture=name):
                _rc2, out, _err = run(fixture(name), *flags)
                self.assertIn(rid, out)

    def test_each_fixture_produces_its_documented_exit_code(self):
        for name, (_rid, rc, flags) in sorted(CASES.items()):
            with self.subTest(fixture=name):
                got, _out, _err = run(fixture(name), *flags)
                self.assertEqual(got, rc)

    def test_disabling_the_rule_removes_it_from_each_fixture(self):
        for name, (rid, _rc, flags) in sorted(CASES.items()):
            with self.subTest(fixture=name):
                _rc2, out, _err = run(fixture(name), "--disable", rid, *flags)
                self.assertNotIn(rid, out)

    def test_each_fixture_scans_at_least_one_file(self):
        for name, (_rid, _rc, flags) in sorted(CASES.items()):
            with self.subTest(fixture=name):
                _rc2, _out, err = run(fixture(name), *flags)
                self.assertNotIn("files_scanned=0", err)

    def test_each_fixture_produces_parseable_json(self):
        for name, (_rid, _rc, flags) in sorted(CASES.items()):
            with self.subTest(fixture=name):
                _rc2, out, _err = run(fixture(name), "--json", *flags)
                json.loads(out)


class NegativeFixtureTests(unittest.TestCase):
    def test_no_negative_fixture_trips_its_own_rule(self):
        for r in ALL_RULES:
            name = r.id.lower().replace("-", "") + "_clean.ipynb"
            with self.subTest(rule=r.id):
                _rc, out, _err = run(os.path.join(NEGATIVES, name), "--include-info")
                self.assertNotIn(r.id, out)

    def test_every_negative_fixture_exits_zero(self):
        for r in ALL_RULES:
            name = r.id.lower().replace("-", "") + "_clean.ipynb"
            with self.subTest(rule=r.id):
                rc, _out, _err = run(os.path.join(NEGATIVES, name))
                self.assertEqual(rc, 0)

    def test_the_negatives_directory_as_a_whole_is_clean(self):
        rc, out, _err = run(NEGATIVES)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")


class HealthyAndUnknownTests(unittest.TestCase):
    def test_the_healthy_fixture_has_no_findings_at_all(self):
        rc, out, err = run(fixture("healthy"), "--include-info")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertIn("findings_total=0", err)

    def test_the_healthy_fixture_is_still_clean_under_strict(self):
        rc, _out, _err = run(fixture("healthy"), "--strict", "--include-info")
        self.assertEqual(rc, 0)

    def test_the_unknown_fixture_rolls_up_to_unknown(self):
        rc, _out, err = run(fixture("unknown"))
        self.assertEqual(rc, 1)
        self.assertIn("verdict: unknown", err)

    def test_the_unknown_fixture_exits_two_under_strict(self):
        rc, _out, _err = run(fixture("unknown"), "--strict")
        self.assertEqual(rc, 2)

    def test_the_gate_finding_is_visible_without_include_info(self):
        _rc, out, _err = run(fixture("unknown"))
        self.assertIn("NBK-010", out)

    def test_the_unknown_fixture_scores_no_file(self):
        _rc, _out, err = run(fixture("unknown"))
        self.assertIn("files_scored=0", err)


class ColabFamilyTests(unittest.TestCase):
    PATH = os.path.join(FIXTURES, "families", "colab_export.ipynb")

    def test_a_hosted_export_reports_the_hosted_mount_as_info(self):
        _rc, out, _err = run(self.PATH, "--include-info")
        self.assertIn("NBK-016", out)

    def test_a_hosted_export_reports_its_missing_language_info(self):
        _rc, out, _err = run(self.PATH, "--include-info")
        self.assertIn("NBK-009", out)

    def test_a_hosted_mount_is_never_reported_as_a_machine_local_path(self):
        _rc, out, _err = run(self.PATH, "--include-info")
        self.assertNotIn("NBK-005", out)

    def test_a_hosted_export_does_not_reach_the_unhealthy_verdict(self):
        rc, _out, _err = run(self.PATH, "--include-info")
        self.assertEqual(rc, 1)


class ExampleTests(unittest.TestCase):
    HEALTHY = os.path.join(EXAMPLES, "healthy_notebook.ipynb")
    WEAK = os.path.join(EXAMPLES, "weak_notebook.ipynb")

    def test_the_healthy_example_exists(self):
        self.assertTrue(os.path.isfile(self.HEALTHY))

    def test_the_weak_example_exists(self):
        self.assertTrue(os.path.isfile(self.WEAK))

    def test_the_healthy_example_exits_zero(self):
        rc, out, _err = run(self.HEALTHY)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_the_healthy_example_is_clean_even_with_info_shown(self):
        rc, out, _err = run(self.HEALTHY, "--include-info")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_the_weak_example_exits_two(self):
        rc, _out, _err = run(self.WEAK)
        self.assertEqual(rc, 2)

    def test_the_weak_example_emits_nbk_001_on_stdout(self):
        _rc, out, _err = run(self.WEAK)
        self.assertIn("NBK-001", out)

    def test_the_weak_example_emits_several_distinct_rules(self):
        _rc, out, _err = run(self.WEAK, "--include-info")
        found = {ln.split()[1] for ln in out.splitlines() if ln.strip()}
        self.assertGreaterEqual(len(found), 8)

    def test_the_weak_example_never_prints_a_credential_value(self):
        _rc, out, _err = run(self.WEAK, "--include-info")
        self.assertNotIn("NOT-A-REAL-CREDENTIAL", out)
        self.assertNotIn("AbCdEfGhIjKlMnOpQrStUvWxYz012345", out)

    def test_the_examples_directory_as_a_whole_exits_two(self):
        rc, _out, _err = run(EXAMPLES)
        self.assertEqual(rc, 2)

    def test_the_weak_example_json_payload_matches_its_exit_code(self):
        rc, out, _err = run(self.WEAK, "--json")
        self.assertEqual(json.loads(out)["exit_code"], rc)


class WholeTreeTests(unittest.TestCase):
    def test_scanning_the_whole_fixture_tree_does_not_crash(self):
        rc, _out, err = run(FIXTURES, "--include-info")
        self.assertIn(rc, (1, 2))
        self.assertIn("files_scanned=", err)

    def test_scanning_the_whole_fixture_tree_produces_parseable_json(self):
        _rc, out, _err = run(FIXTURES, "--json", "--include-info")
        doc = json.loads(out)
        self.assertGreater(doc["files_scanned"], 20)

    def test_the_fixture_tree_reports_both_scored_and_unknown_files(self):
        _rc, out, _err = run(FIXTURES, "--json")
        doc = json.loads(out)
        self.assertGreater(doc["files_scored"], 0)
        self.assertGreater(doc["files_unknown"], 0)


if __name__ == "__main__":
    unittest.main()
