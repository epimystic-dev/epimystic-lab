"""CLI flag contract, exercised through main(argv)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from sarifcheck import __version__
from sarifcheck.limits import ALL_LIMITS, LIMIT_NAMES
from sarifcheck.rules import ALL_RULES

from tests.support import example, fixture, run_cli


class VersionAndHelpTests(unittest.TestCase):
    def test_version_flag_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_unknown_flag_exits_two(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["--definitely-not-a-flag"])
        self.assertEqual(ctx.exception.code, 2)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["--help"])
        self.assertEqual(ctx.exception.code, 0)


class ListRulesTests(unittest.TestCase):
    def test_list_rules_exits_zero(self):
        rc, _out, _err = run_cli(["--list-rules"])
        self.assertEqual(rc, 0)

    def test_list_rules_prints_every_code(self):
        _rc, out, _err = run_cli(["--list-rules"])
        for rule in ALL_RULES:
            self.assertIn(rule.id, out)

    def test_list_rules_prints_severity_and_profile(self):
        _rc, out, _err = run_cli(["--list-rules"])
        self.assertIn("[spec]", out)
        self.assertIn("[ingest]", out)
        self.assertIn("[hygiene]", out)

    def test_list_rules_goes_to_stdout(self):
        _rc, out, err = run_cli(["--list-rules"])
        self.assertIn("SRF-001", out)
        self.assertEqual(err, "")


class ShowLimitsTests(unittest.TestCase):
    def test_show_limits_exits_zero(self):
        rc, _out, _err = run_cli(["--show-limits"])
        self.assertEqual(rc, 0)

    def test_show_limits_names_every_limit(self):
        _rc, out, _err = run_cli(["--show-limits"])
        for name in LIMIT_NAMES:
            self.assertIn(name, out)

    def test_show_limits_carries_provenance(self):
        _rc, out, _err = run_cli(["--show-limits"])
        for limit in ALL_LIMITS:
            self.assertIn(limit.source_url, out)
            self.assertIn(limit.retrieved, out)

    def test_show_limits_disclaims_the_standard(self):
        _rc, out, _err = run_cli(["--show-limits"])
        self.assertIn("NOT part of the OASIS SARIF 2.1.0 specification", out)


class ExitCodeTests(unittest.TestCase):
    def test_healthy_example_is_zero(self):
        rc, _out, _err = run_cli([example("healthy_results.sarif")])
        self.assertEqual(rc, 0)

    def test_weak_example_is_two(self):
        rc, _out, _err = run_cli([example("weak_results.sarif")])
        self.assertEqual(rc, 2)

    def test_medium_only_fixture_is_one(self):
        rc, _out, _err = run_cli([fixture("srf018_no_fingerprints")])
        self.assertEqual(rc, 1)

    def test_info_only_fixture_is_zero_by_default(self):
        rc, _out, _err = run_cli([fixture("srf026_thin_metadata")])
        self.assertEqual(rc, 0)

    def test_info_only_fixture_is_one_under_strict(self):
        rc, _out, _err = run_cli(["--strict", fixture("srf026_thin_metadata")])
        self.assertEqual(rc, 1)

    def test_no_files_is_one_by_default(self):
        rc, _out, _err = run_cli([fixture("unknown")])
        self.assertEqual(rc, 1)

    def test_no_files_is_two_under_strict(self):
        rc, _out, _err = run_cli(["--strict", fixture("unknown")])
        self.assertEqual(rc, 2)

    def test_missing_path_is_two(self):
        rc, _out, err = run_cli(["no-such-directory-here"])
        self.assertEqual(rc, 2)
        self.assertIn("path does not exist", err)

    def test_unparseable_file_is_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "results.sarif")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("not json")
            rc, _out, err = run_cli([path])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR", err)

    def test_partial_scan_is_one(self):
        rc, _out, _err = run_cli([fixture("srf027_external_props")])
        self.assertEqual(rc, 1)


class StreamDisciplineTests(unittest.TestCase):
    def test_findings_go_to_stdout(self):
        _rc, out, _err = run_cli([fixture("srf001_bad_version")])
        self.assertIn("SRF-001", out)

    def test_summary_goes_to_stderr(self):
        _rc, out, err = run_cli([fixture("srf001_bad_version")])
        self.assertIn("verdict:", err)
        self.assertNotIn("verdict:", out)

    def test_clean_run_writes_nothing_to_stdout(self):
        _rc, out, err = run_cli([example("healthy_results.sarif")])
        self.assertEqual(out, "")
        self.assertIn("verdict: healthy", err)

    def test_json_mode_stdout_is_parseable_on_its_own(self):
        _rc, out, _err = run_cli(["--json", fixture("srf001_bad_version")])
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "sarifcheck")

    def test_json_mode_still_writes_the_summary_to_stderr(self):
        _rc, _out, err = run_cli(["--json", fixture("srf001_bad_version")])
        self.assertIn("verdict:", err)


class JsonModeTests(unittest.TestCase):
    def test_version_is_the_package_version(self):
        _rc, out, _err = run_cli(["--json", example("healthy_results.sarif")])
        self.assertEqual(json.loads(out)["version"], __version__)

    def test_exit_code_matches_the_embedded_value(self):
        rc, out, _err = run_cli(["--json", fixture("srf001_bad_version")])
        self.assertEqual(rc, json.loads(out)["exit_code"])

    def test_profiles_are_echoed(self):
        _rc, out, _err = run_cli(
            ["--json", "--profile", "spec", example("healthy_results.sarif")]
        )
        self.assertEqual(json.loads(out)["profiles"], ["spec"])

    def test_limits_are_echoed_with_overrides_applied(self):
        _rc, out, _err = run_cli([
            "--json", "--limit", "max_runs_per_file=3",
            example("healthy_results.sarif"),
        ])
        self.assertEqual(json.loads(out)["limits"]["max_runs_per_file"], 3)


class FilterFlagTests(unittest.TestCase):
    def test_include_info_shows_info_findings(self):
        _rc, out, _err = run_cli([fixture("srf026_thin_metadata")])
        self.assertNotIn("SRF-026", out)
        _rc, out, _err = run_cli(["--include-info", fixture("srf026_thin_metadata")])
        self.assertIn("SRF-026", out)

    def test_disable_removes_a_rule(self):
        _rc, out, _err = run_cli(
            ["--disable", "SRF-001", fixture("srf001_bad_version")]
        )
        self.assertNotIn("SRF-001", out)

    def test_disable_is_repeatable(self):
        rc, out, _err = run_cli([
            "--disable", "SRF-004", "--disable", "SRF-005",
            fixture("srf004_absolute_uri"),
        ])
        self.assertNotIn("SRF-004", out)
        self.assertEqual(rc, 0)

    def test_unknown_disable_code_is_a_usage_error(self):
        rc, _out, err = run_cli(["--disable", "SRF-999", fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("unknown rule code", err)

    def test_profile_spec_drops_ingest_rules(self):
        _rc, out, _err = run_cli(
            ["--profile", "spec", fixture("srf003_missing_schema")]
        )
        self.assertNotIn("SRF-003", out)

    def test_profile_ingest_keeps_ingest_rules(self):
        _rc, out, _err = run_cli(
            ["--profile", "ingest", fixture("srf003_missing_schema")]
        )
        self.assertIn("SRF-003", out)

    def test_bad_profile_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["--profile", "nonsense", fixture("healthy")])
        self.assertEqual(ctx.exception.code, 2)

    def test_ignore_rule_id_suppresses_path_shapes(self):
        rc, out, _err = run_cli(
            ["--ignore-rule-id", "FX001", fixture("srf006_path_in_message")]
        )
        self.assertNotIn("SRF-006", out)
        self.assertEqual(rc, 0)

    def test_allow_path_in_message_suppresses_the_rule(self):
        rc, out, _err = run_cli(
            ["--allow-path-in-message", fixture("srf006_path_in_message")]
        )
        self.assertNotIn("SRF-006", out)
        self.assertEqual(rc, 0)


class ShowMatchesTests(unittest.TestCase):
    def test_matches_are_hidden_by_default(self):
        _rc, out, _err = run_cli([fixture("srf006_path_in_message")])
        self.assertNotIn("devuser", out)

    def test_matches_are_shown_on_request(self):
        _rc, out, _err = run_cli(["--show-matches", fixture("srf006_path_in_message")])
        self.assertIn("devuser", out)

    def test_show_matches_warns_on_stderr(self):
        _rc, _out, err = run_cli(["--show-matches", fixture("srf006_path_in_message")])
        self.assertIn("Do not use this in a public CI log", err)


class LimitOverrideTests(unittest.TestCase):
    def test_limit_override_lowers_a_ceiling(self):
        rc, out, _err = run_cli(
            ["--limit", "max_tags_per_rule=1", fixture("srf017_soft_limit")]
        )
        self.assertIn("SRF-016", out)
        self.assertEqual(rc, 2)

    def test_limit_override_raises_a_ceiling(self):
        rc, out, _err = run_cli(
            ["--limit", "max_tags_per_rule=100", "--limit", "soft_tags_per_rule=100",
             fixture("srf017_soft_limit")]
        )
        self.assertNotIn("SRF-017", out)
        self.assertEqual(rc, 0)

    def test_unknown_limit_name_is_a_usage_error(self):
        rc, _out, err = run_cli(["--limit", "nope=1", fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("unknown limit name", err)

    def test_non_integer_limit_is_a_usage_error(self):
        rc, _out, err = run_cli(
            ["--limit", "max_runs_per_file=many", fixture("healthy")]
        )
        self.assertEqual(rc, 2)
        self.assertIn("needs an integer", err)

    def test_malformed_limit_token_is_a_usage_error(self):
        rc, _out, err = run_cli(["--limit", "max_runs_per_file", fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("NAME=VALUE", err)

    def test_negative_limit_is_a_usage_error(self):
        rc, _out, err = run_cli(
            ["--limit", "max_runs_per_file=-1", fixture("healthy")]
        )
        self.assertEqual(rc, 2)
        self.assertIn("must be >= 0", err)

    def test_limits_file_applies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "limits.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"max_tags_per_rule": 1}, handle)
            rc, out, _err = run_cli(
                ["--limits-file", path, fixture("srf017_soft_limit")]
            )
        self.assertIn("SRF-016", out)
        self.assertEqual(rc, 2)

    def test_limit_flag_wins_over_limits_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "limits.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"max_tags_per_rule": 1}, handle)
            rc, out, _err = run_cli([
                "--limits-file", path, "--limit", "max_tags_per_rule=100",
                "--limit", "soft_tags_per_rule=100",
                fixture("srf017_soft_limit"),
            ])
        self.assertNotIn("SRF-016", out)
        self.assertEqual(rc, 0)

    def test_missing_limits_file_is_a_usage_error(self):
        rc, _out, err = run_cli(
            ["--limits-file", "no-such-file.json", fixture("healthy")]
        )
        self.assertEqual(rc, 2)
        self.assertIn("cannot read limits file", err)

    def test_limits_file_with_bad_json_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "limits.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            rc, _out, err = run_cli(["--limits-file", path, fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", err)

    def test_limits_file_with_unknown_name_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "limits.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"nope": 1}, handle)
            rc, _out, err = run_cli(["--limits-file", path, fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("unknown limit name", err)

    def test_limits_file_holding_an_array_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "limits.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump([1, 2], handle)
            rc, _out, err = run_cli(["--limits-file", path, fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("must hold a JSON object", err)


class BudgetFlagTests(unittest.TestCase):
    def test_max_files_zero_is_a_usage_error(self):
        rc, _out, err = run_cli(["--max-files", "0", fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("--max-files must be > 0", err)

    def test_max_bytes_zero_is_a_usage_error(self):
        rc, _out, err = run_cli(["--max-bytes", "0", fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("--max-bytes must be > 0", err)

    def test_max_bytes_below_file_size_refuses_to_parse(self):
        rc, _out, err = run_cli(["--max-bytes", "10", fixture("healthy")])
        self.assertEqual(rc, 2)
        self.assertIn("size-refused", err)

    def test_glob_extends_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scan.out")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"version": "2.1.0", "runs": []}')
            rc_without, _o1, err1 = run_cli([tmp])
            rc_with, _o2, err2 = run_cli(["--glob", "*.out", tmp])
        self.assertIn("files_scanned=0", err1)
        self.assertIn("files_scanned=1", err2)


class DefaultPathTests(unittest.TestCase):
    def test_default_path_is_the_current_directory(self):
        cwd = os.getcwd()
        try:
            os.chdir(fixture("healthy"))
            rc, _out, err = run_cli([])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)
        self.assertIn("files_scanned=1", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
