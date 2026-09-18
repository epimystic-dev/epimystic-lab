"""CLI behaviour: flags, exit codes, and the stdout / stderr split."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nbfactory as F  # noqa: E402

from nbshape.cli import main  # noqa: E402


CLEAN = F.nb([F.code("x = 1", ec=1)])
DIRTY = F.nb([F.code('p = "/home/jsmith/x"', ec=1)])
WARN = F.nb([F.code("a", ec=5), F.code("b", ec=1)])
INFO_ONLY = F.nb([F.code('p = "/content/x.csv"', ec=1)])


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def run_argparse_exit(*argv):
    """argparse writes --help / --version straight to the process streams.

    Redirect them so the test run stays quiet, and return the SystemExit code.
    """
    sink_out, sink_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(sink_out), contextlib.redirect_stderr(sink_err):
        try:
            main(list(argv), stdout=sink_out, stderr=sink_err)
        except SystemExit as exc:
            return exc.code, sink_out.getvalue(), sink_err.getvalue()
    raise AssertionError("expected argparse to exit for " + repr(argv))


class HelpAndVersionTests(unittest.TestCase):
    def test_help_exits_zero(self):
        code, out, _err = run_argparse_exit("--help")
        self.assertEqual(code, 0)
        self.assertIn("nbshape", out)

    def test_help_documents_every_contract_flag(self):
        _code, out, _err = run_argparse_exit("--help")
        for flag in ("--json", "--strict", "--include-info", "--disable",
                     "--version", "--list-rules"):
            self.assertIn(flag, out)

    def test_version_exits_zero_and_prints_tool_and_version(self):
        code, out, err = run_argparse_exit("--version")
        self.assertEqual(code, 0)
        self.assertRegex((out + err).strip(), r"nbshape \d+\.\d+\.\d+")

    def test_an_unknown_flag_exits_two(self):
        code, _out, err = run_argparse_exit("--definitely-not-a-flag")
        self.assertEqual(code, 2)
        self.assertIn("unrecognized arguments", err)

    def test_list_rules_exits_zero_and_prints_every_rule(self):
        rc, out, _err = run("--list-rules")
        self.assertEqual(rc, 0)
        for i in range(1, 19):
            self.assertIn("NBK-" + str(i).zfill(3), out)


class ExitCodeTests(unittest.TestCase):
    def test_a_clean_notebook_exits_zero(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", CLEAN))
            self.assertEqual(rc, 0)

    def test_a_high_finding_exits_two(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", DIRTY))
            self.assertEqual(rc, 2)

    def test_a_medium_only_finding_exits_one(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", WARN))
            self.assertEqual(rc, 1)

    def test_an_info_only_finding_exits_zero_by_default(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", INFO_ONLY))
            self.assertEqual(rc, 0)

    def test_an_info_only_finding_exits_one_under_strict(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", INFO_ONLY), "--strict")
            self.assertEqual(rc, 1)

    def test_no_files_found_exits_one_by_default(self):
        with F.TempTree() as t:
            rc, _out, err = run(t.dir)
            self.assertEqual(rc, 1)
            self.assertIn("unknown", err)

    def test_no_files_found_exits_two_under_strict(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.dir, "--strict")
            self.assertEqual(rc, 2)

    def test_a_missing_path_exits_two_with_a_stderr_diagnostic(self):
        rc, out, err = run(os.path.join("no", "such", "place"))
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("path does not exist", err)

    def test_an_unscorable_file_exits_one(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", {"hello": 1}))
            self.assertEqual(rc, 1)

    def test_an_unscorable_file_exits_two_under_strict(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", {"hello": 1}), "--strict")
            self.assertEqual(rc, 2)


class StreamDisciplineTests(unittest.TestCase):
    def test_a_clean_run_writes_nothing_to_stdout(self):
        with F.TempTree() as t:
            _rc, out, err = run(t.write("a.ipynb", CLEAN))
            self.assertEqual(out, "")
            self.assertIn("verdict: healthy", err)

    def test_findings_go_to_stdout(self):
        with F.TempTree() as t:
            _rc, out, _err = run(t.write("a.ipynb", DIRTY))
            self.assertIn("NBK-005", out)

    def test_the_verdict_line_goes_to_stderr_not_stdout(self):
        with F.TempTree() as t:
            _rc, out, err = run(t.write("a.ipynb", DIRTY))
            self.assertNotIn("verdict:", out)
            self.assertIn("verdict: unhealthy", err)

    def test_diagnostics_go_to_stderr(self):
        with F.TempTree() as t:
            _rc, out, err = run(t.write_raw("a.ipynb", "{oops"))
            self.assertNotIn("diagnostic:", out)
            self.assertIn("diagnostic:", err)

    def test_json_mode_puts_only_json_on_stdout(self):
        with F.TempTree() as t:
            _rc, out, _err = run(t.write("a.ipynb", DIRTY), "--json")
            json.loads(out)

    def test_json_mode_still_summarises_on_stderr(self):
        with F.TempTree() as t:
            _rc, _out, err = run(t.write("a.ipynb", DIRTY), "--json")
            self.assertIn("verdict:", err)


class FlagTests(unittest.TestCase):
    def test_include_info_surfaces_hidden_findings(self):
        with F.TempTree() as t:
            p = t.write("a.ipynb", INFO_ONLY)
            _rc, plain, _e = run(p)
            _rc2, verbose, _e2 = run(p, "--include-info")
            self.assertNotIn("NBK-016", plain)
            self.assertIn("NBK-016", verbose)

    def test_disable_removes_one_rule(self):
        with F.TempTree() as t:
            p = t.write("a.ipynb", DIRTY)
            _rc, before, _e = run(p)
            rc_after, after, _e2 = run(p, "--disable", "NBK-005")
            self.assertIn("NBK-005", before)
            self.assertNotIn("NBK-005", after)
            self.assertEqual(rc_after, 0)

    def test_disable_is_repeatable(self):
        book = F.nb([
            F.code('p = "/home/jsmith/x"', ec=5),
            F.code("q = 1", ec=1),
        ])
        with F.TempTree() as t:
            p = t.write("a.ipynb", book)
            rc, out, _e = run(p, "--disable", "NBK-005", "--disable", "NBK-001")
            self.assertEqual(rc, 0)
            self.assertEqual(out, "")

    def test_an_unknown_disable_code_exits_two_with_a_diagnostic(self):
        rc, _out, err = run(".", "--disable", "NBK-999")
        self.assertEqual(rc, 2)
        self.assertIn("unknown rule id", err)

    def test_a_zero_max_files_is_rejected(self):
        rc, _out, err = run(".", "--max-files", "0")
        self.assertEqual(rc, 2)
        self.assertIn("--max-files", err)

    def test_a_zero_max_bytes_is_rejected(self):
        rc, _out, err = run(".", "--max-bytes", "0")
        self.assertEqual(rc, 2)
        self.assertIn("--max-bytes", err)

    def test_a_zero_rerun_factor_is_rejected(self):
        rc, _out, err = run(".", "--rerun-factor", "0")
        self.assertEqual(rc, 2)
        self.assertIn("--rerun-factor", err)

    def test_a_zero_min_literal_len_is_rejected(self):
        rc, _out, err = run(".", "--min-literal-len", "0")
        self.assertEqual(rc, 2)
        self.assertIn("--min-literal-len", err)

    def test_a_zero_max_output_bytes_is_rejected(self):
        rc, _out, err = run(".", "--max-output-bytes", "0")
        self.assertEqual(rc, 2)
        self.assertIn("--max-output-bytes", err)

    def test_the_rerun_factor_is_wired_through_to_the_rule(self):
        book = F.nb([F.code("a", ec=1), F.code("b", ec=9)])
        with F.TempTree() as t:
            p = t.write("a.ipynb", book)
            _rc, tight, _e = run(p, "--include-info")
            _rc2, loose, _e2 = run(p, "--include-info", "--rerun-factor", "50")
            self.assertIn("NBK-004", tight)
            self.assertNotIn("NBK-004", loose)

    def test_the_max_output_bytes_flag_is_wired_through(self):
        book = F.nb([F.code("p()", ec=1, outputs=[F.display("image/png", "A" * 5000)])])
        with F.TempTree() as t:
            p = t.write("a.ipynb", book)
            _rc, plain, _e = run(p, "--include-info")
            _rc2, tuned, _e2 = run(p, "--include-info", "--max-output-bytes", "1000")
            self.assertNotIn("NBK-011", plain)
            self.assertIn("NBK-011", tuned)

    def test_the_min_literal_len_flag_is_wired_through(self):
        book = F.nb([F.code('api_key = "' + F.CRED_VALUE + '"', ec=1)])
        with F.TempTree() as t:
            p = t.write("a.ipynb", book)
            _rc, plain, _e = run(p)
            _rc2, loose, _e2 = run(p, "--min-literal-len", "500")
            self.assertIn("NBK-006", plain)
            self.assertNotIn("NBK-006", loose)

    def test_the_max_files_cap_is_wired_through(self):
        with F.TempTree() as t:
            for i in range(4):
                t.write("n" + str(i) + ".ipynb", CLEAN)
            _rc, _out, err = run(t.dir, "--max-files", "2")
            self.assertIn("files_scanned=2", err)

    def test_the_max_bytes_cap_is_wired_through(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            _rc, _out, err = run(t.dir, "--max-bytes", "10")
            self.assertIn("over-size-cap", err)

    def test_checkpoints_are_skipped_by_default_and_included_on_request(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            t.write(os.path.join(".ipynb_checkpoints", "a-checkpoint.ipynb"), CLEAN)
            _rc, _o, default_err = run(t.dir)
            _rc2, _o2, opted_err = run(t.dir, "--include-checkpoints")
            self.assertIn("files_scanned=1", default_err)
            self.assertIn("files_scanned=2", opted_err)

    def test_a_custom_glob_extends_discovery(self):
        with F.TempTree() as t:
            t.write_raw("a.nb", json.dumps(CLEAN))
            _rc, _o, err = run(t.dir, "--glob", "*.nb")
            self.assertIn("files_scanned=1", err)

    def test_the_default_path_is_the_current_directory(self):
        rc, _out, err = run()
        self.assertIn("files_scanned=", err)
        self.assertIn(rc, (0, 1, 2))


class JsonPayloadTests(unittest.TestCase):
    def test_the_payload_exit_code_matches_the_process_exit_code(self):
        with F.TempTree() as t:
            rc, out, _err = run(t.write("a.ipynb", DIRTY), "--json")
            self.assertEqual(json.loads(out)["exit_code"], rc)

    def test_the_payload_lists_the_findings(self):
        with F.TempTree() as t:
            _rc, out, _err = run(t.write("a.ipynb", DIRTY), "--json")
            ids = [f["rule_id"] for f in json.loads(out)["findings"]]
            self.assertIn("NBK-005", ids)

    def test_the_payload_reports_an_unknown_verdict_for_a_non_notebook(self):
        with F.TempTree() as t:
            _rc, out, _err = run(t.write("a.ipynb", {"hello": 1}), "--json")
            self.assertEqual(json.loads(out)["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
