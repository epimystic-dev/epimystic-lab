"""Discovery, reading, and whole-tree scanning."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nbfactory as F  # noqa: E402

from nbshape.rules import RuleConfig  # noqa: E402
from nbshape.scanner import (  # noqa: E402
    CHECKPOINT_DIR,
    DEFAULT_GLOBS,
    discover,
    read_notebook_text,
    scan_file,
    scan_path,
)


CLEAN = F.nb([F.code("x = 1", ec=1)])
DIRTY = F.nb([F.code('p = "/home/jsmith/x"', ec=1)])


class DiscoverTests(unittest.TestCase):
    def test_a_missing_path_yields_nothing(self):
        self.assertEqual(discover(os.path.join("no", "such", "dir")), [])

    def test_a_single_matching_file_is_returned(self):
        with F.TempTree() as t:
            p = t.write("one.ipynb", CLEAN)
            self.assertEqual(discover(p), [p])

    def test_a_single_non_matching_file_is_skipped(self):
        with F.TempTree() as t:
            p = t.write_raw("notes.txt", "hello")
            self.assertEqual(discover(p), [])

    def test_a_directory_walk_finds_nested_notebooks(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            t.write(os.path.join("sub", "b.ipynb"), CLEAN)
            self.assertEqual(len(discover(t.dir)), 2)

    def test_results_are_sorted_deterministically(self):
        with F.TempTree() as t:
            for name in ("z.ipynb", "a.ipynb", "m.ipynb"):
                t.write(name, CLEAN)
            names = [os.path.basename(p) for p in discover(t.dir)]
            self.assertEqual(names, sorted(names))

    def test_checkpoint_directories_are_skipped_by_default(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            t.write(os.path.join(CHECKPOINT_DIR, "a-checkpoint.ipynb"), CLEAN)
            self.assertEqual(len(discover(t.dir)), 1)

    def test_checkpoint_directories_are_included_on_request(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            t.write(os.path.join(CHECKPOINT_DIR, "a-checkpoint.ipynb"), CLEAN)
            self.assertEqual(len(discover(t.dir, include_checkpoints=True)), 2)

    def test_an_explicitly_named_checkpoint_file_is_always_honoured(self):
        with F.TempTree() as t:
            p = t.write(os.path.join(CHECKPOINT_DIR, "a-checkpoint.ipynb"), CLEAN)
            self.assertEqual(discover(p), [p])

    def test_noise_directories_are_pruned(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            t.write(os.path.join("node_modules", "b.ipynb"), CLEAN)
            t.write(os.path.join(".git", "c.ipynb"), CLEAN)
            self.assertEqual(len(discover(t.dir)), 1)

    def test_the_max_files_cap_is_honoured(self):
        with F.TempTree() as t:
            for i in range(6):
                t.write("n" + str(i) + ".ipynb", CLEAN)
            self.assertEqual(len(discover(t.dir, max_files=2)), 2)

    def test_matching_is_case_insensitive(self):
        with F.TempTree() as t:
            p = t.write("Upper.IPYNB", CLEAN)
            self.assertEqual(discover(p), [p])

    def test_a_custom_glob_extends_the_default_set(self):
        with F.TempTree() as t:
            t.write_raw("a.nb", "{}")
            found = discover(t.dir, globs=list(DEFAULT_GLOBS) + ["*.nb"])
            self.assertEqual(len(found), 1)

    def test_non_notebook_files_are_ignored_in_a_walk(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            t.write_raw("b.json", "{}")
            t.write_raw("c.py", "x = 1")
            self.assertEqual(len(discover(t.dir)), 1)


class ReadTests(unittest.TestCase):
    def test_a_utf8_file_reads_back(self):
        with F.TempTree() as t:
            p = t.write_raw("a.ipynb", '{"a": 1}')
            text, err, size = read_notebook_text(p)
            self.assertIsNone(err)
            self.assertEqual(text, '{"a": 1}')
            self.assertEqual(size, 8)

    def test_a_byte_order_mark_is_stripped(self):
        with F.TempTree() as t:
            p = t.write_bytes("a.ipynb", b"\xef\xbb\xbf" + b'{"a": 1}')
            text, err, _size = read_notebook_text(p)
            self.assertIsNone(err)
            self.assertTrue(text.startswith("{"))

    def test_a_missing_file_is_reported_not_raised(self):
        text, err, _size = read_notebook_text(os.path.join("no", "such.ipynb"))
        self.assertIsNone(text)
        self.assertIn("stat-error", err)

    def test_a_file_over_the_byte_cap_is_reported_not_parsed(self):
        with F.TempTree() as t:
            p = t.write_raw("big.ipynb", "x" * 5000)
            text, err, size = read_notebook_text(p, max_bytes=100)
            self.assertIsNone(text)
            self.assertIn("over-size-cap", err)
            self.assertEqual(size, 5000)

    def test_invalid_utf8_is_reported_not_raised(self):
        with F.TempTree() as t:
            p = t.write_bytes("bad.ipynb", b'{"a": "\xff\xfe\xff"}')
            text, err, _size = read_notebook_text(p)
            self.assertIsNone(text)
            self.assertIn("encoding-error", err)

    def test_an_empty_file_reads_as_empty_text(self):
        with F.TempTree() as t:
            p = t.write_raw("empty.ipynb", "")
            text, err, size = read_notebook_text(p)
            self.assertIsNone(err)
            self.assertEqual(text, "")
            self.assertEqual(size, 0)


class ScanFileTests(unittest.TestCase):
    def test_a_clean_notebook_scores_with_no_findings(self):
        with F.TempTree() as t:
            out = scan_file(t.write("a.ipynb", CLEAN))
            self.assertTrue(out.scored)
            self.assertEqual(out.findings, [])
            self.assertIsNone(out.error)

    def test_a_dirty_notebook_scores_with_findings(self):
        with F.TempTree() as t:
            out = scan_file(t.write("a.ipynb", DIRTY))
            self.assertTrue(out.scored)
            self.assertTrue(any(f.rule_id == "NBK-005" for f in out.findings))

    def test_a_non_notebook_does_not_score_and_reports_nbk_010(self):
        with F.TempTree() as t:
            out = scan_file(t.write("a.ipynb", {"hello": 1}))
            self.assertFalse(out.scored)
            self.assertEqual([f.rule_id for f in out.findings], ["NBK-010"])
            self.assertIn("not-a-notebook", out.error)

    def test_unparseable_json_does_not_score_and_reports_nbk_010(self):
        with F.TempTree() as t:
            out = scan_file(t.write_raw("a.ipynb", "{oops"))
            self.assertFalse(out.scored)
            self.assertEqual([f.rule_id for f in out.findings], ["NBK-010"])
            self.assertIn("unparseable", out.error)

    def test_an_empty_file_does_not_score_and_does_not_raise(self):
        with F.TempTree() as t:
            out = scan_file(t.write_raw("a.ipynb", ""))
            self.assertFalse(out.scored)
            self.assertIsNotNone(out.error)

    def test_an_unreadable_path_is_reported_not_raised(self):
        out = scan_file(os.path.join("no", "such.ipynb"))
        self.assertFalse(out.scored)
        self.assertIn("stat-error", out.error)

    def test_a_disabled_rule_does_not_appear(self):
        with F.TempTree() as t:
            out = scan_file(t.write("a.ipynb", DIRTY), disabled=frozenset(["NBK-005"]))
            self.assertNotIn("NBK-005", [f.rule_id for f in out.findings])

    def test_a_custom_config_reaches_the_rules(self):
        book = F.nb([F.code("p()", ec=1, outputs=[F.display("image/png", "A" * 5000)])])
        with F.TempTree() as t:
            p = t.write("a.ipynb", book)
            base = scan_file(p)
            tuned = scan_file(p, config=RuleConfig(max_output_bytes=1000))
            self.assertNotIn("NBK-011", [f.rule_id for f in base.findings])
            self.assertIn("NBK-011", [f.rule_id for f in tuned.findings])

    def test_findings_carry_the_path_they_came_from(self):
        with F.TempTree() as t:
            p = t.write("a.ipynb", DIRTY)
            out = scan_file(p)
            self.assertTrue(all(f.path == p for f in out.findings))


class ScanPathTests(unittest.TestCase):
    def test_an_empty_directory_scans_zero_files(self):
        with F.TempTree() as t:
            r = scan_path(t.dir)
            self.assertEqual(r.files_scanned, 0)
            self.assertEqual(r.findings, tuple())

    def test_counts_split_into_scored_and_unknown(self):
        with F.TempTree() as t:
            t.write("clean.ipynb", CLEAN)
            t.write("bad.ipynb", {"hello": 1})
            r = scan_path(t.dir)
            self.assertEqual(r.files_scanned, 2)
            self.assertEqual(r.files_scored, 1)
            self.assertEqual(r.files_unknown, 1)

    def test_findings_are_sorted_high_first(self):
        with F.TempTree() as t:
            t.write("a.ipynb", F.nb([
                F.code('p = "/content/x"', ec=1),
                F.code('q = "/home/jsmith/x"', ec=2),
            ]))
            r = scan_path(t.dir)
            sevs = [f.severity.value for f in r.findings]
            self.assertEqual(sevs, sorted(sevs, key=lambda s: {"HIGH": 0, "MEDIUM": 1,
                                                               "INFO": 2}[s]))

    def test_errors_are_collected_per_file(self):
        with F.TempTree() as t:
            t.write_raw("a.ipynb", "{oops")
            t.write_raw("b.ipynb", "{also bad")
            r = scan_path(t.dir)
            self.assertEqual(len(r.errors), 2)

    def test_a_checkpoint_copy_does_not_double_the_findings(self):
        with F.TempTree() as t:
            t.write("a.ipynb", DIRTY)
            t.write(os.path.join(CHECKPOINT_DIR, "a-checkpoint.ipynb"), DIRTY)
            default = scan_path(t.dir)
            opted_in = scan_path(t.dir, include_checkpoints=True)
            self.assertEqual(default.files_scanned, 1)
            self.assertEqual(opted_in.files_scanned, 2)
            self.assertLess(len(default.findings), len(opted_in.findings))

    def test_the_byte_cap_routes_a_big_file_to_unknown(self):
        with F.TempTree() as t:
            t.write("a.ipynb", CLEAN)
            r = scan_path(t.dir, max_bytes=10)
            self.assertEqual(r.files_scored, 0)
            self.assertEqual(r.files_unknown, 1)
            self.assertIn("over-size-cap", r.errors[0])

    def test_scanning_a_single_file_path_works(self):
        with F.TempTree() as t:
            p = t.write("a.ipynb", DIRTY)
            r = scan_path(p)
            self.assertEqual(r.files_scanned, 1)


if __name__ == "__main__":
    unittest.main()
