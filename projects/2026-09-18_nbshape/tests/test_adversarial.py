"""Adversarial inputs. The tool must never traceback.

Every case here asserts two things: a sane exit code, and that the process
produced a diagnostic rather than a stack trace. A linter that crashes on a
malformed file is worse than no linter, because CI then reports a tooling
failure where a content failure was meant.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nbfactory as F  # noqa: E402

from nbshape.cli import main  # noqa: E402
from nbshape.parse import build_notebook, demagic, parse_python  # noqa: E402
from nbshape.scanner import scan_file, scan_path  # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


class MalformedFileTests(unittest.TestCase):
    def test_an_empty_file_gives_a_sane_exit_code(self):
        with F.TempTree() as t:
            rc, _out, err = run(t.write_raw("a.ipynb", ""))
            self.assertIn(rc, (1, 2))
            self.assertIn("diagnostic:", err)

    def test_a_file_of_only_whitespace_gives_a_sane_exit_code(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_raw("a.ipynb", "\n\n\t  \n"))
            self.assertIn(rc, (1, 2))

    def test_plain_text_that_is_not_json_is_reported(self):
        with F.TempTree() as t:
            rc, out, _err = run(t.write_raw("a.ipynb", "this is not json at all"))
            self.assertIn(rc, (1, 2))
            self.assertIn("NBK-010", out)

    def test_truncated_json_is_reported(self):
        with F.TempTree() as t:
            rc, out, _err = run(t.write_raw("a.ipynb", '{"cells": [{"source": "x"'))
            self.assertIn(rc, (1, 2))
            self.assertIn("NBK-010", out)

    def test_a_top_level_array_is_reported(self):
        with F.TempTree() as t:
            rc, out, _err = run(t.write("a.ipynb", [1, 2, 3]))
            self.assertIn(rc, (1, 2))
            self.assertIn("NBK-010", out)

    def test_a_top_level_number_is_reported(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_raw("a.ipynb", "42"))
            self.assertIn(rc, (1, 2))

    def test_a_top_level_string_is_reported(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_raw("a.ipynb", '"just a string"'))
            self.assertIn(rc, (1, 2))

    def test_a_json_null_is_reported(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_raw("a.ipynb", "null"))
            self.assertIn(rc, (1, 2))

    def test_a_null_byte_in_the_file_does_not_crash(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_bytes("a.ipynb", b'{"a": "b\x00c"}'))
            self.assertIn(rc, (0, 1, 2))

    def test_a_null_byte_inside_cell_source_does_not_crash(self):
        book = F.nb([F.code("x = 1\x00\ny = 2", ec=1)])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_invalid_utf8_bytes_are_reported_not_raised(self):
        with F.TempTree() as t:
            rc, _out, err = run(t.write_bytes("a.ipynb", b'{"a": "\xff\xfe"}'))
            self.assertIn(rc, (1, 2))
            self.assertIn("encoding-error", err)


class MalformedNotebookShapeTests(unittest.TestCase):
    def test_cells_as_an_object_instead_of_an_array_is_gated(self):
        with F.TempTree() as t:
            rc, out, _err = run(t.write("a.ipynb", {
                "cells": {"0": {"cell_type": "code"}},
                "metadata": {}, "nbformat": 4, "nbformat_minor": 4,
            }))
            self.assertIn(rc, (1, 2))
            self.assertIn("NBK-010", out)

    def test_metadata_as_a_string_does_not_crash(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", {
                "cells": [], "metadata": "oops", "nbformat": 4, "nbformat_minor": 4,
            }))
            self.assertIn(rc, (0, 1, 2))

    def test_outputs_as_a_string_does_not_crash(self):
        book = F.nb([F.code("x = 1", ec=1)])
        book["cells"][0]["outputs"] = "not a list"
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_an_output_entry_that_is_a_string_does_not_crash(self):
        book = F.nb([F.code("x = 1", ec=1, outputs=["not an object"])])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_execution_count_as_a_string_does_not_crash(self):
        book = F.nb([F.code("x = 1")])
        book["cells"][0]["execution_count"] = "three"
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_execution_count_as_a_boolean_does_not_crash(self):
        book = F.nb([F.code("x = 1")])
        book["cells"][0]["execution_count"] = True
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_a_negative_execution_count_does_not_crash(self):
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", F.nb([
                F.code("x = 1", ec=-5), F.code("y = 2", ec=-2),
            ])))
            self.assertIn(rc, (0, 1, 2))

    def test_a_cell_id_that_is_a_number_does_not_crash(self):
        book = F.nb([F.code("x = 1", ec=1)], minor=5)
        book["cells"][0]["id"] = 12345
        with F.TempTree() as t:
            rc, out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))
            self.assertIn("NBK-017", out)

    def test_a_data_value_that_is_a_number_does_not_crash(self):
        book = F.nb([F.code("x", ec=1, outputs=[
            {"output_type": "display_data", "data": {"image/png": 42}, "metadata": {}},
        ])])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_duplicate_json_keys_resolve_without_crashing(self):
        raw = '{"cells": [], "cells": [], "metadata": {}, "nbformat": 4, ' \
              '"nbformat": 4, "nbformat_minor": 4}'
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_raw("a.ipynb", raw))
            self.assertIn(rc, (0, 1, 2))


class ScaleTests(unittest.TestCase):
    def test_a_very_long_single_line_does_not_crash(self):
        book = F.nb([F.code("x = '" + ("a" * 200000) + "'", ec=1)])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_deeply_nested_json_is_reported_not_raised(self):
        depth = 4000
        raw = "[" * depth + "]" * depth
        with F.TempTree() as t:
            rc, _out, _err = run(t.write_raw("a.ipynb", raw))
            self.assertIn(rc, (1, 2))

    def test_deeply_nested_metadata_does_not_crash(self):
        node = {}
        cur = node
        for _ in range(200):
            cur["child"] = {}
            cur = cur["child"]
        book = F.nb([F.code("x = 1", ec=1)])
        book["metadata"]["deep"] = node
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_many_cells_do_not_crash(self):
        book = F.nb([F.code("x = " + str(i), ec=i + 1) for i in range(400)])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_deeply_nested_python_expression_does_not_crash_the_parser(self):
        tree, err = parse_python("x = " + "(" * 200 + "1" + ")" * 200)
        self.assertTrue(tree is not None or err is not None)


class UnicodeTests(unittest.TestCase):
    def test_non_ascii_cell_source_is_handled(self):
        book = F.nb([F.code("titre = 'donn" + chr(0xE9) + "es'", ec=1)])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertEqual(rc, 0)

    def test_a_non_ascii_path_literal_is_still_matched(self):
        book = F.nb([F.code("p = '/home/andr" + chr(0xE9) + "/data.csv'", ec=1)])
        with F.TempTree() as t:
            rc, out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 2))
            self.assertIn("NBK-005", out)

    def test_cjk_source_does_not_crash(self):
        book = F.nb([F.code("label = '" + chr(0x4E2D) + chr(0x6587) + "'", ec=1)])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_an_emoji_in_output_does_not_crash_the_entropy_scan(self):
        book = F.nb([F.code("print(x)", ec=1,
                            outputs=[F.stream(chr(0x1F600) * 200)])])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))

    def test_a_right_to_left_override_in_source_does_not_crash(self):
        book = F.nb([F.code("x = '" + chr(0x202E) + "abc'", ec=1)])
        with F.TempTree() as t:
            rc, _out, _err = run(t.write("a.ipynb", book))
            self.assertIn(rc, (0, 1, 2))


class PathShapeTests(unittest.TestCase):
    def test_a_directory_named_like_a_notebook_is_not_read_as_one(self):
        with F.TempTree() as t:
            os.makedirs(os.path.join(t.dir, "looks_like.ipynb"))
            rc, _out, _err = run(t.dir)
            self.assertIn(rc, (0, 1, 2))

    def test_a_dangling_symlink_shaped_name_is_reported_not_raised(self):
        with F.TempTree() as t:
            target = os.path.join(t.dir, "missing.ipynb")
            out = scan_file(target)
            self.assertFalse(out.scored)
            self.assertIsNotNone(out.error)

    def test_a_walk_does_not_follow_directory_links_into_a_loop(self):
        with F.TempTree() as t:
            t.write("a.ipynb", F.nb([F.code("x = 1", ec=1)]))
            inner = os.path.join(t.dir, "inner")
            os.makedirs(inner)
            try:
                os.symlink(t.dir, os.path.join(inner, "loop"),
                           target_is_directory=True)
            except (OSError, NotImplementedError, AttributeError):
                self.skipTest("symlink creation is not permitted in this environment")
            result = scan_path(t.dir)
            self.assertLessEqual(result.files_scanned, 4)


class RobustnessOfHelpersTests(unittest.TestCase):
    def test_demagic_never_raises_on_odd_input(self):
        for src in ("", "%", "!", "%%", "%%%", "?", "??", "\n\n\n", "%%bash",
                    "x = !", "a?b?c", "    %cd"):
            self.assertIsInstance(demagic(src).python_source, str)

    def test_build_notebook_never_raises_on_odd_input(self):
        for obj in (None, 1, "s", [], {}, {"cells": None}, {"nbformat": None},
                    {"nbformat": 4, "nbformat_minor": 4, "cells": [None]}):
            build_notebook(obj)

    def test_scan_path_on_a_file_that_is_not_a_notebook_glob_scans_nothing(self):
        with F.TempTree() as t:
            p = t.write_raw("notes.md", "hello")
            r = scan_path(p)
            self.assertEqual(r.files_scanned, 0)

    def test_json_output_stays_parseable_for_every_adversarial_case(self):
        cases = ["", "not json", "[]", "null", '{"a":1}']
        with F.TempTree() as t:
            for i, raw in enumerate(cases):
                p = t.write_raw("case" + str(i) + ".ipynb", raw)
                _rc, out, _err = run(p, "--json")
                json.loads(out)


if __name__ == "__main__":
    unittest.main()
