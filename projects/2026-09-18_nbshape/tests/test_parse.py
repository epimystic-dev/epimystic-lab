"""Behaviour of the parsing layer: JSON load, notebook view, de-magicking."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nbfactory as F  # noqa: E402

from nbshape.parse import (  # noqa: E402
    build_notebook,
    demagic,
    load_json_text,
    locate_key,
    locate_literal,
    offset_to_line_col,
    parse_python,
    prepare_cell,
    redact,
    short,
    source_to_str,
    strip_bom,
)


class LoadJsonTests(unittest.TestCase):
    def test_valid_json_object_parses(self):
        obj, err = load_json_text('{"a": 1}')
        self.assertIsNone(err)
        self.assertEqual(obj, {"a": 1})

    def test_empty_text_is_reported_not_raised(self):
        obj, err = load_json_text("")
        self.assertIsNone(obj)
        self.assertIn("empty", err)

    def test_whitespace_only_text_is_reported_as_empty(self):
        obj, err = load_json_text("   \n\t ")
        self.assertIsNone(obj)
        self.assertIn("empty", err)

    def test_malformed_json_is_reported_not_raised(self):
        obj, err = load_json_text('{"a": ')
        self.assertIsNone(obj)
        self.assertIn("not valid JSON", err)

    def test_a_bare_json_array_parses_to_a_list(self):
        obj, err = load_json_text("[1, 2, 3]")
        self.assertIsNone(err)
        self.assertEqual(obj, [1, 2, 3])

    def test_a_byte_order_mark_is_stripped_before_parsing(self):
        obj, err = load_json_text(chr(0xFEFF) + '{"a": 1}')
        self.assertIsNone(err)
        self.assertEqual(obj, {"a": 1})

    def test_strip_bom_leaves_ordinary_text_alone(self):
        self.assertEqual(strip_bom("plain"), "plain")

    def test_duplicate_keys_resolve_to_the_last_value_without_raising(self):
        obj, err = load_json_text('{"nbformat": 3, "nbformat": 4}')
        self.assertIsNone(err)
        self.assertEqual(obj["nbformat"], 4)


class PositionTests(unittest.TestCase):
    def test_offset_zero_is_line_one_column_one(self):
        self.assertEqual(offset_to_line_col("abc", 0), (1, 1))

    def test_offset_after_a_newline_starts_line_two(self):
        self.assertEqual(offset_to_line_col("ab\ncd", 3), (2, 1))

    def test_a_negative_offset_is_clamped_to_the_start(self):
        self.assertEqual(offset_to_line_col("abc", -50), (1, 1))

    def test_an_offset_past_the_end_is_clamped_to_the_end(self):
        line, _col = offset_to_line_col("ab\ncd", 10_000)
        self.assertEqual(line, 2)

    def test_locate_literal_finds_a_json_escaped_source_fragment(self):
        text = '{"source": "x = 1\\ny = 2"}'
        line, col = locate_literal(text, "y = 2")
        self.assertEqual(line, 1)
        self.assertGreater(col, 1)

    def test_locate_literal_returns_one_one_when_absent(self):
        self.assertEqual(locate_literal('{"a": 1}', "nowhere"), (1, 1))

    def test_locate_literal_returns_one_one_for_an_empty_needle(self):
        self.assertEqual(locate_literal('{"a": 1}', ""), (1, 1))

    def test_locate_key_finds_a_quoted_json_key(self):
        line, col = locate_key('{\n  "nbformat": 4\n}', "nbformat")
        self.assertEqual(line, 2)
        self.assertEqual(col, 3)

    def test_locate_key_returns_one_one_when_the_key_is_absent(self):
        self.assertEqual(locate_key('{"a": 1}', "nbformat"), (1, 1))


class ShortAndRedactTests(unittest.TestCase):
    def test_short_collapses_newlines_to_one_line(self):
        self.assertEqual(short("a\nb\tc"), "a b c")

    def test_short_truncates_with_an_ascii_ellipsis(self):
        out = short("x" * 500, limit=20)
        self.assertEqual(len(out), 20)
        self.assertTrue(out.endswith("..."))

    def test_short_of_none_is_the_empty_string(self):
        self.assertEqual(short(None), "")

    def test_redact_never_echoes_the_whole_value(self):
        out = redact("abcdefghijklmnop")
        self.assertNotIn("efghijklmnop", out)
        self.assertIn("16 chars", out)

    def test_redact_of_a_very_short_value_reports_only_the_length(self):
        self.assertEqual(redact("ab"), "<2 chars>")


class SourceNormalisationTests(unittest.TestCase):
    def test_a_string_source_passes_through(self):
        self.assertEqual(source_to_str("x = 1"), "x = 1")

    def test_a_list_source_is_joined_without_adding_separators(self):
        self.assertEqual(source_to_str(["x = 1\n", "y = 2"]), "x = 1\ny = 2")

    def test_a_list_with_non_string_members_drops_them_instead_of_raising(self):
        self.assertEqual(source_to_str(["a", 3, None, "b"]), "ab")

    def test_a_missing_source_becomes_the_empty_string(self):
        self.assertEqual(source_to_str(None), "")


class NotebookGateTests(unittest.TestCase):
    def test_a_well_formed_notebook_passes_the_gate(self):
        view = build_notebook(F.nb([F.code("x = 1", ec=1)]))
        self.assertTrue(view.conformant)
        self.assertIsNone(view.gate_reason)

    def test_a_top_level_list_is_gated(self):
        view = build_notebook([1, 2, 3])
        self.assertFalse(view.conformant)
        self.assertIn("not an object", view.gate_reason)

    def test_a_top_level_string_is_gated(self):
        self.assertFalse(build_notebook("hello").conformant)

    def test_a_missing_nbformat_is_gated(self):
        view = build_notebook({"cells": [], "nbformat_minor": 4})
        self.assertIn("nbformat", view.gate_reason)

    def test_nbformat_three_is_gated(self):
        view = build_notebook({"cells": [], "nbformat": 3, "nbformat_minor": 0})
        self.assertIn("below the version 4", view.gate_reason)

    def test_a_non_integer_nbformat_is_gated(self):
        view = build_notebook({"cells": [], "nbformat": "4", "nbformat_minor": 4})
        self.assertIn("not an integer", view.gate_reason)

    def test_a_boolean_nbformat_is_gated_because_bool_is_not_a_version(self):
        view = build_notebook({"cells": [], "nbformat": True, "nbformat_minor": 4})
        self.assertFalse(view.conformant)

    def test_a_missing_nbformat_minor_is_gated(self):
        view = build_notebook({"cells": [], "nbformat": 4})
        self.assertIn("nbformat_minor", view.gate_reason)

    def test_a_missing_cells_array_is_gated(self):
        view = build_notebook({"nbformat": 4, "nbformat_minor": 4})
        self.assertIn("cells", view.gate_reason)

    def test_a_cell_that_is_not_an_object_is_gated(self):
        view = build_notebook({"cells": ["oops"], "nbformat": 4, "nbformat_minor": 4})
        self.assertIn("cells[0]", view.gate_reason)

    def test_a_cell_without_a_string_cell_type_is_gated(self):
        view = build_notebook(
            {"cells": [{"source": "x"}], "nbformat": 4, "nbformat_minor": 4}
        )
        self.assertIn("cell_type", view.gate_reason)

    def test_a_notebook_with_zero_cells_is_conformant(self):
        self.assertTrue(build_notebook(F.nb([])).conformant)

    def test_language_falls_back_to_kernelspec_when_language_info_is_absent(self):
        view = build_notebook(F.nb([], metadata={"kernelspec": {"language": "python"}}))
        self.assertEqual(view.language(), "python")

    def test_language_is_empty_when_nothing_declares_it(self):
        self.assertEqual(build_notebook(F.nb([], metadata={})).language(), "")

    def test_code_cells_excludes_markdown(self):
        view = build_notebook(F.nb([F.code("x = 1"), F.markdown("hi")]))
        self.assertEqual(len(view.code_cells()), 1)


class DemagicTests(unittest.TestCase):
    def test_plain_python_is_returned_unchanged(self):
        out = demagic("x = 1\ny = 2")
        self.assertEqual(out.python_source, "x = 1\ny = 2")
        self.assertEqual(out.rewritten, 0)

    def test_a_shell_escape_line_becomes_inert_python(self):
        out = demagic("!pip install pandas")
        self.assertEqual(out.python_source, "pass")
        self.assertIsNone(parse_python(out.python_source)[1])

    def test_a_line_magic_becomes_inert_python(self):
        out = demagic("%matplotlib inline\nimport pandas")
        self.assertEqual(out.python_source.split("\n")[0], "pass")

    def test_an_indented_magic_keeps_its_indentation_so_the_block_still_parses(self):
        out = demagic("if True:\n    !echo hi")
        self.assertEqual(out.python_source, "if True:\n    pass")
        self.assertIsNone(parse_python(out.python_source)[1])

    def test_the_help_suffix_is_neutralised(self):
        out = demagic("pandas.DataFrame?")
        self.assertIsNone(parse_python(out.python_source)[1])

    def test_the_double_help_suffix_is_neutralised(self):
        out = demagic("pandas.DataFrame??")
        self.assertIsNone(parse_python(out.python_source)[1])

    def test_an_assignment_from_a_shell_escape_is_neutralised(self):
        out = demagic("files = !ls -la")
        self.assertIsNone(parse_python(out.python_source)[1])

    def test_line_count_is_preserved_so_node_linenos_stay_meaningful(self):
        src = "!echo a\nx = 1\n%cd ..\ny = 2"
        out = demagic(src)
        self.assertEqual(len(out.python_source.split("\n")), len(src.split("\n")))

    def test_a_python_bodied_cell_magic_keeps_its_body(self):
        out = demagic("%%time\ntotal = sum(range(10))")
        self.assertFalse(out.non_python)
        self.assertEqual(out.cell_magic, "time")
        self.assertIn("total = sum", out.python_source)

    def test_a_shell_cell_magic_is_reported_as_non_python(self):
        out = demagic("%%bash\nls -la\necho done")
        self.assertTrue(out.non_python)
        self.assertEqual(out.cell_magic, "bash")

    def test_a_writefile_cell_magic_is_reported_as_non_python(self):
        self.assertTrue(demagic("%%writefile out.txt\nhello").non_python)

    def test_a_non_python_cell_magic_body_still_parses_as_an_empty_module(self):
        out = demagic("%%bash\nthis is not python at all {{{")
        tree, err = parse_python(out.python_source)
        self.assertIsNone(err)
        self.assertIsNotNone(tree)

    def test_a_cell_magic_after_blank_lines_is_still_detected(self):
        self.assertTrue(demagic("\n\n%%bash\nls").non_python)

    def test_empty_source_yields_empty_output(self):
        self.assertEqual(demagic("").python_source, "")

    def test_a_non_string_source_does_not_raise(self):
        self.assertEqual(demagic(None).python_source, "")

    def test_a_percent_inside_a_string_on_a_continuation_line_is_left_alone(self):
        out = demagic('fmt = "%s and %s" % (a, b)')
        self.assertEqual(out.rewritten, 0)


class ParsePythonTests(unittest.TestCase):
    def test_valid_python_returns_a_tree(self):
        tree, err = parse_python("x = 1")
        self.assertIsNotNone(tree)
        self.assertIsNone(err)

    def test_a_syntax_error_is_returned_not_raised(self):
        tree, err = parse_python("def f(\n")
        self.assertIsNone(tree)
        self.assertIn("SyntaxError", err)

    def test_an_embedded_null_byte_is_returned_not_raised(self):
        tree, err = parse_python("x = 1\x00")
        self.assertIsNone(tree)
        self.assertIsNotNone(err)

    def test_a_none_source_is_reported_not_raised(self):
        tree, err = parse_python(None)
        self.assertIsNone(tree)
        self.assertIsNotNone(err)


class PrepareCellTests(unittest.TestCase):
    def _cell(self, source):
        view = build_notebook(F.nb([F.code(source, ec=1)]))
        return prepare_cell(view.cells[0])

    def test_a_plain_cell_has_an_ast(self):
        self.assertTrue(self._cell("x = 1").ast_available)

    def test_a_cell_with_magics_still_has_an_ast(self):
        self.assertTrue(self._cell("!pip install x\nimport os").ast_available)

    def test_a_shell_cell_magic_has_no_ast_and_says_why(self):
        cc = self._cell("%%bash\nls -la")
        self.assertFalse(cc.ast_available)
        self.assertIn("not Python", cc.parse_error)

    def test_a_broken_cell_has_no_ast_and_says_why(self):
        cc = self._cell("def f(\n")
        self.assertFalse(cc.ast_available)
        self.assertIn("SyntaxError", cc.parse_error)

    def test_raw_source_is_preserved_for_textual_rules(self):
        cc = self._cell("%%bash\npip install pandas")
        self.assertIn("pip install pandas", cc.raw_source)


if __name__ == "__main__":
    unittest.main()
