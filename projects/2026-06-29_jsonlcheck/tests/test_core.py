"""Tests for jsonlcheck.core.

Run: ``python -m unittest discover -s tests`` (no external deps)
"""

from __future__ import annotations

import gzip
import io
import os
import tempfile
import unittest

from jsonlcheck import Issue, Options, Severity, check_path, check_stream


def _issues(text: str, **opt_kwargs) -> list[Issue]:
    opts = Options(**opt_kwargs) if opt_kwargs else None
    return list(check_stream(io.StringIO(text), options=opts))


class HappyPath(unittest.TestCase):
    def test_three_valid_objects(self):
        text = '{"a":1}\n{"b":2}\n{"c":3}\n'
        self.assertEqual(_issues(text), [])

    def test_empty_input_is_clean(self):
        self.assertEqual(_issues(""), [])

    def test_mixed_top_level_types_ok_without_homogeneous(self):
        text = '{"a":1}\n[1,2,3]\n"hello"\n42\ntrue\nnull\n'
        self.assertEqual(_issues(text), [])

    def test_unicode_string_value_is_fine(self):
        # raw u-escape, no control char
        text = '{"name":"\\u00e9clair"}\n'
        self.assertEqual(_issues(text), [])

    def test_nested_objects_ok(self):
        text = '{"a":{"b":{"c":[1,2,{"d":null}]}}}\n'
        self.assertEqual(_issues(text), [])


class ParseErrors(unittest.TestCase):
    def test_trailing_comma_is_error(self):
        text = '{"a":1,}\n'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "parse-error")
        self.assertEqual(issues[0].line, 1)
        self.assertIsNotNone(issues[0].column)

    def test_single_quoted_string_is_error(self):
        text = "{'a':1}\n"
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "parse-error")

    def test_unterminated_string_is_error(self):
        text = '{"a":"unterminated\n'
        issues = _issues(text)
        # control char + parse error are both legitimate findings here;
        # confirm parse-error is among them.
        codes = [i.code for i in issues]
        self.assertIn("parse-error", codes)

    def test_error_on_one_line_does_not_stop_subsequent_lines(self):
        text = 'not json\n{"a":1}\nalso not json\n'
        issues = _issues(text)
        # only the bad lines emit issues
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0].line, 1)
        self.assertEqual(issues[1].line, 3)


class BlankLines(unittest.TestCase):
    def test_blank_line_is_flagged_by_default(self):
        text = '{"a":1}\n\n{"b":2}\n'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "blank-line")
        self.assertEqual(issues[0].line, 2)

    def test_blank_line_can_be_allowed(self):
        text = '{"a":1}\n\n{"b":2}\n'
        issues = _issues(text, blank_lines=False)
        self.assertEqual(issues, [])

    def test_whitespace_only_line_is_blank(self):
        text = '{"a":1}\n   \t  \n{"b":2}\n'
        issues = _issues(text)
        codes = [i.code for i in issues]
        self.assertIn("blank-line", codes)


class BomChecks(unittest.TestCase):
    def test_bom_at_start_of_first_line_is_flagged(self):
        text = "﻿" + '{"a":1}\n'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "bom")
        self.assertEqual(issues[0].line, 1)
        self.assertEqual(issues[0].column, 1)

    def test_bom_can_be_disabled(self):
        text = "﻿" + '{"a":1}\n'
        issues = _issues(text, bom=False)
        self.assertEqual(issues, [])

    def test_bom_does_not_stop_parse(self):
        # after we strip the BOM the rest must still parse.
        text = "﻿" + '{"a":1}\n' + '{"b":2}\n'
        issues = _issues(text)
        self.assertEqual([i.code for i in issues], ["bom"])


class NanInf(unittest.TestCase):
    def test_nan_is_flagged_by_default(self):
        text = '{"x":NaN}\n'
        issues = _issues(text)
        codes = [i.code for i in issues]
        self.assertIn("nan-inf", codes)

    def test_infinity_is_flagged_by_default(self):
        text = '{"x":Infinity}\n'
        issues = _issues(text)
        codes = [i.code for i in issues]
        self.assertIn("nan-inf", codes)

    def test_neg_infinity_is_flagged(self):
        text = '{"x":-Infinity}\n'
        issues = _issues(text)
        codes = [i.code for i in issues]
        self.assertIn("nan-inf", codes)

    def test_nan_in_nested_value_is_found(self):
        text = '{"a":[1,2,{"b":NaN}]}\n'
        issues = _issues(text)
        codes = [i.code for i in issues]
        self.assertIn("nan-inf", codes)

    def test_finite_numbers_are_ok(self):
        text = '{"x":1.5, "y":-0.0, "z":1e308}\n'
        issues = _issues(text)
        self.assertEqual(issues, [])

    def test_can_disable_nan_inf_check(self):
        text = '{"x":NaN}\n'
        issues = _issues(text, nan_inf=False)
        self.assertEqual(issues, [])


class DuplicateKeys(unittest.TestCase):
    def test_top_level_duplicate_is_flagged(self):
        text = '{"a":1,"a":2}\n'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "duplicate-key")

    def test_nested_duplicate_is_flagged(self):
        text = '{"outer":{"k":1,"k":2}}\n'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "duplicate-key")

    def test_can_disable(self):
        text = '{"a":1,"a":2}\n'
        issues = _issues(text, duplicate_keys=False)
        self.assertEqual(issues, [])


class ControlChars(unittest.TestCase):
    def test_literal_tab_in_string_is_flagged(self):
        # raw 0x09 inside a JSON string is not legal per RFC 8259
        text = '{"a":"x\ty"}\n'
        issues = _issues(text)
        codes = [i.code for i in issues]
        self.assertIn("control-char", codes)
        cc = next(i for i in issues if i.code == "control-char")
        # column should point at the tab (1-based)
        self.assertEqual(text[cc.column - 1], "\t")

    def test_escaped_tab_is_fine(self):
        text = '{"a":"x\\ty"}\n'
        issues = _issues(text)
        self.assertEqual(issues, [])

    def test_disable_control_chars(self):
        text = '{"a":"x\ty"}\n'
        issues = _issues(text, control_chars=False)
        # parser will accept by default; no findings
        self.assertEqual(issues, [])


class Homogeneous(unittest.TestCase):
    def test_homogeneous_objects_pass(self):
        text = '{"a":1}\n{"b":2}\n{"c":3}\n'
        issues = _issues(text, homogeneous=True)
        self.assertEqual(issues, [])

    def test_mixed_types_flagged(self):
        text = '{"a":1}\n[1,2,3]\n'
        issues = _issues(text, homogeneous=True)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "heterogeneous")
        self.assertEqual(issues[0].line, 2)


class RequiredKeys(unittest.TestCase):
    def test_missing_key_flagged(self):
        text = '{"a":1}\n'
        issues = _issues(text, required_keys=("a", "b"))
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "missing-keys")
        self.assertIn("b", issues[0].message)

    def test_all_present_no_issue(self):
        text = '{"a":1,"b":2}\n'
        issues = _issues(text, required_keys=("a", "b"))
        self.assertEqual(issues, [])

    def test_required_keys_ignored_for_non_objects(self):
        text = '[1,2,3]\n'
        issues = _issues(text, required_keys=("a",))
        self.assertEqual(issues, [])


class FinalNewline(unittest.TestCase):
    def test_missing_trailing_newline_is_warning(self):
        text = '{"a":1}'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "no-final-newline")
        self.assertEqual(issues[0].severity, Severity.WARNING)

    def test_present_trailing_newline_is_clean(self):
        text = '{"a":1}\n'
        self.assertEqual(_issues(text), [])

    def test_crlf_counts_as_newline(self):
        text = '{"a":1}\r\n{"b":2}\r\n'
        self.assertEqual(_issues(text), [])

    def test_empty_file_no_final_newline_warning(self):
        # nothing seen at all → no warning either way
        self.assertEqual(_issues(""), [])


class MaxIssues(unittest.TestCase):
    def test_stops_after_n_issues(self):
        text = "\n\n\n\n\n\n"  # 6 blank lines
        issues = _issues(text, max_issues=2)
        self.assertEqual(len(issues), 2)
        # both blank lines, first two lines reported
        self.assertEqual(issues[0].line, 1)
        self.assertEqual(issues[1].line, 2)


class LineCounting(unittest.TestCase):
    def test_line_numbers_are_1_based(self):
        text = '{"a":1}\nnot json\n{"c":3}\n'
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].line, 2)

    def test_column_reported_for_parse_errors(self):
        text = '{"a":1,"b":}\n'   # syntactically broken
        issues = _issues(text)
        self.assertEqual(len(issues), 1)
        self.assertIsNotNone(issues[0].column)
        self.assertGreaterEqual(issues[0].column, 1)


class PathAndGzip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        for n in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, n))
        os.rmdir(self.tmp)

    def test_check_path_on_plain_file(self):
        p = os.path.join(self.tmp, "x.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"a":1}\n{"b":2}\n')
        self.assertEqual(list(check_path(p)), [])

    def test_check_path_on_gzipped_file(self):
        p = os.path.join(self.tmp, "x.jsonl.gz")
        with gzip.open(p, "wt", encoding="utf-8") as f:
            f.write('{"a":1}\nnope\n')
        issues = list(check_path(p))
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].line, 2)
        self.assertEqual(issues[0].code, "parse-error")


class IssueFormat(unittest.TestCase):
    def test_format_includes_path_line_col_and_code(self):
        i = Issue(line=3, column=7, code="parse-error", message="boom")
        s = i.format("a.jsonl")
        self.assertIn("a.jsonl:3:7", s)
        self.assertIn("[parse-error]", s)
        self.assertIn("boom", s)
        self.assertIn("error", s)

    def test_format_without_column(self):
        i = Issue(line=3, column=None, code="blank-line", message="x")
        s = i.format("a.jsonl")
        self.assertIn("a.jsonl:3:", s)  # no second colon
        # specifically: no ":7:" pattern
        self.assertNotIn("a.jsonl:3:7", s)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
