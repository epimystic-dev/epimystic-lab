"""Tests for mcpservercheck.parse."""

import unittest

from mcpservercheck.parse import (
    BOM,
    find_key_line_col,
    find_value_line_col,
    iter_jsonl,
    load_json_or_none,
    offset_to_line_col,
    short,
    strip_bom,
)


class OffsetToLineColTests(unittest.TestCase):
    def test_start(self):
        self.assertEqual(offset_to_line_col("abc\ndef", 0), (1, 1))

    def test_within_first_line(self):
        self.assertEqual(offset_to_line_col("abc\ndef", 2), (1, 3))

    def test_second_line_first_col(self):
        self.assertEqual(offset_to_line_col("abc\ndef", 4), (2, 1))

    def test_second_line_second_col(self):
        self.assertEqual(offset_to_line_col("abc\ndef", 5), (2, 2))

    def test_third_line(self):
        self.assertEqual(offset_to_line_col("a\nb\nc", 4), (3, 1))

    def test_negative_clamped(self):
        self.assertEqual(offset_to_line_col("abc", -5), (1, 1))

    def test_overflow_clamped(self):
        self.assertEqual(offset_to_line_col("ab", 99), (1, 3))


class FindKeyLineColTests(unittest.TestCase):
    def test_top_key(self):
        text = '{\n  "alpha": 1,\n  "beta": 2\n}'
        line, col = find_key_line_col(text, "beta")
        self.assertEqual(line, 3)
        self.assertGreaterEqual(col, 3)

    def test_missing_key_returns_1_1(self):
        self.assertEqual(find_key_line_col('{"a": 1}', "missing"), (1, 1))

    def test_from_offset_skips_first(self):
        text = '"x" ... "x"'
        line1, _ = find_key_line_col(text, "x", from_offset=4)
        self.assertEqual(line1, 1)

    def test_none_key_returns_1_1(self):
        self.assertEqual(find_key_line_col("x", None), (1, 1))


class FindValueLineColTests(unittest.TestCase):
    def test_finds_value(self):
        text = '{"k": "abc"}'
        line, _ = find_value_line_col(text, '"abc"')
        self.assertEqual(line, 1)

    def test_missing_value_returns_1_1(self):
        self.assertEqual(find_value_line_col("x", "z"), (1, 1))

    def test_empty_returns_1_1(self):
        self.assertEqual(find_value_line_col("x", ""), (1, 1))


class StripBomTests(unittest.TestCase):
    def test_present(self):
        self.assertEqual(strip_bom(BOM + "hi"), "hi")

    def test_absent(self):
        self.assertEqual(strip_bom("hi"), "hi")


class LoadJsonOrNoneTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(load_json_or_none('{"a": 1}'), {"a": 1})

    def test_invalid_returns_none(self):
        self.assertIsNone(load_json_or_none("{not-json"))

    def test_bom_prefix_ok(self):
        self.assertEqual(load_json_or_none(BOM + '{"a": 1}'), {"a": 1})


class IterJsonlTests(unittest.TestCase):
    def test_multi_line(self):
        text = '{"a":1}\n{"b":2}\n'
        out = list(iter_jsonl(text))
        self.assertEqual(out, [(1, {"a": 1}), (2, {"b": 2})])

    def test_blank_lines_skipped(self):
        text = '{"a":1}\n\n{"b":2}\n'
        out = list(iter_jsonl(text))
        self.assertEqual(out, [(1, {"a": 1}), (3, {"b": 2})])

    def test_invalid_line_skipped(self):
        text = '{"a":1}\nnot-json\n{"b":2}\n'
        out = list(iter_jsonl(text))
        self.assertEqual([o[1] for o in out], [{"a": 1}, {"b": 2}])


class ShortTests(unittest.TestCase):
    def test_none(self):
        self.assertEqual(short(None), "")

    def test_no_truncation(self):
        self.assertEqual(short("abc"), "abc")

    def test_truncates_with_ellipsis(self):
        s = "a" * 200
        out = short(s, limit=50)
        self.assertEqual(len(out), 50)
        self.assertTrue(out.endswith("..."))

    def test_flattens_newlines(self):
        self.assertEqual(short("a\nb\tc\rd"), "a b c d")


if __name__ == "__main__":
    unittest.main()
