import unittest

from delegcheck.parse import (
    find_key_line_col,
    find_value_line_col,
    iter_jsonl,
    load_json_or_none,
    offset_to_line_col,
    short,
    strip_bom,
)


class TestOffsetToLineCol(unittest.TestCase):

    def test_start(self):
        self.assertEqual(offset_to_line_col("hello", 0), (1, 1))

    def test_within_first_line(self):
        self.assertEqual(offset_to_line_col("hello", 3), (1, 4))

    def test_second_line_first_col(self):
        self.assertEqual(offset_to_line_col("ab\ncd", 3), (2, 1))

    def test_second_line_second_col(self):
        self.assertEqual(offset_to_line_col("ab\ncd", 4), (2, 2))

    def test_multiline_deeper(self):
        self.assertEqual(offset_to_line_col("a\nb\nc\nd", 6), (4, 1))

    def test_negative_clamped(self):
        self.assertEqual(offset_to_line_col("abc", -5), (1, 1))

    def test_overflow_clamped(self):
        self.assertEqual(offset_to_line_col("abc", 100), (1, 4))


class TestFindKey(unittest.TestCase):

    def test_finds_top_key(self):
        text = '{\n  "credentials": []\n}\n'
        self.assertEqual(find_key_line_col(text, "credentials"), (2, 3))

    def test_missing_returns_1_1(self):
        self.assertEqual(find_key_line_col('{"x": 1}', "credentials"), (1, 1))

    def test_from_offset_skips_first(self):
        text = '"a"\n{"a": 1}\n'
        self.assertEqual(find_key_line_col(text, "a", from_offset=4), (2, 2))


class TestFindValue(unittest.TestCase):

    def test_finds_value_literal(self):
        text = '{"scope": "*"}'
        line, col = find_value_line_col(text, '"*"')
        self.assertEqual(line, 1)
        self.assertGreater(col, 1)

    def test_missing_returns_1_1(self):
        self.assertEqual(find_value_line_col('{"x":1}', '"missing-literal"'), (1, 1))


class TestStripBOM(unittest.TestCase):

    def test_strip_bom_present(self):
        self.assertEqual(strip_bom("\ufeffhello"), "hello")

    def test_no_bom_unchanged(self):
        self.assertEqual(strip_bom("hello"), "hello")


class TestLoadJson(unittest.TestCase):

    def test_valid(self):
        self.assertEqual(load_json_or_none('{"a": 1}'), {"a": 1})

    def test_invalid_returns_none(self):
        self.assertIsNone(load_json_or_none("not json"))

    def test_bom_prefix_ok(self):
        self.assertEqual(load_json_or_none('\ufeff{"a": 1}'), {"a": 1})


class TestIterJsonl(unittest.TestCase):

    def test_multi_line(self):
        text = '{"a": 1}\n{"a": 2}\n'
        got = list(iter_jsonl(text))
        self.assertEqual(got, [(1, {"a": 1}), (2, {"a": 2})])

    def test_blank_lines_skipped(self):
        text = '{"a": 1}\n\n{"a": 2}\n'
        got = list(iter_jsonl(text))
        self.assertEqual(got, [(1, {"a": 1}), (3, {"a": 2})])

    def test_invalid_line_skipped(self):
        text = '{"a": 1}\nbad\n{"a": 3}\n'
        got = list(iter_jsonl(text))
        self.assertEqual(got, [(1, {"a": 1}), (3, {"a": 3})])


class TestShort(unittest.TestCase):

    def test_none(self):
        self.assertEqual(short(None), "")

    def test_no_truncation(self):
        self.assertEqual(short("hello"), "hello")

    def test_truncates_with_ellipsis(self):
        s = short("x" * 200, limit=20)
        self.assertEqual(len(s), 20)
        self.assertTrue(s.endswith("..."))

    def test_flattens_newlines(self):
        self.assertEqual(short("a\nb\tc\rd"), "a b c d")


if __name__ == "__main__":
    unittest.main()
