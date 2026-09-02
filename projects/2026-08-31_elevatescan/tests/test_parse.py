import unittest

from elevatescan.rules import _line_col, _short


class TestLineCol(unittest.TestCase):
    def test_offset_zero_is_line_1_col_1(self):
        self.assertEqual(_line_col("abc", 0), (1, 1))

    def test_negative_offset_treated_as_start(self):
        self.assertEqual(_line_col("abc", -5), (1, 1))

    def test_second_line_first_col(self):
        text = "abc\nxyz"
        self.assertEqual(_line_col(text, 4), (2, 1))

    def test_second_line_second_col(self):
        text = "abc\nxyz"
        self.assertEqual(_line_col(text, 5), (2, 2))

    def test_column_within_first_line(self):
        text = "abcdef"
        self.assertEqual(_line_col(text, 3), (1, 4))

    def test_column_after_windows_style_newline_counts_lf_only(self):
        text = "a\r\nb"
        self.assertEqual(_line_col(text, 3), (2, 1))

    def test_multiline_deeper(self):
        text = "one\ntwo\nthree\nfour"
        self.assertEqual(_line_col(text, text.index("three")), (3, 1))
        self.assertEqual(_line_col(text, text.index("four")), (4, 1))


class TestShort(unittest.TestCase):
    def test_returns_short_string_unchanged(self):
        self.assertEqual(_short("hello"), "hello")

    def test_truncates_long_string_with_ellipsis(self):
        s = "a" * 200
        out = _short(s, n=40)
        self.assertEqual(len(out), 40)
        self.assertTrue(out.endswith("..."))

    def test_flattens_newlines(self):
        self.assertEqual(_short("a\nb\r\nc"), "a b  c")


if __name__ == "__main__":
    unittest.main()
