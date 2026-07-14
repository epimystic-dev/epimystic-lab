"""Parser tests for envcheck."""

import unittest

from envcheck.core import parse_bytes


def _codes(diags):
    return [d.code for d in diags]


class BasicParsing(unittest.TestCase):
    def test_empty_input(self):
        r = parse_bytes(b"")
        self.assertEqual(r.entries, [])
        self.assertEqual(r.diagnostics, [])

    def test_simple_key_value(self):
        r = parse_bytes(b"FOO=bar\n")
        self.assertEqual(r.entries, [("FOO", "bar", 1)])
        self.assertEqual(r.diagnostics, [])

    def test_multiple_entries_track_lines(self):
        r = parse_bytes(b"A=1\nB=2\nC=3\n")
        self.assertEqual([e[2] for e in r.entries], [1, 2, 3])
        self.assertEqual(r.as_dict(), {"A": "1", "B": "2", "C": "3"})

    def test_blank_lines_and_comments_ignored(self):
        r = parse_bytes(b"# comment\n\nFOO=bar\n   # indented comment\n")
        self.assertEqual(r.entries, [("FOO", "bar", 3)])
        self.assertEqual(r.diagnostics, [])

    def test_empty_value(self):
        r = parse_bytes(b"FOO=\n")
        self.assertEqual(r.entries, [("FOO", "", 1)])
        self.assertEqual(r.diagnostics, [])

    def test_key_case_and_underscore(self):
        r = parse_bytes(b"_a1=x\nFoo_Bar=y\n")
        self.assertEqual(r.as_dict(), {"_a1": "x", "Foo_Bar": "y"})

    def test_export_prefix_stripped(self):
        r = parse_bytes(b"export FOO=bar\n")
        self.assertEqual(r.entries, [("FOO", "bar", 1)])
        self.assertEqual(r.diagnostics, [])


class Quoting(unittest.TestCase):
    def test_double_quoted_value_preserved(self):
        r = parse_bytes(b'FOO="hello world"\n')
        self.assertEqual(r.entries, [("FOO", "hello world", 1)])

    def test_single_quoted_value_preserved(self):
        r = parse_bytes(b"FOO='hello world'\n")
        self.assertEqual(r.entries, [("FOO", "hello world", 1)])

    def test_double_quotes_allow_single(self):
        r = parse_bytes(b'FOO="it\'s ok"\n')
        self.assertEqual(r.entries, [("FOO", "it's ok", 1)])

    def test_unclosed_quote_flagged(self):
        r = parse_bytes(b'FOO="unterminated\n')
        self.assertIn("E006", _codes(r.diagnostics))

    def test_trailing_comment_after_close(self):
        r = parse_bytes(b'FOO="v" # trailing\n')
        self.assertEqual(r.entries[0][1], "v")
        self.assertEqual(r.diagnostics, [])

    def test_content_after_close_quote_flagged(self):
        r = parse_bytes(b'FOO="v" garbage\n')
        self.assertIn("E001", _codes(r.diagnostics))


class InlineComments(unittest.TestCase):
    def test_inline_comment_stripped_from_unquoted(self):
        r = parse_bytes(b"FOO=bar # a comment\n")
        self.assertEqual(r.entries[0][1], "bar")

    def test_hash_without_leading_space_is_part_of_value(self):
        r = parse_bytes(b"COLOR=#ff00cc\n")
        self.assertEqual(r.entries[0][1], "#ff00cc")


class WhitespaceIssues(unittest.TestCase):
    def test_unquoted_spaces_flagged(self):
        r = parse_bytes(b"FOO=hello world\n")
        self.assertIn("E005", _codes(r.diagnostics))

    def test_quoted_spaces_clean(self):
        r = parse_bytes(b'FOO="hello world"\n')
        self.assertEqual(r.diagnostics, [])


class Errors(unittest.TestCase):
    def test_line_without_equals_flagged(self):
        r = parse_bytes(b"NOTANASSIGNMENT\n")
        self.assertIn("E001", _codes(r.diagnostics))

    def test_empty_key_flagged(self):
        r = parse_bytes(b"=oops\n")
        self.assertIn("E002", _codes(r.diagnostics))

    def test_invalid_key_flagged(self):
        r = parse_bytes(b"1FOO=bar\n")
        self.assertIn("E003", _codes(r.diagnostics))

    def test_key_with_dash_flagged(self):
        r = parse_bytes(b"foo-bar=baz\n")
        self.assertIn("E003", _codes(r.diagnostics))

    def test_duplicate_key_flagged(self):
        r = parse_bytes(b"A=1\nA=2\n")
        codes = _codes(r.diagnostics)
        self.assertIn("E004", codes)
        self.assertEqual(r.as_dict()["A"], "2")


class FileWideIssues(unittest.TestCase):
    def test_bom_detected(self):
        r = parse_bytes(b"\xef\xbb\xbfFOO=bar\n")
        self.assertTrue(r.had_bom)
        self.assertIn("E008", _codes(r.diagnostics))
        # BOM stripped: value parses.
        self.assertEqual(r.entries, [("FOO", "bar", 1)])

    def test_crlf_detected(self):
        r = parse_bytes(b"FOO=bar\r\n")
        self.assertTrue(r.had_crlf)
        self.assertIn("E007", _codes(r.diagnostics))
        self.assertEqual(r.entries, [("FOO", "bar", 1)])

    def test_non_utf8_bytes_flagged(self):
        r = parse_bytes(b"FOO=\xff\xfe\n")
        self.assertIn("E009", _codes(r.diagnostics))


class LineColumns(unittest.TestCase):
    def test_line_numbers_are_one_indexed(self):
        r = parse_bytes(b"\n\nFOO=bar\n")
        self.assertEqual(r.entries[0][2], 3)

    def test_duplicate_reports_first_line(self):
        r = parse_bytes(b"A=1\nA=2\n")
        dup = [d for d in r.diagnostics if d.code == "E004"][0]
        self.assertEqual(dup.line, 2)
        self.assertIn("line 1", dup.message)


if __name__ == "__main__":
    unittest.main()
