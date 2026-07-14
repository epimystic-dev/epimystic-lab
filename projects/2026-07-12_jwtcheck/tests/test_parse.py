import unittest

from jwtcheck.parse import parse_env


class TestParseEnv(unittest.TestCase):
    def test_empty_input(self):
        entries, errors = parse_env([])
        self.assertEqual(entries, [])
        self.assertEqual(errors, [])

    def test_simple_key_value(self):
        entries, errors = parse_env(["FOO=bar"])
        self.assertEqual(errors, [])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].key, "FOO")
        self.assertEqual(entries[0].value, "bar")
        self.assertEqual(entries[0].line, 1)
        self.assertEqual(entries[0].col, 1)
        self.assertFalse(entries[0].quoted)

    def test_comment_lines_ignored(self):
        entries, errors = parse_env(["# a comment", "  # indented", "FOO=bar"])
        self.assertEqual(errors, [])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].line, 3)

    def test_blank_lines_ignored(self):
        entries, errors = parse_env(["", "   ", "FOO=bar", ""])
        self.assertEqual(errors, [])
        self.assertEqual(len(entries), 1)

    def test_export_prefix(self):
        entries, errors = parse_env(["export FOO=bar"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, "FOO")
        self.assertEqual(entries[0].value, "bar")

    def test_double_quoted_value(self):
        entries, errors = parse_env(['FOO="hello world"'])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].value, "hello world")
        self.assertTrue(entries[0].quoted)

    def test_single_quoted_value(self):
        entries, errors = parse_env(["FOO='hello world'"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].value, "hello world")
        self.assertTrue(entries[0].quoted)

    def test_empty_value(self):
        entries, errors = parse_env(["FOO="])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, "FOO")
        self.assertEqual(entries[0].value, "")

    def test_inline_comment_after_unquoted(self):
        entries, errors = parse_env(["FOO=bar   # inline comment"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].value, "bar")

    def test_hex_color_value_not_a_comment(self):
        # `#` without preceding whitespace inside a value is retained.
        entries, errors = parse_env(["COLOR=#ff00aa"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].value, "#ff00aa")

    def test_empty_value_followed_by_inline_comment(self):
        # `KEY=   # comment` is an empty value with a trailing comment,
        # not a value of `# comment`.
        entries, errors = parse_env(["KEY=   # trailing comment"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, "KEY")
        self.assertEqual(entries[0].value, "")

    def test_unclosed_quote_reports_error(self):
        entries, errors = parse_env(['FOO="hello'])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].line, 1)
        self.assertIn("unclosed", errors[0].message)
        # Value is retained best-effort
        self.assertEqual(entries[0].key, "FOO")

    def test_missing_equals_reports_error(self):
        entries, errors = parse_env(["JUSTAKEY"])
        self.assertEqual(len(errors), 1)
        self.assertIn("missing '='", errors[0].message)
        self.assertEqual(entries, [])

    def test_invalid_identifier_reports_error(self):
        entries, errors = parse_env(["1STARTS_WITH_DIGIT=oops"])
        self.assertEqual(len(errors), 1)
        self.assertIn("invalid identifier", errors[0].message)

    def test_crlf_stripped(self):
        entries, errors = parse_env(["FOO=bar\r\n"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].value, "bar")

    def test_line_numbers_are_1_based(self):
        entries, errors = parse_env(["# c", "FOO=1", "BAR=2"])
        self.assertEqual(entries[0].line, 2)
        self.assertEqual(entries[1].line, 3)

    def test_column_of_key_is_1_when_unindented(self):
        entries, _ = parse_env(["FOO=bar"])
        self.assertEqual(entries[0].col, 1)

    def test_column_of_key_accounts_for_indentation(self):
        entries, _ = parse_env(["   FOO=bar"])
        self.assertEqual(entries[0].col, 4)

    def test_column_of_key_accounts_for_export(self):
        entries, _ = parse_env(["export FOO=bar"])
        # Key sits after `export ` (7 chars).
        self.assertEqual(entries[0].col, 8)

    def test_value_after_spaces_around_equals(self):
        entries, errors = parse_env(["FOO =  bar"])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, "FOO")
        self.assertEqual(entries[0].value, "bar")


if __name__ == "__main__":
    unittest.main()
