"""JSONC parser tests."""

from __future__ import annotations

import unittest

from devcontainercheck.parse import load_text, strip_jsonc


class StripJsoncTests(unittest.TestCase):
    def test_line_comment_removed(self):
        src = '{\n  "a": 1 // trailing\n}\n'
        out = strip_jsonc(src)
        self.assertNotIn("//", out)
        self.assertIn('"a": 1', out)

    def test_block_comment_removed(self):
        src = '{\n  /* leading */\n  "a": 1\n}\n'
        out = strip_jsonc(src)
        self.assertNotIn("/*", out)
        self.assertNotIn("*/", out)
        self.assertIn('"a": 1', out)

    def test_trailing_comma_removed(self):
        src = '{\n  "a": 1,\n  "b": [1, 2, 3,],\n}\n'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertEqual(doc, {"a": 1, "b": [1, 2, 3]})

    def test_comment_marker_inside_string_preserved(self):
        src = '{"a": "https://example.com/*wild*/path"}'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertEqual(doc["a"], "https://example.com/*wild*/path")

    def test_double_slash_inside_string_preserved(self):
        src = '{"a": "https://x.y//z"}'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertEqual(doc["a"], "https://x.y//z")

    def test_escaped_quote_in_string(self):
        src = r'{"a": "he said \"hi // not a comment\""}'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertIn("// not a comment", doc["a"])

    def test_block_comment_newlines_preserved(self):
        src = '{\n  /* line1\nline2 */ "a": 1\n}'
        out = strip_jsonc(src)
        # Each newline in the comment preserved so downstream line
        # numbers still align.
        self.assertEqual(out.count("\n"), src.count("\n"))

    def test_invalid_json_reports_error(self):
        src = '{"a": 1,,}'  # stray second comma not a trailing comma
        _doc, err = load_text(src, "test")
        self.assertIsNotNone(err)
        self.assertIn("invalid JSON", err)


class LoadTextTests(unittest.TestCase):
    def test_plain_json(self):
        src = '{"name": "x"}'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertEqual(doc, {"name": "x"})

    def test_jsonc_with_line_comment_at_top(self):
        src = '// a comment\n{"name": "x"}'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertEqual(doc, {"name": "x"})

    def test_jsonc_with_trailing_comma_in_array(self):
        src = '{"a": [1, 2, 3,]}'
        doc, err = load_text(src, "test")
        self.assertIsNone(err)
        self.assertEqual(doc, {"a": [1, 2, 3]})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
