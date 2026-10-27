"""Parser tests for renovatelint.parse."""

from __future__ import annotations

import unittest

from renovatelint.parse import load_text, parse_duration_days, strip_jsonc


class StripJSONCTests(unittest.TestCase):
    def test_line_comment_removed(self):
        s = strip_jsonc('{"a": 1} // trailing\n')
        self.assertNotIn("//", s)
        self.assertIn('"a"', s)

    def test_block_comment_removed(self):
        s = strip_jsonc('{/* leading */"a": 1}')
        self.assertNotIn("/*", s)
        self.assertNotIn("*/", s)
        self.assertIn('"a"', s)

    def test_trailing_comma_removed(self):
        s = strip_jsonc('{"a": 1,}')
        self.assertNotIn(",}", s)

    def test_string_with_slash_slash_preserved(self):
        s = strip_jsonc('{"url": "http://example.com/path"}')
        self.assertIn("http://example.com/path", s)

    def test_string_with_block_marker_preserved(self):
        s = strip_jsonc('{"regex": "/* not a comment */"}')
        self.assertIn("/* not a comment */", s)

    def test_escaped_quote_in_string(self):
        s = strip_jsonc('{"a": "he said \\"hi\\""}')
        self.assertIn('he said', s)


class LoadTextTests(unittest.TestCase):
    def test_valid_renovate_json(self):
        doc, err = load_text('{"enabled": true}', "renovate.json")
        self.assertIsNone(err)
        self.assertEqual(doc, {"enabled": True})

    def test_invalid_json(self):
        doc, err = load_text("{not json", "renovate.json")
        self.assertIsNone(doc)
        self.assertIsNotNone(err)
        self.assertIn("line", err)
        self.assertIn("column", err)

    def test_package_json_with_renovate_key(self):
        doc, err = load_text(
            '{"name": "pkg", "renovate": {"automerge": true}}',
            "package.json",
        )
        self.assertIsNone(err)
        self.assertEqual(doc, {"automerge": True})

    def test_package_json_without_renovate_key(self):
        doc, err = load_text('{"name": "pkg"}', "package.json")
        self.assertIsNone(doc)
        self.assertIn("no top-level 'renovate' object", err)

    def test_jsonc_comments_in_renovate_file(self):
        doc, err = load_text(
            '{\n'
            '  // enable renovate\n'
            '  "enabled": true,\n'
            '}\n',
            "renovate.json",
        )
        self.assertIsNone(err)
        self.assertEqual(doc, {"enabled": True})


class ParseDurationDaysTests(unittest.TestCase):
    def test_days_phrase(self):
        self.assertEqual(parse_duration_days("14 days"), 14.0)
        self.assertEqual(parse_duration_days("1 day"), 1.0)

    def test_weeks_phrase(self):
        self.assertEqual(parse_duration_days("2 weeks"), 14.0)

    def test_hours_phrase(self):
        self.assertAlmostEqual(parse_duration_days("12 hours"), 0.5)

    def test_compact_d_suffix(self):
        self.assertEqual(parse_duration_days("14d"), 14.0)

    def test_compact_hour_suffix(self):
        self.assertAlmostEqual(parse_duration_days("72h"), 3.0)

    def test_compact_week_suffix(self):
        self.assertEqual(parse_duration_days("2w"), 14.0)

    def test_rejects_non_string(self):
        self.assertIsNone(parse_duration_days(14))
        self.assertIsNone(parse_duration_days(None))

    def test_rejects_unknown_unit(self):
        self.assertIsNone(parse_duration_days("14 fortnights"))

    def test_rejects_garbage(self):
        self.assertIsNone(parse_duration_days("someday"))
        self.assertIsNone(parse_duration_days(""))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
