import io
import os
import tempfile
import unittest

from pjhookcheck import parse as P

from tests import support  # noqa: F401  (import for the tempdir redirect)


class TestOffsetToLineCol(unittest.TestCase):
    def test_zero_is_line_1_col_1(self):
        self.assertEqual(P.offset_to_line_col("hello\nworld", 0), (1, 1))

    def test_within_first_line(self):
        self.assertEqual(P.offset_to_line_col("abcdef", 3), (1, 4))

    def test_after_newline(self):
        self.assertEqual(P.offset_to_line_col("abc\nxy", 4), (2, 1))
        self.assertEqual(P.offset_to_line_col("abc\nxy", 5), (2, 2))

    def test_negative(self):
        self.assertEqual(P.offset_to_line_col("abc", -1), (1, 1))

    def test_overflow_collapses(self):
        text = "abc\nxy"
        line, col = P.offset_to_line_col(text, 999)
        self.assertEqual(line, 2)
        self.assertEqual(col, 3)  # end of second line

    def test_empty_text(self):
        self.assertEqual(P.offset_to_line_col("", 0), (1, 1))
        self.assertEqual(P.offset_to_line_col("", 5), (1, 1))


class TestFindKey(unittest.TestCase):
    def test_finds(self):
        text = '{"scripts": {"install": "x"}}'
        i = P.find_key(text, "scripts")
        self.assertEqual(i, 1)

    def test_missing_returns_minus_one(self):
        self.assertEqual(P.find_key('{}', "scripts"), -1)

    def test_from_offset(self):
        text = '{"a": 1, "a": 2}'
        first = P.find_key(text, "a")
        second = P.find_key(text, "a", from_offset=first + 1)
        self.assertGreater(second, first)


class TestFindStringValue(unittest.TestCase):
    def test_finds(self):
        text = '{"k": "hello"}'
        self.assertGreater(P.find_string_value(text, "hello"), 0)

    def test_empty(self):
        self.assertEqual(P.find_string_value("", ""), -1)


class TestTruncateSnippet(unittest.TestCase):
    def test_short_unchanged(self):
        self.assertEqual(P.truncate_snippet("abc"), "abc")

    def test_long_truncated(self):
        s = "a" * 500
        out = P.truncate_snippet(s, limit=160)
        self.assertTrue(out.endswith("..."))
        self.assertLessEqual(len(out), 200)

    def test_newlines_flattened(self):
        self.assertEqual(P.truncate_snippet("a\nb\rc"), "a b c")


class TestReadText(unittest.TestCase):
    def _write(self, data: bytes) -> str:
        fd, p = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_utf8_no_bom(self):
        p = self._write(b'{"a":1}')
        self.assertEqual(P.read_text(p, 100), '{"a":1}')

    def test_utf8_with_bom_stripped(self):
        p = self._write(b'\xef\xbb\xbf{"a":1}')
        self.assertEqual(P.read_text(p, 100), '{"a":1}')

    def test_latin1_fallback(self):
        # 0xff is invalid UTF-8; latin-1 decodes any byte.
        p = self._write(b'{"k": "\xffbad"}')
        out = P.read_text(p, 100)
        self.assertIn("bad", out)

    def test_max_bytes_truncates(self):
        p = self._write(b"x" * 10000)
        out = P.read_text(p, 100)
        self.assertEqual(len(out), 100)


class TestLoadJson(unittest.TestCase):
    def test_valid(self):
        doc, err = P.load_json('{"a": 1}')
        self.assertIsNone(err)
        self.assertEqual(doc, {"a": 1})

    def test_invalid(self):
        doc, err = P.load_json('{"a":')
        self.assertIsNone(doc)
        self.assertIsNotNone(err)
        self.assertIn("json decode error", err)


class TestHelpers(unittest.TestCase):
    def test_is_object(self):
        self.assertTrue(P.is_object({}))
        self.assertFalse(P.is_object([]))
        self.assertFalse(P.is_object("s"))

    def test_get_object(self):
        self.assertEqual(P.get_object({"a": {"x": 1}}, "a"), {"x": 1})
        self.assertEqual(P.get_object({"a": "s"}, "a"), {})
        self.assertEqual(P.get_object({}, "a"), {})

    def test_iter_dependency_sections_order(self):
        doc = {
            "peerDependencies": {"a": "1"},
            "dependencies": {"b": "2"},
            "devDependencies": {"c": "3"},
            "optionalDependencies": {"d": "4"},
        }
        sections = [name for name, _v in P.iter_dependency_sections(doc)]
        self.assertEqual(
            sections,
            ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"],
        )

    def test_iter_dependency_sections_skips_non_objects(self):
        doc = {"dependencies": []}
        self.assertEqual(P.iter_dependency_sections(doc), [])

    def test_iter_lifecycle_hooks(self):
        doc = {"scripts": {"preinstall": "x", "postinstall": "y", "test": "z"}}
        hooks = P.iter_lifecycle_hooks(doc)
        names = [h for h, _ in hooks]
        self.assertIn("preinstall", names)
        self.assertIn("postinstall", names)
        self.assertNotIn("test", names)

    def test_iter_lifecycle_hooks_skips_non_string_values(self):
        doc = {"scripts": {"preinstall": ["arr"], "install": 42, "postinstall": "ok"}}
        hooks = P.iter_lifecycle_hooks(doc)
        self.assertEqual(hooks, [("postinstall", "ok")])


class TestBomConstant(unittest.TestCase):
    def test_bom_is_single_char(self):
        self.assertEqual(len(P.BOM), 1)
        self.assertEqual(P.BOM, "\ufeff")


if __name__ == "__main__":
    unittest.main()
