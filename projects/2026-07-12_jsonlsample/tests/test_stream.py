import unittest

from jsonlsample.stream import (
    MISSING,
    ParseErrorRecord,
    iter_jsonl,
    path_missing,
    resolve_path,
)


class TestIterJsonl(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(list(iter_jsonl([])), [])

    def test_valid_records(self):
        out = list(iter_jsonl(['{"a": 1}', '{"b": 2}']))
        self.assertEqual(out, [(1, {"a": 1}), (2, {"b": 2})])

    def test_blank_lines_skipped(self):
        out = list(iter_jsonl(["", '{"a": 1}', "   ", '{"b": 2}', ""]))
        # Line numbers stay aligned to source.
        self.assertEqual([ln for ln, _ in out], [2, 4])

    def test_malformed_line_yields_parse_error(self):
        out = list(iter_jsonl(['{"a": 1}', "not json", '{"b": 2}']))
        self.assertEqual(len(out), 3)
        _, mid = out[1]
        self.assertIsInstance(mid, ParseErrorRecord)
        self.assertEqual(mid.line_number, 2)

    def test_supports_all_json_scalars(self):
        out = [item for _, item in iter_jsonl(["1", '"s"', "true", "null", "3.14"])]
        self.assertEqual(out, [1, "s", True, None, 3.14])


class TestResolvePath(unittest.TestCase):
    def test_empty_path_returns_record(self):
        self.assertEqual(resolve_path({"a": 1}, ""), {"a": 1})

    def test_single_key(self):
        self.assertEqual(resolve_path({"a": 1}, "a"), 1)

    def test_nested_key(self):
        self.assertEqual(resolve_path({"a": {"b": {"c": 42}}}, "a.b.c"), 42)

    def test_missing_key_returns_missing_sentinel(self):
        self.assertIs(resolve_path({"a": 1}, "b"), MISSING)

    def test_missing_nested_key(self):
        self.assertIs(resolve_path({"a": {}}, "a.b"), MISSING)

    def test_list_index(self):
        self.assertEqual(resolve_path({"xs": [10, 20, 30]}, "xs.1"), 20)

    def test_list_out_of_range(self):
        self.assertIs(resolve_path({"xs": [10]}, "xs.5"), MISSING)

    def test_list_index_non_integer_segment_missing(self):
        self.assertIs(resolve_path({"xs": [10]}, "xs.first"), MISSING)

    def test_non_container_traversal_missing(self):
        self.assertIs(resolve_path({"a": 5}, "a.b"), MISSING)

    def test_escaped_dot_in_key(self):
        self.assertEqual(resolve_path({"a.b": 1}, "a\\.b"), 1)

    def test_path_missing_predicate(self):
        self.assertTrue(path_missing(MISSING))
        self.assertFalse(path_missing(None))
        self.assertFalse(path_missing(0))
        self.assertFalse(path_missing(""))


if __name__ == "__main__":
    unittest.main()
