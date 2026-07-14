"""Tests for ``jsonldiff.diff_records`` -- the structural core."""

import unittest

from jsonldiff.core import diff_records


def kinds(changes):
    return [c.kind for c in changes]


def paths(changes):
    return [c.path for c in changes]


class Equal(unittest.TestCase):
    def test_identical_dicts_no_change(self):
        self.assertEqual(diff_records({"a": 1}, {"a": 1}), [])

    def test_identical_nested(self):
        r = {"a": {"b": [1, 2, {"c": True}]}}
        self.assertEqual(diff_records(r, r), [])

    def test_int_vs_float_equal(self):
        self.assertEqual(diff_records({"n": 1}, {"n": 1.0}), [])

    def test_empty_dicts_no_change(self):
        self.assertEqual(diff_records({}, {}), [])

    def test_none_equal(self):
        self.assertEqual(diff_records({"a": None}, {"a": None}), [])


class Scalars(unittest.TestCase):
    def test_scalar_change(self):
        c = diff_records({"a": 1}, {"a": 2})
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].kind, "changed")
        self.assertEqual(c[0].path, "a")
        self.assertEqual((c[0].baseline, c[0].candidate), (1, 2))

    def test_bool_and_int_are_distinct(self):
        c = diff_records({"a": True}, {"a": 1})
        self.assertEqual(kinds(c), ["changed"])

    def test_string_vs_number_change(self):
        c = diff_records({"a": "1"}, {"a": 1})
        self.assertEqual(kinds(c), ["changed"])

    def test_null_to_value(self):
        c = diff_records({"a": None}, {"a": 0})
        self.assertEqual(kinds(c), ["changed"])


class DictAddRemove(unittest.TestCase):
    def test_added_key(self):
        c = diff_records({"a": 1}, {"a": 1, "b": 2})
        self.assertEqual(kinds(c), ["added"])
        self.assertEqual(c[0].path, "b")
        self.assertEqual(c[0].candidate, 2)

    def test_removed_key(self):
        c = diff_records({"a": 1, "b": 2}, {"a": 1})
        self.assertEqual(kinds(c), ["removed"])
        self.assertEqual(c[0].path, "b")

    def test_added_and_removed_reported_together(self):
        c = diff_records({"a": 1, "b": 2}, {"a": 1, "c": 3})
        got = {(x.kind, x.path) for x in c}
        self.assertEqual(got, {("removed", "b"), ("added", "c")})


class Nested(unittest.TestCase):
    def test_nested_scalar_change_path(self):
        c = diff_records({"a": {"b": {"c": 1}}}, {"a": {"b": {"c": 2}}})
        self.assertEqual(c[0].path, "a.b.c")
        self.assertEqual(c[0].kind, "changed")

    def test_nested_added(self):
        c = diff_records({"a": {"b": 1}}, {"a": {"b": 1, "c": 2}})
        self.assertEqual(c[0].path, "a.c")
        self.assertEqual(c[0].kind, "added")


class Lists(unittest.TestCase):
    def test_positional_scalar_diff(self):
        c = diff_records({"a": [1, 2, 3]}, {"a": [1, 9, 3]})
        self.assertEqual(kinds(c), ["changed"])
        self.assertEqual(c[0].path, "a.1")

    def test_list_extra_element_flagged_added(self):
        c = diff_records({"a": [1]}, {"a": [1, 2]})
        self.assertEqual(kinds(c), ["added"])
        self.assertEqual(c[0].path, "a.1")

    def test_list_missing_element_flagged_removed(self):
        c = diff_records({"a": [1, 2]}, {"a": [1]})
        self.assertEqual(kinds(c), ["removed"])
        self.assertEqual(c[0].path, "a.1")

    def test_nested_list_dict_diff(self):
        c = diff_records({"a": [{"x": 1}]}, {"a": [{"x": 2}]})
        self.assertEqual(c[0].path, "a.0.x")


class TypeMismatch(unittest.TestCase):
    def test_dict_vs_list(self):
        c = diff_records({"a": {}}, {"a": []})
        self.assertEqual(kinds(c), ["changed"])
        self.assertEqual(c[0].path, "a")

    def test_dict_vs_scalar(self):
        c = diff_records({"a": {"b": 1}}, {"a": "hello"})
        self.assertEqual(kinds(c), ["changed"])
        self.assertEqual(c[0].path, "a")

    def test_list_vs_scalar(self):
        c = diff_records({"a": [1]}, {"a": 1})
        self.assertEqual(kinds(c), ["changed"])
        self.assertEqual(c[0].path, "a")


class Ignore(unittest.TestCase):
    def test_exact_ignore(self):
        c = diff_records({"a": 1, "b": 2}, {"a": 1, "b": 3}, ignore=["b"])
        self.assertEqual(c, [])

    def test_prefix_ignore(self):
        c = diff_records({"m": {"acc": 1}}, {"m": {"acc": 2}}, ignore=["m"])
        self.assertEqual(c, [])

    def test_ignore_only_matches_segment_boundary(self):
        # 'metric' should not swallow 'metrics.acc'.
        c = diff_records(
            {"metrics": {"acc": 1}}, {"metrics": {"acc": 2}}, ignore=["metric"]
        )
        self.assertEqual(len(c), 1)


if __name__ == "__main__":
    unittest.main()
