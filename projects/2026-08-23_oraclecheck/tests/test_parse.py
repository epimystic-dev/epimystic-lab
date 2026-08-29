"""Unit tests for oraclecheck.parse helpers."""

import ast
import unittest

from oraclecheck.parse import (
    call_target_matches,
    contains_call_to_sut,
    contains_reference_to_sut,
    exprs_equal,
    find_prev_assign_to,
    get_call_name,
    get_call_target_module,
    get_dotted_name,
    is_call_to,
    iter_calls,
    literal_bool_value,
    literal_truthy,
    parse_source,
    strip_bom,
    unwrap_await,
)


class TestParseHelpers(unittest.TestCase):

    def test_parse_source_returns_module_on_valid(self):
        m = parse_source("x = 1\n")
        self.assertIsNotNone(m)
        self.assertIsInstance(m, ast.Module)

    def test_parse_source_returns_none_on_syntax_error(self):
        self.assertIsNone(parse_source("def:\n"))

    def test_get_call_name_name_callable(self):
        tree = ast.parse("foo(1)")
        call = tree.body[0].value
        self.assertEqual(get_call_name(call), "foo")

    def test_get_call_name_attribute_callable(self):
        tree = ast.parse("self.assertEqual(a, b)")
        call = tree.body[0].value
        self.assertEqual(get_call_name(call), "assertEqual")

    def test_get_call_name_returns_none_for_non_call(self):
        tree = ast.parse("x")
        name = tree.body[0].value
        self.assertIsNone(get_call_name(name))

    def test_get_dotted_name_name(self):
        tree = ast.parse("x")
        self.assertEqual(get_dotted_name(tree.body[0].value), "x")

    def test_get_dotted_name_attribute_chain(self):
        tree = ast.parse("a.b.c")
        self.assertEqual(get_dotted_name(tree.body[0].value), "a.b.c")

    def test_get_dotted_name_none_for_call(self):
        tree = ast.parse("a.b()")
        # ast.Call is not a Name/Attribute chain root
        self.assertIsNone(get_dotted_name(tree.body[0].value))

    def test_exprs_equal_true_for_same_structure(self):
        a = ast.parse("f(x)").body[0].value
        b = ast.parse("f(x)").body[0].value
        self.assertTrue(exprs_equal(a, b))

    def test_exprs_equal_false_for_different_structure(self):
        a = ast.parse("f(x)").body[0].value
        b = ast.parse("f(y)").body[0].value
        self.assertFalse(exprs_equal(a, b))

    def test_exprs_equal_ignores_source_location(self):
        a = ast.parse("f(x)").body[0].value
        # Manually construct with different offsets
        b = ast.Call(
            func=ast.Name(id="f", ctx=ast.Load()),
            args=[ast.Name(id="x", ctx=ast.Load())],
            keywords=[],
        )
        self.assertTrue(exprs_equal(a, b))

    def test_iter_calls_collects_all(self):
        tree = ast.parse("f(g(x)) + h()\n")
        calls = list(iter_calls(tree))
        names = sorted(get_call_name(c) for c in calls)
        self.assertEqual(names, ["f", "g", "h"])

    def test_iter_calls_empty_when_no_calls(self):
        tree = ast.parse("x = 1\n")
        self.assertEqual(list(iter_calls(tree)), [])

    def test_unwrap_await_removes_await(self):
        tree = ast.parse("async def _():\n await f()\n")
        expr = tree.body[0].body[0].value
        unwrapped = unwrap_await(expr)
        self.assertIsInstance(unwrapped, ast.Call)

    def test_unwrap_await_passthrough_when_not_await(self):
        tree = ast.parse("f()\n")
        expr = tree.body[0].value
        self.assertIs(unwrap_await(expr), expr)

    def test_literal_truthy_matrix(self):
        cases = [
            ("True", True), ("False", False),
            ("1", True), ("0", False),
            ("'x'", True), ("''", False),
            ("None", False),
        ]
        for src, expected in cases:
            with self.subTest(src=src):
                n = ast.parse(src).body[0].value
                self.assertEqual(literal_truthy(n), expected)

    def test_literal_truthy_none_for_dynamic_expr(self):
        n = ast.parse("f(x)").body[0].value
        self.assertIsNone(literal_truthy(n))

    def test_literal_bool_value_only_matches_bool_constant(self):
        self.assertTrue(literal_bool_value(ast.parse("True").body[0].value))
        self.assertFalse(literal_bool_value(ast.parse("False").body[0].value))
        # Integer 1 is truthy but not a *bool* -> None
        self.assertIsNone(literal_bool_value(ast.parse("1").body[0].value))

    def test_get_call_target_module_dotted(self):
        call = ast.parse("mod.sub.f()").body[0].value
        self.assertEqual(get_call_target_module(call), "mod")

    def test_get_call_target_module_bare_name(self):
        call = ast.parse("f()").body[0].value
        self.assertIsNone(get_call_target_module(call))

    def test_call_target_matches_hits(self):
        call = ast.parse("mymod.sub.f()").body[0].value
        self.assertTrue(call_target_matches(call, "mymod"))

    def test_call_target_matches_none_sut(self):
        call = ast.parse("mymod.f()").body[0].value
        self.assertFalse(call_target_matches(call, None))

    def test_contains_call_to_sut_positive(self):
        m = ast.parse("y = mymod.f(x)").body[0]
        self.assertTrue(contains_call_to_sut(m, "mymod"))

    def test_contains_reference_to_sut_attribute(self):
        m = ast.parse("expected = mymod.CONSTANT").body[0]
        self.assertTrue(contains_reference_to_sut(m, "mymod"))

    def test_contains_reference_to_sut_none_when_sut_missing(self):
        m = ast.parse("expected = other.CONSTANT").body[0]
        self.assertFalse(contains_reference_to_sut(m, "mymod"))

    def test_find_prev_assign_to(self):
        src = "def f():\n a = 1\n b = 2\n c = 3\n"
        body = ast.parse(src).body[0].body
        prev = find_prev_assign_to("b", body, 3)
        self.assertIsNotNone(prev)
        self.assertEqual(prev.value.value, 2)

    def test_find_prev_assign_returns_none_when_no_assign(self):
        src = "def f():\n z = 1\n"
        body = ast.parse(src).body[0].body
        self.assertIsNone(find_prev_assign_to("a", body, 1))

    def test_is_call_to_positive(self):
        c = ast.parse("f(1)").body[0].value
        self.assertTrue(is_call_to(c, "f"))

    def test_is_call_to_negative(self):
        c = ast.parse("f(1)").body[0].value
        self.assertFalse(is_call_to(c, "g"))

    def test_strip_bom(self):
        BOM = "﻿"
        self.assertEqual(strip_bom(BOM + "hello"), "hello")
        self.assertEqual(strip_bom("hello"), "hello")
        self.assertEqual(strip_bom(""), "")


if __name__ == "__main__":
    unittest.main()
