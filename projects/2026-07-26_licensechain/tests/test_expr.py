import unittest

from licensechain.expr import (
    parse_expr, ParseError, LicenseId, LicenseRef, With, And, Or,
    iter_leaves, collect_ids, collect_refs, canonical_choices,
)


class SimpleExpressionTests(unittest.TestCase):

    def test_bare_id(self):
        expr = parse_expr("MIT")
        self.assertEqual(expr, LicenseId("MIT"))

    def test_hyphenated_id(self):
        expr = parse_expr("Apache-2.0")
        self.assertEqual(expr, LicenseId("Apache-2.0"))

    def test_dotted_id(self):
        expr = parse_expr("CC-BY-SA-4.0")
        self.assertEqual(expr, LicenseId("CC-BY-SA-4.0"))

    def test_or_later_marker(self):
        expr = parse_expr("GPL-2.0+")
        self.assertEqual(expr, LicenseId("GPL-2.0", or_later=True))

    def test_license_ref(self):
        expr = parse_expr("LicenseRef-MyCustom")
        self.assertEqual(expr, LicenseRef("LicenseRef-MyCustom"))

    def test_license_ref_disallows_plus(self):
        with self.assertRaises(ParseError):
            parse_expr("LicenseRef-MyCustom+")

    def test_document_ref_form(self):
        expr = parse_expr("DocumentRef-abc")
        self.assertEqual(expr, LicenseRef("DocumentRef-abc"))


class WithClauseTests(unittest.TestCase):

    def test_with_exception(self):
        expr = parse_expr("GPL-2.0-or-later WITH Classpath-exception-2.0")
        self.assertEqual(
            expr,
            With(LicenseId("GPL-2.0-or-later"), "Classpath-exception-2.0"),
        )

    def test_with_after_or_later(self):
        expr = parse_expr("GPL-2.0+ WITH Bison-exception-2.2")
        self.assertEqual(
            expr,
            With(LicenseId("GPL-2.0", or_later=True), "Bison-exception-2.2"),
        )

    def test_with_requires_exception(self):
        with self.assertRaises(ParseError):
            parse_expr("MIT WITH")


class AndOrTests(unittest.TestCase):

    def test_and(self):
        expr = parse_expr("MIT AND Apache-2.0")
        self.assertEqual(expr, And(LicenseId("MIT"), LicenseId("Apache-2.0")))

    def test_or(self):
        expr = parse_expr("MIT OR Apache-2.0")
        self.assertEqual(expr, Or(LicenseId("MIT"), LicenseId("Apache-2.0")))

    def test_and_binds_tighter_than_or(self):
        # A OR B AND C => A OR (B AND C)
        expr = parse_expr("MIT OR Apache-2.0 AND BSD-3-Clause")
        self.assertEqual(
            expr,
            Or(
                LicenseId("MIT"),
                And(LicenseId("Apache-2.0"), LicenseId("BSD-3-Clause")),
            ),
        )

    def test_parens_override_precedence(self):
        expr = parse_expr("(MIT OR Apache-2.0) AND BSD-3-Clause")
        self.assertEqual(
            expr,
            And(
                Or(LicenseId("MIT"), LicenseId("Apache-2.0")),
                LicenseId("BSD-3-Clause"),
            ),
        )

    def test_and_is_left_associative(self):
        expr = parse_expr("A AND B AND C")
        self.assertEqual(
            expr,
            And(And(LicenseId("A"), LicenseId("B")), LicenseId("C")),
        )

    def test_or_is_left_associative(self):
        expr = parse_expr("A OR B OR C")
        self.assertEqual(
            expr,
            Or(Or(LicenseId("A"), LicenseId("B")), LicenseId("C")),
        )

    def test_whitespace_tolerance(self):
        e1 = parse_expr("  MIT   OR   Apache-2.0  ")
        e2 = parse_expr("MIT OR Apache-2.0")
        self.assertEqual(e1, e2)

    def test_operators_are_case_sensitive(self):
        # Lowercase "and" is NOT an operator per SPDX spec; it becomes an id
        # and thus creates a parse error (two consecutive ids).
        with self.assertRaises(ParseError):
            parse_expr("MIT and Apache-2.0")

    def test_nested_parens(self):
        expr = parse_expr("((MIT))")
        self.assertEqual(expr, LicenseId("MIT"))

    def test_or_of_ands(self):
        expr = parse_expr("(MIT AND CC-BY-4.0) OR (Apache-2.0 AND CC-BY-4.0)")
        self.assertIsInstance(expr, Or)


class ErrorTests(unittest.TestCase):

    def test_empty_string(self):
        with self.assertRaises(ParseError):
            parse_expr("")

    def test_whitespace_only(self):
        with self.assertRaises(ParseError):
            parse_expr("   ")

    def test_unclosed_paren(self):
        with self.assertRaises(ParseError):
            parse_expr("(MIT")

    def test_leading_operator(self):
        with self.assertRaises(ParseError):
            parse_expr("AND MIT")

    def test_trailing_operator(self):
        with self.assertRaises(ParseError):
            parse_expr("MIT AND")

    def test_double_operator(self):
        with self.assertRaises(ParseError):
            parse_expr("MIT OR OR Apache-2.0")

    def test_invalid_character(self):
        with self.assertRaises(ParseError):
            parse_expr("MIT & Apache-2.0")

    def test_none_input(self):
        with self.assertRaises(ParseError):
            parse_expr(None)


class IntrospectionTests(unittest.TestCase):

    def test_iter_leaves_returns_all(self):
        expr = parse_expr("(MIT OR Apache-2.0) AND CC-BY-4.0")
        leaves = list(iter_leaves(expr))
        self.assertEqual(len(leaves), 3)

    def test_iter_leaves_walks_through_with(self):
        expr = parse_expr("GPL-2.0-or-later WITH Classpath-exception-2.0")
        leaves = list(iter_leaves(expr))
        self.assertEqual(leaves, [LicenseId("GPL-2.0-or-later")])

    def test_collect_ids(self):
        expr = parse_expr("(MIT OR Apache-2.0) AND CC-BY-4.0")
        self.assertEqual(
            collect_ids(expr), {"MIT", "Apache-2.0", "CC-BY-4.0"}
        )

    def test_collect_refs(self):
        expr = parse_expr("MIT AND LicenseRef-Corp-Internal")
        self.assertEqual(collect_refs(expr), {"LicenseRef-Corp-Internal"})

    def test_canonical_choices_single(self):
        expr = parse_expr("MIT")
        self.assertEqual(canonical_choices(expr), [[LicenseId("MIT")]])

    def test_canonical_choices_or(self):
        expr = parse_expr("MIT OR Apache-2.0")
        self.assertEqual(
            canonical_choices(expr),
            [[LicenseId("MIT")], [LicenseId("Apache-2.0")]],
        )

    def test_canonical_choices_and(self):
        expr = parse_expr("MIT AND CC-BY-4.0")
        self.assertEqual(
            canonical_choices(expr),
            [[LicenseId("MIT"), LicenseId("CC-BY-4.0")]],
        )

    def test_canonical_choices_or_of_and(self):
        expr = parse_expr("(MIT AND CC-BY-4.0) OR (Apache-2.0 AND CC-BY-4.0)")
        choices = canonical_choices(expr)
        self.assertEqual(len(choices), 2)
        # Order preserved from the parse.
        self.assertIn(LicenseId("MIT"), choices[0])
        self.assertIn(LicenseId("Apache-2.0"), choices[1])

    def test_canonical_choices_distributes_and_over_or(self):
        expr = parse_expr("(MIT OR Apache-2.0) AND CC-BY-4.0")
        choices = canonical_choices(expr)
        self.assertEqual(len(choices), 2)
        for c in choices:
            self.assertIn(LicenseId("CC-BY-4.0"), c)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
