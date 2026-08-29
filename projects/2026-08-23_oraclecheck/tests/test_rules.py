"""Per-rule positive + negative tests.

Each of the ten rules gets at least one positive-trigger test AND one
negative-clean test, plus registry/severity assertions.
"""

import ast
import unittest

from oraclecheck.config import Config
from oraclecheck.rules import (
    ALL_RULES,
    CHECKS,
    RULE_REGISTRY,
    evaluate_module,
)
from oraclecheck.types import Severity


def _run(src: str, sut: str = None, disabled=frozenset()) -> list:
    module = ast.parse(src)
    config = Config(sut_module=sut, disabled_rules=disabled)
    return evaluate_module(module, src, "test.py", config)


class TestRegistry(unittest.TestCase):

    def test_all_ten_rules_registered(self):
        expected = tuple(f"ORACLE-{i:03d}" for i in range(1, 11))
        self.assertEqual(ALL_RULES, expected)

    def test_all_rules_have_nonempty_descriptions(self):
        for rid in ALL_RULES:
            spec = RULE_REGISTRY[rid]
            self.assertTrue(spec.description.strip(), f"{rid} lacks description")

    def test_all_rules_have_a_check_function(self):
        for rid in ALL_RULES:
            self.assertIn(rid, CHECKS)


class TestRule001SelfComparison(unittest.TestCase):

    def test_positive_assertEqual_same_call_both_sides(self):
        src = "class T:\n def test_x(self):\n  self.assertEqual(f(x), f(x))\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-001" for x in f))

    def test_positive_assert_x_equals_x(self):
        src = "def test_x():\n assert f(1) == f(1)\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-001" for x in f))

    def test_negative_different_sides_not_flagged(self):
        src = "class T:\n def test_x(self):\n  self.assertEqual(f(x), 42)\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-001" for x in f))

    def test_negative_two_identical_literals_ignored(self):
        # Rule 010 will fire on vacuous True==True, but 001 is only for
        # non-literal repeated expressions.
        src = "def test_x():\n assert 1 == 1\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-001" for x in f))


class TestRule002DirectAnchor(unittest.TestCase):

    def test_positive_direct_anchor(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  expected = mymod.compute(1)\n"
            "  self.assertEqual(mymod.compute(1), expected)\n"
        )
        f = _run(src, sut="mymod")
        self.assertTrue(any(x.rule_id == "ORACLE-002" for x in f))

    def test_negative_no_sut_module_skips_rule(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  expected = compute(1)\n"
            "  self.assertEqual(compute(1), expected)\n"
        )
        f = _run(src, sut=None)
        self.assertFalse(any(x.rule_id == "ORACLE-002" for x in f))

    def test_negative_expected_from_literal_not_flagged(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  expected = 42\n"
            "  self.assertEqual(mymod.compute(1), expected)\n"
        )
        f = _run(src, sut="mymod")
        self.assertFalse(any(x.rule_id == "ORACLE-002" for x in f))

    def test_negative_actual_not_from_sut(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  expected = mymod.compute(1)\n"
            "  self.assertEqual(other.compute(1), expected)\n"
        )
        f = _run(src, sut="mymod")
        self.assertFalse(any(x.rule_id == "ORACLE-002" for x in f))


class TestRule003TautologicalRoundTrip(unittest.TestCase):

    def test_positive_dumps_loads_roundtrip(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  self.assertEqual(mymod.loads(mymod.dumps(payload)), payload)\n"
        )
        f = _run(src, sut="mymod")
        self.assertTrue(any(x.rule_id == "ORACLE-003" for x in f))

    def test_positive_encode_decode(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  self.assertEqual(mymod.decode(mymod.encode(x)), x)\n"
        )
        f = _run(src, sut="mymod")
        self.assertTrue(any(x.rule_id == "ORACLE-003" for x in f))

    def test_negative_no_sut_no_fire_unrelated_library_roundtrip(self):
        # When SUT is 'other', json.loads(json.dumps(fixture)) should NOT fire.
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  self.assertEqual(json.loads(json.dumps(payload)), payload)\n"
        )
        f = _run(src, sut="other")
        self.assertFalse(any(x.rule_id == "ORACLE-003" for x in f))

    def test_negative_different_inner_arg(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  self.assertEqual(mymod.loads(mymod.dumps(payload)), other_value)\n"
        )
        f = _run(src, sut="mymod")
        self.assertFalse(any(x.rule_id == "ORACLE-003" for x in f))


class TestRule004SnapshotFromSUT(unittest.TestCase):

    def test_positive_snapshot(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  snap = mymod.render(input_a)\n"
            "  self.assertEqual(mymod.render(input_b), snap)\n"
        )
        f = _run(src, sut="mymod")
        self.assertTrue(any(x.rule_id == "ORACLE-004" for x in f))

    def test_negative_no_sut_hint_skips_rule(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  snap = render(input_a)\n"
            "  self.assertEqual(render(input_b), snap)\n"
        )
        f = _run(src, sut=None)
        self.assertFalse(any(x.rule_id == "ORACLE-004" for x in f))

    def test_negative_identical_args_defers_to_002(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  snap = mymod.render(input_a)\n"
            "  self.assertEqual(mymod.render(input_a), snap)\n"
        )
        f = _run(src, sut="mymod")
        # 004 should NOT fire (identical-args case belongs to 002)
        self.assertFalse(any(x.rule_id == "ORACLE-004" for x in f))
        # 002 SHOULD fire on the same shape
        self.assertTrue(any(x.rule_id == "ORACLE-002" for x in f))

    def test_negative_expected_from_non_sut_call_not_flagged(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  snap = other.render(input_a)\n"
            "  self.assertEqual(mymod.render(input_b), snap)\n"
        )
        f = _run(src, sut="mymod")
        self.assertFalse(any(x.rule_id == "ORACLE-004" for x in f))


class TestRule005IdentityOracle(unittest.TestCase):

    def test_positive_assertTrue_x_equals_x(self):
        src = "class T:\n def t(self):\n  self.assertTrue(f(x) == f(x))\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-005" for x in f))

    def test_positive_assertIs_same(self):
        src = "class T:\n def t(self):\n  self.assertIs(a.b, a.b)\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-005" for x in f))

    def test_positive_bare_assert_x_is_x(self):
        src = "def t():\n assert obj is obj\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-005" for x in f))

    def test_negative_different_ops(self):
        src = "def t():\n assert obj is not None\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-005" for x in f))

    def test_negative_pure_literal_identity_not_flagged(self):
        # `assert 1 is 1` -> not an ORACLE-005 (literal identity); rule 010 territory
        src = "def t():\n assert 1 is 1\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-005" for x in f))


class TestRule006ReprRoundTrip(unittest.TestCase):

    def test_positive_repr_of_same(self):
        src = "class T:\n def t(self):\n  self.assertEqual(repr(x), repr(x))\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-006" for x in f))

    def test_positive_str_of_same(self):
        src = "class T:\n def t(self):\n  self.assertEqual(str(obj), str(obj))\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-006" for x in f))

    def test_negative_different_inners(self):
        src = "class T:\n def t(self):\n  self.assertEqual(repr(x), repr(y))\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-006" for x in f))

    def test_negative_only_one_side_repr(self):
        src = "class T:\n def t(self):\n  self.assertEqual(repr(x), 'literal')\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-006" for x in f))


class TestRule007FixtureFromSUT(unittest.TestCase):

    def test_positive_fixture_from_sut(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  self.assertEqual(mymod.compute(), mymod.EXPECTED_CONSTANT)\n"
        )
        f = _run(src, sut="mymod")
        self.assertTrue(any(x.rule_id == "ORACLE-007" for x in f))

    def test_negative_fixture_from_external_module(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  self.assertEqual(mymod.compute(), spec.EXPECTED_CONSTANT)\n"
        )
        f = _run(src, sut="mymod")
        self.assertFalse(any(x.rule_id == "ORACLE-007" for x in f))

    def test_negative_no_sut_skips_rule(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  self.assertEqual(mymod.compute(), mymod.CONSTANT)\n"
        )
        f = _run(src, sut=None)
        self.assertFalse(any(x.rule_id == "ORACLE-007" for x in f))


class TestRule008MockEchoesInput(unittest.TestCase):

    def test_positive_return_value_attr(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  m = MagicMock()\n"
            "  m.return_value = 'sentinel'\n"
            "  self.assertEqual(m(), 'sentinel')\n"
        )
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-008" for x in f))

    def test_positive_return_value_kwarg(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  m = Mock(return_value='sentinel')\n"
            "  self.assertEqual(m(), 'sentinel')\n"
        )
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-008" for x in f))

    def test_negative_no_mock_assign(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  self.assertEqual(compute(), 'value')\n"
        )
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-008" for x in f))

    def test_negative_different_expected_value(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  m = Mock(return_value='sentinel')\n"
            "  self.assertEqual(compute(m), 'other')\n"
        )
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-008" for x in f))


class TestRule009AssertionUnderExceptPass(unittest.TestCase):

    def test_positive_bare_except_pass(self):
        src = (
            "def t():\n"
            " try:\n"
            "  assert False\n"
            " except:\n"
            "  pass\n"
        )
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-009" for x in f))

    def test_positive_named_assertion_error(self):
        src = (
            "def t():\n"
            " try:\n"
            "  assert x == 1\n"
            " except AssertionError:\n"
            "  pass\n"
        )
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-009" for x in f))

    def test_positive_assertX_call_swallowed(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  try:\n"
            "   self.assertEqual(a, b)\n"
            "  except AssertionError:\n"
            "   pass\n"
        )
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-009" for x in f))

    def test_negative_handler_does_something(self):
        src = (
            "def t():\n"
            " try:\n"
            "  assert x == 1\n"
            " except AssertionError:\n"
            "  raise\n"
        )
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-009" for x in f))

    def test_negative_non_assertion_exception_handler(self):
        src = (
            "def t():\n"
            " try:\n"
            "  assert x == 1\n"
            " except ValueError:\n"
            "  pass\n"
        )
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-009" for x in f))


class TestRule010VacuousCondition(unittest.TestCase):

    def test_positive_assertTrue_True(self):
        src = "class T:\n def t(self):\n  self.assertTrue(True)\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-010" for x in f))

    def test_positive_assertFalse_False(self):
        src = "class T:\n def t(self):\n  self.assertFalse(False)\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-010" for x in f))

    def test_positive_bare_assert_truthy_literal(self):
        src = "def t():\n assert 1\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-010" for x in f))

    def test_positive_bare_assert_nonempty_string(self):
        src = "def t():\n assert 'ok'\n"
        f = _run(src)
        self.assertTrue(any(x.rule_id == "ORACLE-010" for x in f))

    def test_negative_assert_False_intentional_marker(self):
        # `assert False` is a raise-marker, not vacuous.
        src = "def t():\n assert False\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-010" for x in f))

    def test_negative_dynamic_expr_not_flagged(self):
        src = "def t():\n assert compute() == 1\n"
        f = _run(src)
        self.assertFalse(any(x.rule_id == "ORACLE-010" for x in f))


class TestRule002And004AreDisjoint(unittest.TestCase):
    """ORACLE-002 (identical args) and ORACLE-004 (differing args) must never
    both fire on the same assertion.
    """

    def test_identical_args_only_002_fires(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  x = mymod.render(input_a)\n"
            "  self.assertEqual(mymod.render(input_a), x)\n"
        )
        f = _run(src, sut="mymod")
        rule_ids = [x.rule_id for x in f]
        self.assertIn("ORACLE-002", rule_ids)
        self.assertNotIn("ORACLE-004", rule_ids)

    def test_differing_args_only_004_fires(self):
        src = (
            "class T:\n"
            " def t(self):\n"
            "  x = mymod.render(input_a)\n"
            "  self.assertEqual(mymod.render(input_b), x)\n"
        )
        f = _run(src, sut="mymod")
        rule_ids = [x.rule_id for x in f]
        self.assertNotIn("ORACLE-002", rule_ids)
        self.assertIn("ORACLE-004", rule_ids)


class TestRule001And005AreDisjoint(unittest.TestCase):
    """assertIs(x, x) belongs to ORACLE-005 only; ORACLE-001 must not
    duplicate it. `assert x is x` belongs to ORACLE-005 only.
    """

    def test_assertIs_only_005(self):
        src = "class T:\n def t(self):\n  self.assertIs(handle.value, handle.value)\n"
        f = _run(src)
        ids = [x.rule_id for x in f]
        self.assertIn("ORACLE-005", ids)
        self.assertNotIn("ORACLE-001", ids)

    def test_bare_assert_is_only_005(self):
        src = "def t():\n assert obj is obj\n"
        f = _run(src)
        ids = [x.rule_id for x in f]
        self.assertIn("ORACLE-005", ids)
        self.assertNotIn("ORACLE-001", ids)


class TestDisabledRulesRespected(unittest.TestCase):

    def test_disabling_a_rule_suppresses_its_findings(self):
        src = "def t():\n assert 1\n"
        f = _run(src, disabled=frozenset({"ORACLE-010"}))
        self.assertFalse(any(x.rule_id == "ORACLE-010" for x in f))


class TestFindingsAreSorted(unittest.TestCase):

    def test_findings_sorted_by_severity_then_path(self):
        src = (
            "def t():\n"
            " assert True\n"           # ORACLE-010 INFO
            " assert x == x\n"          # ORACLE-001 HIGH
        )
        f = _run(src)
        severities = [x.severity for x in f]
        # HIGH before INFO (HIGH has lower rank number)
        highs = [i for i, s in enumerate(severities) if s == Severity.HIGH]
        infos = [i for i, s in enumerate(severities) if s == Severity.INFO]
        self.assertTrue(all(h < i for h in highs for i in infos))


if __name__ == "__main__":
    unittest.main()
