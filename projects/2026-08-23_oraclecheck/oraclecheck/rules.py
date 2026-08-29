"""Ten anchored-oracle rules.

Each rule is a pure function `check(module, source, path, config) -> list[Finding]`.

Rule severities are fixed by the RuleSpec registry. The registry drives both
enforcement and downstream reporting.
"""

from __future__ import annotations

import ast
from typing import Iterable, List, Optional

from oraclecheck.config import (
    Config,
    ROUNDTRIP_INVERSES,
    ROUNDTRIP_REPR_FUNCS,
)
from oraclecheck.parse import (
    call_target_matches,
    contains_call_to_sut,
    contains_reference_to_sut,
    exprs_equal,
    find_prev_assign_to,
    get_assert_operands,
    get_call_name,
    get_call_target_module,
    get_dotted_name,
    is_call_to,
    iter_calls,
    literal_bool_value,
    literal_truthy,
    unwrap_await,
)
from oraclecheck.types import Finding, RuleSpec, Severity


RULE_REGISTRY: dict = {
    "ORACLE-001": RuleSpec(
        rule_id="ORACLE-001",
        severity=Severity.HIGH,
        description="Self-comparison oracle: same expression on both sides of an equality assertion (assertEqual(f(x), f(x)) or `assert f(x) == f(x)`).",
    ),
    "ORACLE-002": RuleSpec(
        rule_id="ORACLE-002",
        severity=Severity.HIGH,
        description="Direct anchor: expected value is assigned from a call to the SUT immediately before an assertion that also calls the SUT.",
    ),
    "ORACLE-003": RuleSpec(
        rule_id="ORACLE-003",
        severity=Severity.MEDIUM,
        description="Tautological round-trip on self: assertEqual(f(g(x)), x) where f and g are matching inverse pairs from the SUT (dumps/loads, encode/decode, ...).",
    ),
    "ORACLE-004": RuleSpec(
        rule_id="ORACLE-004",
        severity=Severity.HIGH,
        description="Snapshot-from-SUT: expected snapshot captured from the SUT earlier in the same test, then compared against a subsequent SUT invocation.",
    ),
    "ORACLE-005": RuleSpec(
        rule_id="ORACLE-005",
        severity=Severity.HIGH,
        description="Identity oracle: assertEqual(x, x) / assertTrue(x == x) / bare `assert x == x`.",
    ),
    "ORACLE-006": RuleSpec(
        rule_id="ORACLE-006",
        severity=Severity.MEDIUM,
        description="repr/str round-trip on self: assertEqual(repr(x), repr(x)) / str(x) == str(x) with matching inner expression.",
    ),
    "ORACLE-007": RuleSpec(
        rule_id="ORACLE-007",
        severity=Severity.MEDIUM,
        description="Fixture-from-SUT: expected value is an attribute of the SUT module, compared against a call to the SUT (expected = sut.CONSTANT; assertEqual(sut.compute(), sut.CONSTANT)).",
    ),
    "ORACLE-008": RuleSpec(
        rule_id="ORACLE-008",
        severity=Severity.MEDIUM,
        description="Mock-echoes-input: an assertion returns the exact object placed into a mock's return_value / side_effect in the same test.",
    ),
    "ORACLE-009": RuleSpec(
        rule_id="ORACLE-009",
        severity=Severity.HIGH,
        description="Assertion-under-except-pass: assert / assertX call inside a try whose except swallows AssertionError with pass.",
    ),
    "ORACLE-010": RuleSpec(
        rule_id="ORACLE-010",
        severity=Severity.INFO,
        description="Vacuous condition: assertTrue(True) / assertFalse(False) / assert True / assert 1 / assert 'nonempty-literal'.",
    ),
}

ALL_RULES = tuple(sorted(RULE_REGISTRY.keys()))


def _make_finding(rule_id: str, path: str, node: ast.AST, message: str) -> Finding:
    spec = RULE_REGISTRY[rule_id]
    line = getattr(node, "lineno", 0) or 0
    col = getattr(node, "col_offset", 0) or 0
    return Finding(
        rule_id=rule_id,
        severity=spec.severity,
        path=path,
        line=line,
        column=col,
        message=message,
    )


def _iter_stmts_with_context(module: ast.Module):
    """Yield (parent_body_list, index, stmt) tuples for every statement in
    every function body, walking into class bodies too.
    """

    def visit(body: list):
        for i, stmt in enumerate(body):
            yield body, i, stmt
            for name in ("body", "orelse", "finalbody", "handlers"):
                sub = getattr(stmt, name, None)
                if isinstance(sub, list):
                    if sub and isinstance(sub[0], ast.ExceptHandler):
                        for h in sub:
                            yield from visit(h.body)
                    else:
                        yield from visit(sub)

    yield from visit(module.body)


def _iter_asserts(module: ast.Module):
    """Yield ((body_list, index, stmt), call_or_assert_node, left, right)
    tuples for every assertX call and every bare `assert` in the module.
    """
    for body, i, stmt in _iter_stmts_with_context(module):
        if isinstance(stmt, ast.Assert):
            yield (body, i, stmt), stmt, stmt.test, None
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            name = get_call_name(call)
            if name is None:
                continue
            if name.startswith("assert"):
                args = get_assert_operands(call)
                yield (body, i, stmt), call, args[0] if args else None, args[1] if len(args) > 1 else None


# ---------- ORACLE-001: self-comparison ----------


def check_001(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    for ctx, node, left, right in _iter_asserts(module):
        # assertEqual-like two-arg
        if right is not None:
            if isinstance(node, ast.Call):
                fn = get_call_name(node)
                # assertIs belongs to ORACLE-005 (identity); do not double-fire here.
                if fn in {"assertEqual", "assertEquals", "assertAlmostEqual",
                          "assertSequenceEqual", "assertListEqual", "assertTupleEqual",
                          "assertDictEqual", "assertSetEqual", "assertMultiLineEqual"}:
                    if exprs_equal(unwrap_await(left), unwrap_await(right)):
                        if not _is_pure_literal(left):
                            findings.append(_make_finding(
                                "ORACLE-001", path, node,
                                f"self-comparison via {fn}: expected and actual are structurally identical",
                            ))
            continue
        # bare assert: `assert x == x` (ORACLE-005 handles bare `assert x is x`)
        if isinstance(node, ast.Assert):
            test = node.test
            if isinstance(test, ast.Compare) and len(test.ops) == 1:
                op = test.ops[0]
                if isinstance(op, ast.Eq):
                    lhs = test.left
                    rhs = test.comparators[0]
                    if exprs_equal(unwrap_await(lhs), unwrap_await(rhs)) and not _is_pure_literal(lhs):
                        findings.append(_make_finding(
                            "ORACLE-001", path, node,
                            "self-comparison in bare assert: expected and actual are structurally identical",
                        ))
    return findings


def _is_pure_literal(node: ast.AST) -> bool:
    """Two identical *literals* are not an oracle smell (they are a placeholder
    or a spec constant); rule 010 handles the truly-vacuous shapes.
    """
    return isinstance(node, ast.Constant)


# ---------- ORACLE-002: direct anchor ----------


def check_002(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    """Direct anchor: expected assigned from a SUT call with IDENTICAL args
    to the actual-side SUT call. The differing-args form is ORACLE-004; the
    two rules are mutually exclusive.
    """
    findings: List[Finding] = []
    for (body, idx, stmt), node, left, right in _iter_asserts(module):
        if right is None:
            continue
        fn = get_call_name(node) if isinstance(node, ast.Call) else None
        if fn not in {"assertEqual", "assertEquals", "assertIs", "assertAlmostEqual",
                      "assertSequenceEqual", "assertListEqual", "assertTupleEqual",
                      "assertDictEqual", "assertSetEqual", "assertMultiLineEqual"}:
            continue
        actual = unwrap_await(left)
        expected = unwrap_await(right)
        if not _actual_calls_sut(actual, config.sut_module):
            continue
        anchored_name = _expected_name_from_sut(expected, body, idx, config.sut_module)
        if anchored_name is None:
            continue
        prev = find_prev_assign_to(anchored_name, body, idx)
        if prev is None or not isinstance(prev.value, ast.Call):
            continue
        actual_inner = _extract_sut_call(actual, config.sut_module)
        if actual_inner is None:
            continue
        if get_dotted_name(prev.value.func) != get_dotted_name(actual_inner.func):
            continue
        if not _call_args_equal(prev.value, actual_inner):
            continue
        findings.append(_make_finding(
            "ORACLE-002", path, node,
            f"expected value '{anchored_name}' was assigned from a call to the SUT ('{config.sut_module}') on line {getattr(prev, 'lineno', 0)}; both sides flow from the same code with identical arguments",
        ))
    return findings


def _extract_sut_call(node: ast.AST, sut_module: Optional[str]) -> Optional[ast.Call]:
    if sut_module is None:
        return None
    if isinstance(node, ast.Call) and call_target_matches(node, sut_module):
        return node
    for c in iter_calls(node):
        if call_target_matches(c, sut_module):
            return c
    return None


def _actual_calls_sut(node: ast.AST, sut_module: Optional[str]) -> bool:
    if sut_module is None:
        return False
    return contains_call_to_sut(node, sut_module)


def _expected_name_from_sut(
    expected: ast.AST,
    body: list,
    idx: int,
    sut_module: Optional[str],
) -> Optional[str]:
    if sut_module is None:
        return None
    if not isinstance(expected, ast.Name):
        return None
    prev = find_prev_assign_to(expected.id, body, idx)
    if prev is None:
        return None
    if contains_call_to_sut(prev.value, sut_module):
        return expected.id
    return None


def anchored_name_line(name: str, body: list, upto_index: int) -> int:
    prev = find_prev_assign_to(name, body, upto_index)
    return getattr(prev, "lineno", 0) if prev is not None else 0


# ---------- ORACLE-003: tautological round-trip ----------


def check_003(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    for ctx, node, left, right in _iter_asserts(module):
        if right is None:
            continue
        if isinstance(node, ast.Call):
            fn = get_call_name(node)
            if fn not in {"assertEqual", "assertEquals", "assertSequenceEqual",
                          "assertListEqual", "assertTupleEqual", "assertDictEqual"}:
                continue
        pair = _matched_roundtrip(unwrap_await(left), unwrap_await(right), config.sut_module)
        if pair is None:
            pair = _matched_roundtrip(unwrap_await(right), unwrap_await(left), config.sut_module)
        if pair is not None:
            outer, inner = pair
            findings.append(_make_finding(
                "ORACLE-003", path, node,
                f"round-trip against self: {outer}({inner}(...)) compared to the original argument; asserts inverse-pair symmetry, not correctness",
            ))
    return findings


def _matched_roundtrip(actual: ast.AST, expected: ast.AST, sut_module: Optional[str]) -> Optional[tuple]:
    """Return (outer_name, inner_name) if `actual` is a call outer(inner(x))
    with (outer, inner) an inverse pair, and `expected` structurally equal to
    x. Requires the innermost call to reference the SUT when sut_module is set,
    so unrelated json.loads(json.dumps(fixture)) round-trips over library-
    provided data don't false-positive when the SUT is elsewhere.
    """
    if not isinstance(actual, ast.Call):
        return None
    outer_name = get_call_name(actual)
    if outer_name is None:
        return None
    if not actual.args:
        return None
    inner = actual.args[0]
    if not isinstance(inner, ast.Call):
        return None
    inner_name = get_call_name(inner)
    if inner_name is None:
        return None
    if (outer_name, inner_name) not in ROUNDTRIP_INVERSES:
        return None
    if not inner.args:
        return None
    innermost = inner.args[0]
    if not exprs_equal(innermost, expected):
        return None
    # If a SUT module is set, require BOTH calls to route through the SUT to
    # avoid firing on unrelated library round-trips.
    if sut_module is not None:
        if not (call_target_matches(actual, sut_module) or call_target_matches(inner, sut_module)):
            return None
    return (outer_name, inner_name)


# ---------- ORACLE-004: snapshot-from-SUT ----------


def check_004(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    if config.sut_module is None:
        return findings
    for (body, idx, stmt), node, left, right in _iter_asserts(module):
        if right is None:
            continue
        if not isinstance(node, ast.Call):
            continue
        fn = get_call_name(node)
        if fn not in {"assertEqual", "assertEquals", "assertSequenceEqual",
                      "assertListEqual", "assertTupleEqual", "assertDictEqual"}:
            continue
        actual = unwrap_await(left)
        expected = unwrap_await(right)
        if not contains_call_to_sut(actual, config.sut_module):
            continue
        snapshot_line = _snapshot_from_sut(expected, actual, body, idx, config.sut_module)
        if snapshot_line is not None:
            findings.append(_make_finding(
                "ORACLE-004", path, node,
                f"snapshot-from-SUT: expected was captured from a prior SUT call on line {snapshot_line}, then compared against another SUT call; a mutation moves both sides together",
            ))
    return findings


def _snapshot_from_sut(
    expected: ast.AST,
    actual: ast.AST,
    body: list,
    idx: int,
    sut_module: str,
) -> Optional[int]:
    """Snapshot pattern requires the expected side is a Name whose prior
    assignment is a call structurally similar to actual (both go through the
    SUT). Distinct from ORACLE-002 by insisting the assign expression is
    itself a Call to the SUT AND the actual-side call structurally matches
    that prior call (same callable identity, ignoring arguments).
    """
    if not isinstance(expected, ast.Name):
        return None
    prev = find_prev_assign_to(expected.id, body, idx)
    if prev is None:
        return None
    prev_value = prev.value
    if not isinstance(prev_value, ast.Call):
        return None
    if not call_target_matches(prev_value, sut_module):
        return None
    # actual must be a call to the same callable (name-equal, args may differ)
    actual_inner = actual if isinstance(actual, ast.Call) else None
    if actual_inner is None:
        for c in iter_calls(actual):
            if call_target_matches(c, sut_module):
                actual_inner = c
                break
    if actual_inner is None:
        return None
    if get_dotted_name(prev_value.func) != get_dotted_name(actual_inner.func):
        return None
    # And it must NOT be a straight `x = f(...); assertEqual(f(...), x)` on
    # identical args -- rule 002 covers that. Only fire on differing-arg-calls
    # (the true snapshot pattern).
    if _call_args_equal(prev_value, actual_inner):
        return None
    return getattr(prev, "lineno", 0)


def _call_args_equal(a: ast.Call, b: ast.Call) -> bool:
    if len(a.args) != len(b.args):
        return False
    if len(a.keywords) != len(b.keywords):
        return False
    for x, y in zip(a.args, b.args):
        if not exprs_equal(x, y):
            return False
    for x, y in zip(a.keywords, b.keywords):
        if x.arg != y.arg or not exprs_equal(x.value, y.value):
            return False
    return True


# ---------- ORACLE-005: identity oracle ----------


def check_005(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    for ctx, node, left, right in _iter_asserts(module):
        if isinstance(node, ast.Call):
            fn = get_call_name(node)
            if fn in {"assertTrue", "assertFalse"} and left is not None:
                if isinstance(left, ast.Compare) and len(left.ops) == 1:
                    op = left.ops[0]
                    if isinstance(op, (ast.Eq, ast.Is, ast.NotEq, ast.IsNot)):
                        lhs = left.left
                        rhs = left.comparators[0]
                        if exprs_equal(lhs, rhs) and not _is_pure_literal(lhs):
                            findings.append(_make_finding(
                                "ORACLE-005", path, node,
                                f"identity comparison inside {fn}: both sides are the same expression",
                            ))
            elif fn == "assertIs" and left is not None and right is not None:
                if exprs_equal(left, right) and not _is_pure_literal(left):
                    findings.append(_make_finding(
                        "ORACLE-005", path, node,
                        "assertIs(x, x): tautological identity oracle",
                    ))
        elif isinstance(node, ast.Assert):
            test = node.test
            if isinstance(test, ast.Compare) and len(test.ops) == 1:
                op = test.ops[0]
                if isinstance(op, ast.Is):
                    lhs = test.left
                    rhs = test.comparators[0]
                    if exprs_equal(lhs, rhs) and not _is_pure_literal(lhs):
                        findings.append(_make_finding(
                            "ORACLE-005", path, node,
                            "bare assert x is x: identity oracle",
                        ))
    return findings


# ---------- ORACLE-006: repr/str round-trip ----------


def check_006(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    for ctx, node, left, right in _iter_asserts(module):
        if right is None:
            continue
        if not isinstance(node, ast.Call):
            continue
        fn = get_call_name(node)
        if fn not in {"assertEqual", "assertEquals"}:
            continue
        if _both_are_repr_of_same(unwrap_await(left), unwrap_await(right)):
            findings.append(_make_finding(
                "ORACLE-006", path, node,
                "repr/str round-trip: both sides are repr(x) / str(x) of the same inner expression",
            ))
    return findings


def _both_are_repr_of_same(left: ast.AST, right: ast.AST) -> bool:
    def unwrap(n: ast.AST) -> Optional[tuple]:
        if isinstance(n, ast.Call):
            name = get_call_name(n)
            if name in ROUNDTRIP_REPR_FUNCS and n.args:
                return (name, n.args[0])
        return None

    l = unwrap(left)
    r = unwrap(right)
    if l is None or r is None:
        return False
    return l[0] == r[0] and exprs_equal(l[1], r[1])


# ---------- ORACLE-007: fixture-from-SUT ----------


def check_007(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    if config.sut_module is None:
        return findings
    for ctx, node, left, right in _iter_asserts(module):
        if right is None:
            continue
        if not isinstance(node, ast.Call):
            continue
        fn = get_call_name(node)
        if fn not in {"assertEqual", "assertEquals"}:
            continue
        actual = unwrap_await(left)
        expected = unwrap_await(right)
        if not contains_call_to_sut(actual, config.sut_module):
            continue
        # Expected side must be an Attribute-chain rooted at the SUT module,
        # and NOT itself a Call.
        if isinstance(expected, ast.Attribute) and not isinstance(expected, ast.Call):
            walker = expected
            while isinstance(walker, ast.Attribute):
                walker = walker.value
            if isinstance(walker, ast.Name) and walker.id == config.sut_module:
                findings.append(_make_finding(
                    "ORACLE-007", path, node,
                    f"fixture-from-SUT: expected value '{get_dotted_name(expected)}' is defined inside the SUT module '{config.sut_module}'; the expected value should come from an external specification or test-local literal",
                ))
    return findings


# ---------- ORACLE-008: mock-echoes-input ----------


def check_008(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    # First collect per-scope: name -> normalized-mock-value-expr assigned to
    # `.return_value` or produced via `Mock(return_value=...)` / `MagicMock(...)`.
    for func in _iter_funcs(module):
        mock_values: dict = {}
        for stmt in ast.walk(func):
            if isinstance(stmt, ast.Assign):
                # x.return_value = <expr>
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Attribute) and tgt.attr == "return_value":
                        if isinstance(tgt.value, ast.Name):
                            mock_values[tgt.value.id] = stmt.value
                # x = Mock(return_value=<expr>) / MagicMock(return_value=<expr>)
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    val = stmt.value
                    if isinstance(val, ast.Call):
                        name = get_call_name(val)
                        if name in {"Mock", "MagicMock", "AsyncMock"}:
                            for kw in val.keywords:
                                if kw.arg == "return_value":
                                    mock_values[stmt.targets[0].id] = kw.value
        if not mock_values:
            continue
        for stmt in ast.walk(func):
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                name = get_call_name(call)
                if name in {"assertEqual", "assertEquals", "assertIs"}:
                    args = get_assert_operands(call)
                    if len(args) < 2:
                        continue
                    a, b = args[0], args[1]
                    for mock_val in mock_values.values():
                        if exprs_equal(unwrap_await(a), mock_val) or exprs_equal(unwrap_await(b), mock_val):
                            findings.append(_make_finding(
                                "ORACLE-008", path, call,
                                f"mock-echoes-input: assertion compares against an expression identical to a mock's return_value; the SUT is exercising only the mock, not real logic",
                            ))
                            break
    return findings


def _iter_funcs(module: ast.Module) -> Iterable[ast.AST]:
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


# ---------- ORACLE-009: assertion-under-except-pass ----------


def check_009(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.Try):
            continue
        # If any handler swallows AssertionError (or bare except) with only
        # pass, and the try body contains any assert or assertX call, flag.
        swallows = False
        for handler in node.handlers:
            if _handler_swallows_assertion(handler):
                swallows = True
                break
        if not swallows:
            continue
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, ast.Assert):
                findings.append(_make_finding(
                    "ORACLE-009", path, child,
                    "assertion inside try whose except swallows AssertionError with pass; oracle cannot report failure",
                ))
            elif isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                cname = get_call_name(child.value)
                if cname is not None and cname.startswith("assert"):
                    findings.append(_make_finding(
                        "ORACLE-009", path, child,
                        "assertion call inside try whose except swallows AssertionError with pass; oracle cannot report failure",
                    ))
    return findings


def _handler_swallows_assertion(handler: ast.ExceptHandler) -> bool:
    # Body must be exactly one Pass statement (or docstring-and-pass at most).
    body = [b for b in handler.body if not _is_docstring(b)]
    if len(body) != 1 or not isinstance(body[0], ast.Pass):
        return False
    exc = handler.type
    if exc is None:
        return True  # bare except: swallows everything, including AssertionError
    if isinstance(exc, ast.Name) and exc.id in {"AssertionError", "Exception", "BaseException"}:
        return True
    if isinstance(exc, ast.Tuple):
        for e in exc.elts:
            if isinstance(e, ast.Name) and e.id in {"AssertionError", "Exception", "BaseException"}:
                return True
    return False


def _is_docstring(node: ast.AST) -> bool:
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)


# ---------- ORACLE-010: vacuous condition ----------


def check_010(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    for ctx, node, left, right in _iter_asserts(module):
        if isinstance(node, ast.Call):
            fn = get_call_name(node)
            if fn in {"assertTrue", "assertFalse"} and left is not None:
                truthy = literal_truthy(left)
                if truthy is None:
                    continue
                if fn == "assertTrue" and truthy is True:
                    findings.append(_make_finding("ORACLE-010", path, node, "assertTrue(<truthy literal>): vacuous"))
                if fn == "assertFalse" and truthy is False:
                    findings.append(_make_finding("ORACLE-010", path, node, "assertFalse(<falsy literal>): vacuous"))
        elif isinstance(node, ast.Assert):
            truthy = literal_truthy(node.test)
            if truthy is True:
                findings.append(_make_finding("ORACLE-010", path, node, "bare assert <truthy literal>: vacuous"))
            if truthy is False:
                # `assert False` is not vacuous -- it is an intentional test
                # failure marker (raise-like). Skip.
                pass
    return findings


CHECKS = {
    "ORACLE-001": check_001,
    "ORACLE-002": check_002,
    "ORACLE-003": check_003,
    "ORACLE-004": check_004,
    "ORACLE-005": check_005,
    "ORACLE-006": check_006,
    "ORACLE-007": check_007,
    "ORACLE-008": check_008,
    "ORACLE-009": check_009,
    "ORACLE-010": check_010,
}


def evaluate_module(module: ast.Module, source: str, path: str, config: Config) -> List[Finding]:
    """Run all enabled rules against a parsed module. Returns a sorted list."""
    findings: List[Finding] = []
    for rule_id, fn in CHECKS.items():
        if rule_id in config.disabled_rules:
            continue
        findings.extend(fn(module, source, path, config))
    findings.sort(key=lambda f: f.sort_key())
    return findings
