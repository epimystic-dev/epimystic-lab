"""AST helpers: node-shape queries used by the rules module.

All functions are total: they never raise on an unexpected shape; they return
False / empty / None instead. This keeps rules simple and robust to arbitrary
user source.
"""

from __future__ import annotations

import ast
from typing import Iterable, Optional


def parse_source(source: str, path: str = "<source>") -> Optional[ast.Module]:
    """Parse source to an ast.Module, or None on SyntaxError."""
    try:
        return ast.parse(source, filename=path)
    except SyntaxError:
        return None


def get_call_name(node: ast.AST) -> Optional[str]:
    """Return the callable name (dotted) if `node` is a Call, else None.

    Only handles Name and Attribute callables; returns the last-segment name
    for Attribute chains (e.g. `self.assertEqual` -> `assertEqual`).
    """
    if not isinstance(node, ast.Call):
        return None
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def get_dotted_name(node: ast.AST) -> Optional[str]:
    """Return the dotted qualified name if node is Name / Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_dotted_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def normalize_expr(node: ast.AST) -> str:
    """Return an ast.dump of the node stripped of source-location fields so
    two expressions with identical structure but different positions compare
    equal. Constants compare by value and type. Attribute / Name compare by
    identifier. Calls compare by callable + args.
    """
    if node is None:
        return "<none>"
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def exprs_equal(a: ast.AST, b: ast.AST) -> bool:
    """Structural equality on two AST expressions, ignoring source positions."""
    return normalize_expr(a) == normalize_expr(b)


def iter_calls(node: ast.AST) -> Iterable[ast.Call]:
    """Yield all Call nodes at or under `node`."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            yield child


def unwrap_await(node: ast.AST) -> ast.AST:
    """Return the inner expression of an Await node, else `node` unchanged."""
    if isinstance(node, ast.Await):
        return node.value
    return node


def is_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def literal_bool_value(node: ast.AST) -> Optional[bool]:
    """Return True/False if node is a boolean Constant, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def literal_truthy(node: ast.AST) -> Optional[bool]:
    """Return True/False for a broad set of trivially-truthy/falsy literals.

    Applies to Constant nodes only. Returns None when the truth value is not
    statically determinable at the AST level (e.g. Name, Call, arithmetic).
    """
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.Tuple) and not node.elts:
        return False
    if isinstance(node, ast.List) and not node.elts:
        return False
    if isinstance(node, ast.Dict) and not node.keys:
        return False
    return None


def get_call_target_module(node: ast.Call) -> Optional[str]:
    """For `mod.sub.func(...)`, return the top-level Name id, else None.

    Only returns a value when the callable is an Attribute chain rooted at a
    Name (i.e. explicitly dotted). Bare Name callables like `f()` return None
    because the module-of-origin cannot be inferred from source.
    """
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Attribute):
        return None
    walker = node.func
    while isinstance(walker, ast.Attribute):
        walker = walker.value
    if isinstance(walker, ast.Name):
        return walker.id
    return None


def get_assert_operands(call: ast.Call) -> Optional[tuple]:
    """For an assertEqual-family Call, return (left, right) pair or None.

    Handles positional-arg forms. Ignores keyword arguments (msg=..., etc.).
    Uses positional args 0 and 1 for two-arg asserts (assertEqual etc.),
    position 0 only for one-arg asserts (assertTrue etc.).
    """
    args = [a for a in call.args if not isinstance(a, ast.Starred)]
    return tuple(args)


def is_call_to(node: ast.AST, name: str) -> bool:
    """True if node is a Call whose callable's last-segment name is `name`."""
    return isinstance(node, ast.Call) and get_call_name(node) == name


def find_prev_assign_to(name: str, stmts: list, upto_index: int):
    """Return the ast.Assign node most-recently assigning to Name `name` in
    stmts[:upto_index], or None. Only tracks single-target Assign nodes; does
    not follow control flow.
    """
    for i in range(upto_index - 1, -1, -1):
        stmt = stmts[i]
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            tgt = stmt.targets[0]
            if isinstance(tgt, ast.Name) and tgt.id == name:
                return stmt
        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            tgt = stmt.target
            if isinstance(tgt, ast.Name) and tgt.id == name:
                return stmt
    return None


def call_target_matches(call: ast.Call, sut_module: Optional[str]) -> bool:
    """True when the call's outermost Name matches the SUT module hint.

    If sut_module is None, always returns False (heuristic-off).
    """
    if sut_module is None:
        return False
    top = get_call_target_module(call)
    if top is None:
        return False
    return top == sut_module


def contains_call_to_sut(node: ast.AST, sut_module: Optional[str]) -> bool:
    if sut_module is None:
        return False
    for call in iter_calls(node):
        if call_target_matches(call, sut_module):
            return True
    return False


def contains_reference_to_sut(node: ast.AST, sut_module: Optional[str]) -> bool:
    """True if any Name/Attribute chain under node roots at sut_module.

    Distinct from contains_call_to_sut because this catches attribute reads
    (constants, class attributes) even when no call is made.
    """
    if sut_module is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == sut_module:
            return True
        if isinstance(child, ast.Attribute):
            walker = child
            while isinstance(walker, ast.Attribute):
                walker = walker.value
            if isinstance(walker, ast.Name) and walker.id == sut_module:
                return True
    return False


_BOM = "﻿"


def strip_bom(text: str) -> str:
    if text.startswith(_BOM):
        return text[len(_BOM):]
    return text
