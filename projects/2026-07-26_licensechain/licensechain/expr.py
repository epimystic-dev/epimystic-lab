"""SPDX license expression parser.

Implements the SPDX License Expression grammar (v2.3 spec, section 10.1):

    license-expr        = compound-expr
    compound-expr       = simple-expr
                        | simple-expr "WITH" license-exception-id
                        | compound-expr "AND" compound-expr
                        | compound-expr "OR" compound-expr
                        | "(" compound-expr ")"
    simple-expr         = license-id | license-id "+" | license-ref

Precedence (highest first): "+", "WITH", "AND", "OR".

Operators are case-sensitive per SPDX spec (uppercase AND / OR / WITH).
Identifiers are also case-sensitive.

Semantics of node types:

    LicenseId(id, or_later=False)
        -- simple SPDX id, optionally with "+" trailing (or-later).
    LicenseRef(ref)
        -- "LicenseRef-<idstring>"; opaque reference to a custom license.
    With(base, exception)
        -- base license with a named exception (e.g. Classpath-exception-2.0).
    And(left, right)
        -- combined work must comply with both licenses.
    Or(left, right)
        -- user may choose either license (dual-licensed).
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Union, Iterator, List, Set


class ParseError(ValueError):
    """Raised when an SPDX expression is malformed."""

    def __init__(self, message: str, position: int = -1):
        super().__init__(message)
        self.position = position


@dataclass(frozen=True)
class LicenseId:
    spdx_id: str
    or_later: bool = False

    def __str__(self) -> str:
        return f"{self.spdx_id}+" if self.or_later else self.spdx_id


@dataclass(frozen=True)
class LicenseRef:
    ref: str  # includes the "LicenseRef-" prefix; may include "DocumentRef-"

    def __str__(self) -> str:
        return self.ref


@dataclass(frozen=True)
class With:
    base: "Expr"
    exception: str

    def __str__(self) -> str:
        return f"{self.base} WITH {self.exception}"


@dataclass(frozen=True)
class And:
    left: "Expr"
    right: "Expr"

    def __str__(self) -> str:
        return f"({self.left} AND {self.right})"


@dataclass(frozen=True)
class Or:
    left: "Expr"
    right: "Expr"

    def __str__(self) -> str:
        return f"({self.left} OR {self.right})"


Expr = Union[LicenseId, LicenseRef, With, And, Or]


# --------- Lexer -----------------------------------------------------------

class _Token:
    __slots__ = ("kind", "value", "pos")

    def __init__(self, kind: str, value: str, pos: int):
        self.kind = kind
        self.value = value
        self.pos = pos

    def __repr__(self):  # pragma: no cover -- debug only
        return f"Token({self.kind!r}, {self.value!r}, {self.pos})"


_KEYWORDS = {"AND", "OR", "WITH"}
_ID_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789.-"
)


def _tokenize(source: str) -> List[_Token]:
    tokens: List[_Token] = []
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(_Token("LPAREN", "(", i))
            i += 1
            continue
        if c == ")":
            tokens.append(_Token("RPAREN", ")", i))
            i += 1
            continue
        if c == "+":
            tokens.append(_Token("PLUS", "+", i))
            i += 1
            continue
        if c in _ID_CHARS:
            start = i
            while i < n and source[i] in _ID_CHARS:
                i += 1
            word = source[start:i]
            if word in _KEYWORDS:
                tokens.append(_Token(word, word, start))
            else:
                tokens.append(_Token("ID", word, start))
            continue
        raise ParseError(
            f"unexpected character {c!r} at position {i}", position=i
        )
    tokens.append(_Token("EOF", "", n))
    return tokens


# --------- Parser (recursive descent) -------------------------------------

class _Parser:

    def __init__(self, tokens: List[_Token], source: str):
        self._tokens = tokens
        self._i = 0
        self._source = source

    def _peek(self) -> _Token:
        return self._tokens[self._i]

    def _eat(self, kind: str) -> _Token:
        tok = self._tokens[self._i]
        if tok.kind != kind:
            raise ParseError(
                f"expected {kind} but got {tok.kind} ({tok.value!r}) "
                f"at position {tok.pos}",
                position=tok.pos,
            )
        self._i += 1
        return tok

    # OR is lowest precedence.
    def parse(self) -> Expr:
        expr = self._parse_or()
        tok = self._peek()
        if tok.kind != "EOF":
            raise ParseError(
                f"unexpected trailing token {tok.value!r} at position "
                f"{tok.pos}",
                position=tok.pos,
            )
        return expr

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._peek().kind == "OR":
            self._eat("OR")
            right = self._parse_and()
            left = Or(left, right)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_with()
        while self._peek().kind == "AND":
            self._eat("AND")
            right = self._parse_with()
            left = And(left, right)
        return left

    def _parse_with(self) -> Expr:
        base = self._parse_atom()
        if self._peek().kind == "WITH":
            self._eat("WITH")
            exc_tok = self._peek()
            if exc_tok.kind != "ID":
                raise ParseError(
                    "expected exception identifier after WITH at "
                    f"position {exc_tok.pos}",
                    position=exc_tok.pos,
                )
            self._eat("ID")
            return With(base, exc_tok.value)
        return base

    def _parse_atom(self) -> Expr:
        tok = self._peek()
        if tok.kind == "LPAREN":
            self._eat("LPAREN")
            inner = self._parse_or()
            self._eat("RPAREN")
            return inner
        if tok.kind == "ID":
            self._eat("ID")
            # + is allowed after a simple id (or-later marker) but NOT after
            # a LicenseRef- token per SPDX 10.1 spec.
            if tok.value.startswith("LicenseRef-") \
                    or tok.value.startswith("DocumentRef-"):
                if self._peek().kind == "PLUS":
                    raise ParseError(
                        "'+' or-later marker is not permitted on a "
                        f"LicenseRef at position {self._peek().pos}",
                        position=self._peek().pos,
                    )
                return LicenseRef(tok.value)
            or_later = False
            if self._peek().kind == "PLUS":
                self._eat("PLUS")
                or_later = True
            return LicenseId(tok.value, or_later=or_later)
        raise ParseError(
            f"expected license identifier at position {tok.pos}, got "
            f"{tok.kind}",
            position=tok.pos,
        )


def parse_expr(source: str) -> Expr:
    """Parse an SPDX license expression string into an AST."""
    if source is None or not isinstance(source, str):
        raise ParseError("license expression must be a string")
    stripped = source.strip()
    if not stripped:
        raise ParseError("license expression is empty")
    tokens = _tokenize(stripped)
    parser = _Parser(tokens, stripped)
    return parser.parse()


# --------- AST introspection helpers --------------------------------------

def iter_leaves(expr: Expr) -> Iterator[Union[LicenseId, LicenseRef]]:
    """Yield every leaf LicenseId / LicenseRef in the expression, left-to-right.

    Semantics: this ignores AND/OR structure; use it when you want the set
    of licenses named at all, not the effective compatibility. For
    compatibility reasoning use canonical_choices() below.
    """
    if isinstance(expr, (LicenseId, LicenseRef)):
        yield expr
    elif isinstance(expr, With):
        yield from iter_leaves(expr.base)
    elif isinstance(expr, (And, Or)):
        yield from iter_leaves(expr.left)
        yield from iter_leaves(expr.right)
    else:  # pragma: no cover
        raise TypeError(f"unexpected AST node {type(expr).__name__}")


def collect_ids(expr: Expr) -> Set[str]:
    """Return the set of spdx_id strings appearing in the expression."""
    return {leaf.spdx_id for leaf in iter_leaves(expr)
            if isinstance(leaf, LicenseId)}


def collect_refs(expr: Expr) -> Set[str]:
    """Return the set of LicenseRef- ref strings appearing in the expression."""
    return {leaf.ref for leaf in iter_leaves(expr)
            if isinstance(leaf, LicenseRef)}


def canonical_choices(expr: Expr) -> List[List[Expr]]:
    """Convert an expression into disjunctive normal form: a list of AND-
    clauses, any one of which the downstream may pick.

    Example:
        parse_expr("(MIT OR Apache-2.0) AND CC-BY-4.0")
        -> [[MIT, CC-BY-4.0], [Apache-2.0, CC-BY-4.0]]

    This is the shape that rules.py wants when reasoning about obligation
    propagation: each choice is one legal ways to comply.
    """
    if isinstance(expr, Or):
        return canonical_choices(expr.left) + canonical_choices(expr.right)
    if isinstance(expr, And):
        left = canonical_choices(expr.left)
        right = canonical_choices(expr.right)
        return [lc + rc for lc in left for rc in right]
    # Leaf or WITH -- singleton choice, single clause of one term.
    return [[expr]]
