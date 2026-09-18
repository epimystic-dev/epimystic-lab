"""Parsing layer for nbshape: notebook JSON, cell views, and the de-magicking pre-pass.

Everything here is stdlib only (json, ast, re). Nothing executes notebook code
and nothing touches the network.

The de-magicking pre-pass matters more than it looks. Notebook cell source is
NOT valid Python: lines beginning with ``!`` or ``%``, whole cells whose first
line is a ``%%`` cell magic, and the ``?`` / ``??`` help suffixes all raise
SyntaxError in ast.parse. The pre-pass rewrites those lines one-for-one (so
node line numbers still line up with the original source) and reports whether
the cell survived as parseable Python. When it does not, the caller degrades to
textual matching and the scanner emits NBK-015 to say so out loud.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


BOM = chr(0xFEFF)  # zero-width no-break space, the UTF-8 byte-order mark

#: Cell magics whose body IS Python, so the body can still be parsed once the
#: magic line itself is neutralised.
PYTHON_BODIED_CELL_MAGICS = frozenset(
    (
        "time",
        "timeit",
        "capture",
        "prun",
        "debug",
        "pypy",
        "python",
        "python3",
        "memit",
        "snakeviz",
    )
)


def strip_bom(text: str) -> str:
    if text.startswith(BOM):
        return text[1:]
    return text


def offset_to_line_col(text: str, offset: int) -> Tuple[int, int]:
    """Convert a character offset into a 1-indexed (line, column)."""
    if offset < 0:
        offset = 0
    if offset > len(text):
        offset = len(text)
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    if line == 1:
        col = offset + 1
    else:
        col = offset - prefix.rfind("\n")
    return line, col


def locate_literal(text: str, needle: str, from_offset: int = 0) -> Tuple[int, int]:
    """Best-effort 1-indexed (line, column) of a source fragment in the raw .ipynb text.

    The fragment is searched for in its JSON-escaped form first (that is how it
    actually appears on disk), then raw. Returns (1, 1) when not found, which
    is the documented fallback rather than an error.
    """
    if not needle:
        return 1, 1
    candidates = []
    try:
        candidates.append(json.dumps(needle)[1:-1])
    except (TypeError, ValueError):
        pass
    candidates.append(needle)
    for cand in candidates:
        if not cand:
            continue
        idx = text.find(cand, from_offset)
        if idx >= 0:
            return offset_to_line_col(text, idx)
    return 1, 1


def locate_key(text: str, key: str, from_offset: int = 0) -> Tuple[int, int]:
    """Best-effort 1-indexed (line, column) of a JSON key in the raw text."""
    if not key:
        return 1, 1
    idx = text.find('"' + key + '"', from_offset)
    if idx < 0:
        return 1, 1
    return offset_to_line_col(text, idx)


_SHORT_LIMIT = 140


def short(value: Any, limit: int = _SHORT_LIMIT) -> str:
    """Compact single-line rendering of a value for Finding.snippet."""
    if value is None:
        return ""
    s = str(value)
    s = re.sub(r"[\r\n\t]+", " ", s)
    s = s.strip()
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


def redact(value: str, keep: int = 4) -> str:
    """Render a credential-shaped literal without reprinting it.

    nbshape reports the SHAPE of a literal, so echoing the literal back into a
    CI log would defeat the point. Keeps a short head and reports the length.
    """
    if not isinstance(value, str):
        return ""
    if len(value) <= keep:
        return "<" + str(len(value)) + " chars>"
    return value[:keep] + "..." + "<" + str(len(value)) + " chars>"


# ---------------------------------------------------------------------------
# Notebook views
# ---------------------------------------------------------------------------


@dataclass
class CellView:
    """One cell, normalised.

    ``source`` is always a str: nbformat stores it as either a str or a list of
    str (lines with their newlines retained), and both shapes appear in the
    wild.
    """

    index: int
    cell_type: str
    source: str
    execution_count: Any = None
    outputs: Tuple[Any, ...] = field(default_factory=tuple)
    cell_id: Any = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_code(self) -> bool:
        return self.cell_type == "code"

    def first_source_line(self) -> str:
        for ln in self.source.splitlines():
            if ln.strip():
                return ln
        return ""


@dataclass
class NotebookView:
    """A parsed notebook, plus whatever the conformance gate found wrong with it."""

    nbformat: Any = None
    nbformat_minor: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    cells: Tuple[CellView, ...] = field(default_factory=tuple)
    raw: Any = None
    file_bytes: int = 0
    #: Reason the conformance gate rejected this file, or None when it passed.
    gate_reason: Optional[str] = None

    @property
    def conformant(self) -> bool:
        return self.gate_reason is None

    def code_cells(self) -> List[CellView]:
        return [c for c in self.cells if c.is_code]

    def language(self) -> str:
        """Best-effort notebook language, lowercased, or '' when undeclared."""
        li = self.metadata.get("language_info")
        if isinstance(li, dict) and isinstance(li.get("name"), str):
            return li["name"].strip().lower()
        ks = self.metadata.get("kernelspec")
        if isinstance(ks, dict) and isinstance(ks.get("language"), str):
            return ks["language"].strip().lower()
        return ""


def source_to_str(src: Any) -> str:
    """Normalise nbformat's str-or-list-of-str source field to a single str."""
    if isinstance(src, str):
        return src
    if isinstance(src, list):
        parts = [p for p in src if isinstance(p, str)]
        return "".join(parts)
    return ""


def load_json_text(text: str) -> Tuple[Any, Optional[str]]:
    """Parse JSON text. Returns (obj, error_message_or_None). Never raises."""
    text = strip_bom(text)
    if not text.strip():
        return None, "file is empty"
    try:
        return json.loads(text), None
    except RecursionError:
        return None, "JSON nesting is too deep to parse"
    except ValueError as exc:
        return None, "not valid JSON: " + short(exc, 120)
    except TypeError as exc:  # pragma: no cover - defensive
        return None, "not valid JSON: " + short(exc, 120)


def build_notebook(obj: Any, file_bytes: int = 0) -> NotebookView:
    """Build a NotebookView and apply the NBK-010 conformance gate.

    The gate exists because every other rule's field assumptions are unfounded
    on a non-conformant file. A gated file produces exactly one finding
    (NBK-010) and routes to the ``unknown`` verdict, never a cascade of a dozen
    spurious findings off a file the tool cannot reason about.
    """
    nb = NotebookView(raw=obj, file_bytes=file_bytes)
    if not isinstance(obj, dict):
        nb.gate_reason = "top-level JSON value is " + type(obj).__name__ + ", not an object"
        return nb

    nb.nbformat = obj.get("nbformat")
    nb.nbformat_minor = obj.get("nbformat_minor")
    meta = obj.get("metadata")
    nb.metadata = meta if isinstance(meta, dict) else {}

    if "nbformat" not in obj:
        nb.gate_reason = "required top-level key 'nbformat' is absent"
        return nb
    if not isinstance(nb.nbformat, int) or isinstance(nb.nbformat, bool):
        nb.gate_reason = "'nbformat' is " + short(nb.nbformat, 40) + ", not an integer"
        return nb
    if nb.nbformat < 4:
        nb.gate_reason = "'nbformat' is " + str(nb.nbformat) + ", below the version 4 this tool reads"
        return nb
    if "nbformat_minor" not in obj:
        nb.gate_reason = "required top-level key 'nbformat_minor' is absent"
        return nb
    if not isinstance(nb.nbformat_minor, int) or isinstance(nb.nbformat_minor, bool):
        nb.gate_reason = "'nbformat_minor' is " + short(nb.nbformat_minor, 40) + ", not an integer"
        return nb

    cells = obj.get("cells")
    if not isinstance(cells, list):
        nb.gate_reason = "required top-level key 'cells' is absent or not an array"
        return nb

    views: List[CellView] = []
    for i, c in enumerate(cells):
        if not isinstance(c, dict):
            nb.gate_reason = "cells[" + str(i) + "] is " + type(c).__name__ + ", not an object"
            return nb
        ctype = c.get("cell_type")
        if not isinstance(ctype, str):
            nb.gate_reason = "cells[" + str(i) + "] has no string 'cell_type'"
            return nb
        outs = c.get("outputs")
        views.append(
            CellView(
                index=i,
                cell_type=ctype,
                source=source_to_str(c.get("source")),
                execution_count=c.get("execution_count"),
                outputs=tuple(outs) if isinstance(outs, list) else tuple(),
                cell_id=c.get("id"),
                raw=c,
            )
        )
    nb.cells = tuple(views)
    return nb


# ---------------------------------------------------------------------------
# De-magicking pre-pass
# ---------------------------------------------------------------------------


@dataclass
class Demagicked:
    """Result of neutralising IPython magics in one cell's source.

    ``python_source``  line-count-preserving rewrite suitable for ast.parse.
    ``cell_magic``     the ``%%name`` of a cell magic, or '' when there is none.
    ``non_python``     True when the cell is a cell magic whose body is not
                       Python (``%%bash``, ``%%writefile``, ...).
    ``rewritten``      count of lines that were neutralised.
    """

    python_source: str
    cell_magic: str = ""
    non_python: bool = False
    rewritten: int = 0


_HELP_SUFFIX = re.compile(r"^(\s*)([A-Za-z_][\w.]*(?:\([^()]*\))?)\?\??\s*$")
_ASSIGN_MAGIC = re.compile(r"^(\s*)([A-Za-z_]\w*\s*=\s*)[!%].*$")


def _blank_to_pass(indent: str) -> str:
    """A syntactically inert stand-in that preserves indentation and line count."""
    return indent + "pass"


def demagic(source: str) -> Demagicked:
    """Rewrite IPython magic syntax into inert Python, preserving line numbers.

    Handled shapes:
      ``%%name ...`` on the first non-blank line -> whole-cell magic. Python-bodied
        magics (``%%time``, ``%%capture``, ...) keep their body; the rest are
        reported as non-Python so the caller can degrade honestly.
      ``!shell command``            -> ``pass``
      ``%line magic``               -> ``pass``
      ``x = !shell`` / ``x = %magic`` -> ``pass``
      ``name?`` / ``name??``        -> ``pass``

    Every rewrite replaces exactly one line with exactly one line, so an AST
    node's ``lineno`` still indexes the original cell source.
    """
    if not isinstance(source, str) or not source:
        return Demagicked(python_source="")

    lines = source.split("\n")
    cell_magic = ""
    non_python = False
    rewritten = 0

    first_idx = -1
    for i, ln in enumerate(lines):
        if ln.strip():
            first_idx = i
            break

    if first_idx >= 0 and lines[first_idx].lstrip().startswith("%%"):
        head = lines[first_idx].lstrip()[2:].strip()
        cell_magic = head.split()[0] if head.split() else ""
        base = cell_magic.split(".")[0].lower()
        non_python = base not in PYTHON_BODIED_CELL_MAGICS
        lines[first_idx] = _blank_to_pass("")
        rewritten += 1
        if non_python:
            # The body is not Python at all; blank it so a caller that still
            # calls ast.parse gets an empty module rather than a SyntaxError.
            for j in range(first_idx + 1, len(lines)):
                if lines[j].strip():
                    lines[j] = ""
            return Demagicked(
                python_source="\n".join(lines),
                cell_magic=cell_magic,
                non_python=True,
                rewritten=rewritten,
            )

    for i, ln in enumerate(lines):
        stripped = ln.lstrip()
        if not stripped:
            continue
        indent = ln[: len(ln) - len(stripped)]
        if stripped.startswith("!") or stripped.startswith("%"):
            lines[i] = _blank_to_pass(indent)
            rewritten += 1
            continue
        m = _ASSIGN_MAGIC.match(ln)
        if m:
            lines[i] = _blank_to_pass(m.group(1))
            rewritten += 1
            continue
        m = _HELP_SUFFIX.match(ln)
        if m:
            lines[i] = _blank_to_pass(m.group(1))
            rewritten += 1
            continue

    return Demagicked(
        python_source="\n".join(lines),
        cell_magic=cell_magic,
        non_python=non_python,
        rewritten=rewritten,
    )


def parse_python(source: str) -> Tuple[Optional[ast.AST], Optional[str]]:
    """ast.parse a de-magicked cell body. Returns (tree, error_or_None). Never raises."""
    if source is None:
        return None, "no source"
    try:
        return ast.parse(source), None
    except SyntaxError as exc:
        return None, "SyntaxError: " + short(exc.msg if exc.msg else exc, 90)
    except (ValueError, MemoryError, RecursionError) as exc:
        # ValueError covers embedded null bytes; RecursionError covers a
        # pathologically nested expression.
        return None, type(exc).__name__ + ": " + short(exc, 90)


@dataclass
class CellCode:
    """A cell's source in every form the rules need."""

    cell: CellView
    raw_source: str
    demagicked: Demagicked
    tree: Optional[ast.AST] = None
    parse_error: Optional[str] = None

    @property
    def ast_available(self) -> bool:
        return self.tree is not None


def prepare_cell(cell: CellView) -> CellCode:
    """De-magick and parse one code cell, tolerating anything."""
    dm = demagic(cell.source)
    if dm.non_python:
        return CellCode(
            cell=cell,
            raw_source=cell.source,
            demagicked=dm,
            tree=None,
            parse_error="cell magic '%%" + dm.cell_magic + "' body is not Python",
        )
    tree, err = parse_python(dm.python_source)
    return CellCode(
        cell=cell,
        raw_source=cell.source,
        demagicked=dm,
        tree=tree,
        parse_error=err,
    )
