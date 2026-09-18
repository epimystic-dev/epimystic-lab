"""Rule table for nbshape.

Every rule flags a SHAPE in the stored notebook JSON. It never claims that the
notebook will fail to run, never claims an attack, and never certifies that a
notebook reproduces - nbshape executes nothing. The rules are grounded in the
nbformat v4 JSON schema and in the defects that the cited reproducibility
studies measured BY EXECUTION; nbshape only reports the stored-file shapes that
those studies found co-occurring with execution failure.

Rule severities:
  HIGH    the file contradicts itself - the stored record cannot be true as written
  MEDIUM  a shape that makes the stored record incomplete or order-dependent
  INFO    an observation, or a disclosure about nbshape's own coverage
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .parse import (
    CellCode,
    CellView,
    NotebookView,
    locate_key,
    locate_literal,
    redact,
    short,
)
from .types import NOTEBOOK_LEVEL, Finding, Severity


# ---------------------------------------------------------------------------
# Configuration and context
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleConfig:
    """Thresholds a caller can move. Defaults are documented in the README."""

    #: NBK-004 fires when max(execution_count) > code_cell_count * this factor.
    rerun_factor: float = 2.0
    #: NBK-006 source half: minimum string-literal length to be credential-shaped.
    min_literal_len: int = 16
    #: NBK-006 output half: minimum token length for the entropy scan.
    entropy_min_len: int = 32
    #: NBK-006 output half: minimum Shannon entropy in bits per character.
    entropy_min_bits: float = 3.8
    #: NBK-011 absolute payload threshold in bytes.
    max_output_bytes: int = 2 * 1024 * 1024
    #: NBK-011 relative trigger: file must be at least this big for the ratio to count.
    bloat_min_file_bytes: int = 256 * 1024
    #: NBK-011 relative trigger: payload share of total file size.
    bloat_ratio: float = 0.5


@dataclass
class RuleContext:
    """Everything a rule is allowed to look at."""

    nb: NotebookView
    text: str
    path: str
    codes: Tuple[CellCode, ...] = field(default_factory=tuple)
    config: RuleConfig = field(default_factory=RuleConfig)

    def code_by_index(self) -> Dict[int, CellCode]:
        return {c.cell.index: c for c in self.codes}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    check_fn: Callable[[RuleContext], List[Finding]]
    #: A gate rule short-circuits the whole file: when it fires, no other rule
    #: runs and the file routes to the ``unknown`` verdict.
    gate: bool = False
    #: Gate findings stay visible even without --include-info, because hiding
    #: the reason a file could not be scored would be dishonest.
    always_visible: bool = False


def _emit(rule: Rule, ctx: RuleContext, cell: int, line: int, col: int,
          message: str, snippet: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        path=ctx.path,
        cell=cell,
        line=line,
        column=col,
        message=message,
        snippet=snippet,
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character. Returns 0.0 for the empty string."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = float(len(s))
    total = 0.0
    for c in counts.values():
        p = c / n
        total -= p * math.log(p, 2)
    return total


def _is_python_notebook(nb: NotebookView) -> bool:
    lang = nb.language()
    return lang == "" or lang.startswith("python")


def _source_lines(cell: CellView):
    """Yield (1-indexed line number, text) over a cell's source."""
    for i, ln in enumerate(cell.source.split("\n"), start=1):
        yield i, ln


def _pos(ctx: RuleContext, fragment: str) -> Tuple[int, int]:
    return locate_literal(ctx.text, fragment)


def _non_null_counts(nb: NotebookView) -> List[Tuple[int, int]]:
    """(cell_index, execution_count) for code cells with an integer count."""
    out: List[Tuple[int, int]] = []
    for c in nb.code_cells():
        ec = c.execution_count
        if isinstance(ec, bool):
            continue
        if isinstance(ec, int):
            out.append((c.index, ec))
    return out


def _has_outputs(cell: CellView) -> bool:
    return len(cell.outputs) > 0


def _is_stripped(nb: NotebookView) -> bool:
    """True when every code cell has a null execution_count and no outputs."""
    code = nb.code_cells()
    if not code:
        return False
    for c in code:
        if c.execution_count is not None:
            return False
        if _has_outputs(c):
            return False
    return True


# ---------------------------------------------------------------------------
# NBK-001  execution order
# ---------------------------------------------------------------------------


def _rule_001(ctx: RuleContext) -> List[Finding]:
    nb = ctx.nb
    pairs = _non_null_counts(nb)
    if len(pairs) < 2:
        # Zero, one, or all-null counts: absence of evidence, not a finding.
        return []
    inversions: List[Tuple[Tuple[int, int], Tuple[int, int]]] = []
    for i in range(1, len(pairs)):
        if pairs[i][1] <= pairs[i - 1][1]:
            inversions.append((pairs[i - 1], pairs[i]))
    if not inversions:
        return []
    (prev_idx, prev_ec), (cur_idx, cur_ec) = inversions[0]
    cell = nb.cells[cur_idx]
    line, col = _pos(ctx, cell.first_source_line())
    msg = (
        "execution_count over code cells is not strictly increasing in storage order: "
        "cell " + str(cur_idx) + " records [" + str(cur_ec) + "] after cell " +
        str(prev_idx) + " records [" + str(prev_ec) + "]"
    )
    if len(inversions) > 1:
        msg += " (first of " + str(len(inversions)) + " inversions)"
    else:
        msg += " (1 inversion)"
    msg += "; the stored order is not the order the file records having run"
    return [_emit(_RULE_001, ctx, cur_idx, line, col, msg, short(cell.first_source_line()))]


# ---------------------------------------------------------------------------
# NBK-002  outputs with a null execution_count
# ---------------------------------------------------------------------------


def _rule_002(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.nb.code_cells():
        if c.execution_count is None and _has_outputs(c):
            line, col = _pos(ctx, c.first_source_line())
            out.append(_emit(
                _RULE_002, ctx, c.index, line, col,
                "code cell " + str(c.index) + " carries " + str(len(c.outputs)) +
                " output(s) but execution_count is null; the output was retained from a "
                "kernel run that this file no longer describes",
                short(c.first_source_line()),
            ))
    return out


# ---------------------------------------------------------------------------
# NBK-003  duplicate execution counters
# ---------------------------------------------------------------------------


def _rule_003(ctx: RuleContext) -> List[Finding]:
    pairs = _non_null_counts(ctx.nb)
    seen: Dict[int, int] = {}
    out: List[Finding] = []
    for idx, ec in pairs:
        if ec in seen:
            cell = ctx.nb.cells[idx]
            line, col = _pos(ctx, cell.first_source_line())
            out.append(_emit(
                _RULE_003, ctx, idx, line, col,
                "code cells " + str(seen[ec]) + " and " + str(idx) +
                " both record execution_count [" + str(ec) + "]; a kernel counter is "
                "monotonic, so the file contradicts itself",
                short(cell.first_source_line()),
            ))
        else:
            seen[ec] = idx
    return out


# ---------------------------------------------------------------------------
# NBK-004  counter ran past the stored cell count
# ---------------------------------------------------------------------------


def _rule_004(ctx: RuleContext) -> List[Finding]:
    pairs = _non_null_counts(ctx.nb)
    if not pairs:
        return []
    n_code = len(ctx.nb.code_cells())
    if n_code < 1:
        return []
    max_ec = max(ec for _, ec in pairs)
    threshold = n_code * ctx.config.rerun_factor
    if max_ec <= threshold:
        return []
    line, col = locate_key(ctx.text, "execution_count")
    return [_emit(
        _RULE_004, ctx, NOTEBOOK_LEVEL, line, col,
        "the kernel counter reached [" + str(max_ec) + "] against " + str(n_code) +
        " stored code cell(s), above the reporting factor of " +
        ("%g" % ctx.config.rerun_factor) + "; cells were re-run, deleted, or both. This "
        "is an observation about the stored record, not a defect - iterative work "
        "produces it normally",
        "max_execution_count=" + str(max_ec) + " code_cells=" + str(n_code),
    )]


# ---------------------------------------------------------------------------
# NBK-005 / NBK-016  path literals
# ---------------------------------------------------------------------------


_DRIVE_PATH = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]:[\\/][^\s\"'<>|`]+)")
_HOME_PATH = re.compile(r"(/(?:home|Users|users)/([A-Za-z0-9_.\-]+)(?:/[^\s\"'<>|`]*)?)")
_MNT_PATH = re.compile(r"(/mnt/([A-Za-z0-9_.\-]+)(?:/[^\s\"'<>|`]*)?)")
_HOSTED_PATH = re.compile(
    r"(/(?:content|gdrive|kaggle/input|kaggle/working|workspace/\.\w+)"
    r"(?:/[^\s\"'<>|`]*)?)"
)

#: Names that read as a documentation placeholder rather than a real account.
#: Excluding them is a deliberate, documented false negative.
_PLACEHOLDER_USERS = frozenset(
    (
        "user", "username", "youruser", "your_user", "your-user", "yourname",
        "myuser", "me", "name", "placeholder", "someone", "example",
    )
)
_PLACEHOLDER_MOUNTS = frozenset(("data",))


def _rule_005(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for code in ctx.codes:
        cell = code.cell
        for lineno, ln in _source_lines(cell):
            for m in _DRIVE_PATH.finditer(ln):
                frag = m.group(1)
                if len(frag) < 4:
                    continue
                line, col = _pos(ctx, ln.strip() or frag)
                out.append(_emit(
                    _RULE_005, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " line " + str(lineno) +
                    " contains a drive-letter absolute path literal " + short(frag, 80) +
                    "; the literal names a location only this machine has",
                    short(ln),
                ))
            for m in _HOME_PATH.finditer(ln):
                frag, who = m.group(1), m.group(2)
                if who.lower() in _PLACEHOLDER_USERS:
                    continue
                line, col = _pos(ctx, ln.strip() or frag)
                out.append(_emit(
                    _RULE_005, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " line " + str(lineno) +
                    " contains a home-directory absolute path literal " + short(frag, 80) +
                    "; the literal names an account only this machine has",
                    short(ln),
                ))
            for m in _MNT_PATH.finditer(ln):
                frag, who = m.group(1), m.group(2)
                if who.lower() in _PLACEHOLDER_MOUNTS:
                    continue
                line, col = _pos(ctx, ln.strip() or frag)
                out.append(_emit(
                    _RULE_005, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " line " + str(lineno) +
                    " contains a mount-point absolute path literal " + short(frag, 80) +
                    "; the literal names a mount only this machine has",
                    short(ln),
                ))
    return out


def _rule_016(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for code in ctx.codes:
        cell = code.cell
        for lineno, ln in _source_lines(cell):
            for m in _HOSTED_PATH.finditer(ln):
                frag = m.group(1)
                line, col = _pos(ctx, ln.strip() or frag)
                out.append(_emit(
                    _RULE_016, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " line " + str(lineno) +
                    " contains a hosted-runtime path literal " + short(frag, 80) +
                    "; that mount is standard inside the hosting environment and portable "
                    "there, but absent on a local checkout",
                    short(ln),
                ))
    return out


# ---------------------------------------------------------------------------
# NBK-006  credential-shaped literals
# ---------------------------------------------------------------------------


_CRED_NAME = re.compile(
    r"(?:^|_)(?:api[_-]?key|apikey|secret|secrets|token|password|passwd|pwd|"
    r"access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth|"
    r"credential|credentials|bearer|session[_-]?key|sas[_-]?token)(?:$|_)",
    re.IGNORECASE,
)
_CRED_NAME_LOOSE = re.compile(
    r"(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|bearer)",
    re.IGNORECASE,
)
_PLACEHOLDER_VALUE = re.compile(
    r"^(?:your|my|the)?[_\- ]?(?:x{3,}|\.{3,}|\*{3,}|changeme|change[_-]?me|"
    r"placeholder|insert|paste|todo|tbd|none|null|nil|example|dummy|fake|sample|"
    r"replace|redacted|hidden|secret[_-]?here|api[_-]?key[_-]?here|<.*>|\{\{.*\}\})",
    re.IGNORECASE,
)
_ENV_REF = re.compile(r"\$\{?\w+|os\.environ|getenv|dotenv|<[^>]+>|\{\{.*\}\}")
_ASSIGN_TEXT = re.compile(
    r"^\s*([A-Za-z_][\w.\[\]'\"]*)\s*(?::\s*[\w\[\], .]+)?=\s*"
    r"(?P<q>['\"])(?P<val>(?:(?!(?P=q)).)*)(?P=q)"
)


def _looks_like_credential_value(val: str, min_len: int) -> bool:
    if not isinstance(val, str):
        return False
    s = val.strip()
    if len(s) < min_len:
        return False
    if _PLACEHOLDER_VALUE.match(s):
        return False
    if _ENV_REF.search(s):
        return False
    if len(set(s)) <= 3:
        return False
    if " " in s:
        # A sentence, a prompt, a path with spaces - not a token shape.
        return False
    if s.startswith("http://") or s.startswith("https://"):
        return False
    if "/" in s and s.count("/") >= 2 and not s.startswith("ey"):
        # Looks like a path rather than an opaque token.
        return False
    return True


def _ast_cred_hits(tree: ast.AST, min_len: int):
    """Yield (name, value, lineno) for credential-shaped bindings in a parsed cell."""
    for node in ast.walk(tree):
        targets: List[Tuple[str, Any, int]] = []
        if isinstance(node, ast.Assign):
            for t in node.targets:
                nm = _target_name(t)
                if nm:
                    targets.append((nm, node.value, getattr(node, "lineno", 1)))
        elif isinstance(node, ast.AnnAssign):
            nm = _target_name(node.target)
            if nm and node.value is not None:
                targets.append((nm, node.value, getattr(node, "lineno", 1)))
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg:
                    targets.append((kw.arg, kw.value, getattr(node, "lineno", 1)))
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    targets.append((k.value, v, getattr(node, "lineno", 1)))
        for name, value_node, lineno in targets:
            if not _CRED_NAME.search(name) and not _CRED_NAME_LOOSE.search(name):
                continue
            if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                if _looks_like_credential_value(value_node.value, min_len):
                    yield name, value_node.value, lineno


def _target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
    return ""


_TOKEN_SHAPE = re.compile(r"[A-Za-z0-9_\-+/=.]{24,}")
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_DIGIT_ONLY = re.compile(r"^[0-9.eE+\-]+$")

#: Output mime keys whose values are safe to entropy-scan. Everything else -
#: notably image/png, image/jpeg and application/pdf - is a base64 blob that is
#: high-entropy by construction, so scanning it would flag every notebook that
#: plots anything.
ENTROPY_SAFE_MIME = frozenset(("text/plain",))


def _entropy_candidates(cell: CellView):
    """Yield (text, where) for the output text nbshape is allowed to entropy-scan."""
    for i, out in enumerate(cell.outputs):
        if not isinstance(out, dict):
            continue
        otype = out.get("output_type")
        if otype == "stream":
            name = out.get("name")
            if name not in ("stdout", "stderr"):
                continue
            txt = out.get("text")
            if isinstance(txt, list):
                txt = "".join(p for p in txt if isinstance(p, str))
            if isinstance(txt, str) and txt:
                yield txt, "outputs[" + str(i) + "].text (stream " + str(name) + ")"
        elif otype in ("display_data", "execute_result"):
            data = out.get("data")
            if not isinstance(data, dict):
                continue
            for mime, val in data.items():
                if mime not in ENTROPY_SAFE_MIME:
                    continue
                if isinstance(val, list):
                    val = "".join(p for p in val if isinstance(p, str))
                if isinstance(val, str) and val:
                    yield val, "outputs[" + str(i) + "].data['" + str(mime) + "']"


def _high_entropy_tokens(text: str, min_len: int, min_bits: float) -> List[str]:
    hits: List[str] = []
    for m in _TOKEN_SHAPE.finditer(text):
        tok = m.group(0)
        if len(tok) < min_len:
            continue
        if _HEX_ONLY.match(tok):
            # A git sha or a checksum printed by a cell. Documented false negative.
            continue
        if _DIGIT_ONLY.match(tok):
            continue
        if not any(ch.isdigit() for ch in tok):
            continue
        if not any(ch.isalpha() for ch in tok):
            continue
        has_case_mix = any(ch.islower() for ch in tok) and any(ch.isupper() for ch in tok)
        has_sep = "-" in tok or "_" in tok or "." in tok
        if not (has_case_mix or has_sep):
            continue
        if shannon_entropy(tok) < min_bits:
            continue
        hits.append(tok)
    return hits


def _rule_006(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    cfg = ctx.config
    for code in ctx.codes:
        cell = code.cell
        if code.ast_available and code.tree is not None:
            for name, val, lineno in _ast_cred_hits(code.tree, cfg.min_literal_len):
                src_lines = cell.source.split("\n")
                anchor = src_lines[lineno - 1] if 0 < lineno <= len(src_lines) else name
                line, col = _pos(ctx, anchor.strip() or name)
                out.append(_emit(
                    _RULE_006, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " binds '" + name +
                    "' to a credential-shaped string literal of " + str(len(val)) +
                    " characters (" + redact(val) + "); this is a literal SHAPE, not a "
                    "verified secret",
                    "<literal redacted>",
                ))
        else:
            for lineno, ln in _source_lines(cell):
                m = _ASSIGN_TEXT.match(ln)
                if not m:
                    continue
                name = m.group(1)
                val = m.group("val")
                if not _CRED_NAME.search(name) and not _CRED_NAME_LOOSE.search(name):
                    continue
                if not _looks_like_credential_value(val, cfg.min_literal_len):
                    continue
                line, col = _pos(ctx, ln.strip())
                out.append(_emit(
                    _RULE_006, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " binds '" + name +
                    "' to a credential-shaped string literal of " + str(len(val)) +
                    " characters (" + redact(val) + "), matched textually because this "
                    "cell did not parse as Python; this is a literal SHAPE, not a "
                    "verified secret",
                    "<literal redacted>",
                ))
        for text, where in _entropy_candidates(cell):
            toks = _high_entropy_tokens(text, cfg.entropy_min_len, cfg.entropy_min_bits)
            for tok in toks[:3]:
                line, col = _pos(ctx, tok)
                out.append(_emit(
                    _RULE_006, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " " + where +
                    " contains a high-entropy token-shaped string of " + str(len(tok)) +
                    " characters (" + redact(tok) + "); committed output can carry a "
                    "credential the source never showed. This is a SHAPE, not a verified "
                    "secret",
                    "<token redacted>",
                ))
    return out


# ---------------------------------------------------------------------------
# NBK-007  unpinned installs
# ---------------------------------------------------------------------------


_INSTALL_LINE = re.compile(
    r"^\s*[!%]\s*(?:(?:python|python3|py)\s+-m\s+)?"
    r"(?P<tool>pip3?|conda|mamba|uv)\s+(?:pip\s+)?install\s+(?P<rest>.*)$"
)
_BARE_INSTALL_LINE = re.compile(
    r"^\s*(?:(?:python|python3|py)\s+-m\s+)?"
    r"(?P<tool>pip3?|conda|mamba)\s+(?:pip\s+)?install\s+(?P<rest>.*)$"
)
_FLAGS_TAKING_VALUE = frozenset(
    (
        "-r", "--requirement", "-i", "--index-url", "--extra-index-url",
        "-f", "--find-links", "-c", "--constraint", "--target", "-t",
        "--proxy", "--trusted-host", "--python-version", "--platform",
        "--abi", "--implementation", "--prefix", "--root", "--report",
        "--cache-dir", "--log", "--n", "--name", "--channel", "--prefix",
    )
)
_REQ_FLAGS = frozenset(("-r", "--requirement", "-c", "--constraint"))
_SPEC_MARKERS = ("==", ">=", "<=", "~=", "!=", "===", "@", "<", ">")
_URLISH = ("http://", "https://", "git+", "file://", "ssh://", "./", "../", "/")


def _install_targets(rest: str) -> Tuple[List[str], bool]:
    """Split an install command tail into package tokens.

    Returns (unpinned_tokens, pinned_by_reference). A command using ``-r`` or
    ``-c`` is pinned by reference to a requirements or constraints file and is
    never reported.
    """
    rest = rest.split("#", 1)[0]
    rest = rest.split(";")[0] if rest.strip().endswith(";") else rest
    toks = rest.replace("\\\n", " ").split()
    unpinned: List[str] = []
    skip_next = False
    for tok in toks:
        if skip_next:
            skip_next = False
            continue
        if tok in _REQ_FLAGS:
            return [], True
        if tok.startswith("-"):
            base = tok.split("=", 1)[0]
            if base in _REQ_FLAGS:
                return [], True
            if base in _FLAGS_TAKING_VALUE and "=" not in tok:
                skip_next = True
            continue
        clean = tok.strip("'\"")
        if not clean or clean == ".":
            continue
        low = clean.lower()
        if any(low.startswith(p) for p in _URLISH):
            continue
        if low.endswith(".whl") or low.endswith(".tar.gz") or low.endswith(".zip"):
            continue
        if any(mk in clean for mk in _SPEC_MARKERS):
            continue
        if "=" in clean:
            # conda's single-equals pin, e.g. numpy=1.26
            continue
        unpinned.append(clean)
    return unpinned, False


def _rule_007(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for code in ctx.codes:
        cell = code.cell
        shellish = code.demagicked.non_python
        for lineno, ln in _source_lines(cell):
            m = _INSTALL_LINE.match(ln)
            if m is None and shellish:
                m = _BARE_INSTALL_LINE.match(ln)
            if m is None:
                continue
            unpinned, by_ref = _install_targets(m.group("rest"))
            if by_ref or not unpinned:
                continue
            line, col = _pos(ctx, ln.strip())
            out.append(_emit(
                _RULE_007, ctx, cell.index, line, col,
                "cell " + str(cell.index) + " line " + str(lineno) + " installs " +
                ", ".join(sorted(unpinned)[:6]) + " with no version specifier; the "
                "dependency set this notebook ran against is not recoverable from the file",
                short(ln),
            ))
    return out


# ---------------------------------------------------------------------------
# NBK-008  sampling without a visible seed
# ---------------------------------------------------------------------------


_SAMPLING_PATTERNS: Sequence[Tuple[Any, str]] = (
    (re.compile(
        r"\brandom\.(?:random|randint|randrange|sample|shuffle|choice|choices|"
        r"uniform|gauss|normalvariate|betavariate|expovariate|triangular|"
        r"paretovariate|weibullvariate|getrandbits)\s*\("), "random"),
    (re.compile(
        r"\b(?:np|numpy)\.random\.(?:rand|randn|randint|random|random_sample|"
        r"ranf|sample|choice|permutation|shuffle|normal|uniform|binomial|poisson|"
        r"standard_normal|multivariate_normal|beta|gamma|exponential|RandomState)\s*\("),
     "numpy.random"),
    (re.compile(r"\b(?:np\.random\.|numpy\.random\.)?default_rng\s*\(\s*\)"),
     "default_rng() with no seed"),
    (re.compile(
        r"\btorch\.(?:rand|randn|randint|randperm|normal|rand_like|randn_like|"
        r"randint_like|bernoulli|multinomial|poisson)\s*\("), "torch"),
    (re.compile(r"\btf\.random\.\w+\s*\("), "tf.random"),
    (re.compile(r"\bDataLoader\s*\([^)]*\bshuffle\s*=\s*True"), "DataLoader(shuffle=True)"),
)
_TTS = re.compile(r"\btrain_test_split\s*\(")
_SEED_PATTERNS: Sequence[Any] = (
    re.compile(r"\brandom\.seed\s*\("),
    re.compile(r"\b(?:np|numpy)\.random\.seed\s*\("),
    re.compile(r"\bdefault_rng\s*\(\s*[^)\s]"),
    re.compile(r"\btorch\.manual_seed\s*\("),
    re.compile(r"\btorch\.cuda\.manual_seed(?:_all)?\s*\("),
    re.compile(r"\btorch\.use_deterministic_algorithms\s*\("),
    re.compile(r"\btf\.random\.set_seed\s*\("),
    re.compile(r"\btf\.set_random_seed\s*\("),
    re.compile(r"\b(?:pl\.|pytorch_lightning\.|lightning\.)?seed_everything\s*\("),
    re.compile(r"\bset_seed\s*\("),
    re.compile(r"\brandom_state\s*="),
    re.compile(r"\bPYTHONHASHSEED\b"),
    re.compile(r"\bRandomState\s*\(\s*[0-9]"),
)


def _rule_008(ctx: RuleContext) -> List[Finding]:
    hits: List[Tuple[int, int, str, str]] = []
    seeds = 0
    for code in ctx.codes:
        cell = code.cell
        for lineno, ln in _source_lines(cell):
            for pat in _SEED_PATTERNS:
                if pat.search(ln):
                    seeds += 1
            for pat, label in _SAMPLING_PATTERNS:
                if pat.search(ln):
                    hits.append((cell.index, lineno, label, ln))
            for m in _TTS.finditer(ln):
                window = ln[m.end():m.end() + 240]
                if "random_state" not in window:
                    hits.append((cell.index, lineno, "train_test_split without random_state", ln))
    if not hits or seeds > 0:
        return []
    cell_idx, lineno, label, ln = hits[0]
    line, col = _pos(ctx, ln.strip())
    labels = sorted({h[2] for h in hits})
    return [_emit(
        _RULE_008, ctx, cell_idx, line, col,
        "sampling API calls are present (" + ", ".join(labels[:4]) +
        ") and no seeding call is visible in any cell; first at cell " + str(cell_idx) +
        " line " + str(lineno) + ". This is a textual name-shape match: seeding done "
        "inside an imported helper, a %run, or a parameters cell is invisible to nbshape, "
        "so absence of a visible seed is not evidence of non-determinism",
        short(ln),
    )]


# ---------------------------------------------------------------------------
# NBK-009  kernel metadata coherence
# ---------------------------------------------------------------------------


_PY_KERNEL_NAME = re.compile(r"^python(\d+)$", re.IGNORECASE)


def _rule_009(ctx: RuleContext) -> List[Finding]:
    meta = ctx.nb.metadata
    out: List[Finding] = []
    ks = meta.get("kernelspec")
    li = meta.get("language_info")
    ks_ok = isinstance(ks, dict)
    li_ok = isinstance(li, dict)

    missing = []
    if not ks_ok:
        missing.append("metadata.kernelspec")
    if not li_ok:
        missing.append("metadata.language_info")
    if missing:
        line, col = locate_key(ctx.text, "metadata")
        out.append(_emit(
            _RULE_009, ctx, NOTEBOOK_LEVEL, line, col,
            " and ".join(missing) + " is absent; the interpreter this notebook ran under "
            "is undeclared in the file",
            "metadata keys: " + short(", ".join(sorted(meta.keys())) or "<none>", 80),
        ))
        return out

    ks_lang = ks.get("language")
    li_name = li.get("name")
    if isinstance(ks_lang, str) and isinstance(li_name, str):
        if ks_lang.strip().lower() != li_name.strip().lower():
            line, col = locate_key(ctx.text, "language_info")
            out.append(_emit(
                _RULE_009, ctx, NOTEBOOK_LEVEL, line, col,
                "metadata.language_info.name is '" + li_name +
                "' but metadata.kernelspec.language is '" + ks_lang +
                "'; the two declarations disagree",
                "kernelspec.language=" + short(ks_lang, 30) + " language_info.name=" +
                short(li_name, 30),
            ))

    ks_name = ks.get("name")
    li_ver = li.get("version")
    if isinstance(ks_name, str) and isinstance(li_ver, str):
        m = _PY_KERNEL_NAME.match(ks_name.strip())
        if m:
            want = m.group(1)
            major = li_ver.strip().split(".")[0]
            if major and major.isdigit() and major != want:
                line, col = locate_key(ctx.text, "kernelspec")
                out.append(_emit(
                    _RULE_009, ctx, NOTEBOOK_LEVEL, line, col,
                    "metadata.kernelspec.name is '" + ks_name +
                    "' but metadata.language_info.version is '" + li_ver +
                    "'; the kernel name is only a display string, so this inference is "
                    "weak - treat it as a prompt to check, not a defect",
                    "kernelspec.name=" + short(ks_name, 30) + " version=" + short(li_ver, 30),
                ))
    return out


# ---------------------------------------------------------------------------
# NBK-010  conformance gate
# ---------------------------------------------------------------------------


def _rule_010(ctx: RuleContext) -> List[Finding]:
    reason = ctx.nb.gate_reason
    if not reason:
        return []
    line, col = locate_key(ctx.text, "nbformat")
    return [_emit(
        _RULE_010, ctx, NOTEBOOK_LEVEL, line, col,
        "not a schema-conformant nbformat v4 notebook: " + reason +
        "; every other rule's field assumptions are unfounded here, so nbshape scored "
        "no rule against this file and reports it as unknown",
        short(reason, 120),
    )]


# ---------------------------------------------------------------------------
# NBK-011  committed output payload
# ---------------------------------------------------------------------------


def _payload_bytes(nb: NotebookView) -> Tuple[int, str]:
    total = 0
    biggest_mime = ""
    biggest = 0
    for c in nb.code_cells():
        for out in c.outputs:
            if not isinstance(out, dict):
                continue
            data = out.get("data")
            if not isinstance(data, dict):
                continue
            for mime, val in data.items():
                if not isinstance(mime, str) or mime.startswith("text/"):
                    continue
                if isinstance(val, list):
                    n = sum(len(p) for p in val if isinstance(p, str))
                elif isinstance(val, str):
                    n = len(val)
                else:
                    continue
                total += n
                if n > biggest:
                    biggest = n
                    biggest_mime = mime
    return total, biggest_mime


def _rule_011(ctx: RuleContext) -> List[Finding]:
    payload, mime = _payload_bytes(ctx.nb)
    if payload <= 0:
        return []
    cfg = ctx.config
    fb = ctx.nb.file_bytes
    absolute = payload >= cfg.max_output_bytes
    relative = (
        fb >= cfg.bloat_min_file_bytes and payload >= cfg.bloat_ratio * fb
    )
    if not (absolute or relative):
        return []
    line, col = locate_key(ctx.text, "outputs")
    pct = (100.0 * payload / fb) if fb else 0.0
    why = "absolute threshold" if absolute else "share of file size"
    return [_emit(
        _RULE_011, ctx, NOTEBOOK_LEVEL, line, col,
        "committed non-text output payloads total " + str(payload) + " bytes of a " +
        str(fb) + "-byte file (" + ("%.1f" % pct) + " percent, largest mime '" +
        (mime or "?") + "'), over the " + why + "; the notebook is carrying a binary "
        "store in version control",
        "payload_bytes=" + str(payload) + " file_bytes=" + str(fb),
    )]


# ---------------------------------------------------------------------------
# NBK-012  hidden-state shapes
# ---------------------------------------------------------------------------


_CHDIR = re.compile(r"\bos\.chdir\s*\(")
_CD_MAGIC = re.compile(r"^\s*%cd\b")
_STAR_IMPORT = re.compile(r"^\s*from\s+[\w.]+\s+import\s+\*")


def _bound_names(tree: ast.AST) -> Set[str]:
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    names.add(alias.asname)
                elif alias.name and alias.name != "*":
                    names.add(alias.name.split(".")[0])
    return names


def _deleted_names(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Delete):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    yield t.id, getattr(node, "lineno", 1)


def _rule_012(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    seen_bindings: Set[str] = set()
    for code in ctx.codes:
        cell = code.cell
        for lineno, ln in _source_lines(cell):
            if _CHDIR.search(ln) or _CD_MAGIC.match(ln):
                line, col = _pos(ctx, ln.strip())
                out.append(_emit(
                    _RULE_012, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " line " + str(lineno) +
                    " changes the working directory; every later relative path depends on "
                    "this cell having run first, and the file does not express that order",
                    short(ln),
                ))
            if _STAR_IMPORT.match(ln):
                line, col = _pos(ctx, ln.strip())
                out.append(_emit(
                    _RULE_012, ctx, cell.index, line, col,
                    "cell " + str(cell.index) + " line " + str(lineno) +
                    " uses a star-import; which names it binds depends on the imported "
                    "module's version, so later cells carry an unexpressed dependency",
                    short(ln),
                ))
        if code.ast_available and code.tree is not None:
            for name, lineno in _deleted_names(code.tree):
                if name in seen_bindings:
                    src_lines = cell.source.split("\n")
                    anchor = src_lines[lineno - 1] if 0 < lineno <= len(src_lines) else name
                    line, col = _pos(ctx, anchor.strip() or name)
                    out.append(_emit(
                        _RULE_012, ctx, cell.index, line, col,
                        "cell " + str(cell.index) + " deletes '" + name +
                        "', a name bound in an earlier cell; re-running cells out of order "
                        "after this point produces a different namespace",
                        short(anchor),
                    ))
            seen_bindings |= _bound_names(code.tree)
    return out


# ---------------------------------------------------------------------------
# NBK-013  output / cell counter disagreement
# ---------------------------------------------------------------------------


def _rule_013(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.nb.cells:
        if c.is_code:
            cell_ec = c.execution_count
            if not isinstance(cell_ec, int) or isinstance(cell_ec, bool):
                continue
            for i, o in enumerate(c.outputs):
                if not isinstance(o, dict):
                    continue
                if o.get("output_type") != "execute_result":
                    continue
                o_ec = o.get("execution_count")
                if not isinstance(o_ec, int) or isinstance(o_ec, bool):
                    continue
                if o_ec != cell_ec:
                    line, col = _pos(ctx, c.first_source_line())
                    out.append(_emit(
                        _RULE_013, ctx, c.index, line, col,
                        "code cell " + str(c.index) + " records execution_count [" +
                        str(cell_ec) + "] but its outputs[" + str(i) +
                        "] records [" + str(o_ec) + "]; the cell and its own output "
                        "disagree about which run produced it",
                        short(c.first_source_line()),
                    ))
        else:
            bad = []
            raw_ec = c.raw.get("execution_count")
            if "execution_count" in c.raw and raw_ec is not None:
                bad.append("execution_count=" + short(raw_ec, 20))
            raw_outs = c.raw.get("outputs")
            if isinstance(raw_outs, list) and raw_outs:
                bad.append("outputs[" + str(len(raw_outs)) + "]")
            if bad:
                line, col = _pos(ctx, c.first_source_line())
                out.append(_emit(
                    _RULE_013, ctx, c.index, line, col,
                    c.cell_type + " cell " + str(c.index) + " carries " +
                    " and ".join(bad) + "; nbformat v4 gives those fields to code cells "
                    "only, so the record is not self-consistent",
                    short(c.first_source_line()),
                ))
    return out


# ---------------------------------------------------------------------------
# NBK-014  widget state
# ---------------------------------------------------------------------------


WIDGET_STATE_MIME = "application/vnd.jupyter.widget-state+json"


def _rule_014(ctx: RuleContext) -> List[Finding]:
    widgets = ctx.nb.metadata.get("widgets")
    if widgets is None:
        return []
    line, col = locate_key(ctx.text, "widgets")
    if not isinstance(widgets, dict):
        return [_emit(
            _RULE_014, ctx, NOTEBOOK_LEVEL, line, col,
            "metadata.widgets is " + type(widgets).__name__ +
            ", not an object; the stored widget render cannot be restored",
            short(widgets, 60),
        )]
    for val in widgets.values():
        if isinstance(val, dict) and val.get("state"):
            return []
    return [_emit(
        _RULE_014, ctx, NOTEBOOK_LEVEL, line, col,
        "metadata.widgets is present but carries no non-empty 'state' key (expected "
        "under '" + WIDGET_STATE_MIME + "'); the widget render is already broken on "
        "disk and will show as a missing-widget placeholder",
        "widgets keys: " + short(", ".join(sorted(str(k) for k in widgets.keys())) or "<none>", 80),
    )]


# ---------------------------------------------------------------------------
# NBK-015  coverage disclosure
# ---------------------------------------------------------------------------


def _rule_015(ctx: RuleContext) -> List[Finding]:
    if not _is_python_notebook(ctx.nb):
        line, col = locate_key(ctx.text, "language_info")
        return [_emit(
            _RULE_015, ctx, NOTEBOOK_LEVEL, line, col,
            "notebook language is '" + ctx.nb.language() +
            "', so the Python-shaped rules (NBK-006 binding analysis, NBK-008, NBK-012 "
            "delete-tracking) are degraded to textual matching for the whole file",
            "language=" + short(ctx.nb.language(), 40),
        )]
    out: List[Finding] = []
    for code in ctx.codes:
        if code.ast_available:
            continue
        if not code.cell.source.strip():
            continue
        cell = code.cell
        line, col = _pos(ctx, cell.first_source_line())
        out.append(_emit(
            _RULE_015, ctx, cell.index, line, col,
            "cell " + str(cell.index) + " source was not parseable as Python (" +
            short(code.parse_error or "unknown", 70) + "); rules NBK-006 and NBK-012 are "
            "degraded to textual matching for this cell, so nbshape's coverage is not "
            "uniform across this file",
            short(cell.first_source_line()),
        ))
    return out


# ---------------------------------------------------------------------------
# NBK-017  cell id conformance (nbformat_minor >= 5)
# ---------------------------------------------------------------------------


_CELL_ID = re.compile(r"^[a-zA-Z0-9\-_]{1,64}$")


def _rule_017(ctx: RuleContext) -> List[Finding]:
    minor = ctx.nb.nbformat_minor
    if not isinstance(minor, int) or isinstance(minor, bool) or minor < 5:
        return []
    out: List[Finding] = []
    seen: Dict[str, int] = {}
    for c in ctx.nb.cells:
        cid = c.cell_id
        line, col = _pos(ctx, c.first_source_line())
        if cid is None:
            out.append(_emit(
                _RULE_017, ctx, c.index, line, col,
                "cell " + str(c.index) + " has no 'id'; nbformat_minor " + str(minor) +
                " requires a cell id on every cell, and diff or merge tooling keys on it",
                short(c.first_source_line()),
            ))
            continue
        if not isinstance(cid, str) or not _CELL_ID.match(cid):
            out.append(_emit(
                _RULE_017, ctx, c.index, line, col,
                "cell " + str(c.index) + " has id " + short(cid, 40) +
                ", which is not the 1-to-64 character [a-zA-Z0-9-_] form the v4.5 schema "
                "requires",
                short(c.first_source_line()),
            ))
            continue
        if cid in seen:
            out.append(_emit(
                _RULE_017, ctx, c.index, line, col,
                "cell " + str(c.index) + " repeats the id '" + cid + "' already used by "
                "cell " + str(seen[cid]) + "; cell ids must be unique within a notebook",
                short(c.first_source_line()),
            ))
        else:
            seen[cid] = c.index
    return out


# ---------------------------------------------------------------------------
# NBK-018  stripped-notebook state
# ---------------------------------------------------------------------------


def _rule_018(ctx: RuleContext) -> List[Finding]:
    if not _is_stripped(ctx.nb):
        return []
    n = len(ctx.nb.code_cells())
    line, col = locate_key(ctx.text, "cells")
    return [_emit(
        _RULE_018, ctx, NOTEBOOK_LEVEL, line, col,
        "all " + str(n) + " code cell(s) have a null execution_count and no stored "
        "outputs; this is the cleared state a strip-outputs tool produces. The ordering "
        "rules NBK-001 / NBK-002 / NBK-003 / NBK-004 / NBK-013 have no evidence to work "
        "from here, so the ordering dimension is unknown rather than clean",
        str(n) + " code cells, all cleared",
    )]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_RULE_001 = Rule(
    "NBK-001", Severity.MEDIUM,
    "execution counts are not strictly increasing",
    "execution_count over code cells, with nulls dropped, is not strictly "
    "increasing in storage order - the file's own record is not self-consistent "
    "with its stored order.",
    _rule_001,
)
_RULE_002 = Rule(
    "NBK-002", Severity.HIGH,
    "outputs retained with a null execution_count",
    "a code cell carries outputs but execution_count is null - output retained "
    "from a kernel run the file no longer describes.",
    _rule_002,
)
_RULE_003 = Rule(
    "NBK-003", Severity.HIGH,
    "duplicate execution counters",
    "two or more code cells share the same non-null execution_count, which a "
    "monotonic kernel counter cannot produce.",
    _rule_003,
)
_RULE_004 = Rule(
    "NBK-004", Severity.INFO,
    "kernel counter ran past the stored cell count",
    "the maximum execution_count exceeds the stored code-cell count by more than "
    "--rerun-factor. An observation, not a defect: cells were re-run, deleted, or "
    "both, which iterative work produces normally.",
    _rule_004,
)
_RULE_005 = Rule(
    "NBK-005", Severity.HIGH,
    "machine-local absolute path literal",
    "cell source contains a drive-letter, home-directory, or mount-point absolute "
    "path literal naming a location only the authoring machine has.",
    _rule_005,
)
_RULE_006 = Rule(
    "NBK-006", Severity.HIGH,
    "credential-shaped literal",
    "a binding whose name matches a credential vocabulary is bound to a string "
    "literal of at least --min-literal-len characters, or a text/plain or stream "
    "output contains a high-entropy token-shaped string. Reports SHAPES, never "
    "verified secrets.",
    _rule_006,
)
_RULE_007 = Rule(
    "NBK-007", Severity.MEDIUM,
    "install with no version specifier",
    "a pip / conda install invoked through ! or %pip names a package with no "
    "version specifier, so the dependency set is not recoverable from the file.",
    _rule_007,
)
_RULE_008 = Rule(
    "NBK-008", Severity.MEDIUM,
    "sampling calls with no visible seed",
    "sampling API calls are present and no seeding call is visible in any cell. A "
    "textual name-shape match: seeding inside an imported helper is invisible here.",
    _rule_008,
)
_RULE_009 = Rule(
    "NBK-009", Severity.MEDIUM,
    "kernel metadata absent or incoherent",
    "metadata.kernelspec or metadata.language_info is absent, language_info.name "
    "disagrees with kernelspec.language, or a pythonN kernel name disagrees with "
    "language_info.version's major digit.",
    _rule_009,
)
_RULE_010 = Rule(
    "NBK-010", Severity.INFO,
    "not a schema-conformant nbformat v4 notebook",
    "the top-level object is not a dict, or nbformat / nbformat_minor / cells is "
    "absent or malformed, or nbformat is below 4. This rule is a GATE: when it "
    "fires no other rule runs and the file routes to the unknown verdict.",
    _rule_010,
    gate=True,
    always_visible=True,
)
_RULE_011 = Rule(
    "NBK-011", Severity.INFO,
    "committed output payload bloat",
    "committed non-text output payloads exceed --max-output-bytes, or dominate the "
    "file's total size - the notebook is carrying a binary store in version control.",
    _rule_011,
)
_RULE_012 = Rule(
    "NBK-012", Severity.MEDIUM,
    "hidden-state shape",
    "os.chdir or %cd, a star-import, or a del of a name bound in an earlier cell - "
    "each makes cell order load-bearing in a way the file does not express.",
    _rule_012,
)
_RULE_013 = Rule(
    "NBK-013", Severity.HIGH,
    "cell and output counters disagree",
    "an execute_result output's execution_count disagrees with its owning cell's, "
    "or a non-code cell carries a non-null execution_count or non-empty outputs.",
    _rule_013,
)
_RULE_014 = Rule(
    "NBK-014", Severity.INFO,
    "widget metadata without state",
    "metadata.widgets is present with no non-empty 'state' key - the widget render "
    "is already broken on disk.",
    _rule_014,
)
_RULE_015 = Rule(
    "NBK-015", Severity.INFO,
    "cell source was not parseable as Python",
    "a cell did not parse as Python after the magic pre-pass, or the notebook is "
    "not a Python notebook - so NBK-006 and NBK-012 are degraded to textual "
    "matching there. An honest disclosure that coverage is not uniform.",
    _rule_015,
)
_RULE_016 = Rule(
    "NBK-016", Severity.INFO,
    "hosted-runtime path literal",
    "cell source references a hosted-runtime mount such as /content/ or "
    "/kaggle/input/ - portable inside that host, absent on a local checkout.",
    _rule_016,
)
_RULE_017 = Rule(
    "NBK-017", Severity.MEDIUM,
    "cell id missing, malformed, or duplicated",
    "on nbformat_minor 5 and above the schema requires a unique [a-zA-Z0-9-_]{1,64} "
    "'id' on every cell. Never fires on a v4.0 to v4.4 file.",
    _rule_017,
)
_RULE_018 = Rule(
    "NBK-018", Severity.INFO,
    "outputs cleared, execution order not recorded",
    "every code cell has a null execution_count and no outputs. This is the best "
    "case, not a defect: the ordering rules simply have no evidence, so the "
    "ordering dimension is unknown.",
    _rule_018,
)


ALL_RULES: Tuple[Rule, ...] = (
    _RULE_001, _RULE_002, _RULE_003, _RULE_004, _RULE_005, _RULE_006,
    _RULE_007, _RULE_008, _RULE_009, _RULE_010, _RULE_011, _RULE_012,
    _RULE_013, _RULE_014, _RULE_015, _RULE_016, _RULE_017, _RULE_018,
)

RULES_BY_ID: Dict[str, Rule] = {r.id: r for r in ALL_RULES}

GATE_RULES: Tuple[Rule, ...] = tuple(r for r in ALL_RULES if r.gate)
ALWAYS_VISIBLE_IDS = frozenset(r.id for r in ALL_RULES if r.always_visible)


def run_rules(ctx: RuleContext, disabled=frozenset()) -> Tuple[List[Finding], bool]:
    """Run every enabled rule over one notebook.

    Returns (findings, gated). ``gated`` is True when a gate rule fired, in
    which case no non-gate rule was run and the caller should route the file to
    the ``unknown`` verdict.
    """
    findings: List[Finding] = []
    for rule in GATE_RULES:
        if rule.id in disabled:
            continue
        hits = rule.check_fn(ctx)
        if hits:
            findings.extend(hits)
            return findings, True
    if not ctx.nb.conformant:
        # The gate rule itself was disabled but the file is still unscorable.
        return findings, True
    for rule in ALL_RULES:
        if rule.gate or rule.id in disabled:
            continue
        try:
            findings.extend(rule.check_fn(ctx))
        except RecursionError:
            # A pathologically nested structure defeated one rule. Report the
            # rest rather than failing the whole file.
            continue
    return findings, False
