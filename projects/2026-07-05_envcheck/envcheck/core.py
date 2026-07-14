"""envcheck core: parser, diagnostics, drift and secret checks.

The parser accepts the common ``KEY=VALUE`` dotenv dialect: unquoted, single-
quoted, and double-quoted values on a single line, ``#`` line comments, and
blank lines. It intentionally does NOT support multi-line values, backslash
line continuations, variable expansion, or ``export`` prefixes -- these are
outside the compatible-subset every runtime agrees on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

_UTF8_BOM = b"\xef\xbb\xbf"

# Keys: POSIX-ish; conventionally uppercase. Allow lowercase too because the
# real ecosystem does; flag only the truly bad shapes.
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Known-prefix credential patterns. Kept intentionally narrow: false positives
# ruin a linter. The README documents this as a heuristic, not a scanner.
# Each entry: (code, human name, compiled regex).
_SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("sk-prefix-secret-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("sk-ant-prefix-secret-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("github-personal-token", re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ("github-server-token", re.compile(r"\bghs_[A-Za-z0-9]{30,}\b")),
    ("github-oauth-token", re.compile(r"\bgho_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("stripe-live-secret", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("private-key-blob", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


@dataclass(frozen=True)
class Diagnostic:
    """A single finding.

    ``line`` and ``column`` are 1-indexed. ``column`` is ``0`` when the finding
    applies to a whole file or a whole key rather than a specific character.
    ``source`` is one of ``"template"``, ``"env"``, or ``None`` when the
    finding is not attributable to a single file (parser output before
    ``check()`` tags it).
    """

    code: str
    line: int
    column: int
    message: str
    key: Optional[str] = None
    source: Optional[str] = None

    def format(self, path: Optional[str] = None) -> str:
        prefix = f"{path}:" if path else ""
        return f"{prefix}{self.line}:{self.column}: {self.code} {self.message}"

    def with_source(self, source: str) -> "Diagnostic":
        return Diagnostic(
            code=self.code,
            line=self.line,
            column=self.column,
            message=self.message,
            key=self.key,
            source=source,
        )


@dataclass
class ParseResult:
    """Parser output: ordered entries, per-file diagnostics, and metadata."""

    entries: List[Tuple[str, str, int]] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)
    had_bom: bool = False
    had_crlf: bool = False

    def keys(self) -> List[str]:
        return [k for k, _, _ in self.entries]

    def as_dict(self) -> dict:
        # Later assignment wins, matching most dotenv runtimes.
        out: dict = {}
        for k, v, _ in self.entries:
            out[k] = v
        return out


def parse_bytes(data: bytes) -> ParseResult:
    """Parse a raw byte string of dotenv content."""

    result = ParseResult()

    if data.startswith(_UTF8_BOM):
        result.had_bom = True
        result.diagnostics.append(
            Diagnostic(
                code="E008",
                line=1,
                column=1,
                message="file starts with UTF-8 BOM; some shells and runtimes reject this",
            )
        )
        data = data[len(_UTF8_BOM):]

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Fall back to lossy decode so we can still surface line-level issues.
        result.diagnostics.append(
            Diagnostic(
                code="E009",
                line=1,
                column=exc.start + 1,
                message=f"file is not valid UTF-8 at byte {exc.start}: {exc.reason}",
            )
        )
        text = data.decode("utf-8", errors="replace")

    if "\r\n" in text:
        result.had_crlf = True
        result.diagnostics.append(
            Diagnostic(
                code="E007",
                line=1,
                column=0,
                message="file uses CRLF line endings; POSIX shells and some runtimes require LF",
            )
        )

    lines = text.splitlines()
    seen_keys: dict[str, int] = {}

    for i, raw in enumerate(lines, start=1):
        line = raw

        # Strip only the trailing CR that survives splitlines on mixed input.
        # (splitlines already handles the common cases; this is defense.)
        if line.endswith("\r"):
            line = line[:-1]

        stripped = line.lstrip()

        if not stripped:
            continue
        if stripped.startswith("#"):
            continue

        # Allow the ``export KEY=VALUE`` shorthand; strip the prefix.
        if stripped.startswith("export "):
            offset_export = len(line) - len(stripped) + len("export ")
            body = line[offset_export:]
            body_start_col = offset_export + 1
        else:
            offset = len(line) - len(stripped)
            body = line[offset:]
            body_start_col = offset + 1

        eq_index = body.find("=")
        if eq_index < 0:
            result.diagnostics.append(
                Diagnostic(
                    code="E001",
                    line=i,
                    column=body_start_col,
                    message="line is not a KEY=VALUE assignment",
                )
            )
            continue

        key = body[:eq_index].rstrip()
        value_raw = body[eq_index + 1:]
        value_col = body_start_col + eq_index + 1

        if not key:
            result.diagnostics.append(
                Diagnostic(
                    code="E002",
                    line=i,
                    column=body_start_col,
                    message="assignment has an empty key",
                )
            )
            continue

        if not _KEY_RE.match(key):
            result.diagnostics.append(
                Diagnostic(
                    code="E003",
                    line=i,
                    column=body_start_col,
                    message=f"key {key!r} is not a valid shell identifier "
                    "([A-Za-z_][A-Za-z0-9_]*)",
                    key=key,
                )
            )
            # Keep going so drift still reports this key.

        value, vdiags = _parse_value(value_raw, i, value_col)
        result.diagnostics.extend(vdiags)

        if key in seen_keys:
            first_line = seen_keys[key]
            result.diagnostics.append(
                Diagnostic(
                    code="E004",
                    line=i,
                    column=body_start_col,
                    message=f"duplicate key {key!r}; first seen at line {first_line}",
                    key=key,
                )
            )
        else:
            seen_keys[key] = i

        result.entries.append((key, value, i))

    return result


def _parse_value(raw: str, line: int, col: int) -> Tuple[str, List[Diagnostic]]:
    """Parse the right-hand side of a KEY=VALUE line.

    Handles ``"double"`` and ``'single'`` quoted values with a matching-quote
    rule, unquoted values with a trailing ``# comment``, and unquoted values
    with embedded whitespace (flagged).
    """

    diags: List[Diagnostic] = []
    stripped = raw.lstrip()

    if not stripped:
        return "", diags

    quote = stripped[0]
    if quote in ('"', "'"):
        rest = stripped[1:]
        end = rest.find(quote)
        if end < 0:
            diags.append(
                Diagnostic(
                    code="E006",
                    line=line,
                    column=col + (len(raw) - len(stripped)),
                    message=f"unclosed {quote} quote in value",
                )
            )
            return rest, diags
        value = rest[:end]
        trailing = rest[end + 1:].strip()
        if trailing and not trailing.startswith("#"):
            diags.append(
                Diagnostic(
                    code="E001",
                    line=line,
                    column=col + (len(raw) - len(stripped)) + end + 2,
                    message="unexpected content after closing quote",
                )
            )
        return value, diags

    # Unquoted: bash strips a trailing inline comment when preceded by whitespace.
    comment_pos = _find_inline_comment(raw)
    if comment_pos >= 0:
        value_part = raw[:comment_pos].rstrip()
    else:
        value_part = raw.rstrip()

    lstripped_value = value_part.lstrip()
    inner = lstripped_value

    if any(ch.isspace() for ch in inner):
        diags.append(
            Diagnostic(
                code="E005",
                line=line,
                column=col,
                message="unquoted value contains whitespace; quote the value or shells "
                "will only see the first token",
            )
        )

    return inner, diags


def _find_inline_comment(raw: str) -> int:
    """Return the index of a ``#`` that begins an inline comment, or -1.

    An inline comment must be preceded by whitespace. ``KEY=#ff00cc`` keeps
    ``#ff00cc`` as the literal value (matching most dotenv runtimes and bash).
    """

    for i in range(1, len(raw)):
        if raw[i] == "#" and raw[i - 1].isspace():
            return i
    return -1


def parse(path: str | Path) -> ParseResult:
    """Read and parse a file at ``path``."""

    p = Path(path)
    return parse_bytes(p.read_bytes())


@dataclass
class CheckOptions:
    """Behavioural knobs for ``check``."""

    drift: bool = True
    secrets: bool = True
    max_issues: Optional[int] = None
    template_placeholders: Sequence[str] = (
        "changeme",
        "change_me",
        "your-key-here",
        "your_key_here",
        "replace-me",
        "replace_me",
        "todo",
        "xxx",
        "xxxx",
    )


def check(
    template: ParseResult,
    env: Optional[ParseResult] = None,
    options: Optional[CheckOptions] = None,
) -> List[Diagnostic]:
    """Run drift + secret checks. Returns diagnostics from both files plus
    cross-file findings, in a stable order.
    """

    opts = options or CheckOptions()
    findings: List[Diagnostic] = []

    findings.extend(d.with_source("template") for d in template.diagnostics)
    if env is not None:
        findings.extend(d.with_source("env") for d in env.diagnostics)

    if opts.secrets:
        findings.extend(_secret_findings(template, source="template"))
        if env is not None:
            # We still check env, but its findings signal a *real* leaked value
            # in a live config, not just a bad template.
            findings.extend(_secret_findings(env, source="env"))

    if opts.drift and env is not None:
        findings.extend(_drift_findings(template, env, opts))

    if opts.max_issues is not None:
        findings = findings[: opts.max_issues]

    return findings


def _secret_findings(pr: ParseResult, source: str) -> List[Diagnostic]:
    out: List[Diagnostic] = []
    for key, value, line in pr.entries:
        for name, pat in _SECRET_PATTERNS:
            m = pat.search(value)
            if not m:
                continue
            code = "S002" if source == "template" else "S001"
            where = "template" if source == "template" else "env"
            out.append(
                Diagnostic(
                    code=code,
                    line=line,
                    column=0,
                    message=(
                        f"{where} value for {key!r} matches the {name} pattern; "
                        "if this is a real credential it should not be in this file"
                    ),
                    key=key,
                    source=source,
                )
            )
            break
    return out


def _drift_findings(
    template: ParseResult, env: ParseResult, opts: CheckOptions
) -> List[Diagnostic]:
    tkeys = template.as_dict()
    ekeys = env.as_dict()
    tlines = {k: line for k, _, line in template.entries}
    elines = {k: line for k, _, line in env.entries}
    placeholders = {p.strip().lower() for p in opts.template_placeholders}

    out: List[Diagnostic] = []

    for k in template.keys():
        if k not in ekeys:
            out.append(
                Diagnostic(
                    code="D001",
                    line=tlines[k],
                    column=0,
                    message=f"key {k!r} is in template but missing from env",
                    key=k,
                    source="template",
                )
            )
            continue
        placeholder_hit = tkeys.get(k, "").strip().lower() in placeholders
        # An empty env value where the template gives a non-placeholder default
        # is often a real bug (developer forgot to set it).
        if ekeys[k] == "" and tkeys[k] != "" and not placeholder_hit:
            out.append(
                Diagnostic(
                    code="D003",
                    line=elines[k],
                    column=0,
                    message=(
                        f"key {k!r} is empty in env but the template provides "
                        "a non-empty example"
                    ),
                    key=k,
                    source="env",
                )
            )
    for k in env.keys():
        if k not in tkeys:
            out.append(
                Diagnostic(
                    code="D002",
                    line=elines[k],
                    column=0,
                    message=(
                        f"key {k!r} is in env but not documented in the template"
                    ),
                    key=k,
                    source="env",
                )
            )
    return out


def check_files(
    template_path: str | Path,
    env_path: Optional[str | Path] = None,
    options: Optional[CheckOptions] = None,
) -> Tuple[List[Diagnostic], ParseResult, Optional[ParseResult]]:
    """Convenience wrapper: parse both files and run ``check``."""

    tp = parse(template_path)
    ep = parse(env_path) if env_path is not None else None
    diags = check(tp, ep, options)
    return diags, tp, ep
