"""Rule engine for skillcheck.

Given the text of a skill file, apply the PATTERNS library and emit a list
of Finding entries. Also implements two structural rules (SKILLCHECK-009 --
undeclared capabilities) that operate on the whole file rather than the
regex library.

Deterministic (findings sorted by severity, file, line, column, rule).
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Set, Tuple

from skillcheck.patterns import PATTERNS
from skillcheck.verdict import Finding, Severity


RULES = {
    "SKILLCHECK-001": ("destructive shell command in skill body", Severity.CRITICAL),
    "SKILLCHECK-002": ("privilege escalation invocation", Severity.HIGH),
    "SKILLCHECK-003": ("network exfiltration / reverse-shell pattern", Severity.CRITICAL),
    "SKILLCHECK-004": ("credential or secret reference", Severity.HIGH),
    "SKILLCHECK-005": ("obfuscated / hidden execution surface", Severity.HIGH),
    "SKILLCHECK-006": ("prompt-injection payload marker", Severity.MEDIUM),
    "SKILLCHECK-007": ("runtime install-and-execute pattern", Severity.HIGH),
    "SKILLCHECK-008": ("filesystem archive exfiltration", Severity.HIGH),
    "SKILLCHECK-009": ("skill file declares no capabilities / allowed-tools", Severity.INFO),
    "SKILLCHECK-010": ("suspicious external URL reference", Severity.MEDIUM),
}


_EXCERPT_MAX = 120


def _pos_to_line_col(text: str, pos: int) -> Tuple[int, int]:
    if pos < 0:
        pos = 0
    if pos > len(text):
        pos = len(text)
    prefix = text[:pos]
    line = prefix.count("\n") + 1
    last_nl = prefix.rfind("\n")
    col = pos - (last_nl + 1) + 1
    return line, col


def _excerpt(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    snippet = text[line_start:line_end].strip()
    if len(snippet) > _EXCERPT_MAX:
        snippet = snippet[: _EXCERPT_MAX - 1] + "..."
    return snippet


# --- frontmatter helpers for SKILLCHECK-009 -----------------------------


_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)
_CAPABILITY_KEYS = (
    "tools",
    "allowed_tools",
    "allowed-tools",
    "allowedtools",
    "capabilities",
    "permissions",
    "allow",
    "allowlist",
)


def has_capability_declaration(text: str) -> bool:
    """True iff a YAML-frontmatter block at the top declares at least one
    capability/allowed-tools/permissions key with a non-empty value.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return False
    block = m.group(1)
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().lower()
        if key in _CAPABILITY_KEYS:
            value = value.strip()
            # allow either "key: value" or "key:" followed by list/block
            if value and value not in ("~", "null", "[]", "{}"):
                return True
            # look for at least one non-empty indented line following
            idx = block.splitlines().index(line)
            for follow in block.splitlines()[idx + 1 :]:
                fs = follow.strip()
                if not fs:
                    continue
                if follow.startswith((" ", "\t")) and fs and fs != "~":
                    return True
                break
    return False


# --- evaluate ------------------------------------------------------------


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen: Set[Tuple[str, str, int, int, str]] = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.column, f.excerpt)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def evaluate_text(text: str, path: str) -> List[Finding]:
    """Apply the regex-driven pattern library to `text` and return findings."""
    findings: List[Finding] = []
    for pattern in PATTERNS:
        for m in pattern.regex.finditer(text):
            line, col = _pos_to_line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id=pattern.rule_id,
                    severity=pattern.severity,
                    file=path,
                    line=line,
                    column=col,
                    excerpt=_excerpt(text, m.start(), m.end()),
                    message=pattern.message,
                )
            )
    findings = _dedupe(findings)
    findings.sort(key=Finding.sort_key)
    return findings


def evaluate_structural(text: str, path: str) -> List[Finding]:
    """Structural rules that do not derive from the regex pattern library."""
    findings: List[Finding] = []
    if not has_capability_declaration(text):
        findings.append(
            Finding(
                rule_id="SKILLCHECK-009",
                severity=Severity.INFO,
                file=path,
                line=1,
                column=1,
                excerpt=text.splitlines()[0][:_EXCERPT_MAX] if text else "",
                message="skill file declares no capabilities / allowed-tools / permissions in YAML frontmatter",
            )
        )
    return findings
