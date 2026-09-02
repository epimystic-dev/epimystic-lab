"""Ten static rules for instruction-privilege-escalation shapes.

Rule IDs are stable public API. Severities:
  HIGH   -> role-impersonation, override, persistent-goal, scheduled-task, authority claim
  MEDIUM -> tool-output-shaped instruction, URL-embedded instruction, hidden marker, code-fence hijack
  INFO   -> bare sentinel token exposure

The rules are pattern-based; they detect shape, not intent. See README.md for
an honest description of what this catches and what it does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Tuple

from .types import Finding, Severity


def _line_col(text: str, offset: int) -> Tuple[int, int]:
    """1-indexed line and column for a 0-indexed byte offset in `text`."""
    if offset <= 0:
        return 1, 1
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    last_nl = prefix.rfind("\n")
    col = offset - last_nl if last_nl >= 0 else offset + 1
    return line, col


def _short(s: str, n: int = 80) -> str:
    s = s.replace("\r", " ").replace("\n", " ")
    if len(s) > n:
        return s[: n - 3] + "..."
    return s


# ---- ESC-001 : fake role-marker injection ---------------------------------

_ROLE_MARKER_PATTERNS: List[Tuple[str, str]] = [
    ("chatml-system", r"<\|im_start\|>\s*system\b"),
    ("chatml-assistant", r"<\|im_start\|>\s*assistant\b"),
    ("chatml-user-mid", r"<\|im_start\|>\s*user\b"),
    ("chatml-end", r"<\|im_end\|>"),
    ("angle-system", r"<\|system\|>"),
    ("angle-assistant", r"<\|assistant\|>"),
    ("angle-user", r"<\|user\|>"),
    ("header-id-system", r"<\|start_header_id\|>\s*system\s*<\|end_header_id\|>"),
    ("header-id-assistant", r"<\|start_header_id\|>\s*assistant\s*<\|end_header_id\|>"),
    ("bracket-system", r"\[SYSTEM\]\s*[:\-]"),
    ("bracket-instructions", r"\[INSTRUCTIONS\]\s*[:\-]"),
    ("markdown-system-header", r"(?im)^\s{0,3}#{1,6}\s*system\s*:?\s*$"),
    ("markdown-role-header", r"(?im)^\s{0,3}#{1,6}\s*role\s*:?\s*$"),
    ("html-system-tag", r"(?is)<system\b[^>]*>.*?</system\s*>"),
    ("assistant-prefix", r"(?im)^\s*assistant\s*:\s*"),
]

_ROLE_COMPILED = [(k, re.compile(p)) for k, p in _ROLE_MARKER_PATTERNS]


def _check_role_markers(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for label, rx in _ROLE_COMPILED:
        for m in rx.finditer(text):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id="ESC-001",
                    severity=Severity.HIGH,
                    path=path,
                    line=line,
                    column=col,
                    message=f"role-impersonation marker ({label}) in ingested content",
                    evidence=_short(m.group(0)),
                )
            )
    return findings


# ---- ESC-002 : override / disregard-prior-instructions --------------------

_OVERRIDE_PATTERNS = [
    r"(?i)\b(ignore|disregard|forget)\b\s+(?:all\s+|the\s+|any\s+)?(above|prior|previous|preceding|earlier)\s+(instructions?|prompts?|messages?|rules?|context|directives?|guidelines?)",
    r"(?i)\boverride\b\s+(?:all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|messages?)",
    r"(?i)\bthis\b\s+(message|line|note|instruction|rule|paragraph)\s+supersedes?\s+(?:all\s+|the\s+|any\s+)?(prior|previous|above|earlier)",
    r"(?i)(^|\n)\s*new\s+instruction\s*:\s*\S",
    r"(?i)\bignore\s+everything\s+(above|before|preceding)\b",
]

_OVERRIDE_COMPILED = [re.compile(p) for p in _OVERRIDE_PATTERNS]


def _check_override(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for rx in _OVERRIDE_COMPILED:
        for m in rx.finditer(text):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id="ESC-002",
                    severity=Severity.HIGH,
                    path=path,
                    line=line,
                    column=col,
                    message="override-directive shape in ingested content",
                    evidence=_short(m.group(0)),
                )
            )
    return findings


# ---- ESC-003 : persistent-goal / long-term-memory smuggling ---------------

_PERSIST_PATTERNS = [
    r"(?i)\bremember\b\s+(?:this|the following|it)?\s*(?:for|in|across)\s+(?:all\s+|the\s+|every\s+)?(future|next|following|subsequent)\s+(sessions?|conversations?|interactions?|calls?|turns?)",
    r"(?i)\b(store|save|keep|persist|write)\b\s+(?:this|the following|it)\s+(?:in|as|to|into)\s+(?:your\s+|the\s+)?(persistent|long-?term|permanent|standing|durable)\s+(memory|store|context|instructions?|goals?)",
    r"(?i)\badd\b\s+(?:this|the following|it)\s+to\s+(?:your|the\s+agent'?s|the)\s+(persistent|standing|permanent|long-?term)\s+(goals?|memory|instructions?|rules?)",
    r"(?i)\bfrom\s+now\s+on\s*,?\s+(whenever|when|if|before|after|each\s+time)\b",
    r"(?i)\bfor\s+every\s+(future|subsequent|following)\s+(request|task|invocation|turn|call|prompt)\b",
    r"(?i)\bupdate\s+(?:your\s+|the\s+)?system\s+(prompt|instructions?)\s+to\b",
]

_PERSIST_COMPILED = [re.compile(p) for p in _PERSIST_PATTERNS]


def _check_persistent(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for rx in _PERSIST_COMPILED:
        for m in rx.finditer(text):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id="ESC-003",
                    severity=Severity.HIGH,
                    path=path,
                    line=line,
                    column=col,
                    message="persistent-goal / long-term-memory smuggling shape",
                    evidence=_short(m.group(0)),
                )
            )
    return findings


# ---- ESC-004 : scheduled-task hijack --------------------------------------

_SCHED_PATTERNS = [
    r"(?i)\b(register|create|set\s+up|schedule|install)\b\s+(?:a\s+|the\s+|new\s+|another\s+)*(cron\s+job|crontab\s+entry|scheduled\s+task|recurring\s+task|periodic\s+job|task\s+scheduler\s+entry|systemd\s+timer|launchd\s+job)",
    r"(?i)\bschtasks(\.exe)?\s+/create\b",
    r"(?i)(^|\n)\s*(\*|@)[^\n]{0,80}\s+(bash|sh|python|node|curl|wget|powershell|pwsh)\b",
    r"(?i)\bschedule\s+(yourself|this|the following)\s+to\s+run\b",
    r"(?i)\bset\s+up\s+a\s+(daily|weekly|hourly|monthly)\s+(job|task|run)\b",
    r"(?i)\bregister\s+a\s+recurring\s+(agent|job|task)\b",
]

_SCHED_COMPILED = [re.compile(p) for p in _SCHED_PATTERNS]


def _check_scheduled(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for rx in _SCHED_COMPILED:
        for m in rx.finditer(text):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id="ESC-004",
                    severity=Severity.HIGH,
                    path=path,
                    line=line,
                    column=col,
                    message="scheduled-task hijack shape",
                    evidence=_short(m.group(0)),
                )
            )
    return findings


# ---- ESC-005 : elevated-authority claim -----------------------------------

_AUTH_PATTERNS = [
    r"(?i)\bas\s+(?:your|the)\s+(operator|owner|admin(?:istrator)?|principal|superuser|root|maintainer)\b",
    r"(?i)\byou\s+are\s+(?:now\s+)?in\s+(admin|super|root|elevated|privileged|god)\s+mode\b",
    r"(?i)\bassume\s+(root|admin|super(?:user)?|elevated|god)\s+(privilege|role|context|permissions?|mode)\b",
    r"(?i)\bthe\s+(real|actual|true|underlying)\s+(user|principal|operator|owner)\s+(wants|is|says|asks|requires|needs|expects)\b",
    r"(?i)\byour\s+(real|actual|true)\s+principal\s+is\b",
    r"(?i)\bthis\s+is\s+(?:your|the)\s+(system|operator|owner|admin)\s+speaking\b",
    r"(?i)\bthe\s+system\s+has\s+been\s+(reconfigured|updated|upgraded)\s+to\b",
]

_AUTH_COMPILED = [re.compile(p) for p in _AUTH_PATTERNS]


def _check_authority(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for rx in _AUTH_COMPILED:
        for m in rx.finditer(text):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id="ESC-005",
                    severity=Severity.HIGH,
                    path=path,
                    line=line,
                    column=col,
                    message="elevated-authority claim in ingested content",
                    evidence=_short(m.group(0)),
                )
            )
    return findings


# ---- ESC-006 : tool-output-shaped instruction -----------------------------

_TOOL_OUTPUT_MARKER = re.compile(
    r"(?im)^\s{0,3}(tool[_ ]output|observation|stdout|stderr|\[stdout\]|\[stderr\]|\[tool\]|<output>|<observation>|<tool_result>)\s*[:\->]"
)
_TOOL_IMPERATIVE = re.compile(
    r"(?im)^\s{0,3}(now|next|then|finally|afterwards?)\s+(you\s+(?:must|should|will|need\s+to)\s+)?(do|run|execute|call|invoke|open|write|delete|remove|install|download|fetch|post|send)\b"
)


def _check_tool_output(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    markers = list(_TOOL_OUTPUT_MARKER.finditer(text))
    if not markers:
        return findings
    imperatives = list(_TOOL_IMPERATIVE.finditer(text))
    if not imperatives:
        return findings
    for m in markers:
        # any imperative appearing after the marker within the same file counts
        first_after = next((i for i in imperatives if i.start() > m.end()), None)
        if first_after is None:
            continue
        line, col = _line_col(text, m.start())
        findings.append(
            Finding(
                rule_id="ESC-006",
                severity=Severity.MEDIUM,
                path=path,
                line=line,
                column=col,
                message="tool-output marker followed by imperative directive in same content",
                evidence=_short(m.group(0)),
            )
        )
    return findings


# ---- ESC-007 : URL query/fragment-embedded instruction --------------------

_URL_INSTRUCTION = re.compile(
    r"(?i)\bhttps?://[^\s\"'<>`]{1,400}[?&#](instruction|prompt|system|override|role|admin|sudo|persona|jailbreak|inject)=[^\s\"'<>`&]+"
)


def _check_url_instruction(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _URL_INSTRUCTION.finditer(text):
        line, col = _line_col(text, m.start())
        findings.append(
            Finding(
                rule_id="ESC-007",
                severity=Severity.MEDIUM,
                path=path,
                line=line,
                column=col,
                message="URL with instruction-shaped query or fragment parameter",
                evidence=_short(m.group(0)),
            )
        )
    return findings


# ---- ESC-008 : hidden-content markers -------------------------------------

_HTML_COMMENT_INSTRUCTION = re.compile(
    r"(?is)<!--(.*?)-->"
)
_HIDDEN_KEYWORDS = re.compile(
    r"(?i)\b(hidden|invisible|do not (show|display)|if you (can )?read|instruction|prompt|system|obey|override|jailbreak|ignore\s+above)\b"
)
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")


def _check_hidden(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _HTML_COMMENT_INSTRUCTION.finditer(text):
        body = m.group(1)
        if _HIDDEN_KEYWORDS.search(body):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id="ESC-008",
                    severity=Severity.MEDIUM,
                    path=path,
                    line=line,
                    column=col,
                    message="HTML comment carries instruction-shaped hidden content",
                    evidence=_short(m.group(0)),
                )
            )
    # zero-width character presence (any -- one is enough)
    zw_hits = list(_ZERO_WIDTH.finditer(text))
    if zw_hits:
        line, col = _line_col(text, zw_hits[0].start())
        findings.append(
            Finding(
                rule_id="ESC-008",
                severity=Severity.MEDIUM,
                path=path,
                line=line,
                column=col,
                message=f"zero-width character present in content ({len(zw_hits)} occurrence(s))",
                evidence="U+" + "%04X" % ord(zw_hits[0].group(0)),
            )
        )
    return findings


# ---- ESC-009 : code-fence with system/prompt language ---------------------

_FENCE_HIJACK = re.compile(
    r"(?im)^\s{0,3}```(system|prompt|instructions?|role|assistant|persona|jailbreak)\b"
)


def _check_fence(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _FENCE_HIJACK.finditer(text):
        line, col = _line_col(text, m.start())
        findings.append(
            Finding(
                rule_id="ESC-009",
                severity=Severity.MEDIUM,
                path=path,
                line=line,
                column=col,
                message="code fence labelled with role/instruction language",
                evidence=_short(m.group(0)),
            )
        )
    return findings


# ---- ESC-010 : bare sentinel-token exposure -------------------------------

_SENTINEL_TOKENS = [
    "<|endoftext|>",
    "<|eot_id|>",
    "<|eom_id|>",
    "<|end|>",
    "<|beginoftext|>",
    "[INST]",
    "[/INST]",
    "<|EOM|>",
]

def _role_marker_hit(window: str) -> bool:
    for _, rx in _ROLE_COMPILED:
        if rx.search(window):
            return True
    return False


def _check_sentinel(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for tok in _SENTINEL_TOKENS:
        idx = 0
        while True:
            i = text.find(tok, idx)
            if i < 0:
                break
            # do not double-fire when ESC-001 role marker already covers the
            # surrounding 32 chars; keeps ESC-010 as the bare-token catcher only.
            window_start = max(0, i - 32)
            window = text[window_start : i + len(tok) + 32]
            if not _role_marker_hit(window):
                line, col = _line_col(text, i)
                findings.append(
                    Finding(
                        rule_id="ESC-010",
                        severity=Severity.INFO,
                        path=path,
                        line=line,
                        column=col,
                        message=f"bare sentinel token exposed in prose: {tok}",
                        evidence=tok,
                    )
                )
            idx = i + len(tok)
    return findings


# ---- rule registry --------------------------------------------------------

RuleFn = Callable[[str, str], List[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    description: str
    check: RuleFn


ALL_RULES: List[Rule] = [
    Rule(
        id="ESC-001",
        severity=Severity.HIGH,
        description="Fake role-marker injection (chatml / bracket / html / markdown role headers).",
        check=_check_role_markers,
    ),
    Rule(
        id="ESC-002",
        severity=Severity.HIGH,
        description="Override-directive smuggling (ignore/disregard/override prior instructions).",
        check=_check_override,
    ),
    Rule(
        id="ESC-003",
        severity=Severity.HIGH,
        description="Persistent-goal / long-term-memory smuggling.",
        check=_check_persistent,
    ),
    Rule(
        id="ESC-004",
        severity=Severity.HIGH,
        description="Scheduled-task / cron / recurring-job hijack.",
        check=_check_scheduled,
    ),
    Rule(
        id="ESC-005",
        severity=Severity.HIGH,
        description="Elevated-authority claim (as your operator / admin mode / real principal).",
        check=_check_authority,
    ),
    Rule(
        id="ESC-006",
        severity=Severity.MEDIUM,
        description="Tool-output marker followed by imperative directive in same content.",
        check=_check_tool_output,
    ),
    Rule(
        id="ESC-007",
        severity=Severity.MEDIUM,
        description="URL with instruction-shaped query / fragment parameter.",
        check=_check_url_instruction,
    ),
    Rule(
        id="ESC-008",
        severity=Severity.MEDIUM,
        description="Hidden-content marker (HTML comment with instruction words, or zero-width chars).",
        check=_check_hidden,
    ),
    Rule(
        id="ESC-009",
        severity=Severity.MEDIUM,
        description="Code fence labelled with role/instruction language (```system, ```prompt).",
        check=_check_fence,
    ),
    Rule(
        id="ESC-010",
        severity=Severity.INFO,
        description="Bare sentinel-token exposure in prose (endoftext / eot_id / INST).",
        check=_check_sentinel,
    ),
]
