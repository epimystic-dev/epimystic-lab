"""Rule registry for agentmemcheck.

Twelve shape defects on the agent memory-store surface. Rule IDs use
the ``AMC-`` prefix (Agent Memory Check); the lab-wide shared surface
exposes this list as ``ALL_RULES``.

The attack family is grounded in the OWASP Top 10 for Agentic
Applications 2026 ASI06 slot (Memory and Context Poisoning) and the
2026 research corpus on memory-poisoning attacks on LLM agents - the
range of techniques covered by papers published 2026-05 through
2026-08 under the names Sleeper Memory Poisoning, GhostWriter / When
Agents Remember Too Much, MemPoison, FARMA (Forged Amplifying
Rationale Memory Attack), and Non-Malleable Origin-Bound Authority.

The rules capture *shape* defects on the file surface - the structure
of each memory entry at write time, and the structure of the store at
load time - not runtime verification. Each rule is callable, takes
the store document, store-level metadata, the full file text, a
per-entry iterator, and the Options object, and emits zero-or-more
``Finding`` records.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .parse import (
    entry_content,
    entry_id,
    entry_reasoning,
    entry_role,
    entry_source,
    entry_timestamp,
    entry_ttl,
)
from .types import Finding, Options, Severity


Check = Callable[
    [dict, str, str, dict, str, Options, Dict[str, Any]], List[Finding]
]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    check: Check


# ---------------------------------------------------------------------------
# Character-class ranges referenced by AMC-001 and AMC-009.
# ---------------------------------------------------------------------------

# Unicode TAG block (Plane 14 Tags): U+E0000 to U+E007F.
TAG_RANGE = (0xE0000, 0xE007F)

# Bidirectional override controls: LRE / RLE / PDF / LRO / RLO plus
# isolates.
BIDI_CODEPOINTS = frozenset(
    [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
)

# Zero-width / joiner / BOM. BOM at the very start of a document is
# allowed; a BOM anywhere else is a concealment surface.
ZERO_WIDTH_CODEPOINTS = frozenset([0x200B, 0x200C, 0x200D, 0x2060])
BOM_CODEPOINT = 0xFEFF


def _is_control(cp: int) -> bool:
    if cp in (0x09, 0x0A, 0x0D):
        return False
    if 0x00 <= cp <= 0x1F:
        return True
    if 0x7F <= cp <= 0x9F:
        return True
    return False


# Private Use Area ranges, excluding Plane 14 Tags (that is AMC-001).
PUA_RANGES: Tuple[Tuple[int, int], ...] = (
    (0xE000, 0xF8FF),       # BMP PUA
    (0xF0000, 0xFFFFD),     # SPUA-A
    (0x100000, 0x10FFFD),   # SPUA-B
)


def _in_pua(cp: int) -> bool:
    if TAG_RANGE[0] <= cp <= TAG_RANGE[1]:
        return False
    for lo, hi in PUA_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _codepoints(s: str):
    for i, ch in enumerate(s):
        yield i, ord(ch), ch


def _describe_cp(cp: int) -> str:
    return "U+%04X" % cp


def _classify_hidden(cp: int, idx: int) -> Optional[str]:
    """Classify a hidden-character codepoint, or return None if cp is
    not in a hidden-character class. BOM is only flagged when ``idx``
    is non-zero (BOM at offset 0 is a legitimate document marker).
    """
    if TAG_RANGE[0] <= cp <= TAG_RANGE[1]:
        return "TAG block"
    if cp in BIDI_CODEPOINTS:
        return "bidi override"
    if cp in ZERO_WIDTH_CODEPOINTS:
        return "zero-width"
    if cp == BOM_CODEPOINT and idx != 0:
        return "BOM"
    if _is_control(cp):
        return "control"
    if _in_pua(cp):
        return "private-use"
    return None


# ---------------------------------------------------------------------------
# Helpers for AMC-003 / AMC-006 (origin-privilege, instruction-shape).
# ---------------------------------------------------------------------------

_SOURCE_TOKEN_RE = re.compile(r"[^A-Za-z0-9]+")


def _tokenise(s: str) -> List[str]:
    return [t for t in _SOURCE_TOKEN_RE.split(s.lower()) if t]


def _source_is_external(source: Optional[str], options: Options) -> bool:
    if source is None:
        return False
    tokens = _tokenise(source)
    return any(t in options.external_sources for t in tokens)


def _role_is_elevated(role: Optional[str], options: Options) -> bool:
    if role is None:
        return False
    tokens = _tokenise(role)
    return any(t in options.elevated_roles for t in tokens)


# Instruction-shape markers used by AMC-006. These are deliberately
# conservative: they only fire on language that unambiguously addresses
# a model or asserts a system-role instruction. Each entry below is a
# word boundary pattern.
_INSTRUCTION_PATTERNS = (
    r"\bignore\s+(the\s+)?previous\b",
    r"\bdisregard\s+(all\s+|the\s+)?prior\b",
    r"\byou\s+are\s+(a|an|now|the)\b",
    r"\byou\s+must\s+",
    r"\byou\s+should\s+always\b",
    r"\byou\s+should\s+never\b",
    r"\balways\s+(reply|respond|answer|output|execute|run)\b",
    r"\bnever\s+(reveal|disclose|share|mention|refuse)\b",
    r"\bsystem\s*[:>-]\s*",
    r"\b<<\s*system\s*>>\s*",
    r"<\|\s*(system|im_start|im_end|endoftext)\s*\|>",
    r"```(system|prompt|instructions?)\b",
    r"\bfrom\s+now\s+on\b",
    r"\boverride\s+(the|your|all)\s+(prior|previous)\b",
    r"\bforget\s+(all\s+)?(prior|previous|earlier)\s+(instructions|context)\b",
)

_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.IGNORECASE)


def _instruction_shape(text: str) -> Optional[str]:
    m = _INSTRUCTION_RE.search(text)
    if m is None:
        return None
    return m.group(0)


# ---------------------------------------------------------------------------
# Helpers for AMC-004 (FARMA pattern on the reasoning / rationale
# surface).
# ---------------------------------------------------------------------------

# Patterns that signal a reasoning block has stopped being a rationale
# and started being a command / tool-call shape. Deliberately
# conservative - a true rationale block almost never contains any of
# these.
_FARMA_PATTERNS = (
    r"\btool\s*[_-]?\s*call\s*[:=]",
    r"\binvoke\s+tool\b",
    r"\bcall\s+function\s+",
    r"\bexecute\s+(the\s+)?(following|this|next)\s+(command|tool|action)\b",
    r"\bshell\s*[:=]\s*",
    r"\b(curl|wget|rm\s+-rf|chmod|chown|ssh\s+)\b",
    r"\bexfiltrate\b",
    r"\bapi_key\s*[:=]",
    r"<\|tool_call\|>",
    r"\{\s*\"tool\"\s*:",
    r"\[tool\]\s*",
)

_FARMA_RE = re.compile("|".join(_FARMA_PATTERNS), re.IGNORECASE)


def _farma_shape(reasoning: str) -> Optional[str]:
    m = _FARMA_RE.search(reasoning)
    if m is None:
        return None
    return m.group(0)


# ---------------------------------------------------------------------------
# Helpers for AMC-005 (credential-shaped literals).
# ---------------------------------------------------------------------------

# JWT: three base64url segments joined by dots. The deterministic
# JWT header-prefix "eyJ" (base64 of "{\"") plus a reasonable minimum
# length keeps the false-positive rate negligible.
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# AWS-style access-key-id prefix. AKIA / ASIA / AGPA / AIDA / ANPA /
# ANVA / AROA / APKA + 16 upper-alnum characters.
_AWS_RE = re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}\b")

# GitHub classic PAT. ghp_ / ghs_ / gho_ / ghu_ / ghr_ + ~36 bytes.
_GITHUB_RE = re.compile(r"\b(ghp|ghs|gho|ghu|ghr)_[A-Za-z0-9]{30,}\b")

# PEM header. Deliberately matches both RSA and EC private keys.
_PEM_RE = re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----")

# Bearer / api_key / secret shaped assignment. Minimum 20 chars of
# high-entropy-looking suffix.
_BEARER_RE = re.compile(
    r"\b(?:bearer|api[_-]?key|secret|password|token)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9_\-\.]{20,})",
    re.IGNORECASE,
)


_CRED_RULES = (
    (_JWT_RE, "JWT"),
    (_AWS_RE, "AWS-style access key"),
    (_GITHUB_RE, "GitHub token"),
    (_PEM_RE, "PEM private-key header"),
    (_BEARER_RE, "bearer/api-key assignment"),
)


def _credential_shape(text: str) -> Optional[str]:
    for rx, label in _CRED_RULES:
        if rx.search(text):
            return label
    return None


# ---------------------------------------------------------------------------
# Helpers for AMC-009 (cross-script homoglyph in identifier field).
# ---------------------------------------------------------------------------

_LATIN_CORE = set(range(0x0041, 0x005B)) | set(range(0x0061, 0x007B))
_CYRILLIC_LETTERS = set(range(0x0400, 0x0500))
_GREEK_LETTERS = set(range(0x0370, 0x0400))


def _script_of(cp: int) -> str:
    if cp in _LATIN_CORE:
        return "latin"
    if cp in _CYRILLIC_LETTERS:
        return "cyrillic"
    if cp in _GREEK_LETTERS:
        return "greek"
    return "other"


def _has_homoglyph_word(s: str) -> List[str]:
    out: List[str] = []
    for word in re.findall(r"[\w]+", s, flags=re.UNICODE):
        scripts = set()
        for ch in word:
            s_ = _script_of(ord(ch))
            if s_ != "other":
                scripts.add(s_)
            if len(scripts) >= 2:
                break
        if len(scripts) >= 2:
            out.append(word)
    return out


# Identifier fields on which AMC-009 fires.
_IDENTIFIER_KEYS = (
    "user", "username", "user_id", "actor", "principal",
    "subject", "owner", "author", "name", "handle", "entity",
)


def _collect_identifier_fields(entry: dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for key in _IDENTIFIER_KEYS:
        v = entry.get(key)
        if isinstance(v, str) and v.strip():
            out.append((key, v))
    for meta_key in ("metadata", "meta"):
        meta = entry.get(meta_key)
        if isinstance(meta, dict):
            for key in _IDENTIFIER_KEYS:
                v = meta.get(key)
                if isinstance(v, str) and v.strip():
                    out.append((meta_key + "." + key, v))
    return out


# ---------------------------------------------------------------------------
# Helpers for AMC-010 (implausible timestamp).
# ---------------------------------------------------------------------------

_ISO_8601_PATTERNS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def _parse_timestamp(v: Any) -> Optional[datetime]:
    """Return an aware datetime, or None if ``v`` is not a recognised
    timestamp shape. Int / float values are treated as epoch seconds
    (or milliseconds if the magnitude is characteristic of ms).
    """
    if isinstance(v, (int, float)):
        try:
            # If the magnitude looks like milliseconds (year 2001+ in
            # ms is ~1e12; year 2001+ in s is ~1e9), scale down.
            if v > 1e12:
                v = v / 1000.0
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    # Normalise trailing Z before fromisoformat (which, in 3.10, does
    # not accept the Z suffix as a timezone).
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass
    for pat in _ISO_8601_PATTERNS:
        try:
            dt = datetime.strptime(s, pat)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


_UNIX_EPOCH = datetime.fromtimestamp(0, tz=timezone.utc)


# ---------------------------------------------------------------------------
# Rule check implementations.
# ---------------------------------------------------------------------------


def _check_hidden_in_content(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    text = entry_content(entry)
    for idx, cp, _ch in _codepoints(text):
        label = _classify_hidden(cp, idx)
        if label is None:
            continue
        return [Finding(
            rule_id="AMC-001",
            severity=Severity.HIGH,
            message=(
                "memory content contains " + label + " character "
                + _describe_cp(cp) + " at offset " + str(idx)
            ),
            entry_id=name,
            pointer=pointer + ".content",
            path=path,
            hint=(
                "Hidden-character classes (Plane 14 TAG, bidi overrides, "
                "zero-width, control, PUA) are invisible to a human "
                "reviewer but reach the model tokenizer when the entry "
                "is retrieved; strip them before write or reject the "
                "entry"
            ),
        )]
    return []


def _check_missing_origin(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    if entry_source(entry) is not None:
        return []
    return [Finding(
        rule_id="AMC-002",
        severity=Severity.HIGH,
        message="memory entry has no origin / source field",
        entry_id=name,
        pointer=pointer,
        path=path,
        hint=(
            "Non-malleable, origin-bound authority (per the 2026 "
            "LLM-agent memory literature) requires every entry carry "
            "its origin; a missing field makes any later origin claim "
            "unverifiable"
        ),
    )]


def _check_origin_privilege_mismatch(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    source = entry_source(entry)
    role = entry_role(entry)
    if not _source_is_external(source, options):
        return []
    if not _role_is_elevated(role, options):
        return []
    return [Finding(
        rule_id="AMC-003",
        severity=Severity.HIGH,
        message=(
            "external-origin content (source=" + str(source)
            + ") stored at elevated role (role=" + str(role) + ")"
        ),
        entry_id=name,
        pointer=pointer,
        path=path,
        hint=(
            "The untrusted-input-to-trusted-memory promotion is the "
            "core memory-poisoning fault class: a tool output or "
            "web-scraped page should not be stored at system / "
            "developer / instruction role"
        ),
    )]


def _check_forged_reasoning(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    reasoning = entry_reasoning(entry)
    if reasoning is None:
        return []
    hit = _farma_shape(reasoning)
    if hit is None:
        return []
    return [Finding(
        rule_id="AMC-004",
        severity=Severity.HIGH,
        message=(
            "reasoning / rationale block contains command or tool-call "
            "shape (matched: " + repr(hit) + ")"
        ),
        entry_id=name,
        pointer=pointer + ".reasoning",
        path=path,
        hint=(
            "A reasoning block carrying a command or tool-call shape "
            "is the FARMA (Forged Amplifying Rationale Memory Attack) "
            "shape: the model is later invited to re-execute the "
            "stored rationale as if it had produced it itself"
        ),
    )]


def _check_credential_shape(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    text = entry_content(entry)
    label = _credential_shape(text)
    if label is None:
        return []
    return [Finding(
        rule_id="AMC-005",
        severity=Severity.HIGH,
        message=(
            "memory content contains credential-shaped literal ("
            + label + ")"
        ),
        entry_id=name,
        pointer=pointer + ".content",
        path=path,
        hint=(
            "A credential in long-term memory is retrieved on every "
            "match; strip it from the content before write and store "
            "a secret reference instead"
        ),
    )]


def _check_instruction_shape(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    source = entry_source(entry)
    if not _source_is_external(source, options):
        return []
    text = entry_content(entry)
    hit = _instruction_shape(text)
    if hit is None:
        return []
    return [Finding(
        rule_id="AMC-006",
        severity=Severity.MEDIUM,
        message=(
            "external-origin content contains instruction-shape "
            "language (matched: " + repr(hit) + ")"
        ),
        entry_id=name,
        pointer=pointer + ".content",
        path=path,
        hint=(
            "Instruction-shape language in content whose source is "
            "untrusted is the classic indirect-prompt-injection "
            "surface; quarantine or reject before admitting to memory"
        ),
    )]


def _check_duplicate_ids(
    entry, pointer, path, store_meta, content_text, options, context,
):
    seen: Dict[str, str] = context["seen_ids"]
    name = entry_id(entry, pointer)
    # The pointer-fallback name (<root> or "[N]") is unique per entry
    # by construction; we only flag duplicates on an explicit id field.
    explicit = None
    for key in ("id", "memory_id", "record_id", "key", "uid", "uuid"):
        v = entry.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            explicit = str(v)
            break
    if explicit is None:
        return []
    first = seen.get(explicit)
    if first is None:
        seen[explicit] = pointer
        return []
    return [Finding(
        rule_id="AMC-007",
        severity=Severity.MEDIUM,
        message=(
            "duplicate memory id " + repr(explicit)
            + " (first seen at " + first + ")"
        ),
        entry_id=name,
        pointer=pointer,
        path=path,
        hint=(
            "Rewriting / overriding a prior entry is a known "
            "backdoor-plant pattern: a later write at the same id "
            "silently redirects every future retrieval"
        ),
    )]


def _check_missing_ttl(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    if entry_ttl(entry) is not None:
        return []
    # Also look in metadata / meta.
    for meta_key in ("metadata", "meta"):
        meta = entry.get(meta_key)
        if isinstance(meta, dict) and any(k in meta for k in (
            "ttl", "expires_at", "expires", "expiry", "valid_until",
            "retention",
        )):
            return []
    return [Finding(
        rule_id="AMC-008",
        severity=Severity.MEDIUM,
        message="memory entry has no TTL / expiration field",
        entry_id=name,
        pointer=pointer,
        path=path,
        hint=(
            "Unbounded memory lifetime enables sleeper poisoning (an "
            "injected entry can dwell silently until the right "
            "retrieval query); every entry should carry an explicit "
            "TTL or an expires_at timestamp"
        ),
    )]


def _check_homoglyph_identifier(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    for field_name, value in _collect_identifier_fields(entry):
        mixed = _has_homoglyph_word(value)
        if mixed:
            return [Finding(
                rule_id="AMC-009",
                severity=Severity.MEDIUM,
                message=(
                    "identifier field '" + field_name + "' contains "
                    "cross-script word '" + mixed[0]
                    + "' (mixes Latin / Cyrillic / Greek)"
                ),
                entry_id=name,
                pointer=pointer + "." + field_name,
                path=path,
                hint=(
                    "A homoglyph identifier lets an attacker publish an "
                    "entry that renders identically to an existing "
                    "principal's; canonicalise to a single script or "
                    "reject"
                ),
            )]
    return []


def _check_timestamp(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    v = entry_timestamp(entry)
    if v is None:
        return []
    dt = _parse_timestamp(v)
    if dt is None:
        return [Finding(
            rule_id="AMC-010",
            severity=Severity.MEDIUM,
            message=(
                "timestamp field has unparseable value " + repr(v)
            ),
            entry_id=name,
            pointer=pointer + ".timestamp",
            path=path,
            hint=(
                "A memory-poisoning write can carry a crafted timestamp "
                "to beat ordering heuristics; an unparseable timestamp "
                "cannot be ordered at all"
            ),
        )]
    now = context.get("now") or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta_future = (dt - now).total_seconds()
    if delta_future > options.future_grace_seconds:
        return [Finding(
            rule_id="AMC-010",
            severity=Severity.MEDIUM,
            message=(
                "timestamp is implausibly far in the future ("
                + str(int(delta_future)) + " seconds ahead; grace "
                + str(options.future_grace_seconds) + "s)"
            ),
            entry_id=name,
            pointer=pointer + ".timestamp",
            path=path,
            hint="see AMC-010 above",
        )]
    if dt < _UNIX_EPOCH:
        return [Finding(
            rule_id="AMC-010",
            severity=Severity.MEDIUM,
            message="timestamp is before the Unix epoch",
            entry_id=name,
            pointer=pointer + ".timestamp",
            path=path,
            hint="see AMC-010 above",
        )]
    return []


def _check_oversize(
    entry, pointer, path, store_meta, content_text, options, context,
):
    name = entry_id(entry, pointer)
    text = entry_content(entry)
    n = len(text.encode("utf-8"))
    if n < options.oversize_cap_bytes:
        return []
    return [Finding(
        rule_id="AMC-011",
        severity=Severity.INFO,
        message=(
            "memory content is oversized ("
            + str(n) + " bytes; cap " + str(options.oversize_cap_bytes)
            + ")"
        ),
        entry_id=name,
        pointer=pointer + ".content",
        path=path,
        hint=(
            "An unusually large memory entry is a known "
            "exfiltration-staging surface: stolen data is written as "
            "a 'memory' and later retrieved verbatim"
        ),
    )]


def _check_schema_version(
    entry, pointer, path, store_meta, content_text, options, context,
):
    # The schema-version check fires once per store, not per entry.
    # We attach it to the first entry's pointer so the rule can share
    # the per-entry loop.
    if context.get("schema_version_reported"):
        return []
    context["schema_version_reported"] = True
    if store_meta and any(k in store_meta for k in (
        "schema_version", "schemaVersion", "version", "revision",
    )):
        return []
    # If the top-level document is a bare array or JSONL, there is no
    # document-level surface to carry a schema version; still an INFO,
    # because the store itself is drift-prone.
    return [Finding(
        rule_id="AMC-012",
        severity=Severity.INFO,
        message="memory store has no schema_version field",
        entry_id="",
        pointer="<store>",
        path=path,
        hint=(
            "A schema-version field at the store level anchors silent-"
            "change detection: a later shape flip (new required fields, "
            "renamed role tokens, changed timestamp format) is only "
            "visible when the schema version is pinned"
        ),
    )]


# ---------------------------------------------------------------------------
# The registry. Order matters: the shared contract tests assert AMC-001
# is first.
# ---------------------------------------------------------------------------

REGISTRY: List[Rule] = [
    Rule(
        id="AMC-001",
        severity=Severity.HIGH,
        title="Hidden-character class in memory content",
        description=(
            "Plane 14 Tags, bidi overrides, zero-width, mid-string "
            "BOM, control, and private-use codepoints in memory "
            "content are invisible to a human reviewer but reach the "
            "model tokenizer on retrieval."
        ),
        check=_check_hidden_in_content,
    ),
    Rule(
        id="AMC-002",
        severity=Severity.HIGH,
        title="Memory entry missing origin / source field",
        description=(
            "Non-malleable, origin-bound authority requires every "
            "entry carry its origin; a missing field makes any later "
            "origin claim unverifiable."
        ),
        check=_check_missing_origin,
    ),
    Rule(
        id="AMC-003",
        severity=Severity.HIGH,
        title="External-origin content stored at elevated role",
        description=(
            "A tool output / web page / scraped content stored at "
            "system / developer / instruction / persistent role is "
            "the core untrusted-input-to-trusted-memory fault class."
        ),
        check=_check_origin_privilege_mismatch,
    ),
    Rule(
        id="AMC-004",
        severity=Severity.HIGH,
        title="Forged reasoning / rationale block (FARMA shape)",
        description=(
            "A reasoning / rationale / why block containing command "
            "or tool-call shape is the Forged Amplifying Rationale "
            "Memory Attack shape: the model later re-executes the "
            "stored rationale as if it had produced it itself."
        ),
        check=_check_forged_reasoning,
    ),
    Rule(
        id="AMC-005",
        severity=Severity.HIGH,
        title="Credential-shaped literal in memory content",
        description=(
            "JWTs, AWS access keys, GitHub tokens, PEM-wrapped "
            "private keys, and bearer / api_key assignments stored in "
            "memory content are retrieved on every match."
        ),
        check=_check_credential_shape,
    ),
    Rule(
        id="AMC-006",
        severity=Severity.MEDIUM,
        title="Instruction-shape content from external origin",
        description=(
            "Imperative or role-override language in content whose "
            "source is an untrusted class is the classic indirect-"
            "prompt-injection surface at write time."
        ),
        check=_check_instruction_shape,
    ),
    Rule(
        id="AMC-007",
        severity=Severity.MEDIUM,
        title="Duplicate memory ids",
        description=(
            "A later write at the same explicit id silently "
            "redirects every future retrieval; it is a known "
            "backdoor-plant pattern."
        ),
        check=_check_duplicate_ids,
    ),
    Rule(
        id="AMC-008",
        severity=Severity.MEDIUM,
        title="Memory entry missing TTL / expiration",
        description=(
            "Unbounded lifetime enables sleeper poisoning: an "
            "injected entry can dwell silently until the right "
            "retrieval query."
        ),
        check=_check_missing_ttl,
    ),
    Rule(
        id="AMC-009",
        severity=Severity.MEDIUM,
        title="Cross-script homoglyph in identifier field",
        description=(
            "An identifier field (user, actor, principal, author, "
            "name) mixing Latin / Cyrillic / Greek codepoints is an "
            "impersonation surface."
        ),
        check=_check_homoglyph_identifier,
    ),
    Rule(
        id="AMC-010",
        severity=Severity.MEDIUM,
        title="Implausible or unparseable timestamp",
        description=(
            "A timestamp field that is unparseable, implausibly "
            "future-dated, or before the Unix epoch cannot be ordered "
            "and may be a crafted write-ordering attack."
        ),
        check=_check_timestamp,
    ),
    Rule(
        id="AMC-011",
        severity=Severity.INFO,
        title="Oversized memory content",
        description=(
            "An unusually large single memory entry is a known "
            "exfiltration-staging surface."
        ),
        check=_check_oversize,
    ),
    Rule(
        id="AMC-012",
        severity=Severity.INFO,
        title="Memory store missing schema_version",
        description=(
            "A schema-version field at the store level anchors "
            "silent-change detection against the store's own shape."
        ),
        check=_check_schema_version,
    ),
]


def run_all(
    doc: Any,
    store_meta: dict,
    content: str,
    path: str,
    options: Options,
    entries: List[Tuple[str, dict]],
) -> List[Finding]:
    """Run every enabled rule across every extracted memory entry.

    ``entries`` is the output of ``parse.load_text`` third slot;
    passing it in rather than re-deriving lets the CLI tally
    ``entries_scanned`` once.
    """
    out: List[Finding] = []
    context: Dict[str, Any] = {
        "doc": doc,
        "content": content,
        "seen_ids": {},
        "schema_version_reported": False,
    }
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO and not (
            options.strict or options.include_info
        ):
            continue
        for pointer, entry in entries:
            out.extend(
                rule.check(
                    entry, pointer, path, store_meta, content, options,
                    context,
                )
            )
    out.sort(key=lambda f: (f.path, f.pointer, f.rule_id))
    return out


__all__ = ["Rule", "Check", "REGISTRY", "run_all"]
