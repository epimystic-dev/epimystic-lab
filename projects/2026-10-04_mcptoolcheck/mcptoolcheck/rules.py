"""Rule registry for mcptoolcheck.

Twelve shape defects on the MCP tool-descriptor surface. Rule IDs use
the ``MTC-`` prefix (MCP Tool Check); the lab-wide shared surface
exposes this list as ``ALL_RULES``.

The attack family is grounded in two independent 2026 signals:

  * arXiv 2607.05744 (Rashidi, 2026-07-07): invisible-byte
    concealment of tool-metadata payloads via the Unicode TAG block,
    bidi overrides, zero-width characters, and private-use codepoints,
    yielding an approval-view fidelity gap between the human-readable
    dialog and the bytes the model sees.
  * The 2026-10-04 field report cataloguing 140 silent changes across
    66 release pairs of four reference MCP servers (schema flips,
    annotation flips, cosmetic rewordings) all shipped without
    changelog entries.

The rules capture *shape* defects that enable these faults on the
file surface - not runtime verification. Each rule is callable, takes
a tool dict + descriptor path + full file text + options, and emits
zero-or-more ``Finding`` records.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

from .parse import (
    tool_annotations,
    tool_description,
    tool_input_schema,
    tool_name,
)
from .types import Finding, Options, Severity


Check = Callable[[dict, str, str, Options, Dict[str, Any]], List[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    check: Check


# ---------------------------------------------------------------------------
# Character-class ranges referenced by MTC-001 through MTC-005 and MTC-011.
# ---------------------------------------------------------------------------

# Unicode TAG block (Plane 14 Tags): U+E0000 to U+E007F.
TAG_RANGE = (0xE0000, 0xE007F)

# Bidirectional override controls: LRE/RLE/PDF/LRO/RLO plus isolates.
BIDI_CODEPOINTS = frozenset(
    [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
)

# Zero-width / joiner / BOM. BOM at the very start of a document is
# allowed; a BOM anywhere else is a concealment surface.
ZERO_WIDTH_CODEPOINTS = frozenset([0x200B, 0x200C, 0x200D, 0x2060])
BOM_CODEPOINT = 0xFEFF

# C0 and C1 control characters, excluding tab (0x09), LF (0x0A), CR (0x0D).
def _is_control(cp: int) -> bool:
    if cp in (0x09, 0x0A, 0x0D):
        return False
    if 0x00 <= cp <= 0x1F:
        return True
    if 0x7F <= cp <= 0x9F:
        return True
    return False


# Private Use Area ranges, excluding Plane 14 Tags (that is MTC-001).
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


# ---------------------------------------------------------------------------
# Helpers used by multiple rules.
# ---------------------------------------------------------------------------

def _codepoints(s: str):
    for i, ch in enumerate(s):
        yield i, ord(ch), ch


def _describe_cp(cp: int) -> str:
    return "U+%04X" % cp


# Verbs commonly carried on tool names. The sets are intentionally short
# so a false positive does not fire on an ambiguous name; MTC-007 is
# MEDIUM, not HIGH, for this reason.
_WRITE_VERBS = (
    "write", "update", "delete", "create", "set", "put", "post", "patch",
    "send", "exec", "execute", "run", "insert", "upload", "modify",
    "remove", "destroy", "drop", "kill", "shutdown", "install", "deploy",
    "publish", "overwrite", "truncate", "rename", "move",
)
_READ_VERBS = (
    "read", "list", "get", "fetch", "search", "find", "query", "view",
    "show", "describe", "status", "info", "stat", "lookup", "load",
    "download", "preview", "scan", "inspect",
)


def _name_tokens(name: str) -> List[str]:
    """Lowercase word tokens from a tool name, splitting on dash,
    underscore, slash, dot, and camelCase boundaries.
    """
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    parts = re.split(r"[\s_\-./]+", name)
    return [p.lower() for p in parts if p]


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
    """Return the list of mixed-script word spans in ``s``. A word is
    a maximal run of letters/digits/underscore; a word mixes scripts
    when it contains codepoints from more than one of
    {latin, cyrillic, greek}.
    """
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


def _carries_pin(tool: dict, doc: dict) -> bool:
    """A pin is any of ``version``, ``revision``, ``digest``, ``sha256``,
    or ``hash`` on either the tool descriptor itself or on the enclosing
    document. The field value must be a non-empty string.
    """
    for scope in (tool, doc):
        if not isinstance(scope, dict):
            continue
        for key in ("version", "revision", "digest", "sha256", "hash"):
            v = scope.get(key)
            if isinstance(v, str) and v.strip():
                return True
    return False


# ---------------------------------------------------------------------------
# Rule check implementations.
# ---------------------------------------------------------------------------


def _check_tag_block(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    hits: List[Tuple[int, int]] = []
    for idx, cp, _ch in _codepoints(desc):
        if TAG_RANGE[0] <= cp <= TAG_RANGE[1]:
            hits.append((idx, cp))
    if not hits:
        return []
    first_idx, first_cp = hits[0]
    return [Finding(
        rule_id="MTC-001",
        severity=Severity.HIGH,
        message=(
            "tool description contains Unicode TAG block characters ("
            + _describe_cp(first_cp)
            + " at offset "
            + str(first_idx)
            + "; "
            + str(len(hits))
            + " total)"
        ),
        tool_name=name,
        pointer=pointer + ".description",
        path=path,
        hint=(
            "Plane 14 Tag characters (U+E0000-U+E007F) are invisible in "
            "approval dialogs but reach the model's tokenizer; strip them "
            "before display or reject the descriptor"
        ),
    )]


def _check_bidi(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    for idx, cp, _ in _codepoints(desc):
        if cp in BIDI_CODEPOINTS:
            return [Finding(
                rule_id="MTC-002",
                severity=Severity.HIGH,
                message=(
                    "tool description contains bidirectional-override "
                    "character " + _describe_cp(cp)
                    + " at offset " + str(idx)
                ),
                tool_name=name,
                pointer=pointer + ".description",
                path=path,
                hint=(
                    "Bidi overrides can reorder visible text away from "
                    "wire-order; strip or quote them before rendering"
                ),
            )]
    return []


def _check_zero_width(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    for idx, cp, _ in _codepoints(desc):
        if cp in ZERO_WIDTH_CODEPOINTS:
            return [Finding(
                rule_id="MTC-003",
                severity=Severity.HIGH,
                message=(
                    "tool description contains zero-width character "
                    + _describe_cp(cp) + " at offset " + str(idx)
                ),
                tool_name=name,
                pointer=pointer + ".description",
                path=path,
                hint=(
                    "Zero-width characters are a concealment surface; "
                    "either canonicalise descriptions to NFKC and strip "
                    "them, or reject the descriptor"
                ),
            )]
        if cp == BOM_CODEPOINT and idx != 0:
            return [Finding(
                rule_id="MTC-003",
                severity=Severity.HIGH,
                message=(
                    "tool description contains mid-string BOM "
                    "(U+FEFF) at offset " + str(idx)
                ),
                tool_name=name,
                pointer=pointer + ".description",
                path=path,
                hint="BOM is only legal at offset 0 of a document",
            )]
    return []


def _check_control(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    for idx, cp, _ in _codepoints(desc):
        if _is_control(cp):
            return [Finding(
                rule_id="MTC-004",
                severity=Severity.MEDIUM,
                message=(
                    "tool description contains control character "
                    + _describe_cp(cp) + " at offset " + str(idx)
                ),
                tool_name=name,
                pointer=pointer + ".description",
                path=path,
                hint=(
                    "C0 and C1 controls (excluding tab, newline, carriage "
                    "return) have no business in a tool description"
                ),
            )]
    return []


def _check_pua(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    for idx, cp, _ in _codepoints(desc):
        if _in_pua(cp):
            return [Finding(
                rule_id="MTC-005",
                severity=Severity.MEDIUM,
                message=(
                    "tool description contains private-use-area "
                    "character " + _describe_cp(cp)
                    + " at offset " + str(idx)
                ),
                tool_name=name,
                pointer=pointer + ".description",
                path=path,
                hint=(
                    "Private-use characters carry app-specific semantics "
                    "invisible under standard rendering"
                ),
            )]
    return []


def _check_missing_pin(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    doc = context.get("doc") or {}
    if _carries_pin(tool, doc):
        return []
    return [Finding(
        rule_id="MTC-006",
        severity=Severity.HIGH,
        message=(
            "tool descriptor missing version/hash pin (no version, "
            "revision, digest, sha256, or hash field at tool or "
            "document level)"
        ),
        tool_name=name,
        pointer=pointer,
        path=path,
        hint=(
            "Without a pin, a silent change to this tool's name, "
            "description, inputSchema, or annotations cannot be detected "
            "after the initial approval"
        ),
    )]


def _check_annotation_mismatch(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    ann = tool_annotations(tool)
    read_only = ann.get("readOnlyHint")
    destructive = ann.get("destructiveHint")
    tokens = _name_tokens(name)
    out: List[Finding] = []
    if read_only is True and any(t in _WRITE_VERBS for t in tokens):
        out.append(Finding(
            rule_id="MTC-007",
            severity=Severity.MEDIUM,
            message=(
                "annotations.readOnlyHint=true but tool name contains "
                "a write verb (" + ", ".join(
                    t for t in tokens if t in _WRITE_VERBS
                ) + ")"
            ),
            tool_name=name,
            pointer=pointer + ".annotations",
            path=path,
            hint=(
                "A silent flip of readOnlyHint while leaving the name "
                "intact is one of the annotation-flip shapes observed "
                "across reference MCP server releases"
            ),
        ))
    if destructive is True and any(t in _READ_VERBS for t in tokens):
        out.append(Finding(
            rule_id="MTC-007",
            severity=Severity.MEDIUM,
            message=(
                "annotations.destructiveHint=true but tool name "
                "contains a read verb (" + ", ".join(
                    t for t in tokens if t in _READ_VERBS
                ) + ")"
            ),
            tool_name=name,
            pointer=pointer + ".annotations",
            path=path,
            hint="see MTC-007 above",
        ))
    return out


def _check_annotations_missing(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    ann = tool_annotations(tool)
    if "readOnlyHint" in ann or "destructiveHint" in ann:
        return []
    return [Finding(
        rule_id="MTC-008",
        severity=Severity.MEDIUM,
        message=(
            "tool descriptor has no readOnlyHint or destructiveHint "
            "annotation"
        ),
        tool_name=name,
        pointer=pointer,
        path=path,
        hint=(
            "Without an annotation surface, downstream approval UI "
            "cannot pin the tool's effect class; absent is the same "
            "shape as 'flipped silently'"
        ),
    )]


def _check_input_schema(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    schema = tool_input_schema(tool)
    if schema is None:
        return [Finding(
            rule_id="MTC-009",
            severity=Severity.MEDIUM,
            message="tool descriptor has no inputSchema",
            tool_name=name,
            pointer=pointer,
            path=path,
            hint=(
                "A missing inputSchema accepts any payload shape; the "
                "approval record cannot bind the tool's argument "
                "surface"
            ),
        )]
    issues: List[str] = []
    if schema.get("type") != "object":
        issues.append("inputSchema.type is not 'object'")
    if "properties" not in schema or not isinstance(
        schema.get("properties"), dict
    ):
        issues.append("inputSchema.properties is missing")
    if schema.get("additionalProperties") is True:
        issues.append("inputSchema.additionalProperties is true")
    if not issues:
        return []
    return [Finding(
        rule_id="MTC-009",
        severity=Severity.MEDIUM,
        message="permissive inputSchema: " + "; ".join(issues),
        tool_name=name,
        pointer=pointer + ".inputSchema",
        path=path,
        hint=(
            "A permissive inputSchema is a silent-change surface: "
            "later releases can broaden the accepted payload without "
            "appearing in a schema-shape diff"
        ),
    )]


def _check_homoglyph(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    scopes: List[Tuple[str, str]] = [
        (pointer + ".name", name),
        (pointer + ".description", desc),
    ]
    for ptr, text in scopes:
        mixed = _has_homoglyph_word(text)
        if mixed:
            sample = mixed[0]
            return [Finding(
                rule_id="MTC-010",
                severity=Severity.MEDIUM,
                message=(
                    "cross-script word '" + sample
                    + "' mixes Latin / Cyrillic / Greek codepoints"
                ),
                tool_name=name,
                pointer=ptr,
                path=path,
                hint=(
                    "Homoglyph spans let an attacker publish a tool that "
                    "renders identical to an existing one; canonicalise "
                    "to a single script or reject"
                ),
            )]
    return []


def _check_name_hygiene(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    for idx, cp, _ in _codepoints(name):
        in_tag = TAG_RANGE[0] <= cp <= TAG_RANGE[1]
        in_bidi = cp in BIDI_CODEPOINTS
        in_zw = cp in ZERO_WIDTH_CODEPOINTS or (
            cp == BOM_CODEPOINT and idx != 0
        )
        in_ctrl = _is_control(cp)
        in_pua = _in_pua(cp)
        if in_tag or in_bidi or in_zw or in_ctrl or in_pua:
            label = (
                "TAG block" if in_tag
                else "bidi override" if in_bidi
                else "zero-width" if in_zw
                else "control" if in_ctrl
                else "private-use"
            )
            return [Finding(
                rule_id="MTC-011",
                severity=Severity.HIGH,
                message=(
                    "tool name contains " + label + " character "
                    + _describe_cp(cp) + " at offset " + str(idx)
                ),
                tool_name=name,
                pointer=pointer + ".name",
                path=path,
                hint=(
                    "The name field is a higher-trust surface than "
                    "description; concealment here contaminates the "
                    "primary approval anchor"
                ),
            )]
    return []


MIN_DESC_LEN = 10
MAX_DESC_LEN = 1500


def _check_length(tool, pointer, path, options, context):
    name = tool_name(tool, pointer)
    desc = tool_description(tool)
    n = len(desc)
    if n == 0:
        return [Finding(
            rule_id="MTC-012",
            severity=Severity.INFO,
            message="tool description is empty",
            tool_name=name,
            pointer=pointer + ".description",
            path=path,
            hint=(
                "An empty description leaves the model to infer purpose "
                "from the name alone; this is an underdocumentation "
                "surface for later annotation drift"
            ),
        )]
    if n < MIN_DESC_LEN:
        return [Finding(
            rule_id="MTC-012",
            severity=Severity.INFO,
            message=(
                "tool description is very short ("
                + str(n) + " chars; threshold "
                + str(MIN_DESC_LEN) + ")"
            ),
            tool_name=name,
            pointer=pointer + ".description",
            path=path,
            hint="see MTC-012 above",
        )]
    if n > MAX_DESC_LEN:
        return [Finding(
            rule_id="MTC-012",
            severity=Severity.INFO,
            message=(
                "tool description is very long ("
                + str(n) + " chars; threshold "
                + str(MAX_DESC_LEN) + ")"
            ),
            tool_name=name,
            pointer=pointer + ".description",
            path=path,
            hint=(
                "An unusually long description is a known adversarial-"
                "loading surface for metadata-poisoning payloads"
            ),
        )]
    return []


# ---------------------------------------------------------------------------
# The registry. Order matters: the shared contract tests assert MTC-001
# is first.
# ---------------------------------------------------------------------------

REGISTRY: List[Rule] = [
    Rule(
        id="MTC-001",
        severity=Severity.HIGH,
        title="Unicode TAG block characters in tool description",
        description=(
            "Plane 14 Tags (U+E0000-U+E007F) render as nothing in "
            "approval dialogs but reach the model tokenizer, giving an "
            "approval-view fidelity gap."
        ),
        check=_check_tag_block,
    ),
    Rule(
        id="MTC-002",
        severity=Severity.HIGH,
        title="Bidi override characters in tool description",
        description=(
            "LRE/RLE/PDF/LRO/RLO or isolate controls can reorder visible "
            "text away from wire order."
        ),
        check=_check_bidi,
    ),
    Rule(
        id="MTC-003",
        severity=Severity.HIGH,
        title="Zero-width or mid-string BOM in tool description",
        description=(
            "Zero-width characters are a concealment surface for "
            "metadata-poisoning payloads."
        ),
        check=_check_zero_width,
    ),
    Rule(
        id="MTC-004",
        severity=Severity.MEDIUM,
        title="C0/C1 control characters in tool description",
        description=(
            "Control bytes (except tab/newline/CR) are unexpected on a "
            "tool description surface."
        ),
        check=_check_control,
    ),
    Rule(
        id="MTC-005",
        severity=Severity.MEDIUM,
        title="Private-use area characters in tool description",
        description=(
            "PUA codepoints carry app-specific semantics invisible to "
            "standard rendering."
        ),
        check=_check_pua,
    ),
    Rule(
        id="MTC-006",
        severity=Severity.HIGH,
        title="Tool descriptor missing version/hash pin",
        description=(
            "Without a pin field, a silent change to this descriptor "
            "cannot be detected after the initial approval."
        ),
        check=_check_missing_pin,
    ),
    Rule(
        id="MTC-007",
        severity=Severity.MEDIUM,
        title="Annotation hint inconsistent with tool name verb",
        description=(
            "readOnlyHint=true on a 'write/delete/update'-named tool, "
            "or destructiveHint=true on a 'read/list/get'-named tool, "
            "is the annotation-flip shape."
        ),
        check=_check_annotation_mismatch,
    ),
    Rule(
        id="MTC-008",
        severity=Severity.MEDIUM,
        title="Tool descriptor missing readOnlyHint / destructiveHint",
        description=(
            "Without an annotation surface, the approval UI cannot pin "
            "the tool's effect class."
        ),
        check=_check_annotations_missing,
    ),
    Rule(
        id="MTC-009",
        severity=Severity.MEDIUM,
        title="Permissive or absent inputSchema",
        description=(
            "A missing or permissive inputSchema is a silent-change "
            "surface for the tool's argument shape."
        ),
        check=_check_input_schema,
    ),
    Rule(
        id="MTC-010",
        severity=Severity.MEDIUM,
        title="Cross-script homoglyph word in name or description",
        description=(
            "A word that mixes Latin, Cyrillic, and Greek codepoints "
            "is a spoofing surface."
        ),
        check=_check_homoglyph,
    ),
    Rule(
        id="MTC-011",
        severity=Severity.HIGH,
        title="Invisible or control characters in tool name",
        description=(
            "TAG, bidi, zero-width, control, or PUA codepoints in a "
            "name field contaminate the primary approval anchor."
        ),
        check=_check_name_hygiene,
    ),
    Rule(
        id="MTC-012",
        severity=Severity.INFO,
        title="Tool description length is unusual (<10 or >1500 chars)",
        description=(
            "Very short descriptions are an underdocumentation surface; "
            "very long descriptions are an adversarial-loading surface."
        ),
        check=_check_length,
    ),
]


def run_all(
    doc: Any,
    content: str,
    path: str,
    options: Options,
    tools: List[Tuple[str, dict]],
) -> List[Finding]:
    """Run every enabled rule against every extracted tool descriptor.

    ``tools`` is the output of ``parse.extract_tools(doc)``; passing it in
    rather than re-deriving lets the CLI tally ``tools_scanned`` once.
    """
    out: List[Finding] = []
    context = {"doc": doc, "content": content}
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO and not (
            options.strict or options.include_info
        ):
            continue
        for pointer, tool in tools:
            out.extend(rule.check(tool, pointer, path, options, context))
    out.sort(key=lambda f: (f.path, f.pointer, f.rule_id))
    return out


__all__ = ["Rule", "Check", "REGISTRY", "run_all"]
