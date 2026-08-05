"""Regex patterns used by the rule engine.

Patterns are compiled lazily via `pattern()` so tests can inspect the raw
source strings. All patterns are case-insensitive and match on a single
line at a time; the scanner walks the file line-by-line so line numbers
in findings are meaningful.

Vendor neutrality is deliberate and load-bearing here. The shipped patterns
match only **generic** markers ("ai", "llm", "ai-generated", "coding agent",
...), which is how the overwhelming majority of real contribution policies
are actually worded. Specific product names are NOT hardcoded, for two
reasons: the set of assistant products churns every few months, so a baked-in
list is stale on arrival; and a published linter should not carry one
vendor's trademarks in its source. Instead, callers register the names they
care about at runtime:

    from aicontribcheck import patterns
    patterns.register_tool_names(["some-assistant", "another-tool"])

or, from the CLI, `--extra-tool-name some-assistant` (repeatable). Registered
names extend both the AI marker used by the ban/allow/disclosure rules and
the named-tool evidence rule (AICONTRIB-007).
"""

import re
from typing import Dict, Iterable, List, Pattern

# Generic, vendor-neutral AI markers. These carry the detection load.
_GENERIC_AI_TERMS: str = (
    r"ai|artificial\s+intelligence|llm|large\s+language\s+model|"
    r"machine[- ]generated|ai[- ]generated|ai[- ]authored|ai[- ]written|"
    r"generative\s+ai|coding[- ]agent|ai[- ]agent|ai[- ]assistant|ai[- ]assisted"
)

# User-registered product names (empty by default -- see the module docstring).
_EXTRA_TOOL_NAMES: List[str] = []


def register_tool_names(names: Iterable[str]) -> None:
    """Register additional assistant/product names to recognise.

    Names are matched case-insensitively on word boundaries and are regex-escaped,
    so callers pass plain strings, not patterns. Re-registering resets the compiled
    cache so the new names take effect immediately.
    """
    for raw in names:
        name = (raw or "").strip()
        if name and name.lower() not in [n.lower() for n in _EXTRA_TOOL_NAMES]:
            _EXTRA_TOOL_NAMES.append(name)
    _CACHE.clear()


def clear_tool_names() -> None:
    """Forget every registered name (used by tests to isolate cases)."""
    _EXTRA_TOOL_NAMES.clear()
    _CACHE.clear()


def registered_tool_names() -> List[str]:
    """The currently registered product names, in registration order."""
    return list(_EXTRA_TOOL_NAMES)


def _ai_marker() -> str:
    """The AI-marker alternation: generic terms plus any registered names."""
    extra = "|".join(re.escape(n) for n in _EXTRA_TOOL_NAMES)
    return _GENERIC_AI_TERMS + ("|" + extra if extra else "")


# BAN signals -- explicit statements that AI-authored contributions are
# not accepted. These are conservative: we require an explicit refusal
# verb ("do not accept", "banned", "not allowed", "prohibited"), plus an
# AI marker in the same line. Bare mentions of "AI" without a refusal
# verb do NOT trigger (see rule AICONTRIB-001 tests).
def _ban_sources() -> List[str]:
    ai = _ai_marker()
    return [
        # "we do not accept ai-generated contributions"
        r"\b(?:do(?:es)?\s+not|will\s+not|cannot|can'?t|refuse\s+to|refuses\s+to)\s+"
        r"(?:accept|allow|merge|review|consider)\b[^.\n]{0,80}?"
        r"\b(?:" + ai + r")\b",
        # "ai-generated contributions are not allowed / banned / prohibited /
        # forbidden / rejected / disallowed"
        r"\b(?:" + ai + r")\b"
        r"[^.\n]{0,80}?"
        r"\b(?:are\s+not\s+(?:allowed|accepted|welcome|permitted)|"
        r"is\s+not\s+(?:allowed|accepted|welcome|permitted)|"
        r"banned|prohibited|forbidden|disallowed|rejected|not\s+permitted|"
        r"will\s+be\s+(?:rejected|closed))\b",
        # "no ai-generated code" / "no ai contributions"
        r"\bno\s+(?:" + ai + r")[^.\n]{0,50}?"
        r"\b(?:code|contribution|contributions|pr|prs|pull\s+request|pull\s+requests|"
        r"patch|patches|commit|commits|content)\b",
        # "human-authored code only" / "human-written only"
        r"\bhuman[- ](?:authored|written|generated|only)\b[^.\n]{0,50}?"
        r"\b(?:code|contribution|contributions|only|required|mandatory)\b",
    ]


# ALLOW signals -- explicit statements welcoming AI-authored contributions.
def _allow_sources() -> List[str]:
    ai = _ai_marker()
    return [
        r"\b(?:" + ai + r")\b"
        r"[^.\n]{0,80}?"
        r"\b(?:are\s+(?:welcome|encouraged|allowed|accepted|permitted)|"
        r"is\s+(?:welcome|encouraged|allowed|accepted|permitted)|"
        r"we\s+welcome|we\s+accept|we\s+encourage)\b",
        r"\bwe\s+(?:welcome|accept|encourage|allow|permit)\b[^.\n]{0,80}?"
        r"\b(?:" + ai + r")\b[^.\n]{0,50}?"
        r"\b(?:contribution|contributions|code|pr|prs|pull\s+request|pull\s+requests|"
        r"patch|patches|commit|commits)\b",
    ]


# CONDITIONAL signals -- AI OK, but disclosure required.
def _disclosure_sources() -> List[str]:
    ai = _ai_marker()
    return [
        # "ai-authored contributions must be disclosed"
        r"\b(?:" + ai + r")\b"
        r"[^.\n]{0,80}?"
        r"\b(?:must|should|shall|need\s+to|required\s+to|has\s+to|have\s+to)\s+"
        r"(?:be\s+)?(?:disclosed|declared|noted|marked|labeled|labelled|"
        r"acknowledged|indicated)\b",
        # "please disclose ai usage" / "note if ai tools were used"
        r"\b(?:please\s+)?(?:disclose|declare|note|mark|indicate|acknowledge)\b"
        r"[^.\n]{0,80}?"
        r"\b(?:" + ai + r"|ai\s+tool|ai\s+tools|ai\s+use|ai\s+usage|"
        r"ai\s+assist(?:ance|ed)?)\b",
        # "co-authored-by" style attribution requirement for AI
        r"\bco[- ]authored[- ]by\b[^.\n]{0,80}?"
        r"\b(?:" + ai + r"|assistant)\b",
    ]


# ATTRIBUTION / COPYRIGHT signals -- contributions must be assigned or
# signed-off. Assignment-required repos are typically hostile to AI-generated
# code because the contributor cannot assign copyright over generated code
# in many jurisdictions.
_ATTRIBUTION_SOURCES: List[str] = [
    r"\bcopyright\s+(?:assign(?:ment|ed)?|transfer(?:red)?)\b",
    r"\bassign(?:ing|s|ed)?\s+(?:the\s+)?copyright\b",
    r"\btransfer(?:ring|s|red)?\s+(?:the\s+)?copyright\b",
    r"\bcontributor\s+license\s+agreement\b",
    r"\bCLA\b",
    r"\bdeveloper\s+certificate\s+of\s+origin\b",
    r"\bDCO\b",
    r"\bsigned[- ]off[- ]by\b",
    r"\bsign[- ]off\b",
]

# HUMAN REVIEW requirements -- contributions require human review.
_REVIEW_SOURCES: List[str] = [
    r"\bhuman\s+review(?:er|ed)?\s+required\b",
    r"\brequires?\s+human\s+review\b",
    r"\bmust\s+be\s+reviewed\s+by\s+(?:a\s+)?human\b",
    r"\btwo[- ]person\s+rule\b|\bfour[- ]eyes\s+(?:rule|principle|review)\b",
]


# Named-tool references (evidence, not a verdict by itself). Empty until the
# caller registers the names it cares about -- the tool ships vendor-neutral.
def _tool_name_sources() -> List[str]:
    return [r"\b" + re.escape(n) + r"\b" for n in _EXTRA_TOOL_NAMES]


# TESTING / COVERAGE requirements.
_TESTING_SOURCES: List[str] = [
    r"\btests?\s+(?:are\s+)?required\b",
    r"\brequires?\s+tests?\b",
    r"\bmust\s+(?:include|add|write)\s+tests?\b",
    r"\bnew\s+code\s+must\s+be\s+covered\s+by\s+tests?\b",
    r"\btest\s+coverage\s+(?:required|mandatory)\b",
]


def _compile(sources_: List[str]) -> List[Pattern[str]]:
    return [re.compile(s, re.IGNORECASE) for s in sources_]


_CACHE: Dict[str, List[Pattern[str]]] = {}


def _sources_for(kind: str) -> List[str]:
    return {
        "ban": _ban_sources,
        "allow": _allow_sources,
        "disclosure": _disclosure_sources,
        "attribution": lambda: _ATTRIBUTION_SOURCES,
        "review": lambda: _REVIEW_SOURCES,
        "tools": _tool_name_sources,
        "testing": lambda: _TESTING_SOURCES,
    }[kind]()


def pattern(kind: str) -> List[Pattern[str]]:
    """Return the compiled patterns for a rule family."""
    if kind not in _CACHE:
        _CACHE[kind] = _compile(_sources_for(kind))
    return _CACHE[kind]


def sources(kind: str) -> List[str]:
    """Return the raw regex source strings (for testing / diagnostics)."""
    return _sources_for(kind)
