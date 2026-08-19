"""Lightweight markdown-ish structural parser for agent-instruction files.

We do not need a full markdown parser -- we need heading spans, code-fence
awareness (so instructions inside fenced code aren't classified as imperatives),
and per-line classification (heading | imperative | rationale | prose | blank |
code | list-item).
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# Heading: 1-6 leading '#' followed by whitespace then text.
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")

# Ordered/unordered list items.
_LIST_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+(.+)$")

# Code-fence: triple backtick or triple tilde, possibly with an info string.
_CODE_FENCE_RE = re.compile(r"^\s*(```|~~~)")

# Modal / imperative verbs that mark an instruction line.
# We keep this list conservative and public-domain-obvious.
_IMPERATIVE_MODALS = [
    "must",
    "must not",
    "mustn't",
    "should",
    "should not",
    "shouldn't",
    "shall",
    "shall not",
    "always",
    "never",
    "do not",
    "don't",
    "avoid",
    "prefer",
    "require",
    "required",
    "forbidden",
    "prohibited",
    "mandatory",
    "ensure",
    "make sure",
    "only",
]

# Rationale markers that indicate a "why" is attached (paper 2608.11095's remedy).
_RATIONALE_MARKERS = [
    "because",
    "why:",
    "why -",
    "rationale:",
    "rationale -",
    "reason:",
    "reason -",
    "reasoning:",
    "so that",
    "since ",
    "due to",
    "in order to",
    "otherwise",
]

# Drift markers per rule 006.
_DRIFT_MARKERS = ["TODO", "FIXME", "XXX", "HACK", "TBD", "DEPRECATED"]

# Rot marker regex compiled once, word-boundaried, case-sensitive (convention).
_DRIFT_RE = re.compile(r"\b(" + "|".join(_DRIFT_MARKERS) + r")\b")


@dataclass
class Line:
    number: int  # 1-based
    raw: str
    stripped: str
    is_blank: bool
    is_heading: bool
    heading_level: int  # 0 if not heading
    heading_text: str  # empty if not heading
    is_code_fence: bool
    in_code_block: bool  # inside a fenced code block
    is_list_item: bool
    list_content: str  # empty if not list
    is_imperative: bool
    has_rationale: bool  # rationale marker on this same line
    has_drift_marker: bool


@dataclass
class Section:
    heading_level: int  # 0 = document root (before any heading)
    heading_text: str
    heading_line: int  # 0 if root
    start_line: int
    end_line: int
    lines: List[Line] = field(default_factory=list)


@dataclass
class ParsedDocument:
    path: str
    text: str
    lines: List[Line] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)
    # convenient index
    imperatives: List[Line] = field(default_factory=list)


def _is_imperative_line(stripped_lower: str, in_code_block: bool) -> bool:
    """Return True if the line looks like an imperative instruction.

    Heuristic:
      - not inside a fenced code block
      - contains at least one imperative modal as a standalone token (case-insensitive)
      - is not itself a heading

    False positives happen (paper 2608.11095 documents that English-instruction
    detection is inherently imperfect); the rule engine reports imperative-derived
    findings only at INFO severity where appropriate.
    """
    if in_code_block:
        return False
    if not stripped_lower:
        return False
    for modal in _IMPERATIVE_MODALS:
        if _contains_phrase(stripped_lower, modal):
            return True
    return False


def _contains_phrase(text_lower: str, phrase: str) -> bool:
    """Case-insensitive whole-phrase search (word-boundaried on both sides)."""
    idx = text_lower.find(phrase)
    while idx != -1:
        before_ok = idx == 0 or not text_lower[idx - 1].isalnum()
        after_idx = idx + len(phrase)
        after_ok = after_idx == len(text_lower) or not text_lower[after_idx].isalnum()
        if before_ok and after_ok:
            return True
        idx = text_lower.find(phrase, idx + 1)
    return False


def _has_rationale(stripped_lower: str) -> bool:
    for marker in _RATIONALE_MARKERS:
        if _contains_phrase(stripped_lower, marker.rstrip(":- ")):
            return True
    # Parenthetical fragment of >= 8 chars also counts.
    m = re.search(r"\(([^)]{8,})\)", stripped_lower)
    if m:
        return True
    return False


def parse_document(path: str, text: str) -> ParsedDocument:
    """Parse text into a ParsedDocument. Never raises on user content."""
    if text.startswith("﻿"):
        text = text[1:]
    raw_lines = text.splitlines()
    doc = ParsedDocument(path=path, text=text)

    in_code = False
    for i, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        stripped_lower = stripped.lower()

        if _CODE_FENCE_RE.match(raw):
            # Toggle in_code AFTER classifying this line as fence itself.
            fence_line = Line(
                number=i,
                raw=raw,
                stripped=stripped,
                is_blank=stripped == "",
                is_heading=False,
                heading_level=0,
                heading_text="",
                is_code_fence=True,
                in_code_block=in_code,  # the fence marker itself sits at the edge
                is_list_item=False,
                list_content="",
                is_imperative=False,
                has_rationale=False,
                has_drift_marker=bool(_DRIFT_RE.search(raw)),
            )
            doc.lines.append(fence_line)
            in_code = not in_code
            continue

        if in_code:
            doc.lines.append(
                Line(
                    number=i,
                    raw=raw,
                    stripped=stripped,
                    is_blank=stripped == "",
                    is_heading=False,
                    heading_level=0,
                    heading_text="",
                    is_code_fence=False,
                    in_code_block=True,
                    is_list_item=False,
                    list_content="",
                    is_imperative=False,
                    has_rationale=False,
                    has_drift_marker=bool(_DRIFT_RE.search(raw)),
                )
            )
            continue

        heading_match = _HEADING_RE.match(raw)
        if heading_match:
            level = len(heading_match.group(1))
            text_part = heading_match.group(2).strip()
            doc.lines.append(
                Line(
                    number=i,
                    raw=raw,
                    stripped=stripped,
                    is_blank=False,
                    is_heading=True,
                    heading_level=level,
                    heading_text=text_part,
                    is_code_fence=False,
                    in_code_block=False,
                    is_list_item=False,
                    list_content="",
                    is_imperative=False,
                    has_rationale=False,
                    has_drift_marker=bool(_DRIFT_RE.search(raw)),
                )
            )
            continue

        list_match = _LIST_RE.match(raw)
        content_for_classification = list_match.group(1) if list_match else stripped
        content_lower = content_for_classification.lower()

        is_imp = _is_imperative_line(content_lower, in_code_block=False)
        line_obj = Line(
            number=i,
            raw=raw,
            stripped=stripped,
            is_blank=stripped == "",
            is_heading=False,
            heading_level=0,
            heading_text="",
            is_code_fence=False,
            in_code_block=False,
            is_list_item=bool(list_match),
            list_content=list_match.group(1) if list_match else "",
            is_imperative=is_imp,
            has_rationale=_has_rationale(content_lower),
            has_drift_marker=bool(_DRIFT_RE.search(raw)),
        )
        doc.lines.append(line_obj)
        if is_imp:
            doc.imperatives.append(line_obj)

    doc.sections = _build_sections(doc.lines)
    return doc


def _build_sections(lines: List[Line]) -> List[Section]:
    sections: List[Section] = []
    current: Optional[Section] = None
    root_section = Section(
        heading_level=0,
        heading_text="",
        heading_line=0,
        start_line=1,
        end_line=lines[-1].number if lines else 0,
        lines=[],
    )
    current = root_section

    for line in lines:
        if line.is_heading:
            # close previous
            current.end_line = line.number - 1
            sections.append(current)
            current = Section(
                heading_level=line.heading_level,
                heading_text=line.heading_text,
                heading_line=line.number,
                start_line=line.number,
                end_line=line.number,
                lines=[line],
            )
        else:
            current.lines.append(line)

    if current is not None:
        if lines:
            current.end_line = lines[-1].number
        sections.append(current)

    return sections


def tokenize_for_similarity(text: str) -> List[str]:
    """Lowercase alphanumeric token set for near-duplicate similarity."""
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if len(t) > 1]


def jaccard(a: List[str], b: List[str]) -> float:
    if not a and not b:
        return 0.0
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    if union == 0:
        return 0.0
    return inter / union


IMPERATIVE_POSITIVE_MODALS = {"must", "should", "shall", "always", "require", "required", "ensure", "make sure", "only", "prefer", "mandatory"}
IMPERATIVE_NEGATIVE_MODALS = {"must not", "mustn't", "should not", "shouldn't", "shall not", "never", "do not", "don't", "avoid", "forbidden", "prohibited"}


def polarity_of(stripped_lower: str) -> Optional[str]:
    """Return 'positive', 'negative', or None if no clear modal."""
    has_neg = any(_contains_phrase(stripped_lower, m) for m in IMPERATIVE_NEGATIVE_MODALS)
    has_pos = any(_contains_phrase(stripped_lower, m) for m in IMPERATIVE_POSITIVE_MODALS)
    if has_neg and not has_pos:
        return "negative"
    if has_pos and not has_neg:
        return "positive"
    if has_neg and has_pos:
        return "negative"  # negative wins on ties -- more informative
    return None


_STOPWORDS = {
    "a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "is", "are",
    "be", "by", "with", "as", "at", "it", "this", "that", "these", "those",
    "we", "you", "our", "your", "not", "no", "yes",
}
_MODAL_TOKENS = set()
for m in list(IMPERATIVE_POSITIVE_MODALS) + list(IMPERATIVE_NEGATIVE_MODALS):
    for t in m.split():
        _MODAL_TOKENS.add(t)


def normalized_subject_tokens(stripped: str) -> Tuple[str, ...]:
    """Tokens that identify the SUBJECT of an imperative, stripping modals
    and stopwords. Used for contradiction detection: two lines whose subject
    tokens match but whose polarity differs are candidate contradictions."""
    tokens = re.findall(r"[A-Za-z0-9']+", stripped.lower())
    out = []
    for t in tokens:
        if t in _STOPWORDS:
            continue
        if t in _MODAL_TOKENS:
            continue
        if len(t) <= 1:
            continue
        out.append(t)
    return tuple(sorted(out))
