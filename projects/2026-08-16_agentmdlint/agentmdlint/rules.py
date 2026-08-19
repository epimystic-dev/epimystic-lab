"""Rule implementations.

Each rule is a pure function of (ParsedDocument, Config, bytes_length) that
returns a list of Findings for one file. The scanner concatenates results.

Rule IDs are stable identifiers (AGENTMD-NNN) and belong to a rule registry
so tests can assert every documented rule is implemented.
"""

from datetime import date
from typing import Callable, Dict, List, Tuple
import re

from .config import Config
from .parse import (
    ParsedDocument,
    jaccard,
    normalized_subject_tokens,
    polarity_of,
    tokenize_for_similarity,
    _DRIFT_RE,
)
from .types import Finding, Severity


RuleFn = Callable[[ParsedDocument, Config, int], List[Finding]]

RULE_REGISTRY: Dict[str, str] = {}


def _register(rule_id: str, description: str, fn: RuleFn) -> RuleFn:
    RULE_REGISTRY[rule_id] = description
    return fn


def _has_content_word(text: str) -> bool:
    return bool(re.search(r"[A-Za-z]{2,}", text))


# --- AGENTMD-001 -----------------------------------------------------------

def rule_001_bloat_bytes(doc: ParsedDocument, cfg: Config, bytes_len: int) -> List[Finding]:
    if bytes_len > cfg.hard_bytes:
        return [Finding(
            rule_id="AGENTMD-001",
            severity=Severity.HIGH,
            message=(
                "instruction-file byte size " + str(bytes_len)
                + " exceeds hard cap " + str(cfg.hard_bytes)
                + " (unbounded-growth pattern per arXiv 2608.11095)"
            ),
            path=doc.path,
            line=0,
            column=0,
            detail="bytes=" + str(bytes_len) + " hard=" + str(cfg.hard_bytes) + " soft=" + str(cfg.soft_bytes),
        )]
    if bytes_len > cfg.soft_bytes:
        return [Finding(
            rule_id="AGENTMD-001",
            severity=Severity.MEDIUM,
            message=(
                "instruction-file byte size " + str(bytes_len)
                + " exceeds soft cap " + str(cfg.soft_bytes)
            ),
            path=doc.path,
            line=0,
            column=0,
            detail="bytes=" + str(bytes_len) + " soft=" + str(cfg.soft_bytes),
        )]
    return []


rule_001_bloat_bytes = _register(
    "AGENTMD-001",
    "byte-size bloat (soft/hard cap on file bytes)",
    rule_001_bloat_bytes,
)


# --- AGENTMD-002 -----------------------------------------------------------

def rule_002_bloat_instructions(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    count = len(doc.imperatives)
    if count > cfg.hard_instructions:
        return [Finding(
            rule_id="AGENTMD-002",
            severity=Severity.HIGH,
            message=(
                "instruction count " + str(count)
                + " exceeds hard cap " + str(cfg.hard_instructions)
            ),
            path=doc.path,
            line=0,
            column=0,
            detail="count=" + str(count),
        )]
    if count > cfg.soft_instructions:
        return [Finding(
            rule_id="AGENTMD-002",
            severity=Severity.MEDIUM,
            message=(
                "instruction count " + str(count)
                + " exceeds soft cap " + str(cfg.soft_instructions)
            ),
            path=doc.path,
            line=0,
            column=0,
            detail="count=" + str(count),
        )]
    return []


rule_002_bloat_instructions = _register(
    "AGENTMD-002",
    "instruction-count bloat (soft/hard cap on imperative count)",
    rule_002_bloat_instructions,
)


# --- AGENTMD-003 -----------------------------------------------------------

def rule_003_duplicate_instructions(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    imperatives = doc.imperatives
    tokenized: List[Tuple[int, str, List[str]]] = []
    for line in imperatives:
        toks = tokenize_for_similarity(line.stripped)
        if len(toks) >= 3:
            tokenized.append((line.number, line.stripped, toks))

    seen_pairs = set()
    for i in range(len(tokenized)):
        for j in range(i + 1, len(tokenized)):
            ln_a, text_a, ta = tokenized[i]
            ln_b, text_b, tb = tokenized[j]
            sim = jaccard(ta, tb)
            if sim >= cfg.duplicate_threshold:
                key = (ln_a, ln_b)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                findings.append(Finding(
                    rule_id="AGENTMD-003",
                    severity=Severity.MEDIUM,
                    message=(
                        "near-duplicate instruction (jaccard "
                        + ("{:.2f}").format(sim) + " >= "
                        + ("{:.2f}").format(cfg.duplicate_threshold)
                        + ") with line " + str(ln_b)
                    ),
                    path=doc.path,
                    line=ln_a,
                    column=0,
                    detail="dupe_of_line=" + str(ln_b) + " jaccard=" + ("{:.4f}").format(sim),
                ))
    return findings


rule_003_duplicate_instructions = _register(
    "AGENTMD-003",
    "near-duplicate instructions (jaccard-token-set similarity)",
    rule_003_duplicate_instructions,
)


# --- AGENTMD-004 -----------------------------------------------------------

def rule_004_missing_rationale(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    lines = doc.lines
    n = len(lines)
    for idx, line in enumerate(lines):
        if not line.is_imperative:
            continue
        if line.has_rationale:
            continue
        # check immediately following non-blank line for rationale
        has_following = False
        for j in range(idx + 1, min(idx + 3, n)):
            nxt = lines[j]
            if nxt.is_blank:
                continue
            if nxt.is_heading:
                break
            if nxt.has_rationale:
                has_following = True
            break
        if has_following:
            continue
        findings.append(Finding(
            rule_id="AGENTMD-004",
            severity=Severity.INFO,
            message="imperative instruction with no rationale marker (paper 2608.11095: rationale prevents O(2^|D|) deletion cost)",
            path=doc.path,
            line=line.number,
            column=0,
            detail="",
        ))
    return findings


rule_004_missing_rationale = _register(
    "AGENTMD-004",
    "missing rationale on an imperative line",
    rule_004_missing_rationale,
)


# --- AGENTMD-005 -----------------------------------------------------------

def rule_005_dead_heading(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    for section in doc.sections:
        if section.heading_level == 0:
            continue
        # ignore leaf headings whose only "content" is subsections
        content_lines = [
            l for l in section.lines
            if not l.is_heading and not l.is_blank and not l.in_code_block
        ]
        if not content_lines:
            findings.append(Finding(
                rule_id="AGENTMD-005",
                severity=Severity.INFO,
                message="heading '" + section.heading_text + "' has an empty section",
                path=doc.path,
                line=section.heading_line,
                column=0,
                detail="",
            ))
            continue
        token_count = 0
        has_imperative = False
        for l in content_lines:
            token_count += len(tokenize_for_similarity(l.stripped))
            if l.is_imperative:
                has_imperative = True
        if not has_imperative and token_count < cfg.min_section_tokens:
            findings.append(Finding(
                rule_id="AGENTMD-005",
                severity=Severity.INFO,
                message=(
                    "heading '" + section.heading_text + "' has near-empty section ("
                    + str(token_count) + " tokens, no imperative)"
                ),
                path=doc.path,
                line=section.heading_line,
                column=0,
                detail="tokens=" + str(token_count),
            ))
    return findings


rule_005_dead_heading = _register(
    "AGENTMD-005",
    "dead heading (heading with empty or near-empty section)",
    rule_005_dead_heading,
)


# --- AGENTMD-006 -----------------------------------------------------------

def rule_006_drift_marker(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    for line in doc.lines:
        if not line.has_drift_marker:
            continue
        m = _DRIFT_RE.search(line.raw)
        if not m:
            continue
        col = m.start() + 1
        findings.append(Finding(
            rule_id="AGENTMD-006",
            severity=Severity.MEDIUM,
            message="drift marker '" + m.group(1) + "' inside an active instruction file",
            path=doc.path,
            line=line.number,
            column=col,
            detail="marker=" + m.group(1),
        ))
    return findings


rule_006_drift_marker = _register(
    "AGENTMD-006",
    "drift markers (TODO/FIXME/XXX/HACK/TBD/DEPRECATED) in an instruction file",
    rule_006_drift_marker,
)


# --- AGENTMD-007 -----------------------------------------------------------

_DATE_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")


def rule_007_stale_timestamp(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    today = cfg.today or date.today()
    for line in doc.lines:
        if line.in_code_block:
            continue
        for m in _DATE_RE.finditer(line.raw):
            try:
                y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                dt = date(y, mo, d)
            except ValueError:
                continue
            if dt > today:
                continue  # future-dated fragments are not stale
            age_days = (today - dt).days
            if age_days > cfg.stale_days:
                col = m.start() + 1
                findings.append(Finding(
                    rule_id="AGENTMD-007",
                    severity=Severity.MEDIUM,
                    message=(
                        "dated fragment " + m.group(0)
                        + " is " + str(age_days)
                        + " days old (>" + str(cfg.stale_days) + ")"
                    ),
                    path=doc.path,
                    line=line.number,
                    column=col,
                    detail="age_days=" + str(age_days),
                ))
                break  # one finding per line is enough
    return findings


rule_007_stale_timestamp = _register(
    "AGENTMD-007",
    "stale amendment date (YYYY-MM-DD older than --stale-days)",
    rule_007_stale_timestamp,
)


# --- AGENTMD-008 -----------------------------------------------------------

def rule_008_contradiction(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    by_subject: Dict[Tuple[str, ...], List[Tuple[int, str, str]]] = {}
    for line in doc.imperatives:
        pol = polarity_of(line.stripped.lower())
        if pol is None:
            continue
        subj = normalized_subject_tokens(line.stripped)
        if len(subj) < 3:
            continue
        by_subject.setdefault(subj, []).append((line.number, pol, line.stripped))
    for subj, entries in by_subject.items():
        pols = {p for _, p, _ in entries}
        if "positive" in pols and "negative" in pols:
            entries_sorted = sorted(entries, key=lambda x: x[0])
            first = entries_sorted[0]
            other = None
            for e in entries_sorted[1:]:
                if e[1] != first[1]:
                    other = e
                    break
            if other is None:
                continue
            findings.append(Finding(
                rule_id="AGENTMD-008",
                severity=Severity.HIGH,
                message=(
                    "candidate contradiction: line " + str(first[0])
                    + " (" + first[1] + ") vs line " + str(other[0])
                    + " (" + other[1] + ") share subject tokens "
                    + str(list(subj))
                ),
                path=doc.path,
                line=first[0],
                column=0,
                detail=(
                    "pair_line=" + str(other[0])
                    + " subject=" + ",".join(subj)
                ),
            ))
    return findings


rule_008_contradiction = _register(
    "AGENTMD-008",
    "candidate contradiction (same subject tokens, opposite polarity)",
    rule_008_contradiction,
)


# --- AGENTMD-009 -----------------------------------------------------------

def rule_009_no_purpose_header(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    """First non-blank, non-fence line should be a heading; the heading section
    should contain a purpose paragraph (at least one non-imperative prose line).
    """
    first_content_idx = -1
    for i, line in enumerate(doc.lines):
        if line.is_blank:
            continue
        if line.is_code_fence:
            continue
        if line.in_code_block:
            continue
        first_content_idx = i
        break
    if first_content_idx == -1:
        return []  # empty file -- separate handling elsewhere
    first_line = doc.lines[first_content_idx]
    if not first_line.is_heading:
        return [Finding(
            rule_id="AGENTMD-009",
            severity=Severity.INFO,
            message="file does not begin with a purpose heading",
            path=doc.path,
            line=first_line.number,
            column=0,
            detail="",
        )]
    # look for a prose paragraph in the heading's own section (level 0 or 1)
    top_section = None
    for section in doc.sections:
        if section.heading_line == first_line.number:
            top_section = section
            break
    if top_section is None:
        return []
    for l in top_section.lines:
        if l.is_heading:
            continue
        if l.is_blank:
            continue
        if l.in_code_block or l.is_code_fence:
            continue
        if not l.is_imperative and _has_content_word(l.stripped):
            return []
    return [Finding(
        rule_id="AGENTMD-009",
        severity=Severity.INFO,
        message=(
            "purpose heading '" + first_line.heading_text
            + "' has no descriptive prose paragraph"
        ),
        path=doc.path,
        line=first_line.number,
        column=0,
        detail="",
    )]


rule_009_no_purpose_header = _register(
    "AGENTMD-009",
    "missing purpose header (or purpose section has no prose)",
    rule_009_no_purpose_header,
)


# --- AGENTMD-010 -----------------------------------------------------------

def rule_010_imperative_wall(doc: ParsedDocument, cfg: Config, _bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    run_start = None
    run_length = 0
    reported_run_start = None
    for line in doc.lines:
        if line.is_imperative and not line.has_rationale:
            if run_start is None:
                run_start = line.number
                run_length = 1
            else:
                run_length += 1
            continue
        if line.is_blank:
            # blanks don't break the run but don't extend it
            continue
        # otherwise the run ends
        if run_length >= cfg.wall_length and reported_run_start != run_start:
            findings.append(Finding(
                rule_id="AGENTMD-010",
                severity=Severity.INFO,
                message=(
                    "imperative-wall of " + str(run_length)
                    + " lines with no rationale (paper 2608.11095: rationale halts growth)"
                ),
                path=doc.path,
                line=run_start,
                column=0,
                detail="length=" + str(run_length),
            ))
            reported_run_start = run_start
        run_start = None
        run_length = 0
    if run_length >= cfg.wall_length and reported_run_start != run_start:
        findings.append(Finding(
            rule_id="AGENTMD-010",
            severity=Severity.INFO,
            message=(
                "imperative-wall of " + str(run_length)
                + " lines with no rationale (paper 2608.11095: rationale halts growth)"
            ),
            path=doc.path,
            line=run_start,
            column=0,
            detail="length=" + str(run_length),
        ))
    return findings


rule_010_imperative_wall = _register(
    "AGENTMD-010",
    "imperative-wall (>= --wall-length consecutive imperatives without rationale)",
    rule_010_imperative_wall,
)


ALL_RULES: List[RuleFn] = [
    rule_001_bloat_bytes,
    rule_002_bloat_instructions,
    rule_003_duplicate_instructions,
    rule_004_missing_rationale,
    rule_005_dead_heading,
    rule_006_drift_marker,
    rule_007_stale_timestamp,
    rule_008_contradiction,
    rule_009_no_purpose_header,
    rule_010_imperative_wall,
]


def evaluate(doc: ParsedDocument, cfg: Config, bytes_len: int) -> List[Finding]:
    findings: List[Finding] = []
    for fn in ALL_RULES:
        findings.extend(fn(doc, cfg, bytes_len))
    return findings
