"""Rule engine for aicontribcheck.

Each rule is a plain function taking a FileScan target (text + kind +
path) and appending Findings. Rules are grouped by verdict class so the
rollup step can reason about them without re-reading text.

Rules:
  AICONTRIB-001 -- explicit BAN of AI contributions found in text
  AICONTRIB-002 -- explicit ALLOW of AI contributions found in text
  AICONTRIB-003 -- CONDITIONAL: AI OK with disclosure required
  AICONTRIB-004 -- ATTRIBUTION: DCO / CLA / copyright-assignment obligation
  AICONTRIB-005 -- HUMAN REVIEW required
  AICONTRIB-006 -- TESTING required (INFO)
  AICONTRIB-007 -- NAMED TOOL mentioned (INFO evidence only)
  AICONTRIB-008 -- NON-COMMERCIAL LICENSE detected (INFO -- may affect
                    downstream reuse of AI-generated output)
  AICONTRIB-009 -- UNKNOWN: no relevant signal in any scanned file
                    (report-level, not per-file)
  AICONTRIB-010 -- CONFLICT: BAN and ALLOW signals in different files
                    (report-level, not per-file)
"""

from __future__ import annotations

from typing import Callable, List, Tuple

from . import patterns
from .types import Finding, FileScan, Verdict, Severity, RepoReport


RuleFn = Callable[[FileScan, str], None]


def _add(
    fs: FileScan,
    rule: str,
    severity: Severity,
    verdict: Verdict,
    message: str,
    line: int,
    evidence: str,
) -> None:
    fs.findings.append(
        Finding(
            rule=rule,
            severity=severity,
            verdict=verdict,
            message=message,
            file=fs.path,
            line=line,
            evidence=_snippet(evidence),
        )
    )


def _snippet(s: str, limit: int = 160) -> str:
    s = " ".join(s.split())
    if len(s) > limit:
        return s[: limit - 3] + "..."
    return s


def _lines(text: str):
    for i, line in enumerate(text.splitlines(), start=1):
        yield i, line


def rule_ban(fs: FileScan, text: str) -> None:
    for pat in patterns.pattern("ban"):
        for i, line in _lines(text):
            m = pat.search(line)
            if m:
                _add(
                    fs,
                    "AICONTRIB-001",
                    Severity.ERROR,
                    Verdict.BANNED,
                    "explicit ban of AI-authored contributions",
                    i,
                    line.strip(),
                )
                break  # one hit per pattern per file is enough


def rule_allow(fs: FileScan, text: str) -> None:
    for pat in patterns.pattern("allow"):
        for i, line in _lines(text):
            if pat.search(line):
                _add(
                    fs,
                    "AICONTRIB-002",
                    Severity.INFO,
                    Verdict.ALLOWED,
                    "explicit allow of AI-authored contributions",
                    i,
                    line.strip(),
                )
                break


def rule_disclosure(fs: FileScan, text: str) -> None:
    for pat in patterns.pattern("disclosure"):
        for i, line in _lines(text):
            if pat.search(line):
                _add(
                    fs,
                    "AICONTRIB-003",
                    Severity.WARN,
                    Verdict.CONDITIONAL,
                    "disclosure of AI usage required",
                    i,
                    line.strip(),
                )
                break


def rule_attribution(fs: FileScan, text: str) -> None:
    hits: List[Tuple[int, str, str]] = []
    for pat in patterns.pattern("attribution"):
        for i, line in _lines(text):
            m = pat.search(line)
            if m:
                hits.append((i, m.group(0).lower(), line.strip()))
                break
    if hits:
        # De-duplicate by matched token to avoid multiple identical findings.
        seen_tokens: set = set()
        for i, tok, line in hits:
            if tok in seen_tokens:
                continue
            seen_tokens.add(tok)
            _add(
                fs,
                "AICONTRIB-004",
                Severity.WARN,
                Verdict.CONDITIONAL,
                f"contributor attribution obligation ({tok})",
                i,
                line,
            )


def rule_review(fs: FileScan, text: str) -> None:
    for pat in patterns.pattern("review"):
        for i, line in _lines(text):
            if pat.search(line):
                _add(
                    fs,
                    "AICONTRIB-005",
                    Severity.WARN,
                    Verdict.CONDITIONAL,
                    "human review required for contributions",
                    i,
                    line.strip(),
                )
                break


def rule_testing(fs: FileScan, text: str) -> None:
    for pat in patterns.pattern("testing"):
        for i, line in _lines(text):
            if pat.search(line):
                _add(
                    fs,
                    "AICONTRIB-006",
                    Severity.INFO,
                    Verdict.CONDITIONAL,
                    "tests required for contributions",
                    i,
                    line.strip(),
                )
                break


def rule_tools(fs: FileScan, text: str) -> None:
    named: set = set()
    for pat in patterns.pattern("tools"):
        for i, line in _lines(text):
            m = pat.search(line)
            if m:
                tok = m.group(0).lower()
                if tok in named:
                    continue
                named.add(tok)
                _add(
                    fs,
                    "AICONTRIB-007",
                    Severity.INFO,
                    Verdict.UNKNOWN,
                    f"named AI tool referenced: {tok}",
                    i,
                    line.strip(),
                )


_NC_MARKERS = [
    "creativecommons.org/licenses/by-nc",
    "cc-by-nc",
    "cc by-nc",
    "cc by nc",
    "non-commercial",
    "noncommercial",
    "not for commercial use",
    "no commercial use",
]


def rule_noncommercial(fs: FileScan, text: str) -> None:
    if fs.kind != "license":
        return
    lower_lines = list(_lines(text))
    for token in _NC_MARKERS:
        for i, line in lower_lines:
            if token in line.lower():
                _add(
                    fs,
                    "AICONTRIB-008",
                    Severity.INFO,
                    Verdict.CONDITIONAL,
                    "non-commercial license clause detected",
                    i,
                    line.strip(),
                )
                return


RULES: List[Tuple[str, RuleFn]] = [
    ("AICONTRIB-001", rule_ban),
    ("AICONTRIB-002", rule_allow),
    ("AICONTRIB-003", rule_disclosure),
    ("AICONTRIB-004", rule_attribution),
    ("AICONTRIB-005", rule_review),
    ("AICONTRIB-006", rule_testing),
    ("AICONTRIB-007", rule_tools),
    ("AICONTRIB-008", rule_noncommercial),
]


def run_rules(fs: FileScan, text: str) -> None:
    """Run all rules against a single file scan target."""
    for _rid, fn in RULES:
        fn(fs, text)


def rollup(report: RepoReport) -> None:
    """Populate report.verdict / tools_named / required_disclosures /
    required_attributions from per-file findings.

    Rollup rules:
      * If any file has an AICONTRIB-001 finding => BANNED, unless another
        file has an ALLOW at higher precedence (rare) -- in which case we
        surface CONFLICT.
      * Else if any file has an AICONTRIB-002 finding and no BAN => ALLOWED.
      * Else if any file has a CONDITIONAL-verdict finding
        (AICONTRIB-003/004/005/006/008) => CONDITIONAL.
      * Else => UNKNOWN, and an AICONTRIB-009 finding is added to the
        first scanned file (or a synthetic file-record if none).
    """
    ban_files: set = set()
    allow_files: set = set()
    conditional_files: set = set()
    tools: set = set()
    disclosures: List[str] = []
    attributions: List[str] = []

    for fs in report.files_scanned:
        for f in fs.findings:
            if f.rule == "AICONTRIB-001":
                ban_files.add(fs.path)
            elif f.rule == "AICONTRIB-002":
                allow_files.add(fs.path)
            elif f.rule == "AICONTRIB-003":
                conditional_files.add(fs.path)
                disclosures.append(f.evidence)
            elif f.rule == "AICONTRIB-004":
                conditional_files.add(fs.path)
                attributions.append(f.message)
            elif f.rule == "AICONTRIB-005":
                conditional_files.add(fs.path)
            elif f.rule == "AICONTRIB-006":
                conditional_files.add(fs.path)
            elif f.rule == "AICONTRIB-007":
                # extract just the tool name after the colon
                tok = f.message.split(":", 1)[-1].strip()
                tools.add(tok)
            elif f.rule == "AICONTRIB-008":
                conditional_files.add(fs.path)

    if ban_files and allow_files:
        report.verdict = Verdict.CONFLICT
        # Attach a synthetic conflict finding to the first ban file.
        for fs in report.files_scanned:
            if fs.path in ban_files:
                _add(
                    fs,
                    "AICONTRIB-010",
                    Severity.ERROR,
                    Verdict.CONFLICT,
                    "conflicting AI-contribution signals across files "
                    f"(ban in {len(ban_files)} file(s); "
                    f"allow in {len(allow_files)} file(s))",
                    1,
                    "",
                )
                break
    elif ban_files:
        report.verdict = Verdict.BANNED
    elif allow_files:
        report.verdict = Verdict.ALLOWED
    elif conditional_files:
        report.verdict = Verdict.CONDITIONAL
    else:
        report.verdict = Verdict.UNKNOWN
        if report.files_scanned:
            fs = report.files_scanned[0]
            _add(
                fs,
                "AICONTRIB-009",
                Severity.INFO,
                Verdict.UNKNOWN,
                "no AI-contribution policy detected in any scanned file",
                1,
                "",
            )

    report.tools_named = sorted(tools)
    report.required_disclosures = sorted(set(disclosures))
    report.required_attributions = sorted(set(attributions))
