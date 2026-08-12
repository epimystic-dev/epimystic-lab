"""Filesystem scanner for skillcheck.

Discovers canonical skill-file locations under a repo checkout with strict
caps and deterministic ordering, and reads each file with a size cap and
UTF-8 (with latin-1 fallback) decoding. Independent of the rules engine.
"""

from __future__ import annotations

import os
from typing import Iterable, List, Optional, Tuple

from skillcheck.rules import evaluate_text, evaluate_structural
from skillcheck.verdict import Finding, Report, Verdict, Severity


CANONICAL_FILENAMES = frozenset(
    n.lower()
    for n in (
        "SKILL.md",
        "skill.md",
        "AGENT.md",
        "agent.md",
        "AGENTS.md",
        "agents.md",
        "SKILLS.md",
        "skills.md",
    )
)

CANONICAL_DIRECTORIES = ("skills", ".skills", "agents", ".agents", "prompts", ".prompts")

SKILL_SUFFIXES = (".skill.md", ".agent.md")

FILE_SIZE_CAP_BYTES = 512 * 1024
REPO_FILE_CAP = 40


def _is_skill_file(name: str) -> bool:
    low = name.lower()
    if low in CANONICAL_FILENAMES:
        return True
    for suf in SKILL_SUFFIXES:
        if low.endswith(suf):
            return True
    return False


def _within_canonical_dir(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    for part in parts[:-1]:
        if part.lower() in CANONICAL_DIRECTORIES:
            return True
    return False


def discover_skill_files(root: str) -> List[str]:
    """Return a deterministic list of absolute paths of candidate skill files
    under `root`. Descends into canonical skill directories unbounded but
    capped globally at REPO_FILE_CAP.

    A single-file `root` returns [root] iff it looks like a skill file.

    Descends into any of the canonical skill directories at the repository
    root: skills/, .skills/, agents/, .agents/, prompts/, .prompts/.
    """
    if not os.path.exists(root):
        return []
    if os.path.isfile(root):
        return [os.path.abspath(root)]

    root = os.path.abspath(root)
    candidates: List[str] = []

    # Top-level canonical filenames.
    try:
        for entry in sorted(os.listdir(root)):
            full = os.path.join(root, entry)
            if os.path.isfile(full) and _is_skill_file(entry):
                candidates.append(full)
    except OSError:
        pass

    # Canonical directories.
    for cdir in CANONICAL_DIRECTORIES:
        d = os.path.join(root, cdir)
        if os.path.isdir(d):
            for dpath, dnames, fnames in os.walk(d):
                dnames.sort()
                for fname in sorted(fnames):
                    if _is_skill_file(fname):
                        candidates.append(os.path.join(dpath, fname))

    # Deterministic order and dedupe.
    deduped: List[str] = []
    seen = set()
    for c in candidates:
        norm = os.path.normcase(os.path.abspath(c))
        if norm in seen:
            continue
        seen.add(norm)
        deduped.append(c)

    deduped.sort(key=lambda p: (os.path.dirname(p).lower(), os.path.basename(p).lower()))
    return deduped[:REPO_FILE_CAP]


def read_skill_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (text, error). Enforces FILE_SIZE_CAP_BYTES, strips UTF-8 BOM,
    falls back to latin-1 on decode failure.
    """
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return None, f"cannot stat {path}: {e}"
    if size > FILE_SIZE_CAP_BYTES:
        return None, f"file too large ({size} > {FILE_SIZE_CAP_BYTES}): {path}"
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return None, f"cannot read {path}: {e}"
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    return text, None


def scan_path(path: str) -> Report:
    """Scan `path` (file or directory) and return a Report."""
    files = discover_skill_files(path)
    all_findings: List[Finding] = []
    errors: List[str] = []
    files_used: List[str] = []
    if not files:
        if not os.path.exists(path):
            errors.append(f"path does not exist: {path}")
        return _finalize(Report(verdict=Verdict.UNKNOWN, findings=[], files_scanned=[], errors=errors))
    for f in files:
        text, err = read_skill_file(f)
        if err is not None:
            errors.append(err)
            continue
        files_used.append(f)
        all_findings.extend(evaluate_text(text, f))
        all_findings.extend(evaluate_structural(text, f))
    all_findings.sort(key=Finding.sort_key)
    return _finalize(Report(verdict=Verdict.UNKNOWN, findings=all_findings, files_scanned=files_used, errors=errors))


def _finalize(report: Report) -> Report:
    """Compute the verdict rollup from the report's findings."""
    has_crit = any(f.severity == Severity.CRITICAL for f in report.findings)
    has_high = any(f.severity == Severity.HIGH for f in report.findings)
    has_med = any(f.severity == Severity.MEDIUM for f in report.findings)
    has_info = any(f.severity == Severity.INFO for f in report.findings)
    non_info = has_crit or has_high or has_med

    if has_crit or has_high:
        report.verdict = Verdict.UNSAFE
    elif has_med:
        report.verdict = Verdict.SUSPICIOUS
    elif has_info and not non_info:
        report.verdict = Verdict.UNKNOWN
    elif not report.findings and report.files_scanned:
        report.verdict = Verdict.SAFE
    elif not report.files_scanned:
        report.verdict = Verdict.UNKNOWN
    else:
        report.verdict = Verdict.SAFE
    return report
