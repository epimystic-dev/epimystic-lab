"""File-system scanner for nbshape.

Walks a path, opens every *.ipynb it finds, and applies the rule table. Nothing
here executes notebook code, spawns a process, or opens a socket.

Checkpoint files are SKIPPED by default. A .ipynb_checkpoints directory holds
near-duplicates of its parent notebooks, so scanning them by default would
roughly double every finding count on a real repository and destroy the signal
in the rolled-up verdict. Pass --include-checkpoints to opt in.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .parse import build_notebook, load_json_text, prepare_cell, strip_bom
from .rules import RuleConfig, RuleContext, run_rules
from .types import Finding, ScanResult


DEFAULT_GLOBS: Tuple[str, ...] = ("*.ipynb",)
CHECKPOINT_DIR = ".ipynb_checkpoints"

#: Directories a repository walk should never descend into. Skipping them is a
#: speed and noise decision, not a security one.
SKIP_DIRS = frozenset(
    (
        ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
        "env", ".env", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", "site-packages", ".idea", ".vscode", "build", "dist",
        ".eggs", ".ipynb_checkpoints",
    )
)

#: Output-heavy real notebooks reach 100 MB and json.load holds the whole parse
#: in memory, so the default cap is deliberately generous but finite.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FILES = 2000


@dataclass
class FileOutcome:
    """What happened to one file."""

    path: str
    findings: List[Finding] = field(default_factory=list)
    #: True when the conformance gate passed and the full rule table ran.
    scored: bool = False
    #: Human-readable diagnostic for stderr, or None.
    error: Optional[str] = None


def _matches_any(name: str, globs: Sequence[str]) -> bool:
    lname = name.lower()
    for pat in globs:
        if fnmatch.fnmatchcase(lname, pat.lower()):
            return True
    return False


def discover(
    root: str,
    globs: Sequence[str] = DEFAULT_GLOBS,
    max_files: int = DEFAULT_MAX_FILES,
    include_checkpoints: bool = False,
) -> List[str]:
    """Return matching files under ``root``, in a deterministic order.

    A path naming a single file is always honoured, even inside a checkpoint
    directory - an explicit request beats the default skip.
    """
    if not os.path.exists(root):
        return []
    if os.path.isfile(root):
        if _matches_any(os.path.basename(root), globs):
            return [root]
        return []
    hits: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            if d == CHECKPOINT_DIR:
                if include_checkpoints:
                    keep.append(d)
                continue
            if d in SKIP_DIRS:
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            if _matches_any(fn, globs):
                hits.append(os.path.join(dirpath, fn))
                if len(hits) >= max_files:
                    return hits
    return hits


def read_notebook_text(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> Tuple[Optional[str], Optional[str], int]:
    """Read a notebook file as text.

    Returns (text_or_None, error_or_None, file_bytes). The size is checked with
    a stat BEFORE the read, so an oversized file is never loaded into memory.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, "stat-error: " + path + ": " + str(exc), 0
    if size > max_bytes:
        return (
            None,
            "over-size-cap: " + path + ": " + str(size) + " bytes exceeds the "
            + str(max_bytes) + "-byte --max-bytes cap; not parsed",
            size,
        )
    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError as exc:
        return None, "read-error: " + path + ": " + str(exc), size
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return (
            None,
            "encoding-error: " + path + ": not valid UTF-8 (" + str(exc.reason) + "); "
            "the nbformat schema requires UTF-8 JSON",
            size,
        )
    return strip_bom(text), None, size


def scan_file(
    path: str,
    disabled=frozenset(),
    max_bytes: int = DEFAULT_MAX_BYTES,
    config: Optional[RuleConfig] = None,
) -> FileOutcome:
    """Scan one notebook file. Never raises on bad input."""
    cfg = config if config is not None else RuleConfig()
    text, err, size = read_notebook_text(path, max_bytes=max_bytes)
    if text is None:
        return FileOutcome(path=path, findings=[], scored=False, error=err)

    obj, jerr = load_json_text(text)
    if jerr is not None:
        nb = build_notebook(None, file_bytes=size)
        nb.gate_reason = jerr
        ctx = RuleContext(nb=nb, text=text, path=path, codes=tuple(), config=cfg)
        findings, _gated = run_rules(ctx, disabled=disabled)
        return FileOutcome(
            path=path,
            findings=findings,
            scored=False,
            error="unparseable: " + path + ": " + jerr,
        )

    nb = build_notebook(obj, file_bytes=size)
    codes = tuple(prepare_cell(c) for c in nb.cells if c.is_code)
    ctx = RuleContext(nb=nb, text=text, path=path, codes=codes, config=cfg)
    findings, gated = run_rules(ctx, disabled=disabled)
    if gated:
        return FileOutcome(
            path=path,
            findings=findings,
            scored=False,
            error="not-a-notebook: " + path + ": " + (nb.gate_reason or "gate rule fired"),
        )
    return FileOutcome(path=path, findings=findings, scored=True, error=None)


def scan_path(
    root: str,
    globs: Sequence[str] = DEFAULT_GLOBS,
    disabled=frozenset(),
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    include_checkpoints: bool = False,
    config: Optional[RuleConfig] = None,
) -> ScanResult:
    """Walk ``root`` and scan every matching notebook."""
    files = discover(
        root, globs=globs, max_files=max_files, include_checkpoints=include_checkpoints
    )
    all_findings: List[Finding] = []
    errors: List[str] = []
    scored = 0
    for p in files:
        outcome = scan_file(p, disabled=disabled, max_bytes=max_bytes, config=config)
        all_findings.extend(outcome.findings)
        if outcome.error:
            errors.append(outcome.error)
        if outcome.scored:
            scored += 1
    all_findings.sort(key=lambda f: f.sort_key())
    return ScanResult(
        files_scanned=len(files),
        files_scored=scored,
        files_unknown=len(files) - scored,
        findings=tuple(all_findings),
        errors=tuple(errors),
    )
