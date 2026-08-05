"""File discovery for aicontribcheck.

Walks a repo root (or accepts a single file path) and returns the set
of policy-surface files worth scanning. The discovery is deliberately
conservative: we look in ROOT and .github/ and docs/ only, and we cap
per-file size and total-file count so a malicious repo cannot make us
scan an unbounded number of large files.
"""

from __future__ import annotations

import os
from typing import Iterable, List, Optional, Tuple

# (kind, filename) -- filename match is case-insensitive.
_CANONICAL_NAMES: List[Tuple[str, str]] = [
    ("contributing", "CONTRIBUTING.md"),
    ("contributing", "CONTRIBUTING.rst"),
    ("contributing", "CONTRIBUTING.txt"),
    ("contributing", "CONTRIBUTING"),
    ("readme", "README.md"),
    ("readme", "README.rst"),
    ("readme", "README.txt"),
    ("readme", "README"),
    ("agents", "AGENTS.md"),
    ("agents", "AGENTS"),
    ("ai-policy", "AI_POLICY.md"),
    ("ai-policy", "AI-POLICY.md"),
    ("ai-policy", "AI_CONTRIBUTIONS.md"),
    ("ai-policy", "AI-CONTRIBUTIONS.md"),
    ("governance", "GOVERNANCE.md"),
    ("code-of-conduct", "CODE_OF_CONDUCT.md"),
    ("code-of-conduct", "CODE-OF-CONDUCT.md"),
    ("license", "LICENSE"),
    ("license", "LICENSE.md"),
    ("license", "LICENSE.txt"),
    ("license", "COPYING"),
    ("license", "COPYING.md"),
    ("pull-request-template", "PULL_REQUEST_TEMPLATE.md"),
    ("pull-request-template", "PULL_REQUEST_TEMPLATE"),
    ("issue-template", "ISSUE_TEMPLATE.md"),
    ("security", "SECURITY.md"),
]

# Where we look. Order matters for stable output.
_SEARCH_DIRS: List[str] = ["", ".github", "docs", ".github/PULL_REQUEST_TEMPLATE"]

# Safety caps.
MAX_FILE_BYTES = 512 * 1024  # 512 KiB per file
MAX_FILES = 40


def _match_name(entry: str) -> Optional[str]:
    """Return the canonical kind for an entry name, case-insensitively."""
    lower = entry.lower()
    for kind, name in _CANONICAL_NAMES:
        if lower == name.lower():
            return kind
    return None


def discover_policy_files(root: str) -> List[Tuple[str, str]]:
    """Return (kind, absolute_path) tuples for policy files in root.

    If `root` is a file, treat it as a single scan target (kind guessed
    from its name, falling back to "unknown"). Deterministic order.
    """
    if os.path.isfile(root):
        kind = _match_name(os.path.basename(root)) or "unknown"
        return [(kind, os.path.abspath(root))]

    if not os.path.isdir(root):
        return []

    out: List[Tuple[str, str]] = []
    seen: set = set()

    for subdir in _SEARCH_DIRS:
        d = os.path.join(root, subdir) if subdir else root
        if not os.path.isdir(d):
            continue
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for entry in entries:
            kind = _match_name(entry)
            if kind is None:
                continue
            path = os.path.abspath(os.path.join(d, entry))
            if path in seen:
                continue
            if not os.path.isfile(path):
                continue
            seen.add(path)
            out.append((kind, path))
            if len(out) >= MAX_FILES:
                return out
    return out


def read_policy_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (text, error). text is None if the read failed."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, f"stat failed: {exc}"
    if size > MAX_FILE_BYTES:
        return None, f"file too large ({size} bytes; cap {MAX_FILE_BYTES})"
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return None, f"read failed: {exc}"
    # Strip UTF-8 BOM if present.
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError as exc:
            return None, f"decode failed: {exc}"
    return text, None


def iter_lines(text: str) -> Iterable[Tuple[int, str]]:
    """Yield (1-indexed line number, line-without-newline) pairs."""
    for i, line in enumerate(text.splitlines(), start=1):
        yield i, line
