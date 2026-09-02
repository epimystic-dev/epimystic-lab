from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import List

from .config import Config
from .rules import ALL_RULES
from .types import Finding, ScanResult

BOM = "﻿"


def strip_bom(s: str) -> str:
    if s.startswith(BOM):
        return s[len(BOM):]
    return s


def read_text(path: Path, max_bytes: int) -> str:
    with open(path, "rb") as f:
        data = f.read(max_bytes)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return strip_bom(text)


def _matches_any_glob(name: str, globs: List[str]) -> bool:
    lower = name.lower()
    for g in globs:
        if fnmatch.fnmatch(lower, g.lower()):
            return True
    return False


def discover(path: Path, globs: List[str], max_files: int) -> List[Path]:
    if not path.exists():
        return []
    if path.is_file():
        if _matches_any_glob(path.name, globs):
            return [path]
        return []
    matches: List[Path] = []
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for fname in sorted(files):
            if _matches_any_glob(fname, globs):
                matches.append(Path(root) / fname)
                if len(matches) >= max_files:
                    return matches
    return matches


def scan_path(path: Path, config: Config) -> ScanResult:
    result = ScanResult()
    files = discover(path, config.globs, config.max_files)
    result.files_scanned = len(files)
    enabled_rules = [r for r in ALL_RULES if r.id not in config.disabled_rules]
    for f in files:
        try:
            text = read_text(f, config.max_bytes)
        except OSError as exc:
            result.errors.append((str(f), f"read-error: {exc}"))
            continue
        findings: List[Finding] = []
        for rule in enabled_rules:
            try:
                findings.extend(rule.check(text, str(f)))
            except Exception as exc:  # defensive: no rule may crash the run
                result.errors.append((str(f), f"rule-error {rule.id}: {exc}"))
        result.findings.extend(findings)
    result.findings.sort(key=lambda x: x.sort_key())
    return result
