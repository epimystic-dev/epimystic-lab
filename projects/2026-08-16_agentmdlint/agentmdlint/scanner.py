"""Filesystem discovery + orchestration."""

import os
from typing import List, Optional, Tuple

from .config import Config
from .parse import parse_document
from .rules import evaluate
from .types import FileReport, ScanReport


def discover_files(root: str, cfg: Config) -> List[str]:
    """Return canonical instruction-file paths under root, sorted deterministically.

    A single file path (not a directory) is treated as its own singleton candidate
    regardless of filename -- callers that need discovery filtering should pass a
    directory.
    """
    if os.path.isfile(root):
        return [os.path.normpath(root)]
    if not os.path.isdir(root):
        return []

    hits: List[str] = []
    lowered_targets = {t.lower(): t for t in cfg.files}

    for target in cfg.files:
        candidate = os.path.join(root, target)
        if os.path.isfile(candidate):
            hits.append(os.path.normpath(candidate))
            continue
        # case-insensitive fallback for canonical root-relative names
        target_dir = os.path.dirname(target)
        target_base = os.path.basename(target)
        dir_path = os.path.join(root, target_dir) if target_dir else root
        if os.path.isdir(dir_path):
            try:
                for entry in os.listdir(dir_path):
                    if entry.lower() == target_base.lower():
                        full = os.path.join(dir_path, entry)
                        if os.path.isfile(full):
                            hits.append(os.path.normpath(full))
            except OSError:
                pass

    # de-duplicate while preserving deterministic order
    seen = set()
    unique = []
    for p in sorted(hits):
        if p not in seen:
            seen.add(p)
            unique.append(p)

    if cfg.max_files and len(unique) > cfg.max_files:
        unique = unique[: cfg.max_files]
    return unique


def read_file(path: str, cfg: Config) -> Tuple[str, int, Optional[str]]:
    """Return (text, bytes_read, error).

    bytes_read is the on-disk size we ingested (capped at cfg.max_bytes). BOM is
    stripped from the text. If UTF-8 decode fails, we fall back to latin-1.
    """
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return "", 0, "stat_failed: " + str(e)
    try:
        with open(path, "rb") as fh:
            data = fh.read(cfg.max_bytes)
    except OSError as e:
        return "", 0, "read_failed: " + str(e)
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")
    bytes_read = min(size, len(data) + (3 if size > cfg.max_bytes else 0))
    return text, min(size, cfg.max_bytes), None


def scan_path(root: str, cfg: Optional[Config] = None) -> ScanReport:
    cfg = cfg or Config()
    report = ScanReport(root=os.path.normpath(root))
    files = discover_files(root, cfg)
    if not files:
        return report
    for path in files:
        text, bytes_read, err = read_file(path, cfg)
        fr = FileReport(path=path, bytes_read=bytes_read, read_error=err)
        if err is None:
            doc = parse_document(path, text)
            fr.findings = evaluate(doc, cfg, bytes_read)
        report.file_reports.append(fr)
    return report
