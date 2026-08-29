"""Filesystem discovery + safe source reads."""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import List, Optional, Tuple

from oraclecheck.config import Config
from oraclecheck.parse import parse_source, strip_bom
from oraclecheck.rules import evaluate_module
from oraclecheck.types import Finding, ScanResult


def infer_sut_module(path: str) -> Optional[str]:
    """Heuristic: given `tests/test_foo.py` -> 'foo'; `test_foo.py` -> 'foo';
    `foo_test.py` -> 'foo'. Returns None for filenames that don't match.
    """
    name = os.path.basename(path)
    stem, ext = os.path.splitext(name)
    if ext != ".py":
        return None
    if stem.startswith("test_"):
        return stem[len("test_"):]
    if stem.endswith("_test"):
        return stem[: -len("_test")]
    if stem == "tests":
        return None
    return None


def discover_test_files(root: str, config: Config) -> List[str]:
    """Return absolute paths of test files under `root`, respecting max_files.

    Discovery order: deterministic sort by relative path.
    A single-file path is returned unmodified as a singleton if it exists.
    """
    root_path = Path(root)
    if not root_path.exists():
        return []
    if root_path.is_file():
        return [str(root_path.resolve())]

    matches: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames.sort()
        for fn in sorted(filenames):
            fn_lower = fn.lower()
            for pat in config.test_globs:
                if _fnmatch_ci(fn_lower, pat.lower()):
                    matches.append(str(Path(dirpath) / fn))
                    break
    matches.sort()
    if len(matches) > config.max_files:
        matches = matches[: config.max_files]
    return matches


def _fnmatch_ci(name: str, pat: str) -> bool:
    """Simple case-insensitive glob: only *, ?; no character classes."""
    from fnmatch import fnmatchcase
    return fnmatchcase(name, pat)


def read_source(path: str, config: Config) -> Tuple[Optional[str], Optional[str]]:
    """Read a file to text. Returns (source, err). Enforces max_bytes."""
    try:
        with open(path, "rb") as f:
            raw = f.read(config.max_bytes + 1)
        truncated = len(raw) > config.max_bytes
        if truncated:
            raw = raw[: config.max_bytes]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        return strip_bom(text), None
    except FileNotFoundError:
        return None, f"file not found: {path}"
    except PermissionError:
        return None, f"permission denied: {path}"
    except OSError as e:
        return None, f"read error: {path}: {e}"


def scan_path(root: str, config: Config) -> List[ScanResult]:
    """Discover and evaluate every test file under `root`. Returns per-file
    ScanResult (with findings or error). Findings within each file are sorted.
    """
    files = discover_test_files(root, config)
    results: List[ScanResult] = []
    for f in files:
        result = ScanResult(path=f)
        text, err = read_source(f, config)
        if err is not None:
            result.error = err
            results.append(result)
            continue
        module = parse_source(text or "", f)
        if module is None:
            result.error = "syntax error"
            results.append(result)
            continue
        # Per-file SUT hint; fall back to config.sut_module if set.
        sut = config.sut_module or infer_sut_module(f)
        per_file_cfg = _with_sut(config, sut)
        findings = evaluate_module(module, text or "", f, per_file_cfg)
        result.findings = findings
        results.append(result)
    return results


def _with_sut(config: Config, sut: Optional[str]) -> Config:
    return Config(
        max_files=config.max_files,
        max_bytes=config.max_bytes,
        test_globs=config.test_globs,
        test_dirs=config.test_dirs,
        assert_methods=config.assert_methods,
        sut_module=sut,
        include_info=config.include_info,
        strict=config.strict,
        disabled_rules=config.disabled_rules,
    )
