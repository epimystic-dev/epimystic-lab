"""Documented ingestion limits, with provenance.

Every number in this table is one vendor's published code-scanning ingest
ceiling. NONE of them is part of the OASIS SARIF 2.1.0 specification. The
vendor changes these numbers; a linter that silently encodes a stale
constant becomes a liar rather than a helper, so each entry carries the
documentation URL it came from and the date that URL was read.

Override any of them on the command line:

    sarifcheck --limit max_results_per_run=10000 results.sarif
    sarifcheck --limits-file my_endpoint.json results.sarif
    sarifcheck --show-limits

Sources, read 2026-09-18:

  results-exceed-limit
    https://docs.github.com/en/code-security/code-scanning/troubleshooting-sarif-uploads/results-exceed-limit
  results-file-too-large
    https://docs.github.com/en/code-security/code-scanning/troubleshooting-sarif-uploads/results-file-too-large
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


RETRIEVED = "2026-09-18"

URL_EXCEED = (
    "https://docs.github.com/en/code-security/code-scanning/"
    "troubleshooting-sarif-uploads/results-exceed-limit"
)
URL_TOO_LARGE = (
    "https://docs.github.com/en/code-security/code-scanning/"
    "troubleshooting-sarif-uploads/results-file-too-large"
)


@dataclass(frozen=True)
class Limit:
    name: str
    value: int
    kind: str  # "hard" (upload rejected) or "soft" (data dropped / not shown)
    unit: str
    source_url: str
    retrieved: str
    note: str


ALL_LIMITS: Sequence[Limit] = (
    Limit(
        "max_runs_per_file", 20, "hard", "runs",
        URL_EXCEED, RETRIEVED,
        "more than this many runs[] entries in one file rejects the upload",
    ),
    Limit(
        "max_results_per_run", 25000, "hard", "results",
        URL_EXCEED, RETRIEVED,
        "more than this many results in one run rejects the upload",
    ),
    Limit(
        "max_rules_per_run", 25000, "hard", "rules",
        URL_EXCEED, RETRIEVED,
        "rule descriptors per run, counted across driver and every extension",
    ),
    Limit(
        "max_locations_per_result", 1000, "hard", "locations",
        URL_EXCEED, RETRIEVED,
        "locations[] entries on a single result",
    ),
    Limit(
        "max_threadflow_locations_per_result", 10000, "hard", "locations",
        URL_EXCEED, RETRIEVED,
        "thread flow locations on one result, summed across all codeFlows",
    ),
    Limit(
        "max_tags_per_rule", 20, "hard", "tags",
        URL_EXCEED, RETRIEVED,
        "properties.tags entries on one rule descriptor",
    ),
    Limit(
        "max_compressed_bytes", 10485760, "hard", "bytes",
        URL_TOO_LARGE, RETRIEVED,
        "gzip-compressed upload payload size (10 MB); SARIF is repetitive "
        "JSON and compresses heavily, so the uncompressed size is a poor "
        "proxy - sarifcheck compresses the file with zlib and compares that",
    ),
    Limit(
        "soft_results_per_run", 5000, "soft", "results",
        URL_EXCEED, RETRIEVED,
        "results beyond this count in one run are not all shown",
    ),
    Limit(
        "soft_locations_per_result", 100, "soft", "locations",
        URL_EXCEED, RETRIEVED,
        "locations beyond this count on one result are not all shown",
    ),
    Limit(
        "soft_threadflow_locations_per_result", 1000, "soft", "locations",
        URL_EXCEED, RETRIEVED,
        "thread flow locations beyond this count are not all shown",
    ),
    Limit(
        "soft_tags_per_rule", 10, "soft", "tags",
        URL_EXCEED, RETRIEVED,
        "tags beyond this count on one rule are not all shown",
    ),
)


LIMIT_NAMES: Tuple[str, ...] = tuple(limit.name for limit in ALL_LIMITS)


def default_limits() -> Dict[str, int]:
    return dict((limit.name, limit.value) for limit in ALL_LIMITS)


def limit_by_name(name: str) -> Optional[Limit]:
    for limit in ALL_LIMITS:
        if limit.name == name:
            return limit
    return None


def describe(name: str) -> str:
    """One-line provenance string used inside finding messages."""
    limit = limit_by_name(name)
    if limit is None:
        return name + " (no provenance on record)"
    return (
        name + "=" + str(limit.value) + " (" + limit.kind + "; documented "
        + limit.retrieved + " at " + limit.source_url + ")"
    )


def render_table() -> str:
    """Human-readable dump used by --show-limits."""
    lines: List[str] = [
        "sarifcheck ingest limits - one vendor's published code-scanning",
        "ceilings, NOT part of the OASIS SARIF 2.1.0 specification.",
        "Override with --limit NAME=VALUE or --limits-file PATH.",
        "",
    ]
    width = max(len(limit.name) for limit in ALL_LIMITS)
    for limit in ALL_LIMITS:
        lines.append(
            limit.name.ljust(width) + "  " + str(limit.value).rjust(9)
            + "  " + limit.kind.ljust(4) + "  " + limit.unit
        )
        lines.append(" " * (width + 2) + "read " + limit.retrieved + " from " + limit.source_url)
        lines.append(" " * (width + 2) + limit.note)
    return "\n".join(lines) + "\n"


class LimitError(ValueError):
    """Raised when a user-supplied override cannot be used."""


def parse_override(spec: str) -> Tuple[str, int]:
    """Parse one --limit NAME=VALUE token. Raises LimitError on junk."""
    if not isinstance(spec, str) or "=" not in spec:
        raise LimitError("expected NAME=VALUE, got: " + repr(spec))
    name, _, raw = spec.partition("=")
    name = name.strip()
    raw = raw.strip()
    if name not in LIMIT_NAMES:
        raise LimitError(
            "unknown limit name " + repr(name) + "; known names: "
            + ", ".join(LIMIT_NAMES)
        )
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        raise LimitError("limit " + name + " needs an integer, got: " + repr(raw))
    if value < 0:
        raise LimitError("limit " + name + " must be >= 0, got: " + str(value))
    return name, value


def load_limits_file(path: str) -> Dict[str, int]:
    """Load a JSON object of {limit_name: integer}. Raises LimitError."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise LimitError("cannot read limits file " + path + ": " + str(exc))
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LimitError("limits file " + path + " is not UTF-8: " + str(exc))
    try:
        obj = json.loads(decoded)
    except ValueError as exc:
        raise LimitError("limits file " + path + " is not valid JSON: " + str(exc))
    if not isinstance(obj, dict):
        raise LimitError("limits file " + path + " must hold a JSON object")
    out: Dict[str, int] = {}
    for key in sorted(obj.keys()):
        value = obj[key]
        if key not in LIMIT_NAMES:
            raise LimitError(
                "limits file " + path + " has unknown limit name " + repr(key)
            )
        if isinstance(value, bool) or not isinstance(value, int):
            raise LimitError(
                "limits file " + path + " value for " + key + " must be an integer"
            )
        if value < 0:
            raise LimitError(
                "limits file " + path + " value for " + key + " must be >= 0"
            )
        out[key] = value
    return out
