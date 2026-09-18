"""Domain types for sarifcheck.

A Finding is a single flagged shape in one SARIF file. It carries both a
text position (line / column, best effort) and a JSON property path, which
is the primary anchor: SARIF files are machine-generated and the property
path is what a tool author needs in order to fix the emitter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class Profile(str, Enum):
    """Which authority a rule cites.

    SPEC    - a MUST / SHALL in the OASIS SARIF 2.1.0 specification.
    INGEST  - a requirement or a published numeric ceiling of one documented
              code-scanning ingest endpoint. Not part of the SARIF standard.
    HYGIENE - neither: a shape that is legal SARIF and accepted by the ingest
              but that has tripped real consumers or that publishes host
              layout into a report. Advisory by construction.
    """

    SPEC = "spec"
    INGEST = "ingest"
    HYGIENE = "hygiene"


_SEV_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.INFO: 2}


def severity_rank(sev: Severity) -> int:
    return _SEV_RANK[sev]


@dataclass(frozen=True)
class Finding:
    """One flagged shape.

    run_index / result_index are -1 when the finding is not attached to a
    particular run or result (a file-level finding, for example SRF-023).
    `prop` is the JSON property path, for example
    "runs[0].results[3].locations[0].physicalLocation.artifactLocation.uri".
    `snippet` is redacted by default; see report.py and the --show-matches
    flag. A linter that reprints a host path into a CI log has republished
    the thing it is complaining about.
    """

    rule_id: str
    severity: Severity
    path: str
    prop: str
    line: int
    column: int
    message: str
    snippet: str = ""
    run_index: int = -1
    result_index: int = -1

    def sort_key(self) -> Tuple[str, int, int, str, str, int, int]:
        # Deterministic emission order, locked by tests: file, then run,
        # then result, then rule code, then property path. Severity is
        # deliberately NOT part of the sort so that a diff between two
        # commits stays anchored to position rather than to severity drift.
        return (
            self.path,
            self.run_index,
            self.result_index,
            self.rule_id,
            self.prop,
            self.line,
            self.column,
        )


@dataclass
class ScanResult:
    """Outcome of one scan over zero or more files.

    `partial` is set when at least one run could not be fully analysed - the
    documented case is a run carrying externalPropertyFileReferences, whose
    results / rules / artifacts legally live in sidecar files this tool does
    not read. A partial scan can never roll up to `healthy`.
    """

    files_scanned: int = 0
    findings: Tuple[Finding, ...] = field(default_factory=tuple)
    errors: Tuple[str, ...] = field(default_factory=tuple)
    notes: Tuple[str, ...] = field(default_factory=tuple)
    partial: bool = False


@dataclass
class Options:
    """Per-run knobs that rules are allowed to read.

    Kept as one object so a rule signature never grows: adding a knob is a
    field here, not a new positional parameter threaded through scanner.py.
    """

    limits: Dict[str, int] = field(default_factory=dict)
    profiles: FrozenSet[str] = frozenset(
        (Profile.SPEC.value, Profile.INGEST.value, Profile.HYGIENE.value)
    )
    disabled: FrozenSet[str] = frozenset()
    ignore_rule_ids: FrozenSet[str] = frozenset()
    allow_path_in_message: bool = False
    show_matches: bool = False


@dataclass
class RuleContext:
    """Everything a rule check function is given.

    doc     - the parsed JSON document (already known to be a dict).
    text    - the raw decoded file text, for position lookup.
    path    - the file path as given on the command line.
    index   - the precomputed per-run index (see parse.build_index).
    options - see Options.
    """

    doc: Any
    text: str
    path: str
    index: Any
    options: Options
    lookup: Any = None
    compressed_bytes: int = -1
    raw_bytes: int = -1


@dataclass
class RunIndex:
    """Precomputed facts about one runs[] entry.

    Built once per file so that N rules do not each re-walk the same arrays.
    """

    run_index: int = 0
    rules: List[Any] = field(default_factory=list)
    rule_ids: List[Optional[str]] = field(default_factory=list)
    rule_id_to_pos: Dict[str, int] = field(default_factory=dict)
    driver_rule_count: int = 0
    extension_rule_count: int = 0
    has_rule_metadata: bool = False
    uri_base_ids: Dict[str, Any] = field(default_factory=dict)
    has_external_property_files: bool = False
    results: List[Any] = field(default_factory=list)


@dataclass
class DocIndex:
    runs: List[RunIndex] = field(default_factory=list)
    run_count: int = 0
    any_external_property_files: bool = False
