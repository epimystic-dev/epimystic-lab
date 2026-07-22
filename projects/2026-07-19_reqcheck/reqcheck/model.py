"""Dataclass model for parsed requirements files and audit findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Location:
    """1-based line and column position within a file."""

    line: int
    col: int = 1


@dataclass
class Line:
    """One parsed line of a pip requirements file.

    kind:
      - 'blank'        : whitespace-only or empty
      - 'comment'      : starts with '#' after optional leading whitespace
      - 'requirement'  : PEP 508 / pip requirement (may be VCS or URL form)
      - 'option'       : pip option line (--index-url, --require-hashes, etc.)
      - 'include'      : -r/-c include or constraint reference
      - 'editable'     : -e/--editable line (may resolve to url or local path)
      - 'invalid'      : parse error; message set
    """

    kind: str
    raw: str
    location: Location
    # requirement fields
    name: Optional[str] = None           # PEP 503 canonicalized
    raw_name: Optional[str] = None       # as written
    extras: List[str] = field(default_factory=list)
    version_specs: List[str] = field(default_factory=list)   # e.g. ['==1.0'] or ['>=1.0', '<2.0']
    url: Optional[str] = None
    vcs: Optional[str] = None            # 'git', 'hg', 'svn', 'bzr'
    vcs_ref: Optional[str] = None        # value after '@' before '#'
    markers: Optional[str] = None
    hashes: List[str] = field(default_factory=list)   # e.g. ['sha256:abcd...']
    editable: bool = False
    # option fields
    option: Optional[str] = None
    option_value: Optional[str] = None
    # error fields
    error: Optional[str] = None

    def is_requirement_like(self) -> bool:
        return self.kind in ("requirement", "editable") and self.name is not None


@dataclass
class ParsedFile:
    path: str
    lines: List[Line] = field(default_factory=list)
    require_hashes: bool = False
    any_hash_line: bool = False


@dataclass
class Finding:
    rule: str
    severity: str        # 'info', 'warn', 'error'
    message: str
    location: Location
    file: str = ""
    name: Optional[str] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file,
            "line": self.location.line,
            "column": self.location.col,
            "message": self.message,
        }
        if self.name is not None:
            d["name"] = self.name
        if self.suggestion is not None:
            d["suggestion"] = self.suggestion
        return d
