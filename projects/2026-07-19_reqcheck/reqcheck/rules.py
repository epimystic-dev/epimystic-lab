"""Audit rules over a ParsedFile.

Each rule is a small function that returns a list of Finding for one line and
the surrounding file context. Rules are pure and side-effect-free.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .model import Finding, Line, Location, ParsedFile
from .parser import parse_text
from .typosquat import typosquat_candidate


RULES: Dict[str, str] = {
    "REQ-A001": "Unpinned requirement (no `==` exact-version spec).",
    "REQ-A002": "Missing --hash= when the file otherwise pins hashes.",
    "REQ-A003": "Typosquat-shape: name is close to a widely-installed package.",
    "REQ-A004": "Duplicate package declaration.",
    "REQ-A005": "--trusted-host disables TLS verification for a host.",
    "REQ-A006": "VCS install without pinned commit SHA.",
    "REQ-A007": "Non-ASCII character in package name (possible homograph).",
    "REQ-A008": "Editable local install; verify not committed by accident.",
    "REQ-A009": "Custom package index configured (informational).",
}

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")


def _is_commit_shaped(ref: Optional[str]) -> bool:
    if not ref:
        return False
    return len(ref) >= 7 and bool(_HEX_RE.match(ref))


def _has_exact_pin(specs: List[str]) -> bool:
    for s in specs:
        if s.startswith("==") and not s.startswith("==="):
            # Reject wildcard pin '==1.0.*' as non-exact
            if "*" in s:
                continue
            return True
        if s.startswith("==="):
            # arbitrary equality, acceptable as an exact pin
            return True
    return False


def _find_a001(line: Line) -> Optional[Finding]:
    if line.kind != "requirement":
        return None
    if line.url:
        # URL-form or VCS-form: pinning is orthogonal (covered by A006)
        return None
    if not line.name:
        return None
    if _has_exact_pin(line.version_specs):
        return None
    return Finding(
        rule="REQ-A001",
        severity="warn",
        message=(
            f"unpinned requirement '{line.raw_name}': no exact-version '==X.Y.Z' "
            f"spec (found: {line.version_specs or 'no spec'})"
        ),
        location=line.location,
        name=line.name,
        suggestion=f"pin explicitly, e.g. '{line.raw_name}==<exact-version>'",
    )


def _find_a002(line: Line, pf: ParsedFile) -> Optional[Finding]:
    if line.kind != "requirement":
        return None
    if not line.name:
        return None
    # Only fire if the file otherwise pins hashes (any --hash line OR
    # a --require-hashes option).
    if not (pf.any_hash_line or pf.require_hashes):
        return None
    if line.hashes:
        return None
    return Finding(
        rule="REQ-A002",
        severity="warn",
        message=(
            f"'{line.raw_name}' has no --hash= but the file otherwise pins "
            "hashes; mixed hash discipline weakens the integrity contract"
        ),
        location=line.location,
        name=line.name,
        suggestion="append '--hash=sha256:<64hex>' for this line",
    )


def _find_a003(line: Line) -> Optional[Finding]:
    if not line.name:
        return None
    if line.kind not in ("requirement", "editable"):
        return None
    hit = typosquat_candidate(line.name)
    if hit is None:
        return None
    popular, distance = hit
    return Finding(
        rule="REQ-A003",
        severity="warn",
        message=(
            f"package name '{line.raw_name}' is edit-distance-{distance} from "
            f"widely-installed '{popular}'; verify intent"
        ),
        location=line.location,
        name=line.name,
        suggestion=f"if you meant '{popular}', correct the name",
    )


def _find_a007(line: Line) -> Optional[Finding]:
    if not line.raw_name:
        return None
    # Any non-ASCII in the identifier is suspect for a Python package name.
    if any(ord(c) > 127 for c in line.raw_name):
        return Finding(
            rule="REQ-A007",
            severity="warn",
            message=(
                f"package name '{line.raw_name}' contains non-ASCII characters; "
                "PyPI names are ASCII, so this is a homograph-attack red flag"
            ),
            location=line.location,
            name=line.name,
            suggestion="rewrite the name with ASCII letters/digits/'.-_'",
        )
    return None


def _find_a006(line: Line) -> Optional[Finding]:
    """VCS install without a pinned commit SHA."""
    if line.kind not in ("requirement", "editable"):
        return None
    if not line.vcs:
        return None
    if _is_commit_shaped(line.vcs_ref):
        return None
    ref_desc = f"'@{line.vcs_ref}'" if line.vcs_ref else "no ref"
    return Finding(
        rule="REQ-A006",
        severity="warn",
        message=(
            f"{line.vcs}+ URL {ref_desc}: not a >=7-hex commit SHA; the "
            "installed code will drift with the remote"
        ),
        location=line.location,
        name=line.name,
        suggestion="pin to a full commit SHA: '<url>@<40-hex-sha>#egg=<name>'",
    )


def _find_a008(line: Line) -> Optional[Finding]:
    """Editable local install (not VCS)."""
    if line.kind != "editable":
        return None
    if line.vcs:
        return None  # VCS editable is handled by A006
    target = line.url or ""
    return Finding(
        rule="REQ-A008",
        severity="warn",
        message=(
            f"editable local install '{target}' in requirements: usually a "
            "development-only convenience; verify not committed by accident"
        ),
        location=line.location,
        suggestion=(
            "move -e local installs to a dev-only requirements-dev.txt, "
            "or install directly during development"
        ),
    )


def _find_a005(line: Line) -> Optional[Finding]:
    if line.kind == "option" and line.option == "--trusted-host":
        return Finding(
            rule="REQ-A005",
            severity="error",
            message=(
                f"--trusted-host {line.option_value or ''} disables TLS "
                "certificate verification for that host; strong supply-chain risk"
            ),
            location=line.location,
            suggestion="remove --trusted-host and use a properly TLS-certified index",
        )
    return None


def _find_a009(line: Line) -> Optional[Finding]:
    if line.kind != "option":
        return None
    if line.option not in ("-i", "--index-url", "--extra-index-url"):
        return None
    return Finding(
        rule="REQ-A009",
        severity="info",
        message=(
            f"custom package index {line.option} {line.option_value or ''}; "
            "confirm the host is trusted"
        ),
        location=line.location,
    )


def _find_duplicates(pf: ParsedFile) -> List[Finding]:
    groups: Dict[str, List[Line]] = defaultdict(list)
    for line in pf.lines:
        if line.kind not in ("requirement", "editable"):
            continue
        if not line.name:
            continue
        groups[line.name].append(line)
    findings: List[Finding] = []
    for name, lines in groups.items():
        if len(lines) < 2:
            continue
        first = lines[0]
        for extra in lines[1:]:
            findings.append(
                Finding(
                    rule="REQ-A004",
                    severity="warn",
                    message=(
                        f"'{extra.raw_name}' already declared on line "
                        f"{first.location.line}; the later declaration may "
                        "override the earlier"
                    ),
                    location=extra.location,
                    name=name,
                    suggestion="remove the duplicate; keep the intended pin",
                )
            )
    return findings


def audit_parsed(pf: ParsedFile, include_info: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    for line in pf.lines:
        for maker in (_find_a001, _find_a003, _find_a005, _find_a006,
                      _find_a007, _find_a008, _find_a009):
            f = maker(line)
            if f is None:
                continue
            if f.severity == "info" and not include_info:
                continue
            findings.append(f)
        f2 = _find_a002(line, pf)
        if f2 is not None:
            findings.append(f2)
    findings.extend(_find_duplicates(pf))
    for f in findings:
        f.file = pf.path
    findings.sort(key=lambda f: (f.location.line, f.rule))
    return findings


def audit_file(path: str, include_info: bool = False) -> Tuple[ParsedFile, List[Finding]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        text = fh.read()
    pf = parse_text(text, path=path)
    return pf, audit_parsed(pf, include_info=include_info)
