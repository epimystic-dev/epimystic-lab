"""Shared helpers for the sarifcheck test suite.

Every helper here writes a real file and runs the real scanner, so tests are
anchored to behaviour - input in, exit code / rule code / message out -
rather than to internal call shapes.
"""

from __future__ import annotations

import copy
import io
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sarifcheck.cli import main
from sarifcheck.scanner import build_options, scan_path
from sarifcheck.types import ScanResult


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
EXAMPLES_DIR = os.path.join(PROJECT_DIR, "examples")

ALL_PROFILES = frozenset(("spec", "ingest", "hygiene"))


def fixture(name: str) -> str:
    return os.path.join(FIXTURES_DIR, name)


def example(name: str) -> str:
    return os.path.join(EXAMPLES_DIR, name)


# A minimal, deliberately clean SARIF document. Every rule test mutates one
# property of a deep copy of this, so a test that fires a rule proves the
# mutation caused it: the unmutated base produces zero findings.
BASE_DOC: Dict[str, Any] = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "FixtureScanner",
                    "semanticVersion": "1.0.0",
                    "rules": [
                        {
                            "id": "FX001",
                            "shortDescription": {"text": "S."},
                            "fullDescription": {"text": "F."},
                            "help": {"text": "H."},
                            "messageStrings": {"default": {"text": "Default text."}},
                        }
                    ],
                }
            },
            "automationDetails": {"id": "fixture/base"},
            "versionControlProvenance": [
                {
                    "repositoryUri": "https://example.invalid/a/b",
                    "revisionId": "0" * 40,
                }
            ],
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///build/workspace/"}},
            "results": [
                {
                    "ruleId": "FX001",
                    "ruleIndex": 0,
                    "kind": "fail",
                    "level": "warning",
                    "message": {"text": "Base finding."},
                    "partialFingerprints": {"primaryLocationLineHash": "1111222233334444:1"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "src/a.py",
                                    "uriBaseId": "SRCROOT",
                                },
                                "region": {"startLine": 1, "startColumn": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def base_doc() -> Dict[str, Any]:
    return copy.deepcopy(BASE_DOC)


def base_run(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["runs"][0]


def base_result(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["runs"][0]["results"][0]


def base_rule(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["runs"][0]["tool"]["driver"]["rules"][0]


def base_location(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]


def scan_text(
    text: str,
    disabled: Sequence[str] = (),
    profiles: Optional[Sequence[str]] = None,
    limits: Optional[Dict[str, int]] = None,
    ignore_rule_ids: Sequence[str] = (),
    allow_path_in_message: bool = False,
    filename: str = "results.sarif",
    max_bytes: Optional[int] = None,
) -> ScanResult:
    """Write `text` to a temp SARIF file and scan it."""
    from sarifcheck import limits as limits_mod
    from sarifcheck.scanner import DEFAULT_MAX_BYTES

    merged = limits_mod.default_limits()
    if limits:
        merged.update(limits)
    options = build_options(
        limits=merged,
        profiles=frozenset(profiles) if profiles else ALL_PROFILES,
        disabled=frozenset(disabled),
        ignore_rule_ids=frozenset(ignore_rule_ids),
        allow_path_in_message=allow_path_in_message,
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, filename)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        return scan_path(
            path,
            options,
            max_bytes=DEFAULT_MAX_BYTES if max_bytes is None else max_bytes,
        )


def scan_bytes(raw: bytes, filename: str = "results.sarif", **kwargs) -> ScanResult:
    from sarifcheck import limits as limits_mod
    from sarifcheck.scanner import DEFAULT_MAX_BYTES

    merged = limits_mod.default_limits()
    merged.update(kwargs.pop("limits", None) or {})
    options = build_options(
        limits=merged,
        profiles=ALL_PROFILES,
        disabled=frozenset(kwargs.pop("disabled", ()) or ()),
    )
    max_bytes = kwargs.pop("max_bytes", None)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, filename)
        with open(path, "wb") as handle:
            handle.write(raw)
        return scan_path(
            path,
            options,
            max_bytes=DEFAULT_MAX_BYTES if max_bytes is None else max_bytes,
        )


def scan_doc(doc: Dict[str, Any], **kwargs) -> ScanResult:
    return scan_text(json.dumps(doc, indent=2), **kwargs)


def codes(result: ScanResult) -> Set[str]:
    return set(f.rule_id for f in result.findings)


def messages_for(result: ScanResult, rule_id: str) -> List[str]:
    return [f.message for f in result.findings if f.rule_id == rule_id]


def props_for(result: ScanResult, rule_id: str) -> List[str]:
    return [f.prop for f in result.findings if f.rule_id == rule_id]


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Call main() in-process and capture both streams."""
    out = io.StringIO()
    err = io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()
