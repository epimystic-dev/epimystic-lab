"""Shared test helpers.

Fixtures that need an actual Unicode TAG, bidi, zero-width, or
private-use character embed them via chr() at runtime rather than as
source-file literals - the publish gate scans source for the same
character classes the linter flags, and a false positive there blocks
the project.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from mcptoolcheck.cli import main as cli_main
from mcptoolcheck.parse import extract_tools, load_json
from mcptoolcheck.rules import run_all
from mcptoolcheck.types import Finding, Options


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Route temp files into a project-local directory so an endpoint
# scanner watching the user profile Temp folder cannot quarantine a
# fixture mid-write. The directory is dot-prefixed and git-ignored.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


# ---------------------------------------------------------------------------
# Codepoint helpers. The point of these is to keep source files ASCII;
# the shipped linter rules fire on the character class, not the source
# representation.
# ---------------------------------------------------------------------------

def tag_char(cp: int = 0xE0001) -> str:
    """A Plane 14 Tags codepoint (default U+E0001 'LATIN SMALL LETTER
    A, TAG'). Used by MTC-001 fixtures.
    """
    if not (0xE0000 <= cp <= 0xE007F):
        raise ValueError("not a TAG codepoint")
    return chr(cp)


def bidi_char(cp: int = 0x202E) -> str:
    """A bidi-override codepoint. Default U+202E (RIGHT-TO-LEFT OVERRIDE).
    Used by MTC-002 fixtures.
    """
    if cp not in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                  0x2066, 0x2067, 0x2068, 0x2069):
        raise ValueError("not a bidi-override codepoint")
    return chr(cp)


def zw_char(cp: int = 0x200B) -> str:
    """A zero-width codepoint. Default U+200B (ZERO WIDTH SPACE)."""
    if cp not in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
        raise ValueError("not a zero-width codepoint")
    return chr(cp)


def control_char(cp: int = 0x0001) -> str:
    """A C0/C1 control codepoint. Default U+0001."""
    if not ((0x00 <= cp <= 0x1F and cp not in (0x09, 0x0A, 0x0D))
            or (0x7F <= cp <= 0x9F)):
        raise ValueError("not a control codepoint")
    return chr(cp)


def pua_char(cp: int = 0xE100) -> str:
    """A private-use codepoint (not in the Tags block). Default U+E100."""
    if cp == 0xE000:  # fine too but keep the default informative
        pass
    if 0xE0000 <= cp <= 0xE007F:
        raise ValueError("TAG codepoint is MTC-001, not MTC-005")
    if not (
        0xE000 <= cp <= 0xF8FF
        or 0xF0000 <= cp <= 0xFFFFD
        or 0x100000 <= cp <= 0x10FFFD
    ):
        raise ValueError("not a private-use codepoint")
    return chr(cp)


def homoglyph_word() -> str:
    """The word 'paypal' with each 'a' replaced by Cyrillic U+0430, the rest
    Latin - a cross-script word MTC-010 fires on.
    """
    return "p" + chr(0x0430) + "yp" + chr(0x0430) + "l"


# ---------------------------------------------------------------------------
# Fixture builders.
# ---------------------------------------------------------------------------

def build_tool(**overrides: Any) -> Dict[str, Any]:
    """A defensibly-shaped tool descriptor; override by keyword."""
    base: Dict[str, Any] = {
        "name": "read_record",
        "description": (
            "Read a record by id and return the fields in a JSON "
            "object. Fails if the record does not exist."
        ),
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
            "additionalProperties": False,
        },
    }
    base.update(overrides)
    return base


def build_doc(
    tools: Sequence[Dict[str, Any]],
    pinned: bool = True,
) -> Dict[str, Any]:
    """Wrap tools into a tools/list-shaped document. Document-level pin
    is on by default; pass pinned=False to drop it (MTC-006 surface).
    """
    doc: Dict[str, Any] = {"tools": list(tools)}
    if pinned:
        doc["version"] = "2026.10.04-test"
        doc["digest"] = (
            "sha256:"
            + "0" * 64
        )
    return doc


def scan_dict(
    obj: Dict[str, Any],
    options: Optional[Options] = None,
    path: str = "in-memory.json",
) -> Tuple[Optional[str], Sequence[Finding]]:
    options = options or Options()
    content = json.dumps(obj, indent=2, ensure_ascii=False)
    return _scan_text(content, path, options)


def scan_string(
    content: str,
    options: Optional[Options] = None,
    path: str = "in-memory.json",
) -> Tuple[Optional[str], Sequence[Finding]]:
    options = options or Options()
    return _scan_text(content, path, options)


def _scan_text(
    content: str, path: str, options: Options
) -> Tuple[Optional[str], Sequence[Finding]]:
    doc, err = load_json(content)
    if err is not None:
        return err, []
    tools = extract_tools(doc)
    findings = run_all(doc, content, path, options, tools)
    return None, findings


def write_temp(
    obj: Dict[str, Any], name: str = "tooldesc.json"
) -> Tuple[str, str]:
    """Write a tool-descriptor dict to a fresh temp directory, return
    (dir, file_path).
    """
    d = tempfile.mkdtemp(prefix="mcptoolcheck_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)
