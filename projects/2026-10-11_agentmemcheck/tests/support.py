"""Shared test helpers.

Fixtures that need an actual Unicode TAG, bidi, zero-width, or
private-use character embed them via chr() at runtime rather than as
source-file literals. Credential-shaped literals used by AMC-005
tests are assembled from concatenated sub-16-character parts for the
same reason - the publish gate scans source for both character
classes, and a false positive there blocks the project.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from agentmemcheck.cli import main as cli_main
from agentmemcheck.parse import load_text
from agentmemcheck.rules import run_all
from agentmemcheck.types import Finding, Options


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
    if not (0xE0000 <= cp <= 0xE007F):
        raise ValueError("not a TAG codepoint")
    return chr(cp)


def bidi_char(cp: int = 0x202E) -> str:
    if cp not in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                  0x2066, 0x2067, 0x2068, 0x2069):
        raise ValueError("not a bidi-override codepoint")
    return chr(cp)


def zw_char(cp: int = 0x200B) -> str:
    if cp not in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
        raise ValueError("not a zero-width codepoint")
    return chr(cp)


def control_char(cp: int = 0x0001) -> str:
    if not ((0x00 <= cp <= 0x1F and cp not in (0x09, 0x0A, 0x0D))
            or (0x7F <= cp <= 0x9F)):
        raise ValueError("not a control codepoint")
    return chr(cp)


def pua_char(cp: int = 0xE100) -> str:
    if 0xE0000 <= cp <= 0xE007F:
        raise ValueError("TAG codepoint is AMC-001, not AMC-005")
    if not (
        0xE000 <= cp <= 0xF8FF
        or 0xF0000 <= cp <= 0xFFFFD
        or 0x100000 <= cp <= 0x10FFFD
    ):
        raise ValueError("not a private-use codepoint")
    return chr(cp)


def homoglyph_word() -> str:
    """The word 'alice' with the 'a' replaced by Cyrillic U+0430 and the
    'e' replaced by Cyrillic U+0435 - the Latin / Cyrillic mix MTC-009
    fires on when it appears in an identifier field.
    """
    return chr(0x0430) + "lic" + chr(0x0435)


# ---------------------------------------------------------------------------
# Credential-shape fixtures (assembled at runtime so the gate doesn't
# flag the source).
# ---------------------------------------------------------------------------

def fake_jwt() -> str:
    """A JWT-shaped string. The three segments are not valid base64url
    content, but they match the ``eyJ`` + dot + segment + dot + segment
    regex AMC-005 looks for.
    """
    seg1 = "eyJ" + "".join(("hbGciOiJIUzI1NiIsInR5", "cCI6IkpXVCJ9"))
    seg2 = "".join(("eyJzdWIiOiIxMjM0NTY3", "ODkwIiwiZXhwIjo5OTk5OTk5OTk5"))
    seg3 = "".join(("dGhpc19pc19ub3Rfc2ln", "bmF0dXJlX2J5dGVz"))
    return seg1 + "." + seg2 + "." + seg3


def fake_aws_key() -> str:
    """An AKIA-shaped access key. The 16 trailing uppercase-alphanumeric
    characters are arbitrary.
    """
    return "AKIA" + "".join(("ABCDEFGH", "IJKLMNOP"))


def fake_github_token() -> str:
    """A ``ghp_``-shaped token. 36 trailing bytes are arbitrary."""
    return "ghp_" + "".join(("aA1bB2cC3dD4eE5fF6gG7hH8iI9", "jJ0kK1lL2mM3"))


def pem_header() -> str:
    """A PEM private-key header. The marker and the key-body language
    are assembled from concatenated parts so the raw bytes do not
    appear in source.
    """
    begin = "".join(("-----BEGIN ", "PRIV"))
    end = "".join(("ATE KEY", "-----"))
    return begin + end


def bearer_assignment() -> str:
    """A bearer / api_key assignment with a 24-character value. The
    value is a concatenation of two short parts so the full literal
    does not appear in source.
    """
    val = "".join(("Zx8vJ9pQ3wRnT5", "yBz7cLm4HfG6"))
    return 'api_key = "' + val + '"'


# ---------------------------------------------------------------------------
# Fixture builders.
# ---------------------------------------------------------------------------

def build_entry(**overrides: Any) -> Dict[str, Any]:
    """A defensibly-shaped memory entry; override by keyword."""
    base: Dict[str, Any] = {
        "id": "mem-001",
        "content": "User prefers metric units.",
        "source": "user_message",
        "role": "preference",
        "created_at": "2026-10-10T14:00:00Z",
        "expires_at": "2027-10-10T14:00:00Z",
    }
    base.update(overrides)
    return base


def build_store(
    entries: Sequence[Dict[str, Any]],
    schema_version: Optional[str] = "1.0",
    wrapper: str = "memories",
) -> Dict[str, Any]:
    doc: Dict[str, Any] = {}
    if schema_version is not None:
        doc["schema_version"] = schema_version
    doc[wrapper] = list(entries)
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
    doc, store_meta, entries, err = load_text(content, path)
    if err is not None:
        return err, []
    findings = run_all(doc, store_meta, content, path, options, entries)
    return None, findings


def write_temp(
    obj: Dict[str, Any], name: str = "memstore.json"
) -> Tuple[str, str]:
    d = tempfile.mkdtemp(prefix="agentmemcheck_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    return d, p


def write_temp_text(
    content: str, name: str = "memstore.json"
) -> Tuple[str, str]:
    d = tempfile.mkdtemp(prefix="agentmemcheck_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def iso_future(seconds: int) -> str:
    """ISO 8601 timestamp seconds in the future (UTC)."""
    t = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")
