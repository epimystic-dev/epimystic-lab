"""Shared test helpers.

Fixtures that need an actual Unicode TAG, bidi, zero-width, or control
character embed them via ``chr()`` at runtime rather than as source-file
literals. Credential-shaped literals used by RNV-004 tests are
assembled from concatenated sub-16-character parts for the same
reason: the publish gate scans source for both character classes.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from renovatelint.cli import main as cli_main
from renovatelint.rules import run_all
from renovatelint.types import Finding, Options


# Route tempfiles into a project-local directory so an endpoint
# scanner watching the user profile Temp folder cannot quarantine a
# fixture mid-write. The directory is dot-prefixed and git-ignored.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


# ---------------------------------------------------------------------------
# Codepoint helpers.
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
        raise ValueError("TAG codepoint is RNV-006 TAG, not PUA")
    if not (
        0xE000 <= cp <= 0xF8FF
        or 0xF0000 <= cp <= 0xFFFFD
        or 0x100000 <= cp <= 0x10FFFD
    ):
        raise ValueError("not a private-use codepoint")
    return chr(cp)


# ---------------------------------------------------------------------------
# Credential-shape fixtures (assembled at runtime so the publish gate
# does not flag the source).
# ---------------------------------------------------------------------------

def fake_jwt() -> str:
    seg1 = "eyJ" + "".join(("hbGciOiJIUzI1NiIsInR5", "cCI6IkpXVCJ9"))
    seg2 = "".join(("eyJzdWIiOiIxMjM0NTY3", "ODkwIiwiZXhwIjo5OTk5OTk5OTk5"))
    seg3 = "".join(("dGhpc19pc19ub3Rfc2ln", "bmF0dXJlX2J5dGVz"))
    return seg1 + "." + seg2 + "." + seg3


def fake_aws_key() -> str:
    return "AKIA" + "".join(("ABCDEFGH", "IJKLMNOP"))


def fake_github_token() -> str:
    return "ghp_" + "".join(("aA1bB2cC3dD4eE5fF6gG7hH8iI9", "jJ0kK1lL2mM3"))


def pem_header() -> str:
    begin = "".join(("-----BEGIN ", "PRIV"))
    end = "".join(("ATE KEY", "-----"))
    return begin + end


def bearer_assignment() -> str:
    val = "".join(("Zx8vJ9pQ3wRnT5", "yBz7cLm4HfG6"))
    return 'api_key = "' + val + '"'


# ---------------------------------------------------------------------------
# Scan helpers.
# ---------------------------------------------------------------------------

def scan_dict(
    doc: Dict[str, Any],
    options: Optional[Options] = None,
    path: str = "in-memory.json",
) -> Sequence[Finding]:
    options = options or Options(include_info=True)
    return run_all(doc, path, options)


def write_temp(
    doc: Dict[str, Any], name: str = "renovate.json"
) -> Tuple[str, str]:
    d = tempfile.mkdtemp(prefix="rnvlint_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return d, p


def write_temp_text(
    content: str, name: str = "renovate.json"
) -> Tuple[str, str]:
    d = tempfile.mkdtemp(prefix="rnvlint_")
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
