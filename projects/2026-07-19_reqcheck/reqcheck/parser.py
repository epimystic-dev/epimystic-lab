"""Line-oriented parser for pip-style requirements files.

Scope: single-line-per-record only. Backslash line continuation is documented
as out of scope; if encountered, the continuation line is treated as an
independent line (which will usually parse as invalid).

Grammar handled per line:
  requirement    := name_with_extras [version_spec] [';' marker] [ ' --hash=' algo ':' hex ]*
  url_form       := name_with_extras ' @ ' url [' ;' marker]
  vcs_line       := ('git+'|'hg+'|'svn+'|'bzr+') url [ '#egg=' name ]
  editable_line  := '-e '|'--editable ' vcs_line | local_path
  option_line    := '--' word [ '=' value | ' ' value ]
                  | '-' short [ ' ' value ]
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .model import Line, Location, ParsedFile

# PEP 508 says names must be ASCII. We deliberately accept Unicode word chars
# in the parser so that homograph-attack names ARE captured; rule A007 then
# flags them. ``\w`` in Python 3 already matches Unicode letters and digits.
NAME_RE = re.compile(r"^\w[\w.-]*")
EXTRAS_RE = re.compile(r"^\[([A-Za-z0-9._,\s-]*)\]")
VERSION_OP_RE = re.compile(r"^(===|==|!=|<=|>=|~=|<|>)")
VERSION_VAL_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._+*!-]*)")
HASH_RE = re.compile(r"--hash\s*=\s*([A-Za-z0-9_]+):([A-Fa-f0-9]+)")
BOM = "﻿"

VCS_SCHEMES = ("git+", "hg+", "svn+", "bzr+")


def _canonicalize(name: str) -> str:
    """PEP 503 canonicalization: lowercase, runs of . _ - collapsed to single -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _strip_inline_comment(text: str) -> str:
    """Strip a trailing ``# ...`` comment.

    A ``#`` is only treated as a comment start when preceded by whitespace or
    at start of line, and is never inside quotes (requirement lines never use
    quotes, so simple whitespace check suffices).
    """
    # Find " #" (space-then-hash) or "\t#" or ^#
    if not text:
        return text
    if text[0] == "#":
        return ""
    m = re.search(r"\s#", text)
    if m:
        return text[: m.start()]
    return text


def _split_hashes(text: str) -> Tuple[str, List[str]]:
    """Extract all ``--hash=alg:val`` fragments and return (remainder, hashes)."""
    hashes = []
    remainder_parts = []
    last_end = 0
    for m in HASH_RE.finditer(text):
        remainder_parts.append(text[last_end : m.start()])
        hashes.append(f"{m.group(1)}:{m.group(2)}")
        last_end = m.end()
    remainder_parts.append(text[last_end:])
    remainder = "".join(remainder_parts).strip()
    return remainder, hashes


def _split_markers(text: str) -> Tuple[str, Optional[str]]:
    """Split off PEP 508 environment markers on the first `` ;`` boundary."""
    idx = text.find(";")
    if idx < 0:
        return text.strip(), None
    return text[:idx].strip(), text[idx + 1 :].strip()


def _parse_extras(text: str) -> Tuple[List[str], str]:
    m = EXTRAS_RE.match(text)
    if not m:
        return [], text
    body = m.group(1)
    rest = text[m.end() :]
    extras = [x.strip() for x in body.split(",") if x.strip()]
    return extras, rest


def _parse_version_specs(text: str) -> Tuple[List[str], str]:
    specs: List[str] = []
    remaining = text
    while remaining:
        op_m = VERSION_OP_RE.match(remaining)
        if not op_m:
            break
        op = op_m.group(1)
        rest = remaining[op_m.end() :].lstrip()
        val_m = VERSION_VAL_RE.match(rest)
        if not val_m:
            # broken version spec; give up cleanly
            return specs, remaining
        val = val_m.group(1)
        specs.append(op + val)
        remaining = rest[val_m.end() :].lstrip()
        if remaining.startswith(","):
            remaining = remaining[1:].lstrip()
            continue
        break
    return specs, remaining


def _detect_vcs(url: str) -> Optional[str]:
    for scheme in VCS_SCHEMES:
        if url.startswith(scheme):
            return scheme[:-1]
    return None


def _extract_vcs_ref(url: str) -> Optional[str]:
    """Return the ref between the last ``@`` and the following ``#``/end.

    Only the ``@`` that comes AFTER the URL path is considered; user-info ``@``
    in ``git+ssh://user@host/repo`` is skipped because that ``@`` appears
    before the path's last ``/``. Ref must be after the last ``/`` of the
    truncated URL (i.e. embedded in or immediately after the final path
    segment), matching pip's ``vcsurl@ref#egg=name`` convention.
    """
    hash_idx = url.find("#")
    tail = url[:hash_idx] if hash_idx >= 0 else url
    last_slash = tail.rfind("/")
    at_idx = tail.rfind("@")
    if at_idx < 0:
        return None
    if last_slash >= 0 and at_idx < last_slash:
        return None
    ref = tail[at_idx + 1 :]
    return ref or None


def _egg_name(url: str) -> Optional[str]:
    m = re.search(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)", url)
    return m.group(1) if m else None


def _parse_requirement_body(body: str, loc: Location, raw: str) -> Line:
    """Parse a non-option requirement line body (comment/blank already handled)."""
    body, hashes = _split_hashes(body)
    body, markers = _split_markers(body)

    # URL-form: 'name @ url'
    # We look for ' @ ' (with spaces per PEP 508) or a leading VCS scheme.
    vcs = _detect_vcs(body)
    if vcs:
        egg = _egg_name(body)
        return Line(
            kind="requirement",
            raw=raw,
            location=loc,
            name=_canonicalize(egg) if egg else None,
            raw_name=egg,
            url=body,
            vcs=vcs,
            vcs_ref=_extract_vcs_ref(body),
            markers=markers,
            hashes=hashes,
        )

    at_split = re.search(r"\s@\s", body)
    if at_split:
        name_part = body[: at_split.start()].strip()
        url_part = body[at_split.end() :].strip()
        n_m = NAME_RE.match(name_part)
        if not n_m:
            return Line(
                kind="invalid",
                raw=raw,
                location=loc,
                error="URL-form requirement missing valid name",
            )
        raw_name = n_m.group(0)
        rest = name_part[n_m.end() :]
        extras, rest = _parse_extras(rest)
        vcs = _detect_vcs(url_part)
        return Line(
            kind="requirement",
            raw=raw,
            location=loc,
            name=_canonicalize(raw_name),
            raw_name=raw_name,
            extras=extras,
            url=url_part,
            vcs=vcs,
            vcs_ref=_extract_vcs_ref(url_part) if vcs else None,
            markers=markers,
            hashes=hashes,
        )

    # Plain PEP 508: name[extras]version_spec
    n_m = NAME_RE.match(body)
    if not n_m:
        return Line(
            kind="invalid",
            raw=raw,
            location=loc,
            error=f"unrecognized requirement syntax: {body!r}",
        )
    raw_name = n_m.group(0)
    rest = body[n_m.end() :]
    extras, rest = _parse_extras(rest)
    rest = rest.lstrip()
    specs, rest_after = _parse_version_specs(rest)
    if rest_after.strip():
        return Line(
            kind="invalid",
            raw=raw,
            location=loc,
            error=f"trailing tokens after specifier: {rest_after!r}",
        )
    return Line(
        kind="requirement",
        raw=raw,
        location=loc,
        name=_canonicalize(raw_name),
        raw_name=raw_name,
        extras=extras,
        version_specs=specs,
        markers=markers,
        hashes=hashes,
    )


def _parse_option_line(text: str, loc: Location, raw: str) -> Line:
    """Parse a line starting with '-' or '--' as a pip option."""
    # Splitting on '=' first (long options), fall back to whitespace split.
    if text.startswith("--"):
        if "=" in text:
            opt, val = text.split("=", 1)
            opt = opt.strip()
            val = val.strip()
        else:
            parts = text.split(None, 1)
            opt = parts[0]
            val = parts[1].strip() if len(parts) > 1 else ""
    else:
        # short option
        parts = text.split(None, 1)
        opt = parts[0]
        val = parts[1].strip() if len(parts) > 1 else ""

    # Editable
    if opt in ("-e", "--editable"):
        vcs = _detect_vcs(val) if val else None
        return Line(
            kind="editable",
            raw=raw,
            location=loc,
            editable=True,
            url=val or None,
            vcs=vcs,
            vcs_ref=_extract_vcs_ref(val) if vcs else None,
            raw_name=_egg_name(val) if val else None,
            name=_canonicalize(_egg_name(val)) if val and _egg_name(val) else None,
        )
    if opt in ("-r", "--requirement"):
        return Line(
            kind="include",
            raw=raw,
            location=loc,
            option=opt,
            option_value=val,
        )
    if opt in ("-c", "--constraint"):
        return Line(
            kind="include",
            raw=raw,
            location=loc,
            option=opt,
            option_value=val,
        )
    # Generic option
    return Line(
        kind="option",
        raw=raw,
        location=loc,
        option=opt,
        option_value=val or None,
    )


def parse_text(text: str, path: str = "<string>") -> ParsedFile:
    """Parse the full text of a requirements file into a ParsedFile.

    ``text`` is the raw file contents. A leading BOM is stripped. Both LF and
    CRLF line endings are accepted; ``\\r`` bytes are stripped before parsing.
    """
    if text.startswith(BOM):
        text = text[len(BOM) :]

    pf = ParsedFile(path=path)
    for i, raw in enumerate(text.splitlines(), start=1):
        loc = Location(line=i, col=1)
        # Strip a lone \r (shouldn't happen after splitlines, defensive)
        line_text = raw.rstrip("\r")
        stripped = line_text.strip()
        if not stripped:
            pf.lines.append(Line(kind="blank", raw=raw, location=loc))
            continue
        if stripped.startswith("#"):
            pf.lines.append(Line(kind="comment", raw=raw, location=loc))
            continue
        # Strip inline comment before further parsing
        no_comment = _strip_inline_comment(line_text)
        no_comment = no_comment.strip()
        if no_comment.startswith("-"):
            line = _parse_option_line(no_comment, loc, raw)
        else:
            line = _parse_requirement_body(no_comment, loc, raw)
        if line.hashes:
            pf.any_hash_line = True
        if line.kind == "option" and line.option == "--require-hashes":
            pf.require_hashes = True
        pf.lines.append(line)
    return pf
