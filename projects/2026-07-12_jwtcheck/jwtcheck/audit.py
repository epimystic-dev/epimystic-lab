"""JWT / auth-secret hygiene audit rules for .env-family files.

Rule catalog
------------
JWT-A001 (error): JWT algorithm is set to `none` (alg=none defeats verification).
JWT-A002 (error): HMAC (HS256/HS384/HS512) secret shorter than the minimum
                  RFC 7518 §3.2 recommendation (>= the hash byte length: 32/48/64 bytes).
JWT-A003 (error): JWT secret is empty.
JWT-A004 (error): JWT secret matches a well-known weak default
                  (e.g. `secret`, `changeme`, `your-256-bit-secret`).
JWT-A005 (warn):  JWT secret matches a placeholder pattern
                  (e.g. `<REPLACE_ME>`, `todo`, `xxx`, template braces).
JWT-A006 (warn):  JWT secret has low Shannon entropy (< 3.0 bits/char).
JWT-A007 (warn):  Symmetric HMAC algorithm used with a non-templated secret
                  (asymmetric RS/ES/EdDSA is generally preferable in prod).

Recognition
-----------
An env entry is treated as a JWT secret if its key matches one of the
recognised patterns (see JWT_SECRET_KEY_PATTERNS).

Recognition is deliberately narrow: false positives on a security linter
are costly. The catalog can be extended by passing `extra_secret_keys` to
`audit_env`.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

from jwtcheck.parse import EnvEntry, ParseError, parse_env

# ---------------------------------------------------------------------------
# Recognition patterns
# ---------------------------------------------------------------------------

# Compiled once at import.
JWT_SECRET_KEY_PATTERNS: Sequence[str] = (
    # Direct
    r"^JWT_SECRET$",
    r"^JWT_KEY$",
    r"^JWT_SIGNING_KEY$",
    r"^JWT_ACCESS_SECRET$",
    r"^JWT_REFRESH_SECRET$",
    r"^JWT_PRIVATE_KEY$",
    r"^JWT_PUBLIC_KEY$",
    # Framework conventions
    r"^AUTH_SECRET$",
    r"^NEXTAUTH_SECRET$",
    r"^BETTER_AUTH_SECRET$",
    r"^SUPABASE_JWT_SECRET$",
    r"^SESSION_SECRET$",
    r"^ACCESS_TOKEN_SECRET$",
    r"^REFRESH_TOKEN_SECRET$",
    # Common suffix
    r".*_JWT_SECRET$",
    r".*_JWT_KEY$",
)

JWT_ALGO_KEY_PATTERNS: Sequence[str] = (
    r"^JWT_ALGORITHM$",
    r"^JWT_ALG$",
    r"^AUTH_ALGORITHM$",
    r".*_JWT_ALGORITHM$",
)

_SECRET_KEY_RE = re.compile("|".join(JWT_SECRET_KEY_PATTERNS))
_ALGO_KEY_RE = re.compile("|".join(JWT_ALGO_KEY_PATTERNS))

# ---------------------------------------------------------------------------
# Weak defaults
# ---------------------------------------------------------------------------

# Case-folded compare.
WEAK_DEFAULTS: Set[str] = {
    "secret",
    "secret123",
    "secretkey",
    "supersecret",
    "supersecretkey",
    "mysecret",
    "mysecretkey",
    "jwtsecret",
    "jwt_secret",
    "jwt-secret",
    "password",
    "password123",
    "changeme",
    "change_me",
    "change-me",
    "changethis",
    "change_this",
    "please_change_me",
    "your-256-bit-secret",
    "your-256-bit-secret-here",
    "your_secret_here",
    "your-secret-here",
    "some-secret",
    "some_secret",
    "test",
    "testsecret",
    "test_secret",
    "dev",
    "devsecret",
    "development",
    "hello",
    "hello-world",
    "example",
    "example-secret",
    "default",
    "default_secret",
    "admin",
    "root",
    "12345",
    "123456",
    "1234567890",
    "abc123",
    "qwerty",
    "letmein",
}

# Placeholder patterns are "clearly not a real secret" markers.
_PLACEHOLDER_PATTERNS = (
    re.compile(r"^\s*$"),  # empty (also caught by A003 for direct empty)
    re.compile(r"^<.*>$"),  # <REPLACE_ME>
    re.compile(r"^\{\{.*\}\}$"),  # {{VAR}} template
    re.compile(r"^\$\{.*\}$"),  # ${VAR}
    re.compile(r"^x+$", re.IGNORECASE),  # xxx
    re.compile(r"^todo$", re.IGNORECASE),
    re.compile(r"^tbd$", re.IGNORECASE),
    re.compile(r"^fixme$", re.IGNORECASE),
    re.compile(r"^placeholder$", re.IGNORECASE),
    re.compile(r"^replace(_|-)?me$", re.IGNORECASE),
    re.compile(r"^set(_|-)?me$", re.IGNORECASE),
    re.compile(r".*your(_|-)?secret.*", re.IGNORECASE),
    re.compile(r".*your(_|-)?token.*", re.IGNORECASE),
    re.compile(r".*your(_|-)?key.*", re.IGNORECASE),
    re.compile(r".*replace(_|-)?with.*", re.IGNORECASE),
)

# ---------------------------------------------------------------------------
# Algorithm minimum secret sizes (bytes), from RFC 7518 §3.2:
#   "A key of the same size as the hash output (for instance, 256 bits for
#   HS256) or larger MUST be used with this algorithm."
# We compare against the raw byte length of the secret as declared.
# ---------------------------------------------------------------------------

HMAC_MIN_BYTES = {
    "HS256": 32,
    "HS384": 48,
    "HS512": 64,
}

# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One audit finding attributed to a specific env entry (or a file)."""

    rule: str
    severity: str  # "error" | "warn"
    message: str
    key: Optional[str]
    line: int
    col: int
    source: Optional[str] = None  # file path, if known


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------


def is_secret_key(key: str, extra: Optional[Sequence[str]] = None) -> bool:
    if _SECRET_KEY_RE.fullmatch(key) is not None:
        return True
    if extra:
        for pat in extra:
            if re.fullmatch(pat, key) is not None:
                return True
    return False


def is_algorithm_key(key: str) -> bool:
    return _ALGO_KEY_RE.fullmatch(key) is not None


def looks_like_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    for pat in _PLACEHOLDER_PATTERNS:
        if pat.fullmatch(v) is not None:
            return True
    return False


def is_weak_default(value: str) -> bool:
    return value.strip().casefold() in WEAK_DEFAULTS


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character. 0.0 for empty strings."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _looks_pem(value: str) -> bool:
    v = value.strip()
    if not v.startswith("-----BEGIN"):
        return False
    return ("PRIVATE KEY" in v) or ("PUBLIC KEY" in v)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_ENTROPY_MIN = 3.0  # bits/char; below this we warn (empirical, documented in README)


def audit_env(
    entries: Iterable[EnvEntry],
    errors: Optional[Sequence[ParseError]] = None,
    *,
    source: Optional[str] = None,
    extra_secret_keys: Optional[Sequence[str]] = None,
) -> List[Finding]:
    """Run the JWT-audit rule set against a parsed env file.

    Parameters
    ----------
    entries : iterable of EnvEntry
        Parsed env entries.
    errors : sequence of ParseError, optional
        Parse-level errors; each becomes a JWT-P001 finding (parse issue).
    source : str, optional
        File path (for attribution in output).
    extra_secret_keys : sequence of str, optional
        Additional regex patterns for secret-key recognition.
    """
    findings: List[Finding] = []

    if errors:
        for pe in errors:
            findings.append(
                Finding(
                    rule="JWT-P001",
                    severity="error",
                    message=f"parse error: {pe.message}",
                    key=None,
                    line=pe.line,
                    col=pe.col,
                    source=source,
                )
            )

    # Track algorithm keys so we can cross-check HMAC key length.
    algo_by_scope: dict[str, str] = {}
    algo_entry_by_scope: dict[str, EnvEntry] = {}

    for entry in entries:
        if is_algorithm_key(entry.key):
            algo_val = entry.value.strip().upper()
            algo_by_scope[""] = algo_val  # single flat scope for .env
            algo_entry_by_scope[""] = entry
            if algo_val == "NONE":
                findings.append(
                    Finding(
                        rule="JWT-A001",
                        severity="error",
                        message=(
                            f"{entry.key}={entry.value!r}: alg=none disables signature verification"
                        ),
                        key=entry.key,
                        line=entry.line,
                        col=entry.col,
                        source=source,
                    )
                )

    for entry in entries:
        if not is_secret_key(entry.key, extra_secret_keys):
            continue
        val = entry.value
        # JWT-A003: empty
        if val == "":
            findings.append(
                Finding(
                    rule="JWT-A003",
                    severity="error",
                    message=f"{entry.key} is empty",
                    key=entry.key,
                    line=entry.line,
                    col=entry.col,
                    source=source,
                )
            )
            continue

        # A PEM-encoded key: treat as asymmetric, skip length + entropy heuristics.
        if _looks_pem(val):
            continue

        # JWT-A004: weak default
        if is_weak_default(val):
            findings.append(
                Finding(
                    rule="JWT-A004",
                    severity="error",
                    message=(
                        f"{entry.key} is set to a well-known weak default value ({val!r})"
                    ),
                    key=entry.key,
                    line=entry.line,
                    col=entry.col,
                    source=source,
                )
            )
            # continue: further checks would pile-on and confuse output
            continue

        # JWT-A005: placeholder
        if looks_like_placeholder(val):
            findings.append(
                Finding(
                    rule="JWT-A005",
                    severity="warn",
                    message=(
                        f"{entry.key} looks like a placeholder ({val!r}); replace before deploy"
                    ),
                    key=entry.key,
                    line=entry.line,
                    col=entry.col,
                    source=source,
                )
            )
            continue

        # JWT-A002: HMAC secret shorter than algorithm-appropriate byte length
        algo = algo_by_scope.get("")
        if algo in HMAC_MIN_BYTES:
            minimum = HMAC_MIN_BYTES[algo]
            n_bytes = len(val.encode("utf-8"))
            if n_bytes < minimum:
                findings.append(
                    Finding(
                        rule="JWT-A002",
                        severity="error",
                        message=(
                            f"{entry.key}: {algo} requires >= {minimum} bytes "
                            f"(RFC 7518 §3.2); got {n_bytes}"
                        ),
                        key=entry.key,
                        line=entry.line,
                        col=entry.col,
                        source=source,
                    )
                )
            findings.append(
                Finding(
                    rule="JWT-A007",
                    severity="warn",
                    message=(
                        f"{entry.key}: symmetric algorithm {algo} in use; asymmetric "
                        f"(RS256/ES256/EdDSA) is generally preferable in production"
                    ),
                    key=entry.key,
                    line=entry.line,
                    col=entry.col,
                    source=source,
                )
            )

        # JWT-A006: entropy
        ent = shannon_entropy(val)
        if ent < _ENTROPY_MIN:
            findings.append(
                Finding(
                    rule="JWT-A006",
                    severity="warn",
                    message=(
                        f"{entry.key} has low Shannon entropy ({ent:.2f} bits/char, "
                        f"< {_ENTROPY_MIN:.1f}); may be dictionary-derived"
                    ),
                    key=entry.key,
                    line=entry.line,
                    col=entry.col,
                    source=source,
                )
            )

    # Deterministic ordering: by (line, col, rule).
    findings.sort(key=lambda f: (f.line, f.col, f.rule))
    return findings


def audit_file(
    path: Path | str,
    *,
    extra_secret_keys: Optional[Sequence[str]] = None,
) -> List[Finding]:
    """Read and audit a single env file. UTF-8 with BOM tolerated."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        return [
            Finding(
                rule="JWT-P002",
                severity="error",
                message=f"unable to decode as utf-8: {exc}",
                key=None,
                line=1,
                col=1,
                source=str(p),
            )
        ]
    entries, errors = parse_env(text.splitlines())
    return audit_env(
        entries,
        errors,
        source=str(p),
        extra_secret_keys=extra_secret_keys,
    )
