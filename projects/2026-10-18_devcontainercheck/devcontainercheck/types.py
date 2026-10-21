"""Shared datatypes for devcontainercheck.

Severity, Verdict, Finding, ScanResult, and Options are the shape
surface the rest of the package - and the lab-wide shared contract -
agrees on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    """One rule firing against one devcontainer.json at one JSON pointer."""

    rule_id: str
    severity: Severity
    message: str
    pointer: str
    path: str = ""
    hint: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "pointer": self.pointer,
            "path": self.path,
            "hint": self.hint,
        }


@dataclass
class ScanResult:
    """The outcome of scanning one or more devcontainer.json files."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass(frozen=True)
class Options:
    """Scan-time options surfaced by the CLI."""

    strict: bool = False
    include_info: bool = False
    disabled: Tuple[str, ...] = ()
    only: Tuple[str, ...] = ()
    # Host paths DC-006 treats as sensitive bind-mount targets. A mount
    # whose source resolves to one of these (case-insensitively, after
    # ${localEnv:...} expansion to its placeholder) fires HIGH.
    sensitive_host_paths: Tuple[str, ...] = (
        "/", "/root", "/home",
        "/var/run/docker.sock", "/run/docker.sock",
        ".ssh", ".aws", ".gnupg", ".docker",
        ".kube", ".config/gcloud", ".config/gh",
        ".netrc", "_netrc",
    )
    # Host environment variables DC-009 treats as sensitive when
    # exposed through ${localEnv:NAME}.
    sensitive_host_env: Tuple[str, ...] = (
        "api_key", "apikey", "api_token", "token",
        "secret", "password", "passwd", "pass",
        "aws_access_key_id", "aws_secret_access_key",
        "aws_session_token", "github_token", "gh_token",
        "npm_token", "pypi_token", "cargo_token",
        "hf_token",
        "huggingface_token", "docker_password",
        "slack_token", "gitlab_token", "circle_token",
    )
    # A host variable whose lowercased name ENDS in one of these is also
    # treated as sensitive. This is what catches the long tail of vendor and
    # in-house credentials (any *_API_KEY, *_TOKEN, *_SECRET ...) that no
    # fixed list can enumerate. The list above stays for credentials whose
    # names carry no such suffix.
    sensitive_host_env_suffixes: Tuple[str, ...] = (
        "_api_key", "_apikey", "_api_token", "_access_token",
        "_auth_token", "_token", "_secret", "_secret_key",
        "_private_key", "_access_key", "_password", "_passwd",
    )

    def rule_enabled(self, rule_id: str) -> bool:
        if self.only and rule_id not in self.only:
            return False
        if rule_id in self.disabled:
            return False
        return True


__all__ = [
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Options",
]
