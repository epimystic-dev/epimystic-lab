"""Pattern library for skillcheck.

Each Pattern is a named, case-insensitive-by-default regex bound to a rule
family. Patterns are intentionally *narrow*: they must fire on the concrete
risky shape and not on nearby-but-safe wording. Every pattern is exercised
by both a positive test (fires) and a negative test (does not fire) in
tests/test_patterns.py.

The intentional assembly of secret-shaped and sensitive-shaped fixtures at
test time (from concatenated sub-16-char parts) ensures no literal secret
value appears in this source tree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern as _RePattern

from skillcheck.verdict import Severity


@dataclass(frozen=True)
class Pattern:
    rule_id: str
    name: str
    regex: _RePattern
    severity: Severity
    message: str


def _c(pat: str, flags: int = re.IGNORECASE) -> _RePattern:
    return re.compile(pat, flags)


# ---------- SKILL-001 destructive shell ----------
_DESTRUCTIVE_SHELL: List[_RePattern] = [
    _c(r"\brm\s+-[a-z]*r[a-z]*f\b"),
    _c(r"\brm\s+-[a-z]*f[a-z]*r\b"),
    _c(r"\bdd\s+if=/dev/(?:zero|urandom|random)\b"),
    _c(r"\bmkfs\.[a-z0-9]+\b"),
    _c(r"\bshred\s+-[a-z]*\b"),
    _c(r"\bformat\s+[a-z]:\s*(?:/|\\)"),
    _c(r"\bdel\s+/[fsq]\s"),
    _c(r"Remove-Item\b[^\n]*?-Recurse\b[^\n]*?-Force\b"),
    _c(r"Remove-Item\b[^\n]*?-Force\b[^\n]*?-Recurse\b"),
    _c(r":\(\)\s*\{\s*:\|:&\s*\};:"),  # classic fork bomb
]

# ---------- SKILL-002 privilege escalation ----------
_PRIV_ESC: List[_RePattern] = [
    _c(r"(?:^|[\s`;|&(])sudo\s+[a-z]"),
    _c(r"(?:^|[\s`;|&(])doas\s+[a-z]"),
    _c(r"(?:^|[\s`;|&(])su\s+-\s+[a-z]"),
    _c(r"\brunas\s+/user:"),
    _c(r"Start-Process\s+.*-Verb\s+RunAs"),
]

# ---------- SKILL-003 network exfil / reverse shell ----------
_EXFIL: List[_RePattern] = [
    _c(r"\bbash\s+-i\s+>\s*&\s*/dev/tcp/"),
    _c(r"\bsh\s+-i\s+>\s*&\s*/dev/tcp/"),
    _c(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+"),
    _c(r"\bnc\s+-[a-z]*[el][a-z]*\s+"),
    _c(r"\bncat\s+-[a-z]*[el][a-z]*\s+"),
    _c(r"\bcurl\s+[^`\n]*(?:-X\s+POST|--data|--data-binary|-d\s+@)"),
    _c(r"\bwget\s+[^`\n]*(?:--post-file|--post-data)"),
    _c(r"Invoke-WebRequest\s+[^`\n]*-Method\s+POST"),
    _c(r"Invoke-RestMethod\s+[^`\n]*-Method\s+POST"),
]

# ---------- SKILL-004 credential / secret access ----------
_SECRET_PATHS: List[_RePattern] = [
    _c(r"~/\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)\b"),
    _c(r"~/\.aws/credentials\b"),
    _c(r"~/\.aws/config\b"),
    _c(r"~/\.docker/config\.json\b"),
    _c(r"~/\.netrc\b"),
    _c(r"~/\.kube/config\b"),
    _c(r"/etc/shadow\b"),
    _c(r"/etc/gshadow\b"),
    _c(r"%APPDATA%\\+.*credentials", re.IGNORECASE),
    _c(r"%USERPROFILE%\\+\.aws\\+credentials", re.IGNORECASE),
]

_SECRET_ENV: List[_RePattern] = [
    _c(r"\bAWS_SECRET_ACCESS_KEY\b"),
    _c(r"\bAWS_ACCESS_KEY_ID\b"),
    _c(r"\bAWS_SESSION_TOKEN\b"),
    _c(r"\bGITHUB_TOKEN\b"),
    _c(r"\bGH_TOKEN\b"),
    _c(r"\bGITLAB_TOKEN\b"),
    _c(r"\bNPM_TOKEN\b"),
    _c(r"\bPYPI_TOKEN\b"),
    _c(r"\bDOCKER_PASSWORD\b"),
    _c(r"\bSSH_PRIVATE_KEY\b"),
]

# ---------- SKILL-005 obfuscation ----------
_OBFUS: List[_RePattern] = [
    _c(r"\b(?:base64|b64decode)\b[^`\n]*\|\s*(?:sh|bash|zsh|python|python3|perl|ruby|node|eval)\b"),
    _c(r"echo\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash|zsh|python|perl|node)\b"),
    _c(r"\bxxd\s+-r\s*(?:-p\s*)?\|\s*(?:sh|bash|zsh|python|perl|node)\b"),
    _c(r"\beval\s*\$\(\s*base64\s+-d"),
    _c(r"\beval\s*`[^`]*base64[^`]*`"),
    _c(r"\bpowershell\s+[^`\n]*-EncodedCommand\b"),
    _c(r"\bpowershell\s+[^`\n]*-enc\s+[A-Za-z0-9+/=]{16,}"),
]

# Trojan-Source-style / homoglyph markers (byte-level; case-sensitive)
_HIDDEN_CHARS: List[_RePattern] = [
    re.compile(r"[‪-‮⁦-⁩]"),  # bidi overrides
    re.compile(r"[​-‍﻿]"),         # zero-width chars
]

# ---------- SKILL-006 prompt-injection markers ----------
_INJECTION: List[_RePattern] = [
    _c(r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions?\b"),
    _c(r"\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)\s+instructions?\b"),
    _c(r"\byou\s+are\s+now\s+(?:a\s+|an\s+)?(?:new\s+|different\s+)?(?:assistant|agent|persona|dan|ai)\b"),
    _c(r"^\s*SYSTEM:\s+", re.IGNORECASE | re.MULTILINE),
    _c(r"^\s*<\s*system\s*>", re.IGNORECASE | re.MULTILINE),
    _c(r"\bfrom\s+now\s+on,?\s+respond\s+as\b"),
    _c(r"\boverride\s+(?:your\s+|the\s+)?safety\b"),
    _c(r"\bjailbreak\b"),
]

# ---------- SKILL-007 runtime install-and-execute ----------
_INSTALL_EXEC: List[_RePattern] = [
    _c(r"\bcurl\s+[^`\n|]+\|\s*(?:sh|bash|zsh)\b"),
    _c(r"\bwget\s+[^`\n|]+\|\s*(?:sh|bash|zsh)\b"),
    _c(r"\bcurl\s+[^`\n|]+\|\s*python[0-9]?\b"),
    _c(r"\bwget\s+[^`\n|]+\|\s*python[0-9]?\b"),
    _c(r"\biwr\s+[^`\n|]+\|\s*iex\b"),
    _c(r"Invoke-WebRequest\s+[^`\n|]+\|\s*Invoke-Expression\b"),
    _c(r"Invoke-Expression\s+\(\s*(?:Invoke-WebRequest|iwr|New-Object\s+Net\.WebClient)"),
    _c(r"\bpip\s+install\s+[^`\n|;&]+(?:&&|;)\s*python\s+-c\b"),
    _c(r"\bnpm\s+install\s+-g\s+[^`\n|;&]+(?:&&|;)\s*(?:node|npx)\b"),
]

# ---------- SKILL-008 filesystem archive exfil ----------
_ARCHIVE_EXFIL: List[_RePattern] = [
    _c(r"\btar\s+[a-z]*c[a-z]*z[a-z]*f?\s+-\s+[^`\n]*\|\s*(?:curl|nc|ncat|wget)\b"),
    _c(r"\bzip\s+-r\s+-\s+[^`\n]*\|\s*(?:curl|nc|ncat|wget)\b"),
    _c(r"Compress-Archive\s+[^`\n]*\|\s*Invoke-WebRequest\b"),
    _c(r"\b(?:cat|type)\s+[^`\n]*\|\s*curl\s+[^`\n]*-T\s+-(?:\s|$)"),
]

# ---------- SKILL-010 suspicious external URL ----------
_SUSPICIOUS_URL: List[_RePattern] = [
    _c(r"\bhttp://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/"),
    _c(r"\bhttps?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/"),
    _c(r"\bhttps?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)/"),
]


def _mk(rule_id: str, name: str, regex: _RePattern, severity: Severity, message: str) -> Pattern:
    return Pattern(rule_id=rule_id, name=name, regex=regex, severity=severity, message=message)


def _family(rule_id: str, base_name: str, regexes: List[_RePattern], severity: Severity, message: str) -> List[Pattern]:
    return [
        _mk(rule_id, f"{base_name}_{i:02d}", rx, severity, message)
        for i, rx in enumerate(regexes, start=1)
    ]


PATTERNS: List[Pattern] = []
PATTERNS += _family("SKILLCHECK-001", "destructive_shell", _DESTRUCTIVE_SHELL, Severity.CRITICAL,
                   "destructive shell command that can irreversibly delete or overwrite data")
PATTERNS += _family("SKILLCHECK-002", "priv_esc", _PRIV_ESC, Severity.HIGH,
                   "privilege-escalation invocation")
PATTERNS += _family("SKILLCHECK-003", "network_exfil", _EXFIL, Severity.CRITICAL,
                   "network exfiltration / reverse-shell shape")
PATTERNS += _family("SKILLCHECK-004", "secret_path", _SECRET_PATHS, Severity.HIGH,
                   "credential or secret filesystem path reference")
PATTERNS += _family("SKILLCHECK-004", "secret_env", _SECRET_ENV, Severity.HIGH,
                   "sensitive credential environment variable reference")
PATTERNS += _family("SKILLCHECK-005", "obfuscation", _OBFUS, Severity.HIGH,
                   "encoded / obfuscated command execution")
PATTERNS += _family("SKILLCHECK-005", "hidden_char", _HIDDEN_CHARS, Severity.HIGH,
                   "invisible / bidi-override / zero-width control character")
PATTERNS += _family("SKILLCHECK-006", "injection", _INJECTION, Severity.MEDIUM,
                   "prompt-injection payload marker")
PATTERNS += _family("SKILLCHECK-007", "install_exec", _INSTALL_EXEC, Severity.HIGH,
                   "runtime install-and-execute pattern (unsigned remote code)")
PATTERNS += _family("SKILLCHECK-008", "archive_exfil", _ARCHIVE_EXFIL, Severity.HIGH,
                   "filesystem archive exfiltration pipe")
PATTERNS += _family("SKILLCHECK-010", "suspicious_url", _SUSPICIOUS_URL, Severity.MEDIUM,
                   "URL referencing raw IP or common shortener host")


PATTERNS_BY_RULE = {}
for p in PATTERNS:
    PATTERNS_BY_RULE.setdefault(p.rule_id, []).append(p)
