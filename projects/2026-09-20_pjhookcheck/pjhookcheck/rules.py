"""Rule registry for pjhookcheck.

Each rule is a small function `check(doc, text, path, options) -> list[Finding]`.
Rules do not raise; they return an empty list when they do not fire and
they never look at anything outside doc / text / path / options.

The rule set targets install-time supply-chain shapes rather than every
possible package.json quirk. It has 12 rules on a 6 HIGH / 5 MEDIUM /
1 INFO split; the INFO rule is hidden by default and shown only under
--strict / --include-info.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

from .parse import (
    LIFECYCLE_HOOKS,
    find_key,
    find_string_value,
    iter_dependency_sections,
    iter_lifecycle_hooks,
    offset_to_line_col,
    truncate_snippet,
)
from .types import Finding, Options, Severity

Check = Callable[[Any, str, str, Options], List[Finding]]


def _hook_line_col(text: str, hook: str) -> Tuple[int, int]:
    # scripts key first, then the hook key inside it, then the value.
    scripts_off = find_key(text, "scripts")
    off = find_key(text, hook, from_offset=max(0, scripts_off))
    return offset_to_line_col(text, off if off >= 0 else 0)


def _dep_line_col(text: str, section: str, name: str) -> Tuple[int, int]:
    sec_off = find_key(text, section)
    off = find_key(text, name, from_offset=max(0, sec_off))
    return offset_to_line_col(text, off if off >= 0 else 0)


# ---------- Regex constants used by more than one rule ----------

# curl / wget / fetch pipe to a shell interpreter or node.
_FETCH_EXEC_PATTERNS = [
    re.compile(r"\bcurl\b[^|]{1,200}\|\s*(sh|bash|zsh|dash|ash|node|python|python3|ruby|perl)\b"),
    re.compile(r"\bwget\b[^|]{1,200}\|\s*(sh|bash|zsh|dash|ash|node|python|python3|ruby|perl)\b"),
    re.compile(r"\bfetch\b[^|]{1,200}\|\s*(sh|bash|zsh|dash|ash|node|python|python3|ruby|perl)\b"),
    re.compile(r"Invoke-WebRequest\b[^|]{1,200}\|\s*Invoke-Expression", re.IGNORECASE),
    re.compile(r"\biwr\b[^|]{1,200}\|\s*\biex\b", re.IGNORECASE),
]

# node -e, python -c, sh -c, etc. with any non-trivial payload after.
_INLINE_EVAL_PATTERNS = [
    re.compile(r"\bnode\s+(--eval|-e)\b\s+[^\s]"),
    re.compile(r"\bpython3?\s+-c\b\s+[^\s]"),
    re.compile(r"\bruby\s+-e\b\s+[^\s]"),
    re.compile(r"\bperl\s+-e\b\s+[^\s]"),
    re.compile(r"\b(sh|bash|zsh|dash|ash)\s+-c\b\s+[^\s]"),
    re.compile(r"\bpowershell\b[^|]{0,100}(-c|-Command|-EncodedCommand)\b", re.IGNORECASE),
]

# base64 -d, atob, Buffer.from(..., 'base64') piped to exec / eval / node -.
_DECODE_EXEC_PATTERNS = [
    re.compile(r"\bbase64\s+(-d|--decode)\b[^|]{0,200}\|\s*(sh|bash|zsh|node|python|python3)\b"),
    re.compile(r"\bxxd\s+-r\b[^|]{0,200}\|\s*(sh|bash|node)\b"),
    re.compile(r"echo\s+[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*\|\s*base64\s+(-d|--decode)"),
    re.compile(r"Buffer\.from\([^)]*['\"]base64['\"]\)\s*\.\s*toString"),
    re.compile(r"\batob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]"),
]

# Sensitive user / system paths a hook should never write to.
_SENSITIVE_PATHS = [
    "~/.ssh/",
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.bash_profile",
    "~/.npmrc",
    "~/.aws/",
    "~/.docker/",
    "/etc/",
    "/usr/",
    "/root/",
    "$HOME/.ssh",
    "$HOME/.bashrc",
    "%USERPROFILE%\\.ssh",
]

# Global-install invocations across the four major package managers.
_GLOBAL_INSTALL_PATTERNS = [
    re.compile(r"\bnpm\s+(i|install|add)\s+[^&]*\B-g\b"),
    re.compile(r"\bnpm\s+(i|install|add)\s+[^&]*--global\b"),
    re.compile(r"\byarn\s+global\s+add\b"),
    re.compile(r"\bpnpm\s+add\s+[^&]*(-g|--global)\b"),
    re.compile(r"\bbun\s+(add|install)\s+[^&]*(-g|--global)\b"),
]

# Env var names that read as credentials. Case-insensitive.
_SECRET_ENV_NAMES = re.compile(
    r"\$\{?([A-Za-z_][A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|API[_-]?KEY|APIKEY|"
    r"ACCESS[_-]?KEY|PRIVATE[_-]?KEY|NPM[_-]?TOKEN|CI[_-]?JOB[_-]?TOKEN|"
    r"GITHUB[_-]?TOKEN|GH[_-]?TOKEN|AWS[_-]?SECRET|SESSION[_-]?KEY))\}?",
    re.IGNORECASE,
)

# Version specifiers we call "unpinned to a security floor".
_UNPINNED_SPECIFIERS = ("latest", "*", "x", "X", "next", "canary", "beta", "rc", "")

# Git / tarball URL prefixes that bypass the registry-plus-lockfile flow.
_URL_DEP_PREFIXES = (
    "git+",
    "git://",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "http://",
    "https://",
)


# ---------- Individual rules ----------

def rule_pjh_001_fetch_exec(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        if any(p.search(cmd) for p in _FETCH_EXEC_PATTERNS):
            line, col = _hook_line_col(text, hook)
            findings.append(Finding(
                rule_id="PJH-001",
                severity=Severity.HIGH,
                path=path,
                prop=f"scripts.{hook}",
                line=line, column=col,
                message=(
                    f"scripts.{hook} pipes a remote fetch into a shell "
                    "interpreter (curl|sh, wget|sh, iwr|iex or equivalent)"
                ),
                snippet=truncate_snippet(cmd),
            ))
    return findings


def rule_pjh_002_inline_eval(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        if any(p.search(cmd) for p in _INLINE_EVAL_PATTERNS):
            # Suppress false positives when PJH-001 already fired (the
            # fetch-exec message is the more specific signal and lands on
            # the same textual position).
            if any(p.search(cmd) for p in _FETCH_EXEC_PATTERNS):
                continue
            line, col = _hook_line_col(text, hook)
            findings.append(Finding(
                rule_id="PJH-002",
                severity=Severity.HIGH,
                path=path,
                prop=f"scripts.{hook}",
                line=line, column=col,
                message=(
                    f"scripts.{hook} uses an inline-eval interpreter flag "
                    "(node -e, python -c, sh -c or equivalent)"
                ),
                snippet=truncate_snippet(cmd),
            ))
    return findings


def rule_pjh_003_decode_exec(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        if any(p.search(cmd) for p in _DECODE_EXEC_PATTERNS):
            line, col = _hook_line_col(text, hook)
            findings.append(Finding(
                rule_id="PJH-003",
                severity=Severity.HIGH,
                path=path,
                prop=f"scripts.{hook}",
                line=line, column=col,
                message=(
                    f"scripts.{hook} decodes an encoded blob and passes "
                    "the result to a shell or eval site (base64 -d | sh, "
                    "Buffer.from(...,'base64').toString or equivalent)"
                ),
                snippet=truncate_snippet(cmd),
            ))
    return findings


def rule_pjh_004_url_dep_spec(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for section, deps in iter_dependency_sections(doc):
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            s = spec.strip()
            if any(s.startswith(prefix) for prefix in _URL_DEP_PREFIXES):
                line, col = _dep_line_col(text, section, name)
                findings.append(Finding(
                    rule_id="PJH-004",
                    severity=Severity.HIGH,
                    path=path,
                    prop=f"{section}.{name}",
                    line=line, column=col,
                    message=(
                        f"{section}.{name} is a URL specifier ({s.split(':', 1)[0]}:...) "
                        "which is not pinned by content hash and bypasses "
                        "the registry-plus-lockfile flow"
                    ),
                    snippet=truncate_snippet(s),
                ))
    return findings


def rule_pjh_005_file_dep_escapes(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for section, deps in iter_dependency_sections(doc):
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            s = spec.strip()
            if not s.startswith("file:"):
                continue
            target = s[len("file:"):]
            escapes = (
                target.startswith("/")
                or target.startswith("~")
                or target.startswith("..")
                or target.startswith("\\")
                or (len(target) >= 2 and target[1] == ":")
            )
            if escapes:
                line, col = _dep_line_col(text, section, name)
                findings.append(Finding(
                    rule_id="PJH-005",
                    severity=Severity.HIGH,
                    path=path,
                    prop=f"{section}.{name}",
                    line=line, column=col,
                    message=(
                        f"{section}.{name} is a file: specifier that "
                        "escapes the repository root"
                    ),
                    snippet=truncate_snippet(s),
                ))
    return findings


def rule_pjh_006_sensitive_write(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        for token in _SENSITIVE_PATHS:
            if token in cmd:
                line, col = _hook_line_col(text, hook)
                findings.append(Finding(
                    rule_id="PJH-006",
                    severity=Severity.HIGH,
                    path=path,
                    prop=f"scripts.{hook}",
                    line=line, column=col,
                    message=(
                        f"scripts.{hook} references a sensitive user or "
                        f"system path ({token})"
                    ),
                    snippet=truncate_snippet(cmd),
                ))
                break  # one finding per hook is enough
    return findings


def rule_pjh_007_global_install(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        if any(p.search(cmd) for p in _GLOBAL_INSTALL_PATTERNS):
            line, col = _hook_line_col(text, hook)
            findings.append(Finding(
                rule_id="PJH-007",
                severity=Severity.MEDIUM,
                path=path,
                prop=f"scripts.{hook}",
                line=line, column=col,
                message=(
                    f"scripts.{hook} installs a package globally, which "
                    "escapes the project sandbox"
                ),
                snippet=truncate_snippet(cmd),
            ))
    return findings


def rule_pjh_008_secret_env_echo(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        m = _SECRET_ENV_NAMES.search(cmd)
        if m and re.search(r"\b(echo|printf|print)\b", cmd):
            line, col = _hook_line_col(text, hook)
            findings.append(Finding(
                rule_id="PJH-008",
                severity=Severity.MEDIUM,
                path=path,
                prop=f"scripts.{hook}",
                line=line, column=col,
                message=(
                    f"scripts.{hook} prints an environment variable with "
                    f"a credential-shape name ({m.group(1)})"
                ),
                snippet=truncate_snippet(cmd),
            ))
    return findings


def rule_pjh_009_unpinned_spec(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for section, deps in iter_dependency_sections(doc):
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            s = spec.strip()
            reason = None
            if s in _UNPINNED_SPECIFIERS:
                reason = f'the value is "{s}"' if s else "the value is empty"
            elif s in (">=0", ">=0.0", ">=0.0.0", ">0", ">0.0", ">0.0.0"):
                reason = f'the value is "{s}" (unbounded floor)'
            elif re.fullmatch(r"[xX](\.[xX])*", s) or re.fullmatch(r"\d+\.[xX](\.[xX])?", s):
                reason = f'the value is "{s}" (a wildcard version)'
            if reason:
                line, col = _dep_line_col(text, section, name)
                findings.append(Finding(
                    rule_id="PJH-009",
                    severity=Severity.MEDIUM,
                    path=path,
                    prop=f"{section}.{name}",
                    line=line, column=col,
                    message=(
                        f"{section}.{name} has no security floor: {reason}"
                    ),
                    snippet=truncate_snippet(s),
                ))
    return findings


def rule_pjh_010_bundle_dependencies(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(doc, dict):
        return findings
    for name in ("bundleDependencies", "bundledDependencies"):
        val = doc.get(name)
        if isinstance(val, list) and val:
            off = find_key(text, name)
            line, col = offset_to_line_col(text, off if off >= 0 else 0)
            findings.append(Finding(
                rule_id="PJH-010",
                severity=Severity.MEDIUM,
                path=path,
                prop=name,
                line=line, column=col,
                message=(
                    f"{name} lists {len(val)} entries; bundled transitive "
                    "dependencies are hidden from the lockfile and audit tools"
                ),
                snippet=truncate_snippet(", ".join(str(x) for x in val[:6])),
            ))
        elif val is True:
            off = find_key(text, name)
            line, col = offset_to_line_col(text, off if off >= 0 else 0)
            findings.append(Finding(
                rule_id="PJH-010",
                severity=Severity.MEDIUM,
                path=path,
                prop=name,
                line=line, column=col,
                message=(
                    f"{name} is set to true; every declared dependency is "
                    "bundled and hidden from the lockfile"
                ),
                snippet="true",
            ))
    return findings


def rule_pjh_011_obfuscation(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for hook, cmd in iter_lifecycle_hooks(doc):
        # Density of hex/unicode escapes.
        esc = len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", cmd))
        long_line = len(cmd) >= 400 and "\n" not in cmd
        long_b64_like = bool(re.search(r"[A-Za-z0-9+/]{200,}={0,2}", cmd))
        if esc >= 6 or long_line or long_b64_like:
            # Do not double-fire with the higher-severity PJH-003.
            if any(p.search(cmd) for p in _DECODE_EXEC_PATTERNS):
                continue
            line, col = _hook_line_col(text, hook)
            reason = (
                f"{esc} hex/unicode escapes" if esc >= 6
                else "a single line over 400 characters" if long_line
                else "a base64-shape run of 200+ characters"
            )
            findings.append(Finding(
                rule_id="PJH-011",
                severity=Severity.MEDIUM,
                path=path,
                prop=f"scripts.{hook}",
                line=line, column=col,
                message=(
                    f"scripts.{hook} looks obfuscated ({reason}); the "
                    "hook body is not readable in review"
                ),
                snippet=truncate_snippet(cmd),
            ))
    return findings


def rule_pjh_012_package_manager_pin(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    if not isinstance(doc, dict):
        return []
    if "packageManager" in doc:
        return []
    return [Finding(
        rule_id="PJH-012",
        severity=Severity.INFO,
        path=path,
        prop="packageManager",
        line=1, column=1,
        message=(
            "packageManager is not set; corepack cannot pin the client "
            "so the install-time behaviour is up to whichever CLI is on PATH"
        ),
        snippet="",
    )]


# ---------- Registry ----------


class Rule:
    __slots__ = ("id", "severity", "description", "check")

    def __init__(self, rid: str, sev: Severity, desc: str, check: Check) -> None:
        self.id = rid
        self.severity = sev
        self.description = desc
        self.check = check


REGISTRY: Tuple[Rule, ...] = (
    Rule("PJH-001", Severity.HIGH,
         "Lifecycle hook pipes a remote fetch into a shell interpreter.",
         rule_pjh_001_fetch_exec),
    Rule("PJH-002", Severity.HIGH,
         "Lifecycle hook uses an inline-eval interpreter flag.",
         rule_pjh_002_inline_eval),
    Rule("PJH-003", Severity.HIGH,
         "Lifecycle hook decodes an encoded blob into an exec site.",
         rule_pjh_003_decode_exec),
    Rule("PJH-004", Severity.HIGH,
         "Dependency specifier is a git or tarball URL, not registry+hash-pinned.",
         rule_pjh_004_url_dep_spec),
    Rule("PJH-005", Severity.HIGH,
         "file: dependency specifier escapes the repository root.",
         rule_pjh_005_file_dep_escapes),
    Rule("PJH-006", Severity.HIGH,
         "Lifecycle hook references a sensitive user or system path.",
         rule_pjh_006_sensitive_write),
    Rule("PJH-007", Severity.MEDIUM,
         "Lifecycle hook installs a package globally.",
         rule_pjh_007_global_install),
    Rule("PJH-008", Severity.MEDIUM,
         "Lifecycle hook prints an env var with a credential-shape name.",
         rule_pjh_008_secret_env_echo),
    Rule("PJH-009", Severity.MEDIUM,
         "Dependency version specifier has no security floor.",
         rule_pjh_009_unpinned_spec),
    Rule("PJH-010", Severity.MEDIUM,
         "bundleDependencies present; transitive deps hidden from the lockfile.",
         rule_pjh_010_bundle_dependencies),
    Rule("PJH-011", Severity.MEDIUM,
         "Lifecycle hook body is heavily obfuscated.",
         rule_pjh_011_obfuscation),
    Rule("PJH-012", Severity.INFO,
         "packageManager pin is absent; corepack cannot pin the CLI.",
         rule_pjh_012_package_manager_pin),
)


REGISTRY_BY_ID: Dict[str, Rule] = {r.id: r for r in REGISTRY}


def all_rule_ids() -> Tuple[str, ...]:
    return tuple(r.id for r in REGISTRY)


def run_all(doc: Any, text: str, path: str, options: Options) -> List[Finding]:
    out: List[Finding] = []
    for rule in REGISTRY:
        if rule.id in options.disabled:
            continue
        try:
            out.extend(rule.check(doc, text, path, options))
        except Exception as exc:  # keep the scan going on a rule bug
            out.append(Finding(
                rule_id=rule.id,
                severity=Severity.INFO,
                path=path,
                prop="",
                line=1, column=1,
                message=f"rule crashed: {type(exc).__name__}: {exc}",
                snippet="",
            ))
    return out
