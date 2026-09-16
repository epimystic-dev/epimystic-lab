"""Rules for mcpservercheck.

Each rule is a structural check over a parsed MCP server registration
config (a dict from a JSON file, or a per-line dict from a JSONL file).
Rule design: each rule is a specific SHAPE defect grounded in the
MCP-server threat literature (see README for citations). A rule flags
a shape that is often adversarial or often the root cause of a failure;
it never claims intent.
"""

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Sequence, Tuple

from urllib.parse import urlparse

from .parse import find_key_line_col, find_value_line_col, short
from .types import Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    description: str
    check_fn: Callable[[Any, str, str], List[Finding]]


def _emit(rule, path, line, col, message, snippet):
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        path=path,
        line=line,
        column=col,
        message=message,
        snippet=snippet,
    )


def _iter_servers(obj) -> Iterable[Tuple[str, dict]]:
    """Yield (server_name, server_cfg) pairs across the recognised container shapes.

    Supported top-level shapes (recognised across the common client formats):
      {"mcpServers": {name: cfg}}     the most common top-level container
      {"servers":    {name: cfg}}     alternate top-level container
      {"mcp": {"servers": {name: cfg}}}  nested-under-mcp variant
      {name: cfg, name: cfg, ...}     bare top-level (only if each value looks
                                      like a server cfg: has "command" or "url")
    """
    if not isinstance(obj, dict):
        return
    for k in ("mcpServers", "servers"):
        v = obj.get(k)
        if isinstance(v, dict):
            for name, cfg in v.items():
                if isinstance(cfg, dict):
                    yield str(name), cfg
            return
    mcp = obj.get("mcp")
    if isinstance(mcp, dict):
        v = mcp.get("servers")
        if isinstance(v, dict):
            for name, cfg in v.items():
                if isinstance(cfg, dict):
                    yield str(name), cfg
            return
    if all(isinstance(v, dict) and ("command" in v or "url" in v) for v in obj.values()) and obj:
        for name, cfg in obj.items():
            yield str(name), cfg


def _as_str_list(v) -> List[str]:
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def _basename(cmd: str) -> str:
    if not isinstance(cmd, str) or not cmd:
        return ""
    for sep in ("/", "\\"):
        if sep in cmd:
            cmd = cmd.rsplit(sep, 1)[-1]
    return cmd.lower()


_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ash", "ksh", "fish",
    "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "lua", "tcl",
    "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "wscript", "wscript.exe", "cscript", "cscript.exe",
}


def _is_interpreter(base: str) -> bool:
    if not base:
        return False
    if base in _INTERPRETERS:
        return True
    if base.startswith("python"):
        # python, python2, python3, python3.11, python3.13-config, ...
        rest = base[len("python"):]
        if rest == "" or rest == "2" or rest == "3":
            return True
        if rest.startswith("3.") or rest.startswith("2."):
            return True
    return False


_EVAL_FLAGS = {"-c", "/c", "-e", "-command", "-encodedcommand", "-ec"}


def _is_eval_flag(arg: str) -> bool:
    if not isinstance(arg, str):
        return False
    return arg.lower() in _EVAL_FLAGS


def _effective_interpreter_and_flag(command, args) -> Tuple[str, str]:
    """Return (interpreter_basename, eval_flag) if the command is an
    interpreter with an inline-eval flag, else ("", "")."""
    base = _basename(command) if isinstance(command, str) else ""
    args_list = _as_str_list(args)

    # /usr/bin/env <interp> -c ...
    if base == "env" and args_list:
        inner_base = _basename(args_list[0])
        if _is_interpreter(inner_base) and len(args_list) >= 2 and _is_eval_flag(args_list[1]):
            return inner_base, args_list[1].lower()
        # deno eval / bun eval as positional
        if inner_base in ("deno", "bun") and len(args_list) >= 2 and args_list[1].lower() == "eval":
            return inner_base, "eval"
        return "", ""

    if _is_interpreter(base) and args_list and _is_eval_flag(args_list[0]):
        return base, args_list[0].lower()
    # deno eval / bun eval
    if base in ("deno", "bun") and args_list and args_list[0].lower() == "eval":
        return base, "eval"
    return "", ""


def _rule_001_shell_eval(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        interp, flag = _effective_interpreter_and_flag(cfg.get("command"), cfg.get("args"))
        if not interp:
            continue
        line, col = find_key_line_col(text, name)
        if line == 1 and col == 1:
            line, col = find_key_line_col(text, "command")
        findings.append(_emit(
            _RULE_001, path, line, col,
            "server '" + name + "' runs interpreter '" + interp + "' with eval flag '" + flag + "'; "
            "tool args flow into an arbitrary interpreter",
            short(cfg),
        ))
    return findings


_PLAINTEXT_SCHEMES = {"http", "ws"}


def _rule_002_plaintext_transport(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        url = cfg.get("url")
        if not isinstance(url, str) or not url:
            continue
        try:
            parts = urlparse(url)
        except (ValueError, AttributeError):
            continue
        scheme = (parts.scheme or "").lower()
        if scheme in _PLAINTEXT_SCHEMES:
            line, col = find_key_line_col(text, "url")
            findings.append(_emit(
                _RULE_002, path, line, col,
                "server '" + name + "' uses plaintext transport '" + scheme + "://'; "
                "tokens and tool payloads travel unencrypted",
                short(url),
            ))
    return findings


_REF_RE = re.compile(r"^\s*(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)\s*$")


def _is_var_reference(v: str) -> bool:
    if not isinstance(v, str):
        return False
    return _REF_RE.match(v) is not None


_TOKEN_PREFIXES = (
    "sk-", "sk_", "pk-",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
    "AKIA", "ASIA",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "glpat-", "glptt-",
    "AIza",
    "hf_",
    "nvapi-",
    "npm_",
    "sq0atp-", "sq0csp-",
    "pypi-",
)


_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}$")

_BEARER_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.+/=")
_BEARER_MIN_LEN = 32


def _looks_like_bearer_literal(v) -> Tuple[bool, str]:
    """Return (matched, reason) if v looks like an inline bearer literal."""
    if not isinstance(v, str):
        return False, ""
    s = v.strip()
    if not s:
        return False, ""
    if _is_var_reference(s):
        return False, ""
    for p in _TOKEN_PREFIXES:
        if s.startswith(p):
            return True, "known-prefix '" + p + "'"
    if "-----BEGIN" in s:
        return True, "PEM header"
    if _JWT_RE.match(s):
        return True, "JWT shape"
    if len(s) >= _BEARER_MIN_LEN and all(c in _BEARER_CHARS for c in s) and len(set(s)) >= 16:
        return True, "high-entropy long string (" + str(len(s)) + " chars)"
    return False, ""


def _rule_003_inline_bearer(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        env = cfg.get("env")
        if not isinstance(env, dict):
            continue
        for k, v in env.items():
            ok, reason = _looks_like_bearer_literal(v)
            if not ok:
                continue
            line, col = find_key_line_col(text, k)
            findings.append(_emit(
                _RULE_003, path, line, col,
                "server '" + name + "' env['" + str(k) + "'] contains an inline bearer literal (" + reason + "); "
                "reference an env-var (${" + str(k) + "}) or a vault ref instead",
                short(str(v)[:16] + "..."),
            ))
    return findings


_REMOTE_FETCHERS = ("curl", "wget", "fetch", "iwr", "invoke-webrequest")
_PIPE_INTERPRETERS = ("sh", "bash", "zsh", "python", "node", "ruby", "perl", "php")


def _flat_command_line(cfg) -> str:
    parts = []
    cmd = cfg.get("command")
    if isinstance(cmd, str):
        parts.append(cmd)
    args = _as_str_list(cfg.get("args"))
    parts.extend(args)
    return " ".join(parts)


def _has_remote_fetch_and_exec(line: str) -> Tuple[bool, str]:
    lower = line.lower()
    for f in _REMOTE_FETCHERS:
        if f + " " not in lower and not lower.startswith(f + " "):
            continue
        # curl <url> | sh
        for interp in _PIPE_INTERPRETERS:
            if "| " + interp in lower or "|" + interp in lower:
                return True, "'" + f + " ... | " + interp + "' pipe-into-interpreter"
        # bash <(curl ...)
        if "<(curl" in lower or "<(wget" in lower:
            return True, "process-substitution fetch-and-exec"
    if re.search(r"\biex\b", lower):
        return True, "PowerShell iex (Invoke-Expression) usage"
    if "invoke-expression" in lower:
        return True, "PowerShell Invoke-Expression usage"
    return False, ""


def _has_unpinned_git_ref(arg: str) -> Tuple[bool, str]:
    lower = arg.lower()
    if "git+http" not in lower:
        return False, ""
    # accept @<ref> after the URL host/path
    idx = lower.find("git+http")
    tail = arg[idx:]
    # tail is like git+https://host/user/repo.git@sha  or  git+https://host/user/repo
    # split off git+ prefix, then look for '@' after the scheme part
    parts = tail.split("://", 1)
    if len(parts) < 2:
        return True, "git+ URL without scheme"
    rest = parts[1]
    if "@" in rest:
        # even if @, must not be @HEAD / @main / @master with no sha
        at_idx = rest.rfind("@")
        ref = rest[at_idx + 1:].strip()
        if ref.lower() in ("head", "main", "master", "latest", "dev", "trunk"):
            return True, "git+ URL pinned to unstable ref '" + ref + "'"
        return False, ""
    return True, "git+ URL without @<ref>"


def _rule_004_remote_fetch_exec(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        line_text = _flat_command_line(cfg)
        if not line_text:
            continue
        ok, reason = _has_remote_fetch_and_exec(line_text)
        if ok:
            line, col = find_key_line_col(text, "command")
            if line == 1 and col == 1:
                line, col = find_key_line_col(text, name)
            findings.append(_emit(
                _RULE_004, path, line, col,
                "server '" + name + "' command line has " + reason,
                short(line_text),
            ))
    return findings


def _rule_005_structurally_incomplete(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        has_cmd = isinstance(cfg.get("command"), str) and cfg.get("command")
        has_url = isinstance(cfg.get("url"), str) and cfg.get("url")
        if has_cmd or has_url:
            continue
        line, col = find_key_line_col(text, name)
        findings.append(_emit(
            _RULE_005, path, line, col,
            "server '" + name + "' has neither 'command' nor 'url'; "
            "the client cannot start or connect to it",
            short(cfg),
        ))
    return findings


def _rule_006_unpinned_package(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        args = _as_str_list(cfg.get("args"))
        for i, a in enumerate(args):
            ok, reason = _has_unpinned_git_ref(a)
            if ok:
                line, col = find_key_line_col(text, "args")
                findings.append(_emit(
                    _RULE_006, path, line, col,
                    "server '" + name + "' args[" + str(i) + "] uses " + reason,
                    short(a),
                ))
                continue
            low = a.lower()
            if "@latest" in low or a.strip().lower().endswith("@head"):
                line, col = find_key_line_col(text, "args")
                findings.append(_emit(
                    _RULE_006, path, line, col,
                    "server '" + name + "' args[" + str(i) + "] pins to unstable tag '@latest' / '@head'",
                    short(a),
                ))
                continue
            if low.startswith("--tag=latest") or low == "--tag":
                line, col = find_key_line_col(text, "args")
                findings.append(_emit(
                    _RULE_006, path, line, col,
                    "server '" + name + "' args[" + str(i) + "] uses '--tag latest' (moving reference)",
                    short(a),
                ))
    return findings


_CRED_KEY_TOKENS = (
    "token", "key", "secret", "password", "passwd", "pwd",
    "credential", "credentials", "auth", "access_key", "session",
    "apikey", "api_key", "privatekey", "private_key",
)


def _looks_like_cred_key(k: str) -> bool:
    if not isinstance(k, str):
        return False
    kl = k.lower()
    for t in _CRED_KEY_TOKENS:
        if t in kl:
            return True
    return False


def _rule_007_cred_env_key(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        env = cfg.get("env")
        if not isinstance(env, dict):
            continue
        for k, v in env.items():
            if not _looks_like_cred_key(k):
                continue
            if not isinstance(v, str):
                continue
            if v == "":
                continue
            if _is_var_reference(v):
                continue
            # Also skip if the value equals its own key wrapped in ${...}
            if v.strip() == "${" + str(k) + "}":
                continue
            # Do not double-fire when MSC-003 will also flag the bearer literal shape
            # (both rules are legitimate hits; keep both. MSC-003 fires on VALUE shape,
            # MSC-007 fires on KEY-name shape with a non-reference value.)
            line, col = find_key_line_col(text, k)
            findings.append(_emit(
                _RULE_007, path, line, col,
                "server '" + name + "' env['" + str(k) + "'] has an inline value for a credential-shaped key; "
                "use a variable reference (${" + str(k) + "}) so the secret does not live in the config file",
                short(str(v)[:16] + ("..." if len(str(v)) > 16 else "")),
            ))
    return findings


_WILDCARDS = {"*", "all", "*/*", "any", "everyone"}
_PERMISSION_KEYS = ("allowedTools", "allowed_tools", "permissions", "capabilities", "tools")


def _rule_008_wildcard_permission(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        for k in _PERMISSION_KEYS:
            v = cfg.get(k)
            if v is None:
                continue
            if isinstance(v, str) and v.strip().lower() in _WILDCARDS:
                line, col = find_key_line_col(text, k)
                findings.append(_emit(
                    _RULE_008, path, line, col,
                    "server '" + name + "' " + k + " is wildcard '" + v + "'",
                    short(v),
                ))
                continue
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, str) and x.strip().lower() in _WILDCARDS:
                        line, col = find_key_line_col(text, k)
                        findings.append(_emit(
                            _RULE_008, path, line, col,
                            "server '" + name + "' " + k + " contains wildcard entry '" + x + "'",
                            short(v),
                        ))
                        break
        env = cfg.get("env")
        if isinstance(env, dict):
            for ek in env.keys():
                if isinstance(ek, str) and ek.strip() in ("*", "**"):
                    line, col = find_key_line_col(text, "env")
                    findings.append(_emit(
                        _RULE_008, path, line, col,
                        "server '" + name + "' env passthrough key is wildcard '" + ek + "'",
                        short(ek),
                    ))
                    break
    return findings


_TMP_PREFIXES_UNIX = ("/tmp/", "/var/tmp/", "/dev/shm/")
_TMP_PREFIXES_WIN = (
    "%temp%\\", "%tmp%\\", "%temp%/", "%tmp%/",
    "c:\\windows\\temp\\", "c:\\temp\\", "c:/windows/temp/", "c:/temp/",
)
_TMP_PREFIXES_HOME = ("~/downloads/", "~/desktop/", "$tmpdir/")


def _looks_like_writable_temp(cmd: str) -> Tuple[bool, str]:
    if not isinstance(cmd, str) or not cmd:
        return False, ""
    lower = cmd.lower()
    for p in _TMP_PREFIXES_UNIX:
        if lower.startswith(p):
            return True, p.rstrip("/")
    for p in _TMP_PREFIXES_WIN:
        if lower.startswith(p):
            return True, p.rstrip("\\/")
    for p in _TMP_PREFIXES_HOME:
        if lower.startswith(p):
            return True, p.rstrip("/")
    return False, ""


def _rule_009_temp_dir_command(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        cmd = cfg.get("command")
        if not isinstance(cmd, str):
            continue
        ok, prefix = _looks_like_writable_temp(cmd)
        if ok:
            line, col = find_key_line_col(text, "command")
            if line == 1 and col == 1:
                line, col = find_key_line_col(text, name)
            findings.append(_emit(
                _RULE_009, path, line, col,
                "server '" + name + "' command executes from world-writable temp location '" + prefix + "'; "
                "any local process can replace the binary before it runs",
                short(cmd),
            ))
    return findings


def _rule_010_bare_binary_name(parsed, text, path):
    findings = []
    for name, cfg in _iter_servers(parsed):
        cmd = cfg.get("command")
        if not isinstance(cmd, str) or not cmd:
            continue
        s = cmd.strip()
        if not s:
            continue
        if "/" in s or "\\" in s:
            continue
        if s.startswith("."):
            continue
        # Ignore leading environment-variable references like $VAR or ${VAR}
        if s.startswith("$") or s.startswith("%"):
            continue
        line, col = find_key_line_col(text, "command")
        if line == 1 and col == 1:
            line, col = find_key_line_col(text, name)
        findings.append(_emit(
            _RULE_010, path, line, col,
            "server '" + name + "' command '" + s + "' is a bare binary name; "
            "PATH lookup can be hijacked - prefer an absolute path",
            short(cmd),
        ))
    return findings


_RULE_001 = Rule("MSC-001", Severity.HIGH,
                 "server command is an interpreter run with an inline-eval flag", _rule_001_shell_eval)
_RULE_002 = Rule("MSC-002", Severity.HIGH,
                 "server transport is plaintext (http:// or ws://)", _rule_002_plaintext_transport)
_RULE_003 = Rule("MSC-003", Severity.HIGH,
                 "env value contains an inline bearer/API-key literal", _rule_003_inline_bearer)
_RULE_004 = Rule("MSC-004", Severity.HIGH,
                 "command line has remote-fetch-and-execute pattern", _rule_004_remote_fetch_exec)
_RULE_005 = Rule("MSC-005", Severity.HIGH,
                 "server has neither 'command' nor 'url'", _rule_005_structurally_incomplete)
_RULE_006 = Rule("MSC-006", Severity.MEDIUM,
                 "server args contain an unpinned package reference", _rule_006_unpinned_package)
_RULE_007 = Rule("MSC-007", Severity.MEDIUM,
                 "credential-shaped env key has an inline value", _rule_007_cred_env_key)
_RULE_008 = Rule("MSC-008", Severity.MEDIUM,
                 "wildcard in permissions / allowedTools / env passthrough", _rule_008_wildcard_permission)
_RULE_009 = Rule("MSC-009", Severity.MEDIUM,
                 "command executes from a world-writable temp directory", _rule_009_temp_dir_command)
_RULE_010 = Rule("MSC-010", Severity.INFO,
                 "server command is a bare binary name (PATH-hijack advisory)", _rule_010_bare_binary_name)


ALL_RULES: Sequence[Rule] = (
    _RULE_001, _RULE_002, _RULE_003, _RULE_004, _RULE_005,
    _RULE_006, _RULE_007, _RULE_008, _RULE_009, _RULE_010,
)


def run_rules(parsed, text, path, disabled=frozenset()):
    """Run every enabled rule and return the flat list of findings."""
    out: List[Finding] = []
    if parsed is None:
        return out
    for rule in ALL_RULES:
        if rule.id in disabled:
            continue
        out.extend(rule.check_fn(parsed, text, path))
    return out
