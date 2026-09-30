"""Rule registry for approvchainlint.

Each rule is a small function `check(doc, text, path, options) -> list[Finding]`.
Rules do not raise; they return an empty list when they do not fire and
they never look at anything outside doc / text / path / options.

The rule set targets approval-chain shapes across three families of
agent-tool configuration file:

  1. Coding-agent settings files (e.g. `settings.json` under an agent
     config directory) that declare a `permissions` block with
     allow / deny / ask scopes.
  2. MCP-style `mcp.json` with an `mcpServers` block declaring
     command / args / env / tools per server.
  3. Generic agent-tool descriptors with a top-level `tools` (or
     `approvals`) list.

The 12 rules are on a 5 HIGH / 4 MEDIUM / 3 INFO split; INFO rules are
hidden by default and shown only under --include-info / --strict.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .parse import (
    find_key,
    get_list,
    get_object,
    is_object,
    offset_to_line_col,
    truncate_snippet,
)
from .types import Finding, Options, Severity


# ---------- Shape helpers ----------


def _permissions(doc: Any) -> Dict[str, Any]:
    return get_object(doc, "permissions")


def _permissions_list(doc: Any, key: str) -> List[Any]:
    perm = _permissions(doc)
    v = perm.get(key)
    return v if isinstance(v, list) else []


def _tools(doc: Any) -> List[Dict[str, Any]]:
    """Return the list of tool descriptors from either a top-level
    `tools` list or the merged view of `mcpServers.<name>.tools`.
    Non-dict entries are skipped.
    """
    out: List[Dict[str, Any]] = []
    top = doc.get("tools") if is_object(doc) else None
    if isinstance(top, list):
        for t in top:
            if isinstance(t, dict):
                out.append(t)
    mcp = get_object(doc, "mcpServers")
    for _srv_name, srv in mcp.items():
        if not isinstance(srv, dict):
            continue
        tools = srv.get("tools")
        if isinstance(tools, list):
            for t in tools:
                if isinstance(t, dict):
                    out.append(t)
    return out


def _mcp_servers(doc: Any) -> List[Tuple[str, Dict[str, Any]]]:
    mcp = get_object(doc, "mcpServers")
    out: List[Tuple[str, Dict[str, Any]]] = []
    for name, srv in mcp.items():
        if isinstance(srv, dict):
            out.append((name, srv))
    return out


def _approvals(doc: Any) -> List[Dict[str, Any]]:
    v = doc.get("approvals") if is_object(doc) else None
    if not isinstance(v, list):
        return []
    return [e for e in v if isinstance(e, dict)]


def _list_of_str(doc: Any, key: str) -> List[str]:
    v = doc.get(key) if is_object(doc) else None
    if not isinstance(v, list):
        return []
    return [x for x in v if isinstance(x, str)]


def _tool_prop_path(tool: Dict[str, Any], suffix: str = "") -> str:
    name = tool.get("name") or tool.get("id") or "?"
    if suffix:
        return f"tools.{name}.{suffix}"
    return f"tools.{name}"


def _line_col_for_key(text: str, key: str) -> Tuple[int, int]:
    off = find_key(text, key)
    return offset_to_line_col(text, off if off >= 0 else 0)


# ---------- Regex constants ----------

# Subprocess / shell / eval tool tokens paired with a wildcard argument.
_WILDCARD_SUBPROCESS_PATTERNS = [
    re.compile(r"^(Bash|Shell|Exec|Sh|Zsh|Powershell|PowerShell|Pwsh|Cmd|Terminal|Run|Execute)\s*\(\s*(\*|\*\*|\.\*)\s*\)\s*$"),
    re.compile(r"^(Python|Node|Ruby|Perl)\s*\(\s*-c\s+.*\*.*\)\s*$"),
    re.compile(r"^(Bash|Shell)\(\*\)$"),
]

# High-effect capability tokens per the paper (subprocess, shell, exec,
# network, filesystem write, eval).
_HIGH_EFFECT_CAPS = {
    "subprocess", "shell", "exec", "eval", "run", "execute",
    "filesystem_write", "write", "fs_write", "filesystem-write",
    "network", "net", "http", "fetch",
}

_SUBPROCESS_CAPS = {"subprocess", "shell", "exec", "eval", "run", "execute"}
_WRITE_CAPS = {"filesystem_write", "write", "fs_write", "filesystem-write"}
_NETWORK_CAPS = {"network", "net", "http", "fetch"}

_NETWORK_TYPE_TOKENS = {"http", "fetch", "network"}

_STICKY_FLAGS = (
    "sticky", "auto_approve", "remember", "permanent",
    "remember_approval", "always_allow",
)

_CHILD_TOOL_FIELDS = (
    "delegates_to", "child_tools", "subagents", "spawns",
    "invokes_tools", "sub_agents", "dispatches_to",
)

_CHILD_APPROVAL_BINDING_FIELDS = (
    "require_child_approval",
    "record_transitive_effects",
    "bind_child_approvals",
)

_ALLOWLIST_HOST_FIELDS = (
    "allowlist_hosts", "allow_hosts", "hosts_allowlist",
    "allowed_urls", "host_allowlist",
)

_READ_ONLY_MARKERS = ("read_only", "readonly")

_INSTALL_HOOK_FIELDS = (
    "on_load", "on_activate", "preinstall", "postinstall",
    "setup_hook", "startup_command", "boot_command", "init_command",
)

_AUDIT_FIELDS = (
    "audit_log", "trace", "record_effects", "log_transitive",
)

_PAPER_EFFECT_CLASSES = (
    "subprocess", "shell", "exec", "eval",
    "filesystem_write", "write", "fs_write", "filesystem-write",
    "filesystem_read", "filesystem-read", "fs_read", "read",
    "network", "net", "http", "fetch",
    "persistent_state", "persistent-state", "state",
    "external_hook", "external-hook", "hook",
    "package_hook", "package-hook",
)

_STARTUP_APPROVAL_FIELDS = (
    "startup_approvals", "pre_approved_tools",
    "initial_permissions", "defaultAllow",
)

_APPROVAL_SHAPE_FIELDS = (
    "approval", "approvals", "auto_approve", "sticky",
    "ttl_seconds", "ttl", "expires_at", "scope", "capabilities",
    "require_approval",
)

_NETWORK_COMMAND_TOKENS = (
    "curl", "wget", "http",
)

_NETWORK_COMMAND_PY_NODE = (
    "python -m urllib",
    "pip install",
    "npm install",
    "npx",
)

_BARE_TOOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _tool_capabilities(tool: Dict[str, Any]) -> set:
    caps = set()
    v = tool.get("capabilities")
    if isinstance(v, list):
        for c in v:
            if isinstance(c, str):
                caps.add(c.lower())
    v = tool.get("effects")
    if isinstance(v, list):
        for c in v:
            if isinstance(c, str):
                caps.add(c.lower())
    t = tool.get("type")
    if isinstance(t, str):
        caps.add(t.lower())
    if tool.get("network") is True:
        caps.add("network")
    return caps


def _tool_declares_child(tool: Dict[str, Any]) -> bool:
    for f in _CHILD_TOOL_FIELDS:
        v = tool.get(f)
        if isinstance(v, list) and v:
            return True
    return False


def _tool_binds_child_approval(tool: Dict[str, Any]) -> bool:
    for f in _CHILD_APPROVAL_BINDING_FIELDS:
        if tool.get(f) is True:
            return True
    return False


def _tool_has_allowlist(tool: Dict[str, Any]) -> bool:
    for f in _ALLOWLIST_HOST_FIELDS:
        v = tool.get(f)
        if isinstance(v, list) and v:
            return True
    return False


def _tool_has_audit(tool: Dict[str, Any]) -> bool:
    for f in _AUDIT_FIELDS:
        if tool.get(f) is True:
            return True
    return False


def _tool_has_approval_shape(tool: Dict[str, Any]) -> bool:
    for f in _APPROVAL_SHAPE_FIELDS:
        if f in tool:
            return True
    return False


def _tool_declares_effect_class(tool: Dict[str, Any]) -> bool:
    for field in ("effects", "capabilities"):
        v = tool.get(field)
        if isinstance(v, list):
            for c in v:
                if isinstance(c, str) and c.lower() in _PAPER_EFFECT_CLASSES:
                    return True
    return False


def _iter_permission_scopes(doc: Any) -> List[Tuple[str, str]]:
    """Yield (scope_string, prop_path) from `permissions.allow`,
    `permissions.ask`, and every entry's `scope` string in `approvals[]`.
    """
    out: List[Tuple[str, str]] = []
    for section in ("allow", "ask"):
        for i, s in enumerate(_permissions_list(doc, section)):
            if isinstance(s, str):
                out.append((s, f"permissions.{section}[{i}]"))
    for i, entry in enumerate(_approvals(doc)):
        s = entry.get("scope")
        if isinstance(s, str):
            out.append((s, f"approvals[{i}].scope"))
    return out


# ---------- Individual rules ----------


def rule_ac_001_wildcard_subprocess(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for scope, prop in _iter_permission_scopes(doc):
        if any(p.match(scope) for p in _WILDCARD_SUBPROCESS_PATTERNS):
            line, col = _line_col_for_key(text, "permissions") if prop.startswith("permissions.") \
                else _line_col_for_key(text, "approvals")
            findings.append(Finding(
                rule_id="AC-001",
                severity=Severity.HIGH,
                path=path,
                prop=prop,
                line=line, column=col,
                message=(
                    f"scope {scope!r} pre-approves a subprocess/shell/eval "
                    "tool with a wildcard argument; the approval record "
                    "binds every call the wildcard matches"
                ),
                snippet=truncate_snippet(scope),
            ))
    # defaultMode override also fires this rule.
    perm = _permissions(doc)
    mode = perm.get("defaultMode")
    if isinstance(mode, str) and mode in ("acceptEdits", "bypassPermissions", "auto"):
        line, col = _line_col_for_key(text, "defaultMode")
        findings.append(Finding(
            rule_id="AC-001",
            severity=Severity.HIGH,
            path=path,
            prop="permissions.defaultMode",
            line=line, column=col,
            message=(
                f"permissions.defaultMode is {mode!r}; every tool invocation "
                "runs without an interactive gate"
            ),
            snippet=truncate_snippet(mode),
        ))
    return findings


def _entry_has_sticky(entry: Dict[str, Any]) -> Optional[str]:
    for f in _STICKY_FLAGS:
        if entry.get(f) is True:
            return f
    return None


def _entry_ttl(entry: Dict[str, Any]) -> Optional[int]:
    v = entry.get("ttl_seconds")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return int(v)
    return None


def _entry_has_ttl_declared(entry: Dict[str, Any]) -> bool:
    for f in ("ttl_seconds", "ttl", "expires_at"):
        if f in entry:
            return True
    return False


def _entry_touches_high_effect(entry: Dict[str, Any], doc: Any) -> bool:
    caps = entry.get("capabilities")
    if isinstance(caps, list):
        for c in caps:
            if isinstance(c, str) and c.lower() in _HIGH_EFFECT_CAPS:
                return True
    scope = entry.get("scope")
    if isinstance(scope, str):
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9_]*)", scope)
        if m and m.group(1).lower() in {"bash", "shell", "exec", "sh", "run",
                                        "execute", "http", "fetch", "network",
                                        "write", "edit"}:
            return True
    # Look at the tool declaration referenced by name.
    tool_name = entry.get("tool")
    if isinstance(tool_name, str):
        for t in _tools(doc):
            if t.get("name") == tool_name:
                caps = _tool_capabilities(t)
                if caps & _HIGH_EFFECT_CAPS:
                    return True
    return False


def rule_ac_002_sticky_no_ttl(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    approvals = _approvals(doc)
    line, col = _line_col_for_key(text, "approvals")
    for i, entry in enumerate(approvals):
        prop = f"approvals[{i}]"
        sticky_flag = _entry_has_sticky(entry)
        ttl = _entry_ttl(entry)
        has_ttl = _entry_has_ttl_declared(entry)
        touches_high = _entry_touches_high_effect(entry, doc)
        reason = None
        if sticky_flag is not None:
            reason = f"the entry sets {sticky_flag}=true"
        elif ttl is not None and ttl >= 3600:
            reason = f"ttl_seconds={ttl} (>= 3600)"
        elif not has_ttl and touches_high:
            reason = "no ttl_seconds/ttl/expires_at on a HIGH-effect entry"
        if reason:
            findings.append(Finding(
                rule_id="AC-002",
                severity=Severity.HIGH,
                path=path,
                prop=prop,
                line=line, column=col,
                message=(
                    f"approval entry launders future invocations: {reason}; "
                    "the durable record no longer names each tool call"
                ),
                snippet=truncate_snippet(str(entry)),
            ))
    return findings


def _extract_tool_and_args(scope: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse `Tool(args)` -> (tool, args). Returns (None, None) if not
    in that shape. args may be empty."""
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*\((.*)\)\s*$", scope)
    if not m:
        return (None, None)
    return (m.group(1), m.group(2))


def rule_ac_003_scope_broader_than_surface(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    tools_list = _tools(doc)
    # Build a name -> tool lookup.
    by_name: Dict[str, Dict[str, Any]] = {}
    for t in tools_list:
        n = t.get("name")
        if isinstance(n, str):
            by_name[n] = t
    line, col = _line_col_for_key(text, "permissions")
    for scope, prop in _iter_permission_scopes(doc):
        tname, args = _extract_tool_and_args(scope)
        if tname is None or tname not in by_name:
            continue
        tool = by_name[tname]
        # Is scope wildcard-shaped?
        wild = args is None or args.strip() in ("*", "**", "", ".*")
        cmd = tool.get("command")
        p = tool.get("path")
        fixed_command = isinstance(cmd, str) and not any(x in cmd for x in ("*", "?"))
        fixed_path = isinstance(p, str) and not any(x in p for x in ("*", "?"))
        if wild and (fixed_command or fixed_path):
            findings.append(Finding(
                rule_id="AC-003",
                severity=Severity.HIGH,
                path=path,
                prop=prop,
                line=line, column=col,
                message=(
                    f"approval scope {scope!r} for tool {tname!r} is wider "
                    f"than the tool's declared surface (command={cmd!r} "
                    f"path={p!r})"
                ),
                snippet=truncate_snippet(scope),
            ))
            continue
        # Wildcard host case
        hosts = tool.get("network_hosts")
        if isinstance(hosts, list) and hosts and isinstance(args, str):
            if "*" in args or ".*" in args:
                findings.append(Finding(
                    rule_id="AC-003",
                    severity=Severity.HIGH,
                    path=path,
                    prop=prop,
                    line=line, column=col,
                    message=(
                        f"approval scope {scope!r} for tool {tname!r} uses "
                        f"a wildcard host, but the tool declares specific "
                        f"network_hosts={hosts!r}"
                    ),
                    snippet=truncate_snippet(scope),
                ))
    return findings


def rule_ac_004_delegator_no_child_binding(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for t in _tools(doc):
        if not _tool_declares_child(t):
            continue
        if _tool_binds_child_approval(t):
            continue
        # Which child field(s) are declared, for the message?
        declared = [f for f in _CHILD_TOOL_FIELDS if isinstance(t.get(f), list) and t.get(f)]
        line, col = _line_col_for_key(text, declared[0]) if declared else (1, 1)
        findings.append(Finding(
            rule_id="AC-004",
            severity=Severity.HIGH,
            path=path,
            prop=_tool_prop_path(t, declared[0] if declared else "delegates_to"),
            line=line, column=col,
            message=(
                f"tool {t.get('name')!r} declares {declared} but no "
                "require_child_approval / record_transitive_effects / "
                "bind_child_approvals; the approval record names the "
                "delegator only"
            ),
            snippet=truncate_snippet(str(declared)),
        ))
    return findings


def _tool_declares_network(tool: Dict[str, Any]) -> bool:
    if tool.get("network") is True:
        return True
    caps = _tool_capabilities(tool)
    return bool(caps & _NETWORK_CAPS)


def _mcp_server_declares_network(srv: Dict[str, Any]) -> bool:
    cmd = srv.get("command")
    if not isinstance(cmd, str):
        return False
    lower = cmd.lower()
    for tok in _NETWORK_COMMAND_TOKENS:
        if tok in lower:
            return True
    args = srv.get("args")
    joined = cmd
    if isinstance(args, list):
        joined = cmd + " " + " ".join(a for a in args if isinstance(a, str))
    for tok in _NETWORK_COMMAND_PY_NODE:
        if tok in joined:
            return True
    return False


def rule_ac_005_network_no_allowlist(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for t in _tools(doc):
        if not _tool_declares_network(t):
            continue
        # Skip: read-only HTTP-only fetcher.
        caps = _tool_capabilities(t)
        if (any(t.get(m) is True for m in _READ_ONLY_MARKERS)
                and caps == {"http"}):
            continue
        if _tool_has_allowlist(t):
            continue
        line, col = _line_col_for_key(text, "capabilities")
        findings.append(Finding(
            rule_id="AC-005",
            severity=Severity.HIGH,
            path=path,
            prop=_tool_prop_path(t, "capabilities"),
            line=line, column=col,
            message=(
                f"tool {t.get('name')!r} declares network capability but "
                "no allowlist_hosts / allow_hosts / hosts_allowlist / "
                "allowed_urls / host_allowlist"
            ),
            snippet=truncate_snippet(str(sorted(caps))),
        ))
    # MCP servers with network-shaped commands and no allowlist on any
    # of their tools.
    for name, srv in _mcp_servers(doc):
        if not _mcp_server_declares_network(srv):
            continue
        tools = srv.get("tools")
        if isinstance(tools, list) and any(
            isinstance(tt, dict) and _tool_has_allowlist(tt) for tt in tools
        ):
            continue
        line, col = _line_col_for_key(text, name)
        findings.append(Finding(
            rule_id="AC-005",
            severity=Severity.HIGH,
            path=path,
            prop=f"mcpServers.{name}.command",
            line=line, column=col,
            message=(
                f"mcp server {name!r} runs a network-shaped command "
                f"({srv.get('command')!r}) with no host allowlist"
            ),
            snippet=truncate_snippet(str(srv.get("command", ""))),
        ))
    return findings


def rule_ac_006_bare_tool_name(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for scope, prop in _iter_permission_scopes(doc):
        if _BARE_TOOL_NAME.match(scope):
            line, col = _line_col_for_key(text, "permissions") if prop.startswith("permissions.") \
                else _line_col_for_key(text, "approvals")
            findings.append(Finding(
                rule_id="AC-006",
                severity=Severity.MEDIUM,
                path=path,
                prop=prop,
                line=line, column=col,
                message=(
                    f"approval entry {scope!r} is a bare tool name with no "
                    "argument scope; every invocation of the tool inherits "
                    "the approval regardless of arguments"
                ),
                snippet=truncate_snippet(scope),
            ))
    return findings


_READ_ONLY_TYPES = {"read", "readonly", "read_only"}
_WRITE_ISH_CAPS = _SUBPROCESS_CAPS | _WRITE_CAPS | _NETWORK_CAPS


def rule_ac_007_mislabeled_read_only(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for t in _tools(doc):
        is_read = any(t.get(m) is True for m in _READ_ONLY_MARKERS)
        mode = t.get("mode")
        if isinstance(mode, str) and mode.lower() in _READ_ONLY_TYPES:
            is_read = True
        ttype = t.get("type")
        if isinstance(ttype, str) and ttype.lower() == "read":
            is_read = True
        if not is_read:
            continue
        caps = _tool_capabilities(t)
        overlap = caps & _WRITE_ISH_CAPS
        if overlap:
            line, col = _line_col_for_key(text, "capabilities")
            findings.append(Finding(
                rule_id="AC-007",
                severity=Severity.MEDIUM,
                path=path,
                prop=_tool_prop_path(t, "capabilities"),
                line=line, column=col,
                message=(
                    f"tool {t.get('name')!r} is labeled read-only but "
                    f"declares write/exec/network capabilities: "
                    f"{sorted(overlap)}"
                ),
                snippet=truncate_snippet(str(sorted(caps))),
            ))
    return findings


def rule_ac_008_duplicate_divergent(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    # approvals[] duplicates by tool name
    seen_tools: Dict[str, Dict[str, Any]] = {}
    approvals = _approvals(doc)
    line, col = _line_col_for_key(text, "approvals")
    for i, entry in enumerate(approvals):
        tname = entry.get("tool")
        if not isinstance(tname, str):
            continue
        if tname in seen_tools:
            prior = seen_tools[tname]
            fields = ("ttl_seconds", "sticky", "require_approval")
            diverged = [
                f for f in fields if prior.get(f) != entry.get(f)
            ]
            if diverged:
                findings.append(Finding(
                    rule_id="AC-008",
                    severity=Severity.MEDIUM,
                    path=path,
                    prop=f"approvals[{i}]",
                    line=line, column=col,
                    message=(
                        f"approvals[{i}] duplicates tool {tname!r} with "
                        f"divergent policy on: {diverged}"
                    ),
                    snippet=truncate_snippet(str(entry)),
                ))
        else:
            seen_tools[tname] = entry
    # permissions.allow duplicates
    allow = _permissions_list(doc, "allow")
    seen_scopes = set()
    perm_line, perm_col = _line_col_for_key(text, "allow")
    for i, s in enumerate(allow):
        if not isinstance(s, str):
            continue
        if s in seen_scopes:
            findings.append(Finding(
                rule_id="AC-008",
                severity=Severity.MEDIUM,
                path=path,
                prop=f"permissions.allow[{i}]",
                line=perm_line, column=perm_col,
                message=(
                    f"permissions.allow[{i}] duplicates scope {s!r}; "
                    "duplicate approvals with the same key are a "
                    "policy-conflict indicator"
                ),
                snippet=truncate_snippet(s),
            ))
        else:
            seen_scopes.add(s)
    return findings


def _hook_gated_elsewhere(hook_name: str, doc: Any) -> bool:
    for e in _approvals(doc):
        if e.get("tool") == hook_name:
            return True
        s = e.get("scope")
        if isinstance(s, str) and hook_name in s:
            return True
    for s in _permissions_list(doc, "allow"):
        if isinstance(s, str) and hook_name in s:
            return True
    return False


def rule_ac_009_install_hook(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for t in _tools(doc):
        hits: List[str] = []
        for f in _INSTALL_HOOK_FIELDS:
            v = t.get(f)
            if isinstance(v, str) and v.strip():
                hits.append(f)
            elif isinstance(v, list) and v:
                hits.append(f)
        if not hits:
            continue
        # Suppress if any hook field is separately gated
        gated = all(_hook_gated_elsewhere(h, doc) for h in hits)
        if gated:
            continue
        line, col = _line_col_for_key(text, hits[0])
        findings.append(Finding(
            rule_id="AC-009",
            severity=Severity.MEDIUM,
            path=path,
            prop=_tool_prop_path(t, hits[0]),
            line=line, column=col,
            message=(
                f"tool {t.get('name')!r} declares post-approval install "
                f"hook(s) {hits} that are not themselves gated by a "
                "separate approvals[] entry"
            ),
            snippet=truncate_snippet(str(hits)),
        ))
    return findings


def rule_ac_010_delegator_no_audit(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for t in _tools(doc):
        if not _tool_declares_child(t):
            continue
        if _tool_has_audit(t):
            continue
        line, col = _line_col_for_key(text, "delegates_to")
        findings.append(Finding(
            rule_id="AC-010",
            severity=Severity.INFO,
            path=path,
            prop=_tool_prop_path(t, "audit_log"),
            line=line, column=col,
            message=(
                f"tool {t.get('name')!r} delegates to child tools with no "
                "audit_log/trace/record_effects/log_transitive; transitive "
                "effects will not be recorded"
            ),
            snippet="",
        ))
    return findings


def rule_ac_011_missing_effect_class(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    for t in _tools(doc):
        if not _tool_has_approval_shape(t):
            continue
        if _tool_declares_effect_class(t):
            continue
        line, col = _line_col_for_key(text, t.get("name") if isinstance(t.get("name"), str) else "tools")
        findings.append(Finding(
            rule_id="AC-011",
            severity=Severity.INFO,
            path=path,
            prop=_tool_prop_path(t, "effects"),
            line=line, column=col,
            message=(
                f"tool {t.get('name')!r} has an approval-shape field but "
                "no effects/capabilities enumerating any of the six paper "
                "effect classes"
            ),
            snippet="",
        ))
    return findings


def rule_ac_012_startup_high_effect(doc: Any, text: str, path: str, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    if not is_object(doc):
        return findings
    # Build a lookup of tool name -> capability set.
    by_name: Dict[str, set] = {}
    for t in _tools(doc):
        n = t.get("name")
        if isinstance(n, str):
            by_name[n] = _tool_capabilities(t)
    for field_name in _STARTUP_APPROVAL_FIELDS:
        v = doc.get(field_name)
        if not isinstance(v, list):
            continue
        line, col = _line_col_for_key(text, field_name)
        for i, entry in enumerate(v):
            tool_name = None
            if isinstance(entry, str):
                tool_name = entry
                caps = by_name.get(tool_name, set())
                # Also detect Bash(*) / Shell(*) etc. as HIGH-effect
                # tokens even without a matching tool descriptor.
                tname_scope, _args = _extract_tool_and_args(entry)
                if tname_scope and tname_scope.lower() in {"bash", "shell", "exec"}:
                    caps = caps | _SUBPROCESS_CAPS
            elif isinstance(entry, dict):
                tool_name = entry.get("tool") or entry.get("name")
                caps = set()
                if isinstance(tool_name, str):
                    caps = by_name.get(tool_name, set())
                # Merge entry-declared capabilities.
                entry_caps = entry.get("capabilities")
                if isinstance(entry_caps, list):
                    caps = caps | {c.lower() for c in entry_caps if isinstance(c, str)}
            else:
                continue
            if caps & _HIGH_EFFECT_CAPS:
                findings.append(Finding(
                    rule_id="AC-012",
                    severity=Severity.INFO,
                    path=path,
                    prop=f"{field_name}[{i}]",
                    line=line, column=col,
                    message=(
                        f"{field_name}[{i}] pre-approves tool {tool_name!r} "
                        f"at session start with HIGH-effect capabilities "
                        f"{sorted(caps & _HIGH_EFFECT_CAPS)}"
                    ),
                    snippet=truncate_snippet(str(entry)),
                ))
    return findings


# ---------- Registry ----------


class Check:
    __slots__ = ("id", "severity", "description", "check")

    def __init__(self, rid: str, sev: Severity, desc: str, fn: Callable) -> None:
        self.id = rid
        self.severity = sev
        self.description = desc
        self.check = fn

    @property
    def fn(self):
        return self.check


REGISTRY: Tuple[Check, ...] = (
    Check("AC-001", Severity.HIGH,
          "Wildcard-scoped subprocess/shell/eval pre-approval.",
          rule_ac_001_wildcard_subprocess),
    Check("AC-002", Severity.HIGH,
          "Sticky, auto-approved, or unbounded-TTL approval entry.",
          rule_ac_002_sticky_no_ttl),
    Check("AC-003", Severity.HIGH,
          "Approval scope is broader than the tool's declared surface.",
          rule_ac_003_scope_broader_than_surface),
    Check("AC-004", Severity.HIGH,
          "Delegator tool declares child tools without a child-approval binding.",
          rule_ac_004_delegator_no_child_binding),
    Check("AC-005", Severity.HIGH,
          "Network-capable tool with no host allowlist.",
          rule_ac_005_network_no_allowlist),
    Check("AC-006", Severity.MEDIUM,
          "Approval entry is a bare tool name with no argument scope.",
          rule_ac_006_bare_tool_name),
    Check("AC-007", Severity.MEDIUM,
          "Read-only-labeled tool declares write/exec/network capabilities.",
          rule_ac_007_mislabeled_read_only),
    Check("AC-008", Severity.MEDIUM,
          "Duplicate approval keys with divergent policy fields.",
          rule_ac_008_duplicate_divergent),
    Check("AC-009", Severity.MEDIUM,
          "Post-approval install-hook capability without its own gate.",
          rule_ac_009_install_hook),
    Check("AC-010", Severity.INFO,
          "Delegator tool has no audit/trace/record-effects field.",
          rule_ac_010_delegator_no_audit),
    Check("AC-011", Severity.INFO,
          "Tool has approval-shape field but no declared effect class.",
          rule_ac_011_missing_effect_class),
    Check("AC-012", Severity.INFO,
          "Pre-approved HIGH-effect tool listed at session start.",
          rule_ac_012_startup_high_effect),
)

# Alias for the constitutional pjhookcheck-style "Rule" spelling used in
# type hints and docs; the two names refer to the same class.
Rule = Check


REGISTRY_BY_ID: Dict[str, Check] = {r.id: r for r in REGISTRY}


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
