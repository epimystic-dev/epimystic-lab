"""Rules for delegcheck.

Each rule is a structural check over a parsed agent-delegation config
(a dict from a JSON file, or a per-line dict from a JSONL file). The
rule registry is fixed; ordering here is documentation-only. Findings
are sorted deterministically by the report layer.

Rule design principle: each rule is a specific SHAPE defect from the
agent-delegation-config literature (see README for citations). A rule
never claims intent; it flags a shape that is often adversarial or
often the root cause of a failure.
"""

from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Sequence, Tuple

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


def _iter_credentials(obj) -> Iterable[Tuple[dict, int]]:
    """Yield (credential_dict, index) pairs from a config.

    Accepts:
      { "credentials": [ {...}, {...} ] }
      { "credential": {...} }
    """
    if not isinstance(obj, dict):
        return
    creds = obj.get("credentials")
    if isinstance(creds, list):
        for i, c in enumerate(creds):
            if isinstance(c, dict):
                yield c, i
    single = obj.get("credential")
    if isinstance(single, dict):
        yield single, 0


def _iter_tools(obj) -> Iterable[Tuple[dict, int]]:
    if not isinstance(obj, dict):
        return
    tools = obj.get("tools")
    if isinstance(tools, list):
        for i, t in enumerate(tools):
            if isinstance(t, dict):
                yield t, i


def _iter_delegations(obj) -> Iterable[Tuple[dict, int]]:
    if not isinstance(obj, dict):
        return
    dels = obj.get("delegations")
    if isinstance(dels, list):
        for i, d in enumerate(dels):
            if isinstance(d, dict):
                yield d, i


def _get_authorization(obj):
    if not isinstance(obj, dict):
        return None
    return obj.get("authorization")


_UNBOUNDED_SCOPES = {"*", "all", "any", "full", "unlimited", "wildcard"}
_BEARER_TYPES = {"bearer", "oauth", "oauth2", "pat", "token", "api_key", "apikey"}


def _is_bearer(cred: dict) -> bool:
    ctype = cred.get("type")
    if isinstance(ctype, str):
        return ctype.lower() in _BEARER_TYPES
    return "value" in cred or "token" in cred or "secret" in cred


def _rule_001_unbounded_scope(parsed, text, path):
    findings = []
    for cred, i in _iter_credentials(parsed):
        if not _is_bearer(cred):
            continue
        scope = cred.get("scope")
        name = cred.get("name") or cred.get("id") or "credential[" + str(i) + "]"
        line, col = find_key_line_col(text, "scope") if scope is not None else find_key_line_col(text, cred.get("name", "credentials"))
        if scope is None:
            line, col = find_key_line_col(text, cred.get("name") or "credentials")
            findings.append(_emit(
                _RULE_001, path, line, col,
                "bearer credential '" + str(name) + "' has no scope field (unbounded delegation)",
                short(cred),
            ))
            continue
        if isinstance(scope, str) and scope.strip().lower() in _UNBOUNDED_SCOPES:
            findings.append(_emit(
                _RULE_001, path, line, col,
                "bearer credential '" + str(name) + "' has unbounded scope '" + scope + "'",
                short(cred),
            ))
            continue
        if isinstance(scope, list) and any(isinstance(s, str) and s.strip().lower() in _UNBOUNDED_SCOPES for s in scope):
            findings.append(_emit(
                _RULE_001, path, line, col,
                "bearer credential '" + str(name) + "' has unbounded scope entry",
                short(cred),
            ))
            continue
        if isinstance(scope, str) and scope.strip() == "":
            findings.append(_emit(
                _RULE_001, path, line, col,
                "bearer credential '" + str(name) + "' has empty scope string",
                short(cred),
            ))
    return findings


_PRINCIPAL_KEYS = ("principal", "owner", "identity", "sub", "principal_id", "owner_id")


def _rule_002_no_principal(parsed, text, path):
    findings = []
    for tool, i in _iter_tools(parsed):
        if any(k in tool for k in _PRINCIPAL_KEYS):
            continue
        name = tool.get("name") or "tool[" + str(i) + "]"
        line, col = find_key_line_col(text, tool.get("name") or "tools")
        findings.append(_emit(
            _RULE_002, path, line, col,
            "tool '" + str(name) + "' has no principal identity field (owner / principal / identity / sub)",
            short(tool),
        ))
    return findings


_AUTH_IN_MODEL_MODES = {
    "model", "llm", "prompt", "prompt-only", "in-context",
    "agent-decides", "model-decides", "llm-decides", "self",
    "reasoning", "chain-of-thought",
}


def _rule_003_auth_in_model(parsed, text, path):
    findings = []
    auth = _get_authorization(parsed)
    if not isinstance(auth, dict):
        return findings
    mode = auth.get("mode") or auth.get("policy") or auth.get("gate")
    if isinstance(mode, str) and mode.strip().lower() in _AUTH_IN_MODEL_MODES:
        line, col = find_key_line_col(text, "authorization")
        findings.append(_emit(
            _RULE_003, path, line, col,
            "authorization gated inside the model (mode='" + mode + "'); "
            "authorization should be enforced by an external policy engine",
            short(auth),
        ))
    return findings


def _rule_004_parent_cred_reuse(parsed, text, path):
    findings = []
    if not isinstance(parsed, dict):
        return findings
    cred_index = {}
    for cred, i in _iter_credentials(parsed):
        cid = cred.get("name") or cred.get("id")
        if isinstance(cid, str):
            cred_index[cid] = cred
    for d, i in _iter_delegations(parsed):
        ref = d.get("credential_ref") or d.get("token_ref") or d.get("credential")
        if not isinstance(ref, str) or ref not in cred_index:
            continue
        narrowing_keys = ("narrowed_scope", "sub_scope", "constrained_scope",
                          "scope_downgrade", "child_scope", "restricted_scope")
        if any(k in d for k in narrowing_keys):
            continue
        line, col = find_key_line_col(text, "credential_ref")
        if line == 1 and col == 1:
            line, col = find_key_line_col(text, "delegations")
        findings.append(_emit(
            _RULE_004, path, line, col,
            "delegation reuses parent credential '" + ref + "' verbatim without a scope-narrowing field "
            "(confused-deputy shape)",
            short(d),
        ))
    return findings


_DEPTH_KEYS = ("max_depth", "hop_limit", "max_hops", "depth_limit", "delegation_depth", "max_delegation_depth")


def _rule_005_recursive_no_cap(parsed, text, path):
    findings = []
    for d, i in _iter_delegations(parsed):
        if any(k in d for k in _DEPTH_KEYS):
            continue
        line, col = find_key_line_col(text, "delegations")
        edge = str(d.get("from", "?")) + " -> " + str(d.get("to", "?"))
        findings.append(_emit(
            _RULE_005, path, line, col,
            "delegation edge " + edge + " has no depth cap (max_depth / hop_limit); "
            "sub-agents can re-delegate unbounded",
            short(d),
        ))
    return findings


_WILDCARDS = {"*", "all", "any", "everyone", "*/*"}


def _rule_006_wildcard_agent(parsed, text, path):
    findings = []
    for tool, i in _iter_tools(parsed):
        for key in ("permitted_agents", "callers", "allowed_agents", "accessible_by"):
            v = tool.get(key)
            if v is None:
                continue
            if isinstance(v, str) and v.strip().lower() in _WILDCARDS:
                line, col = find_key_line_col(text, key)
                findings.append(_emit(
                    _RULE_006, path, line, col,
                    "tool '" + str(tool.get("name", "?")) + "' has wildcard '" + v + "' for " + key,
                    short(tool),
                ))
            elif isinstance(v, list) and any(isinstance(x, str) and x.strip().lower() in _WILDCARDS for x in v):
                line, col = find_key_line_col(text, key)
                findings.append(_emit(
                    _RULE_006, path, line, col,
                    "tool '" + str(tool.get("name", "?")) + "' has wildcard entry in " + key,
                    short(tool),
                ))
    return findings


_EXPIRY_KEYS = ("expires_at", "ttl_seconds", "expiry", "not_after", "expires_in", "lifetime_seconds", "ttl", "exp")


def _rule_007_no_expiry(parsed, text, path):
    findings = []
    for cred, i in _iter_credentials(parsed):
        if not _is_bearer(cred):
            continue
        if any(k in cred for k in _EXPIRY_KEYS):
            continue
        name = cred.get("name") or cred.get("id") or "credential[" + str(i) + "]"
        line, col = find_key_line_col(text, cred.get("name") or "credentials")
        findings.append(_emit(
            _RULE_007, path, line, col,
            "bearer credential '" + str(name) + "' has no expiry / TTL field",
            short(cred),
        ))
    return findings


_INTERNAL_BOUNDARIES = {"internal", "same", "same-tenant", "in-process", "trusted", "none"}


def _rule_008_boundary_mismatch(parsed, text, path):
    findings = []
    for d, i in _iter_delegations(parsed):
        tb = d.get("trust_boundary") or d.get("boundary")
        if not isinstance(tb, str):
            continue
        if tb.strip().lower() not in _INTERNAL_BOUNDARIES:
            continue
        frm = d.get("from")
        to = d.get("to")
        if not isinstance(frm, str) or not isinstance(to, str):
            continue
        if frm == to:
            continue
        line, col = find_key_line_col(text, "trust_boundary")
        if line == 1 and col == 1:
            line, col = find_key_line_col(text, "boundary")
        findings.append(_emit(
            _RULE_008, path, line, col,
            "delegation " + frm + " -> " + to + " claims trust_boundary='" + tb + "' "
            "but crosses distinct principals",
            short(d),
        ))
    return findings


def _rule_009_cycle(parsed, text, path):
    findings = []
    edges = []
    for d, i in _iter_delegations(parsed):
        f = d.get("from")
        t = d.get("to")
        if isinstance(f, str) and isinstance(t, str):
            edges.append((f, t))
    if not edges:
        return findings
    graph = {}
    for f, t in edges:
        graph.setdefault(f, set()).add(t)
    visited = set()
    stack = set()
    cycles_reported = set()

    def dfs(node, path_stack):
        if node in stack:
            cycle_start = path_stack.index(node) if node in path_stack else 0
            cyc = tuple(path_stack[cycle_start:] + [node])
            key = tuple(sorted(cyc))
            if key not in cycles_reported:
                cycles_reported.add(key)
                arrow = " -> ".join(cyc)
                line, col = find_key_line_col(text, "delegations")
                findings.append(_emit(
                    _RULE_009, path, line, col,
                    "delegation cycle detected: " + arrow,
                    arrow,
                ))
            return
        if node in visited:
            return
        visited.add(node)
        stack.add(node)
        path_stack.append(node)
        for nxt in graph.get(node, ()):
            dfs(nxt, path_stack)
        path_stack.pop()
        stack.discard(node)

    for start in list(graph.keys()):
        dfs(start, [])
    return findings


_BEARER_MIN_LEN = 32
_BEARER_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def _looks_like_bearer_literal(s: str) -> bool:
    if not isinstance(s, str):
        return False
    if len(s) < _BEARER_MIN_LEN:
        return False
    if not all(c in _BEARER_CHARS for c in s):
        return False
    entropy = len(set(s))
    return entropy >= 12


def _rule_010_bearer_literal(parsed, text, path):
    findings = []
    for cred, i in _iter_credentials(parsed):
        if not _is_bearer(cred):
            continue
        val = cred.get("value") or cred.get("token") or cred.get("secret")
        if _looks_like_bearer_literal(val):
            line, col = find_value_line_col(text, '"' + val[:8])
            if line == 1 and col == 1:
                line, col = find_key_line_col(text, "value")
            findings.append(_emit(
                _RULE_010, path, line, col,
                "bearer literal present in config (length " + str(len(val)) + "); "
                "delegation configs should reference secrets by name, not embed them",
                short(val[:16] + "..."),
            ))
    return findings


_RULE_001 = Rule("DEL-001", Severity.HIGH,
                 "bearer credential declared with unbounded scope", _rule_001_unbounded_scope)
_RULE_002 = Rule("DEL-002", Severity.HIGH,
                 "delegated tool has no principal identity field", _rule_002_no_principal)
_RULE_003 = Rule("DEL-003", Severity.HIGH,
                 "authorization gated inside the model rather than externally", _rule_003_auth_in_model)
_RULE_004 = Rule("DEL-004", Severity.HIGH,
                 "delegation reuses parent credential without scope narrowing", _rule_004_parent_cred_reuse)
_RULE_005 = Rule("DEL-005", Severity.HIGH,
                 "delegation edge has no depth cap (hop-limit)", _rule_005_recursive_no_cap)
_RULE_006 = Rule("DEL-006", Severity.MEDIUM,
                 "tool exposed to a wildcard caller", _rule_006_wildcard_agent)
_RULE_007 = Rule("DEL-007", Severity.MEDIUM,
                 "bearer credential has no expiry / TTL field", _rule_007_no_expiry)
_RULE_008 = Rule("DEL-008", Severity.MEDIUM,
                 "internal trust boundary claimed on a cross-principal delegation", _rule_008_boundary_mismatch)
_RULE_009 = Rule("DEL-009", Severity.MEDIUM,
                 "delegation graph contains a cycle", _rule_009_cycle)
_RULE_010 = Rule("DEL-010", Severity.INFO,
                 "bearer literal present in the config file", _rule_010_bearer_literal)


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
