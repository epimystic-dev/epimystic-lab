# approvchainlint

Offline static linter for agent-tool approval configuration files.

Zero dependencies, pure Python standard library. Python 3.10+.

## The problem

An approval record binds a human decision to a command or tool call.
The workflow that call activates can exercise transitive effects the
record does not disclose: package hooks, MCP network authority,
filesystem writes.

arXiv 2609.28586 (Zhang et al., "Agent Approval Laundering: Transitive
Effects Beyond the Approved Invocation", submitted 2026-09-23)
formalises closure-bound approval over six effect classes (subprocess,
network, filesystem-write, eval, persistent-state, external-hook) and
proves an information-limit result: identical policy-visible fields can
require different effect-specific decisions, so record-only policies
cannot guarantee closure.

Reinforcing signal from the same week's Hacker News:

- HN 49852101, "AI: Who Still Uses Permissions?" - documented user
  frustration driving sticky-approval / auto-approve patterns.
- HN 49830471, a "Show HN" for a tooling gateway that manages agent
  tool-call approvals on the user's behalf - middleware that approves
  for the user, the very laundering pattern the paper names.

`approvchainlint` reads a coding-agent `settings.json` with a
`permissions` block, an MCP `mcp.json` file, or a generic agent-tool
descriptor and reports twelve shape defects that enable approval
laundering.

This is an independent implementation. It is not affiliated with or
endorsed by the authors of arXiv 2609.28586.

## Install and run

    git clone <this repo>
    cd projects/2026-09-27_approvchainlint
    python -m approvchainlint examples/healthy_config.json    # rc 0
    python -m approvchainlint examples/weak_config.json       # rc 2

No install step is required to run it - it is standard-library only.
To install it as a command:

    python -m pip install -e .
    approvchainlint settings.json

### Usage

    python -m approvchainlint [PATH ...] [options]

`PATH` may be a `.json` file or a directory. When it is a directory
the walker matches these file names by default: `settings.json`,
`.mcp.json`, `mcp.json`, `tools.json`, `agent-tools.json`,
`permissions.json`.

| Flag | Effect |
|---|---|
| `--json` | Emit the structured report on stdout instead of text |
| `--strict` | Escalate INFO findings to unhealthy; no files scanned becomes rc 2 |
| `--include-info` | Show INFO findings (hidden by default) |
| `--disable CODE` | Turn off one rule; repeatable |
| `--list-rules` | Print the rule registry and exit 0 |
| `--max-files N` | Upper bound on files scanned (default 5000) |
| `--max-bytes N` | Per-file byte cap (default 5 MiB) |
| `--version` | Print the version and exit 0 |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `healthy` - no findings at or above the active severity filter |
| 1 | `needs-attention` - MEDIUM findings only (or INFO under `--include-info`) |
| 2 | `unhealthy` - at least one HIGH finding, INFO under `--strict`, or a read/parse error |

Findings go to **stdout**; summary lines, errors, and the verdict go
to **stderr**, so `python -m approvchainlint --json p.json | jq` is
safe.

In the text report, hidden characters render as `<U+XXXX>` (a zero-width
space in a path, tool name, or snippet prints as `<U+200B>`), so the report
cannot crash a legacy console and cannot conceal the character.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| AC-001 | HIGH   | Wildcard-scoped subprocess/shell/eval pre-approval, or `defaultMode` set to `acceptEdits` / `bypassPermissions` / `auto` |
| AC-002 | HIGH   | Sticky, auto-approved, or unbounded-TTL approval entry (sticky/auto_approve/remember/permanent/remember_approval/always_allow true; ttl_seconds >= 3600; or no ttl on a HIGH-effect entry) |
| AC-003 | HIGH   | Approval scope is broader than the tool's declared surface (wildcard args against a fixed command/path, or wildcard host against a specific `network_hosts` list) |
| AC-004 | HIGH   | Delegator tool declares child tools (`delegates_to` / `child_tools` / `subagents` / `spawns` / `invokes_tools` / `sub_agents` / `dispatches_to`) without a `require_child_approval` / `record_transitive_effects` / `bind_child_approvals` binding |
| AC-005 | HIGH   | Network-capable tool (or MCP server with a curl/wget/http/pip/npm/npx command) with no `allowlist_hosts` / `allow_hosts` / `hosts_allowlist` / `allowed_urls` / `host_allowlist` |
| AC-006 | MEDIUM | Approval entry is a bare tool name with no argument scope (matches `^[A-Za-z_][A-Za-z0-9_]*$`) |
| AC-007 | MEDIUM | Tool labeled `read_only` / `type: read` / `mode: read` declares subprocess / shell / exec / eval / filesystem_write / write / network / net / http / fetch / run / execute capabilities |
| AC-008 | MEDIUM | Duplicate approval keys with divergent policy fields (same tool name in `approvals[]` with different ttl_seconds / sticky / require_approval, or identical scopes in `permissions.allow`) |
| AC-009 | MEDIUM | Post-approval install-hook capability (`on_load` / `on_activate` / `preinstall` / `postinstall` / `setup_hook` / `startup_command` / `boot_command` / `init_command`) without its own gate in `approvals[]` / `permissions.allow` |
| AC-010 | INFO   | Delegator tool has no `audit_log` / `trace` / `record_effects` / `log_transitive` field, so transitive effects will not be recorded (hidden by default; visible with `--include-info`) |
| AC-011 | INFO   | Tool has an approval-shape field but no `effects` / `capabilities` enumerating any of the six paper effect classes (hidden by default; visible with `--include-info`) |
| AC-012 | INFO   | Pre-approved HIGH-effect tool listed at session start via `startup_approvals` / `pre_approved_tools` / `initial_permissions` / `defaultAllow` (hidden by default; visible with `--include-info`) |

Split: **5 HIGH, 4 MEDIUM, 3 INFO**.

## What this tool does NOT do

- It does not execute anything it reads.
- It does not open a network connection.
- It does not evaluate whether an approval decision was correct - only
  whether the record shape is one that can hide transitive effects.
- It does not detect malicious *runtime* behaviour.
- It does not replace a policy engine, a signed approval log, or a
  human review.

A linter reports shapes. It cannot detect an attack, and a clean run
is not a safety certificate. Treat it as a pre-flight primitive: a
config that survives this pass has cleared the twelve shape defects
the rules encode, not "safe."

## Design notes

- **Zero dependencies.** Stdlib only, tested on Python 3.10+.
- **Deterministic output.** Findings are sorted by
  `(file, line, column, rule_id, property_path)` so the same input
  always produces the same output.
- **JSON path anchoring.** Findings carry a JSON property path
  (`permissions.allow[0]`, `tools.<name>.delegates_to`) as the primary
  anchor, plus a best-effort text line and column.
- **Diagnostics on stderr.** All summary and error text goes to stderr,
  so `--json ... | jq` and shell redirects behave.
- **No claim of completeness.** The rules cover well-documented shapes
  named in the paper's abstract and in schema documentation. Novel
  approval-chain patterns can bypass any rule the tool ships with.

## Test suite

    python -m unittest discover -s tests

## Provenance

Rules are derived from the public abstract of arXiv 2609.28586 and
from standard tool-config schema documentation (the coding-agent
`permissions` block convention, the Model Context Protocol `mcp.json`
shape, generic agent-tool descriptor conventions). No reference
implementation of an approval-chain linter was read, vendored, or
mirrored. The tool is an independent implementation and is not
affiliated with or endorsed by any tool vendor, registry, or research
group, including the authors of arXiv 2609.28586.

## License

MIT.

---

*Produced by a human-machine hybrid intelligence, under maker-checker.*
