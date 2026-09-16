# delegcheck

Offline static linter for **agent-delegation configuration files** -- the
JSON / JSONL descriptors that a modern agent harness reads to decide who can
call which tool, with which credential, on whose behalf, and with which
trust boundary. Zero-dep Python stdlib. MIT licensed.

## Why

Agent harnesses increasingly delegate authority across principals -- from
orchestrator to worker, worker to sub-agent, agent to remote tool server.
When the **delegation configuration itself** is shape-defective, the runtime
authorization layer inherits a structural weakness that cannot be recovered
at request time.

Three arXiv papers this week (2026-08-31 to 2026-09-01) converge on the same
observation from independent angles:

- arXiv 2609.00267 ("Delegation Without Trust: An Empirical Gap Analysis of
  Identity, Authorization, and Runtime Governance in Multi-Agent LLM
  Systems", 2026-08-31) enumerates four failure modes: confused-deputy over
  delegated credentials, token theft and replay, prompt-injection privilege
  escalation, and compromised sub-agents; and reports that "a default agent
  runtime modeling common practice (broad bearer credentials, authorization
  gated inside the model) fails all four threats" across the multi-agent
  frameworks it surveys.
- arXiv 2609.00595 ("SoK: When Safe Agents Fail Together: The Security of
  Multi Agent LLM Systems", 2026-09-01) systematises 197 works and observes
  that "safe agents can fail together" when information, state, decisions,
  and authority cross principal boundaries without an execution-level view.
- arXiv 2609.01222 ("What's in Your Agent's Context? Context Privilege
  Escalation Attacks against AI Agent Harness", 2026-09-01) analyses 12
  real-world harnesses and names two attack categories -- MessageRole-CPE
  and Cross-Scope-CPE -- both traceable to configuration-level weaknesses
  in how credentials and roles are declared.

The runtime authorization layer cannot compensate for a config whose
credentials have no scope, whose tools have no principal, whose delegation
edges have no depth cap, and whose authorization mode is "the model
decides." `delegcheck` is the small offline pre-flight primitive that
scans that configuration **before** the harness loads it.

## What it detects

Ten pattern-shape rules across three severities:

| ID       | Severity | Shape |
|---       |---       |---    |
| DEL-001  | HIGH     | Bearer credential declared with unbounded scope (`*` / `all` / missing / empty). |
| DEL-002  | HIGH     | Delegated tool has no principal identity field (`principal` / `owner` / `identity` / `sub`). |
| DEL-003  | HIGH     | Authorization gated inside the model (`mode: llm` / `mode: model` / `gate: agent-decides` / `mode: in-context`). |
| DEL-004  | HIGH     | Delegation reuses parent credential verbatim without a scope-narrowing field (confused-deputy shape). |
| DEL-005  | HIGH     | Delegation edge has no depth cap (`max_depth` / `hop_limit` / `depth_limit`). |
| DEL-006  | MEDIUM   | Tool exposed to a wildcard caller (`permitted_agents: "*"` / `callers: "all"`). |
| DEL-007  | MEDIUM   | Bearer credential has no expiry / TTL field (`expires_at` / `ttl_seconds` / `not_after`). |
| DEL-008  | MEDIUM   | Internal trust boundary claimed on a delegation that crosses distinct principals. |
| DEL-009  | MEDIUM   | Delegation graph contains a cycle. |
| DEL-010  | INFO     | Bearer literal present verbatim in the config file (delegation configs should reference secrets by name). |

Findings roll up into a single **verdict**:

- Any HIGH -> `unhealthy` (exit 2)
- Any MEDIUM (no HIGH) -> `needs-attention` (exit 1)
- INFO only + files scanned -> `healthy` (default) or `needs-attention` (`--strict`)
- No findings + files scanned -> `healthy` (exit 0)
- No files scanned -> `unknown` (exit 1 default, exit 2 `--strict`)
- Path does not exist -> stderr + exit 2

## Install

```bash
python -m pip install -e .
```

Or run directly without installing:

```bash
python -m delegcheck /path/to/scan
```

Requires Python 3.9+. No dependencies.

## Use

```bash
delegcheck                            # scan cwd, text output
delegcheck path/to/dir                # scan a directory
delegcheck path/to/one_file.json      # scan a single file
delegcheck --json path                # machine-readable JSON
delegcheck --strict path              # INFO -> needs-attention; no-files -> exit 2
delegcheck --include-info path        # surface INFO findings in text output
delegcheck --disable DEL-001 path     # disable one rule (repeatable)
delegcheck --glob "*.mcp" path        # extend default file-glob set (repeatable)
delegcheck --list-rules               # print the rule registry
delegcheck --version
```

Default file globs: `*.json`, `*.jsonl`.

### Config shapes recognised

`delegcheck` reads any JSON or JSONL file that contains a subset of these
top-level keys:

- `credentials`: list of `{name, type, value_ref | value, scope, expires_at, ...}`
- `tools`: list of `{name, principal | owner | identity | sub, permitted_agents | callers, ...}`
- `delegations`: list of `{from, to, credential_ref, narrowed_scope, max_depth, trust_boundary, ...}`
- `authorization`: `{mode | policy | gate, ...}`

The shape is a small opinionated schema that captures how MCP-style server
descriptors, LangGraph agent manifests, CrewAI role declarations, and
similar tool-registry JSONs commonly express delegation. Files that do not
contain any of these keys produce zero findings (nothing to score).

### Text output shape

```
verdict: unhealthy
files_scanned=1 findings_total=3 high=2 medium=1 info=0
findings_visible=3 findings_hidden=0
  HIGH DEL-001 config.json:8:7 bearer credential 'root_token' has unbounded scope '*'
  HIGH DEL-003 config.json:33:3 authorization gated inside the model (mode='llm')
  MEDIUM DEL-006 config.json:14:7 tool 'shell_exec' has wildcard entry in permitted_agents
```

### JSON output shape

Deterministic (sorted keys, fixed indent). Findings are sorted by
`(severity, path, line, column, rule_id)`.

## Where it fits

`delegcheck` sits at the **agent-delegation configuration hygiene** layer of
a broader family of small offline linters:

- File-content hygiene: `envcheck`, `jsonlcheck`, `jwtcheck`
- Eval-stream hygiene: `jsonldiff`, `jsonlsample`
- Install-manifest hygiene: `reqcheck`
- License-chain hygiene: `licensechain`
- Contribution-policy hygiene: `aicontribcheck`
- Agent-skill safety hygiene: `skillcheck`
- Agent-instruction maintainability hygiene: `agentmdlint`
- Test-oracle-shape hygiene: `oraclecheck`
- Agent-consumed content hygiene: `elevatescan`
- **Agent-delegation configuration hygiene** (this tool)

`elevatescan` (last cycle) detects escalation *shapes* in the content an
agent will ingest. `delegcheck` detects escalation *susceptibility* in the
delegation configuration itself: the orthogonal question, on the orthogonal
surface, before the same runtime.

## Honest scope and limits

- **Structural, not behavioural.** Every rule reads the declared shape of
  the config. It does not run the harness, does not exchange tokens, does
  not verify a token's actual scope with a real authorization server, does
  not measure whether an authorization mode is *actually* enforced
  externally. It reads what the config says and flags what it doesn't say.
- **JSON / JSONL only.** YAML, TOML, HCL, and other config formats are out
  of scope for v0.1. Convert to JSON first, or extend the glob with `--glob`
  and drop in JSON-equivalent files. JSONL is scanned per-line, one config
  per line.
- **English-key schema.** Rules match the field names above (`credentials`,
  `tools`, `delegations`, `authorization`, `principal`, `owner`, `identity`,
  `scope`, `expires_at`, `max_depth`, `trust_boundary`, etc.). Configs that
  use different key names for the same concepts will produce false
  negatives.
- **False positives expected** on legitimate configs that intentionally use
  a wildcard (e.g., a public-read tool with `permitted_agents: ["*"]`), on
  intentional delegation cycles (rare but real), or on configs that rely on
  external policy for scope narrowing without an explicit narrow-scope
  field. Use `--disable RULE_ID` per repo when the shape is intentional.
- **False negatives expected** on novel or obfuscated shapes: nested
  delegation structures beyond the top-level `delegations` key, scope
  represented as an object rather than a string or list, credentials
  referenced by inline anonymous objects. This is a pre-flight primitive,
  not an adversarial classifier.
- **Per-file byte cap** (default 1 MiB) and **per-run file cap** (default
  1000) are hard bounds; content beyond either is silently ignored. Adjust
  with `--max-bytes` and `--max-files`.
- **Not a general secret detector.** DEL-010 is a shape flag for a bearer
  literal *in the config file*; it is not a substitute for `envcheck`,
  `jwtcheck`, or a full secret-scanning tool.

## Clean-room note

This is an **independent implementation**. Rule design was motivated by the
framings in arXiv 2609.00267 (four failure modes across delegated identity
and authorization), arXiv 2609.00595 (systematisation of compositional
multi-agent failures), and arXiv 2609.01222 (context privilege escalation
categories). The authors' reference code, empirical datasets, subject
harnesses, and per-paper measurement code were **not** consulted. This
project is not affiliated with or endorsed by any of the cited authors,
their institutions, or any AI vendor or product.

## License

MIT. See LICENSE.

---

*Produced by a human-machine hybrid intelligence, under maker-checker.*
