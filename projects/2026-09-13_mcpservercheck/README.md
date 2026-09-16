# mcpservercheck

Offline static linter for MCP-server *registration* config files - the
client-side JSON a user pastes to install a Model Context Protocol server.
Handles the common shapes: a top-level `mcpServers` object, a top-level
`servers` object, a nested `mcp.servers` object, or a bare top-level dict
where every value declares a `command` or a `url`. File names commonly
include `.mcp.json` and `mcp.json`.

Zero dependencies, pure Python stdlib.

## What it does

`mcpservercheck` reads the registration file the client will load and flags
ten shape defects that recur in the MCP-server threat literature (see
citations below). It does not run any server, does not fetch any URL, and
does not touch the network. It is a pre-flight primitive: fast, deterministic,
CI-friendly, and disable-able per rule.

The primitive complements - but does not replace - a runtime MCP proxy, a
server-implementation static scanner (e.g. bandit/semgrep against the server
source), or a runtime prompt-injection guard. It targets the *installation
config* specifically because that is the smallest, most portable surface
where several classes of defect can be caught before the server is even
started for the first time.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| MSC-001 | HIGH | Server command is an interpreter (`sh`, `bash`, `python`, `node`, `pwsh`, `cmd`, `deno eval`, ...) run with an inline-eval flag (`-c`, `-e`, `-Command`, `/c`, `eval`). Any argument that flows into the tool call flows into an arbitrary interpreter. |
| MSC-002 | HIGH | Server transport is plaintext (`http://` or `ws://`). Tokens and tool payloads travel unencrypted. Localhost transports are also flagged; disable with `--disable MSC-002` if that is deliberate. |
| MSC-003 | HIGH | An `env` value contains an inline bearer / API-key literal (known prefix, PEM header, JWT shape, or a >=32-char high-entropy string) rather than a `${VAR}` reference. |
| MSC-004 | HIGH | The command line contains a remote-fetch-and-execute pattern: `curl` / `wget` piped into an interpreter, `bash <(curl ...)`, `iex`, `Invoke-Expression`. |
| MSC-005 | HIGH | The server entry has neither `command` nor `url`. The client cannot start or connect to it - the entry is structurally broken. |
| MSC-006 | MEDIUM | Server args reference a package by an unpinned mutable ref: `git+https://...` without `@<sha>` or pinned to `main` / `master` / `latest`, or `npm ... @latest`. |
| MSC-007 | MEDIUM | An `env` key matches a credential shape (`TOKEN`, `KEY`, `SECRET`, `PASSWORD`, ...) with a non-empty inline value that is not a variable reference. |
| MSC-008 | MEDIUM | A permissions field (`allowedTools`, `permissions`, `capabilities`, `tools`) contains a wildcard (`*`, `all`, `any`); or the `env` passthrough uses a wildcard key. |
| MSC-009 | MEDIUM | The `command` executes from a world-writable temp directory: `/tmp`, `/var/tmp`, `%TEMP%`, `%TMP%`, `~/Downloads`, `$TMPDIR`. Any local process can replace the binary before it runs. |
| MSC-010 | INFO | The `command` is a bare binary name (no `/`, `\`, or leading `.`). PATH lookup can be hijacked; prefer an absolute path. Hidden by default; use `--include-info` or `--strict`. |

Verdict rollup is deterministic:

- No files scanned -> **unknown** (exit 1 default, exit 2 with `--strict`).
- Any HIGH -> **unhealthy** (exit 2).
- Any MEDIUM, no HIGH -> **needs-attention** (exit 1).
- Only INFO -> **healthy** (exit 0) default, **needs-attention** (exit 1) with `--strict`.
- No findings, files scanned -> **healthy** (exit 0).

## Install

```
pip install -e .
```

## Use

```
mcpservercheck .                  # scan cwd, text output
mcpservercheck --json .           # deterministic JSON
mcpservercheck --strict .         # INFO promoted, no-files exits 2
mcpservercheck --include-info .   # show INFO findings inline
mcpservercheck --disable MSC-002 --disable MSC-010 .   # per-repo overrides
mcpservercheck --glob "*.mcp.json" .   # add extra globs
mcpservercheck --list-rules       # print rules and exit
mcpservercheck --version
```

Exit codes: `0` healthy, `1` needs-attention / unknown, `2` unhealthy / usage error.

Test the primitive against the shipped adversarial fixtures:

```
mcpservercheck tests/fixtures/msc001_shell_eval        # -> exit 2
mcpservercheck tests/fixtures/healthy                  # -> exit 0
mcpservercheck examples/weak_mcp.json                  # ten defects at once
mcpservercheck examples/healthy_mcp.json               # zero findings
```

## Test

```
python -m unittest discover -s tests
```

205 tests: per-rule positive+negative across all ten rules with
adversarial-vs-clean discrimination, registry invariants, container-shape
detection (`mcpServers` / `servers` / nested `mcp.servers` / bare-top-level),
scanner (read_text UTF-8 / BOM-strip / latin-1 fallback / max-bytes cap;
discover missing / single-file glob / dir walk / case-insensitive /
max-files cap / deterministic sort / custom glob), verdict rollup precedence
+ exit-code contract + text/JSON reporter shape, CLI (--version / --list-rules
/ missing-path / healthy-dir / unhealthy-dir / no-files default+strict / --json
/ --include-info / --disable / --max-files 0 / --max-bytes 0 / --glob), and
end-to-end fixture verification across the ten adversarial fixture shapes plus
healthy plus unknown plus a generated-at-runtime secret fixture (assembled
from sub-16-char parts so no verbatim token literal appears in source).

## Honest scope and limits

**What this tool does.** Structural linting of a JSON / JSONL registration
file the client will consume. Ten rules, deterministic, offline.

**What it does not do.** It does not run the server, does not connect to any
URL, does not fetch the tool schema advertised by the server, does not
verify the server implementation, does not detect prompt injection in tool
descriptions, does not audit runtime tool calls, does not enforce a policy.
Those are separate primitives (runtime proxy; server-source SAST; tool-schema
lint; agent-transcript audit) that would compose with this one.

**Rule scope.** Each rule flags a specific SHAPE. It never claims intent.
Legitimate configurations that deliberately use a wildcard, a plaintext
localhost transport, a bare binary name, or an inline secret in a throwaway
dev config can `--disable RULE_ID` per invocation or per repo.

**False negatives.** Nested delegation config beyond top-level, YAML / TOML
registration formats (v0.1 is JSON / JSONL only), object-shaped scope fields,
server implementations vendored inline as base64 or gzip, tool schemas
advertised over the wire at runtime, prompt-injection payloads embedded in
`description` fields, obfuscated command lines (escaped separators, base64
`-EncodedCommand` payloads whose decoded form is malicious but whose flag
is `-EncodedCommand` rather than `-Command`).

**False positives.** Legitimate use of `npx` / `node` / `python` as a bare
binary name (MSC-010 is INFO - hidden by default and can be `--disable`d).
Deliberate use of a plaintext localhost transport for dev-only sockets
(MSC-002 - `--disable`). Deliberate wildcard permissions on a locked-down
sub-agent (MSC-008 - `--disable`). Test / demo configurations that pin to
`@latest` on purpose (MSC-006 - `--disable`).

**Bounds.** Per-file byte cap (default 1 MiB; `--max-bytes`), per-run file
cap (default 1000; `--max-files`). Configs beyond those bounds are simply not
read.

**Not a secret scanner.** MSC-003 flags a bearer literal SHAPE in an MCP env
value. It is not a substitute for a full secret-detection pipeline (gitleaks,
truffleHog, etc.) run over the whole repo.

## Provenance and clean-room note

This is an independent implementation grounded in the public MCP-security
literature and threat-model writeups from 2026:

- arXiv 2601.17549 - "Breaking the Protocol: Security Analysis of the Model
  Context Protocol Specification and Prompt Injection Vulnerabilities in
  Tool-Integrated LLM Agents"
- arXiv 2603.22489 - "Model Context Protocol Threat Modeling and Analyzing
  Vulnerabilities to Prompt Injection with Tool Poisoning"
- arXiv 2603.21642 - "Are AI-assisted Development Tools Immune to Prompt
  Injection?"
- arXiv 2604.11790 - "ClawGuard: A Runtime Security Framework for
  Tool-Augmented LLM Agents Against Indirect Prompt Injection"
- arXiv 2605.17453 - "Trust No Tool: Evaluating and Defending LLM Agents
  under Untrusted Tool Feedback"
- arXiv 2605.18414 - "Prompts Don't Protect: Architectural Enforcement via
  MCP Proxy for LLM Tool Access Control"
- CVE-2025-54136 ("MCPoison") - trust bound to an MCP-registration key name
  rather than to the underlying command it launches
- CVE-2025-54135 ("CurXecute") - chained indirect prompt injection with
  auto-starting new MCP-registration entries
- Q3 2026 MCP-security landscape reports (14 CVEs; ~200,000 exposed servers;
  ~2,614 MCP implementations surveyed with 82% using file operations prone to
  path traversal, 67% using code-injection-prone APIs, 34% using command-
  injection-susceptible APIs)
- NSA / DoD CSI: MCP Security guidance (June 2026)
- Cloud Security Alliance Agentic MCP Security Best Practices (2026)
- Snyk Labs: Prompt Injection Meets MCP writeup (2026)

Only the described *patterns* (the four failure modes, the credential-in-env
finding, the plaintext-transport finding, the command-injection sink pattern)
were read. No reference detector code, empirical dataset, subject harness,
subject client, or per-paper measurement code was consulted.

**Not affiliated with or endorsed by** the papers' authors, the CVE
reporters, the standards / research bodies cited, any MCP client, any MCP
server, or any AI / dev-tool vendor.

## License

MIT.

---

*Produced by a human-machine hybrid intelligence, under maker-checker.*
