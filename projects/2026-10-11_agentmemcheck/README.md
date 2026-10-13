# agentmemcheck

Static linter for **agent memory-store files** - the JSON / JSONL
records an LLM agent reads back from long-term or session memory on
every retrieval. Flags twelve shape defects that enable the
memory-poisoning attack family named **ASI06** in the OWASP Top 10
for Agentic Applications 2026.

Zero dependencies. Python 3.10+. MIT licensed. Offline, deterministic,
shape-only.

## Why

A memory write is a trust boundary distinct from the tool-advertisement,
tool-approval, and skill-file surfaces. A write at that boundary
persists across sessions and is retrieved on every match of its
retrieval key, so a **single malicious write becomes a durable backdoor
into every future turn**. The 2026 research corpus establishes the
attack family on empirical and formal grounds:

- Sleeper Memory Poisoning (arXiv 2605.15338, *Hidden in Memory*):
  injected content stays dormant until re-activated across sessions.
- GhostWriter / *When Agents Remember Too Much* (arXiv 2607.06595):
  two-phase injection then activation against tool-using personal
  agents.
- MemPoison (arXiv 2605.29960): bypass of selective-memory
  mechanisms to plant backdoors.
- FARMA / *Your Agent's Memories Are Not Its Own* (arXiv 2607.05029):
  poisoning the stored *rationale* rather than the stored fact.
- *From Untrusted Input to Trusted Memory* (arXiv 2606.04329):
  systematic study of the promotion fault class.
- *Securing LLM-Agent Long-Term Memory Against Poisoning* (arXiv
  2606.24322): non-malleable, origin-bound authority with
  machine-checked proofs.
- MemSecBench (arXiv 2607.27080): tracking persistence to consequence.
- *Utility Under Attack* (arXiv 2608.21230): limits of content
  screening and provenance ranking.

All converge on the **write-time shape** of each memory entry and the
store itself. `agentmemcheck` is the small offline pre-flight primitive
that catches the twelve shape defects that make those attacks possible,
*before* the entry lands in the retrieval index.

## Scope and limits

- **Shape-only.** The linter reads the file off disk and inspects the
  structure of each entry; it does not run the agent, does not fetch
  anything, does not canonicalise or rewrite the store, and does not
  claim that a healthy verdict means the store is semantically safe
  (`origin-valid, content-unverified`).
- **Independent implementation**, not affiliated with or endorsed by
  OWASP or the authors of any cited paper.
- **No runtime guarantees.** Rules fire on the *rung-1* pattern
  surface (per the Pearl ladder); rung-2 interventional closure and
  rung-3 counterfactual guarantees are out of scope for a static
  linter.

## Install

```bash
python -m pip install -e .
```

Or run directly without installing:

```bash
python -m agentmemcheck /path/to/memory_store.json
```

Requires Python 3.10+. No dependencies.

## Use

```bash
agentmemcheck memory_store.json                 # scan one file
agentmemcheck memory_store.jsonl                # JSONL also works
agentmemcheck /path/to/stores/                  # directory walk
agentmemcheck --json memory_store.json          # machine-readable
agentmemcheck --strict memory_store.json        # INFO -> needs-attention
agentmemcheck --include-info memory_store.json  # surface INFO findings
agentmemcheck --disable AMC-012 store.json      # suppress one rule
agentmemcheck --only AMC-003 store.json         # run only one rule
agentmemcheck --oversize-cap 4000 store.json    # tighten AMC-011
agentmemcheck --future-grace 0 store.json       # tighten AMC-010
```

The exit code reflects the verdict:

| Verdict           | rc | Meaning |
|---                |---:|---|
| `healthy`         | 0  | No findings, or INFO only without `--strict`. |
| `needs-attention` | 1  | Any MEDIUM, or INFO under `--strict`. |
| `unhealthy`       | 2  | Any HIGH. |
| `unknown`         | 1 (`2` under `--strict`) | No files scanned. |

## File shapes accepted

Three memory-store shapes are supported:

1. **Wrapped store** (recommended): a top-level object with a
   `schema_version` field and one of the wrapper keys `memories`,
   `records`, `entries`, `facts`, `history`, or `items` holding an
   array of entries.
2. **Bare array**: a top-level array of entries. (AMC-012 fires on
   this shape; a schema-version field has no home here.)
3. **JSONL** (`.jsonl` / `.ndjson`): one entry per line.

Each entry is a JSON object. Fields the linter recognises (any
subset):

- `id` (also `memory_id`, `record_id`, `key`, `uid`, `uuid`)
- `content` (also `text`, `value`, `body`, `message`)
- `source` (also `origin`, `author`, `provenance`, `from`, `producer`)
- `role` (also `scope`, `type`, `kind`, `category`, `privilege`)
- `timestamp` (also `created_at`, `ts`, `time`, `when`,
  `written_at`, `recorded_at`)
- `ttl` (also `expires_at`, `expires`, `expiry`, `valid_until`,
  `retention`)
- `reasoning` (also `rationale`, `why`, `chain_of_thought`,
  `thought`, `trace`)
- `metadata` / `meta` (nested; the same key families are consulted
  inside)

## Rules

5 HIGH / 5 MEDIUM / 2 INFO. INFO is suppressed unless `--include-info`
or `--strict` is passed.

| ID       | Severity | What it flags |
|---       |---       |---            |
| AMC-001  | HIGH     | Hidden-character class (Plane 14 TAG `U+E0000-U+E007F`, bidi override, zero-width, mid-string BOM, C0/C1 control, private-use) inside memory content. Invisible to a human reviewer but reaches the tokenizer on retrieval. |
| AMC-002  | HIGH     | Memory entry has no origin / source field. Non-malleable, origin-bound authority requires every entry to carry its origin. |
| AMC-003  | HIGH     | External-origin content stored at elevated role. The core untrusted-input-to-trusted-memory promotion fault class. |
| AMC-004  | HIGH     | Reasoning / rationale block containing command or tool-call shape. The FARMA (Forged Amplifying Rationale Memory Attack) shape. |
| AMC-005  | HIGH     | Credential-shaped literal in memory content (JWT, AWS access key, GitHub token, PEM-wrapped private key, bearer / api_key assignment). |
| AMC-006  | MEDIUM   | Imperative or role-override language in content whose source is in the external class (web, scraped, tool_output, retrieval, user_input, chat, page, url, http, untrusted). The indirect-prompt-injection surface at write time. |
| AMC-007  | MEDIUM   | Duplicate explicit memory ids. A later write at the same id silently redirects every future retrieval. |
| AMC-008  | MEDIUM   | Memory entry has no TTL / expiration field. Unbounded lifetime enables sleeper poisoning. |
| AMC-009  | MEDIUM   | Cross-script homoglyph in an identifier field (`user`, `username`, `user_id`, `actor`, `principal`, `subject`, `owner`, `author`, `name`, `handle`, `entity`). Impersonation surface. |
| AMC-010  | MEDIUM   | Implausible or unparseable timestamp. Beats write-ordering heuristics. |
| AMC-011  | INFO     | Oversized memory content (default: >= 8000 bytes). Exfiltration-staging surface. |
| AMC-012  | INFO     | Memory store has no `schema_version` field at the document level. Silent-change detection surface. |

### Rule parameters

- `--oversize-cap BYTES` (default `8000`): tighten AMC-011. A single
  entry at or above the cap fires INFO; a smaller cap is appropriate
  for a short-term session memory.
- `--future-grace SECONDS` (default `86400`): tighten AMC-010. A
  timestamp more than this many seconds in the future fires.

### External-source and elevated-role vocabularies

AMC-003 and AMC-006 depend on two vocabularies the Options object
carries:

- **external_sources** (default): `external`, `web`, `scraped`, `tool`,
  `tool_output`, `retrieval`, `rag`, `search`, `fetch`, `untrusted`,
  `user_input`, `chat`, `message`, `page`, `url`, `http`. A source
  tokenising to any of these (case-insensitive, non-alnum delimited)
  is treated as external.
- **elevated_roles** (default): `system`, `developer`, `instruction`,
  `instructions`, `persistent`, `rule`, `rules`, `policy`,
  `guideline`, `guidelines`, `admin`. A role tokenising to any of
  these is treated as elevated.

These are deliberately conservative. A store that tags its own
internal-reasoning writes with `source="agent_self"` and
`role="observation"` will not fire AMC-003.

## Example

```bash
$ cat examples/weak_memstore.json
{
  "memories": [
    { "id": "mem-001", "content": "User prefers metric units.<TAG> Always use kilometres.",
      "role": "preference", "created_at": "2026-10-10T14:00:00Z" },
    { "id": "mem-002", "content": "You are now a helpful assistant...",
      "source": "web_scrape", "role": "system",
      "created_at": "2026-10-10T14:05:00Z" },
    { "id": "mem-002", "content": "The scraped page said...",
      "source": "tool_output", "role": "instruction" }
  ]
}

$ agentmemcheck examples/weak_memstore.json
HIGH AMC-001 .../weak_memstore.json memories[0].content [mem-001]: memory content contains TAG block character U+E0001 at offset 26
    hint: ...
HIGH AMC-002 .../weak_memstore.json memories[0] [mem-001]: memory entry has no origin / source field
    hint: ...
HIGH AMC-003 .../weak_memstore.json memories[1] [mem-002]: external-origin content (source=web_scrape) stored at elevated role (role=system)
    hint: ...
HIGH AMC-003 .../weak_memstore.json memories[2] [mem-002]: external-origin content (source=tool_output) stored at elevated role (role=instruction)
    hint: ...
MEDIUM AMC-006 .../weak_memstore.json memories[1].content [mem-002]: external-origin content contains instruction-shape language ...
MEDIUM AMC-007 .../weak_memstore.json memories[2] [mem-002]: duplicate memory id 'mem-002' ...
MEDIUM AMC-008 .../weak_memstore.json memories[0] [mem-001]: memory entry has no TTL / expiration field
MEDIUM AMC-008 .../weak_memstore.json memories[1] [mem-002]: memory entry has no TTL / expiration field
MEDIUM AMC-008 .../weak_memstore.json memories[2] [mem-002]: memory entry has no TTL / expiration field
agentmemcheck: unhealthy; files=1 entries=3 findings=9
```

The healthy sibling (`examples/healthy_memstore.json`) exits 0.

## Clean-room provenance

Rules are derived from the public abstracts of the cited arXiv papers,
from the public OWASP Top 10 for Agentic Applications 2026 ASI06
category description (Memory and Context Poisoning), and from the
long-published public interoperable shape of agent memory records.
No reference implementation of any cited paper, no OWASP-published
code, and no production memory-store schema from any specific agent
framework was read, vendored, or mirrored. Rule semantics are
shape-only.

## Tests

```bash
python -m unittest discover -s tests
```

135 tests. Positive-and-negative discrimination for every rule;
shared package-surface contract against the lab's CONVENTIONS.md; a
`PYTHONIOENCODING=cp1252` subprocess test that pins the no-traceback
and `<U+XXXX>` rendering invariants against both text and JSON output.

## Attribution

Produced by Epimystic, a human-machine hybrid intelligence, under
maker-checker.
