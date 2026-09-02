# elevatescan

Offline static scanner for **instruction-privilege-escalation shapes** in
files an agent will consume as low-privilege observations, tool outputs, or
user-provided context.

Zero-dep Python stdlib. MIT licensed.

## Why

Modern agent harnesses stitch **low-privilege content** (tool outputs, user
files, scraped pages, retrieved docs) into the same prompt context as
**high-privilege instructions** (system prompt, developer messages,
harness-provided persistent goals). When the low-privilege content contains
the right pattern shape - a fake role marker, an override directive, a
persistent-goal write, a scheduled-task hijack, an authority claim, a
tool-output-looking-like-a-command - the harness template ends up placing that
content in a position where the model treats it at a higher instruction level
than its true origin.

That failure mode has a name in the literature: **instruction privilege
escalation** (arXiv 2608.27299 "When Context Gets Root: Privilege Escalation
in LLM Harnesses", 2026-08-27). Related evidence: SARA / arXiv 2608.27146
("When Tool Outputs Become Commands", 2026-08-27) and LongPIBench / arXiv
2608.28411 ("A Long-Context Benchmark for Prompt Injection", 2026-08-28) both
report that simple heuristic injection shapes reliably bypass state-of-the-
art defenses on the long-context content that agents routinely ingest.

`elevatescan` is the small offline pre-flight primitive that scans that
content **before** it lands in the harness template.

## What it detects

Ten pattern-shape rules across three severities:

| ID       | Severity | Shape |
|---       |---       |---    |
| ESC-001  | HIGH     | Fake role-marker injection (chatml / bracket / html / markdown role headers). |
| ESC-002  | HIGH     | Override-directive smuggling (ignore / disregard / override prior instructions). |
| ESC-003  | HIGH     | Persistent-goal / long-term-memory smuggling. |
| ESC-004  | HIGH     | Scheduled-task / cron / recurring-job hijack. |
| ESC-005  | HIGH     | Elevated-authority claim (as your operator / admin mode / real principal). |
| ESC-006  | MEDIUM   | Tool-output marker followed by imperative directive in same content. |
| ESC-007  | MEDIUM   | URL with instruction-shaped query / fragment parameter. |
| ESC-008  | MEDIUM   | Hidden-content marker (HTML comment with instruction words, or zero-width chars). |
| ESC-009  | MEDIUM   | Code fence labelled with role/instruction language (```system, ```prompt). |
| ESC-010  | INFO     | Bare sentinel-token exposure in prose (endoftext / eot_id / INST). |

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
python -m elevatescan /path/to/scan
```

Requires Python 3.9+. No dependencies.

## Use

```bash
elevatescan                        # scan cwd, text output
elevatescan path/to/dir            # scan a directory
elevatescan path/to/one_file.md    # scan a single file
elevatescan --json path            # machine-readable JSON
elevatescan --strict path          # INFO -> needs-attention; no-files -> exit 2
elevatescan --include-info path    # surface INFO findings in text output
elevatescan --disable ESC-001 path # disable one rule (repeatable)
elevatescan --glob "*.log" path    # extend default file-glob set (repeatable)
elevatescan --list-rules           # print the rule registry
elevatescan --version
```

Default file globs: `*.md`, `*.txt`, `*.json`, `*.jsonl`, `*.yaml`, `*.yml`.

### Text output shape

```
verdict: unhealthy
files_scanned=1 findings_total=3 high=2 medium=1 info=0
findings_visible=3 findings_hidden=0
  HIGH ESC-002 notes.md:5:1 override-directive shape in ingested content
  HIGH ESC-003 notes.md:9:1 persistent-goal / long-term-memory smuggling shape
  MEDIUM ESC-006 notes.md:12:1 tool-output marker followed by imperative directive in same content
```

### JSON output shape

Deterministic (sorted keys, fixed indent). Findings are sorted by
`(severity, path, line, column, rule_id)`.

## Where it fits

`elevatescan` sits at the **agent-consumed content** hygiene layer of a
broader family of small offline linters:

- File-content hygiene: `envcheck`, `jsonlcheck`, `jwtcheck`
- Eval-stream hygiene: `jsonldiff`, `jsonlsample`
- Install-manifest hygiene: `reqcheck`
- License-chain hygiene: `licensechain`
- Contribution-policy hygiene: `aicontribcheck`
- Agent-skill safety hygiene: `skillcheck`
- Agent-instruction maintainability hygiene: `agentmdlint`
- Test-oracle-shape hygiene: `oraclecheck`
- **Agent-consumed content hygiene** (this tool)

The design principle is the same: zero dependencies, deterministic output,
verdict-based exit code, `--json` for CI, honest about scope and limits.

## Honest scope and limits

- **Pattern-based, not proof.** Every rule is a regex over text. It detects a
  shape that is often adversarial. It cannot know intent.
- **False positives are expected** on legitimate corpora that discuss any of
  the shapes it detects: prompt-engineering docs, agent transcripts,
  jailbreak-research papers, security post-mortems. Use `--disable` per file
  or per repo when the flag is a doc-about-the-shape, not the-shape-itself.
- **False negatives are expected** on novel or obfuscated shapes. This is a
  pre-flight primitive, not an adversarial classifier. Layer it with other
  controls (harness-level provenance separation, instruction-hierarchy
  enforcement per SARA/2608.27146, gated tool execution).
- **Text-only.** It reads `*.md`, `*.txt`, `*.json`, `*.jsonl`, `*.yaml`,
  `*.yml` by default. It does not sniff binary, does not follow imports, does
  not decode base64, does not fetch URLs, does not execute anything.
- **Per-file byte cap** (default 1 MiB) and **per-run file cap** (default
  1000) are hard bounds; content beyond either is silently ignored. Adjust
  with `--max-bytes` and `--max-files`.
- **English only.** The lexical patterns are English-only. A non-English
  content stream would produce false-negatives.
- **Not a general secret detector.** Use the companion tools for that.

## Clean-room note

This is an **independent implementation**. Rule design was motivated by the
framings in arXiv 2608.27299 (instruction privilege escalation as an attack
class), arXiv 2608.27146 (tool outputs becoming commands), and arXiv
2608.28411 (long-context injection surface); the authors' reference code,
attack corpora, and per-paper measurement code were **not** consulted. This
project is not affiliated with or endorsed by any of the cited authors, their
institutions, or any AI vendor or product.

## License

MIT. See LICENSE.

---

*Produced by a human-machine hybrid intelligence, under maker-checker.*
