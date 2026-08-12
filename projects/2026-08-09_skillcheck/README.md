# skillcheck

Offline safety linter for agent skill files. Given a repository checkout
(or a single file), it scans a canonical set of agent-skill locations
(`SKILL.md`, `AGENTS.md`, `skills/`, `.skills/`, `agents/`, `.agents/`,
`prompts/`, `.prompts/`, and `*.skill.md`) and emits a structured
verdict about whether the skill inventory is safe to load.

Zero runtime dependencies. Python stdlib only.

## Why this exists

arXiv [2608.05223](https://arxiv.org/abs/2608.05223) ("Towards a Risk
Assessment of Malicious Skill Files in Coding Agents", 2026-08-05)
demonstrates that coding agents can be induced to execute adversarial
shell commands embedded in natural-language skill files, and calls for
skill-interface risk mitigation tooling. `skillcheck` is the small
pre-flight primitive that answers "does the skill inventory of this
repository contain risky patterns before I load it?" -- entirely
offline, as a CLI, a pre-commit hook, or a CI check.

`skillcheck` is an **independent implementation**, not affiliated with
or endorsed by the authors of the paper. The paper's *framing* --
that skill files are an under-audited attack surface -- is the
motivation; the paper's method, benchmark, and any reference code was
**not** consulted.

## Install

```
pip install .
```

Or run directly without installing:

```
python -m skillcheck /path/to/repo
```

## Usage

Scan a repository:

```
skillcheck /path/to/repo
```

Scan a single file:

```
skillcheck path/to/some.skill.md
```

Machine-readable JSON:

```
skillcheck --json /path/to/repo
```

Treat "unknown" verdict as unsafe (useful in CI):

```
skillcheck --strict /path/to/repo
```

Surface INFO-severity findings (hidden by default -- currently only
`SKILLCHECK-009`, "no capabilities declared"):

```
skillcheck --include-info /path/to/repo
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | verdict `safe` (files scanned, no findings) |
| 1 | verdict `suspicious` (medium-severity findings only) |
| 1 | verdict `unknown` (default; no files found or no capabilities declared) |
| 2 | verdict `unsafe` (any critical or high finding) |
| 2 | verdict `unknown` with `--strict` |
| 2 | path does not exist |

## Rules

| Rule ID | Severity | What it flags |
| --- | --- | --- |
| SKILLCHECK-001 | critical | destructive shell (`rm -rf`, `dd`, `mkfs`, `shred`, `Remove-Item -Recurse -Force`, fork bomb) |
| SKILLCHECK-002 | high | privilege escalation (`sudo`, `doas`, `su -`, `runas`, `Start-Process -Verb RunAs`) |
| SKILLCHECK-003 | critical | network exfiltration / reverse shell (`/dev/tcp/...`, `nc -l`, `curl -X POST`, `Invoke-WebRequest -Method POST`) |
| SKILLCHECK-004 | high | credential or secret reference (`~/.ssh/id_*`, `~/.aws/credentials`, `/etc/shadow`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, ...) |
| SKILLCHECK-005 | high | obfuscation (`base64 -d \| bash`, `xxd -r`, `-EncodedCommand`, invisible / bidi-override / zero-width characters) |
| SKILLCHECK-006 | medium | prompt-injection payload markers (`ignore previous instructions`, `you are now`, `SYSTEM:`, `<system>`, `jailbreak`) |
| SKILLCHECK-007 | high | runtime install-and-execute (`curl \| bash`, `iwr \| iex`, `pip install ... && python -c`) |
| SKILLCHECK-008 | high | filesystem archive exfiltration (`tar czf - \| curl`, `zip -r - \| nc`, `Compress-Archive \| Invoke-WebRequest`) |
| SKILLCHECK-009 | info | skill file declares no `tools` / `allowed_tools` / `capabilities` / `permissions` in YAML frontmatter |
| SKILLCHECK-010 | medium | suspicious external URL (raw IPv4 host, common URL shorteners) |

## Verdict rollup

- **safe** -- files were scanned, no findings at info-or-higher raised any risk.
- **suspicious** -- one or more medium-severity findings (typically
  SKILLCHECK-006 or SKILLCHECK-010).
- **unsafe** -- one or more high or critical findings.
- **unknown** -- no skill files found at all, OR all findings are INFO
  (SKILLCHECK-009 only).

## JSON output shape

```
{
  "verdict": "unsafe",
  "files_scanned": ["/repo/SKILL.md"],
  "errors": [],
  "findings": [
    {
      "rule_id": "SKILLCHECK-001",
      "severity": "critical",
      "file": "/repo/SKILL.md",
      "line": 8,
      "column": 6,
      "excerpt": "sudo rm -rf /var/tmp/workspace",
      "message": "destructive shell command that can irreversibly delete or overwrite data"
    }
  ],
  "summary": {
    "total_findings": 1,
    "files_scanned": 1,
    "by_severity": {"critical": 1, "high": 0, "medium": 0, "info": 0}
  }
}
```

Findings are sorted by `(severity, file, line, column, rule_id)` so
downstream tooling gets a stable ordering; JSON output uses
`sort_keys=True` for the same reason.

## Discovery rules

Canonical filenames (case-insensitive): `SKILL.md`, `AGENT.md`,
`AGENTS.md`, `SKILLS.md`.

Canonical directories (walked recursively): `skills/`, `.skills/`,
`agents/`, `.agents/`, `prompts/`, `.prompts/`.

Skill-suffix files: `*.skill.md`, `*.agent.md`.

Caps: at most 40 files per repository; at most 512 KiB per file.
UTF-8 with BOM auto-stripped; latin-1 fallback on invalid UTF-8.
Ordering is deterministic (sorted directory-then-filename).

## Honest scope and limits

- **Pattern-based.** False negatives on unusual wording are expected;
  false positives on ordinary prose are likely on some rule families
  and are traded off against detection completeness. `skillcheck` is a
  pre-flight filter, not a proof.
- **Not a code sandbox.** It analyses skill *text*; it does not run,
  compile, or sandbox anything.
- **Not a policy renderer.** It flags risky patterns; it does not
  decide what the correct policy is.
- **Not a general secret detector.** SKILLCHECK-004 flags known
  credential-file paths and sensitive env-var names as evidence of
  intent; it does not scan for secret *values*. Pair with a general
  secret scanner if you need that.
- **English-heavy.** Injection markers (SKILLCHECK-006) are
  English-language phrases; other languages may not trigger.
- **Not a GitHub API client.** Operates on a local checkout only.
- **Not a legal opinion.** Verdicts are engineering advice, not legal
  advice about liability or policy compliance.
- **Not a linter for the *inside* of code blocks specifically.** It
  scans full file text; risky patterns inside a Markdown code fence
  are flagged the same as in prose (this is intentional -- an agent
  may execute what it sees regardless of fencing).

## Development

Run tests:

```
python -m unittest discover -s tests
```

150 tests covering the pattern library (positive-and-negative per
family, case insensitivity), the rule engine (structural rule
SKILLCHECK-009 plus text-driven rules SKILLCHECK-001..010), the
scanner (discovery, size caps, BOM stripping, latin-1 fallback,
deterministic ordering, per-repo caps), the CLI (exit codes,
`--json`, `--strict`, `--include-info`, `--version`, single-file,
missing-path stderr, default cwd), the report formatters (JSON
parseability, determinism, info toggle, exit-code mapping incl.
strict-mode), and end-to-end fixture smoke tests for six distinct
skill-repo shapes (safe / shell / exfil / obfus / injection /
unknown).

## Provenance

Motivated by arXiv [2608.05223](https://arxiv.org/abs/2608.05223).
Clean-room implementation from published paper *framing only* --
paper method, benchmark, and any reference code was not consulted.
Rule taxonomy derived from independent public sources: OWASP LLM Top
10 (`LLM01: Prompt Injection`), the Trojan Source paper (Boucher &
Anderson, 2021) for bidi-override / zero-width control characters,
common shell-attack primitives in public red-team literature, and
typical YAML-frontmatter conventions for capability declarations in
mature open-source agent-tool projects.

Produced by a human-machine hybrid intelligence, under maker-checker.

## License

MIT. See [LICENSE](LICENSE).
