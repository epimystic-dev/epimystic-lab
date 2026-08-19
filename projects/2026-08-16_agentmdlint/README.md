# agentmdlint

An offline, zero-dependency maintainability linter for agent instruction files
(`AGENTS.md`, `AGENT.md`, `CLAUDE.md`, `GEMINI.md`, `CURSOR.md`,
`AI_INSTRUCTIONS.md`, `.cursorrules`, `.github/copilot-instructions.md`, and
similar).

`agentmdlint` reads what is on disk, applies ten documented rules, and emits a
structured verdict (`healthy` | `needs-attention` | `unhealthy` | `unknown`)
with a machine-readable JSON report. It is a CLI, a pre-commit hook, and a CI
check in one small stdlib-only Python package.

## Why this exists

Agentic coding lives inside instruction files that live at the top of a
repository. These files grow: because appending is cheap, and because once an
instruction's rationale has been lost, deleting it risks a correctness
regression whose cost is exponential in the number of remaining instructions.

The literature calls this "catastrophic remembering" -- the inverse of the
"catastrophic forgetting" phenomenon around which continual learning is
organized (arXiv 2608.11095, 2026-08-11). The paper measured 247,694
instruction lifetimes across 1,867 repositories and observed a +226% mean
lifetime growth with a log-hazard of -0.032/commit against deletion, and
proposed rationale comments as a remedy. `agentmdlint` is the small pre-flight
linter that operationalizes that measurement: it flags the shapes of unbounded
growth in a specific instruction file so a maintainer knows when to prune.

## Install

```
pip install .
```

The package has zero runtime dependencies and works on Python 3.8+.

## Use

Scan the current directory:

```
agentmdlint
```

Scan a specific path or single file:

```
agentmdlint path/to/repo
agentmdlint path/to/AGENTS.md
```

Machine-readable output for CI:

```
agentmdlint --json
```

Fail on info-only findings too (useful in a CI gate):

```
agentmdlint --strict
```

Show info-severity findings in text output (hidden by default):

```
agentmdlint --include-info
```

## Exit codes

| Verdict           | Default exit | `--strict` exit |
|-------------------|--------------|-----------------|
| `healthy`         | 0            | 0               |
| `needs-attention` | 1            | 1               |
| `unhealthy`       | 2            | 2               |
| `unknown`         | 1            | 2               |
| missing path      | 2            | 2               |

INFO-only findings do not change the exit code by default; under `--strict`
they promote the verdict to `needs-attention`.

## Rules

| Rule           | Severity        | Signal                                                                 |
|----------------|-----------------|------------------------------------------------------------------------|
| AGENTMD-001    | MEDIUM / HIGH   | Byte-size bloat (soft/hard cap on file bytes)                          |
| AGENTMD-002    | MEDIUM / HIGH   | Instruction-count bloat (soft/hard cap on imperative count)            |
| AGENTMD-003    | MEDIUM          | Near-duplicate instructions (jaccard-token-set similarity)             |
| AGENTMD-004    | INFO            | Imperative line with no rationale marker                               |
| AGENTMD-005    | INFO            | Dead heading (empty or near-empty section)                             |
| AGENTMD-006    | MEDIUM          | Drift marker (TODO / FIXME / XXX / HACK / TBD / DEPRECATED)            |
| AGENTMD-007    | MEDIUM          | Stale amendment date (`YYYY-MM-DD` older than `--stale-days`)          |
| AGENTMD-008    | HIGH            | Candidate contradiction (same subject tokens, opposite polarity)       |
| AGENTMD-009    | INFO            | Missing purpose header (or purpose section has no prose)               |
| AGENTMD-010    | INFO            | Imperative-wall (`>=` `--wall-length` consecutive imperatives w/o rationale) |

## Configuration

All thresholds are CLI flags with conservative defaults:

| Flag                      | Default    | Meaning                                                     |
|---------------------------|------------|-------------------------------------------------------------|
| `--soft-bytes`            | 20000      | AGENTMD-001 soft cap on file byte size                      |
| `--hard-bytes`            | 60000      | AGENTMD-001 hard cap                                        |
| `--soft-instructions`     | 100        | AGENTMD-002 soft cap on imperative count                    |
| `--hard-instructions`     | 300        | AGENTMD-002 hard cap                                        |
| `--duplicate-threshold`   | 0.85       | AGENTMD-003 jaccard threshold (0.0-1.0)                     |
| `--min-section-tokens`    | 10         | AGENTMD-005 minimum tokens a section needs                  |
| `--stale-days`            | 730        | AGENTMD-007 staleness horizon in days                       |
| `--today`                 | system     | Reference date for staleness (`YYYY-MM-DD`)                 |
| `--wall-length`           | 7          | AGENTMD-010 imperative-wall length                          |
| `--files`                 | (defaults) | Comma-separated filename list to scan                       |
| `--max-files`             | 40         | Per-repo file cap                                           |
| `--max-bytes`             | 1048576    | Per-file byte cap when reading                              |

## Precommit example

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: agentmdlint
      name: agentmdlint
      entry: agentmdlint
      language: system
      pass_filenames: false
      always_run: true
```

## Honest scope and limits

- Pattern-based, not a natural-language reasoner. False negatives are expected
  for imperatives phrased without a modal verb; false positives are expected
  for prose that happens to contain a modal in an unrelated sense.
- Not a code sandbox. It does not execute anything, only reads bytes.
- Not a general secret detector. It is a maintainability primitive; see the
  companion `envcheck`, `jwtcheck`, and `licensechain` tools for other
  concerns.
- Not a full markdown parser. The parser is a lightweight structural pass over
  headings, fenced code blocks, and list items -- enough for classification,
  not enough for reflow.
- English-heavy. The imperative-modal list is English-language conventional.
- Line and column numbers refer to the on-disk file after UTF-8 BOM strip and
  after latin-1 fallback on decode failure.
- Rule AGENTMD-004 (missing rationale) is heuristic and lives at INFO severity
  precisely because rationale placement is stylistic; treat it as guidance,
  not a hard error.
- Rule AGENTMD-008 (contradiction) uses normalized subject-token overlap and
  can false-positive on legitimate exceptions ("always X except when Y").
  Review flagged pairs before acting.
- `.github/copilot-instructions.md` is scanned as a canonical instruction-file
  location alongside the other conventional names; this is discovery scope,
  not endorsement of any tool or vendor.

## Companion primitives in the same family

- `envcheck` -- environment-variable hygiene
- `jsonlcheck` -- JSONL schema hygiene
- `jsonldiff` -- JSONL diff hygiene
- `jsonlsample` -- JSONL sampling hygiene
- `jwtcheck` -- JWT hygiene
- `reqcheck` -- install-manifest hygiene
- `licensechain` -- license-chain hygiene
- `aicontribcheck` -- AI-contribution-policy hygiene
- `skillcheck` -- agent-skill *safety* hygiene (safe-to-load pre-flight)
- `agentmdlint` -- agent-instruction *maintainability* hygiene

`skillcheck` and `agentmdlint` overlap on the same file surface but answer
orthogonal questions: `skillcheck` asks "is this safe to load?" and
`agentmdlint` asks "is this still maintained?". They compose well as a
two-stage pre-flight.

## Clean-room note

`agentmdlint` is an independent implementation of a linter primitive motivated
by the framing in "CLAUDE.md Growth" (arXiv 2608.11095, 2026-08-11). The
paper's methodology, benchmark, and any reference code were not consulted.
`agentmdlint` is not affiliated with or endorsed by the paper's authors.

## License

MIT. See `LICENSE`.

Produced by a human-machine hybrid intelligence, under maker-checker.
