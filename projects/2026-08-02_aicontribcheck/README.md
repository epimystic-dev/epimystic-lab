# aicontribcheck

Offline AI-contribution-policy detector for open-source repositories.
Given a repo checkout, scans the canonical policy surface
(`CONTRIBUTING`, `README`, `AGENTS.md`, `.github/AI_POLICY.md`,
`.github/CONTRIBUTING.md`, `LICENSE`, etc.) for machine-readable
statements about whether AI-authored contributions are allowed,
banned, or conditional, plus any required disclosures / attribution
obligations / human-review requirements. Emits a structured verdict a
coding agent (or a CI check) can act on before opening a pull request.

- **Zero runtime dependencies.** Pure Python stdlib (3.9+).
- **Zero network calls.** Everything reads local files.
- **Deterministic output.** JSON schema is stable and sortable.
- **Ten documented rules** with positive-trigger and negative-clean
  tests for each family.

## The problem

arXiv 2607.26819 ("A First Look at Coding Agents' Compliance with AI
Contribution Rules in Open-Source Communities", 2026-07-29) reports
that coding agents never proactively retrieve contribution rules and
cannot refuse contributions in AI-banned repositories without explicit
prompts. The missing primitive is a small offline tool that,
pre-flight, answers: *does this repo's own contribution policy permit
what I am about to do?*

`aicontribcheck` is that primitive. Run it before an agent opens a PR;
gate the PR on its exit code; parse its JSON to know what
disclosures / attribution trailers you owe.

## Install

```bash
pip install .
```

Or run it as a module without installing:

```bash
python -m aicontribcheck /path/to/repo
```

## CLI

```
aicontribcheck [path] [--json] [--strict] [--include-info] [--extra-tool-name NAME] [--version]
```

- `path` : repo root (or a single policy file). Defaults to `.`.
- `--json` : emit machine-readable JSON (see schema below).
- `--strict` : treat `unknown` verdict as failure (exit 2).
- `--include-info` : include INFO-severity findings in text output.
- `--extra-tool-name NAME` : also recognise `NAME` as an assistant/product name (repeatable).

### Vendor neutrality (why no product names ship in the patterns)

The shipped patterns match **generic** markers only - `ai`, `llm`, `ai-generated`,
`ai-assisted`, `coding agent`, `generative ai`, and so on - which is how the
overwhelming majority of real contribution policies are actually worded.

No specific product names are hardcoded, deliberately. The assistant landscape churns
every few months, so a baked-in list is stale on arrival and quietly gives a false sense
of coverage; and a published linter carrying one vendor's trademarks is a liability, not
a feature. You supply the names you care about instead:

```bash
aicontribcheck . --extra-tool-name some-assistant --extra-tool-name another-tool
```

```python
from aicontribcheck import patterns
patterns.register_tool_names(["some-assistant", "another-tool"])
```

Registered names extend **both** the named-tool evidence rule (`AICONTRIB-007`) and the
AI marker used by the ban/allow/disclosure rules - so `no <name> contributions` is
detected as a ban, not merely noted as a mention. Names are regex-escaped and matched
case-insensitively on word boundaries, so plain strings are safe to pass. With no names
registered, `tools_named` is `[]` - the tool reports what it can actually see, and does
not pretend to a product list it was not given.

### Exit codes

| Verdict       | Default exit | `--strict` exit |
|---------------|--------------|-----------------|
| `allowed`     | 0            | 0               |
| `conditional` | 1            | 1               |
| `unknown`     | 1            | 2               |
| `banned`      | 2            | 2               |
| `conflict`    | 2            | 2               |

## Rules

| Rule            | Severity | Verdict     | What it flags                                              |
|-----------------|----------|-------------|------------------------------------------------------------|
| AICONTRIB-001   | ERROR    | banned      | Explicit refusal of AI-authored contributions              |
| AICONTRIB-002   | INFO     | allowed     | Explicit welcome of AI-authored contributions              |
| AICONTRIB-003   | WARN     | conditional | Disclosure of AI usage required                            |
| AICONTRIB-004   | WARN     | conditional | DCO / CLA / copyright-assignment / signed-off-by required  |
| AICONTRIB-005   | WARN     | conditional | Human review required for contributions                    |
| AICONTRIB-006   | INFO     | conditional | Tests required for contributions                           |
| AICONTRIB-007   | INFO     | unknown     | Named AI tool referenced (evidence, not a verdict)         |
| AICONTRIB-008   | INFO     | conditional | Non-commercial licence detected in `LICENSE`               |
| AICONTRIB-009   | INFO     | unknown     | No AI-contribution policy detected in any scanned file     |
| AICONTRIB-010   | ERROR    | conflict    | Ban and allow signals across different files disagree      |

## JSON schema

Top-level object:

```json
{
  "root": "/abs/path/to/repo",
  "verdict": "allowed | conditional | unknown | banned | conflict",
  "required_disclosures": ["<evidence line>", ...],
  "required_attributions": ["<message>", ...],
  "tools_named": ["<registered-name>", ...],
  "files": [ {"path": "...", "kind": "...", "findings": [ ... ] }, ... ],
  "summary": {
    "files_scanned": 3,
    "counts_by_severity": {"error": 1, "warn": 2, "info": 4},
    "counts_by_rule": {"AICONTRIB-001": 1, ...}
  }
}
```

Each finding:

```json
{
  "rule": "AICONTRIB-001",
  "severity": "error",
  "verdict": "banned",
  "message": "explicit ban of AI-authored contributions",
  "file": "/abs/path/CONTRIBUTING.md",
  "line": 5,
  "evidence": "This project does not accept AI-generated code."
}
```

## Examples

```bash
$ aicontribcheck tests/fixtures/ban_repo
aicontribcheck :: .../tests/fixtures/ban_repo
  verdict         : banned
  files scanned   : 2
  ...
findings:
  [ERROR] AICONTRIB-001 .../CONTRIBUTING.md:5 -- explicit ban of AI-authored contributions
          evidence: This project does not accept AI-generated contributions...
$ echo $?
2
```

```bash
$ aicontribcheck --json tests/fixtures/conditional_repo | python -c "import sys,json; r=json.load(sys.stdin); print(r['verdict'])"
conditional
```

## What we scan

Under repo root and under `.github/` and `docs/`, case-insensitively:

- `CONTRIBUTING.md`, `CONTRIBUTING.rst`, `CONTRIBUTING.txt`, `CONTRIBUTING`
- `README.md`, `README.rst`, `README.txt`, `README`
- `AGENTS.md`, `AGENTS`
- `AI_POLICY.md`, `AI-POLICY.md`, `AI_CONTRIBUTIONS.md`, `AI-CONTRIBUTIONS.md`
- `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`
- `LICENSE`, `LICENSE.md`, `LICENSE.txt`, `COPYING`
- `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE.md`
- `SECURITY.md`

Per-file cap: 512 KiB (rejected as `read_error` above the cap).
Per-repo cap: 40 files.

## Honest scope + limits

- **Not a legal opinion.** aicontribcheck surfaces policy text for
  human (or agent-with-human) review; it does not adjudicate the legal
  effect of what it finds.
- **Not a policy renderer.** It does not tell you how to write a good
  AI-contribution policy; it only detects what is (or is not) there.
- **Pattern-based.** Detection is regex-driven from a curated pattern
  library. False negatives are possible on unusual wording; false
  positives are minimized by requiring both a refusal verb and an AI
  marker on the same line for ERROR-level findings.
- **English-only.** All patterns are English text; contribution
  policies in other languages will report `unknown`.
- **Not a GitHub API client.** Reads the local checkout only; does not
  fetch remote repo metadata, discussions, or issue templates from a
  server. Point it at a working copy.
- **Not a code-provenance scanner.** aicontribcheck answers "is my
  contribution allowed here?" It does NOT answer "was this code
  actually written by AI?" - that is a different problem.
- **No SBOM output.** aicontribcheck writes a policy verdict, not a
  bill of materials.

## Suggested usage

- **As an agent tool.** Call it programmatically before opening a PR
  in a new repo; parse the JSON; refuse to open if verdict is `banned`
  or `conflict`; attach required disclosures if verdict is
  `conditional`.
- **As a CI check.** Run it in a workflow on any PR that carries an
  AI-authorship indicator; fail the check on `banned` verdict.
- **As a pre-commit hook.** Add it to `pre-commit` config with
  `--strict` if your project maintains a stricter default.

## Clean-room provenance

Independent implementation, not affiliated with or endorsed by the
authors of arXiv 2607.26819. The paper's *framing* motivated this
tool; the paper's *method, benchmark, and any reference code were NOT
consulted*. The detection patterns are curated from widely-published
open-source contribution-policy conventions
([Developer Certificate of Origin](https://developercertificate.org/),
[SPDX License List](https://spdx.org/licenses/), Creative Commons
[BY-NC](https://creativecommons.org/licenses/by-nc/4.0/) summary text,
and typical `CONTRIBUTING.md` wording in mature FOSS repositories).

## Tests

```bash
python -m unittest discover -s tests
```

119 tests covering the pattern library, the rule engine, the rollup
logic, the file discovery layer, the CLI contract, and end-to-end
fixture smoke tests.

## Licence

MIT.
