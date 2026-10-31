# CLI conventions for the epimystic-lab hygiene linters

The lab's hygiene linters share a shape by design: offline, stdlib-only, exit codes
meaningful in CI, structured output on request. This page documents what CI consumers
can rely on **today**, evidence-gathered from every published tool on 2026-08-11, and
names the divergences that a future convergence pass will close.

Tools in scope: `jsonlcheck`, `envcheck`, `jwtcheck`, `reqcheck`, `licensechain`,
`aicontribcheck`, `skillcheck`, `agentmdlint`, `oraclecheck`, `elevatescan`,
`delegcheck`, `mcpservercheck`, `nbshape`, `sarifcheck`, `pjhookcheck`,
`approvchainlint`. `seedline` is a library (no CLI); `jsonldiff` and `jsonlsample`
are data-transformation tools rather than linters and follow only the invocation
and stdout/stderr rules below.

## Invocation

Every linter is invokable as `python -m <tool>`, with `argparse`-style flags. The
`--help` flag returns exit code `0`. Unknown flags return exit code `2` via argparse.

    python -m jsonlcheck --help          # rc=0
    python -m jsonlcheck --nope           # rc=2 (argparse: unrecognized arguments)

## Exit codes

### The one invariant every tool upholds

`rc == 0` iff the input was clean (no findings surfaced under the tool's default
severity filter). `rc != 0` iff the tool has something the CI job should notice -
findings, unreadable input, or an internal error. A CI script that only cares
"did anything worth attention happen" can rely on `test $? -eq 0` uniformly across
all sixteen tools.

Evidence (rows 1-7 run 2026-08-11; rows 8-9 run 2026-09-02; row 10 run 2026-09-04; row 11 run 2026-09-11; row 12 run 2026-09-16; rows 13-14 run 2026-09-19; row 15 run 2026-10-30; row 16 run 2026-10-31):

| Tool           | Clean input command                                       | Findings command                                        | Clean rc | Findings rc |
|----------------|-----------------------------------------------------------|---------------------------------------------------------|----------|-------------|
| jsonlcheck     | `echo '{"a": 1}' \| python -m jsonlcheck -`               | `echo 'not json' \| python -m jsonlcheck -`             | 0        | 1           |
| envcheck       | `python -m envcheck examples/template.env examples/template.env` | `python -m envcheck examples/template.env examples/local.env` | 0 | 1     |
| jwtcheck       | `python -m jwtcheck examples/ok.env`                      | `python -m jwtcheck examples/bad.env`                   | 0        | 2           |
| reqcheck       | `python -m reqcheck examples/ok.txt`                      | `python -m reqcheck examples/bad.txt`                   | 0        | 2           |
| licensechain   | `python -m licensechain examples/ok_chain.json`           | `python -m licensechain examples/bad_chain.json`        | 0        | 2           |
| aicontribcheck | `python -m aicontribcheck <repo-with-empty-CONTRIBUTING>` | `python -m aicontribcheck <repo-with-ban-policy>`       | 1        | 2           |
| skillcheck     | `python -m skillcheck <safe-skill-repo>`                  | `python -m skillcheck <repo-with-unsafe-skill>`         | 1*       | 2           |
| agentmdlint    | `python -m agentmdlint examples/healthy_AGENTS.md`        | `python -m agentmdlint examples/unhealthy_AGENTS.md`    | 0        | 2           |
| oraclecheck    | `python -m oraclecheck examples/healthy_test.py`          | `python -m oraclecheck examples/unhealthy_test.py`      | 0        | 2           |
| elevatescan    | `python -m elevatescan examples/healthy_notes.md`         | `python -m elevatescan examples/malicious_notes.md`     | 0        | 2           |
| delegcheck     | `python -m delegcheck examples/healthy_delegation.json`   | `python -m delegcheck examples/weak_delegation.json`    | 0        | 2           |
| mcpservercheck | `python -m mcpservercheck examples/healthy_mcp.json`      | `python -m mcpservercheck examples/weak_mcp.json`       | 0        | 2           |
| nbshape        | `python -m nbshape examples/healthy_notebook.ipynb`       | `python -m nbshape examples/weak_notebook.ipynb`        | 0        | 2           |
| sarifcheck     | `python -m sarifcheck examples/healthy_results.sarif`     | `python -m sarifcheck examples/weak_results.sarif`      | 0        | 2           |
| pjhookcheck    | `python -m pjhookcheck examples/healthy_package.json`     | `python -m pjhookcheck examples/weak_package.json`      | 0        | 2           |
| approvchainlint| `python -m approvchainlint examples/healthy_config.json`  | `python -m approvchainlint examples/weak_config.json`   | 0        | 2           |

*`aicontribcheck` and `skillcheck` return `1` on a "clean" run against most inputs
because their exit codes encode a *verdict* (allowed / unknown / banned or
safe / unknown / unsafe) rather than a finding count - a caller wanting a strict
`0` requires an explicit allowed/safe verdict from the tool. This is a deliberate
verdict-based encoding, not a divergence to fix.

The last nine rows also encode a verdict rollup (`healthy` / `needs-attention` /
`unhealthy`), but the rollup is derived from severity so their clean-input rc is
`0`. See the Convention B entry below for the shared severity mapping.

Each row's "Findings command" is additionally locked by `tests/test_shared_contract.py`
inside the tool: help returns rc 0, the clean command returns rc 0 (with the
`aicontribcheck` / `skillcheck` verdict caveat), and the findings command returns
non-zero. All sixteen tests further assert a tool-specific anchor beyond bare rc so
a false-pass from an unrelated non-zero rc (a missing `__main__.py`, an argparse
rejection of an unknown flag) cannot pass by accident. Fifteen anchor a
tool-specific rule code on stdout; `jsonlcheck` anchors the offending filename
on stderr (its stdout is empty on the findings run so the stderr diagnostic is
the shape available to lock):

| Tool           | Anchor assertion in findings run                         |
|----------------|----------------------------------------------------------|
| envcheck       | `D001` on stdout                                         |
| jwtcheck       | `JWT-A001` on stdout                                     |
| reqcheck       | `REQ-A005` on stdout                                     |
| licensechain   | `LIC-009` on stdout                                      |
| aicontribcheck | `AICONTRIB-001` on stdout                                |
| skillcheck     | `SKILLCHECK-001` on stdout                               |
| agentmdlint    | `AGENTMD-008` on stdout                                  |
| oraclecheck    | `ORACLE-001` on stdout                                   |
| elevatescan    | `ESC-001` on stdout                                      |
| delegcheck     | `DEL-001` on stdout                                      |
| mcpservercheck | `MSC-001` on stdout                                      |
| nbshape        | `NBK-001` on stdout                                      |
| sarifcheck     | `SRF-001` on stdout                                      |
| pjhookcheck    | `PJH-001` on stdout                                      |
| approvchainlint| `AC-001` on stdout                                       |
| jsonlcheck     | `bad.jsonl` on stderr (filename anchor, not a rule code) |

Read the anchor column as a "the tool actually ran" witness paired with the
non-zero-rc invariant, not as a rule-code contract - each per-tool suite locks
the wider output shape.

### The two current conventions for `1` vs `2`

Tools split between two conventions when a finding is present:

- **Convention A - severity-blind.** `rc=1` for any finding, `rc=2` reserved for
  usage/IO error. Followed by `jsonlcheck` and `envcheck`.
- **Convention B - severity-tiered.** `rc=1` for warnings only, `rc=2` for errors
  OR unrecoverable IO. Followed by `jwtcheck`, `reqcheck`, `licensechain`,
  `agentmdlint`, `oraclecheck`, `elevatescan`, `delegcheck`, `mcpservercheck`,
  `nbshape`, `sarifcheck`, `pjhookcheck`, `approvchainlint`. The last nine roll
  findings into an explicit verdict (`healthy` / `needs-attention` / `unhealthy`)
  whose rc mapping is `0 / 1 / 2` - a verdict wrapper over the same severity
  tiers, not a separate convention.
- **Convention C - verdict-based.** `rc` reflects a policy verdict rather than
  finding severity: `1` = `unknown` / `conditional`, `2` = `banned` / `conflict`
  (or `unsafe`). Used by `aicontribcheck` and `skillcheck`. This convention is a
  good fit for policy tools and is not on the convergence list.

A CI job that needs to distinguish "warnings" from "errors" today must know which
convention its tool follows. Convergence toward Convention B for all severity-based
linters is an open item on the maintenance backlog; the convention here
locks in the current state so a future change lands as a documented breaking-change
release rather than as silent drift.

### `--strict`

Thirteen of the sixteen linters expose `--strict`, though the semantic differs
across three families. `jwtcheck` exposes an equivalent knob via
`--severity error`. `jsonlcheck` and `envcheck` do not expose `--strict`; a
finding is a finding under their severity-blind exit code (Convention A).

Evidence (rows 1-8 run 2026-09-12; row 9 run 2026-09-16; rows 10-11 run 2026-09-19;
row 12 run 2026-10-30; row 13 run 2026-10-31;
`--strict` behaviour quoted verbatim from each tool's `python -m <tool> --help`
output):

| Tool           | Family              | `--strict` behaviour                                       |
|----------------|---------------------|------------------------------------------------------------|
| reqcheck       | severity-tiered     | treat warnings as errors (exit 2 on any warning)           |
| licensechain   | severity-tiered     | promote warnings to errors for exit-code purposes          |
| aicontribcheck | verdict-based       | treat `unknown` verdict as failure (exit 2)                |
| skillcheck     | verdict-based       | treat `unknown` verdict as an unsafe exit (2 instead of 1) |
| agentmdlint    | verdict-rollup      | escalate info-only and no-file-found outcomes to nonzero   |
| oraclecheck    | verdict-rollup      | escalate INFO findings and no-files-scanned to exit 1 / 2  |
| elevatescan    | verdict-rollup      | INFO -> `needs-attention`; no-files -> exit 2              |
| delegcheck     | verdict-rollup      | escalate INFO to `needs-attention`; no-files to exit 2     |
| mcpservercheck | verdict-rollup      | escalate INFO to `needs-attention`; no-files to exit 2     |
| nbshape        | verdict-rollup      | escalate INFO to `needs-attention`; an unknown verdict exits 2 |
| sarifcheck     | verdict-rollup      | escalate INFO to `needs-attention`; no files scanned exits 2 |
| pjhookcheck    | verdict-rollup      | escalate INFO to `unhealthy`; no-files to exit 2           |
| approvchainlint| verdict-rollup      | escalate INFO findings to unhealthy; no files scanned becomes rc 2 |

The severity-tiered pair (`reqcheck`, `licensechain`) escalate warnings; the
verdict-based pair (`aicontribcheck`, `skillcheck`) escalate an `unknown`
verdict; the nine verdict-rollup tools (`agentmdlint`, `oraclecheck`,
`elevatescan`, `delegcheck`, `mcpservercheck`, `nbshape`, `sarifcheck`,
`pjhookcheck`, `approvchainlint`) escalate INFO findings and the no-input case.
`pjhookcheck` and `approvchainlint` sit at the stricter end of that family:
under `--strict`, INFO escalates to `unhealthy` (rc 2) rather than the
`needs-attention` (rc 1) that `elevatescan`, `delegcheck`, and `mcpservercheck`
adopt. Callers relying on `--strict` should read the per-tool `--help` to know
which of the three the flag maps to.

## Structured output

Every tool that produces structured output emits it on **stdout** and reserves
**stderr** for human-readable diagnostics (labels, error prefixes, summary lines).
A caller that pipes stdout into `jq` or `json.loads` will never see the tool's
own chatter mixed in.

The flag names and JSON top-level shapes still diverge on shape, but the flag
name is now unified: all three severity-tiered linters (`envcheck` 2026-08-13,
`jwtcheck` 2026-08-14, `reqcheck` 2026-08-15) accept both `--json` and
`--format json`, matching the boolean `--json` shipped by `licensechain`
(2026-07-26), `aicontribcheck` (2026-08-02), `skillcheck` (2026-08-09),
`agentmdlint` (2026-08-16), `oraclecheck` (2026-08-23), `elevatescan`
(2026-08-31), `delegcheck` (2026-09-06), `mcpservercheck` (2026-09-13),
`nbshape` (2026-09-18), `sarifcheck` (2026-09-18), `pjhookcheck`
(2026-09-20), and `approvchainlint` (2026-09-27). Shape convergence remains
the next open target.

| Tool           | Flag                | Top-level JSON shape                                          |
|----------------|---------------------|---------------------------------------------------------------|
| jsonlcheck     | (no JSON mode yet)  | - |
| envcheck       | `--json` (or `--format json`) | NDJSON: one `{"code","line","column","message","file",...}` per line |
| jwtcheck       | `--json` (or `--format json`) | JSON array of `{"rule","severity","message","key","line","col","source"}` |
| reqcheck       | `--json` (or `--format json`) | JSON array of finding objects (`Finding.to_dict()`)           |
| licensechain   | `--json`            | JSON object: `{"tool","version","source","findings":[...],"summary":{...}}` (0.3.0+; `tool` and `version` additive, pre-0.3.0 keys retained) |
| aicontribcheck | `--json`            | JSON object: `{"tool","version","source","findings":[...],"summary":{...}}` plus pre-0.3.0 keys (`root`, `verdict`, `files`, `required_disclosures`, `required_attributions`, `tools_named`) (0.3.0+; `tool`, `version`, `source`, and the flat top-level `findings` list are additive; pre-0.3.0 keys retained) |
| skillcheck     | `--json`            | JSON object: full report (`files_scanned`, `verdict`, ...)       |
| agentmdlint    | `--json`            | JSON object: full report (`tool`, `version`, `root`, `files`, `findings`, `summary`, `verdict`, `exit_code`) |
| oraclecheck    | `--json`            | JSON object: full report (`files_scanned`, `files_errored`, `findings`, `findings_total`, `findings_visible`, `verdict`, `errors`, `exit_code`) |
| elevatescan    | `--json`            | JSON object: full report (`files_scanned`, `findings`, `findings_total`, `findings_visible`, `counts`, `verdict`, `errors`) |
| delegcheck     | `--json`            | JSON object: full report (`files_scanned`, `verdict`, `counts`, `findings`, ...) |
| mcpservercheck | `--json`            | JSON object: full report (`files_scanned`, `verdict`, `counts`, `findings`, ...) |
| nbshape        | `--json`            | JSON object: full report (`tool`, `verdict`, `files_scanned`, `files_scored`, `files_unknown`, `counts`, `findings`, `errors`, `exit_code`) |
| sarifcheck     | `--json`            | JSON object: full report (`tool`, `version`, `verdict`, `files_scanned`, `counts`, `findings`, `errors`, `profiles`, `limits`, `notes`, `disclaimer`, `partial`) |
| pjhookcheck    | `--json`            | JSON object: full report (`tool`, `verdict`, `files_scanned`, `findings`, `errors`) |
| approvchainlint| `--json`            | JSON object: full report (`tool`, `version`, `verdict`, `files_scanned`, `findings`, `summary`, `errors`) |

Consumers should pin the tool version and pin the shape they parse. The next
convergence pass is expected to standardise on `--json` (boolean) and a wrapping
object of shape `{"tool", "version", "source", "findings": [...], "summary": {...}}`
across all severity-based linters; when that lands for a given tool it will be a
major-version bump per tool whenever the delta is a breaking restructuring (NDJSON
or array to wrapping object), and a minor-version bump when the delta is purely
additive (new top-level keys only, pre-existing keys retained).

Progress trail. `licensechain` 0.3.0 (2026-10-10) opened the shape-convergence
campaign as the additive-only case: pre-0.3.0 shipped `{source, findings,
summary}`, 0.3.0 adds `tool` and `version` at the top level with every
pre-existing key retained, and a `test_shared_contract.py`
`test_json_mode_top_level_shape` lock asserts both the new keys and the
pre-existing keys so a future revert surfaces as a shared-contract break.
`aicontribcheck` 0.3.0 (2026-10-13) followed as the second additive-only case:
pre-0.3.0 shipped `{root, verdict, files, required_disclosures,
required_attributions, tools_named, summary}` (with findings only reachable
by walking `files[].findings`), 0.3.0 adds `tool`, `version`, `source`, and a
flat top-level `findings` list; every pre-0.3.0 key retained; the same
`test_json_mode_top_level_shape` shared-contract invariant locks both
directions. `agentmdlint` and `sarifcheck` already ship a top-level
`{tool, version, ...}` pair (from their first publication) and remain
compliant on that axis. The remaining severity-based linters (`envcheck`
NDJSON, `jwtcheck` JSON array, `reqcheck` JSON array, `skillcheck`,
`oraclecheck`, `elevatescan`, `delegcheck`, `mcpservercheck`, `nbshape`)
still diverge on shape; each is a separate convergence tend and will carry
its own version-bump classification.

## Stdout / stderr discipline

The intended discipline:

- Findings and structured output -> **stdout**.
- Diagnostics, labels, error prefixes, summary lines -> **stderr**.
- A silent `rc=0` run should produce no stdout (except structured output when
  requested); tools that print a "no issues" summary do so to stderr.

Empirical clean-run stdout audit (2026-09-23). Every tool was probed against a
known-clean fixture (the same command anchored in the exit-code evidence table
above, or the explicit-allow/explicit-safe fixture that resolves each
verdict-based tool to rc=0), with `--json` NOT requested, and stdout byte count
captured. `-` = complies (0 bytes on stdout on silent clean run):

| Tool           | Clean fixture                             | Clean rc | Clean stdout                                                                             | Complies |
|----------------|-------------------------------------------|----------|------------------------------------------------------------------------------------------|----------|
| jsonlcheck     | `examples/ok.jsonl`                       | 0        | 0 bytes                                                                                  | yes      |
| envcheck       | `examples/template.env` (twice)           | 0        | 0 bytes                                                                                  | yes      |
| jwtcheck       | `examples/ok.env`                         | 0        | 0 bytes                                                                                  | yes      |
| reqcheck       | `examples/ok.txt`                         | 0        | 12 bytes (`no findings`)                                                                 | no       |
| licensechain   | `examples/ok_chain.json`                  | 0        | 62 bytes (report header + `no findings.`)                                                | no       |
| aicontribcheck | `tests/fixtures/allow_repo`               | 0        | 256 bytes (5-line `aicontribcheck ::` report)                                            | no       |
| skillcheck     | `tests/fixtures/safe_skill`               | 0        | 100 bytes (verdict line + counts + `findings: (none)`)                                   | no       |
| agentmdlint    | `examples/healthy_AGENTS.md`              | 0        | 115 bytes (5-line report: tool/version, root, files, verdict, `no findings`)             | no       |
| oraclecheck    | `examples/healthy_test.py`                | 0        | 65 bytes (`verdict: healthy (files_scanned=..., findings=..., exit=0)`)                  | no       |
| elevatescan    | `examples/healthy_notes.md`               | 0        | 110 bytes (3-line summary: `verdict`, counts, visible/hidden)                            | no       |
| delegcheck     | `examples/healthy_delegation.json`        | 0        | 110 bytes (3-line summary matching the elevatescan shape)                                | no       |
| mcpservercheck | `examples/healthy_mcp.json`               | 0        | 110 bytes (3-line summary matching the elevatescan shape)                                | no       |
| nbshape        | `examples/healthy_notebook.ipynb`         | 0        | 0 bytes                                                                                  | yes      |
| sarifcheck     | `examples/healthy_results.sarif`          | 0        | 0 bytes                                                                                  | yes      |

At the 2026-09-23 audit, five tools upheld the "empty stdout on silent clean
run" discipline (`jsonlcheck`, `envcheck`, `jwtcheck`, `nbshape`, `sarifcheck`)
and nine did not (`reqcheck`, `licensechain`, `aicontribcheck`, `skillcheck`,
`agentmdlint`, `oraclecheck`, `elevatescan`, `delegcheck`, `mcpservercheck`),
each emitting a clean-run summary line or multi-line report to stdout. The
nine-tool convergence campaign ran from 2026-09-24 (reqcheck v0.2.0) to
2026-10-08 (mcpservercheck v0.2.0, campaign close) as a minor-version bump
per tool: the exit code is computed before printing so the CLI can route on
it; `rc == 0` text output routes to stderr; `rc != 0` text output continues
to go to stdout; the `--json` payload continues to be written to stdout
byte-for-byte unchanged when requested. Post-campaign empirical re-audit
2026-10-09: all fourteen originally-audited tools return 0 bytes on stdout
for a silent `rc=0` clean run against the same fixtures listed above; the
three-line verdict / counts / visibility summary (or whichever text shape
the tool prints) now routes to stderr. A CI job that pipes the tool's
stdout into `jq` or `test -s` can now rely on the discipline uniformly
across the fourteen linters without having to pass `--json` to force JSON
mode. The historical audit table above is preserved as the dated empirical
record that drove the campaign.

## `--version`

Present on all sixteen linters (`jsonlcheck`, `envcheck`, `jwtcheck`, `reqcheck`,
`licensechain`, `aicontribcheck`, `skillcheck`, `agentmdlint`, `oraclecheck`,
`elevatescan`, `delegcheck`, `mcpservercheck`, `nbshape`, `sarifcheck`,
`pjhookcheck`, `approvchainlint`) and prints `<tool> <version>` then exits `0`.
The `envcheck` and `reqcheck` additions landed 2026-08-12 and closed the
earlier parity gap; `agentmdlint`, `oraclecheck`, `elevatescan`, `delegcheck`,
`mcpservercheck`, `nbshape`, `sarifcheck`, `pjhookcheck`, and `approvchainlint`
shipped `--version` from their first published release.

## Input encoding

Every linter assumes UTF-8 input and reports invalid UTF-8 as a structured error
rather than crashing. Where a tool accepts stdin, `-` is the sentinel path.

## What CI consumers can rely on today

1. `python -m <tool> --help` returns `0`.
2. `python -m <tool>` with a clean input returns `0` (with the noted `aicontribcheck`
   verdict caveat).
3. `python -m <tool>` with findings returns non-zero.
4. Structured output is on stdout; diagnostics on stderr.
5. Tools are stdlib-only, so `pip install` is not required to run any of them from
   a clean clone.

The finer distinctions - severity tiering in the exit code, the exact JSON shape,
`--version` availability - are per-tool and documented above.

## What is planned to converge

On the maintenance backlog:

- ~~Unify `--json` vs `--format json` on a single flag name.~~ Done 2026-08-15:
  all three severity-tiered linters now accept `--json` (envcheck 2026-08-13,
  jwtcheck 2026-08-14, reqcheck 2026-08-15); `--format json` is retained as an
  alias for existing callers.
- Unify the JSON top-level shape (wrapping object with `tool`, `source`, `findings`,
  `summary`).
- Bring severity-based linters onto Convention B (severity-tiered exit codes).
- ~~Add a per-tool test asserting the shared-invariants section above.~~ Done
  2026-09-18 for the first fourteen linters and extended to `pjhookcheck`
  on first publication 2026-09-20 and `approvchainlint` on first publication
  2026-09-27: all sixteen linters carry
  `tests/test_shared_contract.py` locking the three invariants (jsonlcheck /
  envcheck / jwtcheck / reqcheck / licensechain / aicontribcheck /
  skillcheck across 2026-08-19..2026-08-27; `agentmdlint` 2026-08-29;
  `oraclecheck` 2026-09-01; `elevatescan` 2026-09-03; `delegcheck`
  2026-09-09; `mcpservercheck` 2026-09-15; `nbshape` 2026-09-18;
  `sarifcheck` 2026-09-18; `pjhookcheck` 2026-09-20; `approvchainlint`
  2026-09-27).
