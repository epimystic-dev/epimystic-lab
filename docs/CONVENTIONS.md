# CLI conventions for the epimystic-lab hygiene linters

The lab's hygiene linters share a shape by design: offline, stdlib-only, exit codes
meaningful in CI, structured output on request. This page documents what CI consumers
can rely on **today**, evidence-gathered from every published tool on 2026-08-11, and
names the divergences that a future convergence pass will close.

Tools in scope: `jsonlcheck`, `envcheck`, `jwtcheck`, `reqcheck`, `licensechain`,
`aicontribcheck`, `skillcheck`. `seedline` is a library (no CLI); `jsonldiff` and
`jsonlsample` are data-transformation tools rather than linters and follow only the
invocation and stdout/stderr rules below.

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
all six tools.

Evidence (run 2026-08-11):

| Tool           | Clean input command                                       | Findings command                                        | Clean rc | Findings rc |
|----------------|-----------------------------------------------------------|---------------------------------------------------------|----------|-------------|
| jsonlcheck     | `echo '{"a": 1}' \| python -m jsonlcheck -`               | `echo 'not json' \| python -m jsonlcheck -`             | 0        | 1           |
| envcheck       | `python -m envcheck examples/template.env examples/template.env` | `python -m envcheck examples/template.env examples/local.env` | 0 | 1     |
| jwtcheck       | `python -m jwtcheck examples/ok.env`                      | `python -m jwtcheck examples/bad.env`                   | 0        | 2           |
| reqcheck       | `python -m reqcheck examples/ok.txt`                      | `python -m reqcheck examples/bad.txt`                   | 0        | 2           |
| licensechain   | `python -m licensechain examples/ok_chain.json`           | `python -m licensechain examples/bad_chain.json`        | 0        | 2           |
| aicontribcheck | `python -m aicontribcheck <repo-with-empty-CONTRIBUTING>` | `python -m aicontribcheck <repo-with-ban-policy>`       | 1        | 2           |
| skillcheck     | `python -m skillcheck <safe-skill-repo>`                  | `python -m skillcheck <repo-with-unsafe-skill>`         | 1*       | 2           |

*`aicontribcheck` and `skillcheck` return `1` on a "clean" run against most inputs
because their exit codes encode a *verdict* (allowed / unknown / banned or
safe / unknown / unsafe) rather than a finding count - a caller wanting a strict
`0` requires an explicit allowed/safe verdict from the tool. This is a deliberate
verdict-based encoding, not a divergence to fix.

### The two current conventions for `1` vs `2`

Tools split between two conventions when a finding is present:

- **Convention A - severity-blind.** `rc=1` for any finding, `rc=2` reserved for
  usage/IO error. Followed by `jsonlcheck` and `envcheck`.
- **Convention B - severity-tiered.** `rc=1` for warnings only, `rc=2` for errors
  OR unrecoverable IO. Followed by `jwtcheck`, `reqcheck`, `licensechain`.
- **Convention C - verdict-based.** `rc` reflects a policy verdict rather than
  finding severity: `1` = `unknown` / `conditional`, `2` = `banned` / `conflict`
  (or `unsafe`). Used by `aicontribcheck` and `skillcheck`. This convention is a
  good fit for policy tools and is not on the convergence list.

A CI job that needs to distinguish "warnings" from "errors" today must know which
convention its tool follows. Convergence toward Convention B for all severity-based
linters is tracked as an open item in `MAINTENANCE_BACKLOG.md`; the convention here
locks in the current state so a future change lands as a documented breaking-change
release rather than as silent drift.

### `--strict`

Where a tool exposes `--strict` (`reqcheck`, `licensechain`, `aicontribcheck`,
`skillcheck`), the flag promotes lower-severity findings to error for exit-code
purposes. `jwtcheck` exposes an equivalent knob via `--severity error`.

## Structured output

Every tool that produces structured output emits it on **stdout** and reserves
**stderr** for human-readable diagnostics (labels, error prefixes, summary lines).
A caller that pipes stdout into `jq` or `json.loads` will never see the tool's
own chatter mixed in.

The flag names and JSON top-level shapes still diverge on shape, but the flag
name is now unified: all three severity-tiered linters (`envcheck` 2026-08-13,
`jwtcheck` 2026-08-14, `reqcheck` 2026-08-15) accept both `--json` and
`--format json`, matching the boolean `--json` already shipped by
`licensechain`, `aicontribcheck`, and `skillcheck`. Shape convergence remains
the next open target.

| Tool           | Flag                | Top-level JSON shape                                          |
|----------------|---------------------|---------------------------------------------------------------|
| jsonlcheck     | (no JSON mode yet)  | - |
| envcheck       | `--json` (or `--format json`) | NDJSON: one `{"code","line","column","message","file",...}` per line |
| jwtcheck       | `--json` (or `--format json`) | JSON array of `{"rule","severity","message","key","line","col","source"}` |
| reqcheck       | `--json` (or `--format json`) | JSON array of finding objects (`Finding.to_dict()`)           |
| licensechain   | `--json`            | JSON object: `{"source","findings":[...],"summary":{...}}`   |
| aicontribcheck | `--json`            | JSON object: full `RepoReport` (`files_scanned`, `verdict`, ...) |
| skillcheck     | `--json`            | JSON object: full report (`files_scanned`, `verdict`, ...)       |

Consumers should pin the tool version and pin the shape they parse. The next
convergence pass is expected to standardise on `--json` (boolean) and a wrapping
object of shape `{"tool", "version", "source", "findings": [...], "summary": {...}}`
across all severity-based linters; when that lands it will be a major-version bump
per tool, not a silent shape change.

## Stdout / stderr discipline

- Findings and structured output -> **stdout**.
- Diagnostics, labels, error prefixes, summary lines -> **stderr**.
- A silent `rc=0` run should produce no stdout (except structured output when
  requested); tools that print a "no issues" summary do so to stderr.

## `--version`

Present on all seven linters (`jsonlcheck`, `envcheck`, `jwtcheck`, `reqcheck`,
`licensechain`, `aicontribcheck`, `skillcheck`) and prints `<tool> <version>`
then exits `0`. The `envcheck` and `reqcheck` additions landed 2026-08-12 and
close the parity gap the earlier audit named.

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

Tracked in `MAINTENANCE_BACKLOG.md`:

- ~~Unify `--json` vs `--format json` on a single flag name.~~ Done 2026-08-15:
  all three severity-tiered linters now accept `--json` (envcheck 2026-08-13,
  jwtcheck 2026-08-14, reqcheck 2026-08-15); `--format json` is retained as an
  alias for existing callers.
- Unify the JSON top-level shape (wrapping object with `tool`, `source`, `findings`,
  `summary`).
- Bring severity-based linters onto Convention B (severity-tiered exit codes).
- Add a per-tool test asserting the shared-invariants section above.
