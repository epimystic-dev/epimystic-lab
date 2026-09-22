# pjhookcheck

Offline static linter for `package.json` lifecycle-hook and install-time
supply-chain shapes.

Zero dependencies, pure Python standard library. Python 3.10+.

## The problem

npm-family package managers (npm, pnpm, yarn, bun) run the `preinstall`,
`install`, `postinstall`, `prepare`, `preprepare`, `prepublishOnly`,
`prepack`, and `postpack` scripts declared in `package.json` every time
a user runs a plain install. That is a shell interpreter running author-
supplied code on the machine of every consumer, before any application
code has been imported.

Recent field evidence shows that the *hook configuration alone*, not any
package content, is enough to steer downstream execution:

- The AUR 400-package post-install compromise reported in September 2026
  demonstrates that a `postinstall` shim was sufficient to distribute
  malware to every consumer of the affected packages.
- The `pino-SDK-v2` exfiltration and the Shai-Hulud v2 npm supply-chain
  wave both used lifecycle hooks to read `.env` at install time.
- arXiv 2609.03884 shows that lifecycle-hook configuration alone was
  enough to compromise all seven evaluated AI agent harnesses, with
  per-harness success up to 92.5 percent.
- A companion survey in arXiv 2609.07360 measured a 16 percent
  security-defect rate across 3,171 repositories, with install-time
  hooks routinely shipping without a lockfile or any pre-install check.

`pjhookcheck` reads a `package.json` before it is committed or installed
and reports twelve install-time shape defects across two surfaces:
lifecycle-hook command lines and dependency-specifier shapes.

## Install and run

    git clone <this repo>
    cd projects/2026-09-20_pjhookcheck
    python -m pjhookcheck examples/healthy_package.json    # rc 0
    python -m pjhookcheck examples/weak_package.json       # rc 2, findings on stdout

No install step is required to run it - it is standard-library only. To
install it as a command:

    python -m pip install -e .
    pjhookcheck package.json

### Usage

    python -m pjhookcheck [PATH ...] [options]

`PATH` may be a `.json` file or a directory. When it is a directory the
walker matches `package.json` and `**/package.json` by default; add
`--glob PATTERN` to widen.

| Flag | Effect |
|---|---|
| `--json` | Emit the structured report on stdout instead of text |
| `--strict` | Escalate INFO findings to unhealthy; no files scanned becomes rc 2 |
| `--include-info` | Show INFO findings (hidden by default) |
| `--disable CODE` | Turn off one rule; repeatable |
| `--list-rules` | Print the rule registry and exit 0 |
| `--glob PAT` | Extra glob pattern when walking directories; repeatable |
| `--max-files N` | Upper bound on files scanned (default 5000) |
| `--max-bytes N` | Per-file byte cap (default 5 MiB) |
| `--version` | Print the version and exit 0 |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `healthy` - no findings at or above the active severity filter |
| 1 | `needs-attention` - MEDIUM findings only (or INFO under `--include-info`) |
| 2 | `unhealthy` - at least one HIGH finding, INFO under `--strict`, or a read/parse error |

Findings go to **stdout**; all labels, summaries, and diagnostics go to
**stderr**, so `python -m pjhookcheck --json p.json | jq` is safe.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| PJH-001 | HIGH   | Lifecycle hook pipes a remote fetch into a shell interpreter (`curl \| sh`, `wget \| bash`, `iwr \| iex`, `Invoke-WebRequest \| Invoke-Expression`) |
| PJH-002 | HIGH   | Lifecycle hook uses an inline-eval interpreter flag (`node -e`, `python -c`, `sh -c`, `bash -c`, `powershell -Command`) |
| PJH-003 | HIGH   | Lifecycle hook decodes an encoded blob and passes the result to a shell or eval site (`base64 -d \| sh`, `Buffer.from(...,'base64').toString`, long `atob(...)`) |
| PJH-004 | HIGH   | Dependency specifier is a git URL, GitHub / GitLab / Bitbucket / Gist shorthand, or a tarball URL - not registry-plus-hash pinned |
| PJH-005 | HIGH   | `file:` dependency specifier escapes the repository root (absolute, tilde, `..`, or drive-lettered path) |
| PJH-006 | HIGH   | Lifecycle hook references a sensitive user or system path (`~/.ssh/`, `~/.bashrc`, `~/.zshrc`, `~/.npmrc`, `~/.aws/`, `/etc/`, `/usr/`, and equivalents) |
| PJH-007 | MEDIUM | Lifecycle hook installs a package globally (`npm i -g`, `yarn global add`, `pnpm add -g`, `bun add -g`) |
| PJH-008 | MEDIUM | Lifecycle hook prints an environment variable with a credential-shape name (`echo $NPM_TOKEN`, `printf %s ${GITHUB_TOKEN}`, and equivalents) |
| PJH-009 | MEDIUM | Dependency version specifier has no security floor (`latest`, `*`, `x`, `1.x`, `>=0.0.0`, and equivalents) |
| PJH-010 | MEDIUM | `bundleDependencies` / `bundledDependencies` present - transitive dependencies bundled here are hidden from the lockfile and audit tools |
| PJH-011 | MEDIUM | Lifecycle hook body is heavily obfuscated (dense hex or unicode escapes, single line over 400 characters, or a 200+ character base64-shape run) |
| PJH-012 | INFO   | `packageManager` field absent - corepack cannot pin the CLI, so install-time behaviour depends on which CLI is on PATH (hidden by default; visible with `--include-info`) |

Split: **6 HIGH, 5 MEDIUM, 1 INFO**.

## What this tool does NOT do

- It does not execute anything it reads.
- It does not open a network connection.
- It does not know about the *contents* of `node_modules/` or the
  lockfile - lockfile hygiene is a separate surface.
- It does not detect malicious *runtime* behaviour or arbitrary
  code-obfuscation shapes beyond a few well-known signals.
- It does not replace `npm audit`, `pip-audit`-adjacent CVE feeds, or
  a Software Bill of Materials.

A linter reports shapes. It cannot detect an attack, and a clean run
is not a safety certificate. Treat it as a pre-flight primitive: a
package.json that survives this pass has cleared the twelve shape
defects the rules encode, not "safe."

## Design notes

- **Zero dependencies.** Stdlib only, tested on Python 3.10+.
- **Deterministic output.** The findings are sorted by
  `(file, line, column, rule_id, property_path)` so the same input
  always produces the same output.
- **JSON path anchoring.** Findings carry a JSON property path
  (`scripts.postinstall`, `dependencies.foo`) as the primary anchor,
  plus a best-effort text line and column.
- **Diagnostics on stderr.** All summary and error text goes to stderr,
  so `--json ... | jq` and shell redirects behave.
- **No claim of completeness.** The rules cover well-documented shapes
  that have appeared in public incidents. Novel obfuscation of
  `preinstall` can bypass any rule the tool ships with, and detecting
  novel obfuscation is out of scope.

## Test suite

    python -m unittest discover -s tests

At time of writing the suite is 158 tests: types invariants, parse
helpers, per-rule positive-plus-negative discrimination across all
twelve rules with an adversarial-fixture-fires-every-rule global
invariant, scanner discovery and single-file behaviour, verdict rollup
and exit-code mapping, text and JSON report determinism, and
`python -m pjhookcheck` subprocess smoke tests.

## Provenance

This is an independent implementation. Rules are derived from public
specification text (npm and pnpm docs on `scripts` and dependency-URL
specifiers), from named public field incidents (the AUR 400-package
post-install compromise; the Shai-Hulud v2 and `pino-SDK-v2`
exfiltration campaigns), and from published research (arXiv 2609.03884
"A Blind Trust, the Bloody Thrust: When Attacker-Controlled Hook Updates
Steer AI Agent Harnesses"; arXiv 2609.07360 "Scanning the Harness: An
Empirical Study of Supply-Chain Defects in AI Coding-Agent
Configurations"). No reference implementation of an install-hook linter
was read, vendored, or mirrored. The tool is not affiliated with or
endorsed by any package manager, registry, or research group.

## License

MIT.

---

*Produced by a human-machine hybrid intelligence, under maker-checker.*
