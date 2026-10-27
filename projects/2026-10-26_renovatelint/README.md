# renovatelint

Static linter for [Renovate bot](https://docs.renovatebot.com/) config files. Zero dependencies. Python 3.9+.

> *Part of [epimystic-lab](https://github.com/epimystic-dev/epimystic-lab) - small, offline, stdlib-only hygiene linters.*
>
> **Independent implementation, not affiliated with or endorsed by Mend / Renovate, the Renovate maintainer community, or any of the cited security publications.**

## What it does

`renovatelint` reads one of:

- `renovate.json`
- `renovate.json5` / `.renovaterc.json5` (JSONC subset)
- `.renovaterc` / `.renovaterc.json`
- `package.json` with a top-level `renovate` key

and flags twelve shape defects on a 5 HIGH / 5 MEDIUM / 2 INFO split. The rules are shape-only: a Renovate config is a developer-authored artifact that lives on disk and governs when and how dependency updates auto-merge. Shape defects at that layer are detectable statically.

## Why it exists

Renovate is the dominant open-source dependency-update bot. The October 21 2026 LiteLLM supply-chain attack ([Help Net Security 2026-10-22](https://www.helpnetsecurity.com/2026/10/22/litellm-compromised-supply-chain-attack-pypi-docker/), [Socket 2026-10](https://socket.dev/blog/litellm-compromise), [SOCRadar 2026-10](https://socradar.io/blog/litellm-supply-chain-attack-pypi-docker/), [Aviatrix 2026-10](https://aviatrix.ai/threat-research-center/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/)) escalated the fault class the config can prevent: attackers pushed a trojanized wheel (LiteLLM 1.107.0) through the official pipeline and roughly 49,000 installs harvested AWS / Azure / GCP / Kubernetes credentials, AI provider secrets, and developer keys in the ~104-minute exposure window before yank. The 2026 Renovate security-mode posture ([Compass Security 2025-05](https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/), [safeguard.sh 2026](https://safeguard.sh/resources/blog/renovate-2026-security-mode-field-test), [systemshardening.com](https://www.systemshardening.com/articles/cicd/renovate-dependabot-security/)) names the shape family explicitly: a 14-day `minimumReleaseAge` quarantine would have let the registry yank the malicious wheel before any Renovate PR auto-merged.

## Install

Clone the repo and run from the project folder (zero dependencies):

```
python -m renovatelint path/to/renovate.json
```

Or install with pip:

```
pip install -e .
renovatelint path/to/renovate.json
```

## Usage

```
python -m renovatelint [--help] [--version] [--json] [--strict]
                       [--include-info] [--disable RULE_ID]...
                       [--only RULE_ID]... [--min-quarantine-days N]
                       paths...
```

Flag reference:

| Flag | Behaviour |
|---|---|
| `--help` | Print help text, exit 0. |
| `--version` | Print `renovatelint <version>`, exit 0. |
| `--json` | Emit a structured JSON report on stdout (shape: `{tool, version, source, verdict, files_scanned, findings[], error, summary}`; see note below). |
| `--strict` | Surface INFO findings and treat an INFO-only outcome as `needs-attention` (rc 1). |
| `--include-info` | Surface INFO findings without upgrading the verdict. |
| `--disable RULE_ID` | Repeatable. Suppress a specific rule. |
| `--only RULE_ID` | Repeatable. Run only the given rules. |
| `--min-quarantine-days N` | RNV-010 floor in days (default 7, matching the Compass Security / safeguard.sh 2026 recommendation; raise to 14 for the preferred value). |

Exit codes follow the lab's Convention B (severity-tiered rollup):

| Verdict | rc |
|---|---|
| `healthy` | 0 |
| `needs-attention` | 1 |
| `unhealthy` | 2 |
| `unknown` (no files scanned) | 1 (or 2 under `--strict`) |

Discipline (lab-wide): structured output always on stdout; diagnostics (summary line, labels) on stderr. A silent `rc=0` clean run produces no bytes on stdout - the summary routes to stderr - so a CI job can safely pipe `stdout` into `jq` without a `--json` flag.

JSON shape (since 0.2.0): one wrapping object with `tool`, `version`, `source` (comma-joined CLI paths), `findings` (per-rule hits), and `summary` (dict with `total_findings`, `files_scanned`, and `by_severity` keyed `HIGH` / `MEDIUM` / `INFO`), alongside the pre-0.2.0 keys `verdict`, `files_scanned`, `findings`, and `error`. The wrapping shape matches the lab-wide convergence target documented in `docs/CONVENTIONS.md`, so a log aggregator can tell renovatelint output apart from a sibling tool's without out-of-band knowledge. Pre-0.2.0 pinned on `{tool, version, verdict, files_scanned, findings[], error}`; those keys all remain so pinned consumers continue to parse.

## Rules

### HIGH

- **RNV-001** - `enabled: false` at the document root (stealth-off). The whole config is silently disabled: no vulnerability-driven PRs, no update PRs, no audit trail of inaction. A deleted file is louder than a disabled one.
- **RNV-002** - Root `automerge: true` with no `minimumReleaseAge` set anywhere (unguarded auto-merge). Direct response to the LiteLLM 2026 shape: without a quarantine window, Renovate can auto-merge a release the registry has not had time to yank.
- **RNV-003** - `extends` entry references a repo preset (`github>owner/config`, `gitlab>owner/config`, raw URL, etc.) without a `#<tag>` or `@<40-hex-sha>` pin (mutable supply-chain source).
- **RNV-004** - Credential-shaped literal (JWT, AWS access key, GitHub token, PEM private-key header, bearer / api-key assignment) inlined under `hostRules` / `token` / `repositoryToken` / `env` / `customEnvVariables`.
- **RNV-005** - `allowedPostUpgradeCommands` entry pipes a network fetch into a shell interpreter (`curl ... | bash`, `wget ... | sh`, `bash -c "$(curl ...)"`, `iwr | pwsh`). Fetch-and-exec is the dominant 2026 supply-chain shape.

### MEDIUM

- **RNV-006** - Hidden-character class (Plane 14 TAG, bidi overrides, zero-width, mid-string BOM, control, PUA) in any string value. Invisible to a human reviewer; reaches the shell / tokenizer / parser on execution.
- **RNV-007** - `packageRules` entry has `automerge: true` without `matchUpdateTypes` restricted to the safe set (`patch`, `pin`, `digest`, `lockFileMaintenance`, `pinDigest`). Over-broad auto-merge includes major-version bumps where breaking changes land.
- **RNV-008** - `vulnerabilityAlerts.enabled: false` or `osvVulnerabilityAlerts: false` (silently drops the vulnerability-driven PR path).
- **RNV-009** - `allowedPostUpgradeCommands` has non-empty entries (execution surface present; review required even when no fetch-and-exec is detected).
- **RNV-010** - `minimumReleaseAge` set but shorter than 7 days (the Compass Security / safeguard.sh 2026 industry-recommendation floor; the preferred value is 14 days).

### INFO

- **RNV-011** - Missing `$schema` reference (no editor-time validation surface).
- **RNV-012** - Missing `timezone` field (cross-TZ schedule drift).

INFO rules are hidden by default. Surface them with `--include-info` (no verdict change) or `--strict` (upgrades verdict to `needs-attention`).

## Honest scope and limits

- Rule semantics are **shape-only**. The tool does not resolve `extends` presets at scan time, does not fetch remote URLs, does not evaluate expressions. It reports what the config *says*; a dynamic Renovate run can still refuse to auto-merge for reasons the config does not surface.
- The parser is a JSONC superset of plain JSON (comments, trailing commas). Full JSON5 (unquoted keys, single-quoted strings) is **not** supported; a `.json5` config using those features surfaces as a parse error.
- The RNV-003 pin check accepts any `#<text>` suffix as "pinned" and does not distinguish a tag from a SHA. For the strongest pin, use `@<40-hex-sha>`: a tag can be moved, a commit SHA cannot.
- The RNV-004 credential detector matches well-known literal shapes (JWT, AWS, GitHub, PEM, bearer assignment). An opaque high-entropy string without one of these shape markers will not fire.
- The RNV-010 default floor of 7 days is the practical minimum; raise to 14 via `--min-quarantine-days 14` for the preferred posture.
- The tool is stdlib-only; it does not integrate with any external advisory feed and does not resolve CVE references.

## Clean-room citation

Rules are derived from the public [Renovate documentation](https://docs.renovatebot.com/configuration-options/) and the public [Renovate preset documentation](https://docs.renovatebot.com/presets-config/); from the 2026 Renovate security-mode community posture ([Compass Security 2025-05](https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/), [safeguard.sh 2026](https://safeguard.sh/resources/blog/renovate-2026-security-mode-field-test), [safeguard.sh 2026 recipes](https://safeguard.sh/resources/blog/renovate-bot-config-recipes-2026), [systemshardening.com](https://www.systemshardening.com/articles/cicd/renovate-dependabot-security/)); and from public coverage of the October 21 2026 LiteLLM supply-chain attack ([Help Net Security](https://www.helpnetsecurity.com/2026/10/22/litellm-compromised-supply-chain-attack-pypi-docker/), [Socket](https://socket.dev/blog/litellm-compromise), [SOCRadar](https://socradar.io/blog/litellm-supply-chain-attack-pypi-docker/), [Aviatrix](https://aviatrix.ai/threat-research-center/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/)). No Mend- or community-published linter reference implementation was read, vendored, or mirrored.

## Running the tests

From the project directory:

```
python -m unittest discover -s tests
```

The suite covers package-surface invariants (the shared contract: `__version__`, `Severity`, `Verdict`, `Finding`, `ScanResult`, `ALL_RULES`, `Rule`, `main`), per-rule positive-and-negative discrimination, CLI flag handling, verdict rollup, text and JSON output shape, the parser, and a subprocess cp1252-console reporter invariant.

## License

MIT. See [LICENSE](LICENSE).

---

*Produced by Epimystic, a human-machine hybrid intelligence, under maker-checker.*
