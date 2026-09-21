# sarifcheck

Offline static linter for SARIF 2.1.0 result files - the OASIS-standard JSON
that security scanners emit and that code-scanning platforms ingest.

Zero dependencies, pure Python standard library.

## The problem

A SARIF file can be well-formed JSON and still be unusable. It can:

* exceed a documented ingest ceiling, so the upload is truncated or rejected,
* carry absolute filesystem paths that never map back to repository files, so
  every finding lands on no line of code,
* reference rule metadata that is not present in the file, so results arrive
  with no description,
* omit the `partialFingerprints` that let a consumer deduplicate an alert
  across re-uploads, so every re-scan reopens every alert,
* leak the host layout of the build machine into paths and message text.

Each of these produces the same user-visible outcome: the scan ran, the upload
was accepted, and the findings are not where anyone will look for them. A green
pipeline becomes indistinguishable from a working one.

`sarifcheck` reads the file before it is uploaded and reports these shapes.

## Install and run

    git clone <this repo>
    cd projects/2026-09-18_sarifcheck
    python -m sarifcheck examples/healthy_results.sarif    # rc 0
    python -m sarifcheck examples/weak_results.sarif       # rc 2, findings on stdout

No install step is required to run it - it is standard-library-only. To install
it as a command:

    python -m pip install -e .
    sarifcheck results.sarif

### Usage

    python -m sarifcheck [PATH ...] [options]

`PATH` may be a `.sarif` / `.sarif.json` file or a directory, which is walked
for those extensions.

| Flag | Effect |
|---|---|
| `--json` | Emit the structured report on stdout instead of text |
| `--strict` | Escalate INFO findings to `needs-attention`; no files scanned becomes rc 2 |
| `--include-info` | Show INFO findings (hidden by default) |
| `--disable CODE` | Turn off one rule; repeatable |
| `--list-rules` | Print the rule registry and exit 0 |
| `--show-limits` | Print the ingest-limit table, with the date each number was recorded |
| `--limit NAME=VALUE` | Override one ingest limit |
| `--version` | Print the version and exit 0 |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `healthy` - no findings at or above the active severity filter |
| 1 | `needs-attention` - MEDIUM findings only |
| 2 | `unhealthy` - at least one HIGH finding, or the input could not be read |

Findings go to **stdout**; all labels, summaries and diagnostics go to
**stderr**, so `python -m sarifcheck --json x.sarif | jq` is safe.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| SRF-001 | HIGH | `version` is absent or is not `2.1.0` |
| SRF-002 | HIGH | `version` names a superseded or pre-release SARIF version |
| SRF-003 | MEDIUM | `$schema` is absent or does not name a known SARIF 2.1.0 schema URL |
| SRF-004 | HIGH | A result `artifactLocation.uri` is an absolute filesystem path, a `file:` URI, a drive letter, or a UNC path |
| SRF-005 | HIGH | An `artifactLocation.uri` is not a valid URI reference (backslash separator, raw space, malformed percent-escape) |
| SRF-006 | MEDIUM | A result message text contains a host-layout path shape |
| SRF-007 | MEDIUM | A build-path uri carries a home-directory-shaped segment. The account name is redacted in the finding |
| SRF-008 | MEDIUM | A result carries no rule reference in any spec-legal form (`ruleId`, `ruleIndex`, or `rule` reference object) |
| SRF-009 | MEDIUM | A `ruleId` does not resolve to a rule descriptor in this file |
| SRF-010 | INFO | A run carries no rule metadata at all, so reference integrity is not checkable |
| SRF-011 | HIGH | A `ruleIndex` is out of range or disagrees with its `ruleId` |
| SRF-012 | HIGH | A result has no resolvable message (no `message.text`, and no `message.id` resolving into the rule's `messageStrings`) |
| SRF-013 | MEDIUM | A result has an absent or empty `locations[]` |
| SRF-014 | HIGH | A region line or column is zero or negative. SARIF regions are 1-based |
| SRF-015 | HIGH | `kind` is not `fail` but `level` is set to something other than `none` |
| SRF-016 | HIGH | A documented hard ingest ceiling is exceeded |
| SRF-017 | MEDIUM | A documented soft ingest ceiling is exceeded |
| SRF-018 | MEDIUM | Results carry no `partialFingerprints`, so re-uploads produce duplicate alerts |
| SRF-019 | MEDIUM | A rule descriptor is missing `shortDescription`, `fullDescription`, or `help` text |
| SRF-020 | MEDIUM | A `uriBaseId` is referenced but not defined in `originalUriBaseIds` |
| SRF-021 | HIGH | An `originalUriBaseIds` chain is broken - it does not terminate at an absolute root |
| SRF-022 | MEDIUM | `automationDetails.id` is absent in a multi-run file, so matrix jobs overwrite each other's category |
| SRF-023 | HIGH | The gzip-compressed size exceeds the documented upload ceiling |
| SRF-024 | MEDIUM | A shape known to have tripped a real consumer |
| SRF-025 | INFO | A message text contains a token-shaped string |
| SRF-026 | INFO | Provenance metadata is absent (`tool.driver.semanticVersion`, `versionControlProvenance`) |
| SRF-027 | INFO | A run references external property files, so the report is not self-contained |

Run `python -m sarifcheck --list-rules` for the registry as the installed
version defines it.

## The ingest limits are data, not belief

Rules SRF-016, SRF-017 and SRF-023 compare against numeric ceilings published
by a consumer, not against anything in the OASIS specification. Those numbers
change. They therefore live in one table with the date each was recorded and
the URL it came from:

    python -m sarifcheck --show-limits

If your consumer differs, override rather than forking:

    python -m sarifcheck results.sarif --limit results_per_run=5000

## Honest scope

**What this does.** It reads a SARIF file as JSON and reports structural and
hygiene shapes, deterministically, offline.

**What it does not do.**

* It is **not a schema validator**. It does not implement the full SARIF JSON
  Schema, and a clean run does not mean the file is schema-valid.
* It **cannot tell you whether the findings inside the file are correct**. It
  reports on the envelope, not on the scanner's judgement.
* It **cannot confirm your consumer will accept the file**. The ingest limits
  are the ones published at the date in `--show-limits`; a consumer may apply
  others, or change them.
* It **does not detect attacks**, and a clean run is not a safety certificate.
* It executes nothing it reads and opens no network connection.

**Known false-positive modes.**

* SRF-004 is scoped to result and related locations, where a relative uri is
  expected. An absolute uri is legitimate at `workingDirectory.uri`,
  `originalUriBaseIds[*].uri`, and in `artifacts[].location` for some
  generators - those sites are handled by SRF-007 as a hygiene note rather
  than a spec violation.
* SRF-006 and SRF-025 are text-shape heuristics over free-form message text. A
  scanner whose job is to report paths or tokens will legitimately quote one.
  Disable per rule where that is the case.
* SRF-018 fires on generators that legitimately do not compute fingerprints.
  It is MEDIUM, not HIGH, for that reason.
* SRF-010 exists so that an absent `rules[]` array produces one INFO rather
  than a dangling-reference finding against every result.

## Citations

Rules are derived from these sources. Paths are read as text; nothing is
fetched at runtime.

* OASIS, *Static Analysis Results Interchange Format (SARIF) Version 2.1.0*,
  errata01 - the normative specification, including `ruleId` / `ruleIndex`
  semantics and `uriBaseId` resolution.
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html>
* SARIF support for code scanning - the required properties for ingestion.
  <https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning>
* Troubleshooting SARIF uploads: results exceed limit - the documented hard
  and soft ceilings compared by SRF-016, SRF-017 and SRF-023.
  <https://docs.github.com/en/code-security/code-scanning/troubleshooting-sarif-uploads/results-exceed-limit>
* An upstream fix in a maintained scanner whose SARIF URIs stayed absolute when
  the path crossed a symlink - evidence that SRF-004 describes a real defect.
  <https://github.com/awslabs/automated-security-helper/pull/450>
* An upstream issue in a maintained linter emitting an invalid `ruleIndex` -
  evidence for SRF-011.
  <https://github.com/terraform-linters/tflint/issues/2367>

This is an **independent implementation**, built from specification and
documentation text. No reference implementation of a SARIF validator was read
or vendored. It is **not affiliated with or endorsed by** OASIS, or by any
scanner or platform named above.

## Tests

    python -m unittest discover -s tests

## License

MIT - see [LICENSE](LICENSE).

---

*Produced by Epimystic, a human-machine hybrid intelligence, under maker-checker.*
