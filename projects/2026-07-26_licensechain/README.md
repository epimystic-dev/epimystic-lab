# licensechain

Offline license-chain hygiene linter for AI supply chains.
Reads a JSON manifest describing a chain of components (typically
`dataset → model → application`) and reports missing licenses,
incompatible combinations, dropped copyleft obligations, share-alike
violations, non-commercial leakage, and RAIL-family use-restriction
propagation failures.

Zero runtime dependencies. Pure stdlib Python (3.10+). MIT licensed.

---

## The problem it solves

AI supply chains routinely combine artifacts under mismatched licenses:
a share-alike dataset trains a model released under a permissive
license; a non-commercial dataset trains a model shipped commercially;
a copyleft library's obligations quietly drop when its outputs are
repackaged; a `NOASSERTION` upstream leaves an entire chain
unauditable. arXiv 2607.20300 ("Don't Trust the Label: License
Laundering in AI Supply Chains", 2026-07-23) traced 232,270 published
`dataset → model → application` chains and quantified the pattern
empirically: a large fraction propagate a downstream license
inconsistent with the upstream.

`licensechain` is the small pre-publish primitive that answers
*"does my chain preserve its upstream obligations?"* -- entirely
offline, in a form that runs as a pre-commit hook, CI check, or agent
tool call. It is deliberately not a legal opinion, an SBOM generator,
or a license classifier: it is a hygiene linter for chains you have
already declared.

---

## Install

```
pip install .
```

That installs a `licensechain` console script and the `licensechain`
importable package. No runtime dependencies -- the whole thing is
Python stdlib.

Python 3.10 or newer is required (uses `from __future__ import
annotations`, `dataclasses.dataclass(frozen=True)`, and modern
type-hint syntax).

---

## Run

```
licensechain manifest.json
```

Exit codes:

| Code | Meaning                                                     |
|------|-------------------------------------------------------------|
| 0    | No findings above INFO.                                     |
| 1    | Warnings only (obligations to confirm, unknown ids, etc.).  |
| 2    | At least one error, or the manifest could not be loaded.    |

Flags:

- `--json` -- emit findings as JSON instead of text.
- `--strict` -- promote warnings to errors for exit-code purposes.
- `--include-info` -- surface `INFO` severity (e.g. orphan components).
- `-` (as `manifest` arg) -- read from stdin.

---

## Manifest schema

Manifests are JSON with a `version` (integer, currently `1`) and a
`chain` (list of component objects).

```json
{
  "version": 1,
  "chain": [
    {
      "name": "wiki-corpus",
      "role": "dataset",
      "license": "CC-BY-SA-4.0",
      "preserves_notices": true
    },
    {
      "name": "base-tokenizer",
      "role": "library",
      "license": "Apache-2.0",
      "preserves_notices": true
    },
    {
      "name": "base-model",
      "role": "model",
      "license": "CC-BY-SA-4.0",
      "preserves_notices": true,
      "trained_on": ["wiki-corpus"],
      "uses": ["base-tokenizer"]
    },
    {
      "name": "downstream-app",
      "role": "application",
      "license": "CC-BY-SA-4.0",
      "preserves_notices": true,
      "uses": ["base-model"]
    }
  ]
}
```

Fields per component:

| Field                | Type       | Default   | Meaning                                              |
|----------------------|------------|-----------|------------------------------------------------------|
| `name`               | string     | required  | Unique within the chain.                             |
| `role`               | string     | `"other"` | `dataset` / `model` / `application` / `library` / `other`. |
| `license`            | string     | omitted   | SPDX license expression (see below).                 |
| `preserves_notices`  | bool       | `false`   | True iff the component carries upstream notices.     |
| `commercial_use`     | bool       | `true`    | Whether commercial distribution / use is intended.   |
| `trained_on`         | list<str>  | `[]`      | Upstream `dataset` components (model-specific).      |
| `derived_from`       | list<str>  | `[]`      | Upstream derivation source (general).                |
| `uses`               | list<str>  | `[]`      | Upstream runtime dependency.                         |
| `notes`              | string     | omitted   | Free-form.                                           |

The three edge fields (`trained_on`, `derived_from`, `uses`) are
treated identically for compatibility purposes -- the distinction is
preserved only in the report so a reader can locate the failing edge.

### SPDX license expressions

`license` is parsed as a full SPDX 2.3 expression:

- Bare identifiers: `MIT`, `Apache-2.0`, `CC-BY-SA-4.0`.
- Or-later: `GPL-2.0+`.
- With exception: `GPL-2.0-or-later WITH Classpath-exception-2.0`.
- Dual: `MIT OR Apache-2.0` (user picks; downstream compatibility
  succeeds if *any* branch is compatible with an upstream).
- Combined: `MIT AND CC-BY-4.0` (both apply; both must be compatible).
- Parenthesized groups: `(MIT OR Apache-2.0) AND CC-BY-4.0`.
- Custom refs: `LicenseRef-InternalPolicy` (flagged by LIC-010).

Precedence is highest-to-lowest `+` > `WITH` > `AND` > `OR`, per SPDX
spec 10.1. Operators are case-sensitive (uppercase `AND` / `OR` /
`WITH`).

---

## Rules

Every rule fires deterministically; the report is sorted by
`(component-in-chain-order, rule, upstream)`.

| Rule    | Severity | Trigger                                                                             |
|---------|----------|-------------------------------------------------------------------------------------|
| LIC-001 | ERROR    | Component declares no license at all.                                               |
| LIC-002 | WARN     | License expression parses but names an SPDX id not in the curated table.            |
| LIC-003 | ERROR    | License string does not parse as an SPDX expression.                                |
| LIC-004 | ERROR    | Copyleft dropped: upstream is strong or network copyleft, downstream is not compatible. |
| LIC-005 | WARN     | Upstream requires notices; downstream did not declare `preserves_notices: true`.    |
| LIC-006 | ERROR    | Share-alike upstream (CC-BY-SA, CDLA-Sharing, ODbL); downstream picks a different license. |
| LIC-007 | ERROR    | Other incompatibility: no-derivatives upstream, RAIL propagation drop, matrix miss. |
| LIC-008 | WARN     | Unversioned copyleft id (`GPL-2.0`, `GPL-3.0`, `LGPL-2.1`, `LGPL-3.0`, `AGPL-3.0`) -- ambiguous. |
| LIC-009 | ERROR    | Component declares `NOASSERTION` or `NONE`.                                         |
| LIC-010 | WARN     | Component uses a `LicenseRef-` identifier; auditor must inspect the referenced text. |
| LIC-011 | ERROR    | Non-commercial upstream, downstream declares `commercial_use: true`.                |
| LIC-012 | INFO     | Orphan component (no upstream and no downstream references it).                     |

---

## Example runs

**Clean chain** (all obligations preserved):

```
$ licensechain examples/ok_chain.json
# licensechain report for examples/ok_chain.json
no findings.
$ echo $?
0
```

**Bad chain** (dropped obligations):

```
$ licensechain examples/bad_chain.json
# licensechain report for examples/bad_chain.json
[ERROR] LIC-009  mystery-lib: component 'mystery-lib' declares its license
                 as 'NOASSERTION' ...
[ERROR] LIC-004  trained-model <- gpl-lib: copyleft obligation dropped:
                 'gpl-lib' (GPL-3.0-only) is strong-copyleft but downstream
                 'trained-model' declares Apache-2.0 ...
[WARN ] LIC-005  trained-model <- gpl-lib: 'gpl-lib' (GPL-3.0-only)
                 requires attribution / notice preservation ...
[WARN ] LIC-005  trained-model <- nc-dataset: ...
[WARN ] LIC-005  trained-model <- sa-corpus: ...
[ERROR] LIC-006  trained-model <- sa-corpus: share-alike violated:
                 'sa-corpus' (CC-BY-SA-4.0) requires the same license
                 downstream but 'trained-model' declares Apache-2.0
[ERROR] LIC-011  trained-model <- nc-dataset: 'nc-dataset' is licensed
                 under CC-BY-NC-4.0 which forbids commercial use, but
                 downstream 'trained-model' declares commercial_use: true
summary: 4 error(s), 3 warning(s), 0 info
$ echo $?
2
```

Findings are ordered by component (chain order), then rule, then upstream
name -- so the same manifest always produces the same report.

**JSON output** (machine-readable):

```
$ licensechain --json examples/bad_chain.json | jq '.summary'
{
  "error": 4,
  "info": 0,
  "total": 7,
  "warn": 3
}
```

---

## Scope and limits (honest)

`licensechain` is a hygiene linter, not a legal opinion:

- **Not a substitute for legal review.** License compatibility is a
  legal question that depends on jurisdiction, distribution model, and
  the specific license text. This linter surfaces likely problems for
  humans to review; it does not clear a chain for release.
- **SPDX table is curated, not complete.** The knowledge table covers
  ~45 identifiers that appear in practice on AI artifacts (permissive,
  GPL family, LGPL, MPL, EPL, CC family, CDLA, ODbL, RAIL family,
  NOASSERTION / NONE markers). Unknown ids fire LIC-002 rather than
  silently pass. See `licensechain/spdx_data.py` for the full list.
- **Compatibility matrix is heuristic.** Strong-copyleft compatibility
  follows the widely-published FSF matrix (GPL-2.0-or-later upgrades
  to GPL-3.0, GPL-3.0 upgrades to AGPL, etc.); other cases err on the
  side of surfacing a warning rather than silently permitting.
- **RAIL / OpenRAIL family is heuristic-only.** RAIL identifiers are
  not SPDX-official and their obligations are use-restriction clauses
  that vary per model. LIC-007 fires when a RAIL upstream feeds a
  downstream that does not carry a RAIL id -- an auditor still has to
  read both licenses.
- **`preserves_notices` is a self-declaration.** The linter cannot
  verify that a component actually preserves notices; it only checks
  the declared flag. Downstream tooling (e.g. NOTICE-file diff)
  should independently confirm.
- **No SBOM generation.** licensechain reads a chain you have already
  declared; it does not discover components. Use it alongside an
  SBOM tool (Syft, Trivy, etc.) that produces the chain.
- **No license text classification.** licensechain does not read
  LICENSE files and infer an SPDX id. Callers must declare the SPDX
  expression explicitly.
- **No network calls.** Everything runs offline against the curated
  table.

---

## Why a small primitive

The lab's hygiene-linter family already covers file-contents hygiene
(`envcheck`, `jsonlcheck`, `jwtcheck`), eval-stream hygiene
(`jsonldiff`, `jsonlsample`), and install-manifest hygiene
(`reqcheck`). `licensechain` extends the family to license-chain
hygiene -- one of the last hygiene surfaces that AI supply chains
lack a small offline tool for.

---

## Development

```
python -m unittest discover -s tests -v
```

131 tests across:

- SPDX id table and compatibility matrix (28 tests).
- SPDX expression parser (32 tests, including WITH / OR / AND
  precedence, LicenseRef restrictions, unclosed parens, invalid
  characters, whitespace tolerance, case sensitivity of operators).
- Manifest loader (18 tests, including UTF-8 BOM, cycle detection,
  dangling references, duplicate names, unsupported version).
- Rule engine (28 tests, positive-and-negative case per rule).
- CLI (14 tests, exit codes, `--strict`, `--json`, `--include-info`,
  stdin input, missing file).
- End-to-end fixture smoke tests (3 tests).

No dependencies beyond the stdlib.

---

## Provenance

Clean-room implementation. Built from:

- SPDX License Expression Syntax spec, v2.3 (public spec text).
- SPDX License List identifier catalog (public identifier list).
- FSF public commentary on GPL family compatibility.
- Creative Commons license summary pages (public html).
- BigScience OpenRAIL-M public description.
- arXiv 2607.20300 -- consulted only for framing and motivation of
  the license-laundering problem class; no method, tooling, or code
  from the paper was read or used. This project is an independent
  implementation, not affiliated with or endorsed by the paper's
  authors.

MIT licensed.

Authored by a human-machine hybrid intelligence as part of the
epimystic-lab weekly build cycle.
