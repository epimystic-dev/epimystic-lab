# reqcheck

Offline supply-chain hygiene linter for `pip`-style requirements files.
Zero runtime dependencies. Pure Python standard library. MIT-licensed.

`reqcheck` reads a `requirements.txt`-shaped manifest and reports the
pre-install risks that `pip install` itself does not: unpinned versions,
mixed hash discipline, typosquat-shape package names, duplicate
declarations, `--trusted-host` (TLS-verification bypass), VCS URLs whose
ref is not a commit SHA, non-ASCII characters in package names
(homograph shape), and editable local installs that look like
committed-by-accident dev conveniences.

It runs entirely offline. There are no network calls, ever - the
typosquat check compares against a small curated static snapshot of
widely-installed Python packages.

## Why

AI coding agents and human developers alike routinely install
dependencies from a `requirements.txt` without pre-flight verification.
The pattern is systematic enough that the recent arXiv paper 2607.15143
("Setup Complete, Now You Are Compromised", 2026-07-16) frames it as a
supply-chain risk vector in its own right: install steps proceed with
unpinned versions, missing hashes, typosquat-shape names, non-TLS
custom indexes, and VCS URLs whose refs drift with the remote.

`reqcheck` is the small pre-install linter that answers "is this
manifest hygienic?" It runs as a pre-commit hook, a CI check, or an
agent tool call *before* `pip install` runs.

This is an independent clean-room implementation; it is not affiliated
with or endorsed by the authors of arXiv 2607.15143, whose paper is
cited only as motivation.

## Install

    python -m pip install .

or run directly from a clone:

    python -m reqcheck requirements.txt

Requires Python 3.8+. No third-party dependencies.

## Rules

| Rule       | Severity | What it catches                                                                                              |
|------------|----------|--------------------------------------------------------------------------------------------------------------|
| REQ-A001   | warn     | Unpinned requirement (no exact-version `==X.Y.Z`).                                                           |
| REQ-A002   | warn     | Missing `--hash=` on a requirement, when the file otherwise pins hashes (or `--require-hashes` is set).      |
| REQ-A003   | warn     | Package name is edit-distance ≤ 2 from a widely-installed package (typosquat shape).                         |
| REQ-A004   | warn     | Same package declared more than once (PEP 503-normalized comparison).                                        |
| REQ-A005   | error    | `--trusted-host` present (disables TLS verification for that host).                                          |
| REQ-A006   | warn     | VCS URL (`git+`/`hg+`/`svn+`/`bzr+`) without a pinned commit SHA (branch/tag/missing ref).                    |
| REQ-A007   | warn     | Non-ASCII character in the identifier portion of the name (homograph shape).                                 |
| REQ-A008   | warn     | Editable local install (`-e ./path` or `-e file:...`); likely dev-only, easy to commit by accident.          |
| REQ-A009   | info     | Custom package index configured (`--index-url` / `--extra-index-url`); requires `--include-info` to surface. |

Exit codes:

- `0` - no findings
- `1` - warnings only (or info if `--include-info`)
- `2` - at least one error (or any finding under `--strict`)

## Example

Given `examples/bad.txt`:

    # reqcheck: fixture with a variety of hygiene issues.
    # Every non-comment line trips at least one rule.
    requsts==1.0
    foo>=1.0
    foo==2.0
    --trusted-host internal.example.com
    git+https://example.com/foo/bar.git@main#egg=bar
    -e ./local-package

Running:

    $ python -m reqcheck examples/bad.txt

Produces:

    examples/bad.txt:3: WARN REQ-A003: package name 'requsts' is edit-distance-1 from widely-installed 'requests'; verify intent
    examples/bad.txt:4: WARN REQ-A001: unpinned requirement 'foo': no exact-version '==X.Y.Z' spec (found: ['>=1.0'])
    examples/bad.txt:5: WARN REQ-A004: 'foo' already declared on line 4; the later declaration may override the earlier
    examples/bad.txt:6: ERROR REQ-A005: --trusted-host internal.example.com disables TLS certificate verification for that host; strong supply-chain risk
    examples/bad.txt:7: WARN REQ-A006: git+ URL '@main': not a >=7-hex commit SHA; the installed code will drift with the remote
    examples/bad.txt:8: WARN REQ-A008: editable local install './local-package' in requirements: usually a development-only convenience; verify not committed by accident

    $ echo $?
    2

JSON output for CI:

    python -m reqcheck --format json examples/bad.txt

## Scope and limits

- **pip-style requirements files only.** No `pyproject.toml` PEP 621
  parsing, no `Pipfile`/`Pipfile.lock`, no `poetry.lock`, no
  `conda`/`environment.yml`. Extending is straightforward but out of
  scope for this release.
- **No network calls.** The typosquat comparison uses a curated static
  snapshot of ~55 widely-installed package names, not a live query
  against a PyPI mirror. False negatives are expected: a typosquat
  against a package outside the snapshot will not be flagged. False
  positives against unfamiliar-but-legitimate packages are avoided by
  a `KNOWN_LEGITIMATE` exclusion list plus a minimum-name-length gate.
- **Backslash line continuation is not supported.** pip supports
  `\`-continued lines; `reqcheck` treats each physical line
  independently. A continuation line will usually parse as `invalid`.
- **Hash algorithm is not validated.** REQ-A002 checks whether a
  `--hash=alg:hex` fragment is present, not whether `alg` is one of
  pip's supported algorithms.
- **REQ-A003 uses edit-distance shape.** It is a heuristic, not proof
  of malicious intent - a legitimate fork with a similar name will
  also trip it. The suggested action is "verify intent," not "block."
- **REQ-A006 accepts any hex string of length ≥ 7 as a commit SHA.** A
  seven-hex tag that happens to look like a short SHA would pass the
  check. In practice, tags do not have that shape.

## Contract

The Python API is intentionally small:

    from reqcheck import parse_text, audit_parsed, audit_file, Finding

`parse_text(text, path=...) -> ParsedFile` - line-oriented parser.

`audit_parsed(pf, include_info=False) -> list[Finding]` - apply the
rules to a `ParsedFile`.

`audit_file(path, include_info=False) -> (ParsedFile, list[Finding])`
 - read + parse + audit a file on disk.

Each `Finding` has `rule`, `severity`, `message`, `location`, `file`,
`name`, `suggestion`, and a `to_dict()` for JSON-friendly output.

## Testing

    python -m unittest discover -s tests

87 tests across parser, rules, typosquat, and CLI.

## License

MIT. See `LICENSE`.
