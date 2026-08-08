# envcheck

A small, focused drift-and-secret checker for dotenv files. Compares a template
(e.g. `.env.example`) against an actual `.env`, flags key drift, syntax and
encoding issues, and warns when either file contains a value that matches a
known credential pattern.

Zero runtime dependencies. Pure Python standard library. Library + CLI.

## Why

Leaked environment variables are one of the most common vectors for real
security incidents (Palo Alto Networks' Unit 42 documented a single actor
harvesting `.env` files across ~110,000 domains in 2024). At the same time,
drift between `.env.example` and `.env` -- keys added to the template that
never made it into the deployed config -- keeps producing production outages
that are only caught at request time.

The existing ecosystem is either heavy (Rust binaries, hosted services) or
runtime-specific (Node-only, Ruby-only). `envcheck` fills the gap with a
single small Python module: pipeable in CI, runnable as a git pre-commit hook,
usable as a library from a health-check endpoint.

## Install

```bash
# from a checkout:
pip install .
# or, from the project folder without installing:
python -m envcheck --help
```

Python 3.9+.

## Use

```bash
# Compare the default paths (.env.example and .env):
envcheck

# Explicit paths:
envcheck config/.env.template config/.env.local

# CI-style JSON output, one finding per line:
envcheck --format json

# Only drift, no secret scan:
envcheck --no-secrets

# Only secret scan of the template, no env file:
envcheck .env.example --no-drift
```

Exit codes: `0` clean, `1` findings, `2` usage or I/O error.

## Diagnostics

Parser issues (in either file):

| Code | Meaning |
|------|---------|
| E001 | line is not a `KEY=VALUE` assignment (or has stray tokens) |
| E002 | assignment has an empty key |
| E003 | key is not a valid shell identifier |
| E004 | duplicate key (second occurrence flagged) |
| E005 | unquoted value contains whitespace |
| E006 | unclosed quote |
| E007 | file uses CRLF line endings |
| E008 | file starts with a UTF-8 BOM |
| E009 | file is not valid UTF-8 |

Drift (template <-> env):

| Code | Meaning |
|------|---------|
| D001 | key is in the template but missing from the env |
| D002 | key is in the env but not documented in the template |
| D003 | key is empty in the env but the template gives a non-placeholder example |

Secrets (heuristic; known prefixes only):

| Code | Where | Patterns |
|------|-------|----------|
| S001 | env file | value matches a known credential pattern -- a *real* credential in a live config |
| S002 | template | value matches a known credential pattern -- the template committed a real secret |

Patterns matched: AWS access keys (`AKIA`/`ASIA`), Google API keys (`AIza`),
`sk-`- and `sk-ant-`-prefixed secret keys, GitHub tokens
(`ghp_`/`ghs_`/`gho_`), Slack tokens (`xox[baprs]`), Stripe live secrets
(`sk_live_`), and PEM `PRIVATE KEY` blobs. Patterns are matched by prefix
shape; the tool does not attempt to identify or attribute a specific vendor.

## Example

`examples/template.env` documents four keys; `examples/local.env`
introduces three realistic drift patterns — a documented key that
never made it into the deployed config, a value blanked out, and an
undocumented feature flag added in production:

    $ python -m envcheck examples/template.env examples/local.env
    envcheck: 3 issue(s) (D001: 1, D002: 1, D003: 1)
    examples/template.env:3:0: D001 key 'REDIS_URL' is in template but missing from env
    examples/local.env:3:0: D003 key 'SESSION_SECRET' is empty in env but the template provides a non-empty example
    examples/local.env:5:0: D002 key 'FEATURE_FLAG' is in env but not documented in the template

    $ echo $?
    1

(On Windows the emitted paths will use backslash separators; on POSIX,
forward slashes.) The fixtures are drift-only by design; secret
detection is exercised by the test suite so no credential-shaped
literal ships in `examples/`.

## Library

```python
from envcheck import check_files, CheckOptions

findings, template, env = check_files(
    ".env.example",
    ".env",
    CheckOptions(secrets=True, drift=True),
)
for f in findings:
    print(f.code, f.line, f.key, f.message)
```

## Scope, honestly

**What this is.** A small, deterministic linter for the common single-line
`KEY=VALUE` dotenv dialect, focused on the two failure modes we actually see
in production incidents: drift and pasted credentials.

**What this is not.**

- Not a full dotenv runtime. It intentionally does not expand `${VAR}`
  references, does not support multi-line values, does not support backslash
  line continuations, and does not evaluate a shadow shell.
- Not a secrets scanner. The secret patterns are known credential prefixes,
  chosen to keep false positives near zero at the cost of missing high-entropy
  random secrets. For a real repo-wide credential scan use a purpose-built
  tool.
- Not a schema validator. It does not know the *types* your app expects.

**Known limits.** Non-UTF-8 files are decoded lossily and only flagged, so
line/column numbers past the first bad byte may be approximate. Duplicate-key
resolution follows the "last assignment wins" rule of most runtimes; if yours
differs, treat `E004` as fatal.

## License

MIT. See `LICENSE`.

## Authorship & provenance

Produced by a human-machine hybrid intelligence under maker-checker review.
Independent implementation, built clean-room from the dotenv convention as
documented in the twelve-factor app methodology and POSIX shell assignment
grammar. Not derived from or affiliated with any existing dotenv tool.
