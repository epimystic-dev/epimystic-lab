# jwtcheck

A tiny, zero-dependency JWT / auth-secret hygiene linter for `.env` files.
Reports weak defaults, empty secrets, placeholder patterns, low-entropy
values, `alg=none`, and HMAC secrets shorter than the RFC 7518 §3.2
recommended minimum.

## Why

Aggregated 2026 developer-pain-signal data puts *Insecure JWT Secret
Configuration* in the top-3 open complaint clusters, quoting the recurring
observation that "nothing warns them when the environment variable is
missing." Applications routinely ship with weak, missing, or hardcoded
JWT secrets, or with `alg: none` sitting in a config file, because no
small pre-deploy linter is looking at env files for JWT-specific
hygiene. Existing tooling either covers generic credential prefixes (AWS,
GitHub, Slack), or requires a full framework runtime.

`jwtcheck` is the small piece: `.env` in, findings out, exit code drives
CI/pre-commit.

## Install

Local, from the folder:

```
pip install .
```

Or run directly without installing:

```
python -m jwtcheck path/to/.env
```

Python >= 3.8, no runtime dependencies.

## Usage

```
jwtcheck .env
jwtcheck .env .env.example --format json
jwtcheck .env --severity error       # suppress warns in report
jwtcheck .env --extra-secret-key '^MY_CUSTOM_TOKEN$'
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No findings |
| 1 | Warnings only |
| 2 | Errors, or I/O / parse failure |

## Rules

| Rule | Severity | Check |
|---|---|---|
| `JWT-A001` | error | `alg=none` (disables signature verification) |
| `JWT-A002` | error | HS256 / HS384 / HS512 secret shorter than 32 / 48 / 64 bytes (RFC 7518 §3.2) |
| `JWT-A003` | error | JWT secret is empty |
| `JWT-A004` | error | JWT secret matches a well-known weak default (`secret`, `changeme`, `your-256-bit-secret`, ...) |
| `JWT-A005` | warn  | JWT secret matches a placeholder pattern (`<REPLACE_ME>`, `{{VAR}}`, `TODO`, ...) |
| `JWT-A006` | warn  | JWT secret has Shannon entropy < 3.0 bits / char |
| `JWT-A007` | warn  | HMAC (symmetric) algorithm in use; asymmetric (RS/ES/EdDSA) is generally preferable in prod |
| `JWT-P001` | error | `.env` syntax error |
| `JWT-P002` | error | `.env` file was not decodable as UTF-8 |

### Which keys are treated as JWT secrets

The recogniser matches env keys against a small allow-list of
JWT-flavoured conventions used across common backend frameworks:

- `JWT_SECRET`, `JWT_KEY`, `JWT_SIGNING_KEY`, `JWT_ACCESS_SECRET`,
  `JWT_REFRESH_SECRET`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`
- `AUTH_SECRET`, `NEXTAUTH_SECRET`, `BETTER_AUTH_SECRET`,
  `SUPABASE_JWT_SECRET`
- `SESSION_SECRET`, `ACCESS_TOKEN_SECRET`, `REFRESH_TOKEN_SECRET`
- Any key ending `_JWT_SECRET` or `_JWT_KEY` (for per-env / per-tenant
  conventions like `PROD_JWT_SECRET`)

Additional patterns can be added with `--extra-secret-key REGEX`. This
narrow recognition is intentional: a security linter that cries wolf
gets muted. Generic credential-prefix detection (AWS AKIA/ASIA, Google
AIza, GitHub `ghp_`, Slack `xox*`) is what `envcheck` is for; the two
tools compose.

## Scope and limits

This tool is intentionally narrow. It:

- Reads only `.env`-family files (one `KEY=VALUE` per line, optional
  `export` prefix, single-line quoted values). Multi-line values, `${VAR}`
  interpolation, and YAML / TOML / JSON config are all **out of scope**.
- Does not scan source code, git history, or bundle artifacts.
- Does not fetch or validate anything over the network.
- Does not distinguish dev from prod configuration; it does not know
  whether the file it is auditing is actually the deployed one.
- The entropy heuristic (Shannon; `< 3.0` bits / char) is exactly that:
  a heuristic. It will flag a naturally low-entropy but cryptographically
  strong value (rare but possible), and will not catch a
  higher-entropy-but-still-guessable one (e.g. a mnemonic phrase).
- The weak-defaults list is a curated snapshot of values seen across
  public leak reports and framework quick-starts; it is not exhaustive.
- PEM-encoded values (single-line, `-----BEGIN ... KEY-----`) are
  recognised and exempted from length / entropy heuristics; multi-line
  PEM blocks are not supported by the current parser and should be kept
  out of `.env` files (load them from a file path instead).

If the audit passes, it does not mean the deployment is safe. If the
audit fails, it flags a specific, addressable class of exposure.

## Example

`bad.env`:

```
JWT_ALGORITHM=none
JWT_SECRET=
NEXTAUTH_SECRET=changeme
SESSION_SECRET=<REPLACE_ME>
AUTH_SECRET=aaaaaaaaaaaaaaaa
```

```
$ jwtcheck bad.env
bad.env:1:1: error: JWT-A001: JWT_ALGORITHM='none': alg=none disables signature verification
bad.env:2:1: error: JWT-A003: JWT_SECRET is empty
bad.env:3:1: error: JWT-A004: NEXTAUTH_SECRET is set to a well-known weak default value ('changeme')
bad.env:4:1: warn: JWT-A005: SESSION_SECRET looks like a placeholder ('<REPLACE_ME>'); replace before deploy
bad.env:5:1: warn: JWT-A006: AUTH_SECRET has low Shannon entropy (0.00 bits/char, < 3.0); may be dictionary-derived
$ echo $?
2
```

## Development

```
python -m unittest discover -s tests
```

52 tests covering rule catalog, parser, and CLI.

## Provenance and honesty

- **Clean-room.** Built from the JWT / RFC 7518 §3.2 minimum-key-size
  spec, the aggregated 2026 pain-signal cluster (public complaint data),
  and the twelve-factor-app convention for env-based configuration. Not
  derived from any specific existing linter's source.
- **Vendor-neutral.** Authored by a human-machine hybrid intelligence.
  No affiliation with, nor endorsement by, any JWT library, framework
  vendor, or security tool vendor.
- **Bounded claims.** No "state-of-the-art," no "production-ready
  guarantee." What ships is what the tests cover; anything else is scope
  documented above.

## License

MIT. See [LICENSE](LICENSE).
