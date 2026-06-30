# jsonlcheck

A strict, streaming **JSONL** (line-delimited JSON) validator with line:column
diagnostics. Single file, pure stdlib, no dependencies. Python 3.9+.

```
$ python -m jsonlcheck dataset.jsonl
dataset.jsonl:42:17: error: [parse-error] Expecting ',' delimiter
dataset.jsonl:118: error: [duplicate-key] duplicate object key: 'id'
dataset.jsonl:204: error: [nan-inf] value contains non-RFC numeric literal: NaN
dataset.jsonl:999: warning: [no-final-newline] file does not end with a newline
```

## Why this exists

The Python stdlib `json` module is permissive in ways that quietly corrupt
LLM training sets, eval logs, and config dumps:

| Behavior | stdlib `json.loads` | `jsonlcheck` |
|---|---|---|
| `NaN` / `Infinity` literals (RFC 8259 forbids them) | accepted | rejected |
| Duplicate object keys (RFC 8259 §4 says implementations *MAY* reject) | silently kept last | rejected |
| UTF-8 BOM at start of line | parse error with cryptic message | flagged with code `bom`, then stripped |
| Unescaped control characters inside a string | parse error with vague position | reported with the exact column |
| Blank or whitespace-only lines | n/a (per-line validator's job) | flagged |
| Missing trailing newline at EOF | n/a | warning (POSIX-friendly) |

`jsonlcheck` was written for the realistic case where the JSONL file is
**hundreds of MB** of LLM training data or telemetry: streaming O(1) memory,
no full-file parse, gzip auto-detected on `.gz`.

## Install

It's one tiny package — drop the `jsonlcheck/` folder into your repo, or:

```
pip install -e .
```

(A `pyproject.toml` is included for editable / wheel installs. No runtime
dependencies.)

## CLI

```
python -m jsonlcheck [paths...] [flags]
```

| Flag | Effect |
|---|---|
| (positional) | One or more file paths; `-` means stdin (default if none given). `.gz` is auto-decompressed. |
| `--homogeneous` | Require every non-blank line to share the same JSON top-level type (`object`, `array`, etc.). Off by default. |
| `--require-key KEY` | When the top-level value is an object, require this key. Repeatable. |
| `--no-bom` | Don't flag UTF-8 BOMs (they're still silently stripped so parse succeeds). |
| `--allow-blank` | Permit blank or whitespace-only lines. |
| `--allow-nan` | Permit `NaN` / `Infinity` / `-Infinity`. |
| `--allow-duplicate-keys` | Permit duplicate keys in objects. |
| `--allow-control-chars` | Permit literal `U+0000`–`U+001F` inside strings. |
| `--no-final-newline-check` | Don't warn on missing trailing newline. |
| `--max-issues N` | Stop emitting issues after `N` (per file). |
| `--quiet` | Suppress per-issue output; only set the exit code. |

**Exit codes:** `0` (clean or warnings only), `1` (one or more errors),
`2` (CLI usage error from `argparse`).

## Library

```python
from jsonlcheck import check_path, check_stream, Options, Severity

for issue in check_path("dataset.jsonl", options=Options(homogeneous=True)):
    if issue.severity == Severity.ERROR:
        print(issue.format("dataset.jsonl"))
```

Each `Issue` has: `line` (1-based), `column` (1-based or `None`), `code`
(stable string id), `message`, `severity`.

## Scope and honest limits

- **`jsonlcheck` is a structural linter, not a JSON Schema validator.** It
  does not check field types or value ranges. Use `--require-key` for the
  one common case (object keys must exist); for anything richer, pipe the
  parsed lines into `jsonschema` or `pydantic`.
- **Encoding is assumed to be UTF-8** (per RFC 7464 §3). Files in another
  encoding need to be transcoded first; this tool will not autodetect.
- **Line terminators recognized:** LF and CRLF. A bare CR is treated as part
  of the line body.
- **Streaming:** memory use is bounded by the longest single line, not the
  file size. Very long single lines (multi-GB on one line) are loaded into
  memory in full because `json.loads` itself is not streaming.
- **Speed:** ~5 MB/s on cold paths, roughly the speed of `json.loads` itself.
  Not a high-performance validator; if you need parser-level speed, the
  Rust-based linters in the ecosystem will be faster. This tool's bet is
  *clarity of diagnostics* over throughput.

## Tests

```
python -m unittest discover -s tests
```

53 tests, no external dependencies.

## License

MIT. See `LICENSE`.

## Provenance

Built by a human–machine hybrid intelligence working under a published
governance + clean-room build protocol. Clean-room: not derived from any
existing JSONL validator's source. RFC references: RFC 7464 (JSON Text
Sequences), RFC 8259 (JSON).
