# jsonldiff

A small, focused semantic diff for two JSONL streams. Records are compared
structurally, per-path, so ordering of dict keys and whitespace inside a JSON
object stop obscuring the actual differences.

Zero runtime dependencies. Pure Python standard library. Library + CLI.

## Why

Two JSONL files are how most LLM / ML evaluation pipelines record runs -- one
per prompt, one per row, one per case. When a prompt or model version changes,
the natural question is *what actually differs between the previous run and
this one?* Plain `diff` is misleading because JSON serialisers vary key order,
number formatting, and whitespace between versions; `jq` and shell pipelines
work but each team ends up rewriting them; the heavy Python diff libraries
require adding a dependency for something that should be a one-file tool.

`jsonldiff` sits in that gap: a small, deterministic, streaming diff that
gives you paths (`metrics.accuracy: 0.75 -> 0.82`) instead of byte offsets,
handles record alignment either positionally or by a key, and returns
line-delimited JSON for CI pipelines.

## Install

```bash
pip install .
# or:
python -m jsonldiff --help
```

Python 3.9+.

## Use

```bash
# Line-aligned diff of two eval runs:
jsonldiff runs/baseline.jsonl runs/candidate.jsonl

# Machine-readable NDJSON, one change per line, for CI:
jsonldiff baseline.jsonl candidate.jsonl --format json --exit-code

# Align by a record id instead of by line position:
jsonldiff baseline.jsonl candidate.jsonl --key meta.run_id

# Ignore volatile fields (timestamps, latency samples):
jsonldiff baseline.jsonl candidate.jsonl \
    --ignore meta.timestamp --ignore latency.p50

# Stop after the first 20 differences:
jsonldiff baseline.jsonl candidate.jsonl --max-diffs 20
```

Exit codes:

* `0` -- clean run (also the default when differences exist and `--exit-code`
  is not passed, so you can pipe the output without the script failing);
* `1` -- differences found *and* `--exit-code` was requested;
* `2` -- I/O error or JSON parse error somewhere in either file.

## What a difference looks like

Text output:

```
line 12  metrics.accuracy: 0.75 -> 0.82
line 12  latency_ms: 120 -> 130
line 20  + status: "completed"
line 25  - deprecated_field: true
line 30  MISSING in candidate (baseline: {"id":"x","v":1})
```

JSON output (one record per line):

```json
{"kind":"changed","position":12,"path":"metrics.accuracy","baseline":0.75,"candidate":0.82}
{"kind":"added","position":20,"path":"status","candidate":"completed"}
{"kind":"missing_in_candidate","position":30,"baseline":{"id":"x","v":1}}
```

## Change kinds

| Kind | Meaning |
|------|---------|
| `changed` | both sides present at `path`, values differ |
| `added` | `path` in candidate only (positive delta) |
| `removed` | `path` in baseline only (negative delta) |
| `missing_in_baseline` | whole record absent from baseline (line mode: candidate has extra lines; key mode: candidate has an unmatched key) |
| `missing_in_candidate` | whole record absent from candidate |
| `parse_error_baseline` | line failed to parse in the baseline file (or key mode found a duplicate / missing key) |
| `parse_error_candidate` | line failed to parse in the candidate file |

## Library

```python
from jsonldiff import diff_files, diff_records, diff_streams

# High-level: two file paths.
for change in diff_files("baseline.jsonl", "candidate.jsonl", key="id"):
    print(change.kind, change.path, change.baseline, change.candidate)

# Low-level: two already-parsed records.
diffs = diff_records({"a": 1}, {"a": 2})
# [Change(kind='changed', path='a', position=0, baseline=1, candidate=2)]

# Stream: any iterable of text lines.
with open("a.jsonl") as a, open("b.jsonl") as b:
    for change in diff_streams(a, b, ignore=["timestamp"]):
        ...
```

## Semantics

* **Dicts** are compared key-wise; added / removed / recursively-diffed.
* **Lists** are compared **positionally** (index-aligned). Unordered list
  comparison is out of scope for the current release -- when order does not
  matter for you, sort both files first (`jq -Sc . file.jsonl > sorted`).
* **Numbers** follow JSON's single-number model: `1` and `1.0` compare equal.
  Booleans are distinct from integers even though Python treats `True == 1`
  as true.
* **Type mismatches** at a path (dict where a list was expected) are reported
  as a single `changed` event at the containing path -- the tool does not try
  to recurse into a shape mismatch.
* **Key mode** buffers the *baseline* into memory (one entry per record) and
  streams the candidate. For very large baselines pass `--max-diffs` to bail
  out early or split the input.

## Scope, honestly

**What this is.** A small, deterministic, streaming diff between two JSONL
files, with a clean library interface and enough CLI hygiene to drop into CI.

**What this is not.** Not a schema validator (see `jsonlcheck` for that). Not
a fuzzy matcher -- it does not tolerate near-equal floats without an ignore
rule. Not an unordered-set comparator. Not a merge tool.

**Trade-off.** The engine walks both records fully; for records of ~10^4
keys the diff cost is proportional. If you routinely diff single JSONL rows
with millions of nested keys, you want a purpose-built structural diff.

## License

MIT. See `LICENSE`.

## Authorship & provenance

Produced by a human-machine hybrid intelligence under maker-checker review.
Independent implementation of the general idea of "structural per-path diff
between two JSONL streams", built clean-room without reference to any
existing structural-diff library. Not derived from or affiliated with any
existing tool.
