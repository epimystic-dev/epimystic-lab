# jsonlsample

Deterministic sampling for JSONL streams. Three modes, one file, zero
dependencies.

- **Reservoir** (`-n K`) — uniform random sample of size K, streaming,
  O(K) memory (Vitter, 1985, Algorithm R).
- **Bernoulli** (`--fraction F`) — keep each row independently with
  probability F. Streaming, O(1) memory.
- **Stratified reservoir** (`--stratify PATH --per-group K`) —
  independent reservoir of size K per distinct value at a dotted path.
  O(g·K) memory where g is the number of strata seen.

Every mode takes a `--seed` for reproducibility. Same input + same seed
→ byte-identical output.

## Why

Every LLM / ML pipeline hits the same subproblem: given a large JSONL
file (10⁶–10⁸ rows) of eval results or training candidates, produce a
reproducible K-row sample — uniformly, or stratified per label, or as a
fixed fraction. In practice teams reinvent this with `shuf | head`
(non-streaming, non-reproducible, non-stratified), fragile
`jq`-plus-shell recipes, or a heavyweight `datasets` / `polars`
dependency for a job that should be one small tool.

Recent frontier work is beginning to formalise *how much data is enough*
for evaluation (e.g. arXiv 2607.08522, "Stop Guessing When to Stop
Testing," reports 80% cost reduction via adaptive sequential testing).
That work assumes a clean, reproducible sampling primitive underneath.
`jsonlsample` is that primitive.

Sits alongside `jsonlcheck` and `jsonldiff` as the third JSONL hygiene
layer of the lab.

## Install

```
pip install .
```

Or run directly:

```
python -m jsonlsample [options] <file|->
```

Python >= 3.8, no runtime dependencies.

## Usage

Uniform sample of 100 rows:
```
jsonlsample results.jsonl -n 100 --seed 42 > sample.jsonl
```

Bernoulli 1% sample (streaming; sample size ≈ 0.01·n, not exactly):
```
jsonlsample results.jsonl --fraction 0.01 --seed 0 > sample.jsonl
```

Balanced 50-per-label sample:
```
jsonlsample results.jsonl --stratify label --per-group 50 --seed 0 > sample.jsonl
```

Nested paths (dot-separated):
```
jsonlsample results.jsonl --stratify meta.category --per-group 20 > sample.jsonl
```

Pipe from stdin:
```
some_producer | jsonlsample - -n 500 --seed 7
```

Skip malformed lines silently (default: report + exit 2):
```
jsonlsample noisy.jsonl -n 100 --skip-parse-errors > sample.jsonl
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Succeeded; at least one record emitted |
| 1 | No records emitted (empty input, `--fraction 0`, `-n 0`) |
| 2 | Parse error, or CLI-usage / I/O failure |

## Path syntax

Dotted path segments navigate dict keys; list indices are supported when
a segment is an integer literal:

| Path | Applied to `{"a": {"b": [10, 20, 30]}}` |
|---|---|
| `""` (empty) | the whole record |
| `a` | `{"b": [10, 20, 30]}` |
| `a.b` | `[10, 20, 30]` |
| `a.b.1` | `20` |

Escape a literal `.` in a key with a backslash: `metrics\.p50` matches
the key `metrics.p50`. Missing keys, out-of-range indices, and
non-container traversals put the record into the `("__missing__", path)`
group under `--stratify`, so a missing-column bug shows up as a stratum
rather than being silently dropped.

## Statistical properties

- **Reservoir** — every k-subset of an n-element stream is equally likely
  when n > k; when n ≤ k, the sampler returns the whole stream in
  source order. Standard Algorithm R (Vitter 1985); one uniform random
  int per element after the first k.
- **Bernoulli** — sample size is Binomial(n, p): mean np, variance
  np(1−p). Prefer this mode when you want streaming O(1) memory and can
  tolerate a non-exact sample size.
- **Stratified** — an independent reservoir per group key; per-group
  size is capped at `--per-group`. Group memory scales with the number
  of distinct groups seen, not the stream length.

Determinism holds against `random.Random(seed)`. Version-to-version
determinism is contingent on CPython's `random` module semantics
remaining stable.

## Scope and limits

This tool is intentionally narrow:

- Line-per-record JSONL only. Multi-line pretty-printed JSON is
  out of scope; use a JSON→JSONL converter first.
- No compression handling. Pipe from `gunzip -c` for `.jsonl.gz`.
- No output schemas, no column projection, no filter expressions.
  Sample, don't transform.
- Stratified sampling is exact per group (each group's reservoir is
  independent); it does not proportion the total sample to match the
  input distribution — you asked for K per group, you get K per group
  (or the whole group if it has fewer than K rows).
- Sampling is over records as they appear in the input. If your JSONL
  has been sorted by some field, an early-terminated reservoir sample
  will inherit that ordering bias only when n ≤ k; once n > k the sample
  is uniform.

## Example

```
$ jsonlsample examples/tiny.jsonl -n 4 --seed 42
{"id": 6, "label": "cat", "score": 0.65}
{"id": 2, "label": "dog", "score": 0.91}
{"id": 3, "label": "cat", "score": 0.42}
{"id": 10, "label": "bird", "score": 0.88}

$ jsonlsample examples/tiny.jsonl --stratify label --per-group 1 --seed 3
{"id": 9, "label": "cat", "score": 0.51}
{"id": 5, "label": "dog", "score": 0.58}
{"id": 4, "label": "bird", "score": 0.76}
```

(Exact selections depend on the CPython `random` version but are
reproducible on a fixed interpreter.)

## Development

```
python -m unittest discover -s tests
```

Tests cover the streaming JSONL iterator, dotted-path resolution, and
each sampler including statistical checks (empirical first moment for
reservoir; 6-sigma binomial window for Bernoulli).

## Provenance and honesty

- **Clean-room.** Reservoir sampling is Vitter (1985, "Random Sampling
  with a Reservoir," *ACM Transactions on Mathematical Software*),
  Algorithm R — a standard textbook algorithm; the implementation was
  written from the algorithm description, not from any existing library.
  Stratified is a straightforward extension (one reservoir per key).
  Bernoulli is one coin flip per element. Cited motivation from arXiv
  2607.08522 for framing; not affiliated with, nor derived from, the
  authors' materials.
- **Vendor-neutral.** Authored by a human-machine hybrid intelligence.
  No affiliation with any ML framework vendor.
- **Bounded claims.** No "faster than," no "production-ready" guarantees.
  What ships is what the tests cover; anything else is documented above.

## License

MIT. See [LICENSE](LICENSE).
