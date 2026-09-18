# nbshape

Reproducibility-hygiene linter for Jupyter notebook JSON. It reads the stored
`.ipynb` file and flags shapes that correlate with the defects the notebook
reproducibility literature measured by execution: cells executed in an order
the file does not record, outputs retained from a kernel state that no longer
exists, sampling calls with no visible seed, absolute paths to a machine only
the author has, and credential-shaped literals in source or in committed
output.

Zero dependencies, Python standard library only. It executes nothing, spawns
nothing, and opens no socket.

**It cannot tell you whether a notebook reproduces.** See
[What this cannot tell you](#what-this-cannot-tell-you).

## Why

Computational notebooks are the dominant artifact for shared scientific and ML
work, and the measurements are not kind:

- Pimentel et al., *A Large-Scale Study About Quality and Reproducibility of
  Jupyter Notebooks* (MSR 2019; extended in PLOS ONE 2021,
  <https://pubmed.ncbi.nlm.nih.gov/33994841/>) is the foundational independent
  measurement of the out-of-order shape: of the notebooks with an unambiguous
  execution order, 36.4% had cells out of order; 24.1% ran without error; about
  4% reproduced the same results.
- *Automated Modernization of Machine Learning Engineering Notebooks for
  Reproducibility*, arXiv 2602.07195 (2026-02-06): of 12,106 Kaggle competition
  notebooks, only 26% remain reproducible today.
- *Containing the Reproducibility Gap: Automated Repository-Level
  Containerization for Scholarly Jupyter Notebooks*, arXiv 2604.01072
  (2026-04-01): automated containerization of 443 notebooks from 116
  publication-referenced repositories resolved 66.7% of prior dependency
  failures, yet 53.7% still showed low output fidelity, attributed to runtime
  failure and stochastic non-determinism. **Fixing the environment does not fix
  the notebook.**
- *A Study of Scientific Computational Notebook Quality*, arXiv 2603.22726
  (2026-03-24): from the Code Availability statements of all 1,239 Nature 2024
  publications the authors assembled 518 repositories and 1,510 notebooks; of
  the 19 notebooks they attempted to execute, 2 reproduced. The study names
  tangled state changes and heavy code duplication as recurring defects.
- *Why do Machine Learning Notebooks Crash?*, arXiv 2411.16795 (2024; v3
  2025-05-27): 92,542 crashes across 64,031 notebooks; over 40% stem from API
  misuse and notebook-specific issues.
- *Analysing Python Machine Learning Notebooks with Moose*, arXiv 2509.11748
  (2025-09-15): establishes that notebook bad practices arise at three distinct
  levels - general Python conventions, the notebook's own structure, and
  ML-specific practice. Notebook structure is a separable lint layer, and that
  layer is what nbshape works on.

The residue that survives containerization is in-notebook. All of it is plainly
visible in the `.ipynb` JSON without executing a single cell.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| NBK-001 | MEDIUM | `execution_count` over code cells, with nulls dropped, is not strictly increasing in storage order. Reports the first inversion's cell index and the total inversion count. |
| NBK-002 | HIGH | A code cell carries outputs but `execution_count` is null - output retained from a kernel run the file no longer describes. |
| NBK-003 | HIGH | Two or more code cells share the same non-null `execution_count`. A monotonic kernel counter cannot produce that. |
| NBK-004 | INFO | The maximum `execution_count` exceeds the stored code-cell count by more than `--rerun-factor` (default 2.0). An observation, not a defect. |
| NBK-005 | HIGH | Cell source contains a machine-local absolute path literal: a drive letter (`C:\`, `D:/`), `/home/<name>/`, `/Users/<name>/`, or `/mnt/<name>/`. |
| NBK-006 | HIGH | A binding whose name matches a credential vocabulary is bound to a string literal of at least `--min-literal-len` characters (default 16), or a `text/plain` or stream output contains a high-entropy token-shaped string. **Shapes, not verified secrets.** |
| NBK-007 | MEDIUM | A `pip` / `conda` install invoked through `!` or `%pip` names a package with no version specifier at all. |
| NBK-008 | MEDIUM | Sampling API calls are present and no seeding call is visible in any cell. |
| NBK-009 | MEDIUM | `metadata.kernelspec` or `metadata.language_info` is absent; or `language_info.name` disagrees with `kernelspec.language`; or a `python<N>` kernel name disagrees with `language_info.version`'s major digit. |
| NBK-010 | INFO (gate) | Not a schema-conformant nbformat v4 notebook. **This rule is a gate**: when it fires, no other rule runs and the file rolls up to `unknown`. |
| NBK-011 | INFO | Committed non-text output payloads exceed `--max-output-bytes` (default 2 MiB), or dominate a file of at least 256 KiB. The notebook is a binary store. |
| NBK-012 | MEDIUM | Hidden-state shape: `os.chdir` or `%cd`, a star-import, or a `del` of a name bound in an earlier cell. Each makes cell order load-bearing in a way the file does not express. |
| NBK-013 | HIGH | An `execute_result` output's `execution_count` disagrees with its owning cell's, or a non-code cell carries a non-null `execution_count` or non-empty `outputs`. |
| NBK-014 | INFO | `metadata.widgets` is present with no non-empty `state` key - the widget render is already broken on disk. |
| NBK-015 | INFO | A cell did not parse as Python after the magic pre-pass, or the notebook is not a Python notebook. NBK-006 and NBK-012 degrade to textual matching there. |
| NBK-016 | INFO | A hosted-runtime path literal (`/content/`, `/content/drive/`, `/kaggle/input/`, `/gdrive/`). Portable inside that host, absent on a local checkout. |
| NBK-017 | MEDIUM | On `nbformat_minor` 5 and above, a cell `id` is missing, malformed, or duplicated. Never fires on v4.0 to v4.4. |
| NBK-018 | INFO | Every code cell has a null `execution_count` and no outputs. This is the cleared state a strip-outputs tool produces - the best case, not a defect. |

`python -m nbshape --list-rules` prints the registry.

### Verdict rollup

Findings roll up into one verdict, and the verdict maps to the exit code:

- Any HIGH -> `unhealthy` (exit 2)
- Any MEDIUM, no HIGH -> `needs-attention` (exit 1)
- Files were opened but none could be scored -> `unknown` (exit 1; exit 2 with `--strict`)
- INFO only -> `healthy` (exit 0), or `needs-attention` (exit 1) with `--strict`
- No findings, at least one file scored -> `healthy` (exit 0)
- No files found at all -> `unknown` (exit 1; exit 2 with `--strict`)
- Path does not exist -> stderr diagnostic, exit 2

HIGH and MEDIUM outrank `unknown` on purpose: if one notebook in a directory
scored and was unhealthy, the run is unhealthy even when a sibling file was
unreadable.

## Install

```bash
python -m pip install -e .
```

Or run it straight from a clone, with no install at all:

```bash
python -m nbshape /path/to/scan
```

Requires Python 3.9 or newer. No dependencies.

## Use

```bash
nbshape                                  # scan cwd, text output
nbshape path/to/repo                     # scan a directory
nbshape path/to/one.ipynb                # scan a single notebook
nbshape --json path                      # whole report as JSON on stdout
nbshape --strict path                    # INFO -> needs-attention; unknown -> exit 2
nbshape --include-info path              # surface INFO findings
nbshape --disable NBK-004 path           # disable one rule (repeatable)
nbshape --include-checkpoints path       # also scan .ipynb_checkpoints/
nbshape --glob "*.nb" path               # extend the default file-glob set
nbshape --rerun-factor 4 path            # loosen NBK-004
nbshape --max-output-bytes 524288 path   # tighten NBK-011
nbshape --list-rules
nbshape --version
```

### Streams

Findings and `--json` output go to **stdout**. The verdict line, the counts,
and every per-file diagnostic go to **stderr**. A clean run therefore writes
nothing at all to stdout, so `nbshape --json . | jq` never sees the tool's own
commentary. This follows `epimystic-lab/docs/CONVENTIONS.md`.

### Try it

```bash
nbshape examples/healthy_notebook.ipynb    # exit 0, stdout empty
nbshape examples/weak_notebook.ipynb       # exit 2, many shapes at once
nbshape tests/fixtures/nbk005_local_path   # exit 2
nbshape tests/fixtures/healthy             # exit 0
nbshape tests/fixtures/unknown             # exit 1, verdict unknown
```

## Semantics worth knowing before you trust a number

**NBK-001 drops nulls.** `execution_count` values are collected over code cells
in storage order, nulls are dropped, and the remaining sequence is tested for
strict increase. A null is an unrun cell, which is NBK-002's business, not
NBK-001's. Zero code cells, one code cell, and all-null counts are all clean
passes, not crashes.

**A cleared notebook is not a finding.** When every code cell has a null
`execution_count` and no outputs - what `nbstripout`, `jupytext`, or
`nbconvert --ClearOutput` leaves behind - the ordering rules have no evidence to
work from. nbshape emits NBK-018 at INFO and says the ordering dimension is
unknown. It never reports the cleared state as worse than a dirty one.

**NBK-010 is a gate, not just a finding.** If the top-level object is not a
dict, or `nbformat` / `nbformat_minor` / `cells` is absent or malformed, or
`nbformat` is below 4, then every other rule's field assumption is unfounded.
nbshape emits NBK-010, skips the remaining rules, and rolls that file up to
`unknown` rather than cascading a dozen spurious findings off a file it cannot
reason about. A `JSONDecodeError` and valid JSON that is simply not a notebook
get the same handling: a clean `unknown` plus a stderr diagnostic, never a
traceback. The NBK-010 finding stays visible without `--include-info`, because
hiding the reason a file could not be scored would be dishonest.

**Checkpoints are skipped by default.** `.ipynb_checkpoints/` holds
near-duplicates of its parent notebooks; scanning it by default roughly doubles
every finding count on a real repository. Use `--include-checkpoints` to opt in.
An explicitly named checkpoint file is always honoured.

**The magic pre-pass, and what it costs.** Notebook cell source is not valid
Python. Lines beginning with `!` or `%`, whole cells whose first line is a `%%`
cell magic, and the `?` / `??` help suffixes all raise `SyntaxError` in
`ast.parse`. nbshape rewrites each such line one-for-one into an inert statement
so line numbers stay meaningful, then parses the rest. A `%%time` or `%%capture`
cell keeps its Python body; a `%%bash` or `%%writefile` cell does not have one.
When a cell still does not parse, NBK-006 and NBK-012 fall back to regular
expressions for that cell and **NBK-015 says so out loud**. That INFO finding is
not filler - it is the disclosure that nbshape's coverage is not uniform across
a file.

**The entropy scan is mime-bundle aware.** `image/png`, `image/jpeg` and
`application/pdf` output values are base64 blobs that are long and high-entropy
by construction. nbshape entropy-scans only `text/plain` values and `stream`
output text. Without that restriction every notebook that plots anything would
be flagged as leaking a credential.

**NBK-005 versus NBK-016.** `/content/drive/` is the standard mount inside a
hosted runtime and is portable there, so it gets its own INFO code rather than
sitting at HIGH beside a `C:\Users\` path.

**Bounds.** Per-file byte cap (default 64 MiB, `--max-bytes`) checked with a
`stat` before the read, so an oversized notebook is never loaded into memory; it
is reported as `unknown` instead. Per-run file cap (default 2000,
`--max-files`).

## Test

```bash
python -m unittest discover -s tests
```

475 tests. Every rule has a positive fixture that fires it, a negative fixture
beside it that must not, and a `--disable` case. The suite covers the rule table
and registry invariants, the magic pre-pass, the conformance gate, scanner
discovery and byte caps, verdict precedence and the exit-code contract, both
reporters and the stdout/stderr split, every CLI flag, end-to-end runs against
all committed fixtures, the real `python -m nbshape` subprocess entry point, the
shared lab contract, and an adversarial suite: empty file, whitespace-only file,
not-JSON, truncated JSON, top-level array, number, string and null, null bytes,
invalid UTF-8, `cells` as an object, `outputs` as a string, `execution_count` as
a string and as a boolean, a numeric cell id, 4000-deep nesting, a 200,000
character line, 400 cells, non-ASCII and CJK and emoji source, a right-to-left
override, a directory named like a notebook, a dangling path, and a symlink
loop. The tool must never traceback; it must produce a diagnostic and a sane
exit code.

No secret-shaped literal is committed anywhere in this repository. The strings
the NBK-006 detection tests need are assembled at test time from sub-16
character parts in `tests/nbfactory.py`; the committed fixture uses a
self-describing placeholder that no scanner and no reader could mistake for a
real credential.

## Honest scope

**What this tool does.** Static, offline, deterministic linting of nbformat v4
JSON, parsed with `json` and analysed with `ast` and `re` from the standard
library.

**What it does not do.** It does not execute a notebook, start a kernel, import
a notebook's dependencies, resolve an environment, check whether a referenced
file exists, verify an output against a re-run, diff two notebooks, or fix
anything. It has no autofix mode.

**False negatives, named.** A secret read from an environment variable or a
secret manager. A seed set inside an imported helper module, a `%run`, a
parameters cell, or a config file. A machine-local path assembled at runtime
from parts rather than written as a literal. A path literal in a markdown cell
(nbshape scans code cells only for NBK-005 and NBK-016). A loose version range
such as `>=1.26`, which NBK-007 treats as "specified" even though it is not a
pin. A placeholder-looking home directory - `/home/user/`, `/home/username/` and
a short list of similar names are deliberately excluded. `/mnt/data/` is
deliberately excluded. A 40-character hex string in output is deliberately
excluded from the entropy scan, because a git sha printed by a cell is the
common case. Any defect in a cell that did not parse as Python and is not
reachable by regular expression - NBK-015 tells you which cells those are.

**False positives, named.** NBK-004 fires on any notebook iterated on before a
final partial run, which is why it is INFO and configurable. NBK-006 will flag a
long non-secret bound to a variable whose name happens to contain `token` or
`auth`, and will flag a long high-entropy identifier printed in output. NBK-008
fires when seeding happens by a route nbshape cannot see. NBK-009's third check
infers a Python major version from `kernelspec.name`, which is a display string;
that inference is weak and the message says so. NBK-005 will flag a path in a
comment or in an unused string. NBK-012 flags a star-import that the author
knows is fine. Every rule can be turned off with `--disable <CODE>`.

## What this cannot tell you

- **nbshape executes nothing.** It cannot say whether a notebook reproduces,
  predict whether it will run, or verify reproducibility. The studies cited
  above measured reproducibility by running notebooks; nbshape runs nothing. It
  reports stored-JSON shapes that those studies found co-occurring with
  execution failure.
- **NBK-006 reports credential-shaped literals, never detected secrets.** It
  will miss secrets read from environment variables and it will flag long
  non-secret strings. It is not a substitute for a secret-detection pipeline run
  over the whole repository.
- **NBK-001 is not proof of a wrong result.** Strictly increasing
  `execution_count` is neither necessary nor sufficient for correctness. It is
  only the case where the file's own record is self-consistent. The very common
  run-all-then-re-run-one-cell pattern breaks strict monotonicity harmlessly,
  which is exactly why NBK-001 is MEDIUM and the three self-contradiction rules
  (NBK-002, NBK-003, NBK-013) keep HIGH.
- **Clearing every nbshape finding does not make a notebook portable, correct,
  or reproducible.** That claim is unsupportable and nbshape does not make it.

## Why this is not duplicative

The rule *families* here are established prior art from the notebook
reproducibility literature. This tool's claim is the delivery shape, not the
ideas.

- **Pynblint** (collab-uniba; arXiv 2205.11934) has an explicit non-linear
  execution rule covering the same shape as NBK-001, and non-executed-notebook /
  non-executed-cells rules that partially overlap NBK-002. Its latest PyPI
  release is 0.1.6, dated 2024-08-12, and it carries eight runtime dependencies:
  `nbformat`, `nbconvert`, `GitPython`, `rich`, `typer`, `pydantic`,
  `pydantic-settings`, `ipython`. It does not implement duplicate execution
  counts, absolute-path literals, credential-shaped literals, missing seeds,
  unpinned installs, kernelspec / language_info coherence, nbformat conformance,
  payload bloat, hidden-state shapes, output-level `execution_count` mismatch,
  widget state, or checkpoint handling. This is not a claim that pynblint is
  abandoned - only that its last release is dated.
- **Julynter** (Pimentel et al.) is a JupyterLab reproducibility linter covering
  execution order, hidden state, and machine-local paths. It runs inside the
  JupyterLab runtime.
- **nbqa** runs existing Python linters over notebook code cells. It is a
  different layer: Python conventions, not notebook structure.
- **nbstripout** clears outputs. nbshape names the state nbstripout produces
  (NBK-018) and treats it as the best case.
- **nbformat's own validator** checks schema conformance, which is what NBK-010
  does as a gate. `nbcheck` on PyPI is a wrapper around that validator; this
  tool is named `nbshape` to avoid the collision.

What nbshape offers that none of the above does in one artifact: zero runtime
dependencies, standard library only, no notebook runtime and no JupyterLab, one
`python -m` invocation from a clean clone, a rolled-up verdict mapped to CI exit
codes, deterministic JSON on stdout, and a per-rule `--disable`.

## Related tool in this collection

`seedline` is the counterpart to NBK-008: NBK-008 names the shape (sampling
calls, no visible seed) and `seedline` is the fix (a seeding helper). A linter
that names its own remedy in the same published collection is worth more than
either tool alone.

## Provenance and clean-room note

This is an independent implementation. The rules are derived from the nbformat
v4 JSON schema (`nbformat/v4/nbformat.v4.schema.json`, the normative `required`
list that NBK-010 is anchored to - not the narrative format-description page,
which hedges on whether `nbformat` and `nbformat_minor` are formally required)
and from the findings reported in the abstracts and method descriptions of the
papers cited above.

No reference implementation of the same idea was read, vendored, or mirrored.
Specifically: the rule tables and source of `pynblint`, `julynter`, `nbqa`, and
`nbstripout` were not consulted. They are cited above as related work only.

**Not affiliated with or endorsed by** the authors of any paper cited here, the
maintainers of any tool named here, Project Jupyter, or any hosted notebook
service.

## License

MIT.

---

*Produced by a human-machine hybrid intelligence, under maker-checker.*
