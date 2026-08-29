# oraclecheck

Offline AST linter for Python test files that detects **state-anchored
oracles**: assertions whose expected value flows, directly or transitively,
from the code under test itself. When both sides of a comparison come from the
same source, a fault moves measurement and expectation together, the
comparison cancels exactly, and no generated input can reveal the defect. The
oracle cannot fail.

Zero dependencies, pure Python stdlib. MIT-licensed. Python 3.10+.

## Why this exists

Existing lint tooling (`ruff`, `pylint`, `flake8`) has no rule for state-anchored
oracles because the smell is semantic-over-test-structure, not syntactic:
`self.assertEqual(f(x), f(x))` parses cleanly and passes at runtime.
`expected = mymod.compute(1); self.assertEqual(mymod.compute(1), expected)`
also parses cleanly and passes at runtime. Neither exercises the SUT
meaningfully. Both survive every mutation of `compute`.

The motivating paper (see Provenance) measured this failure mode on a deployed
air-traffic-control simulator: 12 model-free property suites, 4 modules, 366
mutants. Re-anchoring **one** holding oracle to a published procedure (with no
production-code change) recovered 8 of 46 previously-missed mutants.

`oraclecheck` is the small offline pre-flight primitive that makes the
anchoring shape visible to a CI job, a pre-commit hook, or a periodic sweep.

## Install

```
python -m pip install .
```

or run from the checkout without installing:

```
python -m oraclecheck.cli --help
```

## Use

```
oraclecheck                                 # scan the current directory
oraclecheck tests/                          # scan a directory
oraclecheck tests/test_foo.py               # scan a single file
oraclecheck --sut mymod tests/              # override the SUT-module hint
oraclecheck --json tests/                   # JSON report for CI
oraclecheck --include-info --strict tests/  # surface INFO findings + escalate
oraclecheck --disable ORACLE-010 tests/     # disable a rule
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | healthy (no findings; or INFO-only under default settings) |
| `1` | needs-attention (MEDIUM finding; or INFO under `--strict`; or no files scanned under default) |
| `2` | unhealthy (HIGH finding; or invalid CLI args; or no files scanned under `--strict`) |

The verdict rollup is monotonic: any HIGH finding forces `unhealthy`; any
MEDIUM without HIGH forces `needs-attention`; INFO alone is `healthy` by
default and `needs-attention` under `--strict`.

## The ten rules

Each rule is documented, has a positive-trigger test and a negative-clean
test, and reports a stable rule ID that CI tooling can allow-list.

| ID | Severity | Shape |
|---|---|---|
| `ORACLE-001` | HIGH | Self-comparison: `assertEqual(f(x), f(x))` / `assert f(x) == f(x)` |
| `ORACLE-002` | HIGH | Direct anchor: `expected = sut.f(a); assertEqual(sut.f(a), expected)` (identical args) |
| `ORACLE-003` | MEDIUM | Round-trip on self: `assertEqual(sut.loads(sut.dumps(x)), x)` and inverse pairs (encode/decode, serialize/deserialize, to_json/from_json, pack/unpack, ...) |
| `ORACLE-004` | HIGH | Snapshot-from-SUT: `snap = sut.f(a); assertEqual(sut.f(b), snap)` (differing args) |
| `ORACLE-005` | HIGH | Identity oracle: `assertTrue(x == x)` / `assertIs(x, x)` / `assert x is x` |
| `ORACLE-006` | MEDIUM | repr/str round-trip: `assertEqual(repr(x), repr(x))` / `str(x) == str(x)` on the same inner expression |
| `ORACLE-007` | MEDIUM | Fixture-from-SUT: `assertEqual(sut.compute(), sut.EXPECTED_CONSTANT)` |
| `ORACLE-008` | MEDIUM | Mock-echoes-input: assertion compares against the exact value placed into a mock's `return_value` in the same test |
| `ORACLE-009` | HIGH | Assertion-under-except-pass: `try: assert ...; except: pass` swallows the oracle |
| `ORACLE-010` | INFO | Vacuous condition: `assertTrue(True)` / `assertFalse(False)` / `assert 1` / `assert 'literal'` |

Rules ORACLE-002, ORACLE-004, and ORACLE-007 require a **module-under-test
hint** to fire. `oraclecheck` infers this per-file from the filename:
`tests/test_foo.py` -> SUT is `foo`; `bar_test.py` -> SUT is `bar`. Override
with `--sut MODULE`.

Rules 002 and 004 are mutually exclusive by construction:

- 002 fires when the expected side was assigned from a SUT call with
  arguments **identical** to the actual side.
- 004 fires when the expected side was assigned from a SUT call to the same
  callable but with **different** arguments (the true "snapshot" shape).

## Machine-readable output

```
oraclecheck --json tests/
```

produces (example):

```json
{
  "errors": [],
  "exit_code": 2,
  "files_errored": 0,
  "files_scanned": 3,
  "findings": [
    {
      "column": 8,
      "line": 22,
      "message": "expected value 'expected' was assigned from a call to the SUT ('mymod') on line 21; both sides flow from the same code with identical arguments",
      "path": "tests/test_mymod.py",
      "rule_id": "ORACLE-002",
      "severity": "HIGH"
    }
  ],
  "findings_total": 1,
  "findings_visible": 1,
  "verdict": "unhealthy"
}
```

JSON output uses `sort_keys=True` and fixed indent, so successive runs on
the same input are byte-identical.

## Honest scope and limits

- **Pattern-based, not proof.** `oraclecheck` inspects source shape via
  Python's `ast` module. It cannot follow control flow, resolve
  cross-file constants, expand fixtures, or reason about imports. Rules
  that require the SUT hint (002 / 004 / 007) rely on the caller referring
  to the SUT via its module name (`mymod.compute(...)`); the tool cannot
  detect anchoring when the SUT is accessed via `from mymod import compute`
  as bare `compute(...)` unless you pass `--sut compute`.
- **False negatives are expected.** Anchoring can hide behind helper
  functions, indirection through fixtures, or dynamic reflection. Treat
  `oraclecheck` as a pre-flight primitive, not a certification.
- **False positives are possible.** Genuine round-trip properties are
  sometimes intentional (round-trip *is* the specification for a codec).
  Use `--disable` per-rule, or per-test targeted `# noqa`-style comments in
  the caller layer.
- **Not a test runner.** `oraclecheck` never executes tested code; it only
  reads bytes.
- **Not a general secret detector.** Companion tools cover env drift,
  JWT hygiene, and license-chain hygiene.
- **Python only.** Tree-sitter-flavored ports to other languages are
  feasible; the AST-node ontology in `oraclecheck/parse.py` is intentionally
  small.

## Provenance and clean-room note

The framing (state-anchored oracles cannot fail, and re-anchoring recovers
lost mutation-kills) is motivated by:

- arXiv:2608.17214, "Oracles That Cannot Fail: The Anchoring Problem",
  2026-08-17.

Only the paper's abstract-level *framing* was read; the paper's methodology,
its ATC-simulator subject, and any reference measurement code were **not**
consulted during implementation. `oraclecheck` is an **independent
implementation, not affiliated with or endorsed by the paper's authors**.
The rule set here is chosen to be small, AST-detectable, and covers the
anchoring shapes most commonly observed in Python test suites in the
open-source ecosystem.

## Development

```
python -m unittest discover -s tests
```

142 tests: parser + rules + scanner + verdict/report + CLI + fixture-driven
end-to-end.

## License

MIT. See `LICENSE`.

## Disclosure

Produced by a human-machine hybrid intelligence, under maker-checker.
