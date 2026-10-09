# mcptoolcheck

Offline static linter for *MCP tool-descriptor* files - the server-side
tool-advertisement surface each MCP server exposes via its `tools/list`
handshake. Reads a `tools/list` response snapshot, a server-side
manifest, or any JSON blob with tool-advertisement objects, and flags
twelve shape defects on the trust surface the agent host must decide to
approve.

Zero dependencies, pure Python stdlib, Python 3.10+.

## What problem it solves

Two converging 2026 signals establish the fault class.

1. **arXiv 2607.05744** (Rashidi, 2026-07-07): *"Unicode TAG-Block
   Concealment of Tool-Metadata Payloads in the Model Context Protocol:
   An Approval-View Fidelity Gap Across Three Independent Server
   Implementations"* shows that Plane 14 Tag characters (U+E0000 to
   U+E007F), bidi overrides, zero-width characters, and private-use
   codepoints are invisible in human approval dialogs but reach the
   model tokenizer. 8 out of 8 attack techniques delivered payloads
   across three independent MCP server implementations; 4 of those
   evaded string-matching sanitizers. The paper calls this an
   *approval-view fidelity gap* - the rendered approval view and the
   bytes delivered to the model do not have to match, and the protocol
   does not require them to.
2. **github.com/Paraphern/rugsnare** (2026-10-04 field report):
   140 silent changes across 66 release pairs of the four reference
   `@modelcontextprotocol/server-*` servers. The breakdown:
   43 BREAKING schema flips (`inputSchema` structure changed),
   28 ANNOTATION flips (`readOnlyHint` / `destructiveHint` toggled),
   7 COSMETIC description rewordings, 37 tools / prompts / resources
   added post-approval, 24 removed. The report concludes:
   *"Not one was announced in a changelog."*

Both signals land on the same surface: the tool-descriptor object the
server advertises. The host approves it once; neither the paper's
invisible-byte concealment nor the field report's silent drift are
observable from the record of that approval.

`mcptoolcheck` is a *pre-flight shape primitive* against this surface.
It is deterministic, offline, and fast; it does not run any MCP
server, does not fetch any URL, and does not touch the network. It is
not a replacement for a runtime integrity gateway (which can hash-pin
and re-check at every call), a runtime prompt-injection guard, or a
server-implementation static scanner (which can audit the server
*source*). It targets the shape of the tool-descriptor file
specifically because that is the smallest, most portable, CI-friendly
surface where several classes of defect can be caught before the
server is even started for the first time.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| MTC-001 | HIGH   | Tool description contains Unicode TAG block characters (U+E0000 to U+E007F). Plane 14 Tags render as nothing in approval dialogs but reach the model's tokenizer. |
| MTC-002 | HIGH   | Tool description contains bidi override characters (U+202A to U+202E, U+2066 to U+2069). Can reorder visible text away from wire order. |
| MTC-003 | HIGH   | Tool description contains zero-width characters (U+200B, U+200C, U+200D, U+2060) or a mid-string BOM (U+FEFF not at offset 0). Concealment surface. |
| MTC-004 | MEDIUM | Tool description contains C0 / C1 control characters (U+0000-U+001F excluding tab/newline/CR; U+007F-U+009F). Unexpected on a description surface. |
| MTC-005 | MEDIUM | Tool description contains private-use-area characters (U+E000-U+F8FF, U+F0000-U+FFFFD, U+100000-U+10FFFD, excluding the Tags block which is MTC-001). App-specific invisible semantics. |
| MTC-006 | HIGH   | Tool descriptor missing version / hash pin (no `version`, `revision`, `digest`, `sha256`, or `hash` field at either tool or document level). A silent change cannot be detected after initial approval. |
| MTC-007 | MEDIUM | Annotation hint inconsistent with name verb: `readOnlyHint=true` on a tool whose name contains a write verb (`write`, `update`, `delete`, `create`, `set`, `send`, `exec`, `install`, `deploy`, ...), or `destructiveHint=true` on a tool whose name contains a read verb (`read`, `list`, `get`, `search`, `view`, `status`, ...). This is the annotation-flip shape named by the field report. |
| MTC-008 | MEDIUM | Tool descriptor has neither a `readOnlyHint` nor a `destructiveHint` annotation. Without an annotation surface, downstream approval UI cannot pin the tool's effect class. |
| MTC-009 | MEDIUM | `inputSchema` is permissive or absent: missing entirely, missing `type`, missing `properties`, or `additionalProperties: true`. A permissive schema is a silent-change surface for the tool's argument shape. |
| MTC-010 | MEDIUM | Cross-script homoglyph word in `name` or `description` (a word mixes Latin / Cyrillic / Greek codepoints). A spoofing surface for publishing a near-identical tool. |
| MTC-011 | HIGH   | Tool `name` field itself contains TAG, bidi, zero-width, control, or PUA codepoints. The name is a higher-trust surface than the description; concealment here contaminates the primary approval anchor. |
| MTC-012 | INFO   | Tool description is empty, very short (<10 chars), or very long (>1500 chars). An underdocumentation or adversarial-loading surface. Hidden by default; surface with `--include-info` or `--strict`. |

Severity split: **5 HIGH** (MTC-001, 002, 003, 006, 011) /
**6 MEDIUM** (MTC-004, 005, 007, 008, 009, 010) / **1 INFO** (MTC-012).

Verdict rollup is deterministic (Convention B from the lab's
`docs/CONVENTIONS.md`):

- Any HIGH -> **unhealthy** (exit 2).
- Any MEDIUM, no HIGH -> **needs-attention** (exit 1).
- Only INFO -> **healthy** (exit 0) default, **needs-attention** (exit 1) with `--strict`.
- No findings, files scanned -> **healthy** (exit 0).
- No files scanned -> **unknown** (exit 1 default, exit 2 with `--strict`).

## Install

```bash
pip install -e .
```

Or run in place without install:

```bash
python -m mcptoolcheck tooldesc.json
```

## Use

```bash
# Scan a single file (default severity).
python -m mcptoolcheck examples/weak_tooldesc.json

# JSON output.
python -m mcptoolcheck tooldesc.json --json

# Surface INFO rules (without changing the verdict).
python -m mcptoolcheck tooldesc.json --include-info

# Strict mode: upgrade INFO-only outcomes to needs-attention.
python -m mcptoolcheck tooldesc.json --strict

# Disable a specific rule.
python -m mcptoolcheck tooldesc.json --disable MTC-010

# Run only a specific rule.
python -m mcptoolcheck tooldesc.json --only MTC-001

# Walk a directory of descriptor files.
python -m mcptoolcheck ./descriptors/
```

Exit codes follow Convention B above; a `0` exit means "no findings
surfaced under the active severity filter," never "I verified this
server is safe." A passing scan is **origin-valid**, not
**verified-safe**.

### Hidden characters are shown, not echoed

The text report writes every character outside printable ASCII as
`<U+XXXX>`. A tool name containing a zero-width space is reported as
`read<U+200B>_file`, not as `read_file` with the character silently
carried along. This keeps the concealed character visible in the very
report meant to expose it, and it means the report can be written to any
console - including a legacy Windows code page that cannot encode a
zero-width space or a Cyrillic letter - without failing. `--json` output
is ASCII-escaped by the JSON encoder and carries the exact original
strings.

## File shapes accepted

Four tool-descriptor file shapes are supported:

1. A `tools/list` response snapshot:
   `{"tools": [{"name": ..., "description": ..., ...}, ...]}`
2. A bare array:
   `[{"name": ..., "description": ..., ...}, ...]`
3. A dict keyed by tool name:
   `{"my_tool": {"description": ..., "inputSchema": {...}}}`
4. A single tool-descriptor object:
   `{"name": ..., "description": ..., ...}`

## Honest scope

- The linter is **shape-only**. It cannot verify that the bytes a
  server advertises today equal the bytes it advertised yesterday
  (that requires a runtime hash-pin gateway and a stored baseline),
  it cannot verify that an approval record is honoured at tool-call
  time, and it cannot detect semantic drift that preserves shape.
- Rule MTC-010 is a tight heuristic. It flags *cross-script words*
  (Latin + Cyrillic, Latin + Greek, etc.) and does not try to
  enumerate every possible homoglyph pair; a pure-Latin word that
  spoofs a pure-Latin name is out of scope.
- Rule MTC-007 fires on an explicit `readOnlyHint=true` or
  `destructiveHint=true` combined with a strong verb token in the
  name. It does not try to infer intent from the description alone.
- Rule MTC-006 counts any non-empty string under `version`,
  `revision`, `digest`, `sha256`, or `hash` as a pin. It does not
  validate the pin format or recompute a digest.

## Clean-room statement

This is an independent implementation. The rule derivation reads only
the public abstract of arXiv 2607.05744 (the named concealment classes
and the five metadata surfaces listed in the paper), the public README
of github.com/Paraphern/rugsnare (the named silent-change categories
and the pinnable surfaces listed in the field report), and the public
Model Context Protocol JSON-RPC specification for the `tools/list`
response shape. No reference implementation of either artifact was
read, vendored, or mirrored. Not affiliated with or endorsed by the
authors of the paper or of the field report.

## License

MIT. See `LICENSE`.
