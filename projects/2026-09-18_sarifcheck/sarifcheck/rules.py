"""The sarifcheck rule table.

Clean-room note (binding on this file): every rule here was derived from the
OASIS SARIF 2.1.0 specification text and from the published code-scanning
ingest documentation. No reference implementation of the same idea was read
or ported - not the .NET SARIF SDK multitool and its rule catalogue, not the
sarif-tools package, not any other validator. Where a rule is obviously the
same shape as one in another tool, that is convergence on a shared spec, and
the README says so plainly rather than pretending novelty.

Each rule carries a profile:

  SPEC    - a MUST / SHALL in OASIS SARIF 2.1.0. The section reference is in
            the rule description; the citation is a paraphrase, never a quote.
  INGEST  - a requirement or published numeric ceiling of one documented
            code-scanning ingest. NOT part of the SARIF standard.
  HYGIENE - legal SARIF that a consumer has tripped over, or that publishes
            host layout into a report. Advisory by construction.

Every rule flags a SHAPE. None of them detects an attack, proves a leak, or
certifies that an upload will be accepted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import limits as limits_mod
from .parse import (
    absolute_uri_shape,
    as_dict,
    as_list,
    count_threadflow_locations,
    home_segment_shape,
    host_layout_matches,
    is_filesystem_absolute,
    iter_result_locations,
    location_artifact,
    nested_text,
    token_shaped_runs,
    uri_reference_defects,
)
from .types import Finding, Profile, RuleContext, Severity


# A single rule must not be able to bury the report. Past this many findings
# from one rule inside one run, the remainder is collapsed into one
# aggregate finding naming the count.
MAX_FINDINGS_PER_RULE_PER_RUN = 50


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    profile: Profile
    title: str
    description: str
    check_fn: Callable[[RuleContext], List[Finding]]


def _locate(ctx: RuleContext, prop: str) -> Tuple[int, int]:
    if ctx.lookup is None:
        return 1, 1
    return ctx.lookup.locate(prop)


def _emit(
    rule: Rule,
    ctx: RuleContext,
    prop: str,
    message: str,
    severity: Optional[Severity] = None,
    run_index: int = -1,
    result_index: int = -1,
    snippet: str = "",
) -> Finding:
    line, column = _locate(ctx, prop)
    return Finding(
        rule_id=rule.id,
        severity=severity or rule.severity,
        path=ctx.path,
        prop=prop,
        line=line,
        column=column,
        message=message,
        snippet=snippet,
        run_index=run_index,
        result_index=result_index,
    )


def _cap(rule: Rule, ctx: RuleContext, findings: List[Finding], run_index: int, prop: str) -> List[Finding]:
    """Collapse an over-long per-run finding list into a capped list."""
    if len(findings) <= MAX_FINDINGS_PER_RULE_PER_RUN:
        return findings
    remainder = len(findings) - MAX_FINDINGS_PER_RULE_PER_RUN
    kept = findings[:MAX_FINDINGS_PER_RULE_PER_RUN]
    kept.append(_emit(
        rule, ctx, prop,
        "and " + str(remainder) + " further " + rule.id + " finding(s) in this run, "
        "not listed individually (per-rule per-run cap is "
        + str(MAX_FINDINGS_PER_RULE_PER_RUN) + ")",
        run_index=run_index,
        result_index=10 ** 9,
    ))
    return kept


def _runs(ctx: RuleContext) -> List[Any]:
    return as_list(as_dict(ctx.doc).get("runs"))


def _limit(ctx: RuleContext, name: str) -> int:
    value = ctx.options.limits.get(name)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    fallback = limits_mod.limit_by_name(name)
    return fallback.value if fallback is not None else 0


# ---------------------------------------------------------------------------
# rule-reference resolution (all three spec-legal forms)
# ---------------------------------------------------------------------------


@dataclass
class RuleRef:
    has_reference: bool = False
    rule_id: Optional[str] = None
    rule_index: Optional[int] = None
    index_source: str = ""
    id_source: str = ""
    via_tool_component: bool = False
    descriptor: Optional[Dict[str, Any]] = None


def resolve_rule_reference(result: Any, run_index: Any) -> RuleRef:
    """Resolve a result's rule reference through every spec-legal form.

    SARIF 2.1.0 lets a result name its rule as a top-level `ruleId`, as a
    top-level `ruleIndex`, or as a `rule` reportingDescriptorReference
    object carrying `id` / `index` / `toolComponent`. A result that carries
    only `rule.index` must not be reported as missing a rule reference.
    """
    ref = RuleRef()
    result_dict = as_dict(result)

    rule_id = result_dict.get("ruleId")
    if isinstance(rule_id, str) and rule_id:
        ref.rule_id = rule_id
        ref.id_source = "ruleId"
        ref.has_reference = True

    rule_index = result_dict.get("ruleIndex")
    if isinstance(rule_index, int) and not isinstance(rule_index, bool):
        ref.rule_index = rule_index
        ref.index_source = "ruleIndex"
        if rule_index != -1:
            ref.has_reference = True

    rule_obj = result_dict.get("rule")
    if isinstance(rule_obj, dict):
        inner_id = rule_obj.get("id")
        if ref.rule_id is None and isinstance(inner_id, str) and inner_id:
            ref.rule_id = inner_id
            ref.id_source = "rule.id"
            ref.has_reference = True
        inner_index = rule_obj.get("index")
        if isinstance(inner_index, int) and not isinstance(inner_index, bool):
            if ref.rule_index is None:
                ref.rule_index = inner_index
                ref.index_source = "rule.index"
            if inner_index != -1:
                ref.has_reference = True
        if "toolComponent" in rule_obj:
            ref.via_tool_component = True

    # Attach the descriptor when it can be resolved without ambiguity.
    if ref.rule_id is not None and ref.rule_id in run_index.rule_id_to_pos:
        pos = run_index.rule_id_to_pos[ref.rule_id]
        ref.descriptor = as_dict(run_index.rules[pos])
    elif (
        ref.rule_index is not None
        and not ref.via_tool_component
        and 0 <= ref.rule_index < run_index.driver_rule_count
    ):
        ref.descriptor = as_dict(run_index.rules[ref.rule_index])
    return ref


# ---------------------------------------------------------------------------
# SRF-001 / SRF-002: version
# ---------------------------------------------------------------------------


_OLDER_VERSIONS = ("1.0.0", "2.0.0")
_PRERELEASE_RE = re.compile(r"^2\.[01]\.0-")


def _is_recognised_older_version(version: Any) -> bool:
    if not isinstance(version, str):
        return False
    if version in _OLDER_VERSIONS:
        return True
    return _PRERELEASE_RE.match(version) is not None


def _rule_001_version(ctx: RuleContext) -> List[Finding]:
    doc = as_dict(ctx.doc)
    version = doc.get("version")
    if version == "2.1.0":
        return []
    if _is_recognised_older_version(version):
        return []  # SRF-002 owns the recognised-older case
    if version is None:
        return [_emit(
            _RULE_001, ctx, "version",
            "top-level 'version' is absent; SARIF 2.1.0 requires the string \"2.1.0\"",
        )]
    return [_emit(
        _RULE_001, ctx, "version",
        "top-level 'version' is " + repr(version) + "; SARIF 2.1.0 requires the "
        "string \"2.1.0\"",
    )]


def _rule_002_old_version(ctx: RuleContext) -> List[Finding]:
    doc = as_dict(ctx.doc)
    version = doc.get("version")
    if not _is_recognised_older_version(version):
        return []
    return [_emit(
        _RULE_002, ctx, "version",
        "this file declares SARIF version " + repr(version) + ", a superseded or "
        "pre-release version; re-emit as 2.1.0 or convert before upload",
    )]


# ---------------------------------------------------------------------------
# SRF-003: $schema
# ---------------------------------------------------------------------------


_SCHEMA_TAIL_RE = re.compile(r"^sarif(-schema)?-(\d+)\.(\d+)\.(\d+)(-[A-Za-z0-9.]+)?\.json$")


def _schema_tail(value: str) -> str:
    tail = value.split("#", 1)[0].split("?", 1)[0]
    tail = tail.rstrip("/")
    if "/" in tail:
        tail = tail.rsplit("/", 1)[-1]
    return tail.lower()


def _classify_schema(value: Any) -> Tuple[str, str]:
    """Return (classification, detail).

    classification is one of "recognised", "other-version", "plausible",
    "unrelated".
    """
    if not isinstance(value, str) or not value.strip():
        return "unrelated", ""
    tail = _schema_tail(value.strip())
    match = _SCHEMA_TAIL_RE.match(tail)
    if match is not None:
        major, minor = match.group(2), match.group(3)
        if (major, minor) == ("2", "1"):
            return "recognised", tail
        return "other-version", major + "." + minor
    if "sarif" in value.lower():
        return "plausible", tail or value.strip()
    return "unrelated", tail or value.strip()


def _rule_003_schema(ctx: RuleContext) -> List[Finding]:
    doc = as_dict(ctx.doc)
    if "$schema" not in doc:
        return [_emit(
            _RULE_003, ctx, "$schema",
            "no '$schema' property. The OASIS spec does not require one; the "
            "documented ingest required-property list does. Point it at the "
            "SARIF 2.1.0 schema URL",
        )]
    classification, detail = _classify_schema(doc.get("$schema"))
    if classification == "recognised":
        return []
    if classification == "other-version":
        return [_emit(
            _RULE_003, ctx, "$schema",
            "'$schema' names SARIF " + detail + ", not 2.1.0",
            severity=Severity.HIGH,
        )]
    if classification == "plausible":
        return [_emit(
            _RULE_003, ctx, "$schema",
            "'$schema' does not match a known SARIF 2.1.0 schema filename "
            "(expected a tail like sarif-schema-2.1.0.json, optionally "
            "-rtm.N); this may still be a valid mirror",
            severity=Severity.INFO,
        )]
    return [_emit(
        _RULE_003, ctx, "$schema",
        "'$schema' does not look like a SARIF schema URL at all",
    )]


# ---------------------------------------------------------------------------
# result-side location walk, shared by SRF-004 / 005 / 014 / 020 / 024 / 025
# ---------------------------------------------------------------------------


def _iter_result_artifact_uris(ctx: RuleContext):
    """Yield (run_pos, result_pos, prop, artifact_location_dict)."""
    for run_pos, run in enumerate(_runs(ctx)):
        run_dict = as_dict(run)
        for result_pos, result in enumerate(as_list(run_dict.get("results"))):
            result_path = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]"
            for loc_prop, location in iter_result_locations(result, result_path):
                artifact, suffix = location_artifact(location)
                if artifact is None:
                    continue
                yield run_pos, result_pos, loc_prop + suffix, artifact


def _rule_004_absolute_uri(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, result_pos, prop, artifact in _iter_result_artifact_uris(ctx):
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri:
            continue
        shape = absolute_uri_shape(uri)
        if not is_filesystem_absolute(uri):
            continue
        extra = ""
        if "uriBaseId" in artifact:
            extra = (
                "; an absolute uri must not carry a uriBaseId (OASIS 2.1.0 "
                "section 3.4.4)"
            )
        finding = _emit(
            _RULE_004, ctx, prop + ".uri",
            "result artifactLocation.uri is absolute (" + shape + ", "
            + str(len(uri)) + " chars); a consumer cannot resolve it against a "
            "repository root, and it publishes the build host's layout" + extra,
            run_index=run_pos, result_index=result_pos,
            snippet=uri,
        )
        per_run.setdefault(run_pos, []).append(finding)
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_004, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


def _rule_005_uri_reference(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, result_pos, prop, artifact in _iter_result_artifact_uris(ctx):
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri:
            continue
        defects = uri_reference_defects(uri)
        if not defects:
            continue
        names = ", ".join(name + " at offset " + str(offset) for name, offset in defects)
        finding = _emit(
            _RULE_005, ctx, prop + ".uri",
            "artifactLocation.uri is not a valid URI reference: " + names
            + "; SARIF requires a URI reference here, so a native path "
              "separator or a raw space has to be escaped",
            run_index=run_pos, result_index=result_pos,
            snippet=uri,
        )
        per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_005, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-006 / SRF-007: host-layout path shapes
# ---------------------------------------------------------------------------


def _rule_006_path_in_message(ctx: RuleContext) -> List[Finding]:
    if ctx.options.allow_path_in_message:
        return []
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            ref = resolve_rule_reference(result, run_index)
            if ref.rule_id is not None and ref.rule_id in ctx.options.ignore_rule_ids:
                continue
            text = nested_text(result, "message")
            if not text:
                continue
            matches = host_layout_matches(text)
            if not matches:
                continue
            shapes = sorted(set(name for name, _, _ in matches))
            first_shape, first_offset, first_len = matches[0]
            prop = (
                "runs[" + str(run_pos) + "].results[" + str(result_pos)
                + "].message.text"
            )
            finding = _emit(
                _RULE_006, ctx, prop,
                "result message text contains a host-layout path shape ("
                + "/".join(shapes) + "), " + str(len(matches)) + " occurrence(s), "
                "first at character offset " + str(first_offset) + " (length "
                + str(first_len) + "). This is a string SHAPE, not evidence "
                "that anything sensitive was exposed. URI relativisation does "
                "not reach message text. Use --show-matches locally, or "
                "--ignore-rule-id / --allow-path-in-message when the path IS "
                "the finding",
                run_index=run_pos, result_index=result_pos,
                snippet=text[first_offset:first_offset + first_len],
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_006, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


def _build_path_sites(ctx: RuleContext):
    """Yield (run_pos, prop, uri) for the three build-path-bearing sites."""
    for run_pos, run in enumerate(_runs(ctx)):
        run_dict = as_dict(run)
        base_ids = run_dict.get("originalUriBaseIds")
        if isinstance(base_ids, dict):
            for key in sorted(base_ids.keys()):
                uri = as_dict(base_ids[key]).get("uri")
                if isinstance(uri, str) and uri:
                    yield (
                        run_pos,
                        "runs[" + str(run_pos) + "].originalUriBaseIds." + str(key) + ".uri",
                        uri,
                    )
        for inv_pos, invocation in enumerate(as_list(run_dict.get("invocations"))):
            uri = as_dict(as_dict(invocation).get("workingDirectory")).get("uri")
            if isinstance(uri, str) and uri:
                yield (
                    run_pos,
                    "runs[" + str(run_pos) + "].invocations[" + str(inv_pos)
                    + "].workingDirectory.uri",
                    uri,
                )
        for art_pos, artifact in enumerate(as_list(run_dict.get("artifacts"))):
            uri = as_dict(as_dict(artifact).get("location")).get("uri")
            if isinstance(uri, str) and uri:
                yield (
                    run_pos,
                    "runs[" + str(run_pos) + "].artifacts[" + str(art_pos)
                    + "].location.uri",
                    uri,
                )


def _rule_007_home_shape_in_uri(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, prop, uri in _build_path_sites(ctx):
        if not is_filesystem_absolute(uri):
            continue
        shape = home_segment_shape(uri)
        if shape is None:
            continue
        name, offset, seg_len = shape
        finding = _emit(
            _RULE_007, ctx, prop,
            "absolute uri carries a home-directory-shaped segment (" + name
            + ") at character offset " + str(offset) + "; the segment is "
            + str(seg_len) + " characters and is redacted here. An absolute "
            "uri is correct at this property, so this is a hygiene note about "
            "the host layout the file carries, not a spec violation and not "
            "proof that anything sensitive was exposed",
            run_index=run_pos,
            snippet=uri,
        )
        per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_007, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "]"))
    return out


# ---------------------------------------------------------------------------
# SRF-008 / 009 / 010 / 011: rule references
# ---------------------------------------------------------------------------


def _rule_008_no_rule_reference(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            ref = resolve_rule_reference(result, run_index)
            if ref.has_reference:
                continue
            prop = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]"
            finding = _emit(
                _RULE_008, ctx, prop,
                "result carries no rule reference in any spec-legal form "
                "(ruleId, ruleIndex, or rule.id / rule.index); this is legal "
                "SARIF, but a consumer cannot group or deduplicate the result",
                run_index=run_pos, result_index=result_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_008, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


def _rule_009_dangling_rule_id(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        if not run_index.has_rule_metadata:
            # Rule metadata is optional in SARIF. With no rules array every
            # ruleId is legally unresolvable, so firing here would emit one
            # finding per result on a large share of real files. SRF-010
            # reports the coverage gap once instead.
            continue
        if run_index.has_external_property_files:
            continue
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            ref = resolve_rule_reference(result, run_index)
            if ref.rule_id is None:
                continue
            if ref.rule_id in run_index.rule_id_to_pos:
                continue
            prop = (
                "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]."
                + (ref.id_source or "ruleId")
            )
            finding = _emit(
                _RULE_009, ctx, prop,
                "ruleId " + repr(ref.rule_id) + " does not resolve to a rule "
                "descriptor in this file (checked tool.driver.rules and every "
                "tool.extensions[].rules); the spec permits this, but a "
                "consumer has no name, help text, or configuration for the rule",
                run_index=run_pos, result_index=result_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_009, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


def _rule_010_no_rule_metadata(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        if run_index.has_rule_metadata:
            continue
        if run_index.has_external_property_files:
            continue
        if not run_index.results:
            continue
        out.append(_emit(
            _RULE_010, ctx, "runs[" + str(run_pos) + "].tool.driver.rules",
            "no rule metadata present in this run (" + str(len(run_index.results))
            + " result(s)); rule-reference integrity is not checkable and rule "
            "help text is not available to a consumer",
            run_index=run_pos,
        ))
    return out


def _rule_011_rule_index(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        count = run_index.driver_rule_count
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            ref = resolve_rule_reference(result, run_index)
            if ref.rule_index is None:
                continue
            if ref.via_tool_component and ref.index_source == "rule.index":
                # Index is relative to a named toolComponent this rule does
                # not resolve in v1; see the README scope statement.
                continue
            index_prop = (
                "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]."
                + (ref.index_source or "ruleIndex")
            )
            problem = ""
            if ref.rule_index < -1:
                problem = (
                    "is " + str(ref.rule_index) + "; SARIF array-index properties "
                    "default to -1 meaning 'not set', and no other negative value "
                    "is meaningful"
                )
            elif ref.rule_index == -1:
                continue
            elif count == 0:
                continue
            elif ref.rule_index >= count:
                problem = (
                    "is " + str(ref.rule_index) + " but tool.driver.rules holds "
                    + str(count) + " descriptor(s); the index is out of bounds"
                )
            else:
                descriptor_id = run_index.rule_ids[ref.rule_index]
                if (
                    ref.rule_id is not None
                    and descriptor_id is not None
                    and descriptor_id != ref.rule_id
                ):
                    problem = (
                        "points at a descriptor whose id is " + repr(descriptor_id)
                        + " while the result's rule id is " + repr(ref.rule_id)
                        + "; the two references disagree"
                    )
            if not problem:
                continue
            finding = _emit(
                _RULE_011, ctx, index_prop,
                (ref.index_source or "ruleIndex") + " " + problem,
                run_index=run_pos, result_index=result_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_011, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-012 / SRF-013: message and locations
# ---------------------------------------------------------------------------


def _rule_012_message(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            message = as_dict(result).get("message")
            prop = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "].message"
            if not isinstance(message, dict):
                finding = _emit(
                    _RULE_012, ctx, prop,
                    "result has no message object; the documented ingest "
                    "requires message.text (or a resolvable message.id)",
                    run_index=run_pos, result_index=result_pos,
                )
                per_run.setdefault(run_pos, []).append(finding)
                continue
            text = message.get("text")
            if isinstance(text, str) and text.strip():
                continue
            message_id = message.get("id")
            if isinstance(message_id, str) and message_id:
                ref = resolve_rule_reference(result, run_index)
                if ref.descriptor is None:
                    # Cannot resolve the descriptor, so cannot judge the id.
                    continue
                strings = as_dict(ref.descriptor.get("messageStrings"))
                if message_id in strings:
                    continue
                finding = _emit(
                    _RULE_012, ctx, prop + ".id",
                    "message.id " + repr(message_id) + " does not resolve to a key "
                    "in the referenced rule's messageStrings; the indirection is "
                    "dangling and a consumer has no text to display",
                    run_index=run_pos, result_index=result_pos,
                )
                per_run.setdefault(run_pos, []).append(finding)
                continue
            finding = _emit(
                _RULE_012, ctx, prop,
                "result has neither message.text nor a message.id; SARIF permits "
                "message.id plus arguments, but one of the two must be present "
                "for any consumer to display the result",
                run_index=run_pos, result_index=result_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_012, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


def _rule_013_locations(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            result_dict = as_dict(result)
            locations = result_dict.get("locations")
            if isinstance(locations, list) and locations:
                continue
            kind = result_dict.get("kind")
            non_location_kind = isinstance(kind, str) and kind != "fail"
            prop = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "].locations"
            if non_location_kind:
                message = (
                    "result has no locations[] and kind is " + repr(kind)
                    + "; the spec permits a location-free result of this kind, so "
                    "this is a note rather than a defect"
                )
                severity = Severity.INFO
            else:
                message = (
                    "result has an absent or empty locations[]; the spec permits "
                    "repository-level and tool-wide results with no location, but "
                    "the documented ingest requires at least one location for a "
                    "kind=fail result"
                )
                severity = None
            finding = _emit(
                _RULE_013, ctx, prop, message, severity=severity,
                run_index=run_pos, result_index=result_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_013, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-014: region coordinates
# ---------------------------------------------------------------------------


_REGION_FIELDS = ("startLine", "startColumn", "endLine", "endColumn")


def _rule_014_region(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            result_path = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]"
            for loc_prop, location in iter_result_locations(result, result_path):
                physical = as_dict(as_dict(location).get("physicalLocation"))
                for region_key in ("region", "contextRegion"):
                    region = physical.get(region_key)
                    if not isinstance(region, dict):
                        continue
                    for field_name in _REGION_FIELDS:
                        value = region.get(field_name)
                        if not isinstance(value, int) or isinstance(value, bool):
                            continue
                        if value >= 1:
                            continue
                        finding = _emit(
                            _RULE_014, ctx,
                            loc_prop + ".physicalLocation." + region_key + "." + field_name,
                            region_key + "." + field_name + " is " + str(value)
                            + "; SARIF region line and column numbers are 1-based, "
                            "so the smallest legal value is 1",
                            run_index=run_pos, result_index=result_pos,
                        )
                        per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_014, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-015: kind / level agreement
# ---------------------------------------------------------------------------


def _rule_015_kind_level(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            result_dict = as_dict(result)
            kind = result_dict.get("kind")
            level = result_dict.get("level")
            if not isinstance(kind, str) or kind == "fail":
                continue
            if not isinstance(level, str) or level == "none":
                continue
            prop = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "].level"
            finding = _emit(
                _RULE_015, ctx, prop,
                "result kind is " + repr(kind) + " but level is " + repr(level)
                + "; SARIF 2.1.0 requires level to be 'none' (or absent) whenever "
                "kind is anything other than 'fail'",
                run_index=run_pos, result_index=result_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_015, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-016 / SRF-017: documented ingest ceilings
# ---------------------------------------------------------------------------


def _tag_count(rule_descriptor: Any) -> int:
    tags = as_dict(as_dict(rule_descriptor).get("properties")).get("tags")
    return len(tags) if isinstance(tags, list) else 0


def _ceiling_findings(ctx: RuleContext, rule: Rule, hard: bool) -> List[Finding]:
    out: List[Finding] = []
    prefix = "" if hard else "soft_"

    def over(name: str, value: int) -> bool:
        return value > _limit(ctx, name)

    def under_hard(hard_name: str, value: int) -> bool:
        # Soft findings are suppressed when the hard ceiling already fired,
        # so one oversized array does not produce two findings.
        return value <= _limit(ctx, hard_name)

    runs = _runs(ctx)
    if hard and over("max_runs_per_file", len(runs)):
        out.append(_emit(
            rule, ctx, "runs",
            "file holds " + str(len(runs)) + " runs, over "
            + limits_mod.describe("max_runs_per_file"),
        ))
    for run_pos, run in enumerate(runs):
        run_index = ctx.index.runs[run_pos]
        results = as_list(as_dict(run).get("results"))
        results_limit = "max_results_per_run" if hard else (prefix + "results_per_run")
        if over(results_limit, len(results)) and (hard or under_hard("max_results_per_run", len(results))):
            out.append(_emit(
                rule, ctx, "runs[" + str(run_pos) + "].results",
                "run holds " + str(len(results)) + " results, over "
                + limits_mod.describe(results_limit),
                run_index=run_pos,
            ))
        if hard:
            rule_total = run_index.driver_rule_count + run_index.extension_rule_count
            if over("max_rules_per_run", rule_total):
                out.append(_emit(
                    rule, ctx, "runs[" + str(run_pos) + "].tool.driver.rules",
                    "run holds " + str(rule_total) + " rule descriptors across "
                    "driver and extensions, over "
                    + limits_mod.describe("max_rules_per_run"),
                    run_index=run_pos,
                ))
        for rule_pos, descriptor in enumerate(run_index.rules):
            tags = _tag_count(descriptor)
            tag_limit = "max_tags_per_rule" if hard else "soft_tags_per_rule"
            if over(tag_limit, tags) and (hard or under_hard("max_tags_per_rule", tags)):
                where = (
                    "runs[" + str(run_pos) + "].tool.driver.rules["
                    + str(rule_pos) + "].properties.tags"
                    if rule_pos < run_index.driver_rule_count
                    else "runs[" + str(run_pos) + "].tool.extensions[].rules[].properties.tags"
                )
                out.append(_emit(
                    rule, ctx, where,
                    "rule descriptor carries " + str(tags) + " tags, over "
                    + limits_mod.describe(tag_limit),
                    run_index=run_pos,
                ))
        for result_pos, result in enumerate(results):
            locations = as_list(as_dict(result).get("locations"))
            loc_limit = "max_locations_per_result" if hard else "soft_locations_per_result"
            if over(loc_limit, len(locations)) and (
                hard or under_hard("max_locations_per_result", len(locations))
            ):
                out.append(_emit(
                    rule, ctx,
                    "runs[" + str(run_pos) + "].results[" + str(result_pos) + "].locations",
                    "result carries " + str(len(locations)) + " locations, over "
                    + limits_mod.describe(loc_limit),
                    run_index=run_pos, result_index=result_pos,
                ))
            flow_total = count_threadflow_locations(result)
            flow_limit = (
                "max_threadflow_locations_per_result" if hard
                else "soft_threadflow_locations_per_result"
            )
            if over(flow_limit, flow_total) and (
                hard or under_hard("max_threadflow_locations_per_result", flow_total)
            ):
                out.append(_emit(
                    rule, ctx,
                    "runs[" + str(run_pos) + "].results[" + str(result_pos) + "].codeFlows",
                    "result carries " + str(flow_total) + " thread flow locations "
                    "summed across every codeFlow, over "
                    + limits_mod.describe(flow_limit),
                    run_index=run_pos, result_index=result_pos,
                ))
    return out


def _rule_016_hard_limits(ctx: RuleContext) -> List[Finding]:
    return _ceiling_findings(ctx, _RULE_016, hard=True)


def _rule_017_soft_limits(ctx: RuleContext) -> List[Finding]:
    return _ceiling_findings(ctx, _RULE_017, hard=False)


# ---------------------------------------------------------------------------
# SRF-018 / SRF-019: deduplication and rule documentation
# ---------------------------------------------------------------------------


def _rule_018_partial_fingerprints(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for run_pos, run in enumerate(_runs(ctx)):
        results = as_list(as_dict(run).get("results"))
        if not results:
            continue
        missing = 0
        first_pos = -1
        for result_pos, result in enumerate(results):
            fingerprints = as_dict(result).get("partialFingerprints")
            if isinstance(fingerprints, dict) and fingerprints:
                continue
            missing += 1
            if first_pos < 0:
                first_pos = result_pos
        if missing == 0:
            continue
        out.append(_emit(
            _RULE_018, ctx, "runs[" + str(run_pos) + "].results",
            str(missing) + " of " + str(len(results)) + " results in this run "
            "carry no partialFingerprints (first at index " + str(first_pos)
            + "). On the action upload path the ingest computes fingerprints "
            "itself; on the direct API upload path the same result can appear "
            "as a duplicate alert across uploads",
            run_index=run_pos, result_index=first_pos,
        ))
    return out


_RULE_DOC_FIELDS = ("shortDescription", "fullDescription", "help")


def _rule_019_rule_docs(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        for rule_pos, descriptor in enumerate(run_index.rules):
            missing = [
                field_name for field_name in _RULE_DOC_FIELDS
                if not nested_text(descriptor, field_name)
            ]
            if not missing:
                continue
            descriptor_id = as_dict(descriptor).get("id")
            where = (
                "runs[" + str(run_pos) + "].tool.driver.rules[" + str(rule_pos) + "]"
                if rule_pos < run_index.driver_rule_count
                else "runs[" + str(run_pos) + "].tool.extensions[].rules["
                     + str(rule_pos - run_index.driver_rule_count) + "]"
            )
            finding = _emit(
                _RULE_019, ctx, where,
                "rule descriptor " + repr(descriptor_id) + " is missing "
                + ", ".join(name + ".text" for name in missing)
                + "; the documented ingest required-property list expects all "
                "three so an alert has a title, a description, and help",
                run_index=run_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_019, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].tool.driver.rules"))
    return out


# ---------------------------------------------------------------------------
# SRF-020 / SRF-021: uriBaseId and the originalUriBaseIds chain
# ---------------------------------------------------------------------------


def _rule_020_undefined_uri_base_id(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        run_index = ctx.index.runs[run_pos]
        if run_index.has_external_property_files:
            continue
        defined = set(run_index.uri_base_ids.keys())
        seen: Dict[str, str] = {}
        run_dict = as_dict(run)
        for result_pos, result in enumerate(as_list(run_dict.get("results"))):
            result_path = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]"
            for loc_prop, location in iter_result_locations(result, result_path):
                artifact, suffix = location_artifact(location)
                if artifact is None:
                    continue
                base_id = artifact.get("uriBaseId")
                if isinstance(base_id, str) and base_id and base_id not in defined:
                    seen.setdefault(base_id, loc_prop + suffix + ".uriBaseId")
        for art_pos, artifact in enumerate(as_list(run_dict.get("artifacts"))):
            base_id = as_dict(as_dict(artifact).get("location")).get("uriBaseId")
            if isinstance(base_id, str) and base_id and base_id not in defined:
                seen.setdefault(
                    base_id,
                    "runs[" + str(run_pos) + "].artifacts[" + str(art_pos)
                    + "].location.uriBaseId",
                )
        for base_id in sorted(seen):
            finding = _emit(
                _RULE_020, ctx, seen[base_id],
                "uriBaseId " + repr(base_id) + " is referenced but not defined in "
                "runs[" + str(run_pos) + "].originalUriBaseIds; a consumer cannot "
                "resolve the relative uri against anything",
                run_index=run_pos,
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_020, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].originalUriBaseIds"))
    return out


def _walk_base_id_chain(base_ids: Dict[str, Any], start: str) -> Tuple[str, str]:
    """Walk an originalUriBaseIds chain to its root.

    Returns (status, detail) where status is "ok", "cycle", "dangling", or
    "relative-root". Each entry may itself carry a uriBaseId naming a parent
    entry; only the root of the chain has to hold an absolute uri.
    """
    seen: List[str] = []
    current = start
    while True:
        if current in seen:
            return "cycle", " -> ".join(seen + [current])
        seen.append(current)
        entry = as_dict(base_ids.get(current))
        parent = entry.get("uriBaseId")
        if isinstance(parent, str) and parent:
            if parent not in base_ids:
                return "dangling", parent
            current = parent
            if len(seen) > len(base_ids) + 1:  # pragma: no cover - belt and braces
                return "cycle", " -> ".join(seen)
            continue
        uri = entry.get("uri")
        if not isinstance(uri, str) or not uri:
            return "relative-root", current
        if absolute_uri_shape(uri) == "":
            return "relative-root", current
        return "ok", current


def _rule_021_base_id_chain(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for run_pos, run in enumerate(_runs(ctx)):
        base_ids = ctx.index.runs[run_pos].uri_base_ids
        if not base_ids:
            continue
        for key in sorted(base_ids.keys()):
            status, detail = _walk_base_id_chain(base_ids, key)
            if status == "ok":
                continue
            prop = "runs[" + str(run_pos) + "].originalUriBaseIds." + str(key)
            if status == "cycle":
                message = (
                    "originalUriBaseIds entry " + repr(key) + " is part of a "
                    "uriBaseId cycle (" + detail + "); the chain has no root to "
                    "resolve against"
                )
            elif status == "dangling":
                message = (
                    "originalUriBaseIds entry " + repr(key) + " names parent "
                    + repr(detail) + ", which is not defined in "
                    "originalUriBaseIds"
                )
            else:
                message = (
                    "originalUriBaseIds chain rooted at " + repr(detail)
                    + " has no absolute uri; SARIF requires the root of a "
                    "uriBaseId chain to be absolute"
                )
            out.append(_emit(_RULE_021, ctx, prop, message, run_index=run_pos))
    return out


# ---------------------------------------------------------------------------
# SRF-022: automationDetails
# ---------------------------------------------------------------------------


def _rule_022_automation_details(ctx: RuleContext) -> List[Finding]:
    runs = _runs(ctx)
    if len(runs) <= 1:
        return []
    out: List[Finding] = []
    for run_pos, run in enumerate(runs):
        details = as_dict(run).get("automationDetails")
        identifier = as_dict(details).get("id")
        if isinstance(identifier, str) and identifier:
            continue
        out.append(_emit(
            _RULE_022, ctx, "runs[" + str(run_pos) + "].automationDetails",
            "this file holds " + str(len(runs)) + " runs and this run has no "
            "automationDetails.id; runs from a matrix job that share a category "
            "overwrite each other's results on the consumer side",
            run_index=run_pos,
        ))
    return out


# ---------------------------------------------------------------------------
# SRF-023: compressed upload size
# ---------------------------------------------------------------------------


def _rule_023_compressed_size(ctx: RuleContext) -> List[Finding]:
    if ctx.compressed_bytes < 0:
        return []
    ceiling = _limit(ctx, "max_compressed_bytes")
    if ctx.compressed_bytes <= ceiling:
        return []
    return [_emit(
        _RULE_023, ctx, "",
        "gzip-compressed size is " + str(ctx.compressed_bytes) + " bytes (raw "
        + str(ctx.raw_bytes) + " bytes), over "
        + limits_mod.describe("max_compressed_bytes")
        + ". The documented ceiling is on the compressed payload, so sarifcheck "
        "compresses the file rather than guessing from the raw size",
    )]


# ---------------------------------------------------------------------------
# SRF-024: shapes known to have tripped a consumer
# ---------------------------------------------------------------------------


def _rule_024_fragile_shapes(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            result_dict = as_dict(result)
            base = "runs[" + str(run_pos) + "].results[" + str(result_pos) + "]"
            for loc_pos, location in enumerate(as_list(result_dict.get("locations"))):
                loc = as_dict(location)
                if "physicalLocation" in loc or "logicalLocations" in loc:
                    continue
                finding = _emit(
                    _RULE_024, ctx, base + ".locations[" + str(loc_pos) + "]",
                    "locations[] entry carries neither physicalLocation nor "
                    "logicalLocations; this is legal SARIF and it is a shape "
                    "that has tripped real consumers rendering the result",
                    run_index=run_pos, result_index=result_pos,
                )
                per_run.setdefault(run_pos, []).append(finding)
            for fix_pos, fix in enumerate(as_list(result_dict.get("fixes"))):
                for change_pos, change in enumerate(as_list(as_dict(fix).get("artifactChanges"))):
                    change_path = (
                        base + ".fixes[" + str(fix_pos) + "].artifactChanges["
                        + str(change_pos) + "]"
                    )
                    replacements = as_dict(change).get("replacements")
                    if not isinstance(replacements, list) or not replacements:
                        finding = _emit(
                            _RULE_024, ctx, change_path + ".replacements",
                            "artifactChange carries an absent or empty "
                            "replacements[]; a consumer applying the fix has "
                            "nothing to apply",
                            run_index=run_pos, result_index=result_pos,
                        )
                        per_run.setdefault(run_pos, []).append(finding)
                        continue
                    for rep_pos, replacement in enumerate(replacements):
                        rep = as_dict(replacement)
                        if "insertedContent" in rep or "deletedRegion" in rep:
                            continue
                        finding = _emit(
                            _RULE_024, ctx,
                            change_path + ".replacements[" + str(rep_pos) + "]",
                            "replacement carries neither insertedContent nor "
                            "deletedRegion; this is a shape that has tripped "
                            "real consumers applying a fix",
                            run_index=run_pos, result_index=result_pos,
                        )
                        per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_024, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-025: token-shaped strings
# ---------------------------------------------------------------------------


def _rule_025_token_shape(ctx: RuleContext) -> List[Finding]:
    per_run: Dict[int, List[Finding]] = {}
    for run_pos, run in enumerate(_runs(ctx)):
        for result_pos, result in enumerate(as_list(as_dict(run).get("results"))):
            text = nested_text(result, "message")
            if not text:
                continue
            runs_found = token_shaped_runs(text)
            if not runs_found:
                continue
            offset, length = runs_found[0]
            finding = _emit(
                _RULE_025, ctx,
                "runs[" + str(run_pos) + "].results[" + str(result_pos) + "].message.text",
                "message text contains " + str(len(runs_found)) + " token-shaped "
                "string(s) (a long opaque base64-like run); first at character "
                "offset " + str(offset) + ", length " + str(length) + ". The "
                "matched text is deliberately not printed. A content digest or a "
                "minified identifier matches this shape too - this is not a "
                "secret detection",
                run_index=run_pos, result_index=result_pos,
                snippet=text[offset:offset + length],
            )
            per_run.setdefault(run_pos, []).append(finding)
    out: List[Finding] = []
    for run_pos in sorted(per_run):
        out.extend(_cap(_RULE_025, ctx, per_run[run_pos], run_pos,
                        "runs[" + str(run_pos) + "].results"))
    return out


# ---------------------------------------------------------------------------
# SRF-026: absent provenance metadata
# ---------------------------------------------------------------------------


def _rule_026_metadata(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for run_pos, run in enumerate(_runs(ctx)):
        run_dict = as_dict(run)
        run_index = ctx.index.runs[run_pos]
        driver = as_dict(as_dict(run_dict.get("tool")).get("driver"))
        semantic = driver.get("semanticVersion")
        if not (isinstance(semantic, str) and semantic):
            out.append(_emit(
                _RULE_026, ctx,
                "runs[" + str(run_pos) + "].tool.driver.semanticVersion",
                "tool.driver.semanticVersion is absent; a consumer cannot tell "
                "which scanner version produced this run",
                run_index=run_pos,
            ))
        provenance = run_dict.get("versionControlProvenance")
        if not (isinstance(provenance, list) and provenance):
            out.append(_emit(
                _RULE_026, ctx,
                "runs[" + str(run_pos) + "].versionControlProvenance",
                "versionControlProvenance is absent; the run does not record "
                "which revision it analysed",
                run_index=run_pos,
            ))
        if not run_index.results and not run_index.rules and not run_index.has_external_property_files:
            out.append(_emit(
                _RULE_026, ctx, "runs[" + str(run_pos) + "]",
                "run holds zero results and zero rule descriptors; it may be an "
                "empty placeholder from a scan that did not execute",
                run_index=run_pos,
            ))
    return out


# ---------------------------------------------------------------------------
# SRF-027: external property files
# ---------------------------------------------------------------------------


def _rule_027_external_property_files(ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    for run_pos, run in enumerate(_runs(ctx)):
        if not ctx.index.runs[run_pos].has_external_property_files:
            continue
        keys = sorted(as_dict(as_dict(run).get("externalPropertyFileReferences")).keys())
        out.append(_emit(
            _RULE_027, ctx,
            "runs[" + str(run_pos) + "].externalPropertyFileReferences",
            "run references external property files (" + ", ".join(keys) + "); "
            "results, rules, and artifacts may legally live in those sidecar "
            "files, which sarifcheck does not read. This run is only partially "
            "analysed and the scan verdict cannot be 'healthy'",
            run_index=run_pos,
        ))
    return out


# ---------------------------------------------------------------------------
# rule table
# ---------------------------------------------------------------------------


_RULE_001 = Rule(
    "SRF-001", Severity.HIGH, Profile.SPEC,
    "version is absent or is not 2.1.0",
    "SARIF 2.1.0 requires the top-level 'version' property to hold the string "
    "\"2.1.0\". A recognised superseded or pre-release version is reported by "
    "SRF-002 instead, so the two never both fire.",
    _rule_001_version,
)
_RULE_002 = Rule(
    "SRF-002", Severity.HIGH, Profile.SPEC,
    "version names a superseded or pre-release SARIF version",
    "The file declares 1.0.0, 2.0.0, or a 2.x pre-release version. Split out "
    "from SRF-001 so an older emitter gets an actionable upgrade message "
    "instead of a generic rejection.",
    _rule_002_old_version,
)
_RULE_003 = Rule(
    "SRF-003", Severity.MEDIUM, Profile.INGEST,
    "$schema is absent or does not name the SARIF 2.1.0 schema",
    "$schema is NOT required by the OASIS specification; it is on the "
    "documented ingest required-property list. Absent reports MEDIUM, a "
    "different SARIF major/minor reports HIGH, and an unrecognised but "
    "plausible SARIF URL reports INFO. Known-good tails: sarif-schema-2.1.0.json "
    "and the -rtm.N variants.",
    _rule_003_schema,
)
_RULE_004 = Rule(
    "SRF-004", Severity.HIGH, Profile.SPEC,
    "result artifactLocation.uri is an absolute filesystem path",
    "Scoped to result-side locations only. An absolute uri is correct and "
    "expected in invocations[].workingDirectory.uri, in originalUriBaseIds, and "
    "in artifacts[].location when a uriBaseId is in play, so those sites are not "
    "visited by this rule. Flags posix-absolute, windows-drive, UNC, and file:// "
    "forms; http(s) URIs are left alone. OASIS 2.1.0 section 3.4.4 also forbids "
    "a uriBaseId alongside an absolute uri, which the message names when both "
    "are present.",
    _rule_004_absolute_uri,
)
_RULE_005 = Rule(
    "SRF-005", Severity.HIGH, Profile.SPEC,
    "artifactLocation.uri is not a valid URI reference",
    "A native backslash separator, a raw unescaped space, or a control "
    "character where SARIF requires a URI reference. Windows emitters produce "
    "the backslash form routinely.",
    _rule_005_uri_reference,
)
_RULE_006 = Rule(
    "SRF-006", Severity.MEDIUM, Profile.HYGIENE,
    "result message text contains a host-layout path shape",
    "URI relativisation does not reach message text. This rule matches a "
    "SHAPE - a drive path, a UNC path, a file:// URI, or a home-directory "
    "segment - and reports the shape, count, and offset, never the matched "
    "text unless --show-matches is given. A match is not evidence that "
    "anything sensitive was exposed. Taint-flow, path-traversal, and "
    "hardcoded-path scanners legitimately quote paths in message text: use "
    "--ignore-rule-id or --allow-path-in-message for those.",
    _rule_006_path_in_message,
)
_RULE_007 = Rule(
    "SRF-007", Severity.MEDIUM, Profile.HYGIENE,
    "build-path uri carries a home-directory-shaped segment",
    "Checks originalUriBaseIds[*].uri, invocations[*].workingDirectory.uri, and "
    "artifacts[*].location.uri - the three sites where a builder's absolute path "
    "lands even when result uris are correctly relative. Percent-encoding, "
    "file:// with and without authority, drive letters, and UNC are normalised "
    "before matching; the account-shaped segment is redacted in the output.",
    _rule_007_home_shape_in_uri,
)
_RULE_008 = Rule(
    "SRF-008", Severity.MEDIUM, Profile.INGEST,
    "result carries no rule reference in any spec-legal form",
    "ruleId is optional in SARIF, so a result without one is legal; the "
    "consequence is that a consumer cannot group or deduplicate it. All three "
    "forms are resolved first: ruleId, ruleIndex, and the rule "
    "reportingDescriptorReference object.",
    _rule_008_no_rule_reference,
)
_RULE_009 = Rule(
    "SRF-009", Severity.MEDIUM, Profile.SPEC,
    "ruleId does not resolve to a rule descriptor in this file",
    "Fires only when the run actually carries rule metadata. Rule metadata is "
    "optional in the spec, so an absent rules array makes every ruleId legally "
    "unresolvable - SRF-010 reports that coverage gap once instead of emitting "
    "one finding per result.",
    _rule_009_dangling_rule_id,
)
_RULE_010 = Rule(
    "SRF-010", Severity.INFO, Profile.SPEC,
    "run carries no rule metadata, so reference integrity is not checkable",
    "One note per run. Not a defect: rule metadata is optional. It states "
    "plainly that SRF-009 could not run against this run.",
    _rule_010_no_rule_metadata,
)
_RULE_011 = Rule(
    "SRF-011", Severity.HIGH, Profile.SPEC,
    "ruleIndex is out of range or disagrees with ruleId",
    "SARIF array-index properties default to -1 meaning 'not set', so -1 and "
    "an absent index are exempt. Flags a value below -1, a value at or beyond "
    "the driver rules array length, and an index whose descriptor id disagrees "
    "with a present ruleId. An index qualified by a toolComponent reference is "
    "out of scope in v1 and is skipped rather than guessed at.",
    _rule_011_rule_index,
)
_RULE_012 = Rule(
    "SRF-012", Severity.HIGH, Profile.INGEST,
    "result has no resolvable message",
    "message.id plus message.arguments referencing the rule's messageStrings is "
    "valid and common, so indirection is resolved before flagging. Fires when "
    "there is neither text nor id, and when a message.id does not resolve to a "
    "key in the referenced rule's messageStrings. When the rule descriptor "
    "cannot be resolved at all the id is left alone.",
    _rule_012_message,
)
_RULE_013 = Rule(
    "SRF-013", Severity.MEDIUM, Profile.INGEST,
    "result has an absent or empty locations[]",
    "Repository-level and tool-wide results with no location are spec-legal; "
    "the documented ingest rejects them for a kind=fail result. Reported at "
    "INFO when result.kind marks a non-location finding.",
    _rule_013_locations,
)
_RULE_014 = Rule(
    "SRF-014", Severity.HIGH, Profile.SPEC,
    "region line or column is zero or negative",
    "SARIF region line and column numbers are 1-based, so the smallest legal "
    "value is 1. A missing startLine is NOT flagged: byteOffset, charOffset, "
    "and byteLength are the legal binary-artifact region forms.",
    _rule_014_region,
)
_RULE_015 = Rule(
    "SRF-015", Severity.HIGH, Profile.SPEC,
    "kind is not 'fail' but level is set to something other than 'none'",
    "One of the few unambiguous MUSTs in the specification: when a result's "
    "kind is anything other than 'fail', its level is required to be 'none' or "
    "absent.",
    _rule_015_kind_level,
)
_RULE_016 = Rule(
    "SRF-016", Severity.HIGH, Profile.INGEST,
    "a documented hard ingest ceiling is exceeded",
    "runs per file, results per run, rule descriptors per run (driver plus "
    "every extension), locations per result, thread flow locations per result "
    "(summed across all codeFlows), and tags per rule. Every number is "
    "date-stamped with its source URL in limits.py and is overridable with "
    "--limit NAME=VALUE or --limits-file.",
    _rule_016_hard_limits,
)
_RULE_017 = Rule(
    "SRF-017", Severity.MEDIUM, Profile.INGEST,
    "a documented soft ingest ceiling is exceeded",
    "The display and truncation thresholds: results per run, locations per "
    "result, thread flow locations per result, and tags per rule. Suppressed "
    "when the matching hard ceiling already fired, so one oversized array "
    "produces one finding.",
    _rule_017_soft_limits,
)
_RULE_018 = Rule(
    "SRF-018", Severity.MEDIUM, Profile.INGEST,
    "results carry no partialFingerprints",
    "Reported once per run with a count rather than once per result. On the "
    "action upload path the ingest computes fingerprints itself; on the direct "
    "API upload path the same result can appear as a duplicate alert across "
    "uploads.",
    _rule_018_partial_fingerprints,
)
_RULE_019 = Rule(
    "SRF-019", Severity.MEDIUM, Profile.INGEST,
    "rule descriptor is missing shortDescription, fullDescription, or help text",
    "The documented ingest required-property list expects all three so an alert "
    "has a title, a description, and help. Not required by the specification.",
    _rule_019_rule_docs,
)
_RULE_020 = Rule(
    "SRF-020", Severity.MEDIUM, Profile.SPEC,
    "uriBaseId is referenced but not defined in originalUriBaseIds",
    "Skipped for a run that carries externalPropertyFileReferences, where the "
    "definition may legally live in a sidecar file.",
    _rule_020_undefined_uri_base_id,
)
_RULE_021 = Rule(
    "SRF-021", Severity.HIGH, Profile.SPEC,
    "originalUriBaseIds chain is broken",
    "Implemented as a chain walk, not a flat check: each entry may itself carry "
    "a uriBaseId naming a parent entry, and only the root of a chain has to hold "
    "an absolute uri. Reports a cycle, a dangling parent, and a chain whose root "
    "uri is missing or relative.",
    _rule_021_base_id_chain,
)
_RULE_022 = Rule(
    "SRF-022", Severity.MEDIUM, Profile.INGEST,
    "automationDetails.id is absent in a multi-run file",
    "Runs from a matrix job that share a category overwrite each other's results "
    "on the consumer side. Only fires when the file holds more than one run.",
    _rule_022_automation_details,
)
_RULE_023 = Rule(
    "SRF-023", Severity.HIGH, Profile.INGEST,
    "gzip-compressed size exceeds the documented upload ceiling",
    "The documented ceiling is on the compressed payload and SARIF is highly "
    "repetitive JSON, so sarifcheck compresses the file with the stdlib zlib "
    "module and compares that, rather than using the raw size as a proxy.",
    _rule_023_compressed_size,
)
_RULE_024 = Rule(
    "SRF-024", Severity.MEDIUM, Profile.HYGIENE,
    "a shape known to have tripped a real consumer",
    "Legal-but-sparse shapes: an artifactChange with an absent or empty "
    "replacements[], a replacement carrying neither insertedContent nor "
    "deletedRegion, and a locations[] entry with neither physicalLocation nor "
    "logicalLocations. Phrased strictly as 'a shape that has tripped a "
    "consumer', never as a prediction that a given consumer will crash.",
    _rule_024_fragile_shapes,
)
_RULE_025 = Rule(
    "SRF-025", Severity.INFO, Profile.HYGIENE,
    "message text contains a token-shaped string",
    "A long opaque base64-like run in result message text. Reports the rule "
    "code, the property path, the offset, and the match length only - never the "
    "substring. A content digest or a minified identifier matches this shape "
    "too; it is not a secret detection.",
    _rule_025_token_shape,
)
_RULE_026 = Rule(
    "SRF-026", Severity.INFO, Profile.HYGIENE,
    "provenance metadata is absent",
    "tool.driver.semanticVersion absent, versionControlProvenance absent, or a "
    "run holding zero results and zero rule descriptors.",
    _rule_026_metadata,
)
_RULE_027 = Rule(
    "SRF-027", Severity.INFO, Profile.SPEC,
    "run references external property files",
    "Results, rules, and artifacts can legally live in sidecar property files "
    "that sarifcheck does not read. The affected run is only partially analysed, "
    "the completeness-dependent rules are suppressed for it, and the scan "
    "verdict can never roll up to 'healthy'.",
    _rule_027_external_property_files,
)


ALL_RULES: Sequence[Rule] = (
    _RULE_001, _RULE_002, _RULE_003, _RULE_004, _RULE_005,
    _RULE_006, _RULE_007, _RULE_008, _RULE_009, _RULE_010,
    _RULE_011, _RULE_012, _RULE_013, _RULE_014, _RULE_015,
    _RULE_016, _RULE_017, _RULE_018, _RULE_019, _RULE_020,
    _RULE_021, _RULE_022, _RULE_023, _RULE_024, _RULE_025,
    _RULE_026, _RULE_027,
)


RULES_BY_ID: Dict[str, Rule] = dict((rule.id, rule) for rule in ALL_RULES)


def run_rules(ctx: RuleContext) -> List[Finding]:
    """Run every enabled, in-profile rule and return the flat finding list."""
    out: List[Finding] = []
    if not isinstance(ctx.doc, dict):
        return out
    for rule in ALL_RULES:
        if rule.id in ctx.options.disabled:
            continue
        if rule.profile.value not in ctx.options.profiles:
            continue
        out.extend(rule.check_fn(ctx))
    return out
