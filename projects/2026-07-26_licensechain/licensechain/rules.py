"""Rule engine for licensechain.

Twelve documented rules. Each rule returns Findings; a Finding is a
structured record with rule id, severity, component, and human-readable
message. rules.py is the only module that decides severity.

Rule catalogue:

  LIC-001  ERROR  Component declares no license at all.
  LIC-002  WARN   License string parses but contains SPDX identifiers not
                  in the curated knowledge table (unknown id).
  LIC-003  ERROR  License string does not parse as an SPDX expression.
  LIC-004  ERROR  Copyleft obligation dropped downstream: upstream is
                  copyleft, downstream declares a permissive-only license
                  and the compatibility matrix rejects the pair.
  LIC-005  WARN   Attribution / notice obligation not confirmed: upstream
                  requires notice preservation but downstream component
                  does not carry `preserves_notices: true`.
  LIC-006  ERROR  Share-alike violated: upstream is share-alike category
                  and downstream picks a different license.
  LIC-007  ERROR  License incompatibility per compatibility matrix (covers
                  cases not caught by LIC-004 / LIC-006, e.g. no-derivatives
                  upstream, use-restriction propagation, dual-license
                  clauses that leave no legal common ground).
  LIC-008  WARN   Unversioned copyleft id (GPL-2.0 / GPL-3.0 / LGPL-2.1
                  / LGPL-3.0 / AGPL-3.0) -- ambiguous whether "-only" or
                  "-or-later" applies.
  LIC-009  ERROR  Critical link declares NOASSERTION or NONE.
  LIC-010  WARN   LicenseRef- component present without embedded license
                  text (an auditor must inspect the reference).
  LIC-011  ERROR  Non-commercial upstream used by a component that declares
                  `commercial_use: true`.
  LIC-012  INFO   Chain contains an orphan component (no upstream and no
                  downstream references it) -- not a violation but often a
                  manifest bug.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set

from .expr import (
    parse_expr, ParseError, Expr, LicenseId, LicenseRef, With,
    collect_ids, collect_refs, canonical_choices, iter_leaves,
)
from .spdx_data import (
    LICENSES, is_known_id, get_license, is_downstream_compatible,
)
from .loader import Chain, Component


class Severity(str, Enum):
    ERROR = "error"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    component: str
    message: str
    upstream: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "rule": self.rule,
            "severity": self.severity.value,
            "component": self.component,
            "message": self.message,
        }
        if self.upstream is not None:
            d["upstream"] = self.upstream
        return d


# --------- Per-component checks -------------------------------------------

def _check_license_declared(c: Component) -> List[Finding]:
    if c.license is None or not c.license.strip():
        return [Finding(
            rule="LIC-001",
            severity=Severity.ERROR,
            component=c.name,
            message=(
                f"component {c.name!r} (role={c.role}) declares no license; "
                "downstream reuse cannot be reasoned about without one"
            ),
        )]
    return []


def _parse_or_error(c: Component) -> tuple[Optional[Expr], List[Finding]]:
    if c.license is None or not c.license.strip():
        return None, []
    try:
        expr = parse_expr(c.license)
        return expr, []
    except ParseError as e:
        return None, [Finding(
            rule="LIC-003",
            severity=Severity.ERROR,
            component=c.name,
            message=(
                f"license expression {c.license!r} does not parse as an "
                f"SPDX license expression: {e}"
            ),
        )]


def _check_known_ids(c: Component, expr: Expr) -> List[Finding]:
    findings: List[Finding] = []
    for spdx_id in sorted(collect_ids(expr)):
        if not is_known_id(spdx_id):
            findings.append(Finding(
                rule="LIC-002",
                severity=Severity.WARN,
                component=c.name,
                message=(
                    f"license identifier {spdx_id!r} is not in the curated "
                    "SPDX table; compatibility rules cannot be applied to it"
                ),
            ))
    return findings


def _check_unversioned(c: Component, expr: Expr) -> List[Finding]:
    findings: List[Finding] = []
    for leaf in iter_leaves(expr):
        if isinstance(leaf, LicenseId) and leaf.spdx_id in LICENSES \
                and LICENSES[leaf.spdx_id].unversioned:
            findings.append(Finding(
                rule="LIC-008",
                severity=Severity.WARN,
                component=c.name,
                message=(
                    f"license identifier {leaf.spdx_id!r} is unversioned; "
                    "prefer the SPDX '-only' or '-or-later' form to remove "
                    "ambiguity about which GPL variant applies"
                ),
            ))
    return findings


def _check_noassertion(c: Component, expr: Expr) -> List[Finding]:
    for leaf in iter_leaves(expr):
        if isinstance(leaf, LicenseId) and leaf.spdx_id in ("NOASSERTION",
                                                            "NONE"):
            return [Finding(
                rule="LIC-009",
                severity=Severity.ERROR,
                component=c.name,
                message=(
                    f"component {c.name!r} declares its license as "
                    f"{leaf.spdx_id!r}; this is not a license and blocks "
                    "any downstream compatibility reasoning"
                ),
            )]
    return []


def _check_license_ref(c: Component, expr: Expr) -> List[Finding]:
    findings: List[Finding] = []
    for ref in sorted(collect_refs(expr)):
        findings.append(Finding(
            rule="LIC-010",
            severity=Severity.WARN,
            component=c.name,
            message=(
                f"component {c.name!r} refers to a custom license "
                f"{ref!r}; the manifest cannot verify its terms and an "
                "auditor must inspect the referenced text"
            ),
        ))
    return findings


# --------- Edge (upstream/downstream) checks ------------------------------

def _representative_ids(expr: Expr) -> List[str]:
    """The set of concrete spdx ids the downstream might be operating under.

    For an OR expression we return every branch; the linter reports on each
    to keep the report deterministic. LicenseRef leaves are ignored here
    (handled by LIC-010).
    """
    ids: List[str] = []
    for choice in canonical_choices(expr):
        for term in choice:
            if isinstance(term, LicenseId):
                ids.append(term.spdx_id)
            elif isinstance(term, With):
                base = term.base
                if isinstance(base, LicenseId):
                    ids.append(base.spdx_id)
    seen: Set[str] = set()
    out: List[str] = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _check_edge(down: Component, up: Component, kind: str,
                down_expr: Optional[Expr], up_expr: Optional[Expr]
                ) -> List[Finding]:
    findings: List[Finding] = []
    if down_expr is None or up_expr is None:
        return findings

    up_ids = [i for i in _representative_ids(up_expr) if is_known_id(i)
              and i not in ("NOASSERTION", "NONE")]
    down_ids = [i for i in _representative_ids(down_expr) if is_known_id(i)
                and i not in ("NOASSERTION", "NONE")]

    if not up_ids or not down_ids:
        return findings

    # SPDX OR-semantics: the downstream may operate under ANY single choice
    # from the upstream expression combined with ANY single choice from its
    # own expression. If at least one (up_id, down_id) pair is compatible,
    # the chain has a legal path and no incompatibility finding fires.
    compatible_pairs: List[tuple[str, str]] = []
    incompat_reasons: List[str] = []
    for up_id in up_ids:
        for down_id in down_ids:
            ok, reason = is_downstream_compatible(up_id, down_id)
            if ok:
                compatible_pairs.append((up_id, down_id))
            else:
                incompat_reasons.append(reason)

    # Obligation-propagation rules apply only when EVERY viable legal path
    # carries the obligation. If any legal path frees the downstream of the
    # obligation, we cannot claim the obligation was dropped -- the
    # downstream may simply have picked that path.
    viable_upstream_ids = (
        {u for u, _d in compatible_pairs} if compatible_pairs else set(up_ids)
    )

    if viable_upstream_ids and all(
        LICENSES[u].restricts_commercial for u in viable_upstream_ids
    ) and down.commercial_use:
        findings.append(Finding(
            rule="LIC-011",
            severity=Severity.ERROR,
            component=down.name,
            upstream=up.name,
            message=(
                f"{up.name!r} (viable legal paths: "
                f"{', '.join(sorted(viable_upstream_ids))}) forbids "
                f"commercial use, but downstream {down.name!r} declares "
                "commercial_use: true (set commercial_use: false or "
                "replace the upstream)"
            ),
        ))
        lic011_fired = True
    else:
        lic011_fired = False

    if viable_upstream_ids and all(
        LICENSES[u].requires_notice for u in viable_upstream_ids
    ) and not down.preserves_notices:
        findings.append(Finding(
            rule="LIC-005",
            severity=Severity.WARN,
            component=down.name,
            upstream=up.name,
            message=(
                f"{up.name!r} (viable legal paths: "
                f"{', '.join(sorted(viable_upstream_ids))}) requires "
                "attribution / notice preservation but downstream "
                f"{down.name!r} does not declare preserves_notices: true; "
                "confirm notices are carried forward"
            ),
        ))

    # LIC-004 / LIC-006 / LIC-007: only fire when NO compatible pair exists.
    if not compatible_pairs:
        # Categorize by the least-permissive upstream branch (share-alike
        # first, then strong-copyleft, then network-copyleft, then use-
        # restricted, then generic).
        first_up = up_ids[0]
        up_lic = get_license(first_up)
        for u in up_ids:
            cat = get_license(u).category
            if cat == "share-alike":
                first_up = u
                up_lic = get_license(u)
                break
        if up_lic.category == "share-alike":
            findings.append(Finding(
                rule="LIC-006",
                severity=Severity.ERROR,
                component=down.name,
                upstream=up.name,
                message=(
                    f"share-alike violated: {up.name!r} ({first_up}) "
                    f"requires the same license downstream but "
                    f"{down.name!r} declares "
                    f"{', '.join(down_ids)}"
                ),
            ))
        elif up_lic.category in ("strong-copyleft", "network-copyleft"):
            findings.append(Finding(
                rule="LIC-004",
                severity=Severity.ERROR,
                component=down.name,
                upstream=up.name,
                message=(
                    f"copyleft obligation dropped: {up.name!r} "
                    f"({first_up}) is {up_lic.category} but downstream "
                    f"{down.name!r} declares "
                    f"{', '.join(down_ids)} which is not on the "
                    "compatibility list"
                ),
            ))
        elif not lic011_fired:
            # LIC-011 already covers the NC-vs-commercial case with a
            # clearer, more actionable message; suppress LIC-007 for the
            # same edge to reduce report noise.
            findings.append(Finding(
                rule="LIC-007",
                severity=Severity.ERROR,
                component=down.name,
                upstream=up.name,
                message=(
                    f"license incompatibility: {up.name!r} ({first_up}) "
                    "is not compatible downstream with "
                    f"{down.name!r} ({', '.join(down_ids)}): "
                    f"{incompat_reasons[0] if incompat_reasons else 'no rule'}"
                ),
            ))
    return findings


# --------- Orphan check ---------------------------------------------------

def _check_orphans(chain: Chain) -> List[Finding]:
    referenced: Set[str] = set()
    for c in chain.components:
        for up_name, _kind in c.upstream_edges():
            referenced.add(up_name)

    findings: List[Finding] = []
    for c in chain.components:
        has_upstream = bool(c.upstream_edges())
        is_referenced = c.name in referenced
        if not has_upstream and not is_referenced:
            findings.append(Finding(
                rule="LIC-012",
                severity=Severity.INFO,
                component=c.name,
                message=(
                    f"component {c.name!r} is orphan: no upstream declared "
                    "and no downstream references it (verify manifest is "
                    "complete)"
                ),
            ))
    return findings


# --------- Public entry point --------------------------------------------

def check_chain(chain: Chain) -> List[Finding]:
    """Run every rule against every component / edge; return sorted findings.

    Sort key: (component, rule, upstream-or-empty) for deterministic output.
    """
    findings: List[Finding] = []
    parsed: dict[str, Optional[Expr]] = {}

    for c in chain.components:
        findings.extend(_check_license_declared(c))
        expr, parse_findings = _parse_or_error(c)
        findings.extend(parse_findings)
        parsed[c.name] = expr
        if expr is not None:
            findings.extend(_check_known_ids(c, expr))
            findings.extend(_check_unversioned(c, expr))
            findings.extend(_check_noassertion(c, expr))
            findings.extend(_check_license_ref(c, expr))

    for down, up, _kind in chain.iter_edges():
        findings.extend(_check_edge(
            down, up, _kind, parsed[down.name], parsed[up.name]
        ))

    findings.extend(_check_orphans(chain))

    def _key(f: Finding):
        # Order components in chain order so a report reads naturally,
        # then by rule, then by upstream.
        component_order = {c.name: i for i, c in
                           enumerate(chain.components)}
        return (component_order.get(f.component, 10**9),
                f.rule, f.upstream or "")

    findings.sort(key=_key)
    return findings
