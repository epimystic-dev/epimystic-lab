"""Curated SPDX license knowledge table for AI-supply-chain compatibility checks.

Scope: the licenses that appear in practice on dataset / model / application
artifacts. Not a full SPDX catalog (SPDX 3.24 lists ~600+ ids); this table
covers what a hygiene linter needs to reason about compatibility and
obligation propagation. Unknown ids are still handled -- rule LIC-002 flags
non-SPDX identifiers explicitly.

Obligation flags per license entry:

  category      -- one of:
                    "permissive"        -- notice-only obligations
                    "weak-copyleft"     -- file / library scoped copyleft
                    "strong-copyleft"   -- combined-work copyleft
                    "network-copyleft"  -- includes network-service trigger
                    "share-alike"       -- CC-family same-license reuse
                    "no-derivatives"    -- modification restricted
                    "non-commercial"    -- commercial use restricted
                    "use-restricted"    -- RAIL / OpenRAIL style clauses
                    "public-domain"     -- effectively no obligations
                    "unknown"           -- fallback

  requires_notice          -- downstream must preserve copyright / license notice
  requires_source          -- downstream must offer corresponding source
  requires_same_license    -- downstream combined work must be same license
  restricts_commercial     -- forbids commercial use
  restricts_modification   -- forbids modification
  restricts_use            -- carries a use-restriction clause (RAIL, custom)
  data_only                -- license is intended for data / datasets, not code
  osi_approved             -- OSI approves the license
  fsf_libre                -- FSF considers it a free-software licence
  unversioned              -- id is ambiguous without a version suffix

Sources consulted (spec + factual identifier lists only, never anyone else's
compatibility-checker code):
  * SPDX License List spec (public spec text, not any tool)
  * FSF license commentary (public html)
  * Creative Commons license summary (public html)
  * BigScience OpenRAIL-M v1 public description
  * SPDX license expression grammar v2.3 spec
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class License:
    spdx_id: str
    name: str
    category: str
    requires_notice: bool = False
    requires_source: bool = False
    requires_same_license: bool = False
    restricts_commercial: bool = False
    restricts_modification: bool = False
    restricts_use: bool = False
    data_only: bool = False
    osi_approved: bool = False
    fsf_libre: bool = False
    unversioned: bool = False


def _l(**kw) -> License:
    return License(**kw)


_LICENSES_LIST = [
    # ---- Permissive (code-oriented) ----
    _l(spdx_id="MIT", name="MIT License", category="permissive",
       requires_notice=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="MIT-0", name="MIT No Attribution", category="public-domain",
       osi_approved=True),
    _l(spdx_id="Apache-2.0", name="Apache License 2.0", category="permissive",
       requires_notice=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="BSD-2-Clause", name="BSD 2-Clause \"Simplified\" License",
       category="permissive", requires_notice=True, osi_approved=True,
       fsf_libre=True),
    _l(spdx_id="BSD-3-Clause", name="BSD 3-Clause \"New\" License",
       category="permissive", requires_notice=True, osi_approved=True,
       fsf_libre=True),
    _l(spdx_id="ISC", name="ISC License", category="permissive",
       requires_notice=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="0BSD", name="BSD Zero Clause License",
       category="public-domain", osi_approved=True),
    _l(spdx_id="Unlicense", name="The Unlicense", category="public-domain",
       osi_approved=True),
    _l(spdx_id="WTFPL", name="Do What The F*ck You Want To Public License",
       category="public-domain", fsf_libre=True),
    _l(spdx_id="Zlib", name="zlib License", category="permissive",
       requires_notice=True, osi_approved=True, fsf_libre=True),

    # ---- Weak copyleft ----
    _l(spdx_id="LGPL-2.1-only", name="GNU LGPL v2.1 only",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       osi_approved=True, fsf_libre=True),
    _l(spdx_id="LGPL-2.1-or-later", name="GNU LGPL v2.1 or later",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       osi_approved=True, fsf_libre=True),
    _l(spdx_id="LGPL-3.0-only", name="GNU LGPL v3.0 only",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       osi_approved=True, fsf_libre=True),
    _l(spdx_id="LGPL-3.0-or-later", name="GNU LGPL v3.0 or later",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       osi_approved=True, fsf_libre=True),
    _l(spdx_id="MPL-2.0", name="Mozilla Public License 2.0",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       osi_approved=True, fsf_libre=True),
    _l(spdx_id="EPL-2.0", name="Eclipse Public License 2.0",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       osi_approved=True, fsf_libre=True),

    # ---- Strong copyleft ----
    _l(spdx_id="GPL-2.0-only", name="GNU GPL v2.0 only",
       category="strong-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="GPL-2.0-or-later", name="GNU GPL v2.0 or later",
       category="strong-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="GPL-3.0-only", name="GNU GPL v3.0 only",
       category="strong-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="GPL-3.0-or-later", name="GNU GPL v3.0 or later",
       category="strong-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="AGPL-3.0-only", name="GNU AGPL v3.0 only",
       category="network-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, osi_approved=True, fsf_libre=True),
    _l(spdx_id="AGPL-3.0-or-later", name="GNU AGPL v3.0 or later",
       category="network-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, osi_approved=True, fsf_libre=True),

    # ---- Unversioned / ambiguous forms (LIC-008) ----
    _l(spdx_id="GPL-2.0", name="GNU GPL v2.0 (unversioned form)",
       category="strong-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, unversioned=True),
    _l(spdx_id="GPL-3.0", name="GNU GPL v3.0 (unversioned form)",
       category="strong-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, unversioned=True),
    _l(spdx_id="LGPL-2.1", name="GNU LGPL v2.1 (unversioned form)",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       unversioned=True),
    _l(spdx_id="LGPL-3.0", name="GNU LGPL v3.0 (unversioned form)",
       category="weak-copyleft", requires_notice=True, requires_source=True,
       unversioned=True),
    _l(spdx_id="AGPL-3.0", name="GNU AGPL v3.0 (unversioned form)",
       category="network-copyleft", requires_notice=True, requires_source=True,
       requires_same_license=True, unversioned=True),

    # ---- Creative Commons (data-oriented) ----
    _l(spdx_id="CC0-1.0", name="Creative Commons Zero v1.0 Universal",
       category="public-domain", data_only=True, fsf_libre=True),
    _l(spdx_id="CC-BY-4.0", name="Creative Commons Attribution 4.0",
       category="permissive", requires_notice=True, data_only=True,
       fsf_libre=True),
    _l(spdx_id="CC-BY-3.0", name="Creative Commons Attribution 3.0",
       category="permissive", requires_notice=True, data_only=True),
    _l(spdx_id="CC-BY-SA-4.0",
       name="Creative Commons Attribution-ShareAlike 4.0",
       category="share-alike", requires_notice=True,
       requires_same_license=True, data_only=True, fsf_libre=True),
    _l(spdx_id="CC-BY-SA-3.0",
       name="Creative Commons Attribution-ShareAlike 3.0",
       category="share-alike", requires_notice=True,
       requires_same_license=True, data_only=True),
    _l(spdx_id="CC-BY-NC-4.0",
       name="Creative Commons Attribution-NonCommercial 4.0",
       category="non-commercial", requires_notice=True,
       restricts_commercial=True, data_only=True),
    _l(spdx_id="CC-BY-NC-SA-4.0",
       name="Creative Commons Attribution-NonCommercial-ShareAlike 4.0",
       category="non-commercial", requires_notice=True,
       requires_same_license=True, restricts_commercial=True,
       data_only=True),
    _l(spdx_id="CC-BY-ND-4.0",
       name="Creative Commons Attribution-NoDerivatives 4.0",
       category="no-derivatives", requires_notice=True,
       restricts_modification=True, data_only=True),
    _l(spdx_id="CC-BY-NC-ND-4.0",
       name="Creative Commons Attribution-NonCommercial-NoDerivatives 4.0",
       category="no-derivatives", requires_notice=True,
       restricts_commercial=True, restricts_modification=True,
       data_only=True),

    # ---- Data-specific ----
    _l(spdx_id="CDLA-Permissive-2.0",
       name="Community Data License Agreement Permissive 2.0",
       category="permissive", requires_notice=True, data_only=True),
    _l(spdx_id="CDLA-Sharing-1.0",
       name="Community Data License Agreement Sharing 1.0",
       category="share-alike", requires_notice=True,
       requires_same_license=True, data_only=True),
    _l(spdx_id="ODbL-1.0", name="Open Database License 1.0",
       category="share-alike", requires_notice=True,
       requires_same_license=True, data_only=True, fsf_libre=True),
    _l(spdx_id="ODC-By-1.0", name="Open Data Commons Attribution License 1.0",
       category="permissive", requires_notice=True, data_only=True),

    # ---- Use-restricted (RAIL family; NOT OSI-approved) ----
    _l(spdx_id="OpenRAIL", name="Open RAIL License (family)",
       category="use-restricted", requires_notice=True, restricts_use=True,
       unversioned=True),
    _l(spdx_id="OpenRAIL-M",
       name="BigScience OpenRAIL-M (model responsible-AI license)",
       category="use-restricted", requires_notice=True, restricts_use=True),
    _l(spdx_id="RAIL", name="Responsible AI License (family)",
       category="use-restricted", requires_notice=True, restricts_use=True,
       unversioned=True),

    # ---- Fallback / marker identifiers per SPDX spec ----
    _l(spdx_id="NOASSERTION", name="No assertion of a license",
       category="unknown"),
    _l(spdx_id="NONE", name="No license (all rights reserved)",
       category="unknown"),
]


LICENSES: Dict[str, License] = {L.spdx_id: L for L in _LICENSES_LIST}


def is_known_id(spdx_id: str) -> bool:
    """True iff spdx_id is present in the curated table (case-sensitive per
    SPDX spec; identifiers are case-sensitive)."""
    return spdx_id in LICENSES


def get_license(spdx_id: str) -> License:
    """Return the License record for spdx_id; raises KeyError if unknown."""
    return LICENSES[spdx_id]


# --- Compatibility matrix -----------------------------------------------
#
# is_downstream_compatible(upstream, downstream) -> (compatible, reason)
#
# "downstream" is the composed / derived work; "upstream" is a component
# consumed by it. This is a linter's heuristic layer (real license
# compatibility is a legal question) -- rules err on the side of surfacing
# a warning rather than silently permitting a risky combination.

_STRONG_COMPATIBLE_PAIRS = {
    ("GPL-2.0-only", "GPL-2.0-only"),
    ("GPL-2.0-or-later", "GPL-2.0-only"),
    ("GPL-2.0-or-later", "GPL-2.0-or-later"),
    ("GPL-2.0-or-later", "GPL-3.0-only"),
    ("GPL-2.0-or-later", "GPL-3.0-or-later"),
    ("GPL-3.0-only", "GPL-3.0-only"),
    ("GPL-3.0-or-later", "GPL-3.0-only"),
    ("GPL-3.0-or-later", "GPL-3.0-or-later"),
    ("AGPL-3.0-only", "AGPL-3.0-only"),
    ("AGPL-3.0-or-later", "AGPL-3.0-only"),
    ("AGPL-3.0-or-later", "AGPL-3.0-or-later"),
    # GPL upgrades to AGPL for network cases (permitted by GPL-3.0 § 13)
    ("GPL-3.0-only", "AGPL-3.0-only"),
    ("GPL-3.0-or-later", "AGPL-3.0-only"),
    ("GPL-3.0-or-later", "AGPL-3.0-or-later"),
}


def is_downstream_compatible(upstream_id: str, downstream_id: str
                             ) -> tuple[bool, str]:
    """Heuristic answer to: 'may a component under upstream_id be combined
    into a work distributed under downstream_id?'

    Returns (True, "") if compatible; (False, reason) if not.

    Undefined for unknown ids -- caller should gate on is_known_id() first.
    """
    if upstream_id == downstream_id:
        return True, ""

    up = LICENSES[upstream_id]
    down = LICENSES[downstream_id]

    # Public-domain / MIT-0 upstream: compatible with anything.
    if up.category == "public-domain":
        return True, ""

    # No-derivatives upstream: downstream must be the same or nothing changed.
    if up.category == "no-derivatives":
        return False, (f"{upstream_id} is a no-derivatives license; a "
                       f"downstream work under {downstream_id} implies "
                       f"modification, which is not permitted")

    # Non-commercial upstream: downstream must also be non-commercial.
    if up.restricts_commercial and not down.restricts_commercial:
        return False, (f"{upstream_id} restricts commercial use; downstream "
                       f"{downstream_id} does not carry that restriction")

    # Share-alike upstream (CC-BY-SA, CDLA-Sharing, ODbL): downstream must
    # be the same license.
    if up.category == "share-alike":
        return False, (f"{upstream_id} requires downstream under the same "
                       f"license; {downstream_id} is not the same")

    # Strong copyleft upstream: only specific downstream ids permitted.
    if up.category == "strong-copyleft":
        if (upstream_id, downstream_id) in _STRONG_COMPATIBLE_PAIRS:
            return True, ""
        return False, (f"{upstream_id} is strong copyleft; combined work "
                       f"under {downstream_id} is not on the compatibility "
                       f"list")

    # Network copyleft upstream: even stricter.
    if up.category == "network-copyleft":
        if (upstream_id, downstream_id) in _STRONG_COMPATIBLE_PAIRS:
            return True, ""
        return False, (f"{upstream_id} is network (AGPL-style) copyleft; "
                       f"combined work under {downstream_id} is not on the "
                       f"compatibility list")

    # Weak copyleft upstream: downstream may be permissive if the copyleft
    # component is used as a library and its own source is preserved;
    # we flag as "requires source availability" only, not as incompatible.
    if up.category == "weak-copyleft":
        return True, ""

    # Non-commercial upstream (that isn't ND / SA -- those branches already
    # handled above): compatible as long as the downstream also restricts
    # commercial use. The stricter branches above already returned; this
    # covers the plain CC-BY-NC family.
    if up.category == "non-commercial":
        if down.restricts_commercial:
            return True, ""
        return False, (f"{upstream_id} restricts commercial use; downstream "
                       f"{downstream_id} does not carry that restriction")

    # Use-restricted upstream (RAIL / OpenRAIL): downstream must also
    # carry the restriction, else obligations were dropped.
    if up.category == "use-restricted":
        if down.category == "use-restricted":
            return True, ""
        return False, (f"{upstream_id} carries use restrictions (RAIL-family "
                       f"clauses); downstream {downstream_id} does not "
                       f"propagate those restrictions")

    # Permissive upstream: broadly compatible with anything.
    if up.category == "permissive":
        return True, ""

    # Unknown fallback.
    return False, (f"{upstream_id} and {downstream_id} have no known "
                   f"compatibility rule in this table")
