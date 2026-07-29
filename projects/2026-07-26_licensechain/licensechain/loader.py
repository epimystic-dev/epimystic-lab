"""Manifest loader for licensechain.

A manifest describes a chain of components -- typically a dataset that a
model was trained on, a model built from that dataset, and one or more
applications that use the model. Each component has a name, a role, and a
declared license expression; edges are declared via `trained_on` / `uses`
/ `derived_from` fields.

Manifest schema (JSON):

    {
      "version": 1,
      "chain": [
        {
          "name": "<unique-name>",
          "role": "dataset" | "model" | "application" | "library" | "other",
          "license": "<SPDX expression>"        (optional but strongly rec.)
          "preserves_notices": true|false        (optional; default false)
          "commercial_use": true|false           (optional; default true)
          "trained_on":   ["<name>", ...]        (optional; model-specific)
          "derived_from": ["<name>", ...]        (optional; general derivation)
          "uses":         ["<name>", ...]        (optional; runtime dep)
          "notes": "..."                         (optional; freeform)
        },
        ...
      ]
    }

Any of trained_on / derived_from / uses represents an upstream edge; the
distinction is preserved in findings but they are all treated as
obligation-propagating relations for compatibility purposes.

Loader guarantees:
  * Every component has a name, and names are unique within the chain.
  * All referenced upstream names exist in the chain (else LoadError).
  * The graph is acyclic (else LoadError).

Rule-level concerns (missing license, non-SPDX id, etc.) are NOT enforced
by the loader -- they are the responsibility of rules.py, which returns
them as Findings rather than exceptions. The loader only fails on
structural problems that make the manifest un-analyzable.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Iterable, Tuple


ALLOWED_ROLES = {"dataset", "model", "application", "library", "other"}


class LoadError(ValueError):
    """Raised when a manifest cannot be loaded due to a structural problem."""


@dataclass
class Component:
    name: str
    role: str
    license: Optional[str] = None
    preserves_notices: bool = False
    commercial_use: bool = True
    trained_on: List[str] = field(default_factory=list)
    derived_from: List[str] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def upstream_edges(self) -> List[Tuple[str, str]]:
        """Return (upstream_name, edge_kind) for every declared upstream."""
        edges: List[Tuple[str, str]] = []
        for u in self.trained_on:
            edges.append((u, "trained_on"))
        for u in self.derived_from:
            edges.append((u, "derived_from"))
        for u in self.uses:
            edges.append((u, "uses"))
        return edges


@dataclass
class Chain:
    version: int
    components: List[Component]

    def by_name(self) -> Dict[str, Component]:
        return {c.name: c for c in self.components}

    def iter_edges(self) -> Iterable[Tuple[Component, Component, str]]:
        """Yield (downstream, upstream, kind) for every edge in the chain."""
        idx = self.by_name()
        for c in self.components:
            for up_name, kind in c.upstream_edges():
                yield c, idx[up_name], kind


def _validate_component(raw: dict, index: int) -> Component:
    if not isinstance(raw, dict):
        raise LoadError(
            f"chain[{index}]: expected an object, got {type(raw).__name__}"
        )
    if "name" not in raw or not isinstance(raw["name"], str) \
            or not raw["name"].strip():
        raise LoadError(f"chain[{index}]: 'name' must be a non-empty string")
    name = raw["name"].strip()

    role = raw.get("role", "other")
    if not isinstance(role, str) or role not in ALLOWED_ROLES:
        raise LoadError(
            f"chain[{index}] ({name}): 'role' must be one of "
            f"{sorted(ALLOWED_ROLES)}, got {role!r}"
        )

    license_field = raw.get("license", None)
    if license_field is not None and not isinstance(license_field, str):
        raise LoadError(
            f"chain[{index}] ({name}): 'license' must be a string or omitted"
        )

    for list_field in ("trained_on", "derived_from", "uses"):
        val = raw.get(list_field, [])
        if not isinstance(val, list) \
                or not all(isinstance(x, str) for x in val):
            raise LoadError(
                f"chain[{index}] ({name}): {list_field!r} must be a list "
                f"of strings"
            )

    return Component(
        name=name,
        role=role,
        license=license_field,
        preserves_notices=bool(raw.get("preserves_notices", False)),
        commercial_use=bool(raw.get("commercial_use", True)),
        trained_on=list(raw.get("trained_on", [])),
        derived_from=list(raw.get("derived_from", [])),
        uses=list(raw.get("uses", [])),
        notes=raw.get("notes"),
    )


def _check_acyclic(components: List[Component]) -> None:
    idx = {c.name: c for c in components}
    WHITE, GRAY, BLACK = 0, 1, 2
    colors = {c.name: WHITE for c in components}

    def visit(name: str, path: List[str]) -> None:
        if colors[name] == GRAY:
            cycle = path[path.index(name):] + [name]
            raise LoadError(
                f"chain contains a cycle: {' -> '.join(cycle)}"
            )
        if colors[name] == BLACK:
            return
        colors[name] = GRAY
        for up, _kind in idx[name].upstream_edges():
            visit(up, path + [name])
        colors[name] = BLACK

    for c in components:
        if colors[c.name] == WHITE:
            visit(c.name, [])


def _from_dict(data: dict) -> Chain:
    if not isinstance(data, dict):
        raise LoadError(
            f"manifest root must be an object, got {type(data).__name__}"
        )
    version = data.get("version", 1)
    if not isinstance(version, int):
        raise LoadError("'version' must be an integer")
    if version != 1:
        raise LoadError(
            f"unsupported manifest version {version} (this build supports 1)"
        )
    chain_raw = data.get("chain")
    if not isinstance(chain_raw, list):
        raise LoadError("'chain' must be a list of component objects")
    if not chain_raw:
        raise LoadError("'chain' is empty; manifest must declare >=1 component")

    components = [_validate_component(r, i) for i, r in enumerate(chain_raw)]

    names = [c.name for c in components]
    if len(set(names)) != len(names):
        seen: Dict[str, int] = {}
        for i, n in enumerate(names):
            if n in seen:
                raise LoadError(
                    f"duplicate component name {n!r} (first at chain[{seen[n]}],"
                    f" repeated at chain[{i}])"
                )
            seen[n] = i

    known = set(names)
    for c in components:
        for up_name, kind in c.upstream_edges():
            if up_name not in known:
                raise LoadError(
                    f"component {c.name!r} declares {kind}={up_name!r} but no "
                    f"component with that name exists in the chain"
                )

    _check_acyclic(components)

    return Chain(version=version, components=components)


def load_manifest(source) -> Chain:
    """Load a manifest from a path (str / os.PathLike) or a JSON string.

    If source is a path that exists on disk, it is read and parsed as JSON.
    Otherwise source is treated as the JSON text itself.

    A file-like object with a .read() method is also accepted.
    """
    import os

    if hasattr(source, "read"):
        text = source.read()
    elif isinstance(source, (str, os.PathLike)):
        s = os.fspath(source)
        # Heuristic: if it starts with { or [ after strip, treat as inline
        # JSON. Otherwise try to open it as a file path.
        stripped = s.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            text = s
        else:
            if not os.path.exists(s):
                raise LoadError(f"manifest file not found: {s}")
            with open(s, "r", encoding="utf-8-sig") as f:
                text = f.read()
    else:
        raise LoadError(
            f"unsupported source type {type(source).__name__}: "
            "expected path, JSON string, or file-like"
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LoadError(f"manifest is not valid JSON: {e}") from e

    return _from_dict(data)
