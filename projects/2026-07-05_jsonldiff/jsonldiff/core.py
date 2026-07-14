"""jsonldiff core: streaming JSONL diff with structural, path-aware output.

Two alignment modes:

* Line mode (default): the Nth record of one file is compared to the Nth record
  of the other. O(1) memory, streaming both files in parallel.
* Key mode (``key`` argument): each record is indexed by the value at a dotted
  path (e.g. ``id`` or ``metadata.run_id``); records with equal keys are
  compared, and unmatched records are reported as missing on their respective
  side. Buffers the baseline into memory (O(N_baseline) records).

Diff semantics:

* Dicts are compared key-wise: added / removed / recursively-diffed.
* Lists are compared position-wise (index-aligned). Unordered comparison is
  out of scope for the MVP.
* Scalars use Python ``==`` for equality; JSON numbers of different types
  (``1`` vs ``1.0``) compare equal, matching JSON's single-number model.
* Type mismatches (dict where a list was expected, etc.) are reported as a
  single ``changed`` event at the containing path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
)

_MISSING = object()


@dataclass(frozen=True)
class Change:
    """A single structural change between two records."""

    kind: str
    path: str
    position: int
    baseline: Any = None
    candidate: Any = None
    key: Any = None
    # ``kind`` values:
    # - "changed"                     : both sides present, values differ
    # - "added"                       : path present in candidate, not baseline
    # - "removed"                     : path present in baseline, not candidate
    # - "missing_in_baseline"         : whole record absent from baseline
    # - "missing_in_candidate"        : whole record absent from candidate
    # - "parse_error_baseline"        : baseline line failed to parse
    # - "parse_error_candidate"       : candidate line failed to parse

    def to_json(self) -> dict:
        d: dict = {"kind": self.kind, "position": self.position}
        if self.path:
            d["path"] = self.path
        if self.baseline is not _MISSING and self.kind != "added":
            d["baseline"] = self.baseline
        if self.candidate is not _MISSING and self.kind != "removed":
            d["candidate"] = self.candidate
        if self.key is not None:
            d["key"] = self.key
        return d


def diff_records(
    baseline: Any,
    candidate: Any,
    position: int = 0,
    ignore: Sequence[str] = (),
    prefix: str = "",
) -> List[Change]:
    """Diff two already-parsed JSON records."""

    ignore_set = set(ignore)
    out: List[Change] = []
    _walk(baseline, candidate, prefix, position, ignore_set, out)
    return out


def _walk(
    a: Any,
    b: Any,
    path: str,
    position: int,
    ignore: set,
    out: List[Change],
) -> None:
    if _ignored(path, ignore):
        return
    if type(a) is dict and type(b) is dict:
        _walk_dict(a, b, path, position, ignore, out)
        return
    if type(a) is list and type(b) is list:
        _walk_list(a, b, path, position, ignore, out)
        return
    if a == b and type(a) is type(b):
        return
    # Handle JSON's single-number semantics: int and float compare equal.
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool):
        if a == b:
            return
    out.append(Change(kind="changed", path=path, position=position, baseline=a, candidate=b))


def _walk_dict(a: dict, b: dict, path: str, position: int, ignore: set, out: List[Change]) -> None:
    for key in a:
        sub = _join(path, key)
        if _ignored(sub, ignore):
            continue
        if key not in b:
            out.append(Change(kind="removed", path=sub, position=position, baseline=a[key]))
        else:
            _walk(a[key], b[key], sub, position, ignore, out)
    for key in b:
        if key in a:
            continue
        sub = _join(path, key)
        if _ignored(sub, ignore):
            continue
        out.append(Change(kind="added", path=sub, position=position, candidate=b[key]))


def _walk_list(a: list, b: list, path: str, position: int, ignore: set, out: List[Change]) -> None:
    for i in range(min(len(a), len(b))):
        _walk(a[i], b[i], _join(path, str(i)), position, ignore, out)
    if len(a) > len(b):
        for i in range(len(b), len(a)):
            sub = _join(path, str(i))
            if _ignored(sub, ignore):
                continue
            out.append(Change(kind="removed", path=sub, position=position, baseline=a[i]))
    elif len(b) > len(a):
        for i in range(len(a), len(b)):
            sub = _join(path, str(i))
            if _ignored(sub, ignore):
                continue
            out.append(Change(kind="added", path=sub, position=position, candidate=b[i]))


def _join(prefix: str, part: str) -> str:
    return part if not prefix else f"{prefix}.{part}"


def _ignored(path: str, ignore: set) -> bool:
    if not path:
        return False
    if path in ignore:
        return True
    # Prefix match on dotted segments only, so ``metrics`` ignores
    # ``metrics.accuracy`` but not ``metrics_v2.accuracy``.
    for pat in ignore:
        if path.startswith(pat + "."):
            return True
    return False


def _extract_key(record: Any, key_path: str) -> Any:
    """Extract the value at ``key_path`` from a parsed JSON record.

    Missing intermediate segments raise ``KeyError`` so callers can distinguish
    "explicitly-null key" from "no key here". Array indices are supported.
    """

    if not key_path:
        return record
    cur = record
    for part in key_path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                raise KeyError(part)
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError as exc:
                raise KeyError(part) from exc
            if idx < 0 or idx >= len(cur):
                raise KeyError(part)
            cur = cur[idx]
        else:
            raise KeyError(part)
    return cur


def _iter_jsonl(stream: Iterable[str]) -> Iterator[Tuple[int, Any, Optional[str]]]:
    """Yield ``(position, parsed, error)`` per non-blank line.

    ``position`` is 1-indexed. ``error`` is ``None`` on success, otherwise a
    short message; ``parsed`` is ``None`` on error.
    """

    for i, raw in enumerate(stream, start=1):
        line = raw
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
        if not line.strip():
            continue
        try:
            yield i, json.loads(line), None
        except json.JSONDecodeError as exc:
            yield i, None, f"json parse error at column {exc.colno}: {exc.msg}"


def diff_streams(
    baseline: Iterable[str],
    candidate: Iterable[str],
    key: Optional[str] = None,
    ignore: Sequence[str] = (),
    max_diffs: Optional[int] = None,
) -> Iterator[Change]:
    """Diff two iterables of raw JSONL text lines. Yields ``Change`` records
    lazily so callers can bail out early.
    """

    if key is None:
        yield from _diff_by_line(baseline, candidate, ignore, max_diffs)
    else:
        yield from _diff_by_key(baseline, candidate, key, ignore, max_diffs)


def _diff_by_line(
    baseline: Iterable[str],
    candidate: Iterable[str],
    ignore: Sequence[str],
    max_diffs: Optional[int],
) -> Iterator[Change]:
    a_iter = _iter_jsonl(baseline)
    b_iter = _iter_jsonl(candidate)
    emitted = 0
    while True:
        try:
            a_pos, a_val, a_err = next(a_iter)
        except StopIteration:
            a_pos = a_val = a_err = None
        try:
            b_pos, b_val, b_err = next(b_iter)
        except StopIteration:
            b_pos = b_val = b_err = None

        if a_pos is None and b_pos is None:
            return

        # Use the max of the two positions as the emit-position: it is stable
        # when the streams are equal length, and clearly identifies the
        # offending line otherwise.
        pos = a_pos if a_pos is not None else b_pos

        if a_err:
            yield Change(kind="parse_error_baseline", path="", position=a_pos or 0, baseline=a_err)
            emitted += 1
        if b_err:
            yield Change(kind="parse_error_candidate", path="", position=b_pos or 0, candidate=b_err)
            emitted += 1
        if max_diffs is not None and emitted >= max_diffs:
            return

        if a_pos is None:
            yield Change(kind="missing_in_baseline", path="", position=b_pos, candidate=b_val)
            emitted += 1
        elif b_pos is None:
            yield Change(kind="missing_in_candidate", path="", position=a_pos, baseline=a_val)
            emitted += 1
        elif a_err or b_err:
            pass  # already reported
        else:
            for change in diff_records(a_val, b_val, position=pos, ignore=ignore):
                yield change
                emitted += 1
                if max_diffs is not None and emitted >= max_diffs:
                    return

        if max_diffs is not None and emitted >= max_diffs:
            return


def _diff_by_key(
    baseline: Iterable[str],
    candidate: Iterable[str],
    key_path: str,
    ignore: Sequence[str],
    max_diffs: Optional[int],
) -> Iterator[Change]:
    index: dict = {}
    order: List = []
    seen_baseline_keys: set = set()
    emitted = 0

    for pos, val, err in _iter_jsonl(baseline):
        if err:
            yield Change(kind="parse_error_baseline", path="", position=pos, baseline=err)
            emitted += 1
            if max_diffs is not None and emitted >= max_diffs:
                return
            continue
        try:
            k = _extract_key(val, key_path)
        except KeyError:
            yield Change(
                kind="parse_error_baseline",
                path="",
                position=pos,
                baseline=f"key path {key_path!r} missing from record",
            )
            emitted += 1
            if max_diffs is not None and emitted >= max_diffs:
                return
            continue
        marker = _hashable_key(k)
        if marker in index:
            # Duplicate key: keep the first, note the collision.
            yield Change(
                kind="parse_error_baseline",
                path="",
                position=pos,
                baseline=f"duplicate key {k!r} at baseline line {pos}",
                key=k,
            )
            emitted += 1
            if max_diffs is not None and emitted >= max_diffs:
                return
            continue
        index[marker] = (pos, val, k)
        order.append(marker)

    for pos, val, err in _iter_jsonl(candidate):
        if err:
            yield Change(kind="parse_error_candidate", path="", position=pos, candidate=err)
            emitted += 1
            if max_diffs is not None and emitted >= max_diffs:
                return
            continue
        try:
            k = _extract_key(val, key_path)
        except KeyError:
            yield Change(
                kind="parse_error_candidate",
                path="",
                position=pos,
                candidate=f"key path {key_path!r} missing from record",
            )
            emitted += 1
            if max_diffs is not None and emitted >= max_diffs:
                return
            continue
        marker = _hashable_key(k)
        if marker not in index:
            yield Change(kind="missing_in_baseline", path="", position=pos, candidate=val, key=k)
            emitted += 1
        else:
            b_pos, b_val, b_key = index[marker]
            for change in diff_records(b_val, val, position=pos, ignore=ignore):
                yield Change(
                    kind=change.kind,
                    path=change.path,
                    position=pos,
                    baseline=change.baseline,
                    candidate=change.candidate,
                    key=k,
                )
                emitted += 1
                if max_diffs is not None and emitted >= max_diffs:
                    return
            seen_baseline_keys.add(marker)
        if max_diffs is not None and emitted >= max_diffs:
            return

    for marker in order:
        if marker in seen_baseline_keys:
            continue
        b_pos, b_val, b_key = index[marker]
        yield Change(kind="missing_in_candidate", path="", position=b_pos, baseline=b_val, key=b_key)
        emitted += 1
        if max_diffs is not None and emitted >= max_diffs:
            return


def _hashable_key(k: Any) -> Any:
    """Return a hashable representation of ``k``. Lists and dicts are
    JSON-serialised with sorted keys so equal-content keys collide.
    """

    if isinstance(k, (str, int, float, bool)) or k is None:
        return ("scalar", k)
    return ("json", json.dumps(k, sort_keys=True, ensure_ascii=False))


def diff_files(
    baseline_path: str | Path,
    candidate_path: str | Path,
    key: Optional[str] = None,
    ignore: Sequence[str] = (),
    max_diffs: Optional[int] = None,
) -> List[Change]:
    """Diff two files on disk. Returns the full change list."""

    with open(baseline_path, "r", encoding="utf-8", newline="") as a, open(
        candidate_path, "r", encoding="utf-8", newline=""
    ) as b:
        return list(diff_streams(a, b, key=key, ignore=ignore, max_diffs=max_diffs))
