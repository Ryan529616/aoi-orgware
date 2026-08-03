"""Pure, bounded checkpoint compaction helpers."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Sequence
from typing import Any, NamedTuple, cast


class CompactFactHistory(NamedTuple):
    marker: str
    recent: tuple[str, ...]


def snapshot_exact_json_object(value: object) -> dict[str, Any]:
    """Detach one plain-JSON object without invoking subtype callbacks."""

    active: set[int] = set()

    def clone(item: object) -> Any:
        item_type = type(item)
        if item_type is dict:
            identity = id(item)
            if identity in active:
                raise TypeError("checkpoint state must not contain cycles")
            active.add(identity)
            mapping = cast(dict[object, object], item)
            object_copy: dict[str, Any] = {}
            for key, child in mapping.items():
                if type(key) is not str:
                    raise TypeError("checkpoint state keys must be exact strings")
                object_copy[key] = clone(child)
            active.remove(identity)
            return object_copy
        if item_type is list:
            identity = id(item)
            if identity in active:
                raise TypeError("checkpoint state must not contain cycles")
            active.add(identity)
            sequence = cast(list[object], item)
            array_copy = [clone(child) for child in sequence]
            active.remove(identity)
            return array_copy
        if item_type in {str, int, bool} or item is None:
            return item
        if item_type is float and math.isfinite(cast(float, item)):
            return item
        raise TypeError("checkpoint state must contain only exact JSON builtins")

    try:
        snapshot = clone(value)
    except RecursionError as exc:
        raise TypeError("checkpoint state nesting exceeds the safe limit") from exc
    if type(snapshot) is not dict:
        raise TypeError("checkpoint state must be an exact JSON object")
    return snapshot


def checkpoint_compaction_marker(
    label: str,
    records: Sequence[dict[str, object]],
    compact_statuses: set[str],
    omitted_fields_per_record: int,
) -> str:
    """Describe terminal-detail compaction without dropping live records."""

    compact_count = sum(
        str(record.get("status")) in compact_statuses for record in records
    )
    status_counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
    counts = ",".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    ) or "none"
    return (
        f"Terminal-detail fallback for {label}: total={len(records)}; "
        f"full_detail={len(records) - compact_count}; "
        f"compact_detail={compact_count}; "
        f"omitted_field_slots={compact_count * omitted_fields_per_record}; "
        f"status_counts={counts}; complete records remain in state.json"
    )


def compact_fact_history(
    facts: Sequence[str],
    *,
    minimum_count: int,
    recent_tail: int,
    state_record_ref: str,
) -> CompactFactHistory | None:
    """Digest the complete fact history and retain a bounded verbatim tail."""

    if isinstance(minimum_count, bool) or not isinstance(minimum_count, int):
        raise ValueError("minimum_count must be an integer")
    if isinstance(recent_tail, bool) or not isinstance(recent_tail, int):
        raise ValueError("recent_tail must be an integer")
    if minimum_count < 0 or recent_tail < 0:
        raise ValueError("checkpoint fact bounds must be non-negative")
    if any(type(fact) is not str for fact in facts):
        raise TypeError("checkpoint facts must contain exact strings")
    if len(facts) < minimum_count:
        return None

    canonical = json.dumps(
        list(facts),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    recent_count = min(len(facts), recent_tail)
    recent = tuple(facts[-recent_count:]) if recent_count else ()
    # ``harnesslib._markdown_list`` strips edge whitespace and omits empty
    # entries.  Count only source entries that survive that normalization
    # byte-for-byte; keep the selected source-tail count separate.
    recent_verbatim = sum(
        bool(fact) and fact == fact.strip() for fact in recent
    )
    marker = (
        f"Established fact history: count={len(facts)}; "
        f"history_sha256={hashlib.sha256(canonical).hexdigest()}; "
        f"record={state_record_ref}; recent_verbatim={recent_verbatim}; "
        f"recent_source_entries={recent_count}"
    )
    return CompactFactHistory(marker=marker, recent=recent)


def first_fitting_text(
    *,
    render: Callable[[int], str],
    highest_recent_tail: int,
    max_bytes: int,
) -> str | None:
    """Return the largest recent-fact tail whose full render fits."""

    if isinstance(highest_recent_tail, bool) or not isinstance(
        highest_recent_tail, int
    ):
        raise ValueError("highest_recent_tail must be an integer")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise ValueError("max_bytes must be an integer")
    if highest_recent_tail < 0 or max_bytes < 0:
        raise ValueError("checkpoint render bounds must be non-negative")

    for recent_tail in range(highest_recent_tail, -1, -1):
        text = render(recent_tail)
        if not isinstance(text, str):
            raise TypeError("checkpoint renderer must return text")
        if len(text.encode("utf-8")) <= max_bytes:
            return text
    return None
