"""Pure, bounded checkpoint compaction helpers."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Sequence
from typing import Any, NamedTuple, cast


CHECKPOINT_STRING_HISTORY_FIELDS = (
    "facts",
    "decisions",
    "rejected_paths",
    "changed_files",
)
_STRING_HISTORY_LABELS = {
    "facts": "fact",
    "decisions": "decision",
    "rejected_paths": "rejected-path",
    "changed_files": "changed-file",
}
_STRING_HISTORY_FORMAT = "aoi-checkpoint-string-history-v1"
HistoryTailVector = tuple[int, int, int, int]


class CompactStringHistory(NamedTuple):
    marker: str
    recent: tuple[str, ...]


CompactFactHistory = CompactStringHistory


class CheckpointStringHistoryPolicy(NamedTuple):
    forced_fields: frozenset[str]
    required_tails: HistoryTailVector


EMPTY_CHECKPOINT_STRING_HISTORY_POLICY = CheckpointStringHistoryPolicy(
    forced_fields=frozenset(),
    required_tails=(0, 0, 0, 0),
)


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


def compact_string_history(
    entries: Sequence[str],
    *,
    field: str,
    minimum_count: int,
    recent_tail: int,
    state_record_ref: str,
    force: bool = False,
) -> CompactStringHistory | None:
    """Digest one allowed string history and retain a bounded verbatim tail."""

    if type(field) is not str or field not in CHECKPOINT_STRING_HISTORY_FIELDS:
        raise ValueError("checkpoint string history field is not allowed")
    if isinstance(minimum_count, bool) or not isinstance(minimum_count, int):
        raise ValueError("minimum_count must be an integer")
    if isinstance(recent_tail, bool) or not isinstance(recent_tail, int):
        raise ValueError("recent_tail must be an integer")
    if type(force) is not bool:
        raise ValueError("force must be an exact boolean")
    if minimum_count < 0 or recent_tail < 0:
        raise ValueError("checkpoint string history bounds must be non-negative")
    if type(entries) not in {list, tuple}:
        raise TypeError("checkpoint string history must be an exact list or tuple")
    if any(type(entry) is not str for entry in entries):
        raise TypeError("checkpoint string history must contain exact strings")
    if (
        type(state_record_ref) is not str
        or not state_record_ref.endswith(f"#{field}")
        or "\n" in state_record_ref
        or "\r" in state_record_ref
    ):
        raise ValueError("checkpoint string history record reference is invalid")
    if not entries or (len(entries) < minimum_count and not force):
        return None

    value_canonical = json.dumps(
        list(entries),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    field_canonical = json.dumps(
        [_STRING_HISTORY_FORMAT, field, list(entries)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    recent_count = min(len(entries), recent_tail)
    recent = tuple(entries[-recent_count:]) if recent_count else ()
    # ``harnesslib._markdown_list`` strips edge whitespace and omits empty
    # entries.  Count only source entries that survive that normalization
    # byte-for-byte; keep the selected source-tail count separate.
    recent_verbatim = sum(bool(entry) and entry == entry.strip() for entry in recent)
    value_digest = hashlib.sha256(value_canonical).hexdigest()
    field_digest = hashlib.sha256(field_canonical).hexdigest()
    marker = (
        f"Established {_STRING_HISTORY_LABELS[field]} history: count={len(entries)}; "
        f"history_sha256={value_digest}; "
        f"record={state_record_ref}; recent_verbatim={recent_verbatim}; "
        f"format={_STRING_HISTORY_FORMAT}; field={field}; "
        f"total_count={len(entries)}; "
        f"omitted_source_entries={len(entries) - recent_count}; "
        f"field_history_sha256={field_digest}; "
        f"recent_source_entries={recent_count}"
    )
    return CompactStringHistory(marker=marker, recent=recent)


def compact_fact_history(
    facts: Sequence[str],
    *,
    minimum_count: int,
    recent_tail: int,
    state_record_ref: str,
) -> CompactFactHistory | None:
    """Compatibility wrapper for the established facts history."""

    return compact_string_history(
        facts,
        field="facts",
        minimum_count=minimum_count,
        recent_tail=recent_tail,
        state_record_ref=state_record_ref,
    )


def project_checkpoint_string_histories(
    histories: dict[str, tuple[Sequence[str], str]],
    *,
    compact: bool,
    minimum_count: int,
    recent_tail: int,
    policy: CheckpointStringHistoryPolicy = EMPTY_CHECKPOINT_STRING_HISTORY_POLICY,
) -> dict[str, tuple[str, ...]]:
    """Project the complete closed history set or its digest-bound summaries."""

    if type(histories) is not dict or set(histories) != set(
        CHECKPOINT_STRING_HISTORY_FIELDS
    ):
        raise ValueError("checkpoint string histories must use the closed field set")
    if type(compact) is not bool:
        raise ValueError("checkpoint string history projection flag must be a boolean")
    if type(policy) is not CheckpointStringHistoryPolicy:
        raise TypeError("checkpoint string history policy has an invalid type")
    forced_fields = policy.forced_fields
    required_tails = policy.required_tails
    if type(forced_fields) is not frozenset or any(
        type(field) is not str for field in forced_fields
    ):
        raise TypeError("forced checkpoint history fields must be an exact frozenset")
    if not forced_fields.issubset(CHECKPOINT_STRING_HISTORY_FIELDS):
        raise ValueError("forced checkpoint history fields are not allowed")
    if (
        type(required_tails) is not tuple
        or len(required_tails) != len(CHECKPOINT_STRING_HISTORY_FIELDS)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in required_tails
        )
    ):
        raise ValueError("required checkpoint history tails are invalid")
    if (forced_fields or any(required_tails)) and not compact:
        raise ValueError("forced checkpoint history compaction requires compact mode")

    projected: dict[str, tuple[str, ...]] = {}
    for index, field in enumerate(CHECKPOINT_STRING_HISTORY_FIELDS):
        item = histories[field]
        if type(item) is not tuple or len(item) != 2:
            raise TypeError("checkpoint string history input must be an exact pair")
        entries, state_record_ref = item
        if required_tails[index] > len(entries):
            raise ValueError("required checkpoint history tail exceeds its field")
        summary = compact_string_history(
            entries,
            field=field,
            minimum_count=(minimum_count if compact else len(entries) + 1),
            recent_tail=max(recent_tail, required_tails[index]),
            state_record_ref=state_record_ref,
            force=field in forced_fields,
        )
        projected[field] = (
            (summary.marker, *summary.recent) if summary is not None else tuple(entries)
        )
    return projected


def derive_durable_string_history_policy(
    candidate: dict[str, Any],
    durable: dict[str, Any],
    *,
    minimum_count: int,
) -> CheckpointStringHistoryPolicy:
    """Bind compaction to an exact durable prefix and preserve every new suffix."""

    if type(candidate) is not dict or type(durable) is not dict:
        raise TypeError("checkpoint history states must be exact dictionaries")
    if (
        isinstance(minimum_count, bool)
        or not isinstance(minimum_count, int)
        or minimum_count < 0
    ):
        raise ValueError("minimum_count must be a non-negative integer")
    forced: list[str] = []
    required: list[int] = []
    for field in CHECKPOINT_STRING_HISTORY_FIELDS:
        candidate_entries = candidate.get(field, [])
        durable_entries = durable.get(field, [])
        if type(candidate_entries) is not list or type(durable_entries) is not list:
            raise TypeError("checkpoint history state fields must be exact lists")
        if any(
            type(entry) is not str
            for entries in (candidate_entries, durable_entries)
            for entry in entries
        ):
            raise TypeError("checkpoint history state fields must contain exact strings")
        if (
            len(durable_entries) > len(candidate_entries)
            or candidate_entries[: len(durable_entries)] != durable_entries
        ):
            raise ValueError(
                f"checkpoint history field {field!r} does not extend its durable prefix"
            )
        if candidate_entries and len(candidate_entries) < minimum_count:
            forced.append(field)
        required.append(len(candidate_entries) - len(durable_entries))
    return CheckpointStringHistoryPolicy(
        forced_fields=frozenset(forced),
        required_tails=cast(HistoryTailVector, tuple(required)),
    )


def first_fitting_text(
    *,
    render: Callable[[int], str],
    highest_recent_tail: int,
    max_bytes: int,
) -> str | None:
    """Return the largest shared string-history tail whose full render fits."""

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


def select_checkpoint_text(
    full_text: str,
    *,
    render_compact: Callable[[int | None], str],
    compact_threshold_bytes: int,
    max_bytes: int,
    highest_recent_tail: int,
) -> str | None:
    """Select the compact projection without replacing a valid smaller full view."""

    if type(full_text) is not str:
        raise TypeError("full checkpoint text must be an exact string")
    for value, label in (
        (compact_threshold_bytes, "compact_threshold_bytes"),
        (max_bytes, "max_bytes"),
        (highest_recent_tail, "highest_recent_tail"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{label} must be a non-negative integer")
    if compact_threshold_bytes > max_bytes:
        raise ValueError("checkpoint compact threshold exceeds the hard ceiling")

    full_size = len(full_text.encode("utf-8"))
    if full_size <= compact_threshold_bytes:
        return full_text
    compact_text = render_compact(None)
    if type(compact_text) is not str:
        raise TypeError("compact checkpoint renderer must return an exact string")
    compact_size = len(compact_text.encode("utf-8"))
    if full_size <= max_bytes and compact_size > max_bytes:
        return full_text
    if compact_size <= max_bytes:
        return compact_text
    return first_fitting_text(
        render=lambda recent_tail: render_compact(recent_tail),
        highest_recent_tail=highest_recent_tail,
        max_bytes=max_bytes,
    )
