"""Pure semantic-event contracts for AOI task state.

The event ledger is the authority for a semantic-v2 task.  ``state.json`` is
only a projection: its reserved top-level ``_semantic`` member identifies the
ledger head and is deliberately excluded from the domain-state hash.  This
module performs no filesystem I/O so the schema, canonical hashes, replay, and
idempotency rules can be tested before a writer is enabled.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import Any, Iterable, Literal, Mapping, Sequence, cast


EVENT_SCHEMA_VERSION = 2
DELTA_SCHEMA_VERSION = 1
PROJECTION_SCHEMA_VERSION = 2
ZERO_SHA256 = "0" * 64
SEMANTIC_ENVELOPE_KEY = "_semantic"

MAX_CANONICAL_JSON_BYTES = 16 * 1024 * 1024
MAX_TRANSITION_PAYLOAD_BYTES = 1024 * 1024
MAX_EVENT_BYTES = MAX_CANONICAL_JSON_BYTES + 4096
MAX_DELTA_OPERATIONS = 4096
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 1_000_000
MAX_COLLECTION_ENTRIES = 100_000
MAX_LEDGER_EVENTS = 1_000_000
MAX_EVENT_SEQUENCE = 999_999_999_999

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_EVENT_TYPE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_COMMAND_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_RECORDED_AT_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_EVENT_FIELDS = {
    "schema_version",
    "sequence",
    "prev_event_sha256",
    "event_type",
    "command_id",
    "recorded_at",
    "authority_ref",
    "payload",
    "payload_sha256",
    "base_projection_sha256",
    "result_projection_sha256",
    "event_sha256",
}
_ENVELOPE_FIELDS = {
    "schema_version",
    "sequence",
    "head_event_sha256",
    "domain_sha256",
}


class SemanticEventError(ValueError):
    """A semantic-event record, delta, chain, or projection is invalid."""


@dataclass(frozen=True)
class ProjectionValidation:
    """Result of binding a stored projection to a validated ledger."""

    status: Literal["current", "behind"]
    stored_sequence: int
    head_sequence: int
    canonical_projection: dict[str, Any]


def _validate_json_value(
    value: Any,
    *,
    path: str = "$",
    depth: int = 0,
    containers: set[int] | None = None,
    budget: list[int] | None = None,
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise SemanticEventError(f"JSON value exceeds depth bound at {path}")
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_JSON_NODES:
        raise SemanticEventError(f"JSON value exceeds global node bound at {path}")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SemanticEventError(f"non-finite JSON number at {path}")
        return
    if not isinstance(value, (dict, list)):
        raise SemanticEventError(
            f"unsupported JSON value at {path}: {type(value).__name__}"
        )
    if len(value) > MAX_COLLECTION_ENTRIES:
        raise SemanticEventError(f"JSON collection exceeds entry bound at {path}")
    if containers is None:
        containers = set()
    identity = id(value)
    if identity in containers:
        raise SemanticEventError(f"repeated or cyclic JSON container at {path}")
    # JSON has tree semantics. Reject shared container aliases rather than
    # allowing a tiny Python DAG to expand exponentially during serialization.
    containers.add(identity)
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                containers=containers,
                budget=budget,
            )
        return
    for key, item in value.items():
        if not isinstance(key, str):
            raise SemanticEventError(f"non-string JSON object key at {path}")
        _validate_json_value(
            item,
            path=f"{path}.{key}",
            depth=depth + 1,
            containers=containers,
            budget=budget,
        )


def _canonical_string_size(value: str) -> int:
    size = 2  # surrounding quotes
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
            size += 2
        elif codepoint < 0x20:
            size += 6
        else:
            try:
                size += len(character.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise SemanticEventError(
                    "value cannot be encoded as canonical JSON: invalid Unicode"
                ) from exc
    return size


def _canonical_json_size(value: Any, *, limit: int) -> int:
    """Compute exact encoded size without first materializing escaped JSON."""

    def measure(item: Any, remaining: int) -> int:
        if item is None:
            size = 4
        elif item is True:
            size = 4
        elif item is False:
            size = 5
        elif isinstance(item, str):
            size = _canonical_string_size(item)
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            try:
                size = len(json.dumps(item, allow_nan=False).encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise SemanticEventError(
                    f"value cannot be encoded as canonical JSON: {exc}"
                ) from exc
        elif isinstance(item, list):
            size = 2 + max(0, len(item) - 1)
            if size > remaining:
                return size
            for child in item:
                size += measure(child, remaining - size)
                if size > remaining:
                    return size
        else:
            assert isinstance(item, dict)
            size = 2 + max(0, len(item) - 1)
            if size > remaining:
                return size
            for key, child in item.items():
                size += _canonical_string_size(key) + 1
                if size > remaining:
                    return size
                size += measure(child, remaining - size)
                if size > remaining:
                    return size
        return size

    return measure(value, limit)


def canonical_json_bytes(value: Any, *, max_bytes: int = MAX_CANONICAL_JSON_BYTES) -> bytes:
    """Return AOI's project-defined canonical UTF-8 JSON representation."""

    _validate_json_value(value)
    measured = _canonical_json_size(value, limit=max_bytes)
    if measured > max_bytes:
        raise SemanticEventError(
            f"canonical JSON exceeds byte bound ({measured} > {max_bytes})"
        )
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise SemanticEventError(f"value cannot be encoded as canonical JSON: {exc}") from exc
    if len(encoded) > max_bytes:
        raise SemanticEventError(
            f"canonical JSON exceeds byte bound ({len(encoded)} > {max_bytes})"
        )
    if len(encoded) != measured:
        raise SemanticEventError("canonical JSON size preflight disagrees with encoder")
    return encoded


def canonical_sha256(value: Any, *, max_bytes: int = MAX_CANONICAL_JSON_BYTES) -> str:
    return hashlib.sha256(canonical_json_bytes(value, max_bytes=max_bytes)).hexdigest()


def _json_clone(value: Any) -> Any:
    return json.loads(canonical_json_bytes(value).decode("utf-8"))


def _domain_state(value: Mapping[str, Any], *, allow_envelope: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticEventError("semantic projection domain must be a JSON object")
    cloned = _json_clone(value)
    if SEMANTIC_ENVELOPE_KEY in cloned:
        if not allow_envelope:
            raise SemanticEventError(
                f"domain state reserves top-level key {SEMANTIC_ENVELOPE_KEY!r}"
            )
        del cloned[SEMANTIC_ENVELOPE_KEY]
    return cloned


def projection_domain(projection: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached domain state, excluding the projection-only envelope."""

    return _domain_state(projection, allow_envelope=True)


def projection_sha256(projection_or_domain: Mapping[str, Any]) -> str:
    return canonical_sha256(_domain_state(projection_or_domain, allow_envelope=True))


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int or signed-zero aliases."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(old, new) for old, new in zip(left, right, strict=True)
        )
    if isinstance(left, float):
        return json.dumps(left, allow_nan=False) == json.dumps(right, allow_nan=False)
    return left == right


def _append_delta_operations(
    before: dict[str, Any],
    after: dict[str, Any],
    path: list[str],
    operations: list[dict[str, Any]],
) -> None:
    for key in sorted(set(before) | set(after)):
        child_path = [*path, key]
        if key not in after:
            operations.append({"op": "remove", "path": child_path})
            continue
        if key not in before:
            operations.append(
                {"op": "set", "path": child_path, "value": copy.deepcopy(after[key])}
            )
            continue
        old = before[key]
        new = after[key]
        if _json_equal(old, new):
            continue
        if isinstance(old, dict) and isinstance(new, dict):
            _append_delta_operations(old, new, child_path, operations)
            continue
        if isinstance(old, list) and isinstance(new, list):
            prefix = 0
            shared = min(len(old), len(new))
            while prefix < shared and _json_equal(old[prefix], new[prefix]):
                prefix += 1
            suffix = 0
            while (
                suffix < len(old) - prefix
                and suffix < len(new) - prefix
                and _json_equal(
                    old[len(old) - 1 - suffix], new[len(new) - 1 - suffix]
                )
            ):
                suffix += 1
            old_end = len(old) - suffix if suffix else len(old)
            new_end = len(new) - suffix if suffix else len(new)
            operations.append(
                {
                    "op": "splice",
                    "path": child_path,
                    "start": prefix,
                    "delete": old_end - prefix,
                    "values": copy.deepcopy(new[prefix:new_end]),
                }
            )
            continue
        operations.append(
            {"op": "set", "path": child_path, "value": copy.deepcopy(new)}
        )


def build_delta(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> dict[str, Any]:
    """Build the unique AOI delta from one domain state to another."""

    old = _domain_state(before, allow_envelope=True)
    new = _domain_state(after, allow_envelope=True)
    operations: list[dict[str, Any]] = []
    _append_delta_operations(old, new, [], operations)
    if not operations:
        raise SemanticEventError("semantic transition may not contain an empty delta")
    if len(operations) > MAX_DELTA_OPERATIONS:
        raise SemanticEventError(
            f"semantic delta exceeds operation bound ({len(operations)} > "
            f"{MAX_DELTA_OPERATIONS})"
        )
    delta = {"delta_version": DELTA_SCHEMA_VERSION, "operations": operations}
    canonical_json_bytes(delta, max_bytes=MAX_TRANSITION_PAYLOAD_BYTES)
    return delta


def _validate_delta_path(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_JSON_DEPTH
        or any(not isinstance(part, str) for part in value)
    ):
        raise SemanticEventError("delta path must be a non-empty bounded string list")
    if value[0] == SEMANTIC_ENVELOPE_KEY:
        raise SemanticEventError("delta may not mutate the projection envelope")
    return list(value)


def _delta_parent(state: dict[str, Any], path: Sequence[str]) -> tuple[dict[str, Any], str]:
    parent = state
    for part in path[:-1]:
        child = parent.get(part)
        if not isinstance(child, dict):
            raise SemanticEventError(f"delta path parent is not an object: {list(path)!r}")
        parent = child
    return parent, path[-1]


def apply_delta(base: Mapping[str, Any], delta: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and apply a canonical delta to a detached domain state."""

    state = _domain_state(base, allow_envelope=True)
    if not isinstance(delta, dict) or set(delta) != {"delta_version", "operations"}:
        raise SemanticEventError("semantic delta schema is invalid")
    if delta.get("delta_version") != DELTA_SCHEMA_VERSION:
        raise SemanticEventError("semantic delta version is unsupported")
    operations = delta.get("operations")
    if (
        not isinstance(operations, list)
        or not operations
        or len(operations) > MAX_DELTA_OPERATIONS
    ):
        raise SemanticEventError("semantic delta operation list is invalid")
    canonical_json_bytes(delta, max_bytes=MAX_TRANSITION_PAYLOAD_BYTES)
    for operation in operations:
        if not isinstance(operation, dict):
            raise SemanticEventError("semantic delta operation must be an object")
        kind = operation.get("op")
        if kind == "set":
            if set(operation) != {"op", "path", "value"}:
                raise SemanticEventError("set operation schema is invalid")
            path = _validate_delta_path(operation["path"])
            parent, key = _delta_parent(state, path)
            parent[key] = _json_clone(operation["value"])
        elif kind == "remove":
            if set(operation) != {"op", "path"}:
                raise SemanticEventError("remove operation schema is invalid")
            path = _validate_delta_path(operation["path"])
            parent, key = _delta_parent(state, path)
            if key not in parent:
                raise SemanticEventError(f"delta removes missing key at {path!r}")
            del parent[key]
        elif kind == "splice":
            if set(operation) != {"op", "path", "start", "delete", "values"}:
                raise SemanticEventError("splice operation schema is invalid")
            path = _validate_delta_path(operation["path"])
            parent, key = _delta_parent(state, path)
            target = parent.get(key)
            start = operation.get("start")
            delete = operation.get("delete")
            values = operation.get("values")
            if not isinstance(target, list):
                raise SemanticEventError(f"splice target is not a list at {path!r}")
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or isinstance(delete, bool)
                or not isinstance(delete, int)
                or start < 0
                or delete < 0
                or start > len(target)
                or start + delete > len(target)
                or not isinstance(values, list)
            ):
                raise SemanticEventError(f"splice bounds or values are invalid at {path!r}")
            target[start : start + delete] = _json_clone(values)
        else:
            raise SemanticEventError(f"unsupported semantic delta operation: {kind!r}")
    canonical = build_delta(base, state)
    if canonical_json_bytes(canonical) != canonical_json_bytes(delta):
        raise SemanticEventError("semantic delta is valid but not canonical")
    return state


def _validate_recorded_at(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or not _RECORDED_AT_RE.fullmatch(value)
    ):
        raise SemanticEventError("semantic event recorded_at is invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise SemanticEventError("semantic event recorded_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SemanticEventError("semantic event recorded_at requires an explicit timezone")
    return value


def _validate_event_identity(
    event_type: Any, command_id: Any, authority_ref: Any, recorded_at: Any
) -> tuple[str, str, str, str]:
    if not isinstance(event_type, str) or not _EVENT_TYPE_RE.fullmatch(event_type):
        raise SemanticEventError("semantic event type is invalid")
    if not isinstance(command_id, str) or not _COMMAND_ID_RE.fullmatch(command_id):
        raise SemanticEventError("semantic event command id is invalid")
    if (
        not isinstance(authority_ref, str)
        or not authority_ref.strip()
        or len(authority_ref) > 1024
        or any(ord(character) < 0x20 for character in authority_ref)
    ):
        raise SemanticEventError("semantic event authority reference is invalid")
    return event_type, command_id, authority_ref, _validate_recorded_at(recorded_at)


def _event_digest(event: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_sha256"}
    return canonical_sha256(unsigned, max_bytes=MAX_EVENT_BYTES)


def _validate_event_record(event: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict) or set(event) != _EVENT_FIELDS:
        raise SemanticEventError("semantic event schema is invalid")
    if event.get("schema_version") != EVENT_SCHEMA_VERSION:
        raise SemanticEventError("semantic event schema version is unsupported")
    sequence = event.get("sequence")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
        or sequence > MAX_EVENT_SEQUENCE
    ):
        raise SemanticEventError("semantic event sequence is invalid")
    _validate_event_identity(
        event.get("event_type"),
        event.get("command_id"),
        event.get("authority_ref"),
        event.get("recorded_at"),
    )
    for field in (
        "prev_event_sha256",
        "payload_sha256",
        "base_projection_sha256",
        "result_projection_sha256",
        "event_sha256",
    ):
        if not isinstance(event.get(field), str) or not _SHA256_RE.fullmatch(event[field]):
            raise SemanticEventError(f"semantic event {field} is invalid")
    payload = event.get("payload")
    payload_bound = (
        MAX_EVENT_BYTES
        if event.get("event_type") in {"genesis", "legacy_genesis"}
        else MAX_TRANSITION_PAYLOAD_BYTES
    )
    if canonical_sha256(payload, max_bytes=payload_bound) != event["payload_sha256"]:
        raise SemanticEventError("semantic event payload hash mismatch")
    if _event_digest(event) != event["event_sha256"]:
        raise SemanticEventError("semantic event hash mismatch")
    canonical_json_bytes(event, max_bytes=MAX_EVENT_BYTES)
    return _json_clone(event)


def _build_event(
    *,
    sequence: int,
    previous_sha256: str,
    event_type: str,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
    payload: dict[str, Any],
    base_projection_sha256: str,
    result_projection_sha256: str,
) -> dict[str, Any]:
    _validate_event_identity(event_type, command_id, authority_ref, recorded_at)
    event: dict[str, Any] = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "sequence": sequence,
        "prev_event_sha256": previous_sha256,
        "event_type": event_type,
        "command_id": command_id,
        "recorded_at": recorded_at,
        "authority_ref": authority_ref,
        "payload": _json_clone(payload),
        "payload_sha256": canonical_sha256(
            payload,
            max_bytes=(
                MAX_EVENT_BYTES
                if event_type in {"genesis", "legacy_genesis"}
                else MAX_TRANSITION_PAYLOAD_BYTES
            ),
        ),
        "base_projection_sha256": base_projection_sha256,
        "result_projection_sha256": result_projection_sha256,
        "event_sha256": "",
    }
    event["event_sha256"] = _event_digest(event)
    return _validate_event_record(event)


def create_genesis_event(
    domain_state: Mapping[str, Any],
    *,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    """Create sequence one.  Only genesis records carry a full snapshot."""

    domain = _domain_state(domain_state, allow_envelope=False)
    return _build_event(
        sequence=1,
        previous_sha256=ZERO_SHA256,
        event_type="genesis",
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
        payload={"snapshot": domain},
        base_projection_sha256=ZERO_SHA256,
        result_projection_sha256=canonical_sha256(domain),
    )


def create_legacy_genesis_event(
    domain_state: Mapping[str, Any],
    *,
    legacy_snapshot_sha256: str,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    """Create a migration genesis that binds the exact preserved legacy bytes."""

    if not isinstance(legacy_snapshot_sha256, str) or not _SHA256_RE.fullmatch(
        legacy_snapshot_sha256
    ):
        raise SemanticEventError("legacy snapshot SHA-256 is invalid")
    domain = _domain_state(domain_state, allow_envelope=False)
    return _build_event(
        sequence=1,
        previous_sha256=ZERO_SHA256,
        event_type="legacy_genesis",
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
        payload={
            "snapshot": domain,
            "legacy_snapshot_sha256": legacy_snapshot_sha256,
        },
        base_projection_sha256=ZERO_SHA256,
        result_projection_sha256=canonical_sha256(domain),
    )


def create_transition_event(
    previous_event: Mapping[str, Any],
    base_projection: Mapping[str, Any],
    result_projection: Mapping[str, Any],
    *,
    event_type: str,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    """Create the next event from a canonical bounded domain-state delta."""

    if event_type in {"genesis", "legacy_genesis"}:
        raise SemanticEventError("transition event may not use a genesis event type")
    previous = _validate_event_record(previous_event)
    base = _domain_state(base_projection, allow_envelope=True)
    result = _domain_state(result_projection, allow_envelope=True)
    if canonical_sha256(base) != previous["result_projection_sha256"]:
        raise SemanticEventError("transition base does not match previous event result")
    delta = build_delta(base, result)
    return _build_event(
        sequence=previous["sequence"] + 1,
        previous_sha256=previous["event_sha256"],
        event_type=event_type,
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
        payload={"delta": delta},
        base_projection_sha256=canonical_sha256(base),
        result_projection_sha256=canonical_sha256(result),
    )


def projection_for_event(
    domain_state: Mapping[str, Any], event: Mapping[str, Any]
) -> dict[str, Any]:
    domain = _domain_state(domain_state, allow_envelope=False)
    record = _validate_event_record(event)
    domain_sha = canonical_sha256(domain)
    if domain_sha != record["result_projection_sha256"]:
        raise SemanticEventError("projection domain does not match event result")
    domain[SEMANTIC_ENVELOPE_KEY] = {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "sequence": record["sequence"],
        "head_event_sha256": record["event_sha256"],
        "domain_sha256": domain_sha,
    }
    return domain


def _events_list(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    records = list(islice(iter(events), MAX_LEDGER_EVENTS + 1))
    if not records or len(records) > MAX_LEDGER_EVENTS:
        raise SemanticEventError("semantic ledger event count is invalid")
    return [_validate_event_record(event) for event in records]


def replay_events(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate a complete chain and return its canonical latest projection."""

    records = _events_list(events)
    command_ids: set[str] = set()
    domain: dict[str, Any] | None = None
    for index, event in enumerate(records, start=1):
        if event["sequence"] != index:
            raise SemanticEventError("semantic ledger sequence gap or reordering")
        if event["command_id"] in command_ids:
            raise SemanticEventError("semantic ledger contains a duplicate command id")
        command_ids.add(event["command_id"])
        if index == 1:
            if (
                event["event_type"] not in {"genesis", "legacy_genesis"}
                or event["prev_event_sha256"] != ZERO_SHA256
                or event["base_projection_sha256"] != ZERO_SHA256
                or not isinstance(event["payload"], dict)
            ):
                raise SemanticEventError("semantic ledger genesis contract is invalid")
            if event["event_type"] == "genesis":
                valid_payload = set(event["payload"]) == {"snapshot"}
            else:
                valid_payload = set(event["payload"]) == {
                    "snapshot",
                    "legacy_snapshot_sha256",
                } and bool(
                    _SHA256_RE.fullmatch(
                        str(event["payload"].get("legacy_snapshot_sha256", ""))
                    )
                )
            if not valid_payload:
                raise SemanticEventError("semantic ledger genesis payload is invalid")
            domain = _domain_state(event["payload"]["snapshot"], allow_envelope=False)
        else:
            previous = records[index - 2]
            if event["event_type"] in {"genesis", "legacy_genesis"}:
                raise SemanticEventError("semantic ledger contains a non-initial genesis")
            if event["prev_event_sha256"] != previous["event_sha256"]:
                raise SemanticEventError("semantic ledger previous-event hash mismatch")
            if not isinstance(event["payload"], dict) or set(event["payload"]) != {"delta"}:
                raise SemanticEventError("semantic transition payload schema is invalid")
            assert domain is not None
            if canonical_sha256(domain) != event["base_projection_sha256"]:
                raise SemanticEventError("semantic transition base projection mismatch")
            domain = apply_delta(domain, event["payload"]["delta"])
        assert domain is not None
        if canonical_sha256(domain) != event["result_projection_sha256"]:
            raise SemanticEventError("semantic event result projection mismatch")
    return projection_for_event(cast(Mapping[str, Any], domain), records[-1])


def _projection_envelope(projection: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(projection, dict) or SEMANTIC_ENVELOPE_KEY not in projection:
        raise SemanticEventError("semantic projection envelope is missing")
    envelope = projection[SEMANTIC_ENVELOPE_KEY]
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        raise SemanticEventError("semantic projection envelope schema is invalid")
    if envelope.get("schema_version") != PROJECTION_SCHEMA_VERSION:
        raise SemanticEventError("semantic projection envelope version is unsupported")
    sequence = envelope.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise SemanticEventError("semantic projection sequence is invalid")
    for field in ("head_event_sha256", "domain_sha256"):
        if not isinstance(envelope.get(field), str) or not _SHA256_RE.fullmatch(envelope[field]):
            raise SemanticEventError(f"semantic projection {field} is invalid")
    return _json_clone(envelope)


def validate_projection(
    events: Iterable[Mapping[str, Any]], stored_projection: Mapping[str, Any]
) -> ProjectionValidation:
    """Validate a stored projection and classify only a valid prefix as behind."""

    records = _events_list(events)
    canonical = replay_events(records)
    envelope = _projection_envelope(stored_projection)
    stored_sequence = envelope["sequence"]
    if stored_sequence > len(records):
        raise SemanticEventError("semantic projection is ahead of its ledger")
    prefix_projection = replay_events(records[:stored_sequence])
    prefix_envelope = _projection_envelope(prefix_projection)
    stored_domain = projection_domain(stored_projection)
    if canonical_sha256(stored_domain) != envelope["domain_sha256"]:
        raise SemanticEventError("stored projection domain hash mismatch")
    if (
        envelope["head_event_sha256"] != prefix_envelope["head_event_sha256"]
        or envelope["domain_sha256"] != prefix_envelope["domain_sha256"]
        or canonical_json_bytes(stored_domain)
        != canonical_json_bytes(projection_domain(prefix_projection))
    ):
        raise SemanticEventError("stored projection diverges from its ledger prefix")
    status: Literal["current", "behind"] = (
        "current" if stored_sequence == len(records) else "behind"
    )
    return ProjectionValidation(
        status=status,
        stored_sequence=stored_sequence,
        head_sequence=len(records),
        canonical_projection=canonical,
    )


def command_semantics(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return fields that must agree for an idempotent command retry."""

    record = _validate_event_record(event)
    return {
        "event_type": record["event_type"],
        "command_id": record["command_id"],
        "authority_ref": record["authority_ref"],
        "payload": record["payload"],
        "base_projection_sha256": record["base_projection_sha256"],
        "result_projection_sha256": record["result_projection_sha256"],
    }


def resolve_command_retry(
    events: Iterable[Mapping[str, Any]], proposed_event: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Return the existing event for an exact retry; reject semantic reuse."""

    records = _events_list(events)
    # Idempotency is meaningful only relative to one valid linear authority.
    # Never let a matching command record short-circuit chain validation.
    replay_events(records)
    proposed = _validate_event_record(proposed_event)
    matches = [event for event in records if event["command_id"] == proposed["command_id"]]
    if not matches:
        return None
    if len(matches) != 1 or canonical_json_bytes(
        command_semantics(matches[0])
    ) != canonical_json_bytes(command_semantics(proposed)):
        raise SemanticEventError("command id was reused for different semantics")
    return _json_clone(matches[0])


def event_filename(sequence: int) -> str:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
        or sequence > MAX_EVENT_SEQUENCE
    ):
        raise SemanticEventError("semantic event sequence is invalid")
    return f"{sequence:012d}.json"


def parse_event_filename(name: str) -> int:
    if not isinstance(name, str) or not re.fullmatch(r"[0-9]{12}\.json", name):
        raise SemanticEventError("semantic event filename is invalid")
    sequence = int(name[:-5])
    if sequence < 1 or event_filename(sequence) != name:
        raise SemanticEventError("semantic event filename is non-canonical")
    return sequence
