"""Compact dispatch-v6 persistence over the semantic-v2 object ledger.

This module deliberately does not read task state or the event directory through
private APIs.  A lifecycle caller supplies the complete task-local event chain;
the generic semantic object store authenticates that chain against the live
ledger before any mutation.  Full routing authorities and outcomes live only in
content-addressed objects.  ``state.json`` receives a bounded digest projection.
"""

from __future__ import annotations

import json
import re
from itertools import islice
from typing import Any, Iterable, Mapping

from . import harnesslib as h
from . import routing_authority as authority
from . import routing_bundle as bundle
from . import semantic_events as semantic
from . import semantic_objects as objects
from . import semantic_store as store


ROUTING_PERSISTENCE_SCHEMA_VERSION = 1
ROUTING_TRANSACTION_SCHEMA_VERSION = 1
ROUTING_NAMESPACE_KEY = "routing_v6"
MAX_ROUTING_ENTRIES = 4_096
MAX_ROUTING_ENTRY_BYTES = 1_536
MAX_ROUTING_NAMESPACE_BYTES = 4 * 1024 * 1024
MAX_ROUTING_PROJECTION_BYTES = 16 * 1024 * 1024
MAX_ROUTING_TRANSACTION_BYTES = 20 * 1024 * 1024
MAX_LEGACY_PACKETS = 4_096

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PHASE_RANK = {"authority": 1, "outcome": 2, "terminal": 3}
_EVENT_TYPE = {
    "authority": "routing_authority_recorded",
    "outcome": "routing_outcome_recorded",
    "terminal": "routing_terminal_recorded",
}
_BINDING_KIND = {
    "authority": "packet_authority",
    "outcome": "outcome_slot",
    "terminal": "terminal_slot",
}
_OBJECT_TYPES = {
    "authority": ("routing_authority",),
    "outcome": ("routing_authority", "routing_outcome"),
    "terminal": ("routing_authority", "routing_outcome", "routing_terminal"),
}
_ENTRY_FIELDS = {
    "schema_version",
    "packet_schema_version",
    "packet_id",
    "arm_id",
    "attempt",
    "outcome_slot_sha256",
    "phase",
    "routing_authority_object_sha256",
    "routing_outcome_object_sha256",
    "routing_terminal_object_sha256",
}
_NAMESPACE_FIELDS = {"schema_version", "entries"}
_TERMINAL_FIELDS = {
    "schema_version",
    "packet_id",
    "outcome_slot_sha256",
    "routing_authority_sha256",
    "routing_outcome_sha256",
    "terminal_status",
    "typed_outcome",
}
_TRANSACTION_FIELDS = {
    "schema_version",
    "stage",
    "task_id",
    "event_type",
    "command_id",
    "recorded_at",
    "authority_ref",
    "expected_head_sha256",
    "result_state",
    "planned_event",
    "objects",
    "binding",
    "transaction_sha256",
}
_SEMANTIC_OBJECT_FIELDS = {
    "schema_version",
    "object_type",
    "task_id",
    "object_identity",
    "payload",
    "payload_sha256",
    "object_sha256",
}
_SEMANTIC_BINDING_FIELDS = {
    "schema_version",
    "binding_kind",
    "task_id",
    "binding_key",
    "expected_semantic_head_sha256",
    "planned_event_sha256",
    "result_projection_sha256",
    "object_sha256s",
    "binding_sha256",
}


class RoutingPersistenceError(h.HarnessError):
    """A routing transaction, projection, object group, or cutover is unsafe."""


def _fail(message: str, exc: BaseException | None = None) -> RoutingPersistenceError:
    return RoutingPersistenceError(message if exc is None else f"{message}: {exc}")


def _clone(value: Any, *, max_bytes: int = MAX_ROUTING_PROJECTION_BYTES) -> Any:
    try:
        return json.loads(semantic.canonical_json_bytes(value, max_bytes=max_bytes).decode("utf-8"))
    except (semantic.SemanticEventError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("routing value is not bounded canonical JSON", exc) from exc


def _sha(value: Any, label: str = "SHA-256") -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RoutingPersistenceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _exact_int(value: Any, label: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RoutingPersistenceError(f"{label} is invalid")
    return value


def _bounded_records(values: Iterable[Any], maximum: int, label: str) -> list[Any]:
    try:
        rows = list(islice(iter(values), maximum + 1))
    except TypeError as exc:
        raise _fail(f"{label} is not iterable", exc) from exc
    if len(rows) > maximum:
        raise RoutingPersistenceError(f"{label} exceeds count bound")
    return rows


def _freeze_event_chain(
    event_chain: Iterable[Mapping[str, Any]], task_id: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = _bounded_records(event_chain, semantic.MAX_LEDGER_EVENTS, "semantic event chain")
    try:
        replayed = semantic.replay_events(rows)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("routing event chain is invalid", exc) from exc
    domain = semantic.projection_domain(replayed)
    if domain.get("task_id") != task_id:
        raise RoutingPersistenceError("routing event chain belongs to another task")
    return [_clone(row, max_bytes=semantic.MAX_EVENT_BYTES) for row in rows], replayed


def routing_outcome_slot_sha256(arm: Mapping[str, Any]) -> str:
    """Return the public, deterministic CAS slot shared by every outcome for one arm."""

    try:
        checked = authority.validate_arm_authority(arm)
        packet = checked["packet_authority"]
        attempt = checked["attempt_identity"]
        return semantic.canonical_sha256(
            {
                "routing_authority_sha256": authority.authority_sha256(checked),
                "packet_id": packet["packet_id"],
                "arm_id": attempt["arm_id"],
                "attempt": attempt["attempt"],
            },
            max_bytes=authority.MAX_RECORD_BYTES,
        )
    except (authority.RoutingAuthorityError, semantic.SemanticEventError) as exc:
        raise _fail("invalid routing authority slot", exc) from exc


def _authority_object(task_id: str, arm: Mapping[str, Any]) -> dict[str, Any]:
    try:
        checked = authority.validate_arm_authority(arm)
        identity = authority.authority_sha256(checked)
        return objects.create_semantic_object(
            object_type="routing_authority",
            task_id=task_id,
            object_identity=identity,
            payload=checked,
        )
    except (authority.RoutingAuthorityError, objects.SemanticObjectError) as exc:
        raise _fail("cannot seal routing authority object", exc) from exc


def _outcome_object(
    task_id: str, arm: Mapping[str, Any], outcome: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        checked_arm = authority.validate_arm_authority(arm)
        checked = authority.validate_dispatch_outcome(checked_arm, outcome)
        if checked["outcome_slot_sha256"] != routing_outcome_slot_sha256(checked_arm):
            raise RoutingPersistenceError("routing outcome uses the wrong CAS slot")
        return objects.create_semantic_object(
            object_type="routing_outcome",
            task_id=task_id,
            object_identity=checked["routing_outcome_sha256"],
            payload=checked,
        )
    except RoutingPersistenceError:
        raise
    except (authority.RoutingAuthorityError, objects.SemanticObjectError) as exc:
        raise _fail("cannot seal routing outcome object", exc) from exc


def _terminal_payload(
    arm: Mapping[str, Any],
    outcome: Mapping[str, Any],
    *,
    terminal_status: str,
    typed_outcome: str,
) -> dict[str, Any]:
    try:
        checked_arm = authority.validate_arm_authority(arm)
        checked_outcome = authority.validate_dispatch_outcome(checked_arm, outcome)
        finalized = bundle.finalize_v6_record(
            bundle.build_v6_record(checked_arm, checked_outcome),
            terminal_status=terminal_status,
            typed_outcome=typed_outcome,
        )
    except (authority.RoutingAuthorityError, bundle.RoutingBundleError) as exc:
        raise _fail("invalid routing terminal classification", exc) from exc
    return {
        "schema_version": ROUTING_PERSISTENCE_SCHEMA_VERSION,
        "packet_id": checked_arm["packet_authority"]["packet_id"],
        "outcome_slot_sha256": checked_outcome["outcome_slot_sha256"],
        "routing_authority_sha256": authority.authority_sha256(checked_arm),
        "routing_outcome_sha256": checked_outcome["routing_outcome_sha256"],
        "terminal_status": finalized["terminal_status"],
        "typed_outcome": finalized["typed_outcome"],
    }


def _terminal_object(
    task_id: str,
    arm: Mapping[str, Any],
    outcome: Mapping[str, Any],
    *,
    terminal_status: str,
    typed_outcome: str,
) -> dict[str, Any]:
    payload = _terminal_payload(
        arm,
        outcome,
        terminal_status=terminal_status,
        typed_outcome=typed_outcome,
    )
    try:
        identity = semantic.canonical_sha256(payload, max_bytes=objects.MAX_SMALL_OBJECT_BYTES)
        return objects.create_semantic_object(
            object_type="routing_terminal",
            task_id=task_id,
            object_identity=identity,
            payload=payload,
        )
    except (semantic.SemanticEventError, objects.SemanticObjectError) as exc:
        raise _fail("cannot seal routing terminal object", exc) from exc


def _entry_for(
    stage: str,
    arm: Mapping[str, Any],
    sealed: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    checked = authority.validate_arm_authority(arm)
    packet = checked["packet_authority"]
    attempt = checked["attempt_identity"]
    entry = {
        "schema_version": ROUTING_PERSISTENCE_SCHEMA_VERSION,
        "packet_schema_version": 6,
        "packet_id": packet["packet_id"],
        "arm_id": attempt["arm_id"],
        "attempt": attempt["attempt"],
        "outcome_slot_sha256": routing_outcome_slot_sha256(checked),
        "phase": stage,
        "routing_authority_object_sha256": sealed["routing_authority"]["object_sha256"],
        "routing_outcome_object_sha256": (
            sealed["routing_outcome"]["object_sha256"] if stage in {"outcome", "terminal"} else None
        ),
        "routing_terminal_object_sha256": (
            sealed["routing_terminal"]["object_sha256"] if stage == "terminal" else None
        ),
    }
    return validate_routing_entry(entry)


def validate_routing_entry(
    value: Mapping[str, Any], *, expected_slot: str | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ENTRY_FIELDS:
        raise RoutingPersistenceError("routing projection entry schema is invalid")
    item = _clone(value, max_bytes=MAX_ROUTING_ENTRY_BYTES)
    if item["schema_version"] != ROUTING_PERSISTENCE_SCHEMA_VERSION:
        raise RoutingPersistenceError("routing projection entry version is unsupported")
    if item["packet_schema_version"] != 6:
        raise RoutingPersistenceError("routing projection entry is not packet schema v6")
    packet_id = h.validate_id(item["packet_id"], "packet id")
    arm_id = h.validate_id(item["arm_id"], "arm id")
    attempt = _exact_int(item["attempt"], "routing attempt", minimum=1)
    slot = _sha(item["outcome_slot_sha256"], "routing outcome slot")
    if expected_slot is not None and slot != expected_slot:
        raise RoutingPersistenceError("routing projection key differs from its outcome slot")
    phase = item["phase"]
    if phase not in _PHASE_RANK:
        raise RoutingPersistenceError("routing projection phase is invalid")
    authority_object = _sha(
        item["routing_authority_object_sha256"], "routing authority object SHA-256"
    )
    outcome_object = item["routing_outcome_object_sha256"]
    terminal_object = item["routing_terminal_object_sha256"]
    if phase == "authority" and (outcome_object is not None or terminal_object is not None):
        raise RoutingPersistenceError("authority projection entry has later-stage objects")
    if phase == "outcome" and (outcome_object is None or terminal_object is not None):
        raise RoutingPersistenceError("outcome projection entry has invalid object phases")
    if phase == "terminal" and (outcome_object is None or terminal_object is None):
        raise RoutingPersistenceError("terminal projection entry is incomplete")
    if outcome_object is not None:
        _sha(outcome_object, "routing outcome object SHA-256")
    if terminal_object is not None:
        _sha(terminal_object, "routing terminal object SHA-256")
    checked = {
        **item,
        "packet_id": packet_id,
        "arm_id": arm_id,
        "attempt": attempt,
        "routing_authority_object_sha256": authority_object,
    }
    semantic.canonical_json_bytes(checked, max_bytes=MAX_ROUTING_ENTRY_BYTES)
    return checked


def validate_routing_namespace(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"schema_version": ROUTING_PERSISTENCE_SCHEMA_VERSION, "entries": {}}
    if not isinstance(value, dict) or set(value) != _NAMESPACE_FIELDS:
        raise RoutingPersistenceError("routing projection namespace schema is invalid")
    if value.get("schema_version") != ROUTING_PERSISTENCE_SCHEMA_VERSION:
        raise RoutingPersistenceError("routing projection namespace version is unsupported")
    entries = value.get("entries")
    if not isinstance(entries, dict) or len(entries) > MAX_ROUTING_ENTRIES:
        raise RoutingPersistenceError("routing projection entry collection is invalid")
    checked: dict[str, dict[str, Any]] = {}
    for slot, entry in entries.items():
        _sha(slot, "routing projection slot")
        checked[slot] = validate_routing_entry(entry, expected_slot=slot)
    result = {
        "schema_version": ROUTING_PERSISTENCE_SCHEMA_VERSION,
        "entries": {slot: checked[slot] for slot in sorted(checked)},
    }
    semantic.canonical_json_bytes(result, max_bytes=MAX_ROUTING_NAMESPACE_BYTES)
    return result


def routing_namespace_from_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    try:
        domain = (
            semantic.projection_domain(projection)
            if semantic.SEMANTIC_ENVELOPE_KEY in projection
            else _clone(projection)
        )
        semantic.canonical_json_bytes(domain, max_bytes=MAX_ROUTING_PROJECTION_BYTES)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("routing projection is invalid", exc) from exc
    return validate_routing_namespace(domain.get(ROUTING_NAMESPACE_KEY))


def _advance_projection(base: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    domain = _clone(base)
    semantic.canonical_json_bytes(domain, max_bytes=MAX_ROUTING_PROJECTION_BYTES)
    namespace = validate_routing_namespace(domain.get(ROUTING_NAMESPACE_KEY))
    entry = validate_routing_entry(candidate)
    slot = entry["outcome_slot_sha256"]
    existing = namespace["entries"].get(slot)
    stage = entry["phase"]
    if existing is None:
        if stage != "authority":
            raise RoutingPersistenceError("routing outcome or terminal has no authority projection")
        if len(namespace["entries"]) >= MAX_ROUTING_ENTRIES:
            raise RoutingPersistenceError("routing projection reached entry count bound")
    else:
        if existing == entry:
            raise RoutingPersistenceError("routing stage is already reflected in the projection")
        if existing["packet_id"] != entry["packet_id"] or existing["arm_id"] != entry["arm_id"]:
            raise RoutingPersistenceError("routing outcome slot collides across packet authorities")
        if existing["attempt"] != entry["attempt"]:
            raise RoutingPersistenceError("routing outcome slot collides across attempts")
        if existing["routing_authority_object_sha256"] != entry["routing_authority_object_sha256"]:
            raise RoutingPersistenceError(
                "routing authority object changed within one outcome slot"
            )
        if _PHASE_RANK[stage] != _PHASE_RANK[existing["phase"]] + 1:
            raise RoutingPersistenceError("routing projection transition is not monotonic")
        if stage == "terminal" and (
            existing["routing_outcome_object_sha256"]
            != entry["routing_outcome_object_sha256"]
        ):
            raise RoutingPersistenceError("routing outcome object changed before terminalization")
    namespace["entries"][slot] = entry
    domain[ROUTING_NAMESPACE_KEY] = validate_routing_namespace(namespace)
    semantic.canonical_json_bytes(domain, max_bytes=MAX_ROUTING_PROJECTION_BYTES)
    return domain


def _individual_object(value: Mapping[str, Any], task_id: str) -> dict[str, Any]:
    wrapped = objects.validate_semantic_object(value)
    if wrapped["task_id"] != task_id or wrapped["object_type"] not in {
        "routing_authority",
        "routing_outcome",
        "routing_terminal",
    }:
        raise RoutingPersistenceError("routing object task or type is invalid")
    kind = wrapped["object_type"]
    payload = wrapped["payload"]
    if kind == "routing_authority":
        checked = authority.validate_arm_authority(payload)
        identity = authority.authority_sha256(checked)
    elif kind == "routing_outcome":
        if not isinstance(payload, dict):
            raise RoutingPersistenceError("routing outcome payload is invalid")
        identity = _sha(payload.get("routing_outcome_sha256"), "routing outcome identity")
        if authority.outcome_sha256(payload) != identity:
            raise RoutingPersistenceError("routing outcome payload hash is invalid")
    else:
        if not isinstance(payload, dict) or set(payload) != _TERMINAL_FIELDS:
            raise RoutingPersistenceError("routing terminal payload schema is invalid")
        if payload["schema_version"] != ROUTING_PERSISTENCE_SCHEMA_VERSION:
            raise RoutingPersistenceError("routing terminal payload version is unsupported")
        h.validate_id(payload["packet_id"], "packet id")
        for field in (
            "outcome_slot_sha256",
            "routing_authority_sha256",
            "routing_outcome_sha256",
        ):
            _sha(payload[field], f"routing terminal {field}")
        identity = semantic.canonical_sha256(
            payload, max_bytes=objects.MAX_SMALL_OBJECT_BYTES
        )
    if wrapped["object_identity"] != identity:
        raise RoutingPersistenceError("routing object identity differs from its payload")
    return wrapped


def _validate_object_group(
    values: Iterable[Mapping[str, Any]], task_id: str, *, expected_stage: str
) -> dict[str, Any]:
    if expected_stage not in _OBJECT_TYPES:
        raise RoutingPersistenceError("routing object-group stage is invalid")
    rows = _bounded_records(values, 3, "routing object group")
    by_type: dict[str, dict[str, Any]] = {}
    for row in rows:
        wrapped = _individual_object(row, task_id)
        if wrapped["object_type"] in by_type:
            raise RoutingPersistenceError("routing object group repeats an object type")
        by_type[wrapped["object_type"]] = wrapped
    required = set(_OBJECT_TYPES[expected_stage])
    if set(by_type) != required:
        raise RoutingPersistenceError("routing binding object types or cardinality are invalid")
    arm_object = by_type["routing_authority"]
    arm = authority.validate_arm_authority(arm_object["payload"])
    slot = routing_outcome_slot_sha256(arm)
    outcome = None
    if "routing_outcome" in by_type:
        outcome_object = by_type["routing_outcome"]
        outcome = authority.validate_dispatch_outcome(arm, outcome_object["payload"])
        if outcome["outcome_slot_sha256"] != slot:
            raise RoutingPersistenceError("routing outcome object belongs to another slot")
    terminal = None
    if "routing_terminal" in by_type:
        assert outcome is not None
        terminal_object = by_type["routing_terminal"]
        terminal = terminal_object["payload"]
        expected = _terminal_payload(
            arm,
            outcome,
            terminal_status=terminal["terminal_status"],
            typed_outcome=terminal["typed_outcome"],
        )
        if terminal != expected:
            raise RoutingPersistenceError("routing terminal object cross-binding is invalid")
    return {
        "stage": expected_stage,
        "slot": slot,
        "objects": by_type,
        "authority": arm,
        "outcome": outcome,
        "terminal": terminal,
    }


def _transaction_base(
    *,
    stage: str,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    arm: Mapping[str, Any],
    outcome: Mapping[str, Any] | None,
    terminal_status: str | None,
    typed_outcome: str | None,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    task_id = h.validate_id(task_id, "task id")
    records, replayed = _freeze_event_chain(event_chain, task_id)
    arm_checked = authority.validate_arm_authority(arm)
    if arm_checked["task_id"] != task_id:
        raise RoutingPersistenceError("routing authority belongs to another task")
    sealed_rows = [_authority_object(task_id, arm_checked)]
    if stage in {"outcome", "terminal"}:
        if outcome is None:
            raise RoutingPersistenceError("routing outcome stage requires an outcome")
        sealed_rows.append(_outcome_object(task_id, arm_checked, outcome))
    if stage == "terminal":
        if terminal_status is None or typed_outcome is None:
            raise RoutingPersistenceError("routing terminal stage requires a terminal pair")
        assert outcome is not None
        sealed_rows.append(
            _terminal_object(
                task_id,
                arm_checked,
                outcome,
                terminal_status=terminal_status,
                typed_outcome=typed_outcome,
            )
        )
    sealed = {row["object_type"]: row for row in sealed_rows}
    entry = _entry_for(stage, arm_checked, sealed)
    base_domain = semantic.projection_domain(replayed)
    result_state = _advance_projection(base_domain, entry)
    planned = semantic.create_transition_event(
        records[-1],
        replayed,
        result_state,
        event_type=_EVENT_TYPE[stage],
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
    )
    binding = objects.create_semantic_binding(
        binding_kind=_BINDING_KIND[stage],
        task_id=task_id,
        binding_key=entry["outcome_slot_sha256"],
        expected_semantic_head_sha256=planned["prev_event_sha256"],
        planned_event_sha256=planned["event_sha256"],
        result_projection_sha256=planned["result_projection_sha256"],
        object_sha256s=sorted(row["object_sha256"] for row in sealed_rows),
    )
    base = {
        "schema_version": ROUTING_TRANSACTION_SCHEMA_VERSION,
        "stage": stage,
        "task_id": task_id,
        "event_type": _EVENT_TYPE[stage],
        "command_id": planned["command_id"],
        "recorded_at": planned["recorded_at"],
        "authority_ref": planned["authority_ref"],
        "expected_head_sha256": planned["prev_event_sha256"],
        "result_state": result_state,
        "planned_event": planned,
        "objects": sorted(sealed_rows, key=lambda row: row["object_type"]),
        "binding": binding,
    }
    base["transaction_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_ROUTING_TRANSACTION_BYTES
    )
    return validate_routing_transaction(base)


def prepare_authority_transaction(
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    arm: Mapping[str, Any],
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    return _transaction_base(
        stage="authority",
        task_id=task_id,
        event_chain=event_chain,
        arm=arm,
        outcome=None,
        terminal_status=None,
        typed_outcome=None,
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
    )


def prepare_outcome_transaction(
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    arm: Mapping[str, Any],
    outcome: Mapping[str, Any],
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    return _transaction_base(
        stage="outcome",
        task_id=task_id,
        event_chain=event_chain,
        arm=arm,
        outcome=outcome,
        terminal_status=None,
        typed_outcome=None,
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
    )


def prepare_terminal_transaction(
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    arm: Mapping[str, Any],
    outcome: Mapping[str, Any],
    terminal_status: str,
    typed_outcome: str,
    command_id: str,
    recorded_at: str,
    authority_ref: str,
) -> dict[str, Any]:
    return _transaction_base(
        stage="terminal",
        task_id=task_id,
        event_chain=event_chain,
        arm=arm,
        outcome=outcome,
        terminal_status=terminal_status,
        typed_outcome=typed_outcome,
        command_id=command_id,
        recorded_at=recorded_at,
        authority_ref=authority_ref,
    )


def validate_routing_transaction(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _TRANSACTION_FIELDS:
        raise RoutingPersistenceError("routing transaction schema is invalid")
    item = _clone(value, max_bytes=MAX_ROUTING_TRANSACTION_BYTES)
    if item["schema_version"] != ROUTING_TRANSACTION_SCHEMA_VERSION:
        raise RoutingPersistenceError("routing transaction version is unsupported")
    stage = item["stage"]
    if stage not in _OBJECT_TYPES or item["event_type"] != _EVENT_TYPE[stage]:
        raise RoutingPersistenceError("routing transaction stage or event type is invalid")
    task_id = h.validate_id(item["task_id"], "task id")
    group = _validate_object_group(item["objects"], task_id, expected_stage=stage)
    binding = objects.validate_semantic_binding(item["binding"])
    if (
        binding["binding_kind"] != _BINDING_KIND[stage]
        or binding["binding_key"] != group["slot"]
        or binding["task_id"] != task_id
        or binding["object_sha256s"]
        != sorted(row["object_sha256"] for row in group["objects"].values())
    ):
        raise RoutingPersistenceError("routing transaction binding contract is invalid")
    planned = item["planned_event"]
    try:
        semantics = semantic.command_semantics(planned)
    except semantic.SemanticEventError as exc:
        raise _fail("routing planned event is invalid", exc) from exc
    if (
        planned["event_sha256"] != binding["planned_event_sha256"]
        or planned["prev_event_sha256"] != binding["expected_semantic_head_sha256"]
        or planned["result_projection_sha256"] != binding["result_projection_sha256"]
        or planned["prev_event_sha256"] != item["expected_head_sha256"]
        or semantics["event_type"] != item["event_type"]
        or planned["command_id"] != item["command_id"]
        or planned["recorded_at"] != item["recorded_at"]
        or planned["authority_ref"] != item["authority_ref"]
    ):
        raise RoutingPersistenceError("routing transaction event cross-binding is invalid")
    result_state = _clone(item["result_state"])
    if result_state.get("task_id") != task_id:
        raise RoutingPersistenceError("routing transaction result belongs to another task")
    if semantic.canonical_sha256(result_state) != binding["result_projection_sha256"]:
        raise RoutingPersistenceError("routing transaction result hash is invalid")
    namespace = routing_namespace_from_projection(result_state)
    entry = namespace["entries"].get(group["slot"])
    expected_entry = _entry_for(stage, group["authority"], group["objects"])
    if entry != expected_entry:
        raise RoutingPersistenceError("routing transaction result entry is invalid")
    preimage = {key: item[key] for key in _TRANSACTION_FIELDS if key != "transaction_sha256"}
    if item["transaction_sha256"] != semantic.canonical_sha256(
        preimage, max_bytes=MAX_ROUTING_TRANSACTION_BYTES
    ):
        raise RoutingPersistenceError("routing transaction SHA-256 is invalid")
    return item


def _routing_report_from_generic(
    report: Mapping[str, Any], projection: Mapping[str, Any]
) -> dict[str, Any]:
    task_id = h.validate_id(report.get("task_id"), "task id")
    object_rows = report.get("objects")
    binding_rows = report.get("bindings")
    if not isinstance(object_rows, list) or not isinstance(binding_rows, list):
        raise RoutingPersistenceError("generic semantic object report is invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    routing_digests: set[str] = set()
    authority_by_identity: dict[str, dict[str, Any]] = {}
    outcome_by_identity: dict[str, dict[str, Any]] = {}
    for row in object_rows:
        if not isinstance(row, dict):
            raise RoutingPersistenceError("semantic object report row is invalid")
        try:
            wrapped = {key: row[key] for key in _SEMANTIC_OBJECT_FIELDS}
        except KeyError as exc:
            raise _fail("semantic object report row is incomplete", exc) from exc
        checked = objects.validate_semantic_object(wrapped)
        by_digest[checked["object_sha256"]] = checked
        if checked["object_type"] not in {
            "routing_authority",
            "routing_outcome",
            "routing_terminal",
        }:
            continue
        checked = _individual_object(checked, task_id)
        routing_digests.add(checked["object_sha256"])
        if checked["object_type"] == "routing_authority":
            prior = authority_by_identity.setdefault(checked["object_identity"], checked)
            if prior["object_sha256"] != checked["object_sha256"]:
                raise RoutingPersistenceError("routing authority identity is not unique")
        elif checked["object_type"] == "routing_outcome":
            prior = outcome_by_identity.setdefault(checked["object_identity"], checked)
            if prior["object_sha256"] != checked["object_sha256"]:
                raise RoutingPersistenceError("routing outcome identity is not unique")
    # Validate even orphan outcomes/terminals against immutable predecessors.
    for digest in sorted(routing_digests):
        checked = by_digest[digest]
        if checked["object_type"] == "routing_outcome":
            arm = authority_by_identity.get(checked["payload"].get("routing_authority_sha256"))
            if arm is None:
                raise RoutingPersistenceError("routing outcome object has no authority object")
            authority.validate_dispatch_outcome(arm["payload"], checked["payload"])
        elif checked["object_type"] == "routing_terminal":
            payload = checked["payload"]
            arm = authority_by_identity.get(payload["routing_authority_sha256"])
            outcome = outcome_by_identity.get(payload["routing_outcome_sha256"])
            if arm is None or outcome is None:
                raise RoutingPersistenceError("routing terminal object has missing predecessors")
            expected = _terminal_payload(
                arm["payload"],
                outcome["payload"],
                terminal_status=payload["terminal_status"],
                typed_outcome=payload["typed_outcome"],
            )
            if expected != payload:
                raise RoutingPersistenceError("routing terminal object cross-binding is invalid")
    groups: list[dict[str, Any]] = []
    for row in binding_rows:
        if not isinstance(row, dict):
            raise RoutingPersistenceError("semantic binding report row is invalid")
        try:
            binding = {key: row[key] for key in _SEMANTIC_BINDING_FIELDS}
        except KeyError as exc:
            raise _fail("semantic binding report row is incomplete", exc) from exc
        binding = objects.validate_semantic_binding(binding)
        references = set(binding["object_sha256s"])
        if references & routing_digests and binding["binding_kind"] not in set(
            _BINDING_KIND.values()
        ):
            raise RoutingPersistenceError("routing object is referenced by a non-routing binding")
        if binding["binding_kind"] not in set(_BINDING_KIND.values()):
            continue
        stage = next(key for key, kind in _BINDING_KIND.items() if kind == binding["binding_kind"])
        try:
            group = _validate_object_group(
                [by_digest[digest] for digest in binding["object_sha256s"]],
                task_id,
                expected_stage=stage,
            )
        except KeyError as exc:
            raise _fail("routing binding references a missing object", exc) from exc
        if binding["binding_key"] != group["slot"]:
            raise RoutingPersistenceError("routing binding key differs from its outcome slot")
        groups.append(
            {
                **group,
                "binding": binding,
                "classification": row.get("classification"),
            }
        )
    namespace = routing_namespace_from_projection(projection)
    entries = namespace["entries"]
    committed = {
        (group["slot"], group["stage"]): group
        for group in groups
        if group["classification"] == "committed"
    }
    for group in groups:
        entry = entries.get(group["slot"])
        rank = _PHASE_RANK[group["stage"]]
        if group["classification"] == "committed":
            if entry is None or _PHASE_RANK[entry["phase"]] < rank:
                raise RoutingPersistenceError("committed routing binding is absent from projection")
        elif group["classification"] == "pending":
            current_rank = 0 if entry is None else _PHASE_RANK[entry["phase"]]
            if current_rank != rank - 1:
                raise RoutingPersistenceError(
                    "pending routing binding does not follow projection phase"
                )
        else:
            raise RoutingPersistenceError("routing binding classification is invalid")
        if entry is not None:
            visible_rank = (
                rank if group["classification"] == "committed" else rank - 1
            )
            if visible_rank >= 1 and entry["routing_authority_object_sha256"] != (
                group["objects"]["routing_authority"]["object_sha256"]
            ):
                raise RoutingPersistenceError(
                    "routing projection authority object cross-binding is invalid"
                )
            if visible_rank >= 2 and entry["routing_outcome_object_sha256"] != (
                group["objects"]["routing_outcome"]["object_sha256"]
            ):
                raise RoutingPersistenceError(
                    "routing projection outcome object cross-binding is invalid"
                )
            if visible_rank >= 3 and entry["routing_terminal_object_sha256"] != (
                group["objects"]["routing_terminal"]["object_sha256"]
            ):
                raise RoutingPersistenceError(
                    "routing projection terminal object cross-binding is invalid"
                )
    for slot, entry in entries.items():
        for stage, rank in _PHASE_RANK.items():
            if rank <= _PHASE_RANK[entry["phase"]] and (slot, stage) not in committed:
                raise RoutingPersistenceError("routing projection lacks a committed stage binding")
    return {
        "task_id": task_id,
        "namespace": namespace,
        "groups": sorted(groups, key=lambda row: (row["slot"], _PHASE_RANK[row["stage"]])),
        "routing_object_sha256s": sorted(routing_digests),
        "routing_binding_sha256s": sorted(
            group["binding"]["binding_sha256"] for group in groups
        ),
    }


def inspect_routing_persistence(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    task_id = h.validate_id(task_id, "task id")
    records, replayed = _freeze_event_chain(event_chain, task_id)
    report = objects.inspect_semantic_objects(paths, task_id, records)
    return _routing_report_from_generic(report, replayed)


def commit_routing_transaction(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Commit or recover one object -> binding -> event -> projection transaction."""

    tx = validate_routing_transaction(transaction)
    records, replayed = _freeze_event_chain(event_chain, tx["task_id"])
    generic = objects.require_no_pending_bindings(
        paths,
        tx["task_id"],
        records,
        expected_binding_sha256=tx["binding"]["binding_sha256"],
    )
    specialized = _routing_report_from_generic(generic, replayed)
    existing = next(
        (
            row
            for row in generic["bindings"]
            if row["binding_sha256"] == tx["binding"]["binding_sha256"]
        ),
        None,
    )
    same_slot = [
        row
        for row in generic["bindings"]
        if row["binding_kind"] == tx["binding"]["binding_kind"]
        and row["binding_key"] == tx["binding"]["binding_key"]
    ]
    if existing is None and same_slot:
        raise RoutingPersistenceError("routing CAS slot is already bound differently")
    if existing is not None and existing.get("classification") == "committed":
        matching = [
            event
            for event in records
            if event["event_sha256"] == tx["planned_event"]["event_sha256"]
        ]
        if len(matching) != 1:
            raise RoutingPersistenceError("committed routing binding has no unique ledger event")
        projection = store.repair_semantic_projection(paths, tx["task_id"])
        return {
            "task_id": tx["task_id"],
            "stage": tx["stage"],
            "binding": tx["binding"],
            "event": matching[0],
            "projection": projection,
            "idempotent_replay": True,
            "routing_report": specialized,
        }
    group = _validate_object_group(
        tx["objects"], tx["task_id"], expected_stage=tx["stage"]
    )
    expected_result = _advance_projection(
        semantic.projection_domain(replayed),
        _entry_for(tx["stage"], group["authority"], group["objects"]),
    )
    if semantic.canonical_json_bytes(expected_result) != semantic.canonical_json_bytes(
        tx["result_state"]
    ):
        raise RoutingPersistenceError(
            "routing transaction changes state outside its exact routing entry"
        )
    if any(
        event["event_sha256"] == tx["planned_event"]["event_sha256"]
        for event in records
    ):
        raise RoutingPersistenceError("routing event exists without its binding sentinel")
    # Preflight before publishing new objects.  An objects-only crash retry still
    # passes because its command and binding have not been published.
    store.preflight_semantic_append(
        paths,
        tx["task_id"],
        command_id=tx["command_id"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
    rebuilt = semantic.create_transition_event(
        records[-1],
        replayed,
        tx["result_state"],
        event_type=tx["event_type"],
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
        authority_ref=tx["authority_ref"],
    )
    if semantic.canonical_json_bytes(rebuilt) != semantic.canonical_json_bytes(
        tx["planned_event"]
    ):
        raise RoutingPersistenceError("routing transaction was not prepared from the live chain")
    for wrapped in tx["objects"]:
        objects.publish_semantic_object(paths, wrapped)
    objects.publish_semantic_binding(paths, tx["binding"], records)
    appended = store.append_semantic_transition(
        paths,
        tx["task_id"],
        tx["result_state"],
        event_type=tx["event_type"],
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
        authority_ref=tx["authority_ref"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
    if appended.event["event_sha256"] != tx["planned_event"]["event_sha256"]:
        raise RoutingPersistenceError("semantic append published a different routing event")
    committed_report = inspect_routing_persistence(
        paths, tx["task_id"], [*records, appended.event]
    )
    return {
        "task_id": tx["task_id"],
        "stage": tx["stage"],
        "binding": tx["binding"],
        "event": appended.event,
        "projection": appended.projection,
        "idempotent_replay": appended.idempotent_replay,
        "routing_report": committed_report,
    }


def routing_capacity_view_from_store(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    *,
    legacy_outcomes: Iterable[Mapping[str, Any]] = (),
    unattempted_v6_outcomes: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    report = inspect_routing_persistence(paths, task_id, event_chain)
    records: list[dict[str, Any]] = []
    for group in report["groups"]:
        if group["stage"] != "terminal" or group["classification"] != "committed":
            continue
        terminal = group["terminal"]
        records.append(
            {
                "authority": group["authority"],
                "outcome": group["outcome"],
                "terminal_status": terminal["terminal_status"],
                "typed_outcome": terminal["typed_outcome"],
            }
        )
    for outcome in _bounded_records(legacy_outcomes, MAX_LEGACY_PACKETS, "legacy outcomes"):
        records.append({"legacy_outcome": _clone(outcome, max_bytes=authority.MAX_RECORD_BYTES)})
    for outcome in _bounded_records(
        unattempted_v6_outcomes, MAX_LEGACY_PACKETS, "unattempted v6 outcomes"
    ):
        records.append(
            {"unattempted_v6_outcome": _clone(outcome, max_bytes=authority.MAX_RECORD_BYTES)}
        )
    if len(records) > MAX_ROUTING_ENTRIES:
        raise RoutingPersistenceError("routing capacity input exceeds record count bound")
    try:
        return authority.capacity_routing_view(records)
    except authority.RoutingAuthorityError as exc:
        raise _fail("stored routing capacity input is invalid", exc) from exc


def classify_legacy_cutover(packets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify v0-v5 snapshots without mutating them or current v6 packets."""

    rows = _bounded_records(packets, MAX_LEGACY_PACKETS, "packet snapshots")
    terminal: list[str] = []
    ready: list[str] = []
    blockers: list[str] = []
    v6: list[str] = []
    for raw in rows:
        packet = _clone(raw, max_bytes=authority.MAX_RECORD_BYTES)
        if not isinstance(packet, dict):
            raise RoutingPersistenceError("packet snapshot is invalid")
        packet_id = h.validate_id(packet.get("packet_id"), "packet id")
        version = packet.get("packet_schema_version", packet.get("schema_version", 0))
        version = _exact_int(version, "packet schema version", maximum=6)
        status = packet.get("status")
        if not isinstance(status, str) or status not in h.PACKET_STATUSES:
            raise RoutingPersistenceError("packet snapshot status is invalid")
        attempts = _bounded_records(
            packet.get("dispatch_attempts", []), MAX_ROUTING_ENTRIES, "dispatch attempts"
        )
        live_attempt = any(
            isinstance(attempt, dict) and attempt.get("status") == "armed"
            for attempt in attempts
        )
        if version == 6:
            v6.append(packet_id)
            continue
        if status in {"armed", "dispatched"} or live_attempt:
            blockers.append(packet_id)
        elif status == "ready":
            ready.append(packet_id)
        elif status in {"done", "failed", "cancelled"}:
            terminal.append(packet_id)
        else:
            raise RoutingPersistenceError("legacy packet has an unsupported live state")
    return {
        "schema_version": ROUTING_PERSISTENCE_SCHEMA_VERSION,
        "terminal_legacy_packet_ids": sorted(terminal),
        "ready_legacy_migration_packet_ids": sorted(ready),
        "active_legacy_blocker_packet_ids": sorted(blockers),
        "v6_packet_ids": sorted(v6),
        "cutover_allowed": not blockers and not ready,
    }


__all__ = [
    "MAX_ROUTING_ENTRIES",
    "MAX_ROUTING_ENTRY_BYTES",
    "MAX_ROUTING_NAMESPACE_BYTES",
    "MAX_ROUTING_PROJECTION_BYTES",
    "ROUTING_NAMESPACE_KEY",
    "RoutingPersistenceError",
    "classify_legacy_cutover",
    "commit_routing_transaction",
    "inspect_routing_persistence",
    "prepare_authority_transaction",
    "prepare_outcome_transaction",
    "prepare_terminal_transaction",
    "routing_capacity_view_from_store",
    "routing_namespace_from_projection",
    "routing_outcome_slot_sha256",
    "validate_routing_entry",
    "validate_routing_namespace",
    "validate_routing_transaction",
]
