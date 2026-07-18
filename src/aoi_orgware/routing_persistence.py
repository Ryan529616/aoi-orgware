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
from . import cohorts
from . import resource_governance
from . import resource_config
from . import routing_authority as authority
from . import routing_bundle as bundle
from . import semantic_events as semantic
from . import semantic_objects as objects
from . import semantic_store as store
from . import transition_permits as permits


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
_DIRECT_ROUTING_BINDING_KINDS = frozenset(_BINDING_KIND.values())
_PERMIT_ROUTING_BINDING_KIND = "permit_consumption"
_COHORT_ROUTING_BINDING_KIND = "cohort_advance"
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


def prepare_authority_effect(
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    arm: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the pure routing effect of one packet-schema-v6 arm.

    A permit/cohort runtime owns the event and its single composite binding.
    It needs this exact object and projection delta without manufacturing a
    second routing binding or lifecycle event.
    """

    task_id = h.validate_id(task_id, "task id")
    _records, replayed = _freeze_event_chain(event_chain, task_id)
    checked_arm = authority.validate_arm_authority(arm)
    if checked_arm["task_id"] != task_id:
        raise RoutingPersistenceError("routing authority belongs to another task")
    routing_authority = _authority_object(task_id, checked_arm)
    entry = _entry_for("authority", checked_arm, {"routing_authority": routing_authority})
    result_state = _advance_projection(semantic.projection_domain(replayed), entry)
    # The long names are the public composite-runtime contract.  The concise
    # aliases keep this first public extraction source-compatible with callers
    # that adopted the packet wording before the runtime module landed.
    return {
        "routing_authority_object": routing_authority,
        "routing_entry": entry,
        "result_state": result_state,
        "routing_authority": routing_authority,
        "authority_entry": entry,
    }


def prepare_authority_batch_effect(
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    arms: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build one ordered, atomic projection delta for a bounded arm batch."""

    task_id = h.validate_id(task_id, "task id")
    _records, replayed = _freeze_event_chain(event_chain, task_id)
    raw_arms = _bounded_records(
        arms, cohorts.MAX_CONCURRENCY, "routing authority batch"
    )
    if not raw_arms:
        raise RoutingPersistenceError("routing authority batch is empty")
    result_state = semantic.projection_domain(replayed)
    route_objects: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    seen_packets: set[str] = set()
    seen_slots: set[str] = set()
    seen_authorities: set[str] = set()
    for raw_arm in raw_arms:
        try:
            checked_arm = authority.validate_arm_authority(raw_arm)
        except authority.RoutingAuthorityError as exc:
            raise _fail("routing authority batch contains an invalid arm", exc) from exc
        packet_id = checked_arm["packet_authority"]["packet_id"]
        authority_sha256 = authority.authority_sha256(checked_arm)
        if checked_arm["task_id"] != task_id:
            raise RoutingPersistenceError(
                "routing authority batch contains another task"
            )
        route_object = _authority_object(task_id, checked_arm)
        entry = _entry_for(
            "authority", checked_arm, {"routing_authority": route_object}
        )
        outcome_slot_sha256 = entry["outcome_slot_sha256"]
        if (
            packet_id in seen_packets
            or authority_sha256 in seen_authorities
            or outcome_slot_sha256 in seen_slots
        ):
            raise RoutingPersistenceError(
                "routing authority batch repeats a packet, authority, or outcome slot"
            )
        result_state = _advance_projection(result_state, entry)
        route_objects.append(route_object)
        entries.append(entry)
        seen_packets.add(packet_id)
        seen_authorities.add(authority_sha256)
        seen_slots.add(outcome_slot_sha256)
    return {
        "routing_authority_objects": route_objects,
        "routing_entries": entries,
        "result_state": result_state,
    }


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


def _permit_composite_group(
    binding: Mapping[str, Any],
    by_digest: Mapping[str, Mapping[str, Any]],
    task_id: str,
) -> dict[str, Any]:
    """Validate the one binding that owns a permitted ``packet.arm`` effect."""

    try:
        wrapped_rows = [by_digest[digest] for digest in binding["object_sha256s"]]
    except KeyError as exc:
        raise _fail("permit routing binding references a missing object", exc) from exc
    by_type: dict[str, dict[str, Any]] = {}
    for row in wrapped_rows:
        wrapped = objects.validate_semantic_object(row)
        if wrapped["task_id"] != task_id or wrapped["object_type"] in by_type:
            raise RoutingPersistenceError("permit routing binding object group is invalid")
        by_type[wrapped["object_type"]] = wrapped
    if set(by_type) != {"transition_decision", "transition_permit", "routing_authority"}:
        raise RoutingPersistenceError("permit routing binding object types or cardinality are invalid")
    try:
        decision = permits.validate_transition_decision(by_type["transition_decision"]["payload"])
        permit = permits.validate_transition_permit(by_type["transition_permit"]["payload"])
        pair = permits.validate_decision_permit_pair(decision, permit)
        consumption_identity = permits.permit_consumption_identity(permit)
    except permits.TransitionPermitError as exc:
        raise _fail("permit routing decision or permit is invalid", exc) from exc
    if by_type["transition_decision"]["object_identity"] != decision["decision_sha256"]:
        raise RoutingPersistenceError("transition decision object identity differs from its payload")
    if by_type["transition_permit"]["object_identity"] != permit["permit_sha256"]:
        raise RoutingPersistenceError("transition permit object identity differs from its payload")
    if decision["task_id"] != task_id or permit["task_id"] != task_id:
        raise RoutingPersistenceError("permit routing contract task differs from binding task")
    routing_authority = _individual_object(by_type["routing_authority"], task_id)
    arm = authority.validate_arm_authority(routing_authority["payload"])
    if arm["task_id"] != task_id:
        raise RoutingPersistenceError("permit routing authority task differs from binding task")
    routing_authority_sha256 = authority.authority_sha256(arm)
    if (
        pair["decision"]["action"] != "packet.arm"
        or pair["decision"]["parameters"]["packet_id"]
        != arm["packet_authority"]["packet_id"]
        or pair["decision"]["parameters"]["routing_authority_sha256"]
        != routing_authority_sha256
    ):
        raise RoutingPersistenceError("permit routing decision does not authorize this authority")
    if binding["binding_key"] != consumption_identity:
        raise RoutingPersistenceError("permit routing binding key differs from consumption identity")
    if binding["expected_semantic_head_sha256"] != permit["expected_semantic_head_sha256"]:
        raise RoutingPersistenceError("permit routing binding head differs from permit")
    return {
        "stage": "authority",
        "slot": routing_outcome_slot_sha256(arm),
        "objects": {"routing_authority": routing_authority},
        "authority": arm,
        "outcome": None,
        "terminal": None,
        "decision": decision,
        "permit": permit,
        "binding": binding,
        "composite": True,
    }


def _arm_execution_selection_id(
    arm: Mapping[str, Any], *, required: bool = True
) -> str:
    """Return the selection identity sealed by both arm resource preimages."""

    event_selection = arm["resource_authority"]["event_snapshot"].get(
        "execution_selection_id"
    )
    envelope_selection = arm["resource_envelope"]["snapshot"].get(
        "execution_selection_id"
    )
    if (
        not isinstance(event_selection, str)
        or event_selection != envelope_selection
    ):
        raise RoutingPersistenceError(
            "cohort routing arm has no exact execution-selection identity"
        )
    if not event_selection:
        if required:
            raise RoutingPersistenceError(
                "cohort routing arm has no exact execution-selection identity"
            )
        return ""
    try:
        return h.validate_id(event_selection, "execution selection id")
    except h.HarnessError as exc:
        raise _fail("cohort routing execution-selection identity is invalid", exc) from exc


def _arm_transport_slot(arm: Mapping[str, Any]) -> dict[str, str]:
    return {
        "transport": arm["transport_authority"]["transport"],
        "parent_session_id": arm["parent_authority"]["session_id"],
        "expected_agent_type": arm["transport_authority"]["expected_agent_type"],
    }


def _transport_slots_collide(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> bool:
    return (
        left["transport"] == right["transport"]
        and left["parent_session_id"] == right["parent_session_id"]
        and (
            left["expected_agent_type"] == "*"
            or right["expected_agent_type"] == "*"
            or left["expected_agent_type"] == right["expected_agent_type"]
        )
    )


def _require_authority_entry_identity(
    entry: Mapping[str, Any],
    arm: Mapping[str, Any],
    routing_authority_object: Mapping[str, Any],
) -> None:
    """Cross-check immutable arm identity while allowing later route phases."""

    expected = _entry_for(
        "authority", arm, {"routing_authority": routing_authority_object}
    )
    immutable_fields = {
        "schema_version",
        "packet_schema_version",
        "packet_id",
        "arm_id",
        "attempt",
        "outcome_slot_sha256",
        "routing_authority_object_sha256",
    }
    if any(entry.get(field) != expected[field] for field in immutable_fields):
        raise RoutingPersistenceError(
            "committed composite routing projection entry identity is invalid"
        )


def _cohort_terminal_outcome(terminal: Mapping[str, Any]) -> str:
    terminal_status = terminal.get("terminal_status")
    typed_outcome = terminal.get("typed_outcome")
    if typed_outcome == "accepted":
        return "accepted"
    if typed_outcome == "rejected" or terminal_status == "done":
        return "rejected"
    if terminal_status == "cancelled" or typed_outcome == "cancelled":
        return "cancelled"
    if terminal_status == "failed":
        return "failed"
    raise RoutingPersistenceError("routing terminal has no cohort outcome mapping")


def _cohort_prefix_truth(
    prefix_projection: Mapping[str, Any],
    by_digest: Mapping[str, Mapping[str, Any]],
    task_id: str,
) -> dict[str, Any]:
    """Derive route states from one authenticated semantic prefix projection."""

    namespace = routing_namespace_from_projection(prefix_projection)
    by_authority: dict[str, dict[str, Any]] = {}
    active_packets: dict[str, dict[str, Any]] = {}
    terminal_packet_ids: set[str] = set()
    armed_transport_slots: list[dict[str, Any]] = []
    for slot, entry in namespace["entries"].items():
        try:
            wrapped_arm = _individual_object(
                by_digest[entry["routing_authority_object_sha256"]], task_id
            )
        except KeyError as exc:
            raise _fail(
                "routing prefix entry references a missing authority object", exc
            ) from exc
        if wrapped_arm["object_type"] != "routing_authority":
            raise RoutingPersistenceError(
                "routing prefix authority reference has the wrong object type"
            )
        arm = authority.validate_arm_authority(wrapped_arm["payload"])
        _require_authority_entry_identity(entry, arm, wrapped_arm)
        authority_sha256 = authority.authority_sha256(arm)
        packet_id = arm["packet_authority"]["packet_id"]
        if authority_sha256 in by_authority:
            raise RoutingPersistenceError(
                "routing prefix repeats a cohort authority identity"
            )
        selection_id = _arm_execution_selection_id(arm, required=False)
        status = "armed"
        terminal_outcome: str | None = None
        outcome: dict[str, Any] | None = None
        if entry["phase"] in {"outcome", "terminal"}:
            try:
                wrapped_outcome = _individual_object(
                    by_digest[entry["routing_outcome_object_sha256"]], task_id
                )
            except KeyError as exc:
                raise _fail(
                    "routing prefix entry references a missing outcome object", exc
                ) from exc
            if wrapped_outcome["object_type"] != "routing_outcome":
                raise RoutingPersistenceError(
                    "routing prefix outcome reference has the wrong object type"
                )
            outcome = authority.validate_dispatch_outcome(
                arm, wrapped_outcome["payload"]
            )
            if outcome["dispatch_provenance"] == "codex_subagent_start_observed":
                status = "start_observed"
        if entry["phase"] == "terminal":
            try:
                wrapped_terminal = _individual_object(
                    by_digest[entry["routing_terminal_object_sha256"]], task_id
                )
            except KeyError as exc:
                raise _fail(
                    "routing prefix entry references a missing terminal object", exc
                ) from exc
            if wrapped_terminal["object_type"] != "routing_terminal":
                raise RoutingPersistenceError(
                    "routing prefix terminal reference has the wrong object type"
                )
            terminal_outcome = _cohort_terminal_outcome(wrapped_terminal["payload"])
            status = "terminal"
            terminal_packet_ids.add(packet_id)
        if status in {"armed", "start_observed"}:
            if packet_id in active_packets:
                raise RoutingPersistenceError(
                    "routing prefix has concurrent active attempts for one packet"
                )
            active_packets[packet_id] = {
                "selection_id": selection_id,
                "delegation_depth": _exact_int(
                    arm["packet_authority"].get("delegation_depth"),
                    "routing prefix delegation depth",
                    minimum=1,
                    maximum=resource_config.AOI_MAX_DELEGATION_DEPTH,
                ),
                "routing_authority_sha256": authority_sha256,
            }
        if status == "armed":
            armed_transport_slots.append(
                {
                    **_arm_transport_slot(arm),
                    "packet_id": packet_id,
                    "routing_authority_sha256": authority_sha256,
                }
            )
        by_authority[authority_sha256] = {
            "packet_id": packet_id,
            "status": status,
            "terminal_outcome": terminal_outcome,
            "selection_id": selection_id,
            "resource_envelope_sha256": arm["resource_envelope"]["snapshot_sha256"],
            "outcome_slot_sha256": slot,
        }
    return {
        "by_authority": by_authority,
        "active_packets": active_packets,
        "active_packet_ids": set(active_packets),
        "terminal_packet_ids": terminal_packet_ids,
        "armed_transport_slots": armed_transport_slots,
    }


def _require_current_lane_snapshot(
    domain: Mapping[str, Any], raw_snapshot: Any, label: str
) -> dict[str, Any]:
    if not isinstance(raw_snapshot, Mapping):
        raise RoutingPersistenceError(f"{label} is invalid")
    snapshot = dict(raw_snapshot)
    lane_id = h.validate_id(snapshot.get("lane_id"), f"{label} lane id")
    raw_lanes = domain.get("lanes", [])
    if not isinstance(raw_lanes, list) or len(raw_lanes) > MAX_LEGACY_PACKETS:
        raise RoutingPersistenceError("semantic prefix lane collection is invalid or over bound")
    matches = [lane for lane in raw_lanes if isinstance(lane, Mapping) and lane.get("lane_id") == lane_id]
    if len(matches) != 1:
        raise RoutingPersistenceError(f"{label} does not name exactly one current lane")
    try:
        expected = resource_governance.lane_authority_snapshot(dict(matches[0]))
    except (KeyError, TypeError, ValueError) as exc:
        raise _fail(f"{label} current lane authority is incomplete", exc) from exc
    if snapshot != expected:
        raise RoutingPersistenceError(f"{label} is stale or differs from current lane authority")
    return snapshot


def _require_active_v2_execution_selection(
    prefix_projection: Mapping[str, Any],
    selection_id: str,
    plan: Mapping[str, Any],
    groups: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Authenticate the exact active v2 selection and arm dynamic envelope."""

    try:
        domain = semantic.projection_domain(prefix_projection)
    except semantic.SemanticEventError as exc:
        raise _fail("cohort execution-selection prefix is invalid", exc) from exc
    if (
        domain.get("task_execution_schema_version") != 2
        or isinstance(domain.get("task_execution_schema_version"), bool)
        or domain.get("execution_policy_version") != 2
        or isinstance(domain.get("execution_policy_version"), bool)
        or domain.get("legacy_execution_policy") is not False
    ):
        raise RoutingPersistenceError(
            "cohort advance requires native execution-policy v2 markers at its exact head"
        )
    raw_selections = domain.get("execution_selections", [])
    if not isinstance(raw_selections, list) or len(raw_selections) > MAX_LEGACY_PACKETS:
        raise RoutingPersistenceError(
            "semantic prefix execution-selection collection is invalid or over bound"
        )
    matches = [
        row
        for row in raw_selections
        if isinstance(row, Mapping) and row.get("selection_id") == selection_id
    ]
    if len(matches) != 1:
        raise RoutingPersistenceError(
            "cohort advance requires exactly one matching execution selection"
        )
    selection = dict(matches[0])
    if (
        selection.get("integrity_version") != 1
        or isinstance(selection.get("integrity_version"), bool)
        or selection.get("execution_selection_version") != 2
        or isinstance(selection.get("execution_selection_version"), bool)
        or selection.get("status") != "active"
    ):
        raise RoutingPersistenceError(
            "cohort advance execution selection is not one active integrity-v1/v2 record"
        )
    if selection.get("mode") not in {"single", "centralized_parallel", "hybrid"}:
        raise RoutingPersistenceError("cohort execution-selection mode is invalid")
    envelope = selection.get("resource_envelope")
    if not isinstance(envelope, Mapping):
        raise RoutingPersistenceError("cohort execution-selection resource envelope is invalid")
    envelope = dict(envelope)
    envelope_sha256 = _sha(
        selection.get("resource_envelope_sha256"),
        "cohort execution-selection resource envelope SHA-256",
    )
    try:
        actual_envelope_sha256 = semantic.canonical_sha256(envelope)
        target_contract = resource_governance.execution_selection_target_contract_from_record(
            dict(domain), selection
        )
        actual_target_contract_sha256 = semantic.canonical_sha256(target_contract)
    except (semantic.SemanticEventError, h.HarnessError, TypeError, ValueError) as exc:
        raise _fail("cohort execution-selection contract is invalid", exc) from exc
    if actual_envelope_sha256 != envelope_sha256:
        raise RoutingPersistenceError(
            "cohort execution-selection resource envelope lost integrity"
        )
    target_contract_sha256 = _sha(
        selection.get("target_contract_sha256"),
        "cohort execution-selection target contract SHA-256",
    )
    if (
        actual_target_contract_sha256 != target_contract_sha256
        or plan["execution_selection_target_contract_sha256"]
        != target_contract_sha256
    ):
        raise RoutingPersistenceError(
            "cohort plan differs from the active execution-selection target contract"
        )
    lane_snapshots = selection.get("lane_snapshots")
    if (
        not isinstance(lane_snapshots, list)
        or not lane_snapshots
        or len(lane_snapshots) > cohorts.MAX_CONCURRENCY
    ):
        raise RoutingPersistenceError("cohort execution-selection lane snapshots are invalid")
    seen_lanes: set[str] = set()
    for index, snapshot in enumerate(lane_snapshots):
        checked = _require_current_lane_snapshot(
            domain, snapshot, f"execution-selection lane snapshot {index}"
        )
        if checked["lane_id"] in seen_lanes:
            raise RoutingPersistenceError("cohort execution selection repeats a lane snapshot")
        seen_lanes.add(checked["lane_id"])
    steward_snapshot = selection.get("steward_snapshot")
    if steward_snapshot != {}:
        checked_steward = _require_current_lane_snapshot(
            domain, steward_snapshot, "execution-selection Steward snapshot"
        )
        if checked_steward["lane_id"] in seen_lanes:
            raise RoutingPersistenceError(
                "cohort execution selection repeats the Steward in specialist lanes"
            )
    task_plan_sha256 = _sha(
        selection.get("task_plan_sha256"),
        "cohort execution-selection task plan SHA-256",
    )
    if task_plan_sha256 != domain.get("plan_sha256"):
        raise RoutingPersistenceError(
            "cohort execution selection differs from the exact-head task plan"
        )
    max_first_level = _exact_int(
        envelope.get("max_active_first_level_agents"),
        "cohort execution-selection first-level capacity",
        minimum=1,
        maximum=cohorts.MAX_CONCURRENCY,
    )
    max_total = _exact_int(
        envelope.get("max_active_total_agents"),
        "cohort execution-selection total capacity",
        minimum=1,
        maximum=cohorts.MAX_CONCURRENCY,
    )
    max_depth = _exact_int(
        envelope.get("max_delegation_depth"),
        "cohort execution-selection delegation-depth capacity",
        minimum=1,
        maximum=resource_config.AOI_MAX_DELEGATION_DEPTH,
    )
    if max_first_level > max_total:
        raise RoutingPersistenceError(
            "cohort execution-selection first-level capacity exceeds total capacity"
        )
    expected_dynamic_envelope = {
        **envelope,
        "execution_selection_id": selection_id,
        "resource_envelope_sha256": envelope_sha256,
    }
    try:
        dynamic_envelope_sha256 = semantic.canonical_sha256(expected_dynamic_envelope)
    except semantic.SemanticEventError as exc:
        raise _fail("cohort execution-selection dynamic envelope is invalid", exc) from exc
    if plan["resource_envelope_sha256"] != dynamic_envelope_sha256:
        raise RoutingPersistenceError(
            "cohort plan differs from the active execution-selection dynamic envelope"
        )
    for group in groups:
        arm = group["authority"]
        event = arm["resource_authority"]["event_snapshot"]
        if (
            arm["packet_authority"]["task_plan_sha256"] != task_plan_sha256
            or event["task_plan_sha256"] != task_plan_sha256
            or event["execution_selection_id"] != selection_id
            or event["dynamic_envelope"] != expected_dynamic_envelope
            or arm["resource_envelope"]["snapshot"] != expected_dynamic_envelope
            or arm["resource_envelope"]["snapshot_sha256"]
            != dynamic_envelope_sha256
        ):
            raise RoutingPersistenceError(
                "cohort routing arm differs from the active execution-selection contract"
            )
    return {
        "selection": selection,
        "selection_id": selection_id,
        "max_active_first_level_agents": max_first_level,
        "max_active_total_agents": max_total,
        "max_delegation_depth": max_depth,
        "dynamic_envelope": expected_dynamic_envelope,
        "dynamic_envelope_sha256": dynamic_envelope_sha256,
    }


def _prefix_execution_occupancy(
    prefix_projection: Mapping[str, Any],
    routing_active_packets: Mapping[str, Mapping[str, Any]],
    routing_terminal_packet_ids: set[str],
) -> dict[str, Any]:
    """Union routing-v6, state packet, and external-job occupancy without drift."""

    domain = semantic.projection_domain(prefix_projection)
    raw_packets = domain.get("packets", [])
    if not isinstance(raw_packets, list) or len(raw_packets) > MAX_LEGACY_PACKETS:
        raise RoutingPersistenceError(
            "semantic prefix packet collection is invalid or over bound"
        )
    active_packets = {packet_id: dict(row) for packet_id, row in routing_active_packets.items()}
    seen_state_packet_ids: set[str] = set()
    for packet in raw_packets:
        if not isinstance(packet, Mapping):
            raise RoutingPersistenceError("semantic prefix packet row is invalid")
        packet_id = h.validate_id(packet.get("packet_id"), "packet id")
        if packet_id in seen_state_packet_ids:
            raise RoutingPersistenceError("semantic prefix repeats a packet id")
        seen_state_packet_ids.add(packet_id)
        attempts = packet.get("dispatch_attempts", [])
        if not isinstance(attempts, list) or len(attempts) > MAX_ROUTING_ENTRIES:
            raise RoutingPersistenceError("semantic prefix dispatch attempts are invalid or over bound")
        live_attempt = any(
            isinstance(attempt, Mapping) and attempt.get("status") == "armed"
            for attempt in attempts
        )
        if packet.get("status") not in {"armed", "dispatched"} and not live_attempt:
            continue
        if packet_id in routing_terminal_packet_ids and packet_id not in active_packets:
            # A committed routing terminal is the newer event-authoritative
            # fact for that exact packet; the legacy/state row may lag.
            continue
        selection_id = packet.get("execution_selection_id", "")
        if not isinstance(selection_id, str):
            raise RoutingPersistenceError(
                "executing state packet execution-selection identity is invalid"
            )
        if selection_id:
            h.validate_id(selection_id, "execution selection id")
        depth = _exact_int(
            packet.get("delegation_depth", 1),
            "executing state packet delegation depth",
            minimum=1,
            maximum=resource_config.AOI_MAX_DELEGATION_DEPTH,
        )
        prior = active_packets.get(packet_id)
        state_truth = {
            "selection_id": selection_id,
            "delegation_depth": depth,
            "routing_authority_sha256": None,
        }
        if prior is not None:
            if (
                prior["selection_id"] != selection_id
                or prior["delegation_depth"] != depth
            ):
                raise RoutingPersistenceError(
                    "routing and state-backed active packet occupancy conflict"
                )
        else:
            active_packets[packet_id] = state_truth
    raw_jobs = domain.get("jobs", [])
    if not isinstance(raw_jobs, list) or len(raw_jobs) > MAX_LEGACY_PACKETS:
        raise RoutingPersistenceError("semantic prefix job collection is invalid or over bound")
    standalone_jobs: list[dict[str, str]] = []
    seen_run_ids: set[str] = set()
    for job in raw_jobs:
        if not isinstance(job, Mapping):
            raise RoutingPersistenceError("semantic prefix job row is invalid")
        if job.get("status") not in h.ACTIVE_JOB_STATUSES:
            continue
        run_id = h.validate_id(job.get("run_id"), "job run id")
        if run_id in seen_run_ids:
            raise RoutingPersistenceError("semantic prefix repeats an active job id")
        seen_run_ids.add(run_id)
        selection_id = job.get("execution_selection_id", "")
        if not isinstance(selection_id, str):
            raise RoutingPersistenceError(
                "active job execution-selection identity is invalid"
            )
        if selection_id:
            h.validate_id(selection_id, "execution selection id")
        owner_packet_id = job.get("owner_packet_id", "")
        if not isinstance(owner_packet_id, str):
            raise RoutingPersistenceError("active job owner packet identity is invalid")
        if owner_packet_id:
            h.validate_id(owner_packet_id, "job owner packet id")
            owner = active_packets.get(owner_packet_id)
            if owner is None or owner["selection_id"] != selection_id:
                raise RoutingPersistenceError(
                    "active owned job has no matching active packet chain"
                )
            continue
        standalone_jobs.append(
            {"run_id": run_id, "selection_id": selection_id}
        )
    return {
        "active_packets": active_packets,
        "standalone_jobs": standalone_jobs,
    }


def _cohort_composite_groups(
    binding: Mapping[str, Any],
    by_digest: Mapping[str, Mapping[str, Any]],
    task_id: str,
) -> list[dict[str, Any]]:
    """Validate one permitted cohort advance that owns several arm entries."""

    try:
        wrapped_rows = [by_digest[digest] for digest in binding["object_sha256s"]]
    except KeyError as exc:
        raise _fail("cohort routing binding references a missing object", exc) from exc
    singleton: dict[str, dict[str, Any]] = {}
    route_objects: list[dict[str, Any]] = []
    for row in wrapped_rows:
        wrapped = objects.validate_semantic_object(row)
        if wrapped["task_id"] != task_id:
            raise RoutingPersistenceError(
                "cohort routing binding object belongs to another task"
            )
        if wrapped["object_type"] == "routing_authority":
            route_objects.append(wrapped)
        elif wrapped["object_type"] in {
            "transition_decision",
            "transition_permit",
            "cohort_plan",
        }:
            if wrapped["object_type"] in singleton:
                raise RoutingPersistenceError(
                    "cohort routing binding repeats a singleton object type"
                )
            singleton[wrapped["object_type"]] = wrapped
        else:
            raise RoutingPersistenceError(
                "cohort routing binding contains an unsupported object type"
            )
    if (
        set(singleton)
        != {"transition_decision", "transition_permit", "cohort_plan"}
        or not 1 <= len(route_objects) <= cohorts.MAX_CONCURRENCY
    ):
        raise RoutingPersistenceError(
            "cohort routing binding object types or cardinality are invalid"
        )
    try:
        decision = permits.validate_transition_decision(
            singleton["transition_decision"]["payload"]
        )
        permit = permits.validate_transition_permit(
            singleton["transition_permit"]["payload"]
        )
        pair = permits.validate_decision_permit_pair(decision, permit)
        plan = cohorts.validate_cohort(singleton["cohort_plan"]["payload"])
        consumption_identity = permits.permit_consumption_identity(permit)
    except (permits.TransitionPermitError, cohorts.CohortError) as exc:
        raise _fail("cohort routing decision, permit, or plan is invalid", exc) from exc
    if (
        singleton["transition_decision"]["object_identity"]
        != decision["decision_sha256"]
        or singleton["transition_permit"]["object_identity"]
        != permit["permit_sha256"]
        or singleton["cohort_plan"]["object_identity"]
        != plan["cohort_sha256"]
    ):
        raise RoutingPersistenceError(
            "cohort routing contract object identity differs from its payload"
        )
    parameters = pair["decision"]["parameters"]
    if (
        decision["task_id"] != task_id
        or permit["task_id"] != task_id
        or pair["decision"]["action"] != "cohort.advance"
        or pair["decision"]["target_ids"] != [plan["cohort_id"]]
        or parameters["cohort_id"] != plan["cohort_id"]
        or parameters["cohort_sha256"] != plan["cohort_sha256"]
        or not 0 <= parameters["wave_index"] < len(plan["waves"])
    ):
        raise RoutingPersistenceError(
            "cohort routing decision does not authorize this plan and wave"
        )
    if binding["binding_key"] != consumption_identity:
        raise RoutingPersistenceError(
            "cohort routing binding key differs from consumption identity"
        )
    if binding["expected_semantic_head_sha256"] != permit[
        "expected_semantic_head_sha256"
    ]:
        raise RoutingPersistenceError("cohort routing binding head differs from permit")

    wave_index = parameters["wave_index"]
    wave = plan["waves"][wave_index]
    plan_refs = {
        ref["packet_id"]: ref["routing_authority_sha256"]
        for ref in plan["packet_refs"]
    }
    transport_slots = {
        row["packet_id"]: row for row in plan["transport_slots"]
    }
    by_packet: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {}
    seen_slots: set[str] = set()
    execution_selection_id: str | None = None
    for wrapped in route_objects:
        route_object = _individual_object(wrapped, task_id)
        try:
            arm = authority.validate_arm_authority(route_object["payload"])
            authority_sha256 = authority.authority_sha256(arm)
            outcome_slot_sha256 = routing_outcome_slot_sha256(arm)
        except authority.RoutingAuthorityError as exc:
            raise _fail("cohort routing authority is invalid", exc) from exc
        packet_id = arm["packet_authority"]["packet_id"]
        slot = transport_slots.get(packet_id)
        arm_selection_id = _arm_execution_selection_id(arm)
        arm_depth = _exact_int(
            arm["packet_authority"].get("delegation_depth"),
            "cohort routing delegation depth",
            minimum=1,
            maximum=resource_config.AOI_MAX_DELEGATION_DEPTH,
        )
        if arm_depth != 1:
            raise RoutingPersistenceError(
                "cohort advance schema v1 supports depth-one routing authorities only"
            )
        if execution_selection_id is None:
            execution_selection_id = arm_selection_id
        elif execution_selection_id != arm_selection_id:
            raise RoutingPersistenceError(
                "cohort routing authorities differ in execution-selection identity"
            )
        if (
            arm["task_id"] != task_id
            or packet_id not in wave
            or packet_id in by_packet
            or plan_refs.get(packet_id) != authority_sha256
            or wrapped["object_identity"] != authority_sha256
            or plan["resource_envelope_sha256"]
            != arm["resource_envelope"]["snapshot_sha256"]
            or arm["chief_authority"]["session_id"]
            != permit["chief_authority"]["session_id"]
            or arm["chief_authority"]["epoch"] != permit["chief_authority"]["epoch"]
            or slot is None
            or slot["transport"] != arm["transport_authority"]["transport"]
            or slot["parent_session_id"] != arm["parent_authority"]["session_id"]
            or slot["expected_agent_type"]
            != arm["transport_authority"]["expected_agent_type"]
            or outcome_slot_sha256 in seen_slots
        ):
            raise RoutingPersistenceError(
                "cohort routing authority differs from its sealed plan, permit, or slot"
            )
        by_packet[packet_id] = (route_object, arm, outcome_slot_sha256)
        seen_slots.add(outcome_slot_sha256)
    assert execution_selection_id is not None
    try:
        expected_selection_identity_sha256 = (
            cohorts.execution_selection_identity_sha256(execution_selection_id)
        )
    except cohorts.CohortError as exc:
        raise _fail("cohort routing execution-selection identity is invalid", exc) from exc
    if (
        plan["execution_selection_identity_sha256"]
        != expected_selection_identity_sha256
    ):
        raise RoutingPersistenceError(
            "cohort plan differs from its arms' execution-selection identity"
        )
    selected_packet_ids = [packet_id for packet_id in wave if packet_id in by_packet]
    if len(selected_packet_ids) != len(route_objects):
        raise RoutingPersistenceError(
            "cohort routing authority selection is not unique in wave order"
        )
    selection_base = {
        "schema_version": cohorts.COHORT_ADVANCE_SELECTION_SCHEMA_VERSION,
        "cohort_sha256": plan["cohort_sha256"],
        "wave_index": wave_index,
        "routes": [
            {
                "packet_id": packet_id,
                "routing_authority_sha256": authority.authority_sha256(
                    by_packet[packet_id][1]
                ),
                "outcome_slot_sha256": by_packet[packet_id][2],
            }
            for packet_id in selected_packet_ids
        ],
    }
    return [
        {
            "stage": "authority",
            "slot": by_packet[packet_id][2],
            "objects": {"routing_authority": by_packet[packet_id][0]},
            "authority": by_packet[packet_id][1],
            "outcome": None,
            "terminal": None,
            "decision": decision,
            "permit": permit,
            "cohort_plan": plan,
            # The exact-head pass seals this base only after deriving live
            # states and capacity from the authenticated semantic prefix.
            "selection": selection_base,
            "execution_selection_id": execution_selection_id,
            "binding": binding,
            "composite": True,
            "composite_kind": "cohort",
        }
        for packet_id in selected_packet_ids
    ]


def _validate_cohort_exact_head_contracts(
    groups: list[dict[str, Any]],
    records: list[Mapping[str, Any]],
    event_by_sha: Mapping[str, Mapping[str, Any]],
    by_digest: Mapping[str, Mapping[str, Any]],
    task_id: str,
) -> None:
    """Re-derive every cohort advance at its binding's exact semantic head.

    The full chain is already authenticated.  This pass applies each public
    semantic delta once and validates all cohort bindings when their expected
    head is reached, so cost is linear in ledger length rather than one replay
    per binding.
    """

    contracts: dict[str, dict[str, Any]] = {}
    for group in groups:
        if group.get("composite_kind") != "cohort":
            continue
        binding = group["binding"]
        binding_sha256 = binding["binding_sha256"]
        invariant = {
            "binding": binding,
            "decision": group["decision"],
            "cohort_plan": group["cohort_plan"],
            "selection": group["selection"],
            "execution_selection_id": group["execution_selection_id"],
            "classification": group["classification"],
        }
        prior = contracts.get(binding_sha256)
        if prior is None:
            contracts[binding_sha256] = {**invariant, "groups": [group]}
        else:
            if any(prior[key] != value for key, value in invariant.items()):
                raise RoutingPersistenceError(
                    "cohort routing binding expands to inconsistent arm contracts"
                )
            prior["groups"].append(group)
    if not contracts:
        return

    by_head: dict[str, list[dict[str, Any]]] = {}
    by_planned_event: dict[str, list[dict[str, Any]]] = {}
    committed_contracts: set[str] = set()
    for binding_sha256, contract in contracts.items():
        head_sha256 = contract["binding"]["expected_semantic_head_sha256"]
        if head_sha256 not in event_by_sha:
            raise RoutingPersistenceError(
                "cohort routing binding expected head is absent from the ledger"
            )
        by_head.setdefault(head_sha256, []).append(contract)
        if contract["classification"] == "committed":
            planned_event_sha256 = contract["binding"]["planned_event_sha256"]
            if planned_event_sha256 not in event_by_sha:
                raise RoutingPersistenceError(
                    "committed cohort routing binding planned event is absent from the ledger"
                )
            by_planned_event.setdefault(planned_event_sha256, []).append(contract)
            committed_contracts.add(binding_sha256)

    try:
        domain = semantic.projection_domain(semantic.replay_events(records[:1]))
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("cannot initialize cohort exact-head replay", exc) from exc
    validated: set[str] = set()
    after_image_validated: set[str] = set()
    for index, event in enumerate(records):
        before_domain = domain
        if index:
            try:
                domain = semantic.apply_delta(domain, event["payload"]["delta"])
            except (semantic.SemanticEventError, KeyError, TypeError) as exc:
                raise _fail("cannot replay cohort exact-head semantic delta", exc) from exc
        try:
            if semantic.canonical_sha256(domain) != event["result_projection_sha256"]:
                raise RoutingPersistenceError(
                    "cohort exact-head replay diverges from authenticated event result"
                )
            prefix_projection = semantic.projection_for_event(domain, event)
        except semantic.SemanticEventError as exc:
            raise _fail("cohort exact-head projection is invalid", exc) from exc

        head_contracts = by_head.get(event["event_sha256"], [])
        if head_contracts:
            prefix_truth = _cohort_prefix_truth(prefix_projection, by_digest, task_id)
            occupancy = _prefix_execution_occupancy(
                prefix_projection,
                prefix_truth["active_packets"],
                prefix_truth["terminal_packet_ids"],
            )
            for contract in head_contracts:
                plan = contract["cohort_plan"]
                selection_base = contract["selection"]
                selection_id = contract["execution_selection_id"]
                selection_contract = _require_active_v2_execution_selection(
                    prefix_projection,
                    selection_id,
                    plan,
                    contract["groups"],
                )
                active_packets = occupancy["active_packets"]
                standalone_jobs = occupancy["standalone_jobs"]
                foreign_packets = [
                    packet_id
                    for packet_id, truth in active_packets.items()
                    if truth["selection_id"] != selection_id
                ]
                foreign_jobs = [
                    row["run_id"]
                    for row in standalone_jobs
                    if row["selection_id"] != selection_id
                ]
                if foreign_packets or foreign_jobs:
                    raise RoutingPersistenceError(
                        "cohort advance is blocked by a foreign or implicit execution epoch"
                    )
                active_total = len(active_packets)
                active_first_level = sum(
                    truth["delegation_depth"] == 1
                    for truth in active_packets.values()
                ) + len(standalone_jobs)
                max_total = selection_contract["max_active_total_agents"]
                max_first_level = selection_contract[
                    "max_active_first_level_agents"
                ]
                if active_total > max_total or active_first_level > max_first_level:
                    raise RoutingPersistenceError(
                        "cohort exact-head occupancy already exceeds its execution envelope"
                    )
                packet_states: dict[str, dict[str, str | None]] = {}
                for ref in plan["packet_refs"]:
                    packet_id = ref["packet_id"]
                    active_packet_truth = active_packets.get(packet_id)
                    if (
                        active_packet_truth is not None
                        and active_packet_truth["routing_authority_sha256"]
                        != ref["routing_authority_sha256"]
                    ):
                        raise RoutingPersistenceError(
                            "cohort packet has another active authority at its exact head"
                        )
                    route_state = prefix_truth["by_authority"].get(
                        ref["routing_authority_sha256"]
                    )
                    if route_state is None:
                        if packet_id in active_packets:
                            raise RoutingPersistenceError(
                                "cohort packet has another active authority at its exact head"
                            )
                        packet_states[packet_id] = {
                            "status": "planned",
                            "terminal_outcome": None,
                        }
                        continue
                    if (
                        route_state["packet_id"] != packet_id
                        or route_state["selection_id"] != selection_id
                        or route_state["resource_envelope_sha256"]
                        != plan["resource_envelope_sha256"]
                    ):
                        raise RoutingPersistenceError(
                            "cohort prefix route differs from its plan identity or envelope"
                        )
                    packet_states[packet_id] = {
                        "status": route_state["status"],
                        "terminal_outcome": route_state["terminal_outcome"],
                    }
                remaining_total = max_total - active_total
                remaining_first_level = max_first_level - active_first_level
                available_capacity = max(
                    0, min(remaining_total, remaining_first_level)
                )
                try:
                    sealed_selection = cohorts.seal_cohort_advance_selection(
                        plan,
                        selection_base,
                        packet_states,
                        available_capacity=available_capacity,
                    )
                except cohorts.CohortError as exc:
                    raise _fail(
                        "cohort routing selection is ineligible at its exact semantic head",
                        exc,
                    ) from exc
                if (
                    contract["decision"]["technical_payload_sha256"]
                    != sealed_selection["selection_sha256"]
                ):
                    raise RoutingPersistenceError(
                        "cohort routing decision technical payload differs from exact selection"
                    )
                selected_packet_ids = {
                    route["packet_id"] for route in sealed_selection["routes"]
                }
                selected_slots = [
                    slot
                    for slot in plan["transport_slots"]
                    if slot["packet_id"] in selected_packet_ids
                ]
                for selected_slot in selected_slots:
                    if any(
                        _transport_slots_collide(selected_slot, occupied)
                        for occupied in prefix_truth["armed_transport_slots"]
                    ):
                        raise RoutingPersistenceError(
                            "cohort routing selection collides with an armed transport slot"
                        )
                for group in contract["groups"]:
                    group["selection"] = sealed_selection
                validated.add(contract["binding"]["binding_sha256"])

        planned_contracts = by_planned_event.get(event["event_sha256"], [])
        if planned_contracts:
            expected_domain = _clone(before_domain)
            expected_namespace = routing_namespace_from_projection(expected_domain)
            for contract in planned_contracts:
                binding_sha256 = contract["binding"]["binding_sha256"]
                if binding_sha256 not in validated:
                    raise RoutingPersistenceError(
                        "cohort planned event precedes exact-head authorization"
                    )
                for group in contract["groups"]:
                    expected_entry = _entry_for(
                        "authority",
                        group["authority"],
                        {"routing_authority": group["objects"]["routing_authority"]},
                    )
                    if group["slot"] in expected_namespace["entries"]:
                        raise RoutingPersistenceError(
                            "cohort planned event tries to replace an existing routing entry"
                        )
                    expected_namespace["entries"][group["slot"]] = expected_entry
                expected_domain[ROUTING_NAMESPACE_KEY] = validate_routing_namespace(
                    expected_namespace
                )
                after_image_validated.add(binding_sha256)
            try:
                expected_bytes = semantic.canonical_json_bytes(
                    expected_domain, max_bytes=MAX_ROUTING_PROJECTION_BYTES
                )
                actual_bytes = semantic.canonical_json_bytes(
                    domain, max_bytes=MAX_ROUTING_PROJECTION_BYTES
                )
            except semantic.SemanticEventError as exc:
                raise _fail("cohort planned event after-image is invalid", exc) from exc
            if actual_bytes != expected_bytes:
                raise RoutingPersistenceError(
                    "cohort planned event has a partial or altered exact after-image"
                )
    if validated != set(contracts):
        raise RoutingPersistenceError(
            "not every cohort routing binding was validated at its exact head"
        )
    if after_image_validated != committed_contracts:
        raise RoutingPersistenceError(
            "not every committed cohort routing binding has an exact planned after-image"
        )


def _routing_report_from_generic(
    report: Mapping[str, Any],
    projection: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    task_id = h.validate_id(report.get("task_id"), "task id")
    object_rows = report.get("objects")
    binding_rows = report.get("bindings")
    if not isinstance(object_rows, list) or not isinstance(binding_rows, list):
        raise RoutingPersistenceError("generic semantic object report is invalid")
    records = _bounded_records(
        event_chain, semantic.MAX_LEDGER_EVENTS, "routing event chain"
    )
    event_by_sha: dict[str, Mapping[str, Any]] = {}
    for event in records:
        if not isinstance(event, Mapping):
            raise RoutingPersistenceError("routing event chain row is invalid")
        digest = event.get("event_sha256")
        _sha(digest, "routing event SHA-256")
        if digest in event_by_sha:
            raise RoutingPersistenceError("routing event chain repeats an event SHA-256")
        event_by_sha[digest] = event
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
        if references & routing_digests and binding["binding_kind"] not in (
            _DIRECT_ROUTING_BINDING_KINDS
            | {_PERMIT_ROUTING_BINDING_KIND, _COHORT_ROUTING_BINDING_KIND}
        ):
            raise RoutingPersistenceError("routing object is referenced by a non-routing binding")
        if binding["binding_kind"] == _PERMIT_ROUTING_BINDING_KIND:
            group = _permit_composite_group(binding, by_digest, task_id)
            groups.append({**group, "classification": row.get("classification")})
            continue
        if binding["binding_kind"] == _COHORT_ROUTING_BINDING_KIND:
            cohort_groups = _cohort_composite_groups(binding, by_digest, task_id)
            groups.extend(
                {**group, "classification": row.get("classification")}
                for group in cohort_groups
            )
            continue
        if binding["binding_kind"] not in _DIRECT_ROUTING_BINDING_KINDS:
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
    owned_stages: set[tuple[str, str]] = set()
    binding_sha256s: set[str] = set()
    binding_contracts: dict[str, dict[str, Any]] = {}
    committed: dict[tuple[str, str], dict[str, Any]] = {}
    for group in groups:
        key = (group["slot"], group["stage"])
        if key in owned_stages:
            raise RoutingPersistenceError("routing slot stage has multiple owning bindings")
        owned_stages.add(key)
        binding_sha = group["binding"]["binding_sha256"]
        prior_binding = binding_contracts.get(binding_sha)
        if prior_binding is None:
            binding_contracts[binding_sha] = group["binding"]
            binding_sha256s.add(binding_sha)
        elif (
            group.get("composite_kind") != "cohort"
            or prior_binding != group["binding"]
        ):
            raise RoutingPersistenceError("routing binding digest is not unique")
        if group["classification"] == "committed":
            committed[key] = group
    for group in groups:
        entry = entries.get(group["slot"])
        rank = _PHASE_RANK[group["stage"]]
        if group["classification"] == "committed":
            event = event_by_sha.get(group["binding"]["planned_event_sha256"])
            if event is None:
                raise RoutingPersistenceError("committed routing binding has no ledger event")
            try:
                event_type = semantic.command_semantics(event)["event_type"]
            except semantic.SemanticEventError as exc:
                raise _fail("routing binding ledger event is invalid", exc) from exc
            if group.get("composite_kind") == "cohort":
                expected_event_type = "permitted_cohort_advance"
            elif group.get("composite"):
                expected_event_type = "permitted_packet_arm"
            else:
                expected_event_type = _EVENT_TYPE[group["stage"]]
            if event_type != expected_event_type:
                raise RoutingPersistenceError("routing binding ledger event type is invalid")
            if entry is None or _PHASE_RANK[entry["phase"]] < rank:
                raise RoutingPersistenceError("committed routing binding is absent from projection")
            if group.get("composite"):
                _require_authority_entry_identity(
                    entry,
                    group["authority"],
                    group["objects"]["routing_authority"],
                )
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
    _validate_cohort_exact_head_contracts(
        groups, records, event_by_sha, by_digest, task_id
    )
    return {
        "task_id": task_id,
        "namespace": namespace,
        "groups": sorted(groups, key=lambda row: (row["slot"], _PHASE_RANK[row["stage"]])),
        "routing_object_sha256s": sorted(routing_digests),
        "routing_binding_sha256s": sorted(binding_sha256s),
    }


def inspect_routing_persistence(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    task_id = h.validate_id(task_id, "task id")
    records, replayed = _freeze_event_chain(event_chain, task_id)
    report = objects.inspect_semantic_objects(paths, task_id, records)
    return _routing_report_from_generic(report, replayed, records)


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
    specialized = _routing_report_from_generic(generic, replayed, records)
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
    "prepare_authority_effect",
    "prepare_authority_batch_effect",
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
