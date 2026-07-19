"""Atomic semantic-v2 persistence for one-shot transition permits.

This module is the supported-API filesystem/runtime owner for permitted
lifecycle writes.  A permit is not a reusable Chief credential: a Chief-fenced
issuance publishes immutable decision, permit, and routing-authority records
plus one exact no-replace marker, and the controller may reserve only that
marker's exact event through a single semantic binding.

AOI's documented cooperative threat model still applies.  These checks do not
claim containment against arbitrary Python importing private publishers or a
hostile process rewriting the state directory; that stronger boundary would
require signatures or process/filesystem isolation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from itertools import islice
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from . import cohorts
from . import harnesslib as h
from . import permit_projection as permit_projection_contract
from . import routing_authority as authority
from . import routing_persistence as routing
from . import semantic_events as semantic
from . import semantic_objects as objects
from . import semantic_store as store
from . import transition_permits as permits


PERMIT_RUNTIME_SCHEMA_VERSION = permit_projection_contract.PERMIT_RUNTIME_SCHEMA_VERSION
PERMIT_TRANSACTION_SCHEMA_VERSION = 1
PERMIT_ISSUANCE_SCHEMA_VERSION = 1
COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION = 2
COHORT_PERMIT_ISSUANCE_SCHEMA_VERSION = 2
PERMIT_NAMESPACE_KEY = permit_projection_contract.PERMIT_NAMESPACE_KEY
PERMIT_ISSUANCE_DIRECTORY = "permit-issuances-v1"
COHORT_PERMIT_ISSUANCE_DIRECTORY = "permit-issuances-v2"
MAX_PERMIT_CONSUMPTIONS = permit_projection_contract.MAX_PERMIT_CONSUMPTIONS
MAX_PERMIT_NAMESPACE_BYTES = permit_projection_contract.MAX_PERMIT_NAMESPACE_BYTES
MAX_PERMIT_TRANSACTION_BYTES = 2 * 1024 * 1024
MAX_COHORT_PERMIT_TRANSACTION_BYTES = routing.MAX_ROUTING_TRANSACTION_BYTES
MAX_PERMIT_ISSUANCE_BYTES = 64 * 1024
MAX_COHORT_PERMIT_ISSUANCE_BYTES = 64 * 1024
MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES = 64 * 1024 * 1024
MAX_PERMIT_ISSUANCES = MAX_PERMIT_CONSUMPTIONS

_SHA256 = re.compile(r"[0-9a-f]{64}")
_EVENT_TYPE = "permitted_packet_arm"
_COHORT_EVENT_TYPE = "permitted_cohort_advance"
_CONSUMPTION_FIELDS = {
    "schema_version",
    "permit_sha256",
    "decision_sha256",
    "replay_marker",
    "action",
    "target_ids",
    "routing_slots",
    "cohort_state",
}
_NAMESPACE_FIELDS = {"schema_version", "consumptions", "replay_markers"}
_TRANSACTION_FIELDS = {
    "schema_version",
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
_OBJECT_FIELDS = {
    "schema_version",
    "object_type",
    "task_id",
    "object_identity",
    "payload",
    "payload_sha256",
    "object_sha256",
}
_BINDING_FIELDS = {
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
_ISSUER_FIELDS = {"session_id", "epoch", "authority_record_sha256"}
_ISSUANCE_FIELDS = {
    "schema_version",
    "marker_type",
    "task_id",
    "permit_sha256",
    "decision_sha256",
    "expected_semantic_head_sha256",
    "action",
    "target_ids",
    "parameters_sha256",
    "routing_authority_sha256",
    "object_sha256s",
    "consumption_identity",
    "replay_marker",
    "planned_event_sha256",
    "binding_sha256",
    "transaction_sha256",
    "issuer_chief_authority",
    "issued_at",
    "issuance_sha256",
}
_COHORT_ISSUANCE_FIELDS = {
    "schema_version",
    "marker_type",
    "task_id",
    "permit_sha256",
    "decision_sha256",
    "expected_semantic_head_sha256",
    "action",
    "target_ids",
    "parameters_sha256",
    "technical_payload_sha256",
    "cohort_sha256",
    "wave_index",
    "selection_sha256",
    "routes",
    "routing_authority_sha256s",
    "object_sha256s",
    "consumption_identity",
    "replay_marker",
    "planned_event_sha256",
    "result_projection_sha256",
    "binding_sha256",
    "transaction_sha256",
    "issuer_chief_authority",
    "issued_at",
    "issuance_sha256",
}
_COHORT_ROUTE_FIELDS = {
    "packet_id",
    "routing_authority_sha256",
    "outcome_slot_sha256",
}


class PermitRuntimeError(h.HarnessError):
    """A permit transaction or its persisted semantic projection is unsafe."""


def _fail(message: str, exc: BaseException | None = None) -> PermitRuntimeError:
    return PermitRuntimeError(message if exc is None else f"{message}: {exc}")


def _clone(value: Any, *, maximum: int = semantic.MAX_CANONICAL_JSON_BYTES) -> Any:
    try:
        return json.loads(
            semantic.canonical_json_bytes(value, max_bytes=maximum).decode("utf-8")
        )
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("permit runtime value is not bounded canonical JSON", exc) from exc


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise PermitRuntimeError(f"{label} is not lowercase SHA-256")
    return value


def _exact_version(value: Any, expected: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise PermitRuntimeError(f"{label} is invalid")
    return expected


def _instant(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise PermitRuntimeError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise _fail(f"{label} is invalid", exc) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermitRuntimeError(f"{label} needs a timezone")
    return parsed


def _issuance_time(value: Any) -> datetime:
    parsed = _instant(value, "permit issuance time")
    canonical = parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if value != canonical:
        raise PermitRuntimeError(
            "permit issuance time must be canonical UTC with microseconds"
        )
    return parsed


def _validate_arm_consumption_window(
    arm: Mapping[str, Any], current_time: datetime
) -> None:
    if (
        not isinstance(current_time, datetime)
        or current_time.tzinfo is None
        or current_time.utcoffset() is None
    ):
        raise PermitRuntimeError("permit commit time must be timezone-aware")
    attempt = arm["attempt_identity"]
    if not (
        _instant(attempt["armed_at"], "routing arm start")
        <= current_time
        <= _instant(attempt["expires_at"], "routing arm expiry")
    ):
        raise PermitRuntimeError("routing arm is not live at permit consumption")


def _validate_delta_scope(payload: Mapping[str, Any]) -> None:
    delta = payload.get("delta") if isinstance(payload, dict) else None
    operations = delta.get("operations") if isinstance(delta, dict) else None
    if not isinstance(operations, list) or not operations:
        raise PermitRuntimeError("permit transaction delta is invalid")
    allowed = {routing.ROUTING_NAMESPACE_KEY, PERMIT_NAMESPACE_KEY}
    roots: set[str] = set()
    for operation in operations:
        path = operation.get("path") if isinstance(operation, dict) else None
        if (
            not isinstance(path, list)
            or not path
            or not isinstance(path[0], str)
            or path[0] not in allowed
        ):
            raise PermitRuntimeError("permit transaction delta exceeds its namespaces")
        roots.add(path[0])
    if roots != allowed:
        raise PermitRuntimeError("permit transaction delta omits a required namespace")


def _require_bounded_json(value: Any, maximum: int, label: str) -> None:
    try:
        semantic.canonical_json_bytes(value, max_bytes=maximum)
    except semantic.SemanticEventError as exc:
        raise _fail(f"{label} exceeds its canonical JSON bound", exc) from exc


def _bounded_records(values: Iterable[Any], maximum: int, label: str) -> list[Any]:
    if isinstance(values, (str, bytes, Mapping)):
        raise PermitRuntimeError(f"{label} must be an iterable of records")
    try:
        rows = list(islice(iter(values), maximum + 1))
    except TypeError as exc:
        raise _fail(f"{label} is not iterable", exc) from exc
    if not rows or len(rows) > maximum:
        raise PermitRuntimeError(f"{label} is empty or exceeds its count bound")
    return rows


def _freeze_event_chain(
    event_chain: Iterable[Mapping[str, Any]], task_id: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = _bounded_records(event_chain, semantic.MAX_LEDGER_EVENTS, "semantic event chain")
    try:
        replayed = semantic.replay_events(rows)
    except (semantic.SemanticEventError, TypeError, ValueError) as exc:
        raise _fail("permit semantic event chain is invalid", exc) from exc
    domain = semantic.projection_domain(replayed)
    if domain.get("task_id") != task_id:
        raise PermitRuntimeError("permit semantic event chain belongs to another task")
    return [
        _clone(row, maximum=semantic.MAX_EVENT_BYTES)
        for row in rows
    ], replayed


def _prefix_for_head(
    records: list[dict[str, Any]], expected_head_sha256: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    expected = _sha(expected_head_sha256, "permit expected semantic head")
    matches = [index for index, event in enumerate(records) if event["event_sha256"] == expected]
    if len(matches) != 1:
        raise PermitRuntimeError("permit expected semantic head is absent or non-unique")
    prefix = records[: matches[0] + 1]
    try:
        replayed = semantic.replay_events(prefix)
    except semantic.SemanticEventError as exc:
        raise _fail("permit semantic prefix replay failed", exc) from exc
    return prefix, replayed


def validate_permit_consumption(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one compact, digest-only consumed-permit projection row."""
    try:
        return permit_projection_contract.validate_permit_consumption(value)
    except (permit_projection_contract.PermitProjectionError, h.HarnessError) as exc:
        raise _fail("permit consumption projection is invalid", exc) from exc


def validate_permit_namespace(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the task-global consumption and replay-marker indexes."""
    try:
        if isinstance(value, Mapping):
            consumptions = value.get("consumptions")
            replay_markers = value.get("replay_markers")
            if (
                isinstance(consumptions, Mapping)
                and len(consumptions) > MAX_PERMIT_CONSUMPTIONS
            ) or (
                isinstance(replay_markers, Mapping)
                and len(replay_markers) > MAX_PERMIT_CONSUMPTIONS
            ):
                raise PermitRuntimeError(
                    "permit projection indexes are invalid or over bound"
                )
        checked = permit_projection_contract.validate_permit_namespace(value)
        _require_bounded_json(
            checked, MAX_PERMIT_NAMESPACE_BYTES, "permit projection namespace"
        )
        return checked
    except (permit_projection_contract.PermitProjectionError, h.HarnessError) as exc:
        raise _fail("permit projection namespace is invalid", exc) from exc


def permit_namespace_from_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return permit_projection_contract.permit_namespace_from_projection(projection)
    except (permit_projection_contract.PermitProjectionError, h.HarnessError) as exc:
        raise _fail("permit projection is invalid", exc) from exc


def _consumption_receipt(
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    routing_entry: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    try:
        entry = routing.validate_routing_entry(routing_entry)
        return permit_projection_contract.packet_consumption_receipt(
            decision, permit, entry["outcome_slot_sha256"]
        )
    except (
        permit_projection_contract.PermitProjectionError,
        permits.TransitionPermitError,
        routing.RoutingPersistenceError,
    ) as exc:
        raise _fail("packet permit consumption receipt is invalid", exc) from exc


def _advance_permit_projection(
    base: Mapping[str, Any], identity: str, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        return permit_projection_contract.advance_permit_projection(base, identity, receipt)
    except (permit_projection_contract.PermitProjectionError, h.HarnessError) as exc:
        raise _fail("cannot advance permit projection", exc) from exc


def _contract_objects(
    task_id: str,
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    routing_authority_object: Mapping[str, Any],
) -> list[dict[str, Any]]:
    checked_decision = permits.validate_transition_decision(decision)
    checked_permit = permits.validate_transition_permit(permit)
    route_object = objects.validate_semantic_object(routing_authority_object)
    rows = [
        objects.create_semantic_object(
            object_type="transition_decision",
            task_id=task_id,
            object_identity=checked_decision["decision_sha256"],
            payload=checked_decision,
        ),
        objects.create_semantic_object(
            object_type="transition_permit",
            task_id=task_id,
            object_identity=checked_permit["permit_sha256"],
            payload=checked_permit,
        ),
        route_object,
    ]
    return sorted(rows, key=lambda row: row["object_type"])


def _contract_group(
    wrapped_rows: Iterable[Mapping[str, Any]],
    task_id: str,
) -> dict[str, Any]:
    rows = _bounded_records(wrapped_rows, 3, "permit transaction objects")
    by_type: dict[str, dict[str, Any]] = {}
    for raw in rows:
        wrapped = objects.validate_semantic_object(raw)
        if wrapped["task_id"] != task_id or wrapped["object_type"] in by_type:
            raise PermitRuntimeError("permit transaction object group is invalid")
        by_type[wrapped["object_type"]] = wrapped
    if set(by_type) != {"transition_decision", "transition_permit", "routing_authority"}:
        raise PermitRuntimeError("permit transaction object types or cardinality are invalid")
    try:
        decision = permits.validate_transition_decision(
            by_type["transition_decision"]["payload"]
        )
        permit = permits.validate_transition_permit(by_type["transition_permit"]["payload"])
        pair = permits.validate_decision_permit_pair(decision, permit)
        arm = authority.validate_arm_authority(by_type["routing_authority"]["payload"])
        routing_authority_sha256 = authority.authority_sha256(arm)
    except (permits.TransitionPermitError, authority.RoutingAuthorityError) as exc:
        raise _fail("permit transaction contract objects are invalid", exc) from exc
    if (
        by_type["transition_decision"]["object_identity"] != decision["decision_sha256"]
        or by_type["transition_permit"]["object_identity"] != permit["permit_sha256"]
        or by_type["routing_authority"]["object_identity"] != routing_authority_sha256
        or decision["task_id"] != task_id
        or permit["task_id"] != task_id
        or arm["task_id"] != task_id
    ):
        raise PermitRuntimeError("permit transaction object identity cross-binding is invalid")
    packet_id = arm["packet_authority"]["packet_id"]
    arm_chief = arm["chief_authority"]
    if (
        pair["decision"]["action"] != "packet.arm"
        or pair["decision"]["target_ids"] != [packet_id]
        or pair["decision"]["parameters"]["packet_id"] != packet_id
        or permit["chief_authority"]
        != {"session_id": arm_chief["session_id"], "epoch": arm_chief["epoch"]}
        or pair["decision"]["parameters"]["routing_authority_sha256"]
        != routing_authority_sha256
        or pair["decision"]["technical_payload_sha256"] != routing_authority_sha256
        or _instant(permit["expires_at"], "permit expiry")
        > _instant(arm["attempt_identity"]["expires_at"], "routing arm expiry")
    ):
        raise PermitRuntimeError("permit decision does not bind this routing authority")
    return {
        "objects": by_type,
        "decision": decision,
        "permit": permit,
        "arm": arm,
        "routing_authority_sha256": routing_authority_sha256,
    }


def _cohort_contract_objects(
    task_id: str,
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    cohort_plan: Mapping[str, Any],
    routing_authority_objects: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    try:
        checked_decision = permits.validate_transition_decision(decision)
        checked_permit = permits.validate_transition_permit(permit)
        plan = cohorts.validate_cohort(cohort_plan)
    except (permits.TransitionPermitError, cohorts.CohortError) as exc:
        raise _fail("cohort permit contract is invalid", exc) from exc
    route_rows = _bounded_records(
        routing_authority_objects,
        cohorts.MAX_CONCURRENCY,
        "cohort permit routing-authority objects",
    )
    rows = [
        objects.create_semantic_object(
            object_type="transition_decision",
            task_id=task_id,
            object_identity=checked_decision["decision_sha256"],
            payload=checked_decision,
        ),
        objects.create_semantic_object(
            object_type="transition_permit",
            task_id=task_id,
            object_identity=checked_permit["permit_sha256"],
            payload=checked_permit,
        ),
        objects.create_semantic_object(
            object_type="cohort_plan",
            task_id=task_id,
            object_identity=plan["cohort_sha256"],
            payload=plan,
        ),
    ]
    for raw in route_rows:
        wrapped = objects.validate_semantic_object(raw)
        if wrapped["task_id"] != task_id or wrapped["object_type"] != "routing_authority":
            raise PermitRuntimeError(
                "cohort permit routing-authority object is invalid"
            )
        rows.append(wrapped)
    if len({row["object_sha256"] for row in rows}) != len(rows):
        raise PermitRuntimeError("cohort permit contract repeats an object")
    return sorted(
        rows,
        key=lambda row: (
            row["object_type"],
            row["object_identity"],
            row["object_sha256"],
        ),
    )


def _cohort_contract_group(
    wrapped_rows: Iterable[Mapping[str, Any]],
    binding_value: Mapping[str, Any],
    task_id: str,
) -> dict[str, Any]:
    rows = _bounded_records(
        wrapped_rows,
        cohorts.MAX_CONCURRENCY + 3,
        "cohort permit transaction objects",
    )
    if len(rows) < 4:
        raise PermitRuntimeError("cohort permit transaction object group is incomplete")
    by_digest: dict[str, dict[str, Any]] = {}
    for raw in rows:
        wrapped = objects.validate_semantic_object(raw)
        if wrapped["task_id"] != task_id or wrapped["object_sha256"] in by_digest:
            raise PermitRuntimeError("cohort permit transaction object group is invalid")
        by_digest[wrapped["object_sha256"]] = wrapped
    binding = objects.validate_semantic_binding(binding_value)
    if (
        binding["binding_kind"] != "cohort_advance"
        or binding["task_id"] != task_id
        or binding["object_sha256s"] != sorted(by_digest)
    ):
        raise PermitRuntimeError("cohort permit transaction binding refs are invalid")
    try:
        groups = routing._cohort_composite_groups(binding, by_digest, task_id)
    except routing.RoutingPersistenceError as exc:
        raise _fail("cohort permit routing composite is invalid", exc) from exc
    if not groups or len(groups) > cohorts.MAX_CONCURRENCY:
        raise PermitRuntimeError("cohort permit routing composite cardinality is invalid")
    first = groups[0]
    selection = first["selection"]
    if any(
        group["decision"] != first["decision"]
        or group["permit"] != first["permit"]
        or group["cohort_plan"] != first["cohort_plan"]
        or group["selection"] != selection
        for group in groups[1:]
    ):
        raise PermitRuntimeError("cohort permit routing composite is inconsistent")
    try:
        selection_sha256 = semantic.canonical_sha256(
            selection, max_bytes=cohorts.MAX_COHORT_BYTES
        )
    except semantic.SemanticEventError as exc:
        raise _fail("cohort permit selection cannot be hashed", exc) from exc
    if first["decision"]["technical_payload_sha256"] != selection_sha256:
        raise PermitRuntimeError(
            "cohort permit decision technical payload differs from its exact routes"
        )
    canonical_rows = sorted(
        by_digest.values(),
        key=lambda row: (
            row["object_type"],
            row["object_identity"],
            row["object_sha256"],
        ),
    )
    return {
        "objects": by_digest,
        "canonical_objects": canonical_rows,
        "groups": groups,
        "decision": first["decision"],
        "permit": first["permit"],
        "cohort_plan": first["cohort_plan"],
        "selection": {**selection, "selection_sha256": selection_sha256},
        "routing_authorities": [group["authority"] for group in groups],
        "routing_authority_objects": [
            group["objects"]["routing_authority"] for group in groups
        ],
        "routing_authority_sha256s": [
            authority.authority_sha256(group["authority"]) for group in groups
        ],
        "routing_slots": [group["slot"] for group in groups],
        "binding": binding,
    }


def _permit_issuance_base(
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
    *,
    authority_record_sha256: str,
    issued_at: str,
) -> dict[str, Any]:
    permit = group["permit"]
    decision = group["decision"]
    arm = group["arm"]
    _issuance_time(issued_at)
    return {
        "schema_version": PERMIT_ISSUANCE_SCHEMA_VERSION,
        "marker_type": "permit_issuance-v1",
        "task_id": transaction["task_id"],
        "permit_sha256": permit["permit_sha256"],
        "decision_sha256": decision["decision_sha256"],
        "expected_semantic_head_sha256": permit[
            "expected_semantic_head_sha256"
        ],
        "action": permit["action"],
        "target_ids": list(permit["target_ids"]),
        "parameters_sha256": semantic.canonical_sha256(permit["parameters"]),
        "routing_authority_sha256": group["routing_authority_sha256"],
        "object_sha256s": sorted(
            wrapped["object_sha256"] for wrapped in group["objects"].values()
        ),
        "consumption_identity": permits.permit_consumption_identity(permit),
        "replay_marker": permits.permit_replay_marker(permit),
        "planned_event_sha256": transaction["planned_event"]["event_sha256"],
        "binding_sha256": transaction["binding"]["binding_sha256"],
        "transaction_sha256": transaction["transaction_sha256"],
        "issuer_chief_authority": {
            "session_id": permit["chief_authority"]["session_id"],
            "epoch": permit["chief_authority"]["epoch"],
            "authority_record_sha256": _sha(
                authority_record_sha256, "Chief authority record SHA-256"
            ),
        },
        "issued_at": issued_at,
    }


def _create_permit_issuance(
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
    *,
    authority_record_sha256: str,
    issued_at: str,
) -> dict[str, Any]:
    base = _permit_issuance_base(
        transaction,
        group,
        authority_record_sha256=authority_record_sha256,
        issued_at=issued_at,
    )
    marker = {
        **base,
        "issuance_sha256": semantic.canonical_sha256(
            base, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
        ),
    }
    return validate_permit_issuance(marker)


def validate_permit_issuance(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one immutable Chief issuance marker."""

    if not isinstance(value, dict) or set(value) != _ISSUANCE_FIELDS:
        raise PermitRuntimeError("permit issuance marker schema is invalid")
    item = _clone(value, maximum=MAX_PERMIT_ISSUANCE_BYTES)
    _exact_version(
        item["schema_version"],
        PERMIT_ISSUANCE_SCHEMA_VERSION,
        "permit issuance marker version",
    )
    if item["marker_type"] != "permit_issuance-v1":
        raise PermitRuntimeError("permit issuance marker type is invalid")
    item["task_id"] = h.validate_id(item["task_id"], "permit issuance task id")
    for field, label in (
        ("permit_sha256", "permit issuance permit SHA-256"),
        ("decision_sha256", "permit issuance decision SHA-256"),
        (
            "expected_semantic_head_sha256",
            "permit issuance expected semantic head SHA-256",
        ),
        ("parameters_sha256", "permit issuance parameters SHA-256"),
        (
            "routing_authority_sha256",
            "permit issuance routing authority SHA-256",
        ),
        ("consumption_identity", "permit issuance consumption identity"),
        ("replay_marker", "permit issuance replay marker"),
        ("planned_event_sha256", "permit issuance planned event SHA-256"),
        ("binding_sha256", "permit issuance binding SHA-256"),
        ("transaction_sha256", "permit issuance transaction SHA-256"),
    ):
        item[field] = _sha(item[field], label)
    if item["action"] != "packet.arm":
        raise PermitRuntimeError("permit issuance action is invalid")
    if (
        not isinstance(item["target_ids"], list)
        or len(item["target_ids"]) != 1
    ):
        raise PermitRuntimeError("permit issuance target shape is invalid")
    item["target_ids"] = [
        h.validate_id(item["target_ids"][0], "permit issuance target id")
    ]
    references = item["object_sha256s"]
    if (
        not isinstance(references, list)
        or len(references) != 3
        or any(not isinstance(digest, str) for digest in references)
        or references != sorted(set(references))
    ):
        raise PermitRuntimeError("permit issuance object references are invalid")
    item["object_sha256s"] = [
        _sha(digest, "permit issuance object SHA-256") for digest in references
    ]
    issuer = item["issuer_chief_authority"]
    if not isinstance(issuer, dict) or set(issuer) != _ISSUER_FIELDS:
        raise PermitRuntimeError("permit issuance Chief authority schema is invalid")
    session_id = h.validate_id(issuer["session_id"], "permit issuance Chief session")
    epoch = issuer["epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise PermitRuntimeError("permit issuance Chief epoch is invalid")
    item["issuer_chief_authority"] = {
        "session_id": session_id,
        "epoch": epoch,
        "authority_record_sha256": _sha(
            issuer["authority_record_sha256"],
            "permit issuance Chief authority record SHA-256",
        ),
    }
    _issuance_time(item["issued_at"])
    preimage = {
        key: item[key] for key in _ISSUANCE_FIELDS if key != "issuance_sha256"
    }
    expected = semantic.canonical_sha256(
        preimage, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
    )
    if item["issuance_sha256"] != expected:
        raise PermitRuntimeError("permit issuance marker SHA-256 is invalid")
    _require_bounded_json(item, MAX_PERMIT_ISSUANCE_BYTES, "permit issuance marker")
    return item


def _validate_issuance_group(
    marker: Mapping[str, Any],
    task_id: str,
    group: Mapping[str, Any],
) -> dict[str, Any]:
    checked = validate_permit_issuance(marker)
    permit = group["permit"]
    decision = group["decision"]
    arm = group["arm"]
    expected = {
        "task_id": task_id,
        "permit_sha256": permit["permit_sha256"],
        "decision_sha256": decision["decision_sha256"],
        "expected_semantic_head_sha256": permit[
            "expected_semantic_head_sha256"
        ],
        "action": permit["action"],
        "target_ids": permit["target_ids"],
        "parameters_sha256": semantic.canonical_sha256(permit["parameters"]),
        "routing_authority_sha256": group["routing_authority_sha256"],
        "object_sha256s": sorted(
            wrapped["object_sha256"] for wrapped in group["objects"].values()
        ),
        "consumption_identity": permits.permit_consumption_identity(permit),
        "replay_marker": permits.permit_replay_marker(permit),
        "issuer_chief_authority": {
            "session_id": permit["chief_authority"]["session_id"],
            "epoch": permit["chief_authority"]["epoch"],
            "authority_record_sha256": arm["chief_authority"][
                "authority_sha256"
            ],
        },
    }
    if any(checked[key] != value for key, value in expected.items()):
        raise PermitRuntimeError(
            "permit issuance marker does not bind the exact transaction contract"
        )
    issued_at = _issuance_time(checked["issued_at"])
    if not (
        _instant(arm["attempt_identity"]["armed_at"], "routing arm start")
        <= issued_at
        <= _instant(arm["attempt_identity"]["expires_at"], "routing arm expiry")
        and issued_at <= _instant(permit["expires_at"], "permit expiry")
    ):
        raise PermitRuntimeError("permit issuance marker lies outside its authority window")
    return checked


def _validate_issuance_contract(
    marker: Mapping[str, Any],
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
) -> dict[str, Any]:
    checked = _validate_issuance_group(marker, transaction["task_id"], group)
    if (
        checked["planned_event_sha256"]
        != transaction["planned_event"]["event_sha256"]
        or checked["binding_sha256"] != transaction["binding"]["binding_sha256"]
        or checked["transaction_sha256"] != transaction["transaction_sha256"]
    ):
        raise PermitRuntimeError(
            "permit issuance marker does not bind the exact transaction contract"
        )
    return checked


def _cohort_permit_issuance_base(
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
    *,
    authority_record_sha256: str,
    issued_at: str,
) -> dict[str, Any]:
    permit = group["permit"]
    decision = group["decision"]
    selection = group["selection"]
    _issuance_time(issued_at)
    return {
        "schema_version": COHORT_PERMIT_ISSUANCE_SCHEMA_VERSION,
        "marker_type": "permit_issuance-v2",
        "task_id": transaction["task_id"],
        "permit_sha256": permit["permit_sha256"],
        "decision_sha256": decision["decision_sha256"],
        "expected_semantic_head_sha256": permit[
            "expected_semantic_head_sha256"
        ],
        "action": permit["action"],
        "target_ids": list(permit["target_ids"]),
        "parameters_sha256": semantic.canonical_sha256(permit["parameters"]),
        "technical_payload_sha256": decision["technical_payload_sha256"],
        "cohort_sha256": group["cohort_plan"]["cohort_sha256"],
        "wave_index": selection["wave_index"],
        "selection_sha256": selection["selection_sha256"],
        "routes": _clone(
            selection["routes"], maximum=cohorts.MAX_COHORT_BYTES
        ),
        "routing_authority_sha256s": list(
            group["routing_authority_sha256s"]
        ),
        "object_sha256s": sorted(group["objects"]),
        "consumption_identity": permits.permit_consumption_identity(permit),
        "replay_marker": permits.permit_replay_marker(permit),
        "planned_event_sha256": transaction["planned_event"]["event_sha256"],
        "result_projection_sha256": transaction["planned_event"][
            "result_projection_sha256"
        ],
        "binding_sha256": transaction["binding"]["binding_sha256"],
        "transaction_sha256": transaction["transaction_sha256"],
        "issuer_chief_authority": {
            "session_id": permit["chief_authority"]["session_id"],
            "epoch": permit["chief_authority"]["epoch"],
            "authority_record_sha256": _sha(
                authority_record_sha256, "Chief authority record SHA-256"
            ),
        },
        "issued_at": issued_at,
    }


def _create_cohort_permit_issuance(
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
    *,
    authority_record_sha256: str,
    issued_at: str,
) -> dict[str, Any]:
    base = _cohort_permit_issuance_base(
        transaction,
        group,
        authority_record_sha256=authority_record_sha256,
        issued_at=issued_at,
    )
    marker = {
        **base,
        "issuance_sha256": semantic.canonical_sha256(
            base, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
        ),
    }
    return validate_cohort_permit_issuance(marker)


def validate_cohort_permit_issuance(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one immutable schema-v2 cohort permit issuance marker."""

    if not isinstance(value, dict) or set(value) != _COHORT_ISSUANCE_FIELDS:
        raise PermitRuntimeError("cohort permit issuance marker schema is invalid")
    item = _clone(value, maximum=MAX_COHORT_PERMIT_ISSUANCE_BYTES)
    _exact_version(
        item["schema_version"],
        COHORT_PERMIT_ISSUANCE_SCHEMA_VERSION,
        "cohort permit issuance marker version",
    )
    if item["marker_type"] != "permit_issuance-v2":
        raise PermitRuntimeError("cohort permit issuance marker type is invalid")
    item["task_id"] = h.validate_id(
        item["task_id"], "cohort permit issuance task id"
    )
    for field, label in (
        ("permit_sha256", "cohort permit issuance permit SHA-256"),
        ("decision_sha256", "cohort permit issuance decision SHA-256"),
        (
            "expected_semantic_head_sha256",
            "cohort permit issuance expected semantic head SHA-256",
        ),
        ("parameters_sha256", "cohort permit issuance parameters SHA-256"),
        (
            "technical_payload_sha256",
            "cohort permit issuance technical payload SHA-256",
        ),
        ("cohort_sha256", "cohort permit issuance cohort SHA-256"),
        ("selection_sha256", "cohort permit issuance selection SHA-256"),
        ("consumption_identity", "cohort permit issuance consumption identity"),
        ("replay_marker", "cohort permit issuance replay marker"),
        ("planned_event_sha256", "cohort permit issuance planned event SHA-256"),
        (
            "result_projection_sha256",
            "cohort permit issuance result projection SHA-256",
        ),
        ("binding_sha256", "cohort permit issuance binding SHA-256"),
        ("transaction_sha256", "cohort permit issuance transaction SHA-256"),
    ):
        item[field] = _sha(item[field], label)
    if item["action"] != "cohort.advance":
        raise PermitRuntimeError("cohort permit issuance action is invalid")
    if not isinstance(item["target_ids"], list) or len(item["target_ids"]) != 1:
        raise PermitRuntimeError("cohort permit issuance target shape is invalid")
    item["target_ids"] = [
        h.validate_id(item["target_ids"][0], "cohort permit issuance target id")
    ]
    wave_index = item["wave_index"]
    if (
        not isinstance(wave_index, int)
        or isinstance(wave_index, bool)
        or not 0 <= wave_index <= 1_000_000
    ):
        raise PermitRuntimeError("cohort permit issuance wave index is invalid")
    routes = item["routes"]
    if (
        not isinstance(routes, list)
        or not 1 <= len(routes) <= cohorts.MAX_CONCURRENCY
    ):
        raise PermitRuntimeError("cohort permit issuance routes are invalid")
    checked_routes: list[dict[str, Any]] = []
    seen_packets: set[str] = set()
    seen_slots: set[str] = set()
    for raw in routes:
        if not isinstance(raw, dict) or set(raw) != _COHORT_ROUTE_FIELDS:
            raise PermitRuntimeError("cohort permit issuance route schema is invalid")
        route = {
            "packet_id": h.validate_id(
                raw["packet_id"], "cohort permit issuance route packet id"
            ),
            "routing_authority_sha256": _sha(
                raw["routing_authority_sha256"],
                "cohort permit issuance route authority SHA-256",
            ),
            "outcome_slot_sha256": _sha(
                raw["outcome_slot_sha256"],
                "cohort permit issuance route slot SHA-256",
            ),
        }
        if (
            route["packet_id"] in seen_packets
            or route["outcome_slot_sha256"] in seen_slots
        ):
            raise PermitRuntimeError(
                "cohort permit issuance routes repeat a packet or slot"
            )
        seen_packets.add(route["packet_id"])
        seen_slots.add(route["outcome_slot_sha256"])
        checked_routes.append(route)
    item["routes"] = checked_routes
    authority_sha256s = item["routing_authority_sha256s"]
    if (
        not isinstance(authority_sha256s, list)
        or authority_sha256s
        != [route["routing_authority_sha256"] for route in checked_routes]
    ):
        raise PermitRuntimeError(
            "cohort permit issuance routing-authority order is invalid"
        )
    item["routing_authority_sha256s"] = [
        _sha(digest, "cohort permit issuance routing authority SHA-256")
        for digest in authority_sha256s
    ]
    expected_selection_sha256 = semantic.canonical_sha256(
        {
            "schema_version": cohorts.COHORT_ADVANCE_SELECTION_SCHEMA_VERSION,
            "cohort_sha256": item["cohort_sha256"],
            "wave_index": wave_index,
            "routes": checked_routes,
        },
        max_bytes=cohorts.MAX_COHORT_BYTES,
    )
    if (
        item["selection_sha256"] != expected_selection_sha256
        or item["technical_payload_sha256"] != expected_selection_sha256
    ):
        raise PermitRuntimeError(
            "cohort permit issuance selection identity is invalid"
        )
    references = item["object_sha256s"]
    if (
        not isinstance(references, list)
        or not 4 <= len(references) <= cohorts.MAX_CONCURRENCY + 3
        or references != sorted(set(references))
    ):
        raise PermitRuntimeError(
            "cohort permit issuance object references are invalid"
        )
    item["object_sha256s"] = [
        _sha(digest, "cohort permit issuance object SHA-256")
        for digest in references
    ]
    issuer = item["issuer_chief_authority"]
    if not isinstance(issuer, dict) or set(issuer) != _ISSUER_FIELDS:
        raise PermitRuntimeError(
            "cohort permit issuance Chief authority schema is invalid"
        )
    epoch = issuer["epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise PermitRuntimeError(
            "cohort permit issuance Chief epoch is invalid"
        )
    item["issuer_chief_authority"] = {
        "session_id": h.validate_id(
            issuer["session_id"], "cohort permit issuance Chief session"
        ),
        "epoch": epoch,
        "authority_record_sha256": _sha(
            issuer["authority_record_sha256"],
            "cohort permit issuance Chief authority record SHA-256",
        ),
    }
    _issuance_time(item["issued_at"])
    preimage = {
        key: item[key]
        for key in _COHORT_ISSUANCE_FIELDS
        if key != "issuance_sha256"
    }
    expected = semantic.canonical_sha256(
        preimage, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
    )
    if item["issuance_sha256"] != expected:
        raise PermitRuntimeError("cohort permit issuance marker SHA-256 is invalid")
    _require_bounded_json(
        item,
        MAX_COHORT_PERMIT_ISSUANCE_BYTES,
        "cohort permit issuance marker",
    )
    return item


def _validate_cohort_issuance_group(
    marker: Mapping[str, Any],
    task_id: str,
    group: Mapping[str, Any],
) -> dict[str, Any]:
    checked = validate_cohort_permit_issuance(marker)
    permit = group["permit"]
    decision = group["decision"]
    selection = group["selection"]
    authority_record_sha256s = {
        arm["chief_authority"]["authority_sha256"]
        for arm in group["routing_authorities"]
    }
    if len(authority_record_sha256s) != 1:
        raise PermitRuntimeError(
            "cohort routing authorities do not share one Chief record"
        )
    expected = {
        "task_id": task_id,
        "permit_sha256": permit["permit_sha256"],
        "decision_sha256": decision["decision_sha256"],
        "expected_semantic_head_sha256": permit[
            "expected_semantic_head_sha256"
        ],
        "action": "cohort.advance",
        "target_ids": permit["target_ids"],
        "parameters_sha256": semantic.canonical_sha256(permit["parameters"]),
        "technical_payload_sha256": decision["technical_payload_sha256"],
        "cohort_sha256": group["cohort_plan"]["cohort_sha256"],
        "wave_index": selection["wave_index"],
        "selection_sha256": selection["selection_sha256"],
        "routes": selection["routes"],
        "routing_authority_sha256s": group["routing_authority_sha256s"],
        "object_sha256s": sorted(group["objects"]),
        "result_projection_sha256": group["binding"][
            "result_projection_sha256"
        ],
        "consumption_identity": permits.permit_consumption_identity(permit),
        "replay_marker": permits.permit_replay_marker(permit),
        "issuer_chief_authority": {
            "session_id": permit["chief_authority"]["session_id"],
            "epoch": permit["chief_authority"]["epoch"],
            "authority_record_sha256": next(iter(authority_record_sha256s)),
        },
    }
    if any(checked[key] != value for key, value in expected.items()):
        raise PermitRuntimeError(
            "cohort permit issuance marker does not bind the exact contract"
        )
    issued_at = _issuance_time(checked["issued_at"])
    if issued_at > _instant(permit["expires_at"], "cohort permit expiry"):
        raise PermitRuntimeError(
            "cohort permit issuance marker lies outside its permit window"
        )
    for arm in group["routing_authorities"]:
        if not (
            _instant(arm["attempt_identity"]["armed_at"], "routing arm start")
            <= issued_at
            <= _instant(arm["attempt_identity"]["expires_at"], "routing arm expiry")
        ):
            raise PermitRuntimeError(
                "cohort permit issuance marker lies outside a routing authority window"
            )
    return checked


def _validate_cohort_issuance_contract(
    marker: Mapping[str, Any],
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
) -> dict[str, Any]:
    checked = _validate_cohort_issuance_group(
        marker, transaction["task_id"], group
    )
    if (
        checked["planned_event_sha256"]
        != transaction["planned_event"]["event_sha256"]
        or checked["binding_sha256"]
        != transaction["binding"]["binding_sha256"]
        or checked["transaction_sha256"] != transaction["transaction_sha256"]
    ):
        raise PermitRuntimeError(
            "cohort permit issuance marker does not bind the exact transaction"
        )
    return checked


def _issuance_task_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    try:
        task = h.task_dir(paths, h.validate_id(task_id, "permit issuance task id"))
        canonical = h.canonicalize_no_link_traversal(
            task, "permit issuance task directory"
        )
        if canonical != task or not canonical.exists():
            raise PermitRuntimeError(
                "permit issuance task directory is missing or non-canonical"
            )
        h.validate_existing_regular_directory(
            canonical, "permit issuance task directory"
        )
        return canonical
    except PermitRuntimeError:
        raise
    except h.HarnessError as exc:
        raise _fail("invalid permit issuance task directory", exc) from exc


def _validate_private_directory(path: Path, label: str) -> Path:
    try:
        canonical = h.canonicalize_no_link_traversal(path, label)
        if canonical != path:
            raise PermitRuntimeError(f"{label} is non-canonical")
        metadata = canonical.lstat()
        if h._path_is_link_like(canonical) or not stat.S_ISDIR(metadata.st_mode):
            raise PermitRuntimeError(f"{label} must be a non-linked directory")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermitRuntimeError(f"{label} is not private")
        if h.canonicalize_no_link_traversal(canonical, label) != canonical:
            raise PermitRuntimeError(f"{label} changed while being checked")
        return canonical
    except FileNotFoundError as exc:
        raise _fail(f"{label} is missing", exc) from exc
    except PermitRuntimeError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _fail(f"invalid {label}", exc) from exc


def _issuance_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    return _issuance_task_directory(paths, task_id) / PERMIT_ISSUANCE_DIRECTORY


def _ensure_issuance_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    task = _issuance_task_directory(paths, task_id)
    directory = task / PERMIT_ISSUANCE_DIRECTORY
    if not directory.exists() and not h._path_is_link_like(directory):
        try:
            directory.mkdir(mode=0o700)
            if os.name != "nt":
                directory.chmod(0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise _fail("cannot create permit issuance directory", exc) from exc
    if h.canonicalize_no_link_traversal(
        task, "permit issuance task directory"
    ) != task:
        raise PermitRuntimeError(
            "permit issuance task directory changed during store creation"
        )
    return _validate_private_directory(directory, "permit issuance directory")


def _cohort_issuance_directory(paths: h.HarnessPaths, task_id: str) -> Path:
    return (
        _issuance_task_directory(paths, task_id)
        / COHORT_PERMIT_ISSUANCE_DIRECTORY
    )


def _ensure_cohort_issuance_directory(
    paths: h.HarnessPaths, task_id: str
) -> Path:
    task = _issuance_task_directory(paths, task_id)
    directory = task / COHORT_PERMIT_ISSUANCE_DIRECTORY
    if not directory.exists() and not h._path_is_link_like(directory):
        try:
            directory.mkdir(mode=0o700)
            if os.name != "nt":
                directory.chmod(0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise _fail("cannot create cohort permit issuance directory", exc) from exc
    if h.canonicalize_no_link_traversal(
        task, "permit issuance task directory"
    ) != task:
        raise PermitRuntimeError(
            "permit issuance task directory changed during store creation"
        )
    return _validate_private_directory(
        directory, "cohort permit issuance directory"
    )


def permit_issuance_path(
    paths: h.HarnessPaths, task_id: str, permit_sha256: str
) -> Path:
    """Return the sole canonical marker slot for one permit digest."""

    digest = _sha(permit_sha256, "permit issuance path permit SHA-256")
    return h.task_dir(paths, h.validate_id(task_id, "permit issuance task id")) / (
        PERMIT_ISSUANCE_DIRECTORY
    ) / f"{digest}.json"


def cohort_permit_issuance_path(
    paths: h.HarnessPaths, task_id: str, permit_sha256: str
) -> Path:
    """Return the canonical schema-v2 marker slot for one cohort permit."""

    digest = _sha(permit_sha256, "cohort permit issuance path permit SHA-256")
    return h.task_dir(
        paths, h.validate_id(task_id, "cohort permit issuance task id")
    ) / COHORT_PERMIT_ISSUANCE_DIRECTORY / f"{digest}.json"


def _read_permit_issuance(path: Path, task_id: str) -> dict[str, Any]:
    try:
        if h.canonicalize_no_link_traversal(path, "permit issuance marker") != path:
            raise PermitRuntimeError("permit issuance marker path is non-canonical")
        h.validate_existing_regular_file(path, "permit issuance marker")
        before = path.lstat()
        if (
            h._path_is_link_like(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise PermitRuntimeError(
                "permit issuance marker must be one regular non-linked file"
            )
        if os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077:
            raise PermitRuntimeError("permit issuance marker is not private")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise PermitRuntimeError(
                    "permit issuance marker changed while being opened"
                )
            raw = handle.read(MAX_PERMIT_ISSUANCE_BYTES + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise _fail("permit issuance marker is missing", exc) from exc
    except PermitRuntimeError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _fail("cannot read permit issuance marker", exc) from exc
    if len(raw) > MAX_PERMIT_ISSUANCE_BYTES:
        raise PermitRuntimeError("permit issuance marker exceeds byte bound")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity
        != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(raw) != finished.st_size
        or (os.name != "nt" and stat.S_IMODE(after.st_mode) & 0o077)
        or h.canonicalize_no_link_traversal(path, "permit issuance marker") != path
    ):
        raise PermitRuntimeError("permit issuance marker changed while being read")
    try:
        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise PermitRuntimeError(
                        f"permit issuance marker has duplicate JSON key {key!r}"
                    )
                result[key] = item
            return result

        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        marker = validate_permit_issuance(decoded)
        canonical = semantic.canonical_json_bytes(
            marker, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
        )
    except PermitRuntimeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, semantic.SemanticEventError) as exc:
        raise _fail("permit issuance marker JSON is invalid", exc) from exc
    if raw != canonical:
        raise PermitRuntimeError("permit issuance marker bytes are not canonical JSON")
    if marker["task_id"] != task_id:
        raise PermitRuntimeError("permit issuance marker task identity is invalid")
    if path.name != f"{marker['permit_sha256']}.json":
        raise PermitRuntimeError("permit issuance marker filename is invalid")
    return marker


def _read_cohort_permit_issuance(
    path: Path, task_id: str
) -> dict[str, Any]:
    try:
        if h.canonicalize_no_link_traversal(
            path, "cohort permit issuance marker"
        ) != path:
            raise PermitRuntimeError(
                "cohort permit issuance marker path is non-canonical"
            )
        h.validate_existing_regular_file(path, "cohort permit issuance marker")
        before = path.lstat()
        if (
            h._path_is_link_like(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise PermitRuntimeError(
                "cohort permit issuance marker must be one regular non-linked file"
            )
        if os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077:
            raise PermitRuntimeError("cohort permit issuance marker is not private")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise PermitRuntimeError(
                    "cohort permit issuance marker changed while being opened"
                )
            raw = handle.read(MAX_COHORT_PERMIT_ISSUANCE_BYTES + 1)
            finished = os.fstat(handle.fileno())
        after = path.lstat()
    except FileNotFoundError as exc:
        raise _fail("cohort permit issuance marker is missing", exc) from exc
    except PermitRuntimeError:
        raise
    except (h.HarnessError, OSError) as exc:
        raise _fail("cannot read cohort permit issuance marker", exc) from exc
    if len(raw) > MAX_COHORT_PERMIT_ISSUANCE_BYTES:
        raise PermitRuntimeError("cohort permit issuance marker exceeds byte bound")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity
        != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or opened.st_nlink != 1
        or finished.st_nlink != 1
        or after.st_nlink != 1
        or len(raw) != finished.st_size
        or (os.name != "nt" and stat.S_IMODE(after.st_mode) & 0o077)
        or h.canonicalize_no_link_traversal(
            path, "cohort permit issuance marker"
        )
        != path
    ):
        raise PermitRuntimeError(
            "cohort permit issuance marker changed while being read"
        )
    try:
        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise PermitRuntimeError(
                        f"cohort permit issuance marker has duplicate JSON key {key!r}"
                    )
                result[key] = item
            return result

        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        marker = validate_cohort_permit_issuance(decoded)
        canonical = semantic.canonical_json_bytes(
            marker, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
        )
    except PermitRuntimeError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        semantic.SemanticEventError,
    ) as exc:
        raise _fail("cohort permit issuance marker JSON is invalid", exc) from exc
    if raw != canonical:
        raise PermitRuntimeError(
            "cohort permit issuance marker bytes are not canonical JSON"
        )
    if marker["task_id"] != task_id:
        raise PermitRuntimeError(
            "cohort permit issuance marker task identity is invalid"
        )
    if path.name != f"{marker['permit_sha256']}.json":
        raise PermitRuntimeError(
            "cohort permit issuance marker filename is invalid"
        )
    return marker


def _scan_permit_issuances(
    paths: h.HarnessPaths, task_id: str
) -> tuple[list[dict[str, Any]], int]:
    directory = _issuance_directory(paths, task_id)
    if not directory.exists() and not h._path_is_link_like(directory):
        return [], 0
    directory = _validate_private_directory(directory, "permit issuance directory")
    rows: list[dict[str, Any]] = []
    aggregate = 0
    seen: set[str] = set()
    unique_fields: dict[str, set[str]] = {
        "consumption_identity": set(),
        "replay_marker": set(),
        "binding_sha256": set(),
        "planned_event_sha256": set(),
        "transaction_sha256": set(),
        "issuance_sha256": set(),
    }
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if (
                    path.parent != directory
                    or not re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
                ):
                    raise PermitRuntimeError(
                        "permit issuance directory has an unexpected entry"
                    )
                if len(rows) >= MAX_PERMIT_ISSUANCES:
                    raise PermitRuntimeError(
                        "permit issuance store exceeds marker count bound"
                    )
                marker = _read_permit_issuance(path, task_id)
                digest = marker["permit_sha256"]
                if digest in seen:
                    raise PermitRuntimeError(
                        "permit issuance store has duplicate permit identity"
                    )
                seen.add(digest)
                for field, values in unique_fields.items():
                    if marker[field] in values:
                        raise PermitRuntimeError(
                            f"permit issuance store has duplicate {field}"
                        )
                    values.add(marker[field])
                aggregate += len(
                    semantic.canonical_json_bytes(
                        marker, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
                    )
                )
                if aggregate > MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES:
                    raise PermitRuntimeError(
                        "permit issuance store exceeds aggregate byte bound"
                    )
                rows.append(marker)
    except PermitRuntimeError:
        raise
    except OSError as exc:
        raise _fail("cannot enumerate permit issuance store", exc) from exc
    rows.sort(key=lambda marker: marker["permit_sha256"])
    return rows, aggregate


def _scan_cohort_permit_issuances(
    paths: h.HarnessPaths, task_id: str
) -> tuple[list[dict[str, Any]], int]:
    directory = _cohort_issuance_directory(paths, task_id)
    if not directory.exists() and not h._path_is_link_like(directory):
        return [], 0
    directory = _validate_private_directory(
        directory, "cohort permit issuance directory"
    )
    rows: list[dict[str, Any]] = []
    aggregate = 0
    seen: set[str] = set()
    unique_fields: dict[str, set[str]] = {
        "consumption_identity": set(),
        "replay_marker": set(),
        "binding_sha256": set(),
        "planned_event_sha256": set(),
        "transaction_sha256": set(),
        "issuance_sha256": set(),
    }
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if (
                    path.parent != directory
                    or not re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
                ):
                    raise PermitRuntimeError(
                        "cohort permit issuance directory has an unexpected entry"
                    )
                if len(rows) >= MAX_PERMIT_ISSUANCES:
                    raise PermitRuntimeError(
                        "cohort permit issuance store exceeds marker count bound"
                    )
                marker = _read_cohort_permit_issuance(path, task_id)
                digest = marker["permit_sha256"]
                if digest in seen:
                    raise PermitRuntimeError(
                        "cohort permit issuance store has duplicate permit identity"
                    )
                seen.add(digest)
                for field, values in unique_fields.items():
                    if marker[field] in values:
                        raise PermitRuntimeError(
                            f"cohort permit issuance store has duplicate {field}"
                        )
                    values.add(marker[field])
                aggregate += len(
                    semantic.canonical_json_bytes(
                        marker, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
                    )
                )
                if aggregate > MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES:
                    raise PermitRuntimeError(
                        "cohort permit issuance store exceeds aggregate byte bound"
                    )
                rows.append(marker)
    except PermitRuntimeError:
        raise
    except OSError as exc:
        raise _fail("cannot enumerate cohort permit issuance store", exc) from exc
    rows.sort(key=lambda marker: marker["permit_sha256"])
    return rows, aggregate


def _scan_all_permit_issuances(
    paths: h.HarnessPaths, task_id: str
) -> tuple[list[dict[str, Any]], int]:
    v1_rows, v1_bytes = _scan_permit_issuances(paths, task_id)
    v2_rows, v2_bytes = _scan_cohort_permit_issuances(paths, task_id)
    rows = [*v1_rows, *v2_rows]
    aggregate = v1_bytes + v2_bytes
    if len(rows) > MAX_PERMIT_ISSUANCES:
        raise PermitRuntimeError(
            "permit issuance stores exceed the global marker count bound"
        )
    if aggregate > MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES:
        raise PermitRuntimeError(
            "permit issuance stores exceed the global aggregate byte bound"
        )
    unique_fields = (
        "permit_sha256",
        "consumption_identity",
        "replay_marker",
        "binding_sha256",
        "planned_event_sha256",
        "transaction_sha256",
        "issuance_sha256",
    )
    for field in unique_fields:
        values = [marker[field] for marker in rows]
        if len(values) != len(set(values)):
            raise PermitRuntimeError(
                f"permit issuance stores have duplicate {field} across schema versions"
            )
    return sorted(
        rows,
        key=lambda marker: (
            marker["permit_sha256"],
            marker["schema_version"],
        ),
    ), aggregate


def _publish_permit_issuance(
    paths: h.HarnessPaths, marker: Mapping[str, Any]
) -> dict[str, Any]:
    h._require_chief_lock(paths)
    checked = validate_permit_issuance(marker)
    directory = _ensure_issuance_directory(paths, checked["task_id"])
    rows, aggregate = _scan_all_permit_issuances(paths, checked["task_id"])
    raw = semantic.canonical_json_bytes(
        checked, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
    )
    destination = permit_issuance_path(
        paths, checked["task_id"], checked["permit_sha256"]
    )
    if destination.parent != directory:
        raise PermitRuntimeError("permit issuance marker path escaped its store")
    existing = {
        row["permit_sha256"]: row for row in rows
    }.get(checked["permit_sha256"])
    if existing is not None:
        if semantic.canonical_json_bytes(
            existing, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
        ) != raw:
            raise PermitRuntimeError(
                "permit issuance slot is already bound to divergent bytes"
            )
        return existing
    if len(rows) >= MAX_PERMIT_ISSUANCES:
        raise PermitRuntimeError("permit issuance store exceeds marker count bound")
    if aggregate + len(raw) > MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES:
        raise PermitRuntimeError("permit issuance store exceeds aggregate byte bound")
    try:
        h.atomic_create_bytes(destination, raw)
    except h.HarnessError as exc:
        if not (destination.exists() or h._path_is_link_like(destination)):
            raise _fail("cannot publish permit issuance marker", exc) from exc
    stored = _read_permit_issuance(destination, checked["task_id"])
    if semantic.canonical_json_bytes(
        stored, max_bytes=MAX_PERMIT_ISSUANCE_BYTES
    ) != raw:
        raise PermitRuntimeError(
            "permit issuance publication collided with divergent bytes"
        )
    return stored


def _publish_cohort_permit_issuance(
    paths: h.HarnessPaths, marker: Mapping[str, Any]
) -> dict[str, Any]:
    h._require_chief_lock(paths)
    checked = validate_cohort_permit_issuance(marker)
    directory = _ensure_cohort_issuance_directory(paths, checked["task_id"])
    rows, aggregate = _scan_all_permit_issuances(paths, checked["task_id"])
    raw = semantic.canonical_json_bytes(
        checked, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
    )
    destination = cohort_permit_issuance_path(
        paths, checked["task_id"], checked["permit_sha256"]
    )
    if destination.parent != directory:
        raise PermitRuntimeError(
            "cohort permit issuance marker path escaped its store"
        )
    existing = {
        row["permit_sha256"]: row for row in rows
    }.get(checked["permit_sha256"])
    if existing is not None:
        if semantic.canonical_json_bytes(
            existing, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
        ) != raw:
            raise PermitRuntimeError(
                "cohort permit issuance slot is already bound to divergent bytes"
            )
        return existing
    if len(rows) >= MAX_PERMIT_ISSUANCES:
        raise PermitRuntimeError(
            "permit issuance stores exceed the global marker count bound"
        )
    if aggregate + len(raw) > MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES:
        raise PermitRuntimeError(
            "permit issuance stores exceed the global aggregate byte bound"
        )
    try:
        h.atomic_create_bytes(destination, raw)
    except h.HarnessError as exc:
        if not (destination.exists() or h._path_is_link_like(destination)):
            raise _fail("cannot publish cohort permit issuance marker", exc) from exc
    stored = _read_cohort_permit_issuance(destination, checked["task_id"])
    if semantic.canonical_json_bytes(
        stored, max_bytes=MAX_COHORT_PERMIT_ISSUANCE_BYTES
    ) != raw:
        raise PermitRuntimeError(
            "cohort permit issuance publication collided with divergent bytes"
        )
    return stored


def _required_permit_issuance(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
) -> dict[str, Any]:
    rows, _aggregate = _scan_all_permit_issuances(paths, transaction["task_id"])
    matches = [
        marker
        for marker in rows
        if marker["schema_version"] == PERMIT_ISSUANCE_SCHEMA_VERSION
        and marker["permit_sha256"] == group["permit"]["permit_sha256"]
    ]
    if len(matches) != 1:
        raise PermitRuntimeError(
            "Chief permit issuance marker is missing or non-unique"
        )
    return _validate_issuance_contract(matches[0], transaction, group)


def _required_cohort_permit_issuance(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    group: Mapping[str, Any],
) -> dict[str, Any]:
    rows, _aggregate = _scan_all_permit_issuances(
        paths, transaction["task_id"]
    )
    matches = [
        marker
        for marker in rows
        if marker["schema_version"] == COHORT_PERMIT_ISSUANCE_SCHEMA_VERSION
        and marker["permit_sha256"] == group["permit"]["permit_sha256"]
    ]
    if len(matches) != 1:
        raise PermitRuntimeError(
            "Chief cohort permit issuance marker is missing or non-unique"
        )
    return _validate_cohort_issuance_contract(
        matches[0], transaction, group
    )


def prepare_permitted_arm_transaction(
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    arm: Mapping[str, Any],
    command_id: str,
    recorded_at: str,
) -> dict[str, Any]:
    """Prepare the exact objects -> one binding -> event transaction."""

    task_id = h.validate_id(task_id, "task id")
    records, _replayed = _freeze_event_chain(event_chain, task_id)
    pair = permits.validate_decision_permit_pair(decision, permit)
    checked_decision = pair["decision"]
    checked_permit = pair["permit"]
    if checked_permit["task_id"] != task_id or checked_permit["action"] != "packet.arm":
        raise PermitRuntimeError("permit is not a packet.arm decision for this task")
    prefix, prefix_projection = _prefix_for_head(
        records, checked_permit["expected_semantic_head_sha256"]
    )
    effect = routing.prepare_authority_effect(
        task_id=task_id,
        event_chain=prefix,
        arm=arm,
    )
    routing_authority_sha256 = authority.authority_sha256(arm)
    if (
        checked_decision["parameters"]["routing_authority_sha256"]
        != routing_authority_sha256
        or checked_decision["technical_payload_sha256"] != routing_authority_sha256
    ):
        raise PermitRuntimeError("permit decision technical payload differs from routing authority")
    identity, receipt = _consumption_receipt(
        checked_decision,
        checked_permit,
        effect["routing_entry"],
    )
    result_state = _advance_permit_projection(effect["result_state"], identity, receipt)
    authority_ref = f"permit:{checked_permit['permit_sha256']}"
    try:
        planned = semantic.create_transition_event(
            prefix[-1],
            prefix_projection,
            result_state,
            event_type=_EVENT_TYPE,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=authority_ref,
        )
    except semantic.SemanticEventError as exc:
        raise _fail("cannot create permitted packet.arm event", exc) from exc
    sealed_objects = _contract_objects(
        task_id,
        checked_decision,
        checked_permit,
        effect["routing_authority_object"],
    )
    binding = objects.create_semantic_binding(
        binding_kind="permit_consumption",
        task_id=task_id,
        binding_key=identity,
        expected_semantic_head_sha256=planned["prev_event_sha256"],
        planned_event_sha256=planned["event_sha256"],
        result_projection_sha256=planned["result_projection_sha256"],
        object_sha256s=sorted(row["object_sha256"] for row in sealed_objects),
    )
    base = {
        "schema_version": PERMIT_TRANSACTION_SCHEMA_VERSION,
        "task_id": task_id,
        "event_type": _EVENT_TYPE,
        "command_id": planned["command_id"],
        "recorded_at": planned["recorded_at"],
        "authority_ref": authority_ref,
        "expected_head_sha256": planned["prev_event_sha256"],
        "result_state": result_state,
        "planned_event": planned,
        "objects": sealed_objects,
        "binding": binding,
    }
    base["transaction_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_PERMIT_TRANSACTION_BYTES
    )
    return validate_permitted_arm_transaction(base)


def validate_permitted_arm_transaction(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a detached, self-hashed permitted packet.arm transaction."""

    if not isinstance(value, dict) or set(value) != _TRANSACTION_FIELDS:
        raise PermitRuntimeError("permit transaction schema is invalid")
    item = _clone(value, maximum=MAX_PERMIT_TRANSACTION_BYTES)
    _exact_version(
        item["schema_version"],
        PERMIT_TRANSACTION_SCHEMA_VERSION,
        "permit transaction version",
    )
    task_id = h.validate_id(item["task_id"], "task id")
    group = _contract_group(item["objects"], task_id)
    decision = group["decision"]
    permit = group["permit"]
    binding = objects.validate_semantic_binding(item["binding"])
    identity = permits.permit_consumption_identity(permit)
    expected_refs = sorted(
        wrapped["object_sha256"] for wrapped in group["objects"].values()
    )
    canonical_objects = sorted(
        group["objects"].values(), key=lambda wrapped: wrapped["object_type"]
    )
    if (
        item["objects"] != canonical_objects
        or binding["binding_kind"] != "permit_consumption"
        or binding["task_id"] != task_id
        or binding["binding_key"] != identity
        or binding["object_sha256s"] != expected_refs
        or binding["expected_semantic_head_sha256"]
        != permit["expected_semantic_head_sha256"]
    ):
        raise PermitRuntimeError("permit transaction binding contract is invalid")
    planned = item["planned_event"]
    try:
        semantics = semantic.command_semantics(planned)
    except semantic.SemanticEventError as exc:
        raise _fail("permit transaction planned event is invalid", exc) from exc
    authority_ref = f"permit:{permit['permit_sha256']}"
    _validate_delta_scope(semantics["payload"])
    recorded = _instant(planned["recorded_at"], "permit event recorded_at")
    if not (
        _instant(group["arm"]["attempt_identity"]["armed_at"], "routing arm start")
        <= recorded
        <= _instant(group["arm"]["attempt_identity"]["expires_at"], "routing arm expiry")
        and recorded <= _instant(permit["expires_at"], "permit expiry")
    ):
        raise PermitRuntimeError("permit event lies outside its authority window")
    if (
        item["event_type"] != _EVENT_TYPE
        or semantics["event_type"] != _EVENT_TYPE
        or item["authority_ref"] != authority_ref
        or planned["authority_ref"] != authority_ref
        or item["command_id"] != planned["command_id"]
        or item["recorded_at"] != planned["recorded_at"]
        or item["expected_head_sha256"] != planned["prev_event_sha256"]
        or planned["prev_event_sha256"] != binding["expected_semantic_head_sha256"]
        or planned["event_sha256"] != binding["planned_event_sha256"]
        or planned["result_projection_sha256"] != binding["result_projection_sha256"]
    ):
        raise PermitRuntimeError("permit transaction event cross-binding is invalid")
    if semantic.SEMANTIC_ENVELOPE_KEY in item["result_state"]:
        raise PermitRuntimeError("permit transaction result must be a domain projection")
    result_state = semantic.projection_domain(item["result_state"])
    if result_state.get("task_id") != task_id:
        raise PermitRuntimeError("permit transaction result belongs to another task")
    if semantic.canonical_sha256(result_state) != binding["result_projection_sha256"]:
        raise PermitRuntimeError("permit transaction result projection digest is invalid")
    route_namespace = routing.routing_namespace_from_projection(result_state)
    route_slot = routing.routing_outcome_slot_sha256(group["arm"])
    route_entry = route_namespace["entries"].get(route_slot)
    expected_route_entry = routing._entry_for(
        "authority",
        group["arm"],
        {"routing_authority": group["objects"]["routing_authority"]},
    )
    if route_entry != expected_route_entry:
        raise PermitRuntimeError("permit transaction routing projection is invalid")
    namespace = permit_namespace_from_projection(result_state)
    expected_identity, expected_receipt = _consumption_receipt(
        decision, permit, route_entry
    )
    if (
        expected_identity != identity
        or namespace["consumptions"].get(identity) != expected_receipt
        or namespace["replay_markers"].get(expected_receipt["replay_marker"])
        != identity
    ):
        raise PermitRuntimeError("permit transaction consumption projection is invalid")
    preimage = {key: item[key] for key in _TRANSACTION_FIELDS if key != "transaction_sha256"}
    if item["transaction_sha256"] != semantic.canonical_sha256(
        preimage, max_bytes=MAX_PERMIT_TRANSACTION_BYTES
    ):
        raise PermitRuntimeError("permit transaction SHA-256 is invalid")
    return item


def _cohort_consumption_receipt(
    group: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    try:
        return permit_projection_contract.cohort_consumption_receipt(
            group["decision"],
            group["permit"],
            cohort_sha256=group["cohort_plan"]["cohort_sha256"],
            wave_index=group["decision"]["parameters"]["wave_index"],
            selection_sha256=group["selection"]["selection_sha256"],
            routing_slots=group["routing_slots"],
        )
    except (
        permit_projection_contract.PermitProjectionError,
        permits.TransitionPermitError,
        KeyError,
        TypeError,
    ) as exc:
        raise _fail("cohort permit consumption receipt is invalid", exc) from exc


def _validate_cohort_consumption_window(
    routing_authorities: Iterable[Mapping[str, Any]],
    permit: Mapping[str, Any],
    current_time: datetime,
) -> None:
    rows = _bounded_records(
        routing_authorities,
        cohorts.MAX_CONCURRENCY,
        "cohort permit routing authorities",
    )
    for arm in rows:
        _validate_arm_consumption_window(arm, current_time)
    if _instant(permit["expires_at"], "cohort permit expiry") <= current_time:
        raise PermitRuntimeError("cohort permit is expired")


def prepare_permitted_cohort_transaction(
    paths: h.HarnessPaths,
    *,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
    decision: Mapping[str, Any],
    permit: Mapping[str, Any],
    cohort_plan: Mapping[str, Any],
    arms: Iterable[Mapping[str, Any]],
    command_id: str,
    recorded_at: str,
) -> dict[str, Any]:
    """Prepare one exact N-route plus one-consumption cohort transaction."""

    task_id = h.validate_id(task_id, "task id")
    records, _replayed = _freeze_event_chain(event_chain, task_id)
    try:
        pair = permits.validate_decision_permit_pair(decision, permit)
        plan = cohorts.validate_cohort(cohort_plan)
    except (permits.TransitionPermitError, cohorts.CohortError) as exc:
        raise _fail("cohort permit decision, permit, or plan is invalid", exc) from exc
    checked_decision = pair["decision"]
    checked_permit = pair["permit"]
    parameters = checked_permit["parameters"]
    if (
        checked_permit["task_id"] != task_id
        or checked_permit["action"] != "cohort.advance"
        or checked_permit["target_ids"] != [plan["cohort_id"]]
        or parameters["cohort_sha256"] != plan["cohort_sha256"]
    ):
        raise PermitRuntimeError(
            "permit is not a cohort.advance decision for this task and plan"
        )
    prefix, prefix_projection = _prefix_for_head(
        records, checked_permit["expected_semantic_head_sha256"]
    )
    try:
        effect = routing.prepare_cohort_authority_effect(
            paths,
            task_id=task_id,
            event_chain=prefix,
            cohort_plan=plan,
            wave_index=parameters["wave_index"],
            arms=arms,
        )
    except routing.RoutingPersistenceError as exc:
        raise _fail("cannot prepare cohort routing effect", exc) from exc
    selection = effect["selection"]
    if checked_decision["technical_payload_sha256"] != selection["selection_sha256"]:
        raise PermitRuntimeError(
            "cohort permit decision technical payload differs from exact selection"
        )
    chief_identity = checked_permit["chief_authority"]
    for arm in effect["routing_authorities"]:
        if {
            "session_id": arm["chief_authority"]["session_id"],
            "epoch": arm["chief_authority"]["epoch"],
        } != chief_identity:
            raise PermitRuntimeError(
                "cohort routing authority differs from permit Chief authority"
            )
        if _instant(checked_permit["expires_at"], "cohort permit expiry") > _instant(
            arm["attempt_identity"]["expires_at"], "cohort routing arm expiry"
        ):
            raise PermitRuntimeError(
                "cohort permit outlives one of its routing authorities"
            )
    sealed_objects = _cohort_contract_objects(
        task_id,
        checked_decision,
        checked_permit,
        plan,
        effect["routing_authority_objects"],
    )
    provisional = {
        "decision": checked_decision,
        "permit": checked_permit,
        "cohort_plan": plan,
        "selection": selection,
        "routing_slots": [
            entry["outcome_slot_sha256"] for entry in effect["routing_entries"]
        ],
    }
    identity, receipt = _cohort_consumption_receipt(provisional)
    result_state = _advance_permit_projection(
        effect["result_state"], identity, receipt
    )
    authority_ref = f"permit:{checked_permit['permit_sha256']}"
    try:
        planned = semantic.create_transition_event(
            prefix[-1],
            prefix_projection,
            result_state,
            event_type=_COHORT_EVENT_TYPE,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=authority_ref,
        )
    except semantic.SemanticEventError as exc:
        raise _fail("cannot create permitted cohort.advance event", exc) from exc
    binding = objects.create_semantic_binding(
        binding_kind="cohort_advance",
        task_id=task_id,
        binding_key=identity,
        expected_semantic_head_sha256=planned["prev_event_sha256"],
        planned_event_sha256=planned["event_sha256"],
        result_projection_sha256=planned["result_projection_sha256"],
        object_sha256s=sorted(row["object_sha256"] for row in sealed_objects),
    )
    base = {
        "schema_version": COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION,
        "task_id": task_id,
        "event_type": _COHORT_EVENT_TYPE,
        "command_id": planned["command_id"],
        "recorded_at": planned["recorded_at"],
        "authority_ref": authority_ref,
        "expected_head_sha256": planned["prev_event_sha256"],
        "result_state": result_state,
        "planned_event": planned,
        "objects": sealed_objects,
        "binding": binding,
    }
    base["transaction_sha256"] = semantic.canonical_sha256(
        base, max_bytes=MAX_COHORT_PERMIT_TRANSACTION_BYTES
    )
    return validate_permitted_cohort_transaction(base)


def validate_permitted_cohort_transaction(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one detached schema-v2 permitted cohort transaction."""

    if not isinstance(value, dict) or set(value) != _TRANSACTION_FIELDS:
        raise PermitRuntimeError("cohort permit transaction schema is invalid")
    item = _clone(value, maximum=MAX_COHORT_PERMIT_TRANSACTION_BYTES)
    _exact_version(
        item["schema_version"],
        COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION,
        "cohort permit transaction version",
    )
    task_id = h.validate_id(item["task_id"], "task id")
    binding = objects.validate_semantic_binding(item["binding"])
    group = _cohort_contract_group(item["objects"], binding, task_id)
    if item["objects"] != group["canonical_objects"]:
        raise PermitRuntimeError("cohort permit transaction objects are not canonical")
    permit = group["permit"]
    identity = permits.permit_consumption_identity(permit)
    if binding["binding_key"] != identity:
        raise PermitRuntimeError("cohort permit transaction binding identity is invalid")
    planned = item["planned_event"]
    try:
        semantics = semantic.command_semantics(planned)
    except semantic.SemanticEventError as exc:
        raise _fail("cohort permit transaction planned event is invalid", exc) from exc
    _validate_delta_scope(semantics["payload"])
    authority_ref = f"permit:{permit['permit_sha256']}"
    recorded = _instant(planned["recorded_at"], "cohort permit event recorded_at")
    if recorded > _instant(permit["expires_at"], "cohort permit expiry"):
        raise PermitRuntimeError("cohort permit event lies outside its permit window")
    for arm in group["routing_authorities"]:
        if not (
            _instant(arm["attempt_identity"]["armed_at"], "cohort routing arm start")
            <= recorded
            <= _instant(
                arm["attempt_identity"]["expires_at"], "cohort routing arm expiry"
            )
        ):
            raise PermitRuntimeError(
                "cohort permit event lies outside a routing authority window"
            )
    if (
        item["event_type"] != _COHORT_EVENT_TYPE
        or semantics["event_type"] != _COHORT_EVENT_TYPE
        or item["authority_ref"] != authority_ref
        or planned["authority_ref"] != authority_ref
        or item["command_id"] != planned["command_id"]
        or item["recorded_at"] != planned["recorded_at"]
        or item["expected_head_sha256"] != planned["prev_event_sha256"]
        or planned["prev_event_sha256"]
        != binding["expected_semantic_head_sha256"]
        or planned["event_sha256"] != binding["planned_event_sha256"]
        or planned["result_projection_sha256"]
        != binding["result_projection_sha256"]
    ):
        raise PermitRuntimeError("cohort permit transaction event cross-binding is invalid")
    if semantic.SEMANTIC_ENVELOPE_KEY in item["result_state"]:
        raise PermitRuntimeError(
            "cohort permit transaction result must be a domain projection"
        )
    result_state = semantic.projection_domain(item["result_state"])
    if result_state.get("task_id") != task_id:
        raise PermitRuntimeError("cohort permit transaction belongs to another task")
    if semantic.canonical_sha256(result_state) != binding["result_projection_sha256"]:
        raise PermitRuntimeError(
            "cohort permit transaction result projection digest is invalid"
        )
    route_namespace = routing.routing_namespace_from_projection(result_state)
    for arm, wrapped, slot in zip(
        group["routing_authorities"],
        group["routing_authority_objects"],
        group["routing_slots"],
        strict=True,
    ):
        expected_entry = routing._entry_for(
            "authority", arm, {"routing_authority": wrapped}
        )
        if route_namespace["entries"].get(slot) != expected_entry:
            raise PermitRuntimeError(
                "cohort permit transaction routing projection is invalid"
            )
    namespace = permit_namespace_from_projection(result_state)
    expected_identity, expected_receipt = _cohort_consumption_receipt(group)
    if (
        expected_identity != identity
        or namespace["consumptions"].get(identity) != expected_receipt
        or namespace["replay_markers"].get(expected_receipt["replay_marker"])
        != identity
    ):
        raise PermitRuntimeError(
            "cohort permit transaction consumption projection is invalid"
        )
    preimage = {
        key: item[key] for key in _TRANSACTION_FIELDS if key != "transaction_sha256"
    }
    if item["transaction_sha256"] != semantic.canonical_sha256(
        preimage, max_bytes=MAX_COHORT_PERMIT_TRANSACTION_BYTES
    ):
        raise PermitRuntimeError("cohort permit transaction SHA-256 is invalid")
    return item


def _current_chief_authority(
    paths: h.HarnessPaths, current_time: datetime
) -> dict[str, Any]:
    if (
        not isinstance(current_time, datetime)
        or current_time.tzinfo is None
        or current_time.utcoffset() is None
    ):
        raise PermitRuntimeError("permit commit time must be timezone-aware")
    try:
        record = h.load_chief_authority(paths)
        expires_at = datetime.fromisoformat(
            record["expires_at"][:-1] + "+00:00"
            if record["expires_at"].endswith("Z")
            else record["expires_at"]
        )
    except (h.HarnessError, KeyError, TypeError, ValueError) as exc:
        raise _fail("cannot validate current Chief authority for permit", exc) from exc
    if record["status"] != "active" or expires_at <= current_time:
        raise PermitRuntimeError("permit Chief authority is inactive or expired")
    return {"session_id": record["session_id"], "epoch": record["epoch"]}


def _require_issued_contract_objects(
    generic_report: Mapping[str, Any], transaction: Mapping[str, Any]
) -> None:
    rows = generic_report.get("objects")
    if not isinstance(rows, list):
        raise PermitRuntimeError("generic semantic object report is invalid")
    stored: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            wrapped = objects.validate_semantic_object(
                {key: row[key] for key in _OBJECT_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("issued permit object report is invalid", exc) from exc
        stored[wrapped["object_sha256"]] = wrapped
    for wrapped in transaction["objects"]:
        if stored.get(wrapped["object_sha256"]) != wrapped:
            raise PermitRuntimeError(
                "permit contract objects were not durably issued by Chief"
            )


def issue_permitted_arm_transaction(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    *,
    chief_session_id: str,
    chief_epoch: int,
    chief_token: str,
    current_time: datetime,
) -> dict[str, Any]:
    """Chief-fenced durable issuance; no lifecycle event is committed here.

    The exact objects are published first.  The final immutable issuance
    marker is the linearization point that makes them consumable.  An
    objects-only crash is therefore harmless and recoverable by the same live
    Chief while the permit window remains valid.
    """

    h._require_chief_lock(paths)
    tx = validate_permitted_arm_transaction(transaction)
    records, replayed = _freeze_event_chain(event_chain, tx["task_id"])
    group = _contract_group(tx["objects"], tx["task_id"])
    try:
        live = h.require_chief_authority(
            paths,
            session_id=chief_session_id,
            epoch=chief_epoch,
            token=chief_token,
            now=current_time,
        )
    except h.HarnessError as exc:
        raise _fail("permit issuance requires live Chief authority", exc) from exc
    live_identity = {"session_id": live["session_id"], "epoch": live["epoch"]}
    generic = objects.inspect_semantic_objects(paths, tx["task_id"], records)
    markers, _aggregate = _scan_all_permit_issuances(paths, tx["task_id"])
    existing = next(
        (
            marker
            for marker in markers
            if marker["permit_sha256"] == group["permit"]["permit_sha256"]
        ),
        None,
    )
    if existing is not None:
        marker = _validate_issuance_contract(existing, tx, group)
        _require_issued_contract_objects(generic, tx)
        issuer = marker["issuer_chief_authority"]
        if {
            "session_id": issuer["session_id"],
            "epoch": issuer["epoch"],
        } != live_identity:
            raise PermitRuntimeError(
                "permit issuance replay belongs to another Chief authority"
            )
        return {
            "task_id": tx["task_id"],
            "permit_sha256": group["permit"]["permit_sha256"],
            "transaction_sha256": tx["transaction_sha256"],
            "issuance_sha256": marker["issuance_sha256"],
            "issued_object_sha256s": marker["object_sha256s"],
            "semantic_head_sha256": marker["expected_semantic_head_sha256"],
            "idempotent_replay": True,
        }
    candidate_identity = permits.permit_consumption_identity(group["permit"])
    candidate_replay_marker = permits.permit_replay_marker(group["permit"])
    if any(
        marker["consumption_identity"] == candidate_identity
        or marker["replay_marker"] == candidate_replay_marker
        for marker in markers
    ):
        raise PermitRuntimeError(
            "permit issuance identity or replay marker is already reserved"
        )
    generic = objects.require_no_pending_bindings(paths, tx["task_id"], records)
    if any(
        row["binding_kind"] == "permit_consumption"
        and row["binding_key"] == tx["binding"]["binding_key"]
        for row in generic["bindings"]
    ):
        raise PermitRuntimeError("permit consumption already has a binding")
    rebuilt = prepare_permitted_arm_transaction(
        task_id=tx["task_id"],
        event_chain=records,
        decision=group["decision"],
        permit=group["permit"],
        arm=group["arm"],
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
    )
    if semantic.canonical_json_bytes(rebuilt, max_bytes=MAX_PERMIT_TRANSACTION_BYTES) != (
        semantic.canonical_json_bytes(tx, max_bytes=MAX_PERMIT_TRANSACTION_BYTES)
    ):
        raise PermitRuntimeError("permit issuance is not based on the current ledger head")
    recorded_at = _instant(tx["recorded_at"], "permit issuance recorded_at")
    if recorded_at > current_time:
        raise PermitRuntimeError("permit issuance precedes its planned event time")
    _validate_arm_consumption_window(group["arm"], current_time)
    if group["permit"]["chief_authority"] != live_identity:
        raise PermitRuntimeError("permit issuer differs from live Chief authority")
    if group["arm"]["chief_authority"]["authority_sha256"] != semantic.canonical_sha256(
        live
    ):
        raise PermitRuntimeError("routing arm is not bound to the live Chief record")
    namespace = permit_namespace_from_projection(replayed)
    try:
        permits.validate_transition_consumption(
            group["permit"],
            task_id=tx["task_id"],
            semantic_head_sha256=records[-1]["event_sha256"],
            decision_sha256=group["decision"]["decision_sha256"],
            action="packet.arm",
            target_ids=group["permit"]["target_ids"],
            parameters=group["permit"]["parameters"],
            chief_authority=live_identity,
            current_time=current_time,
            consumed_identities=namespace["consumptions"].keys(),
            consumed_replay_markers=namespace["replay_markers"].keys(),
        )
    except permits.TransitionPermitError as exc:
        raise _fail("Chief cannot issue this permit", exc) from exc
    store.preflight_semantic_append(
        paths,
        tx["task_id"],
        command_id=tx["command_id"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
    published = [objects.publish_semantic_object(paths, wrapped) for wrapped in tx["objects"]]
    verified = objects.inspect_semantic_objects(paths, tx["task_id"], records)
    _require_issued_contract_objects(verified, tx)
    issued_at = current_time.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    marker = _publish_permit_issuance(
        paths,
        _create_permit_issuance(
            tx,
            group,
            authority_record_sha256=semantic.canonical_sha256(live),
            issued_at=issued_at,
        ),
    )
    return {
        "task_id": tx["task_id"],
        "permit_sha256": group["permit"]["permit_sha256"],
        "transaction_sha256": tx["transaction_sha256"],
        "issuance_sha256": marker["issuance_sha256"],
        "issued_object_sha256s": sorted(row["object_sha256"] for row in published),
        "semantic_head_sha256": records[-1]["event_sha256"],
        "idempotent_replay": False,
    }


def issue_permitted_cohort_transaction(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    *,
    chief_session_id: str,
    chief_epoch: int,
    chief_token: str,
    current_time: datetime,
) -> dict[str, Any]:
    """Chief-fenced durable issuance of one exact cohort transaction."""

    h._require_chief_lock(paths)
    tx = validate_permitted_cohort_transaction(transaction)
    records, replayed = _freeze_event_chain(event_chain, tx["task_id"])
    group = _cohort_contract_group(tx["objects"], tx["binding"], tx["task_id"])
    try:
        live = h.require_chief_authority(
            paths,
            session_id=chief_session_id,
            epoch=chief_epoch,
            token=chief_token,
            now=current_time,
        )
    except h.HarnessError as exc:
        raise _fail(
            "cohort permit issuance requires live Chief authority", exc
        ) from exc
    live_identity = {"session_id": live["session_id"], "epoch": live["epoch"]}
    generic = objects.inspect_semantic_objects(paths, tx["task_id"], records)
    markers, _aggregate = _scan_all_permit_issuances(paths, tx["task_id"])
    existing = next(
        (
            marker
            for marker in markers
            if marker["permit_sha256"] == group["permit"]["permit_sha256"]
        ),
        None,
    )
    if existing is not None:
        marker = _validate_cohort_issuance_contract(existing, tx, group)
        _require_issued_contract_objects(generic, tx)
        issuer = marker["issuer_chief_authority"]
        if {
            "session_id": issuer["session_id"],
            "epoch": issuer["epoch"],
        } != live_identity:
            raise PermitRuntimeError(
                "cohort permit issuance replay belongs to another Chief authority"
            )
        return {
            "task_id": tx["task_id"],
            "permit_sha256": group["permit"]["permit_sha256"],
            "transaction_sha256": tx["transaction_sha256"],
            "issuance_sha256": marker["issuance_sha256"],
            "issued_object_sha256s": marker["object_sha256s"],
            "semantic_head_sha256": marker[
                "expected_semantic_head_sha256"
            ],
            "idempotent_replay": True,
        }
    candidate_identity = permits.permit_consumption_identity(group["permit"])
    candidate_replay_marker = permits.permit_replay_marker(group["permit"])
    if any(
        marker["consumption_identity"] == candidate_identity
        or marker["replay_marker"] == candidate_replay_marker
        for marker in markers
    ):
        raise PermitRuntimeError(
            "cohort permit issuance identity or replay marker is already reserved"
        )
    generic = objects.require_no_pending_bindings(
        paths, tx["task_id"], records
    )
    if any(
        row["binding_kind"] == "cohort_advance"
        and row["binding_key"] == tx["binding"]["binding_key"]
        for row in generic["bindings"]
    ):
        raise PermitRuntimeError("cohort permit consumption already has a binding")
    rebuilt = prepare_permitted_cohort_transaction(
        paths,
        task_id=tx["task_id"],
        event_chain=records,
        decision=group["decision"],
        permit=group["permit"],
        cohort_plan=group["cohort_plan"],
        arms=group["routing_authorities"],
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
    )
    if semantic.canonical_json_bytes(
        rebuilt, max_bytes=MAX_COHORT_PERMIT_TRANSACTION_BYTES
    ) != semantic.canonical_json_bytes(
        tx, max_bytes=MAX_COHORT_PERMIT_TRANSACTION_BYTES
    ):
        raise PermitRuntimeError(
            "cohort permit issuance is not based on the current ledger head"
        )
    if _instant(tx["recorded_at"], "cohort permit issuance recorded_at") > current_time:
        raise PermitRuntimeError(
            "cohort permit issuance precedes its planned event time"
        )
    _validate_cohort_consumption_window(
        group["routing_authorities"], group["permit"], current_time
    )
    if group["permit"]["chief_authority"] != live_identity:
        raise PermitRuntimeError(
            "cohort permit issuer differs from live Chief authority"
        )
    live_sha256 = semantic.canonical_sha256(live)
    if any(
        arm["chief_authority"]["authority_sha256"] != live_sha256
        for arm in group["routing_authorities"]
    ):
        raise PermitRuntimeError(
            "cohort routing arm is not bound to the live Chief record"
        )
    namespace = permit_namespace_from_projection(replayed)
    try:
        permits.validate_transition_consumption(
            group["permit"],
            task_id=tx["task_id"],
            semantic_head_sha256=records[-1]["event_sha256"],
            decision_sha256=group["decision"]["decision_sha256"],
            action="cohort.advance",
            target_ids=group["permit"]["target_ids"],
            parameters=group["permit"]["parameters"],
            chief_authority=live_identity,
            current_time=current_time,
            consumed_identities=namespace["consumptions"].keys(),
            consumed_replay_markers=namespace["replay_markers"].keys(),
        )
    except permits.TransitionPermitError as exc:
        raise _fail("Chief cannot issue this cohort permit", exc) from exc
    store.preflight_semantic_append(
        paths,
        tx["task_id"],
        command_id=tx["command_id"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
    published = [
        objects.publish_semantic_object(paths, wrapped)
        for wrapped in tx["objects"]
    ]
    verified = objects.inspect_semantic_objects(paths, tx["task_id"], records)
    _require_issued_contract_objects(verified, tx)
    issued_at = current_time.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    marker = _publish_cohort_permit_issuance(
        paths,
        _create_cohort_permit_issuance(
            tx,
            group,
            authority_record_sha256=live_sha256,
            issued_at=issued_at,
        ),
    )
    return {
        "task_id": tx["task_id"],
        "permit_sha256": group["permit"]["permit_sha256"],
        "transaction_sha256": tx["transaction_sha256"],
        "issuance_sha256": marker["issuance_sha256"],
        "issued_object_sha256s": sorted(
            row["object_sha256"] for row in published
        ),
        "semantic_head_sha256": records[-1]["event_sha256"],
        "idempotent_replay": False,
    }


def inspect_permit_runtime(
    paths: h.HarnessPaths,
    task_id: str,
    event_chain: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Authenticate permit objects, bindings, projection indexes, and routing."""

    task_id = h.validate_id(task_id, "task id")
    records, replayed = _freeze_event_chain(event_chain, task_id)
    generic = objects.inspect_semantic_objects(paths, task_id, records)
    routing_report = routing.inspect_routing_persistence(paths, task_id, records)
    namespace = permit_namespace_from_projection(replayed)
    object_rows = generic.get("objects")
    binding_rows = generic.get("bindings")
    if not isinstance(object_rows, list) or not isinstance(binding_rows, list):
        raise PermitRuntimeError("generic semantic object report is invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    contract_digests: set[str] = set()
    permit_object_sha256s: dict[str, str] = {}
    for row in object_rows:
        try:
            wrapped = objects.validate_semantic_object(
                {key: row[key] for key in _OBJECT_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("permit semantic object report row is invalid", exc) from exc
        by_digest[wrapped["object_sha256"]] = wrapped
        if wrapped["object_type"] in {"transition_decision", "transition_permit"}:
            contract_digests.add(wrapped["object_sha256"])
        if wrapped["object_type"] == "transition_permit":
            try:
                checked_permit = permits.validate_transition_permit(
                    wrapped["payload"]
                )
            except permits.TransitionPermitError as exc:
                raise _fail("stored transition permit is invalid", exc) from exc
            if wrapped["object_identity"] != checked_permit["permit_sha256"]:
                raise PermitRuntimeError(
                    "stored transition permit object identity is invalid"
                )
            if checked_permit["permit_sha256"] in permit_object_sha256s:
                raise PermitRuntimeError(
                    "permit object store has duplicate permit identity"
                )
            permit_object_sha256s[checked_permit["permit_sha256"]] = wrapped[
                "object_sha256"
            ]
    validated_bindings: list[tuple[dict[str, Any], str]] = []
    binding_by_sha256: dict[str, dict[str, Any]] = {}
    for row in binding_rows:
        try:
            binding = objects.validate_semantic_binding(
                {key: row[key] for key in _BINDING_FIELDS}
            )
        except (KeyError, objects.SemanticObjectError) as exc:
            raise _fail("permit semantic binding report row is invalid", exc) from exc
        classification = row.get("classification")
        if classification not in {"pending", "committed"}:
            raise PermitRuntimeError("permit binding classification is invalid")
        if binding["binding_sha256"] in binding_by_sha256:
            raise PermitRuntimeError("semantic binding digest is not unique")
        binding_by_sha256[binding["binding_sha256"]] = binding
        validated_bindings.append((binding, classification))

    issuance_rows, _issuance_bytes = _scan_all_permit_issuances(paths, task_id)
    issuance_by_permit: dict[str, dict[str, Any]] = {}
    issuance_report: list[dict[str, Any]] = []
    for marker in issuance_rows:
        if marker["schema_version"] == PERMIT_ISSUANCE_SCHEMA_VERSION:
            try:
                group = _contract_group(
                    [by_digest[digest] for digest in marker["object_sha256s"]],
                    task_id,
                )
            except KeyError as exc:
                raise _fail(
                    "permit issuance marker references a missing semantic object",
                    exc,
                ) from exc
            checked_marker = _validate_issuance_group(marker, task_id, group)
        elif marker["schema_version"] == COHORT_PERMIT_ISSUANCE_SCHEMA_VERSION:
            binding = binding_by_sha256.get(marker["binding_sha256"])
            if binding is None:
                # Objects-only issuance is valid before reservation.  Rebuild
                # the exact detached binding shape from the marker itself.
                binding = objects.create_semantic_binding(
                    binding_kind="cohort_advance",
                    task_id=task_id,
                    binding_key=marker["consumption_identity"],
                    expected_semantic_head_sha256=marker[
                        "expected_semantic_head_sha256"
                    ],
                    planned_event_sha256=marker["planned_event_sha256"],
                    result_projection_sha256=marker["result_projection_sha256"],
                    object_sha256s=marker["object_sha256s"],
                )
                if binding["binding_sha256"] != marker["binding_sha256"]:
                    raise PermitRuntimeError(
                        "cohort permit issuance marker binding SHA-256 is invalid"
                    )
            try:
                group = _cohort_contract_group(
                    [by_digest[digest] for digest in marker["object_sha256s"]],
                    binding,
                    task_id,
                )
            except KeyError as exc:
                raise _fail(
                    "cohort permit issuance marker references a missing object",
                    exc,
                ) from exc
            checked_marker = _validate_cohort_issuance_group(
                marker, task_id, group
            )
        else:
            raise PermitRuntimeError("permit issuance marker version is unsupported")
        if checked_marker["permit_sha256"] in issuance_by_permit:
            raise PermitRuntimeError(
                "permit issuance store has multiple markers for one permit"
            )
        issuance_by_permit[checked_marker["permit_sha256"]] = checked_marker
        issuance_report.append(
            {
                **checked_marker,
                "classification": (
                    "consumed"
                    if checked_marker["consumption_identity"]
                    in namespace["consumptions"]
                    else "issued"
                ),
            }
        )
    rows: list[dict[str, Any]] = []
    committed: dict[str, dict[str, Any]] = {}
    binding_digests: set[str] = set()
    event_by_sha = {event["event_sha256"]: event for event in records}
    for binding, classification in validated_bindings:
        references = set(binding["object_sha256s"])
        if references & contract_digests and binding["binding_kind"] not in {
            "permit_consumption",
            "cohort_advance",
        }:
            raise PermitRuntimeError(
                "permit contract object is referenced by another binding kind"
            )
        if binding["binding_kind"] not in {
            "permit_consumption",
            "cohort_advance",
        }:
            continue
        if binding["binding_kind"] == "permit_consumption":
            try:
                group = _contract_group(
                    [by_digest[digest] for digest in binding["object_sha256s"]],
                    task_id,
                )
            except KeyError as exc:
                raise _fail(
                    "permit binding references a missing semantic object", exc
                ) from exc
            permit = group["permit"]
            identity, expected_receipt = _consumption_receipt(
                group["decision"],
                permit,
                routing._entry_for(
                    "authority",
                    group["arm"],
                    {"routing_authority": group["objects"]["routing_authority"]},
                ),
            )
            expected_event_type = _EVENT_TYPE
        else:
            try:
                group = _cohort_contract_group(
                    [by_digest[digest] for digest in binding["object_sha256s"]],
                    binding,
                    task_id,
                )
            except KeyError as exc:
                raise _fail(
                    "cohort permit binding references a missing semantic object", exc
                ) from exc
            permit = group["permit"]
            identity, expected_receipt = _cohort_consumption_receipt(group)
            expected_event_type = _COHORT_EVENT_TYPE
        identity = permits.permit_consumption_identity(permit)
        marker = issuance_by_permit.get(permit["permit_sha256"])
        if marker is None:
            raise PermitRuntimeError(
                "permit consumption binding has no Chief issuance marker"
            )
        if (
            marker["binding_sha256"] != binding["binding_sha256"]
            or marker["planned_event_sha256"]
            != binding["planned_event_sha256"]
        ):
            raise PermitRuntimeError(
                "permit consumption binding differs from its issuance marker"
            )
        if (
            binding["binding_key"] != identity
            or binding["expected_semantic_head_sha256"]
            != permit["expected_semantic_head_sha256"]
        ):
            raise PermitRuntimeError("permit binding identity or head is invalid")
        projected = namespace["consumptions"].get(identity)
        if classification == "committed":
            committed_event = event_by_sha.get(binding["planned_event_sha256"])
            if (
                committed_event is None
                or committed_event["event_type"] != expected_event_type
                or committed_event["authority_ref"]
                != f"permit:{permit['permit_sha256']}"
            ):
                raise PermitRuntimeError(
                    "committed permit binding has invalid event semantics"
                )
            if projected != expected_receipt:
                raise PermitRuntimeError("committed permit binding is absent from projection")
            if identity in committed:
                raise PermitRuntimeError("permit consumption identity has multiple owning bindings")
            committed[identity] = binding
        elif classification == "pending":
            if projected is not None:
                raise PermitRuntimeError("pending permit binding is already visible in projection")
        else:
            raise PermitRuntimeError("permit binding classification is invalid")
        binding_digests.add(binding["binding_sha256"])
        rows.append(
            {
                "consumption_identity": identity,
                "receipt": expected_receipt,
                "binding": binding,
                "classification": classification,
            }
        )
    if set(namespace["consumptions"]) != set(committed):
        raise PermitRuntimeError("permit projection has no unique committed binding owner")
    if not binding_digests.issubset(set(routing_report["routing_binding_sha256s"])):
        raise PermitRuntimeError("permit binding is absent from routing ownership")
    binding_classifications = {
        row["receipt"]["permit_sha256"]: row["classification"] for row in rows
    }
    for marker_row in issuance_report:
        if marker_row["consumption_identity"] in namespace["consumptions"]:
            marker_row["classification"] = "consumed"
        elif marker_row["permit_sha256"] in binding_classifications:
            marker_row["classification"] = "reserved"
        else:
            marker_row["classification"] = "issued"
    return {
        "task_id": task_id,
        "namespace": namespace,
        "issuances": sorted(
            issuance_report, key=lambda row: row["permit_sha256"]
        ),
        "issuance_sha256s": sorted(
            marker["issuance_sha256"] for marker in issuance_rows
        ),
        "unissued_permit_object_sha256s": sorted(
            object_sha256
            for permit_sha256, object_sha256 in permit_object_sha256s.items()
            if permit_sha256 not in issuance_by_permit
        ),
        "consumptions": sorted(rows, key=lambda row: row["consumption_identity"]),
        "permit_binding_sha256s": sorted(binding_digests),
        "routing_report": routing_report,
    }


def commit_permitted_arm_transaction(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    *,
    current_time: datetime,
) -> dict[str, Any]:
    """Commit or recover one permitted packet.arm semantic transaction."""

    h._require_chief_lock(paths)
    tx = validate_permitted_arm_transaction(transaction)
    records, replayed = _freeze_event_chain(event_chain, tx["task_id"])
    generic = objects.require_no_pending_bindings(
        paths,
        tx["task_id"],
        records,
        expected_binding_sha256=tx["binding"]["binding_sha256"],
    )
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
        if row["binding_kind"] == "permit_consumption"
        and row["binding_key"] == tx["binding"]["binding_key"]
    ]
    if existing is None and same_slot:
        raise PermitRuntimeError("permit consumption CAS slot is already bound differently")
    group = _contract_group(tx["objects"], tx["task_id"])
    _require_issued_contract_objects(generic, tx)
    _required_permit_issuance(paths, tx, group)
    if existing is not None and existing.get("classification") == "committed":
        matching = [
            event
            for event in records
            if event["event_sha256"] == tx["planned_event"]["event_sha256"]
        ]
        if len(matching) != 1:
            raise PermitRuntimeError("committed permit binding has no unique ledger event")
        projection = store.repair_semantic_projection(paths, tx["task_id"])
        report = inspect_permit_runtime(paths, tx["task_id"], records)
        return {
            "task_id": tx["task_id"],
            "binding": tx["binding"],
            "event": matching[0],
            "projection": projection,
            "idempotent_replay": True,
            "permit_report": report,
        }
    rebuilt = prepare_permitted_arm_transaction(
        task_id=tx["task_id"],
        event_chain=records,
        decision=group["decision"],
        permit=group["permit"],
        arm=group["arm"],
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
    )
    if semantic.canonical_json_bytes(rebuilt, max_bytes=MAX_PERMIT_TRANSACTION_BYTES) != (
        semantic.canonical_json_bytes(tx, max_bytes=MAX_PERMIT_TRANSACTION_BYTES)
    ):
        raise PermitRuntimeError("permit transaction was not prepared from its exact ledger base")
    if existing is None:
        namespace = permit_namespace_from_projection(replayed)
        _validate_arm_consumption_window(group["arm"], current_time)
        live_chief = _current_chief_authority(paths, current_time)
        try:
            permits.validate_transition_consumption(
                group["permit"],
                task_id=tx["task_id"],
                semantic_head_sha256=records[-1]["event_sha256"],
                decision_sha256=group["decision"]["decision_sha256"],
                action="packet.arm",
                target_ids=group["permit"]["target_ids"],
                parameters=group["permit"]["parameters"],
                chief_authority=live_chief,
                current_time=current_time,
                consumed_identities=namespace["consumptions"].keys(),
                consumed_replay_markers=namespace["replay_markers"].keys(),
            )
        except permits.TransitionPermitError as exc:
            raise _fail("permit cannot authorize this transition", exc) from exc
    # A published exact binding is the consumption reservation linearization
    # point.  Recovery may finish after expiry or Chief renewal/takeover; it may
    # not alter the planned bytes.  Direct calls to lower-level publishers are
    # outside the cooperative supported-API boundary documented above.
    store.preflight_semantic_append(
        paths,
        tx["task_id"],
        command_id=tx["command_id"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
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
        raise PermitRuntimeError("semantic append published a different permit event")
    committed_records = [*records, appended.event]
    report = inspect_permit_runtime(paths, tx["task_id"], committed_records)
    return {
        "task_id": tx["task_id"],
        "binding": tx["binding"],
        "event": appended.event,
        "projection": appended.projection,
        "idempotent_replay": appended.idempotent_replay,
        "permit_report": report,
    }


def commit_permitted_cohort_transaction(
    paths: h.HarnessPaths,
    transaction: Mapping[str, Any],
    event_chain: Iterable[Mapping[str, Any]],
    *,
    current_time: datetime,
) -> dict[str, Any]:
    """Commit or recover one issued permitted cohort.advance transaction."""

    h._require_chief_lock(paths)
    tx = validate_permitted_cohort_transaction(transaction)
    records, replayed = _freeze_event_chain(event_chain, tx["task_id"])
    generic = objects.require_no_pending_bindings(
        paths,
        tx["task_id"],
        records,
        expected_binding_sha256=tx["binding"]["binding_sha256"],
    )
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
        if row["binding_kind"] == "cohort_advance"
        and row["binding_key"] == tx["binding"]["binding_key"]
    ]
    if existing is None and same_slot:
        raise PermitRuntimeError(
            "cohort permit consumption CAS slot is already bound differently"
        )
    group = _cohort_contract_group(
        tx["objects"], tx["binding"], tx["task_id"]
    )
    _require_issued_contract_objects(generic, tx)
    _required_cohort_permit_issuance(paths, tx, group)
    if existing is not None and existing.get("classification") == "committed":
        matching = [
            event
            for event in records
            if event["event_sha256"] == tx["planned_event"]["event_sha256"]
        ]
        if len(matching) != 1:
            raise PermitRuntimeError(
                "committed cohort permit binding has no unique ledger event"
            )
        projection_state = store.repair_semantic_projection(paths, tx["task_id"])
        report = inspect_permit_runtime(paths, tx["task_id"], records)
        return {
            "task_id": tx["task_id"],
            "binding": tx["binding"],
            "event": matching[0],
            "projection": projection_state,
            "idempotent_replay": True,
            "permit_report": report,
        }
    rebuilt = prepare_permitted_cohort_transaction(
        paths,
        task_id=tx["task_id"],
        event_chain=records,
        decision=group["decision"],
        permit=group["permit"],
        cohort_plan=group["cohort_plan"],
        arms=group["routing_authorities"],
        command_id=tx["command_id"],
        recorded_at=tx["recorded_at"],
    )
    if semantic.canonical_json_bytes(
        rebuilt, max_bytes=MAX_COHORT_PERMIT_TRANSACTION_BYTES
    ) != semantic.canonical_json_bytes(
        tx, max_bytes=MAX_COHORT_PERMIT_TRANSACTION_BYTES
    ):
        raise PermitRuntimeError(
            "cohort permit transaction was not prepared from its exact ledger base"
        )
    if existing is None:
        namespace = permit_namespace_from_projection(replayed)
        _validate_cohort_consumption_window(
            group["routing_authorities"], group["permit"], current_time
        )
        live_chief = _current_chief_authority(paths, current_time)
        try:
            permits.validate_transition_consumption(
                group["permit"],
                task_id=tx["task_id"],
                semantic_head_sha256=records[-1]["event_sha256"],
                decision_sha256=group["decision"]["decision_sha256"],
                action="cohort.advance",
                target_ids=group["permit"]["target_ids"],
                parameters=group["permit"]["parameters"],
                chief_authority=live_chief,
                current_time=current_time,
                consumed_identities=namespace["consumptions"].keys(),
                consumed_replay_markers=namespace["replay_markers"].keys(),
            )
        except permits.TransitionPermitError as exc:
            raise _fail("cohort permit cannot authorize this transition", exc) from exc
    store.preflight_semantic_append(
        paths,
        tx["task_id"],
        command_id=tx["command_id"],
        expected_head_sha256=tx["expected_head_sha256"],
    )
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
        raise PermitRuntimeError(
            "semantic append published a different cohort permit event"
        )
    committed_records = [*records, appended.event]
    report = inspect_permit_runtime(paths, tx["task_id"], committed_records)
    return {
        "task_id": tx["task_id"],
        "binding": tx["binding"],
        "event": appended.event,
        "projection": appended.projection,
        "idempotent_replay": appended.idempotent_replay,
        "permit_report": report,
    }


__all__ = [
    "COHORT_PERMIT_ISSUANCE_DIRECTORY",
    "COHORT_PERMIT_ISSUANCE_SCHEMA_VERSION",
    "COHORT_PERMIT_TRANSACTION_SCHEMA_VERSION",
    "MAX_COHORT_PERMIT_ISSUANCE_BYTES",
    "MAX_COHORT_PERMIT_TRANSACTION_BYTES",
    "MAX_PERMIT_CONSUMPTIONS",
    "MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES",
    "MAX_PERMIT_ISSUANCE_BYTES",
    "MAX_PERMIT_ISSUANCES",
    "MAX_PERMIT_NAMESPACE_BYTES",
    "MAX_PERMIT_TRANSACTION_BYTES",
    "PERMIT_ISSUANCE_DIRECTORY",
    "PERMIT_ISSUANCE_SCHEMA_VERSION",
    "PERMIT_NAMESPACE_KEY",
    "PERMIT_RUNTIME_SCHEMA_VERSION",
    "PERMIT_TRANSACTION_SCHEMA_VERSION",
    "PermitRuntimeError",
    "commit_permitted_arm_transaction",
    "commit_permitted_cohort_transaction",
    "cohort_permit_issuance_path",
    "inspect_permit_runtime",
    "issue_permitted_arm_transaction",
    "issue_permitted_cohort_transaction",
    "permit_issuance_path",
    "permit_namespace_from_projection",
    "prepare_permitted_arm_transaction",
    "prepare_permitted_cohort_transaction",
    "validate_cohort_permit_issuance",
    "validate_permit_consumption",
    "validate_permit_issuance",
    "validate_permit_namespace",
    "validate_permitted_arm_transaction",
    "validate_permitted_cohort_transaction",
]
