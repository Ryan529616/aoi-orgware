"""Pure bounded history checks used by the acceptance-candidate contract.

This module deliberately has no dependency on ``acceptance_contract`` and no
ledger, authority, or completion side effects.  It mirrors the relevant
reducer transition rules over explicit caller-supplied witnesses only.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, NamedTuple

from aoi_orgware.company.contracts import (
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    CompanyContractError,
    company_contract_sha256,
    validate_dispatch_request,
    validate_execution_node,
)
from aoi_orgware.company.invariants import InvariantObject


class AcceptanceHistoryError(ValueError):
    """An explicit bounded revision history cannot be trusted."""


class HistoryEntry(NamedTuple):
    """One validated immutable projection witness and its decoded payload."""

    item: InvariantObject
    payload: dict[str, Any]


_DISPATCH_TRANSITIONS = {
    "queued": frozenset({"admitted", "cancelled"}),
    "admitted": frozenset({"in_flight", "cancelled"}),
    "in_flight": frozenset({"dispatched", "effect_unknown", "failed_known"}),
    "effect_unknown": frozenset({"dispatched", "failed_known"}),
    "dispatched": frozenset(),
    "failed_known": frozenset(),
    "cancelled": frozenset(),
}

_DISPATCH_IDENTITY_FIELDS = (
    "reservation_id",
    "task_id",
    "packet_id",
    "manager_node_id",
    "target_node_id",
    "department_id",
    "parent_execution_id",
    "requested_role",
    "requested_capability_tier",
    "route_policy_id",
    "scope_sha256",
    "delegation_depth",
    "created_at",
)

_EXECUTION_IDENTITY_FIELDS = (
    "company_id",
    "company_incarnation",
    "lock_domain_generation",
    "execution_id",
    "execution_kind",
    "display_name",
    "organization_node_id",
    "department_id",
    "parent_execution_id",
    "execution_depth",
    "execution_path",
    "task_id",
    "packet_id",
    "thread_id",
    "turn_id",
    "agent_id",
    "job_id",
    "dispatch_id",
    "registration_id",
    "provider",
    "model",
    "effort",
    "carrier_id",
    "role",
    "delegation_depth",
    "created_at",
)


def _fail(message: str) -> None:
    raise AcceptanceHistoryError(message)


def _identity(item: Any) -> tuple[str, str, str, int, str]:
    if (
        type(item) is not InvariantObject
        or type(item.contract_type) is not str
        or type(item.object_key) is not str
        or type(item.event_id) is not str
        or type(item.global_sequence) is not int
        or isinstance(item.global_sequence, bool)
        or item.global_sequence < 0
        or type(item.payload_sha256) is not str
    ):
        _fail("history requires exact invariant objects")
    return (
        item.contract_type,
        item.object_key,
        item.event_id,
        item.global_sequence,
        item.payload_sha256,
    )


def _timestamp(value: Any) -> datetime:
    if type(value) is not str:
        _fail("history timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise AcceptanceHistoryError(f"history timestamp is invalid: {exc}") from exc
    if parsed.tzinfo is None:
        _fail("history timestamp lacks timezone")
    return parsed


def timestamp_precedes(left: Any, right: Any) -> bool:
    """Compare two validated timestamp spellings without widening authority."""
    return _timestamp(left) < _timestamp(right)


def _decoded_dispatch(witness: InvariantObject, dispatch_request_id: str) -> HistoryEntry:
    contract_type, object_key, _, _, payload_sha256 = _identity(witness)
    if contract_type != DISPATCH_REQUEST_V1 or object_key != dispatch_request_id:
        _fail("dispatch witness identity differs")
    try:
        payload = validate_dispatch_request(witness.payload)
    except CompanyContractError as exc:
        raise AcceptanceHistoryError(f"dispatch witness is invalid: {exc}") from exc
    if payload["dispatch_request_id"] != dispatch_request_id:
        _fail("dispatch witness request differs")
    if payload_sha256 != company_contract_sha256(witness.payload):
        _fail("dispatch witness payload hash differs")
    return HistoryEntry(witness, payload)


def validate_dispatch_history(
    values: tuple[InvariantObject, ...], dispatch_request_id: str,
) -> tuple[HistoryEntry, ...]:
    """Validate the reducer-equivalent DispatchRequest revision chain."""
    if type(values) is not tuple or not 1 <= len(values) <= 32 or type(dispatch_request_id) is not str:
        _fail("dispatch revision witnesses are unavailable")
    entries = tuple(_decoded_dispatch(witness, dispatch_request_id) for witness in values)
    ordered = tuple(sorted(entries, key=lambda entry: entry.payload["revision"]))
    if [entry.payload["revision"] for entry in ordered] != list(range(1, len(ordered) + 1)):
        _fail("dispatch revision witnesses are not contiguous")
    revision_ids: set[str] = set()
    command_ids: set[str] = set()
    event_ids: set[str] = set()
    for index, entry in enumerate(ordered):
        item, payload = entry
        if item.event_id in event_ids:
            _fail("dispatch revision event identity was reused")
        event_ids.add(item.event_id)
        if payload["dispatch_revision_id"] in revision_ids or payload["command_id"] in command_ids:
            _fail("dispatch revision or command identity was reused")
        revision_ids.add(payload["dispatch_revision_id"])
        command_ids.add(payload["command_id"])
        if index == 0:
            if (
                payload["revision"] != 1
                or payload["state"] != "queued"
                or payload["attempt"] != 0
                or payload["previous_event_id"] is not None
                or payload["previous_payload_sha256"] is not None
            ):
                _fail("dispatch origin predecessor differs")
            continue
        previous = ordered[index - 1]
        if item.global_sequence <= previous.item.global_sequence:
            _fail("dispatch revision does not advance the company cursor")
        if (
            payload["previous_event_id"],
            payload["previous_payload_sha256"],
        ) != (previous.item.event_id, previous.item.payload_sha256):
            _fail("dispatch witness predecessor differs")
        if any(payload[field] != previous.payload[field] for field in _DISPATCH_IDENTITY_FIELDS):
            _fail("dispatch history immutable identity differs")
        if (
            payload["state"] == previous.payload["state"]
            or payload["state"] not in _DISPATCH_TRANSITIONS[previous.payload["state"]]
        ):
            _fail("dispatch history state transition differs")
    return ordered


def select_current_dispatch(
    values: list[tuple[InvariantObject, dict[str, Any]]], dispatch_request_id: str,
) -> HistoryEntry:
    """Choose one current visible dispatch revision without guessing a history."""
    if type(values) is not list:
        _fail("current dispatch witnesses are invalid")
    matches = [HistoryEntry(item, payload) for item, payload in values if payload.get("dispatch_request_id") == dispatch_request_id]
    if not matches:
        _fail("current dispatch request is unavailable")
    highest_revision = max(entry.payload["revision"] for entry in matches)
    current = [entry for entry in matches if entry.payload["revision"] == highest_revision]
    if len(current) != 1:
        _fail("current dispatch request is ambiguous")
    return current[0]


def _decoded_execution(witness: InvariantObject, execution_id: str) -> HistoryEntry:
    contract_type, object_key, _, _, payload_sha256 = _identity(witness)
    if contract_type != EXECUTION_NODE_V1 or object_key != execution_id:
        _fail("execution witness identity differs")
    try:
        payload = validate_execution_node(witness.payload)
    except CompanyContractError as exc:
        raise AcceptanceHistoryError(f"execution witness is invalid: {exc}") from exc
    if payload["execution_id"] != execution_id:
        _fail("execution witness identifier differs")
    if payload_sha256 != company_contract_sha256(witness.payload):
        _fail("execution witness payload hash differs")
    return HistoryEntry(witness, payload)


def validate_execution_history(
    values: tuple[InvariantObject, ...], execution_id: str,
) -> tuple[HistoryEntry, ...]:
    """Validate exact execution revisions and return reducer-current ordering.

    Execution nodes do not carry an ordinal/predecessor field.  Their bounded
    parity is therefore event order plus immutable identity, append-only job
    and evidence identifiers, monotonic usage cursor, and non-regressing
    update time.  This does not claim a complete ledger history.
    """
    if type(values) is not tuple or not 1 <= len(values) <= 64 or type(execution_id) is not str:
        _fail("execution revision witnesses are unavailable")
    entries = tuple(_decoded_execution(witness, execution_id) for witness in values)
    identities: set[tuple[str, int, str]] = set()
    event_ids: set[str] = set()
    ordered = tuple(sorted(entries, key=lambda entry: (entry.item.global_sequence, entry.item.event_id)))
    for index, entry in enumerate(ordered):
        identity = (entry.item.event_id, entry.item.global_sequence, entry.item.payload_sha256)
        if identity in identities:
            _fail("execution revision logical identity was reused")
        identities.add(identity)
        if entry.item.event_id in event_ids:
            _fail("execution revision event identity was reused")
        event_ids.add(entry.item.event_id)
        if index == 0:
            continue
        previous = ordered[index - 1]
        if entry.item.global_sequence <= previous.item.global_sequence:
            _fail("execution revision does not advance the company cursor")
        if any(entry.payload[field] != previous.payload[field] for field in _EXECUTION_IDENTITY_FIELDS):
            _fail("execution revision immutable identity differs")
        if previous.payload["job_ids"] != entry.payload["job_ids"][:len(previous.payload["job_ids"])]:
            _fail("execution revision rewrites durable job history")
        if previous.payload["evidence_ids"] != entry.payload["evidence_ids"][:len(previous.payload["evidence_ids"])]:
            _fail("execution revision rewrites durable evidence history")
        if entry.payload["usage_cursor"] < previous.payload["usage_cursor"]:
            _fail("execution revision regresses usage cursor")
        if _timestamp(entry.payload["updated_at"]) < _timestamp(previous.payload["updated_at"]):
            _fail("execution revision regresses updated_at")
    return ordered


def select_current_execution(
    values: list[tuple[InvariantObject, dict[str, Any]]], execution_id: str,
) -> HistoryEntry:
    """Validate and select the reducer-current ExecutionNode witness."""
    if type(values) is not list:
        _fail("current execution witnesses are invalid")
    witnesses = tuple(item for item, payload in values if payload.get("execution_id") == execution_id)
    history = validate_execution_history(witnesses, execution_id)
    return history[-1]


def validate_execution_predecessor_pair(
    predecessor: InvariantObject,
    producer: InvariantObject,
) -> tuple[HistoryEntry, HistoryEntry]:
    """Require a real earlier execution revision immediately before producer."""
    _, _, _, _, _ = _identity(predecessor)
    _, _, _, _, _ = _identity(producer)
    try:
        predecessor_payload = validate_execution_node(predecessor.payload)
        producer_payload = validate_execution_node(producer.payload)
    except CompanyContractError as exc:
        raise AcceptanceHistoryError(f"execution predecessor witness is invalid: {exc}") from exc
    if predecessor_payload["execution_id"] != producer_payload["execution_id"]:
        _fail("execution predecessor and producer differ")
    history = validate_execution_history(
        (predecessor, producer), producer_payload["execution_id"],
    )
    if history != (HistoryEntry(predecessor, predecessor_payload), HistoryEntry(producer, producer_payload)):
        _fail("execution predecessor is not the immediate earlier revision")
    return history[0], history[1]
