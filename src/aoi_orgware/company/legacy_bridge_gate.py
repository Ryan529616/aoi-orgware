"""Read-only exact-current preflight for one legacy bridge ingest scope.

This module proves only that the current legacy source bytes have (or have not)
been durably observed at the exact current company projection head.  A
``satisfied`` result is one necessary structural precondition for a later
legacy-controlled spawn/job launch; it is not mutation, dispatch, job-launch,
or provider authority.  Provider runtime coverage remains an independent axis.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any, NamedTuple, Never

from aoi_orgware.frozen_json import thaw_frozen_json, thaw_json_payload

from .contracts import (
    CompanyContractError,
    company_contract_sha256,
    validate_company_event,
    validate_company_transaction_receipt,
    validate_company_transaction_request,
)
from .ledger import LedgerEventRecord, LedgerTransactionRecord
from .legacy_bridge_health import (
    LEGACY_BRIDGE_COVERAGE_V1,
    MAX_SOURCE_DOCUMENT_BYTES,
    legacy_bridge_attempt_id,
    validate_legacy_bridge_coverage,
)
from .legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    validate_legacy_bridge_observation,
)
from .readmodel import ProjectedObject
from .state import CompanyQuerySnapshot, CompanyStateOwner


_SHA256 = re.compile(r"[0-9a-f]{64}")
_DECISIONS = frozenset({"satisfied", "blocked", "unknown"})
_REASONS = frozenset(
    {
        "current_structural_ingest_observed",
        "current_ingest_degraded",
        "current_source_not_observed",
        "current_health_missing",
        "company_state_degraded",
    }
)


class LegacyBridgeGateError(CompanyContractError):
    """The exact-current legacy bridge preflight cannot be derived safely."""


class LegacyBridgePrestartGateV1(NamedTuple):
    """Deep-immutable evidence for one non-authoritative pre-start check."""

    schema_version: int
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    bridge_scope_id: str
    decision: str
    reason: str
    ingest_state: str
    provider_coverage_state: str
    source_currentness: str
    source_document_sha256: str
    source_document_size_bytes: int
    ledger_cursor: int
    ledger_head_sha256: str
    readmodel_cursor: int
    readmodel_head_sha256: str
    pointer_sha256: str
    transaction_id: str | None
    command_id: str | None
    transaction_sha256: str | None
    coverage_record_id: str | None
    coverage_event_id: str | None
    coverage_global_sequence: int | None
    coverage_payload_sha256: str | None
    observation_record_id: str | None
    observation_event_id: str | None
    observation_global_sequence: int | None
    observation_payload_sha256: str | None
    assessment_id: str | None
    observation_id: str | None
    publication_effect: str
    authority: str
    repo_write_capability: str
    dispatch_capability: str
    job_launch_capability: str
    gate_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self._asdict())


def _fail(message: str) -> Never:
    raise LegacyBridgeGateError(message)


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


def _exact_identity(snapshot: CompanyQuerySnapshot) -> tuple[str, int, int]:
    health = snapshot.health
    identity = health.ledger_heads.identity
    readmodel = health.readmodel_head
    if (
        type(identity) is not tuple
        or len(identity) != 3
        or type(identity[0]) is not str
        or not identity[0]
        or type(identity[1]) is not int
        or type(identity[2]) is not int
        or identity[1] < 1
        or identity[2] < 0
        or (readmodel.company_id, readmodel.company_incarnation,
            readmodel.lock_domain_generation) != identity
    ):
        _fail("legacy bridge gate company identity is unavailable")
    return identity


def _head_values(snapshot: CompanyQuerySnapshot) -> tuple[int, str, int, str]:
    ledger = snapshot.health.ledger_heads.global_head
    readmodel = snapshot.health.readmodel_head
    values: tuple[tuple[Any, Any], ...] = (
        (ledger.global_sequence, ledger.transaction_sha256),
        (readmodel.global_sequence, readmodel.transaction_sha256),
    )
    for cursor, digest in values:
        if (
            type(cursor) is not int
            or cursor < 1
            or type(digest) is not str
            or _SHA256.fullmatch(digest) is None
        ):
            _fail("legacy bridge gate company head is unavailable")
    return (
        ledger.global_sequence,
        ledger.transaction_sha256,
        readmodel.global_sequence,
        readmodel.transaction_sha256,
    )


def _durable_attempt(
    state: CompanyStateOwner,
    *,
    attempt_id: str,
    coverage_item: ProjectedObject,
    coverage_payload: dict[str, Any],
    observation_item: ProjectedObject | None,
    observation_payload: dict[str, Any] | None,
) -> tuple[str, str, str]:
    """Bind projected current objects to their exact immutable ledger event."""

    transaction_id = f"legacy-bridge-transaction-{attempt_id}"
    command_id = f"legacy-bridge-command-{attempt_id}"
    record = CompanyStateOwner.record_by_transaction_id(state, transaction_id)
    if (
        type(record) is not LedgerTransactionRecord
        or type(record.global_sequence) is not int
        or record.global_sequence != coverage_item.global_sequence
        or type(record.events) is not tuple
        or record.reservations
    ):
        _fail("legacy bridge gate durable attempt record differs")
    try:
        request_plain = thaw_frozen_json(thaw_json_payload(record.request))
        receipt_plain = thaw_frozen_json(thaw_json_payload(record.receipt))
        request = validate_company_transaction_request(request_plain)
        receipt = validate_company_transaction_receipt(receipt_plain)
    except MemoryError:
        raise
    except Exception as exc:
        raise LegacyBridgeGateError(
            "legacy bridge gate durable attempt envelope is invalid"
        ) from exc
    if (
        request["transaction_id"] != transaction_id
        or request["command_id"] != command_id
        or receipt["transaction_id"] != transaction_id
        or receipt["command_id"] != command_id
        or receipt["state"] != "committed"
        or receipt["global_sequence"] != record.global_sequence
    ):
        _fail("legacy bridge gate durable attempt identity differs")
    expected: tuple[tuple[str, str, dict[str, Any], ProjectedObject], ...]
    if observation_item is None or observation_payload is None:
        expected = ((
            "legacy.bridge.coverage",
            f"legacy-bridge-event-1-{attempt_id}",
            coverage_payload,
            coverage_item,
        ),)
    else:
        expected = (
            (
                "legacy.bridge.observation",
                f"legacy-bridge-event-1-{attempt_id}",
                observation_payload,
                observation_item,
            ),
            (
                "legacy.bridge.coverage",
                f"legacy-bridge-event-2-{attempt_id}",
                coverage_payload,
                coverage_item,
            ),
        )
    if len(record.events) != len(expected):
        _fail("legacy bridge gate durable attempt membership differs")
    for wrapped, (event_type, event_id, payload, projected) in zip(
        record.events,
        expected,
        strict=True,
    ):
        if type(wrapped) is not LedgerEventRecord:
            _fail("legacy bridge gate durable event type is invalid")
        try:
            event_plain = thaw_frozen_json(thaw_json_payload(wrapped.event))
            event = validate_company_event(event_plain)
        except MemoryError:
            raise
        except Exception as exc:
            raise LegacyBridgeGateError(
                "legacy bridge gate durable event is invalid"
            ) from exc
        if (
            event["transaction_id"] != transaction_id
            or event["command_id"] != command_id
            or event["event_id"] != event_id
            or event["event_type"] != event_type
            or event["stream"] != "evidence"
            or event["provenance"] != "adapter_receipt_persisted"
            or event["payload"] != payload
            or event["payload_sha256"] != company_contract_sha256(payload)
            or projected.event_id != event_id
            or projected.global_sequence != record.global_sequence
        ):
            _fail("legacy bridge gate durable event differs from projection")
    transaction_sha256 = _sha(
        receipt["transaction_sha256"],
        "legacy bridge transaction digest",
    )
    return transaction_id, command_id, transaction_sha256


def _coverage_object(
    state: CompanyStateOwner,
    snapshot: CompanyQuerySnapshot,
    bridge_scope_id: str,
    *,
    company: tuple[str, int, int],
    ledger_cursor: int,
) -> tuple[
    ProjectedObject | None,
    dict[str, Any] | None,
    str | None,
    ProjectedObject | None,
    str | None,
    str | None,
    str | None,
    str | None,
]:
    matches: list[ProjectedObject] = []
    for item in snapshot.objects:
        if type(item) is not ProjectedObject:
            _fail("legacy bridge gate projected object type is invalid")
        if (
            item.contract_type == LEGACY_BRIDGE_COVERAGE_V1
            and item.object_key == bridge_scope_id
        ):
            matches.append(item)
    if not matches:
        return None, None, None, None, None, None, None, None
    if len(matches) != 1:
        _fail("legacy bridge gate current health is ambiguous")
    item = matches[0]
    if (
        type(item.record_id) is not str
        or not item.record_id
        or type(item.event_id) is not str
        or not item.event_id
        or type(item.global_sequence) is not int
        or not 1 <= item.global_sequence <= ledger_cursor
        or item.stream != "evidence"
        or not isinstance(item.payload, Mapping)
    ):
        _fail("legacy bridge gate current health metadata is malformed")
    try:
        plain = thaw_json_payload(item.payload)
        if type(plain) is not dict:
            _fail("legacy bridge gate current health payload is malformed")
        payload = validate_legacy_bridge_coverage(plain)
        payload_sha256 = company_contract_sha256(payload)
    except MemoryError:
        raise
    except LegacyBridgeGateError:
        raise
    except Exception as exc:
        raise LegacyBridgeGateError(
            "legacy bridge gate current health payload is invalid"
        ) from exc
    if payload["bridge_scope_id"] != bridge_scope_id:
        _fail("legacy bridge gate current health scope differs")
    if (
        (
            payload["company_id"],
            payload["company_incarnation"],
            payload["lock_domain_generation"],
        )
        != company
        or item.record_id != payload["assessment_id"]
    ):
        _fail("legacy bridge gate current health identity differs")
    attempt_id = legacy_bridge_attempt_id(
        bridge_scope_id,
        source_document_sha256=str(payload["source_document_sha256"]),
        source_document_size_bytes=int(payload["source_document_size_bytes"]),
    )
    event_index = 2 if payload["ingest_state"] == "observed" else 1
    if item.event_id != f"legacy-bridge-event-{event_index}-{attempt_id}":
        _fail("legacy bridge gate current health event identity differs")

    observation_item: ProjectedObject | None = None
    observation: dict[str, Any] | None = None
    observation_sha256: str | None = None
    if payload["ingest_state"] == "observed":
        observations = [
            candidate
            for candidate in snapshot.objects
            if (
                type(candidate) is ProjectedObject
                and candidate.contract_type == LEGACY_BRIDGE_OBSERVATION_V1
                and candidate.object_key == bridge_scope_id
            )
        ]
        if len(observations) != 1:
            _fail("legacy bridge gate linked observation is missing or ambiguous")
        observation_item = observations[0]
        if (
            type(observation_item.record_id) is not str
            or type(observation_item.event_id) is not str
            or type(observation_item.global_sequence) is not int
            or observation_item.stream != "evidence"
            or observation_item.global_sequence != item.global_sequence
            or observation_item.event_id
            != f"legacy-bridge-event-1-{attempt_id}"
            or observation_item.event_id == item.event_id
            or not isinstance(observation_item.payload, Mapping)
        ):
            _fail("legacy bridge gate linked observation metadata differs")
        try:
            observation_plain = thaw_json_payload(observation_item.payload)
            if type(observation_plain) is not dict:
                _fail("legacy bridge gate linked observation payload is malformed")
            observation = validate_legacy_bridge_observation(observation_plain)
            observation_sha256 = company_contract_sha256(observation)
        except MemoryError:
            raise
        except LegacyBridgeGateError:
            raise
        except Exception as exc:
            raise LegacyBridgeGateError(
                "legacy bridge gate linked observation payload is invalid"
            ) from exc
        if (
            (
                observation["company_id"],
                observation["company_incarnation"],
                observation["lock_domain_generation"],
            )
            != company
            or observation["bridge_scope_id"] != bridge_scope_id
            or observation["observation_id"] != payload["observation_id"]
            or observation_item.record_id != observation["observation_id"]
        ):
            _fail("legacy bridge gate linked observation identity differs")
    transaction_id, command_id, transaction_sha256 = _durable_attempt(
        state,
        attempt_id=attempt_id,
        coverage_item=item,
        coverage_payload=payload,
        observation_item=observation_item,
        observation_payload=observation,
    )
    return (
        item,
        payload,
        payload_sha256,
        observation_item,
        observation_sha256,
        transaction_id,
        command_id,
        transaction_sha256,
    )


def _seal(unsigned: dict[str, Any]) -> LegacyBridgePrestartGateV1:
    decision = unsigned["decision"]
    reason = unsigned["reason"]
    if decision not in _DECISIONS or reason not in _REASONS:
        _fail("legacy bridge gate outcome is invalid")
    sealed = {
        **unsigned,
        "gate_sha256": company_contract_sha256(
            {"domain": "aoi.legacy-bridge.prestart-gate.v1", **unsigned}
        ),
    }
    return LegacyBridgePrestartGateV1(**sealed)


def _derive_from_snapshot(
    state: CompanyStateOwner,
    snapshot: CompanyQuerySnapshot,
    scope: str,
    source_sha256: str,
    source_size: int,
) -> LegacyBridgePrestartGateV1:
    if type(snapshot) is not CompanyQuerySnapshot:
        _fail("legacy bridge gate current snapshot type is invalid")
    company_id, company_incarnation, lock_generation = _exact_identity(snapshot)
    company = (company_id, company_incarnation, lock_generation)
    ledger_cursor, ledger_head, readmodel_cursor, readmodel_head = _head_values(
        snapshot
    )
    pointer_sha256 = _sha(snapshot.health.pointer_sha256, "company pointer digest")
    healthy = (
        snapshot.health.status == "ready"
        and snapshot.health.ledger_status == "ready"
        and snapshot.health.projection_status == "ready"
        and snapshot.health.blob_status == "ready"
        and ledger_cursor == readmodel_cursor
        and ledger_head == readmodel_head
    )
    (
        item,
        payload,
        payload_sha256,
        observation_item,
        observation_payload_sha256,
        transaction_id,
        command_id,
        transaction_sha256,
    ) = _coverage_object(
        state,
        snapshot,
        scope,
        company=company,
        ledger_cursor=ledger_cursor,
    )

    if not healthy:
        decision = "unknown"
        reason = "company_state_degraded"
        ingest_state = "unknown"
        coverage_state = "unknown"
        currentness = "unknown"
        publication_effect = "unknown"
    elif payload is None:
        decision = "unknown"
        reason = "current_health_missing"
        ingest_state = "unknown"
        coverage_state = "unknown"
        currentness = "missing"
        publication_effect = "unknown"
    elif (
        payload["source_document_sha256"] != source_sha256
        or payload["source_document_size_bytes"] != source_size
    ):
        decision = "blocked"
        reason = "current_source_not_observed"
        ingest_state = str(payload["ingest_state"])
        coverage_state = str(payload["coverage_state"])
        currentness = "stale"
        publication_effect = "unknown"
    elif payload["ingest_state"] == "degraded":
        decision = "blocked"
        reason = "current_ingest_degraded"
        ingest_state = "degraded"
        coverage_state = str(payload["coverage_state"])
        currentness = "exact"
        publication_effect = "durable_readback"
    elif payload["ingest_state"] == "observed":
        decision = "satisfied"
        reason = "current_structural_ingest_observed"
        ingest_state = "observed"
        coverage_state = str(payload["coverage_state"])
        currentness = "exact"
        publication_effect = "durable_readback"
    else:  # Contract validation above makes this unreachable.
        _fail("legacy bridge gate current ingest state is invalid")

    return _seal(
        {
            "schema_version": 1,
            "company_id": company_id,
            "company_incarnation": company_incarnation,
            "lock_domain_generation": lock_generation,
            "bridge_scope_id": scope,
            "decision": decision,
            "reason": reason,
            "ingest_state": ingest_state,
            "provider_coverage_state": coverage_state,
            "source_currentness": currentness,
            "source_document_sha256": source_sha256,
            "source_document_size_bytes": source_size,
            "ledger_cursor": ledger_cursor,
            "ledger_head_sha256": ledger_head,
            "readmodel_cursor": readmodel_cursor,
            "readmodel_head_sha256": readmodel_head,
            "pointer_sha256": pointer_sha256,
            "transaction_id": transaction_id,
            "command_id": command_id,
            "transaction_sha256": transaction_sha256,
            "coverage_record_id": None if item is None else item.record_id,
            "coverage_event_id": None if item is None else item.event_id,
            "coverage_global_sequence": (
                None if item is None else item.global_sequence
            ),
            "coverage_payload_sha256": payload_sha256,
            "observation_record_id": (
                None if observation_item is None else observation_item.record_id
            ),
            "observation_event_id": (
                None if observation_item is None else observation_item.event_id
            ),
            "observation_global_sequence": (
                None
                if observation_item is None
                else observation_item.global_sequence
            ),
            "observation_payload_sha256": observation_payload_sha256,
            "assessment_id": None if payload is None else payload["assessment_id"],
            "observation_id": None if payload is None else payload["observation_id"],
            "publication_effect": publication_effect,
            "authority": "none",
            "repo_write_capability": "absent",
            "dispatch_capability": "absent",
            "job_launch_capability": "absent",
        }
    )


def derive_legacy_bridge_prestart_gate(
    state: CompanyStateOwner,
    bridge_scope_id: str,
    source_document: bytes,
) -> LegacyBridgePrestartGateV1:
    """Derive one current, read-only, non-authoritative structural preflight.

    A matching durable ``ingest_state=observed`` satisfies this one bridge
    condition even though provider runtime coverage remains degraded.  Missing,
    stale, degraded, or unhealthy state never satisfies the preflight.
    """

    if type(state) is not CompanyStateOwner:
        _fail("legacy bridge gate requires exact CompanyStateOwner")
    scope = _sha(bridge_scope_id, "legacy bridge scope id")
    if (
        type(source_document) is not bytes
        or len(source_document) > MAX_SOURCE_DOCUMENT_BYTES
    ):
        _fail("legacy bridge gate source document exceeds its bounded API")
    try:
        # Bind the public implementation on the exact owner class so an
        # ordinary instance attribute cannot select a stale snapshot.
        snapshot = CompanyStateOwner.query_snapshot(state)
        result = _derive_from_snapshot(
            state,
            snapshot,
            scope,
            hashlib.sha256(source_document).hexdigest(),
            len(source_document),
        )
        current = CompanyStateOwner.heads(state)
        if (
            current.identity
            != (
                result.company_id,
                result.company_incarnation,
                result.lock_domain_generation,
            )
            or current.global_head.global_sequence != result.ledger_cursor
            or current.global_head.transaction_sha256
            != result.ledger_head_sha256
        ):
            _fail("legacy bridge gate company head changed during derivation")
        return result
    except LegacyBridgeGateError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise LegacyBridgeGateError(
            "legacy bridge gate current snapshot is unavailable"
        ) from exc


__all__ = [
    "LegacyBridgeGateError",
    "LegacyBridgePrestartGateV1",
    "derive_legacy_bridge_prestart_gate",
]
