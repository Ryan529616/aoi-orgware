"""Supervisor-owned append-once publication of legacy job terminal truth."""
from __future__ import annotations

import hashlib
from typing import Any, Mapping, NamedTuple, NoReturn

from ..frozen_json import thaw_frozen_json, thaw_json_payload
from .contracts import (
    BLOB_REF_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from .ledger import (
    LedgerCommitEffectUnknownError,
    LedgerConflictError,
    LedgerTransactionRecord,
)
from .legacy_bridge_contract import (
    LEGACY_BRIDGE_OBSERVATION_V1,
    validate_legacy_bridge_observation,
)
from .legacy_bridge_job_terminal import (
    LEGACY_BRIDGE_JOB_TERMINAL_RECEIPT_V1,
    LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE,
    build_legacy_bridge_job_terminal_receipt,
    build_legacy_bridge_job_terminal_source,
    legacy_bridge_job_terminal_ledger_recorded_at,
)
from .supervisor import CompanySupervisor
from .state import CompanyStateInvariantError
from .transactions import CompanyEventDraft, build_company_transaction_request


class LegacyBridgeJobTerminalPublicationError(RuntimeError):
    """Terminal evidence cannot be joined or durably published exactly once."""


class LegacyBridgeJobTerminalPublicationResult(NamedTuple):
    transaction_id: str
    command_id: str
    bridge_scope_id: str
    terminal_key_id: str
    receipt_id: str
    effect: str
    global_sequence: int | None
    idempotent_replay: bool


def _fail(message: str) -> NoReturn:
    raise LegacyBridgeJobTerminalPublicationError(message)


def _plain(value: Any) -> Any:
    return thaw_frozen_json(thaw_json_payload(value))


def _wire_id(kind: str, receipt_id: str) -> str:
    return f"legacy-terminal-{kind}-{receipt_id}"


def _current_observation(
    supervisor: CompanySupervisor,
    bridge_scope_id: str,
) -> tuple[Any, dict[str, Any]]:
    matches = [
        item for item in CompanySupervisor.objects(
            supervisor, contract_type=LEGACY_BRIDGE_OBSERVATION_V1,
        )
        if item.payload.get("bridge_scope_id") == bridge_scope_id
    ]
    if len(matches) != 1:
        _fail("legacy terminal current observation is missing or ambiguous")
    projected = matches[0]
    try:
        observation = validate_legacy_bridge_observation(_plain(projected.payload))
    except Exception as exc:
        raise LegacyBridgeJobTerminalPublicationError(
            "legacy terminal current observation is invalid",
        ) from exc
    if (
        projected.record_id != observation["observation_id"]
        or projected.global_sequence < 1
    ):
        _fail("legacy terminal current observation metadata differs")
    return projected, observation


def _raw_ref(supervisor: CompanySupervisor, source_bytes: bytes) -> dict[str, Any]:
    metadata = supervisor._state.blobs.put(source_bytes)
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": LEGACY_BRIDGE_JOB_TERMINAL_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }


def _store_terminal_artifacts(
    supervisor: CompanySupervisor,
    references: Any,
    artifact_payloads: Any,
) -> None:
    if (
        type(references) is not list
        or type(artifact_payloads) is not tuple
        or len(references) != len(artifact_payloads)
    ):
        _fail("legacy terminal artifact payload set differs")
    for reference, member in zip(references, artifact_payloads, strict=True):
        if (
            type(reference) is not dict
            or type(member) is not tuple
            or len(member) != 2
            or type(member[0]) is not str
            or type(member[1]) is not bytes
        ):
            _fail("legacy terminal artifact payload is invalid")
        role, payload = member
        expected_sha = reference.get("sha256")
        expected_size = reference.get("size_bytes")
        if (
            reference.get("role") != role
            or expected_sha != hashlib.sha256(payload).hexdigest()
            or expected_size != len(payload)
        ):
            _fail("legacy terminal artifact payload binding differs")
        metadata = supervisor._state.blobs.put(payload)
        verified = supervisor._state.blobs.metadata(str(expected_sha))
        if (
            metadata.sha256 != expected_sha
            or metadata.size_bytes != expected_size
            or verified.sha256 != expected_sha
            or verified.size_bytes != expected_size
            or supervisor._state.blobs.read(str(expected_sha)) != payload
        ):
            _fail("legacy terminal artifact CAS readback differs")


def _request(
    supervisor: CompanySupervisor,
    receipt: Mapping[str, Any],
    *,
    recorded_at: str,
) -> dict[str, Any]:
    receipt_id = str(receipt["receipt_id"])
    return build_company_transaction_request(
        CompanySupervisor.heads(supervisor),
        CompanySupervisor._supervisor_authority(supervisor),
        transaction_id=_wire_id("transaction", receipt_id),
        command_id=_wire_id("command", receipt_id),
        events=[CompanyEventDraft(
            event_id=_wire_id("event", receipt_id),
            event_type="legacy.bridge.job_terminal.reconciled",
            recorded_at=recorded_at,
            payload=receipt,
            provenance="adapter_receipt_persisted",
        )],
    )


def _result_from_record(
    record: LedgerTransactionRecord,
    *,
    receipt: Mapping[str, Any],
    replay: bool,
) -> LegacyBridgeJobTerminalPublicationResult:
    receipt_id = str(receipt["receipt_id"])
    transaction_id = _wire_id("transaction", receipt_id)
    command_id = _wire_id("command", receipt_id)
    if (
        type(record) is not LedgerTransactionRecord
        or record.global_sequence < 1
        or record.request.get("transaction_id") != transaction_id
        or record.request.get("command_id") != command_id
        or len(record.events) != 1
        or _plain(record.events[0].event.get("payload")) != dict(receipt)
        or record.events[0].event.get("event_id") != _wire_id("event", receipt_id)
        or record.receipt.get("state") != "committed"
    ):
        _fail("legacy terminal durable record differs")
    return LegacyBridgeJobTerminalPublicationResult(
        transaction_id,
        command_id,
        str(receipt["bridge_scope_id"]),
        str(receipt["terminal_key_id"]),
        receipt_id,
        "committed",
        record.global_sequence,
        replay,
    )


def publish_legacy_bridge_job_terminal(
    supervisor: CompanySupervisor,
    evidence: Mapping[str, Any],
    artifact_payloads: tuple[tuple[str, bytes], ...],
) -> LegacyBridgeJobTerminalPublicationResult:
    """Join evidence to the current observation and append one receipt."""

    if (
        type(supervisor) is not CompanySupervisor
        or type(evidence) is not dict
        or type(artifact_payloads) is not tuple
    ):
        _fail("legacy terminal publisher inputs are invalid")
    bridge_scope_id = str(evidence.get("bridge_scope_id", ""))
    projected, observation = _current_observation(supervisor, bridge_scope_id)
    try:
        source = build_legacy_bridge_job_terminal_source(
            evidence,
            source_observation_id=str(observation["observation_id"]),
            source_observation_payload_sha256=company_contract_sha256(observation),
            source_observation_global_sequence=projected.global_sequence,
        )
        _store_terminal_artifacts(
            supervisor, source["artifacts"], artifact_payloads,
        )
        source_bytes = canonical_company_json_bytes(source)
        raw_ref = _raw_ref(supervisor, source_bytes)
        receipt = build_legacy_bridge_job_terminal_receipt(
            source,
            source_sha256=str(raw_ref["sha256"]),
            raw_artifact=raw_ref,
        )
    except LegacyBridgeJobTerminalPublicationError:
        raise
    except Exception as exc:
        raise LegacyBridgeJobTerminalPublicationError(
            "legacy terminal source or receipt is invalid",
        ) from exc
    recorded_at = legacy_bridge_job_terminal_ledger_recorded_at(
        receipt["observed_at"],
    )
    request = _request(supervisor, receipt, recorded_at=recorded_at)
    transaction_id = str(request["transaction_id"])
    durable = CompanySupervisor.record_by_transaction_id(
        supervisor, transaction_id,
    )
    if durable is not None:
        return _result_from_record(durable, receipt=receipt, replay=True)
    try:
        committed = CompanySupervisor.commit(
            supervisor, request, recorded_at=recorded_at,
        )
    except LedgerCommitEffectUnknownError:
        return LegacyBridgeJobTerminalPublicationResult(
            transaction_id,
            str(request["command_id"]),
            bridge_scope_id,
            str(receipt["terminal_key_id"]),
            str(receipt["receipt_id"]),
            "effect_unknown",
            None,
            False,
        )
    except LedgerConflictError:
        raced = CompanySupervisor.record_by_transaction_id(
            supervisor, transaction_id,
        )
        if raced is None:
            raise
        return _result_from_record(raced, receipt=receipt, replay=True)
    except CompanyStateInvariantError as exc:
        raise LegacyBridgeJobTerminalPublicationError(
            "legacy terminal receipt conflicts with durable truth",
        ) from exc
    return _result_from_record(
        committed.record, receipt=receipt,
        replay=bool(committed.idempotent_replay),
    )


__all__ = [
    "LegacyBridgeJobTerminalPublicationError",
    "LegacyBridgeJobTerminalPublicationResult",
    "publish_legacy_bridge_job_terminal",
]
