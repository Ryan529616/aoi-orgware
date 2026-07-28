"""Canonical transaction construction for the sole AOI company writer.

This module creates no authority and performs no I/O.  The Supervisor supplies
one already-issued actor authority, a bounded ledger-head snapshot, and
projectable company contracts.  The builder binds every nested object to one
company incarnation and produces the exact compare-and-swap request accepted
by :class:`CompanyLedger`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from typing import Any

from .contracts import (
    ALERT_V1,
    ARTIFACT_EDGE_V1,
    AUTHORITY_GRANT_V1,
    BACKUP_ENVELOPE_V1,
    CANARY_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_EVENT_V1,
    COMPANY_MANIFEST_V1,
    COMPANY_TRANSACTION_REQUEST_V1,
    CONTROL_INTENT_V1,
    CRYPTO_VERIFICATION_RECEIPT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXPECTED_HEAD_V1,
    EXPECTED_TRANSACTION_HEAD_V1,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    NEEDS_USER_V1,
    NEEDS_USER_REVISION_V1,
    OPTIMIZER_PROPOSAL_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_CODEX_HOME_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    RATE_CARD_V1,
    ROUTE_POLICY_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    TASK_REVISION_V1,
    USAGE_BURN_REVISION_V1,
    USAGE_COUNTER_SAMPLE_V1,
    USAGE_EVENT_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    ZERO_SHA256,
    company_contract_sha256,
    validate_actor_authority,
    validate_company_contract,
    validate_company_transaction_request,
)
from .ledger import LedgerHeadsSnapshot


class CompanyTransactionBuildError(ValueError):
    """A Supervisor transaction cannot be constructed unambiguously."""


@dataclass(frozen=True)
class CompanyEventDraft:
    """One immutable event requested for the next company transaction."""

    event_id: str
    event_type: str
    recorded_at: str
    payload: Mapping[str, Any]
    provenance: str = "AOI_verified"


_STREAM_ORDER = ("org", "execution", "evidence", "usage", "alert")
_PROJECTABLE_STREAM = {
    COMPANY_MANIFEST_V1: "org",
    AUTHORITY_GRANT_V1: "org",
    TAKEOVER_CAPABILITY_V1: "org",
    TAKEOVER_CONSUMPTION_RECEIPT_V1: "org",
    ORGANIZATION_NODE_V1: "org",
    DEPARTMENT_IDENTITY_V1: "org",
    DEPARTMENT_SNAPSHOT_V1: "org",
    CHIEF_TERM_V1: "org",
    CARRIER_BINDING_V1: "org",
    ROUTE_POLICY_V1: "org",
    TASK_REVISION_V1: "org",
    WORK_DEFINITION_ENFORCEMENT_V1: "org",
    EXECUTION_NODE_V1: "execution",
    EXECUTION_EVENT_V1: "execution",
    CONTROL_INTENT_V1: "execution",
    MUTATION_INTENT_V1: "execution",
    EXTERNAL_JOB_V1: "execution",
    DISPATCH_REQUEST_V1: "execution",
    WORK_PACKET_V1: "execution",
    WORK_DISPATCH_BINDING_V1: "execution",
    PROVIDER_CODEX_HOME_V1: "execution",
    PROVIDER_LAUNCH_BINDING_V1: "execution",
    PROVIDER_WORKER_OPERATION_V1: "execution",
    PROVIDER_WORKER_IO_RECEIPT_V1: "evidence",
    PROVIDER_TURN_RESULT_RECEIPT_V1: "evidence",
    EXTERNAL_JOB_EFFECT_RECEIPT_V1: "evidence",
    WORK_RESULT_RECEIPT_V1: "evidence",
    PROVIDER_LIFECYCLE_RECEIPT_V1: "evidence",
    ENGINEERING_DISPOSITION_RECEIPT_V1: "evidence",
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1: "evidence",
    EVIDENCE_RECORD_V1: "evidence",
    ARTIFACT_EDGE_V1: "evidence",
    OPTIMIZER_PROPOSAL_V1: "evidence",
    CANARY_V1: "evidence",
    BACKUP_ENVELOPE_V1: "evidence",
    CRYPTO_VERIFICATION_RECEIPT_V1: "evidence",
    USAGE_EVENT_V1: "usage",
    USAGE_BURN_REVISION_V1: "usage",
    RATE_CARD_V1: "usage",
    ALERT_V1: "alert",
    NEEDS_USER_V1: "alert",
    NEEDS_USER_REVISION_V1: "alert",
    PROVIDER_TELEMETRY_RECEIPT_V1: "evidence",
    PROVIDER_COVERAGE_REVISION_V1: "evidence",
    USAGE_COUNTER_SAMPLE_V1: "usage",
}


def _binding(value: Mapping[str, Any]) -> tuple[str, int, int]:
    return (
        str(value["company_id"]),
        int(value["company_incarnation"]),
        int(value["lock_domain_generation"]),
    )


def build_company_transaction_request(
    heads: LedgerHeadsSnapshot,
    authority: Mapping[str, Any],
    *,
    transaction_id: str,
    command_id: str,
    events: Sequence[CompanyEventDraft],
) -> dict[str, Any]:
    """Build and validate one exact multi-stream CAS transaction request.

    Empty-ledger bootstrap derives the company binding from ``authority``.
    Once the ledger is bound, the authority must match its durable identity.
    Event order is caller-defined and preserved; expected stream heads use a
    fixed order so equivalent input produces byte-identical request data.
    """

    if not events:
        raise CompanyTransactionBuildError(
            "company transaction requires at least one event",
        )
    actor = validate_actor_authority(authority)
    identity = _binding(actor)
    if heads.identity is not None and heads.identity != identity:
        raise CompanyTransactionBuildError(
            "actor authority differs from the durable ledger identity",
        )

    binding = {
        "company_id": identity[0],
        "company_incarnation": identity[1],
        "lock_domain_generation": identity[2],
    }
    wrapped_events: list[dict[str, Any]] = []
    touched_streams: set[str] = set()
    for draft in events:
        payload = validate_company_contract(draft.payload)
        if _binding(payload) != identity:
            raise CompanyTransactionBuildError(
                "event payload differs from the transaction company binding",
            )
        contract_type = str(payload["contract_type"])
        if (
            contract_type == DISPATCH_REQUEST_V1
            and str(payload["command_id"]) != command_id
        ):
            raise CompanyTransactionBuildError(
                "DispatchRequest command_id differs from the transaction command_id",
            )
        if contract_type == PROVIDER_TELEMETRY_RECEIPT_V1 and (
            str(payload["transaction_id"]) != transaction_id
            or str(payload["command_id"]) != command_id
        ):
            raise CompanyTransactionBuildError(
                "ProviderTelemetryReceipt differs from the outer transaction or command",
            )
        if contract_type == WORK_DISPATCH_BINDING_V1 and (
            str(payload["transaction_id"]) != transaction_id
            or str(payload["command_id"]) != command_id
        ):
            raise CompanyTransactionBuildError(
                "WorkDispatchBinding differs from the outer transaction or command",
            )
        stream = _PROJECTABLE_STREAM.get(contract_type)
        if stream is None:
            raise CompanyTransactionBuildError(
                f"contract is not projectable: {contract_type}",
            )
        touched_streams.add(stream)
        wrapped_events.append(
            {
                "contract_type": COMPANY_EVENT_V1,
                "schema_version": 1,
                **binding,
                "transaction_id": transaction_id,
                "command_id": command_id,
                "event_id": draft.event_id,
                "stream": stream,
                "event_type": draft.event_type,
                "recorded_at": draft.recorded_at,
                # Canonical JSON rejects repeated container identity even when
                # values are equal.  Each envelope therefore owns a detached
                # authority value; equality is rechecked by the validator.
                "actor_authority": copy.deepcopy(actor),
                "provenance": draft.provenance,
                "payload": payload,
                "payload_sha256": company_contract_sha256(payload),
            },
        )

    takeover_capabilities = [
        event["payload"]
        for event in wrapped_events
        if event["payload"]["contract_type"] == TAKEOVER_CAPABILITY_V1
    ]
    takeover_receipts = [
        event["payload"]
        for event in wrapped_events
        if event["payload"]["contract_type"]
        == TAKEOVER_CONSUMPTION_RECEIPT_V1
    ]
    if takeover_capabilities or takeover_receipts:
        if (
            len(takeover_capabilities) != 1
            or len(takeover_receipts) != 1
        ):
            raise CompanyTransactionBuildError(
                "takeover requires exactly one capability and consumption receipt",
            )
        capability = takeover_capabilities[0]
        receipt = takeover_receipts[0]
        if (
            receipt["capability"] != capability
            or receipt["capability_sha256"]
            != capability["capability_sha256"]
            or capability["consumption_id"] != receipt["consumption_id"]
            or capability["consumption_transaction_id"] != transaction_id
            or capability["consumption_command_id"] != command_id
            or receipt["transaction_id"] != transaction_id
            or receipt["command_id"] != command_id
        ):
            raise CompanyTransactionBuildError(
                "takeover capability and receipt differ from the outer command",
            )

    expected_heads: list[dict[str, Any]] = []
    for stream in _STREAM_ORDER:
        if stream not in touched_streams:
            continue
        cursor, digest = heads.stream_heads.get(
            stream,
            (0, ZERO_SHA256),
        )
        expected_heads.append(
            {
                "contract_type": EXPECTED_HEAD_V1,
                "schema_version": 1,
                **binding,
                "transaction_id": transaction_id,
                "command_id": command_id,
                "stream": stream,
                "cursor": cursor,
                "event_sha256": digest,
            },
        )

    request: dict[str, Any] = {
        "contract_type": COMPANY_TRANSACTION_REQUEST_V1,
        "schema_version": 1,
        **binding,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "actor_authority": actor,
        "expected_transaction_head": {
            "contract_type": EXPECTED_TRANSACTION_HEAD_V1,
            "schema_version": 1,
            **binding,
            "transaction_id": transaction_id,
            "command_id": command_id,
            "global_sequence": heads.global_head.global_sequence,
            "transaction_sha256": heads.global_head.transaction_sha256,
        },
        "expected_heads": expected_heads,
        "events": wrapped_events,
    }
    request["request_sha256"] = company_contract_sha256(request)
    return validate_company_transaction_request(request)


__all__ = [
    "CompanyEventDraft",
    "CompanyTransactionBuildError",
    "build_company_transaction_request",
]
