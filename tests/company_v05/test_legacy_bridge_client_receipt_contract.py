from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest

from aoi_orgware.company import legacy_bridge_client as client
from aoi_orgware.company import legacy_bridge_client_receipt_contract as contract
from aoi_orgware.company import legacy_bridge_client_receipts as receipts
from aoi_orgware.company.contracts import (
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.legacy_bridge import normalize_legacy_bridge_snapshot
from aoi_orgware.company.legacy_bridge_contract import (
    build_legacy_bridge_observation,
    legacy_bridge_scope_id,
)
from aoi_orgware.company.legacy_bridge_control_protocol import (
    LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
    build_legacy_bridge_prestart_query,
)
from aoi_orgware.company.legacy_bridge_health import legacy_bridge_attempt_id
from aoi_orgware.company.legacy_bridge_ingest_protocol import (
    build_legacy_bridge_ingest_wire_result,
    build_legacy_bridge_ingest_command,
)
from aoi_orgware.company.legacy_bridge_publisher import LegacyBridgeIngestResult


T0 = "2026-08-05T08:00:00Z"
ARCHIVE = "a" * 64
MANIFEST = "b" * 64
STATE = "c" * 64


def _source() -> bytes:
    return canonical_company_json_bytes({
        "document_type": "legacy_bridge_snapshot_v1",
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_kind": "aoi_legacy_v04",
        "source_version": "0.4.0a4",
        "legacy_archive_sha256": ARCHIVE,
        "legacy_state_sha256": STATE,
        "legacy_receipt_set_sha256": None,
        "legacy_receipt_quality": "unavailable",
        "observed_at": T0,
        "task_id": "task-1",
        "entries": [{
            "kind": "task",
            "legacy_id": "task-1",
            "parent_kind": None,
            "parent_legacy_id": None,
            "stated_status": "active",
            "source_record_sha256": hashlib.sha256(b"task-1").hexdigest(),
            "receipt_refs": [],
        }],
    })


def _prepared() -> tuple[bytes, dict[str, object]]:
    source = _source()
    projection = normalize_legacy_bridge_snapshot(source)
    scope = legacy_bridge_scope_id(
        projection.key,
        legacy_archive_sha256=ARCHIVE,
        task_identity_digest=projection.task_identity_digest,
    )
    attempt = legacy_bridge_attempt_id(
        scope,
        source_document_sha256=hashlib.sha256(source).hexdigest(),
        source_document_size_bytes=len(source),
    )
    command = build_legacy_bridge_ingest_command(
        service_instance_id="resident-1",
        company_id="company-1",
        company_incarnation=1,
        lock_domain_generation=1,
        manifest_sha256=MANIFEST,
        source_document=source,
        task_identity_digest=projection.task_identity_digest,
        legacy_archive_sha256=ARCHIVE,
        received_at=T0,
    )
    return source, client._prepared(
        command,
        projection,
        "task-1",
        "0.4.0a4",
        scope,
        attempt,
    )


def _reseal(schema: str, value: dict[str, object]) -> dict[str, object]:
    payload = {
        name: member
        for name, member in value.items()
        if name not in {"schema_version", "receipt_sha256"}
    }
    return receipts.seal(schema, payload)


def _ingest_command(source: bytes, prepared: dict[str, object]) -> Any:
    return build_legacy_bridge_ingest_command(
        service_instance_id=cast(str, prepared["service_instance_id"]),
        company_id=cast(str, prepared["company_id"]),
        company_incarnation=cast(int, prepared["company_incarnation"]),
        lock_domain_generation=cast(int, prepared["lock_domain_generation"]),
        manifest_sha256=cast(str, prepared["manifest_sha256"]),
        source_document=source,
        task_identity_digest=cast(str, prepared["task_identity_digest"]),
        legacy_archive_sha256=cast(str, prepared["legacy_archive_sha256"]),
        received_at=cast(str, prepared["received_at"]),
    )


def _post_result(source: bytes, prepared: dict[str, object]) -> dict[str, Any]:
    command = _ingest_command(source, prepared)
    projection = normalize_legacy_bridge_snapshot(source)
    observation = build_legacy_bridge_observation(
        projection,
        ingested_at=cast(str, prepared["received_at"]),
    )
    result = LegacyBridgeIngestResult(
        transaction_id=cast(str, prepared["transaction_id"]),
        command_id=cast(str, prepared["command_id"]),
        bridge_scope_id=cast(str, prepared["bridge_scope_id"]),
        assessment_id=company_contract_sha256({
            "domain": "aoi.legacy-bridge.coverage.v1",
            "attempt_id": prepared["attempt_id"],
        }),
        observation_id=cast(str, observation["observation_id"]),
        ingest_state="observed",
        coverage_state="degraded",
        effect="none",
        global_sequence=7,
        idempotent_replay=False,
    )
    return build_legacy_bridge_ingest_wire_result(command, result).as_dict()


def _query_result(source: bytes, prepared: dict[str, object]) -> dict[str, Any]:
    command = build_legacy_bridge_prestart_query(
        service_instance_id=cast(str, prepared["service_instance_id"]),
        company_id=cast(str, prepared["company_id"]),
        company_incarnation=cast(int, prepared["company_incarnation"]),
        lock_domain_generation=cast(int, prepared["lock_domain_generation"]),
        manifest_sha256=cast(str, prepared["manifest_sha256"]),
        bridge_scope_id=cast(str, prepared["bridge_scope_id"]),
        source_document=source,
    )
    observation = build_legacy_bridge_observation(
        normalize_legacy_bridge_snapshot(source),
        ingested_at=cast(str, prepared["received_at"]),
    )
    gate: dict[str, Any] = {
        "schema_version": 1,
        "company_id": command.company_id,
        "company_incarnation": command.company_incarnation,
        "lock_domain_generation": command.lock_domain_generation,
        "bridge_scope_id": command.bridge_scope_id,
        "decision": "satisfied",
        "reason": "current_structural_ingest_observed",
        "ingest_state": "observed",
        "provider_coverage_state": "degraded",
        "source_currentness": "exact",
        "source_document_sha256": command.source_document_sha256,
        "source_document_size_bytes": len(source),
        "ledger_cursor": 7,
        "ledger_head_sha256": "1" * 64,
        "readmodel_cursor": 7,
        "readmodel_head_sha256": "1" * 64,
        "pointer_sha256": "2" * 64,
        "transaction_id": prepared["transaction_id"],
        "command_id": prepared["command_id"],
        "transaction_sha256": "3" * 64,
        "coverage_record_id": "coverage-1",
        "coverage_event_id": "coverage-event-1",
        "coverage_global_sequence": 7,
        "coverage_payload_sha256": "4" * 64,
        "observation_record_id": "observation-1",
        "observation_event_id": "observation-event-1",
        "observation_global_sequence": 7,
        "observation_payload_sha256": "5" * 64,
        "assessment_id": "assessment-1",
        "observation_id": observation["observation_id"],
        "publication_effect": "durable_readback",
        "authority": "none",
        "repo_write_capability": "absent",
        "dispatch_capability": "absent",
        "job_launch_capability": "absent",
    }
    gate["gate_sha256"] = company_contract_sha256({
        "domain": "aoi.legacy-bridge.prestart-gate.v1",
        **gate,
    })
    return {
        "schema_version": LEGACY_BRIDGE_PRESTART_RESULT_SCHEMA,
        "service_instance_id": command.service_instance_id,
        "company_id": command.company_id,
        "company_incarnation": command.company_incarnation,
        "lock_domain_generation": command.lock_domain_generation,
        "manifest_sha256": command.manifest_sha256,
        "bridge_scope_id": command.bridge_scope_id,
        "cursor": 7,
        "gate": gate,
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("company_id", "company-2"),
        ("company_incarnation", "1"),
        ("lock_domain_generation", True),
        ("source_version", "0.4.0a3"),
        ("task_id", "task-2"),
        ("task_identity_digest", "x"),
        ("legacy_archive_sha256", "x"),
        ("bridge_scope_id", "d" * 64),
        ("attempt_id", "e" * 64),
        ("transaction_id", "legacy-bridge-transaction-wrong"),
        ("request_sha256", "f" * 64),
        ("received_at", "2026-08-05T09:00:00Z"),
    ],
)
def test_self_sealed_prepared_source_semantic_forgery_is_rejected(
    field: str,
    replacement: object,
) -> None:
    source, prepared = _prepared()
    forged = dict(prepared)
    forged[field] = replacement

    with pytest.raises(contract.ReceiptContractError, match="semantic_binding"):
        contract.validate_prepared(_reseal(receipts.PREPARED_SCHEMA, forged), source)


def test_terminal_none_cannot_be_resealed_as_committed_reconciliation() -> None:
    source, prepared = _prepared()
    prepared = contract.validate_prepared(prepared, source)
    terminal = receipts.seal(receipts.TERMINAL_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "post_kind": "operation_error",
        "post_code": "service_binding_mismatch",
        "post_status": 409,
        "post_cursor": None,
        "post_effect": "none",
        "post_result": None,
        "wire_result_sha256": None,
        "query_state": "unavailable",
        "query_result": None,
        "query_service_instance_id": None,
        "gate_decision": None,
        "gate_reason": None,
        "gate_cursor": None,
        "gate_sha256": None,
        "effect": "none",
        "exit_code": 2,
        "terminal_at": T0,
    })
    terminal = contract.validate_terminal(terminal, prepared, source)
    for field in ("post_code", "post_status"):
        forged_terminal = dict(terminal)
        forged_terminal[field] = None
        with pytest.raises(
            contract.ReceiptContractError,
            match="(post_mismatch|invalid_post)",
        ):
            contract.validate_terminal(
                _reseal(receipts.TERMINAL_SCHEMA, forged_terminal), prepared, source,
            )
    reconciliation = receipts.seal(receipts.RECONCILIATION_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "terminal_receipt_sha256": terminal["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "query_result": _query_result(source, prepared),
        "query_service_instance_id": "resident-1",
        "gate_decision": "satisfied",
        "gate_reason": "current_structural_ingest_observed",
        "gate_cursor": 7,
        "gate_sha256": "1" * 64,
        "effect": "committed",
        "exit_code": 0,
        "reconciled_at": T0,
    })

    with pytest.raises(contract.ReceiptContractError, match="binding_mismatch"):
        contract.validate_reconciliation(reconciliation, prepared, terminal, source)


def test_terminal_receipt_cannot_predate_its_prepared_observation() -> None:
    source, prepared = _prepared()
    prepared = contract.validate_prepared(prepared, source)
    terminal = receipts.seal(receipts.TERMINAL_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "post_kind": "operation_error",
        "post_code": "service_binding_mismatch",
        "post_status": 409,
        "post_cursor": None,
        "post_effect": "none",
        "post_result": None,
        "wire_result_sha256": None,
        "query_state": "unavailable",
        "query_result": None,
        "query_service_instance_id": None,
        "gate_decision": None,
        "gate_reason": None,
        "gate_cursor": None,
        "gate_sha256": None,
        "effect": "none",
        "exit_code": 2,
        "terminal_at": "2026-08-05T07:59:59Z",
    })

    with pytest.raises(
        contract.ReceiptContractError,
        match="terminal_receipt_monotonicity_mismatch",
    ):
        contract.validate_terminal(terminal, prepared, source)


def test_terminal_effect_must_follow_durable_query_and_wire_shape() -> None:
    source, prepared = _prepared()
    prepared = contract.validate_prepared(prepared, source)
    forged = receipts.seal(receipts.TERMINAL_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "post_kind": "success",
        "post_code": None,
        "post_status": None,
        "post_cursor": 7,
        "post_effect": "committed",
        "post_result": None,
        "wire_result_sha256": None,
        "query_state": "unavailable",
        "query_result": None,
        "query_service_instance_id": None,
        "gate_decision": None,
        "gate_reason": None,
        "gate_cursor": None,
        "gate_sha256": None,
        "effect": "committed",
        "exit_code": 0,
        "terminal_at": T0,
    })

    with pytest.raises(contract.ReceiptContractError, match="post_mismatch"):
        contract.validate_terminal(forged, prepared, source)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("gate_decision", "blocked"), ("query_service_instance_id", None)],
)
def test_committed_terminal_binds_gate_decision_and_query_service(
    field: str,
    replacement: object,
) -> None:
    source, prepared = _prepared()
    prepared = contract.validate_prepared(prepared, source)
    post_result = _post_result(source, prepared)
    query_result = _query_result(source, prepared)
    gate = cast(dict[str, Any], query_result["gate"])
    terminal = receipts.seal(receipts.TERMINAL_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "post_kind": "success",
        "post_code": None,
        "post_status": None,
        "post_cursor": 7,
        "post_effect": "committed",
        "post_result": post_result,
        "wire_result_sha256": hashlib.sha256(
            canonical_company_json_bytes(post_result),
        ).hexdigest(),
        "query_state": "resident_durable_readback",
        "query_result": query_result,
        "query_service_instance_id": "resident-1",
        "gate_decision": "satisfied",
        "gate_reason": "current_structural_ingest_observed",
        "gate_cursor": 7,
        "gate_sha256": gate["gate_sha256"],
        "effect": "committed",
        "exit_code": 0,
        "terminal_at": T0,
    })
    forged = dict(terminal)
    forged[field] = replacement
    with pytest.raises(contract.ReceiptContractError, match="(gate|effect)_mismatch"):
        contract.validate_terminal(
            _reseal(receipts.TERMINAL_SCHEMA, forged), prepared, source,
        )


@pytest.mark.parametrize(
    ("decision", "exit_code"),
    [("blocked", 0), ("satisfied", 4)],
)
def test_reconciliation_binds_gate_decision_to_exit(
    decision: str,
    exit_code: int,
) -> None:
    source, prepared = _prepared()
    prepared = contract.validate_prepared(prepared, source)
    terminal = receipts.seal(receipts.TERMINAL_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "post_kind": "transport_or_decode_error",
        "post_code": "effect_unknown",
        "post_status": None,
        "post_cursor": None,
        "post_effect": "effect_unknown",
        "post_result": None,
        "wire_result_sha256": None,
        "query_state": "unavailable",
        "query_result": None,
        "query_service_instance_id": "resident-1",
        "gate_decision": None,
        "gate_reason": None,
        "gate_cursor": None,
        "gate_sha256": None,
        "effect": "effect_unknown",
        "exit_code": 3,
        "terminal_at": T0,
    })
    terminal = contract.validate_terminal(terminal, prepared, source)
    query_result = _query_result(source, prepared)
    gate = cast(dict[str, Any], query_result["gate"])
    reconciliation = receipts.seal(receipts.RECONCILIATION_SCHEMA, {
        "prepared_receipt_sha256": prepared["receipt_sha256"],
        "terminal_receipt_sha256": terminal["receipt_sha256"],
        "attempt_id": prepared["attempt_id"],
        "query_result": query_result,
        "query_service_instance_id": "resident-1",
        "gate_decision": decision,
        "gate_reason": "current_structural_ingest_observed",
        "gate_cursor": 7,
        "gate_sha256": gate["gate_sha256"],
        "effect": "committed",
        "exit_code": exit_code,
        "reconciled_at": T0,
    })
    with pytest.raises(contract.ReceiptContractError, match="binding_mismatch"):
        contract.validate_reconciliation(reconciliation, prepared, terminal, source)
