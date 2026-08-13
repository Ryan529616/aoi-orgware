"""Adversarial public-API coverage for provider lifecycle receipt admission."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    COMPANY_MANIFEST_V1,
    DEPARTMENT_IDENTITY_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
    validate_carrier_binding,
)
from aoi_orgware.company.ledger import LedgerCorruptionError
from aoi_orgware.company.supervisor import (
    CompanyDepartmentLifecycleError,
    CompanySupervisor,
    _department_dispatch_event_id,
    _department_dispatch_execution_id,
    _department_known_carrier,
    _department_lead_execution,
    _known_carrier_from_provider_receipt,
    _next_department_dispatch_payload,
    _provider_lifecycle_drafts,
    _provider_lifecycle_evidence,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"


def _manifest() -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows" if os.name == "nt" else "posix",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def _chief_carrier() -> dict[str, Any]:
    return {
        "carrier_id": "carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "session_id": "session-1",
        "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _department_carrier() -> dict[str, str]:
    return {
        "carrier_id": "rtl-carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "effort": "high",
        "session_id": "rtl-session-1",
        "thread_id": "rtl-thread-1",
    }


def _initialize(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        known_carrier=_chief_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )


def _objects(supervisor: CompanySupervisor, contract_type: str) -> list[dict[str, Any]]:
    return [dict(item.payload) for item in supervisor.objects(contract_type=contract_type)]


def _rtl_department_id(supervisor: CompanySupervisor) -> str:
    return str(next(
        item["department_id"]
        for item in _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        if item["name"] == "RTL"
    ))


def _in_flight_dispatch(
    supervisor: CompanySupervisor,
    *,
    dispatch_request_id: str = "rtl-dispatch",
) -> str:
    department_id = _rtl_department_id(supervisor)
    dispatch_suffix = dispatch_request_id.removeprefix("rtl-dispatch").lstrip("-")
    if dispatch_request_id == "rtl-dispatch":
        supervisor.resume_department(
            department_id,
            transaction_id="resume-transaction",
            command_id="resume-command",
            requested_at="2026-07-27T00:01:00Z",
            recorded_at="2026-07-27T00:02:00Z",
            dispatch_request_id=dispatch_request_id,
            reservation_id="rtl-reservation",
            task_id="rtl-task",
            packet_id="rtl-packet",
            route_policy_id="rtl-route",
            requested_role="rtl_lead",
            requested_capability_tier="standard",
        )
    else:
        supervisor.enqueue_department_dispatch(
            department_id,
            transaction_id=f"enqueue-{dispatch_suffix}-transaction",
            command_id=f"enqueue-{dispatch_suffix}-command",
            requested_at="2026-07-27T00:07:00Z",
            recorded_at="2026-07-27T00:08:00Z",
            dispatch_request_id=dispatch_request_id,
            reservation_id=f"rtl-{dispatch_suffix}-reservation",
            task_id=f"rtl-{dispatch_suffix}-task",
            packet_id=f"rtl-{dispatch_suffix}-packet",
            route_policy_id=f"rtl-{dispatch_suffix}-route",
            requested_role="rtl_lead",
            requested_capability_tier="standard",
        )
    supervisor.admit_department_dispatch(
        dispatch_request_id,
        transaction_id=(
            "admit-transaction"
            if dispatch_request_id == "rtl-dispatch"
            else f"admit-{dispatch_suffix}-transaction"
        ),
        command_id=(
            "admit-command"
            if dispatch_request_id == "rtl-dispatch"
            else f"admit-{dispatch_suffix}-command"
        ),
        recorded_at=(
            "2026-07-27T00:03:00Z"
            if dispatch_request_id == "rtl-dispatch"
            else "2026-07-27T00:09:00Z"
        ),
    )
    supervisor.begin_department_dispatch(
        dispatch_request_id,
        transaction_id=(
            "begin-transaction"
            if dispatch_request_id == "rtl-dispatch"
            else f"begin-{dispatch_suffix}-transaction"
        ),
        command_id=(
            "begin-command"
            if dispatch_request_id == "rtl-dispatch"
            else f"begin-{dispatch_suffix}-command"
        ),
        recorded_at=(
            "2026-07-27T00:04:00Z"
            if dispatch_request_id == "rtl-dispatch"
            else "2026-07-27T00:10:00Z"
        ),
    )
    return dispatch_request_id


def _dispatch(
    supervisor: CompanySupervisor,
    dispatch_request_id: str = "rtl-dispatch",
) -> dict[str, Any]:
    return next(
        item
        for item in _objects(supervisor, DISPATCH_REQUEST_V1)
        if item["dispatch_request_id"] == dispatch_request_id
    )


def _next_dispatch_revision_id(
    dispatch: dict[str, Any],
    *,
    target_state: str,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "company_id": dispatch["company_id"],
        "company_incarnation": dispatch["company_incarnation"],
        "lock_domain_generation": dispatch["lock_domain_generation"],
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "previous_revision": dispatch["revision"],
        "target_state": target_state,
        "transaction_id": transaction_id,
        "command_id": command_id,
    })
    return f"department-dispatch-revision-{digest}"


def _stored_artifact(
    supervisor: CompanySupervisor,
    content: bytes,
    *,
    media_type: str = PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
) -> dict[str, Any]:
    metadata = supervisor._state.blobs.put(content)
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": media_type,
        "availability": "available",
    }


def _receipt(
    supervisor: CompanySupervisor,
    *,
    event_kind: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    source_mutator: Callable[[dict[str, Any]], None] | None = None,
    receipt_mutator: Callable[[dict[str, Any]], None] | None = None,
    raw_bytes_mutator: Callable[[bytes], bytes] | None = None,
    artifact_media_type: str = PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    raw_artifact: dict[str, Any] | None = None,
    receipt_id: str | None = None,
    source_event_id: str | None = None,
    dispatch_request_id: str = "rtl-dispatch",
) -> dict[str, Any]:
    dispatch = _dispatch(supervisor, dispatch_request_id)
    carrier = _department_carrier()
    runtime: dict[str, Any]
    if event_kind == "dispatch_succeeded":
        digest = company_contract_sha256({
            "dispatch_request_id": dispatch["dispatch_request_id"],
            "transaction_id": transaction_id,
            "carrier_id": carrier["carrier_id"],
        })
        runtime = {
            "provider_dispatch_id": "provider-dispatch-rtl-1",
            "execution_id": f"department-lead-execution-{digest}",
            "carrier_id": carrier["carrier_id"],
            "session_id": carrier["session_id"],
            "thread_id": carrier["thread_id"],
        }
        dispatch_revision = int(dispatch["revision"]) + 1
        dispatch_revision_id = _next_dispatch_revision_id(
            dispatch,
            target_state="dispatched",
            transaction_id=transaction_id,
            command_id=command_id,
        )
    elif event_kind == "execution_stopped":
        execution = next(
            item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["dispatch_id"] == dispatch["dispatch_request_id"]
        )
        bound_carrier = next(
            item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
            if item["carrier_id"] == execution["carrier_id"]
        )
        runtime = {
            "provider_dispatch_id": dispatch["provider_dispatch_id"],
            "execution_id": execution["execution_id"],
            "carrier_id": execution["carrier_id"],
            "session_id": bound_carrier["session_id"],
            "thread_id": execution["thread_id"],
        }
        carrier = {
            **carrier,
            "provider": execution["provider"],
            "model": execution["model"],
            "effort": execution["effort"],
        }
        dispatch_revision = int(dispatch["revision"])
        dispatch_revision_id = dispatch["dispatch_revision_id"]
    elif event_kind == "dispatch_effect_unknown":
        runtime = {
            "provider_dispatch_id": None,
            "execution_id": None,
            "carrier_id": None,
            "session_id": None,
            "thread_id": None,
        }
        dispatch_revision = int(dispatch["revision"]) + 1
        dispatch_revision_id = _next_dispatch_revision_id(
            dispatch,
            target_state="effect_unknown",
            transaction_id=transaction_id,
            command_id=command_id,
        )
    else:
        raise AssertionError(f"unsupported lifecycle event {event_kind}")

    source: dict[str, Any] = {
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_event_id": (
            f"provider-event-{event_kind}-{transaction_id}"
            if source_event_id is None
            else source_event_id
        ),
        "event_kind": event_kind,
        "dispatch_request_id": dispatch["dispatch_request_id"],
        **runtime,
        "organization_node_id": dispatch["target_node_id"],
        "provider": carrier["provider"],
        "model": carrier["model"],
        "effort": carrier["effort"],
        "reconcile_ref": (
            "reconcile-unknown-effect"
            if event_kind == "dispatch_effect_unknown"
            else None
        ),
        "observed_at": recorded_at,
        "provenance": "adapter_receipt_persisted",
        "observation": (
            {"state": "partial", "reason": "collector_lag"}
            if event_kind == "dispatch_effect_unknown"
            else {"state": "known", "reason": "observed"}
        ),
    }
    if source_mutator is not None:
        source_mutator(source)
    raw_bytes = canonical_company_json_bytes(source)
    if raw_bytes_mutator is not None:
        raw_bytes = raw_bytes_mutator(raw_bytes)
    artifact = raw_artifact or _stored_artifact(
        supervisor,
        raw_bytes,
        media_type=artifact_media_type,
    )
    receipt: dict[str, Any] = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "receipt_id": (
            f"provider-receipt-{event_kind}-{transaction_id}"
            if receipt_id is None
            else receipt_id
        ),
        "source_event_id": source["source_event_id"],
        "event_kind": event_kind,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "dispatch_revision_id": dispatch_revision_id,
        "dispatch_revision": dispatch_revision,
        **runtime,
        "organization_node_id": dispatch["target_node_id"],
        "provider": carrier["provider"],
        "model": carrier["model"],
        "effort": carrier["effort"],
        "reconcile_ref": source["reconcile_ref"],
        "observed_at": recorded_at,
        "provenance": "adapter_receipt_persisted",
        "observation": source["observation"],
        "raw_artifact": artifact,
        "receipt_sha256": "0" * 64,
    }
    if receipt_mutator is not None:
        receipt_mutator(receipt)
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    })
    return receipt


def _state_snapshot(supervisor: CompanySupervisor) -> tuple[Any, ...]:
    return (
        supervisor.heads().global_head.global_sequence,
        _objects(supervisor, DISPATCH_REQUEST_V1),
        _objects(supervisor, EXECUTION_NODE_V1),
        _objects(supervisor, CARRIER_BINDING_V1),
    )


def _forged_success_commit_request(
    supervisor: CompanySupervisor,
    dispatch_request_id: str,
) -> dict[str, Any]:
    """Build a lawful success batch, except for deliberately invalid raw bytes."""

    transaction_id = "generic-commit-invalid-source-transaction"
    command_id = "generic-commit-invalid-source-command"
    recorded_at = "2026-07-27T00:05:00Z"
    current = supervisor._current_department_dispatch(dispatch_request_id)
    department_id = str(current.payload["department_id"])
    _identity, lead, _snapshot, existing_carrier = supervisor._department_context(
        department_id,
    )
    parent = next(
        item.payload
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_id"] == current.payload["parent_execution_id"]
    )
    receipt = _receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id=transaction_id,
        command_id=command_id,
        recorded_at=recorded_at,
        dispatch_request_id=dispatch_request_id,
    )
    receipt["raw_artifact"] = _stored_artifact(supervisor, b"{}")
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    })
    evidence = _provider_lifecycle_evidence(receipt)
    carrier, carrier_provenance, thread_id, effort = _department_known_carrier(
        supervisor._binding(),
        lead_node_id=str(lead.payload["node_id"]),
        known_carrier=_known_carrier_from_provider_receipt(receipt),
        recorded_at=recorded_at,
    )
    carrier_event_type = "department.carrier.bound"
    if existing_carrier is not None:
        if existing_carrier.payload["state"] != "parked":
            raise AssertionError("test setup requires no active department carrier")
        carrier = validate_carrier_binding({
            **carrier,
            "bound_at": existing_carrier.payload["bound_at"],
        })
        carrier_event_type = "department.carrier.resumed"
    execution_id = _department_dispatch_execution_id(
        current.payload,
        transaction_id=transaction_id,
        carrier_id=str(carrier["carrier_id"]),
    )
    assert receipt["execution_id"] == execution_id
    execution = _department_lead_execution(
        supervisor._binding(),
        dispatch=current.payload,
        parent=parent,
        lead=lead.payload,
        carrier=carrier,
        thread_id=thread_id,
        effort=effort,
        execution_id=execution_id,
        receipt_id=str(receipt["receipt_id"]),
        evidence_ids=[str(evidence["evidence_id"])],
        provenance=carrier_provenance,
        recorded_at=recorded_at,
    )
    dispatched = _next_department_dispatch_payload(
        current,
        target_state="dispatched",
        transaction_id=transaction_id,
        command_id=command_id,
        recorded_at=recorded_at,
        effect_evidence=[receipt["raw_artifact"]],
        reconcile_ref=None,
        provenance=carrier_provenance,
        observation={"state": "known", "reason": "observed"},
        provider_dispatch_id=str(receipt["provider_dispatch_id"]),
        execution_id=execution_id,
    )
    digest = company_contract_sha256({
        "dispatch_request_id": dispatch_request_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
    })
    drafts = [
        *_provider_lifecycle_drafts(receipt, evidence=evidence),
        CompanyEventDraft(
            event_id=f"department-carrier-bind-{digest}",
            event_type=carrier_event_type,
            recorded_at=recorded_at,
            payload=carrier,
            provenance=carrier_provenance,
        ),
        CompanyEventDraft(
            event_id=f"department-execution-{digest}",
            event_type="execution.department_lead.created",
            recorded_at=recorded_at,
            payload=execution,
            provenance=carrier_provenance,
        ),
        CompanyEventDraft(
            event_id=_department_dispatch_event_id(
                dispatched,
                transaction_id=transaction_id,
            ),
            event_type="dispatch.request.dispatched",
            recorded_at=recorded_at,
            payload=dispatched,
            provenance=carrier_provenance,
        ),
    ]
    return build_company_transaction_request(
        supervisor.heads(),
        supervisor._supervisor_authority(),
        transaction_id=transaction_id,
        command_id=command_id,
        events=drafts,
    )


def test_generic_commit_rejects_invalid_provider_source_before_runtime_mutation(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path)
    dispatch_id = _in_flight_dispatch(supervisor)
    before = _state_snapshot(supervisor)
    request = _forged_success_commit_request(supervisor, dispatch_id)

    with pytest.raises(
        CompanyStateInvariantError,
        match="provider lifecycle source bytes are invalid",
    ):
        supervisor.commit(
            request,
            recorded_at="2026-07-27T00:05:00Z",
        )

    assert _state_snapshot(supervisor) == before


def test_generic_commit_rejects_execution_stop_without_provider_membership(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path)
    dispatch_id = _in_flight_dispatch(supervisor)
    success = _receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id="valid-success-transaction",
        command_id="valid-success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    dispatched = supervisor.dispatch_department_lead(
        dispatch_id,
        success,
        transaction_id="valid-success-transaction",
        command_id="valid-success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    assert dispatched.execution_id is not None
    execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_id"] == dispatched.execution_id
    )
    transaction_id = "forged-execution-stop-transaction"
    command_id = "forged-execution-stop-command"
    recorded_at = "2026-07-27T00:06:00Z"
    forged_execution = {
        **execution,
        "runtime_status": "stopped",
        "updated_at": recorded_at,
        "last_event_at": recorded_at,
        "heartbeat_at": None,
        "current_tool": None,
        "receipt_id": "nonexistent-provider-receipt",
        "evidence_ids": [
            *execution["evidence_ids"],
            "nonexistent-provider-evidence",
        ],
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
    }
    digest = company_contract_sha256({
        "execution_id": dispatched.execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
    })
    request = build_company_transaction_request(
        supervisor.heads(),
        supervisor._supervisor_authority(),
        transaction_id=transaction_id,
        command_id=command_id,
        events=[
            CompanyEventDraft(
                event_id=f"forged-execution-stop-{digest}",
                event_type="execution.department_lead.stopped",
                recorded_at=recorded_at,
                payload=forged_execution,
                provenance="adapter_receipt_persisted",
            ),
        ],
    )
    before = _state_snapshot(supervisor)

    with pytest.raises(
        CompanyStateInvariantError,
        match="department execution status transaction membership differs",
    ):
        supervisor.commit(request, recorded_at=recorded_at)

    assert _state_snapshot(supervisor) == before


def test_adversarial_dispatch_receipts_fail_closed_without_runtime_mutation(
    tmp_path: Path,
) -> None:
    cases: tuple[tuple[str, Callable[[CompanySupervisor], dict[str, Any]]], ...] = (
        (
            "raw_literal",
            lambda supervisor: _receipt(
                supervisor,
                event_kind="dispatch_succeeded",
                transaction_id="raw-literal-transaction",
                command_id="raw-literal-command",
                recorded_at="2026-07-27T00:05:00Z",
                raw_bytes_mutator=lambda _raw: b"{}",
            ),
        ),
        (
            "wrong_media_type",
            lambda supervisor: _receipt(
                supervisor,
                event_kind="dispatch_succeeded",
                transaction_id="wrong-media-transaction",
                command_id="wrong-media-command",
                recorded_at="2026-07-27T00:05:00Z",
                artifact_media_type="application/json",
            ),
        ),
        (
            "noncanonical_json",
            lambda supervisor: _receipt(
                supervisor,
                event_kind="dispatch_succeeded",
                transaction_id="noncanonical-transaction",
                command_id="noncanonical-command",
                recorded_at="2026-07-27T00:05:00Z",
                raw_bytes_mutator=lambda raw: json.dumps(
                    json.loads(raw.decode("utf-8")),
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8"),
            ),
        ),
        (
            "source_receipt_mismatch",
            lambda supervisor: _receipt(
                supervisor,
                event_kind="dispatch_succeeded",
                transaction_id="source-mismatch-transaction",
                command_id="source-mismatch-command",
                recorded_at="2026-07-27T00:05:00Z",
                source_mutator=lambda source: source.__setitem__(
                    "model", "other-model"
                ),
            ),
        ),
        (
            "aoi_verified_provenance",
            lambda supervisor: _receipt(
                supervisor,
                event_kind="dispatch_succeeded",
                transaction_id="aoi-provenance-transaction",
                command_id="aoi-provenance-command",
                recorded_at="2026-07-27T00:05:00Z",
                receipt_mutator=lambda receipt: receipt.__setitem__(
                    "provenance", "AOI_verified"
                ),
            ),
        ),
        (
            "dispatch_revision_id_mismatch",
            lambda supervisor: _receipt(
                supervisor,
                event_kind="dispatch_succeeded",
                transaction_id="revision-id-mismatch-transaction",
                command_id="revision-id-mismatch-command",
                recorded_at="2026-07-27T00:05:00Z",
                receipt_mutator=lambda receipt: receipt.__setitem__(
                    "dispatch_revision_id", "wrong-dispatch-revision"
                ),
            ),
        ),
    )
    for label, receipt_factory in cases:
        supervisor = _initialize(tmp_path / label)
        dispatch_id = _in_flight_dispatch(supervisor)
        before = _state_snapshot(supervisor)
        receipt = receipt_factory(supervisor)

        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.dispatch_department_lead(
                dispatch_id,
                receipt,
                transaction_id=str(receipt["transaction_id"]),
                command_id=str(receipt["command_id"]),
                recorded_at=str(receipt["observed_at"]),
            )

        assert _state_snapshot(supervisor) == before, label


def test_nonexistent_stop_artifact_leaves_dispatched_runtime_unchanged(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path)
    dispatch_id = _in_flight_dispatch(supervisor)
    success = _receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id="success-transaction",
        command_id="success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    dispatched = supervisor.dispatch_department_lead(
        dispatch_id,
        success,
        transaction_id="success-transaction",
        command_id="success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    assert dispatched.execution_id is not None
    before = _state_snapshot(supervisor)
    missing_artifact = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": "f" * 64,
        "size_bytes": 1,
        "media_type": PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }
    receipt = _receipt(
        supervisor,
        event_kind="execution_stopped",
        transaction_id="missing-stop-artifact-transaction",
        command_id="missing-stop-artifact-command",
        recorded_at="2026-07-27T00:06:00Z",
        raw_artifact=missing_artifact,
    )

    with pytest.raises(CompanyDepartmentLifecycleError):
        supervisor.stop_department_execution(
            dispatched.execution_id,
            receipt,
            transaction_id="missing-stop-artifact-transaction",
            command_id="missing-stop-artifact-command",
            recorded_at="2026-07-27T00:06:00Z",
        )

    assert _state_snapshot(supervisor) == before


def test_oversized_provider_source_receipt_fails_before_ledger_mutation(
    tmp_path: Path,
) -> None:
    supervisor = _initialize(tmp_path)
    dispatch_id = _in_flight_dispatch(supervisor)
    before = _state_snapshot(supervisor)
    receipt = _receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id="oversized-source-transaction",
        command_id="oversized-source-command",
        recorded_at="2026-07-27T00:05:00Z",
        raw_bytes_mutator=lambda _raw: b"x" * (
            MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES + 1
        ),
    )
    assert receipt["raw_artifact"]["size_bytes"] > (
        MAX_PROVIDER_LIFECYCLE_SOURCE_BYTES
    )

    with pytest.raises(CompanyDepartmentLifecycleError):
        supervisor.dispatch_department_lead(
            dispatch_id,
            receipt,
            transaction_id="oversized-source-transaction",
            command_id="oversized-source-command",
            recorded_at="2026-07-27T00:05:00Z",
        )

    assert _state_snapshot(supervisor) == before


def test_effect_unknown_reused_receipt_or_source_identity_fails_closed(
    tmp_path: Path,
) -> None:
    cases: tuple[tuple[str, str, str, str, str], ...] = (
        (
            "receipt_id",
            "reused-provider-receipt",
            "reused-provider-receipt",
            "first-provider-source-event",
            "second-provider-source-event",
        ),
        (
            "source_event_id",
            "first-provider-receipt",
            "second-provider-receipt",
            "reused-provider-source-event",
            "reused-provider-source-event",
        ),
    )
    for (
        label,
        first_receipt_id,
        second_receipt_id,
        first_source_event_id,
        second_source_event_id,
    ) in cases:
        supervisor = _initialize(tmp_path / label)
        first_dispatch_id = _in_flight_dispatch(supervisor)
        first = _receipt(
            supervisor,
            event_kind="dispatch_effect_unknown",
            transaction_id="unknown-first-transaction",
            command_id="unknown-first-command",
            recorded_at="2026-07-27T00:05:00Z",
            receipt_id=first_receipt_id,
            source_event_id=first_source_event_id,
        )
        unknown = supervisor.mark_department_dispatch_effect_unknown(
            first_dispatch_id,
            first,
            transaction_id="unknown-first-transaction",
            command_id="unknown-first-command",
            recorded_at="2026-07-27T00:05:00Z",
        )
        assert unknown.dispatch_state == "effect_unknown"
        assert _dispatch(supervisor, first_dispatch_id)["state"] == "in_flight"
        second_dispatch_id = _in_flight_dispatch(
            supervisor,
            dispatch_request_id="rtl-dispatch-second",
        )
        before = _state_snapshot(supervisor)
        second = _receipt(
            supervisor,
            event_kind="dispatch_effect_unknown",
            transaction_id="unknown-second-transaction",
            command_id="unknown-second-command",
            recorded_at="2026-07-27T00:11:00Z",
            receipt_id=second_receipt_id,
            source_event_id=second_source_event_id,
            dispatch_request_id=second_dispatch_id,
        )
        assert second["receipt_sha256"] != first["receipt_sha256"]
        assert second["raw_artifact"]["sha256"] != first["raw_artifact"]["sha256"]

        with pytest.raises(
            LedgerCorruptionError,
            match="event_id was already reserved or committed: provider-lifecycle-",
        ):
            supervisor.mark_department_dispatch_effect_unknown(
                second_dispatch_id,
                second,
                transaction_id="unknown-second-transaction",
                command_id="unknown-second-command",
                recorded_at="2026-07-27T00:11:00Z",
            )

        assert _state_snapshot(supervisor) == before, label
