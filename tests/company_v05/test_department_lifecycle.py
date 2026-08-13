"""Public-API acceptance tests for durable department lifecycle transitions."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

import aoi_orgware.company.supervisor as supervisor_module
from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_DOCUMENT_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
    ENGINEERING_DISPOSITION_SOURCE_V1,
    EXECUTION_NODE_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.supervisor import (
    CompanyDepartmentLifecycleError,
    CompanySupervisor,
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


def _known_carrier() -> dict[str, Any]:
    return {
        "carrier_id": "carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "session_id": "session-1",
        "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _known_department_carrier() -> dict[str, Any]:
    return {
        "carrier_id": "rtl-carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "effort": "high",
        "session_id": "rtl-session-1",
        "thread_id": "rtl-thread-1",
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
    }


def _handoff_carrier() -> dict[str, Any]:
    return {
        "carrier_id": "carrier-2",
        "provider": "claude",
        "model": "model-2",
        "session_id": "session-2",
        "thread_id": "thread-2",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def _initialize(tmp_path: Path) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        _manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        known_carrier=_known_carrier(),
        platform="windows" if os.name == "nt" else "posix",
    )


def _objects(supervisor: CompanySupervisor, contract_type: str) -> list[dict[str, Any]]:
    return [dict(item.payload) for item in supervisor.objects(contract_type=contract_type)]


def _rtl(supervisor: CompanySupervisor) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity = next(
        item
        for item in _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        if item["name"] == "RTL"
    )
    lead = next(
        item
        for item in _objects(supervisor, ORGANIZATION_NODE_V1)
        if item["node_id"] == identity["lead_node_id"]
    )
    snapshot = next(
        item
        for item in _objects(supervisor, DEPARTMENT_SNAPSHOT_V1)
        if item["department_id"] == identity["department_id"]
    )
    return identity, lead, snapshot


def _routing(label: str) -> dict[str, str]:
    return {
        "dispatch_request_id": f"{label}-dispatch",
        "reservation_id": f"{label}-reservation",
        "task_id": f"{label}-task",
        "packet_id": f"{label}-packet",
        "route_policy_id": f"{label}-route",
        "requested_role": "rtl_lead",
        "requested_capability_tier": "standard",
    }


def _resume(
    supervisor: CompanySupervisor,
    *,
    label: str = "resume",
    requested_at: str = "2026-07-27T00:01:00Z",
    recorded_at: str = "2026-07-27T00:02:00Z",
) -> Any:
    identity, _, _ = _rtl(supervisor)
    return supervisor.resume_department(
        identity["department_id"],
        transaction_id=f"{label}-transaction",
        command_id=f"{label}-command",
        requested_at=requested_at,
        recorded_at=recorded_at,
        **_routing(label),
    )


def _stored_blob(
    supervisor: CompanySupervisor,
    content: bytes,
    *,
    media_type: str = "text/plain",
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


def _provider_receipt(
    supervisor: CompanySupervisor,
    *,
    event_kind: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    provider_dispatch_id: str | None = None,
    reconcile_ref: str | None = None,
    raw_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dispatch = _objects(supervisor, DISPATCH_REQUEST_V1)[0]
    carrier_data = _known_department_carrier()
    execution_id: str | None
    carrier_id: str | None
    session_id: str | None
    thread_id: str | None
    if event_kind == "dispatch_succeeded":
        carrier_id = str(carrier_data["carrier_id"])
        digest = company_contract_sha256({
            "dispatch_request_id": dispatch["dispatch_request_id"],
            "transaction_id": transaction_id,
            "carrier_id": carrier_id,
        })
        execution_id = f"department-lead-execution-{digest}"
        session_id = str(carrier_data["session_id"])
        thread_id = str(carrier_data["thread_id"])
        dispatch_revision = int(dispatch["revision"]) + 1
        target_state = "dispatched"
    elif event_kind == "execution_stopped":
        execution = next(
            item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["dispatch_id"] == dispatch["dispatch_request_id"]
        )
        carrier = next(
            item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
            if item["carrier_id"] == execution["carrier_id"]
        )
        execution_id = str(execution["execution_id"])
        carrier_id = str(execution["carrier_id"])
        session_id = str(carrier["session_id"])
        thread_id = str(execution["thread_id"])
        carrier_data = {
            **carrier_data,
            "provider": execution["provider"],
            "model": execution["model"],
            "effort": execution["effort"],
        }
        provider_dispatch_id = str(dispatch["provider_dispatch_id"])
        dispatch_revision = int(dispatch["revision"])
        dispatch_revision_id = str(dispatch["dispatch_revision_id"])
    else:
        execution_id = None
        carrier_id = None
        session_id = None
        thread_id = None
        dispatch_revision = int(dispatch["revision"]) + 1
        target_state = {
            "dispatch_failed": "failed_known",
            "dispatch_effect_unknown": "effect_unknown",
        }[event_kind]
    if event_kind != "execution_stopped":
        revision_digest = company_contract_sha256({
            "company_id": dispatch["company_id"],
            "company_incarnation": dispatch["company_incarnation"],
            "lock_domain_generation": dispatch["lock_domain_generation"],
            "dispatch_request_id": dispatch["dispatch_request_id"],
            "previous_revision": dispatch["revision"],
            "target_state": target_state,
            "transaction_id": transaction_id,
            "command_id": command_id,
        })
        dispatch_revision_id = (
            f"department-dispatch-revision-{revision_digest}"
        )
    observation = (
        {"state": "partial", "reason": "collector_lag"}
        if event_kind == "dispatch_effect_unknown"
        else {"state": "known", "reason": "observed"}
    )
    source_event_id = f"provider-event-{event_kind}-{transaction_id}"
    if raw_artifact is None:
        source = {
            "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "source_event_id": source_event_id,
            "event_kind": event_kind,
            "dispatch_request_id": dispatch["dispatch_request_id"],
            "provider_dispatch_id": provider_dispatch_id,
            "execution_id": execution_id,
            "carrier_id": carrier_id,
            "organization_node_id": dispatch["target_node_id"],
            "provider": carrier_data["provider"],
            "model": carrier_data["model"],
            "effort": carrier_data["effort"],
            "session_id": session_id,
            "thread_id": thread_id,
            "reconcile_ref": reconcile_ref,
            "observed_at": recorded_at,
            "provenance": "adapter_receipt_persisted",
            "observation": observation,
        }
        artifact = _stored_blob(
            supervisor,
            canonical_company_json_bytes(source),
            media_type=PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
        )
    else:
        artifact = raw_artifact
    receipt: dict[str, Any] = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "receipt_id": f"provider-receipt-{event_kind}-{transaction_id}",
        "source_event_id": source_event_id,
        "event_kind": event_kind,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "dispatch_revision_id": dispatch_revision_id,
        "dispatch_revision": dispatch_revision,
        "provider_dispatch_id": provider_dispatch_id,
        "execution_id": execution_id,
        "carrier_id": carrier_id,
        "organization_node_id": dispatch["target_node_id"],
        "provider": carrier_data["provider"],
        "model": carrier_data["model"],
        "effort": carrier_data["effort"],
        "session_id": session_id,
        "thread_id": thread_id,
        "reconcile_ref": reconcile_ref,
        "observed_at": recorded_at,
        "provenance": "adapter_receipt_persisted",
        "observation": observation,
        "raw_artifact": artifact,
        "receipt_sha256": "0" * 64,
    }
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value
        for key, value in receipt.items()
        if key != "receipt_sha256"
    })
    return receipt


def _engineering_disposition(
    supervisor: CompanySupervisor,
    execution_id: str,
    *,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
) -> tuple[bytes, dict[str, Any]]:
    execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["execution_id"] == execution_id
    )
    carrier = next(
        item
        for item in _objects(supervisor, CARRIER_BINDING_V1)
        if item["carrier_id"] == execution["carrier_id"]
    )
    source = {
        "source_type": ENGINEERING_DISPOSITION_SOURCE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_event_id": f"engineering-source-{transaction_id}",
        "receipt_id": f"engineering-receipt-{transaction_id}",
        "execution_id": execution_id,
        "expected_execution_payload_sha256":
            company_contract_sha256(
                supervisor_module._plain(execution),
            ),
        "reporter_execution_id": execution_id,
        "reporter_carrier_id": execution["carrier_id"],
        "provider": execution["provider"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "from_status": execution["engineering_status"],
        "to_status": "idle",
        "reason_code": "handoff_ready",
        "result_packet_id": execution["packet_id"],
        "observed_at": recorded_at,
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }
    source_bytes = canonical_company_json_bytes(source)
    artifact = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": company_contract_sha256(source),
        "size_bytes": len(source_bytes),
        "media_type": ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }
    receipt = {
        "contract_type": ENGINEERING_DISPOSITION_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        **{
            key: source[key]
            for key in (
                "source_event_id",
                "receipt_id",
                "execution_id",
                "expected_execution_payload_sha256",
                "reporter_execution_id",
                "reporter_carrier_id",
                "provider",
                "session_id",
                "thread_id",
                "from_status",
                "to_status",
                "reason_code",
                "result_packet_id",
                "observed_at",
                "provenance",
                "observation",
            )
        },
        "transaction_id": transaction_id,
        "command_id": command_id,
        "raw_artifact": artifact,
    }
    receipt["receipt_sha256"] = company_contract_sha256(receipt)
    return source_bytes, receipt


def _mutate_engineering_disposition(
    source_bytes: bytes,
    receipt: dict[str, Any],
    field: str,
    value: object,
) -> tuple[bytes, dict[str, Any]]:
    source = json.loads(source_bytes)
    source[field] = value
    mutated_bytes = canonical_company_json_bytes(source)
    mutated = copy.deepcopy(receipt)
    mutated[field] = value
    mutated["raw_artifact"]["sha256"] = company_contract_sha256(source)
    mutated["raw_artifact"]["size_bytes"] = len(mutated_bytes)
    mutated["receipt_sha256"] = company_contract_sha256({
        key: member
        for key, member in mutated.items()
        if key != "receipt_sha256"
    })
    return mutated_bytes, mutated


def _stopped_rtl_execution(
    supervisor: CompanySupervisor,
) -> str:
    _resume(supervisor)
    supervisor.admit_department_dispatch(
        "resume-dispatch",
        transaction_id="adversarial-admit-transaction",
        command_id="adversarial-admit-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    supervisor.begin_department_dispatch(
        "resume-dispatch",
        transaction_id="adversarial-start-transaction",
        command_id="adversarial-start-command",
        recorded_at="2026-07-27T00:04:00Z",
    )
    dispatched = supervisor.dispatch_department_lead(
        "resume-dispatch",
        _provider_receipt(
            supervisor,
            event_kind="dispatch_succeeded",
            transaction_id="adversarial-success-transaction",
            command_id="adversarial-success-command",
            recorded_at="2026-07-27T00:05:00Z",
            provider_dispatch_id="provider-dispatch-adversarial",
        ),
        transaction_id="adversarial-success-transaction",
        command_id="adversarial-success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    assert dispatched.execution_id is not None
    supervisor.stop_department_execution(
        dispatched.execution_id,
        _provider_receipt(
            supervisor,
            event_kind="execution_stopped",
            transaction_id="adversarial-stop-transaction",
            command_id="adversarial-stop-command",
            recorded_at="2026-07-27T00:06:00Z",
        ),
        transaction_id="adversarial-stop-transaction",
        command_id="adversarial-stop-command",
        recorded_at="2026-07-27T00:06:00Z",
    )
    return dispatched.execution_id


def _existing_json_blob(
    supervisor: CompanySupervisor,
    sha256: str,
) -> dict[str, Any]:
    metadata = supervisor._state.blobs.metadata(sha256)
    return {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": "application/json",
        "availability": "available",
    }


def _park_document(
    supervisor: CompanySupervisor,
    *,
    captured_at: str,
) -> dict[str, Any]:
    identity, lead, snapshot = _rtl(supervisor)
    named = {
        "charter_ref": _existing_json_blob(
            supervisor,
            snapshot["charter_sha256"],
        ),
        "constraints_ref": _existing_json_blob(
            supervisor,
            snapshot["constraints_sha256"],
        ),
        "decisions_ref": _existing_json_blob(
            supervisor,
            snapshot["decisions_sha256"],
        ),
        "open_questions_ref": _existing_json_blob(
            supervisor,
            snapshot["open_questions_sha256"],
        ),
        "handoff_ref": _existing_json_blob(
            supervisor,
            snapshot["handoff_sha256"],
        ),
        "dissent_ref": _stored_blob(
            supervisor,
            b'{"kind":"dissent","revision":2}',
            media_type="application/json",
        ),
        "blockers_ref": _stored_blob(
            supervisor,
            b'{"kind":"blockers","revision":2}',
            media_type="application/json",
        ),
        "risks_ref": _stored_blob(
            supervisor,
            b'{"kind":"risks","revision":2}',
            media_type="application/json",
        ),
        "backlog_ref": _stored_blob(
            supervisor,
            b'{"kind":"backlog","revision":2}',
            media_type="application/json",
        ),
    }
    return {
        "document_type": DEPARTMENT_SNAPSHOT_DOCUMENT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "department_id": identity["department_id"],
        "lead_node_id": lead["node_id"],
        "snapshot_id": "rtl-snapshot-rev2",
        "revision": snapshot["revision"] + 1,
        "previous_snapshot_id": snapshot["snapshot_id"],
        "previous_document_sha256":
            snapshot["artifact_refs"][0]["sha256"],
        "company_cursor": supervisor.heads().global_head.global_sequence + 1,
        "captured_at": captured_at,
        "capture_reason": "park",
        **named,
        "active_dispatch_request_ids": [],
        "active_execution_ids": [],
        "job_ids": [],
        "evidence_ids": [],
        "artifact_refs": [],
    }


def test_resume_then_active_enqueue_preserves_stable_department_and_lead_ids(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        before_identity, before_lead, _ = _rtl(supervisor)
        resumed = _resume(supervisor)
        assert resumed.lifecycle_state == "waking"
        assert resumed.dispatch_state == "queued"

        active_identity, active_lead, _ = _rtl(supervisor)
        assert active_identity["department_id"] == before_identity["department_id"]
        assert active_identity["lead_node_id"] == before_identity["lead_node_id"]
        assert active_lead["node_id"] == before_lead["node_id"]
        assert active_identity["status"] == active_lead["status"] == "active"

        enqueued = supervisor.enqueue_department_dispatch(
            active_identity["department_id"],
            transaction_id="active-enqueue-transaction",
            command_id="active-enqueue-command",
            requested_at="2026-07-27T00:03:00Z",
            recorded_at="2026-07-27T00:04:00Z",
            **_routing("active-enqueue"),
        )
        assert enqueued.lifecycle_state == "active"
        assert enqueued.dispatch_state == "queued"
        after_identity, after_lead, _ = _rtl(supervisor)
        assert after_identity["department_id"] == before_identity["department_id"]
        assert after_identity["lead_node_id"] == before_identity["lead_node_id"]
        assert after_lead["node_id"] == before_lead["node_id"]
        dispatches = _objects(supervisor, DISPATCH_REQUEST_V1)
        assert {item["dispatch_request_id"] for item in dispatches} == {
            "resume-dispatch", "active-enqueue-dispatch",
        }
        assert all(item["target_node_id"] == before_lead["node_id"] for item in dispatches)


def test_resume_exact_replay_is_cursor_stable_and_divergent_retry_fails_closed(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        first = _resume(supervisor)
        cursor = supervisor.heads().global_head.global_sequence
        replay = _resume(supervisor)
        assert replay.transaction_id == first.transaction_id
        assert replay.command_id == first.command_id
        assert replay.global_sequence == first.global_sequence
        assert replay.dispatch_request_id == first.dispatch_request_id
        assert replay.idempotent_replay is True
        assert supervisor.heads().global_head.global_sequence == cursor

        identity, _, _ = _rtl(supervisor)
        divergent = _routing("resume")
        divergent["task_id"] = "different-task"
        with pytest.raises(
            CompanyDepartmentLifecycleError,
            match="routing differs",
        ):
            supervisor.resume_department(
                identity["department_id"],
                transaction_id="resume-transaction",
                command_id="resume-command",
                requested_at="2026-07-27T00:01:00Z",
                recorded_at="2026-07-27T00:02:00Z",
                **divergent,
            )
        assert supervisor.heads().global_head.global_sequence == cursor


def test_chief_takeover_preserves_queued_department_dispatch_ancestry(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        _resume(supervisor)
        dispatch_before = _objects(supervisor, DISPATCH_REQUEST_V1)[0]
        capability = supervisor.prepare_chief_takeover(
            _handoff_carrier(),
            user_action_ref="user-action-department-handoff",
            objective_sha256="e" * 64,
            scope_sha256="f" * 64,
            nonce_sha256="6" * 64,
            issued_at="2026-07-27T00:03:00Z",
            expires_at="2026-07-27T01:00:00Z",
        )
        result = supervisor.takeover_chief(
            capability,
            _handoff_carrier(),
            consumed_at="2026-07-27T00:04:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        assert result.outcome == "consumed"
        dispatch_after = _objects(supervisor, DISPATCH_REQUEST_V1)[0]
        assert dispatch_after == dispatch_before
        assert dispatch_after["parent_execution_id"] == dispatch_before["parent_execution_id"]
        term = _objects(supervisor, CHIEF_TERM_V1)[0]
        assert term["carrier_id"] == "carrier-2"
        assert any(
            item["carrier_id"] == "carrier-2" and item["state"] == "active"
            for item in _objects(supervisor, CARRIER_BINDING_V1)
        )


def test_park_rejects_invalid_document_and_pending_work_without_cursor_advance(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        identity, _, _ = _rtl(supervisor)
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyDepartmentLifecycleError,
            match="snapshot document is invalid",
        ):
            supervisor.park_department(
                identity["department_id"],
                {},
                transaction_id="invalid-park-transaction",
                command_id="invalid-park-command",
                requested_at="2026-07-27T00:01:00Z",
                recorded_at="2026-07-27T00:02:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before

        _resume(supervisor)
        pending_cursor = supervisor.heads().global_head.global_sequence
        document = _park_document(
            supervisor,
            captured_at="2026-07-27T00:03:00Z",
        )
        with pytest.raises(
            (CompanyDepartmentLifecycleError, CompanyStateInvariantError),
            match="pending|active|unknown",
        ):
            supervisor.park_department(
                identity["department_id"],
                document,
                transaction_id="pending-park-transaction",
                command_id="pending-park-command",
                requested_at="2026-07-27T00:02:30Z",
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == pending_cursor


def test_automatic_dispatch_known_success_is_durable_and_provider_bound(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        _resume(supervisor)
        admitted = supervisor.admit_department_dispatch(
            "resume-dispatch",
            transaction_id="resume-admit-transaction",
            command_id="resume-admit-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        assert admitted.dispatch_state == "admitted"
        assert admitted.revision == 2
        started = supervisor.begin_department_dispatch(
            "resume-dispatch",
            transaction_id="resume-start-transaction",
            command_id="resume-start-command",
            recorded_at="2026-07-27T00:04:00Z",
        )
        assert started.dispatch_state == "in_flight"
        assert started.revision == 3
        receipt = _provider_receipt(
            supervisor,
            event_kind="dispatch_succeeded",
            transaction_id="resume-success-transaction",
            command_id="resume-success-command",
            recorded_at="2026-07-27T00:05:00Z",
            provider_dispatch_id="provider-dispatch-rtl-1",
        )
        dispatched = supervisor.dispatch_department_lead(
            "resume-dispatch",
            receipt,
            transaction_id="resume-success-transaction",
            command_id="resume-success-command",
            recorded_at="2026-07-27T00:05:00Z",
        )
        assert dispatched.dispatch_state == "dispatched"
        assert dispatched.revision == 4
        assert dispatched.receipt_state == "committed"
        assert dispatched.execution_id is not None
        assert dispatched.carrier_id == "rtl-carrier-1"
        dispatch = _objects(supervisor, DISPATCH_REQUEST_V1)[0]
        execution = next(
            item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["dispatch_id"] == "resume-dispatch"
        )
        carrier = next(
            item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
            if item["carrier_id"] == "rtl-carrier-1"
        )
        assert dispatch["execution_id"] == execution["execution_id"]
        assert dispatch["provider_dispatch_id"] == "provider-dispatch-rtl-1"
        assert execution["organization_node_id"] == carrier["actor_id"]
        assert execution["runtime_status"] == "running"
        assert execution["engineering_status"] == "active"
        assert execution["provenance"] == "adapter_receipt_persisted"

        replay = supervisor.dispatch_department_lead(
            "resume-dispatch",
            receipt,
            transaction_id="resume-success-transaction",
            command_id="resume-success-command",
            recorded_at="2026-07-27T00:05:00Z",
        )
        assert replay.idempotent_replay
        assert replay.global_sequence == dispatched.global_sequence


def test_effect_unknown_dispatch_creates_no_carrier_or_execution(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        _resume(supervisor)
        supervisor.admit_department_dispatch(
            "resume-dispatch",
            transaction_id="unknown-admit-transaction",
            command_id="unknown-admit-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.begin_department_dispatch(
            "resume-dispatch",
            transaction_id="unknown-start-transaction",
            command_id="unknown-start-command",
            recorded_at="2026-07-27T00:04:00Z",
        )
        carrier_count = len(_objects(supervisor, CARRIER_BINDING_V1))
        execution_count = len(_objects(supervisor, EXECUTION_NODE_V1))
        receipt = _provider_receipt(
            supervisor,
            event_kind="dispatch_effect_unknown",
            transaction_id="unknown-effect-transaction",
            command_id="unknown-effect-command",
            recorded_at="2026-07-27T00:05:00Z",
            reconcile_ref="reconcile-unknown-effect",
        )
        unknown = supervisor.mark_department_dispatch_effect_unknown(
            "resume-dispatch",
            receipt,
            transaction_id="unknown-effect-transaction",
            command_id="unknown-effect-command",
            recorded_at="2026-07-27T00:05:00Z",
        )
        assert unknown.dispatch_state == "effect_unknown"
        assert unknown.receipt_state == "effect_unknown"
        assert len(_objects(supervisor, CARRIER_BINDING_V1)) == carrier_count
        assert len(_objects(supervisor, EXECUTION_NODE_V1)) == execution_count
        current = _objects(supervisor, DISPATCH_REQUEST_V1)[0]
        assert current["state"] == "in_flight"
        assert current["revision"] == 3
        durable = supervisor.records_after(0)[-1]
        assert durable.events == ()
        assert len(durable.reservations) == 3
        assert durable.reservations[0].event["payload"]["contract_type"] == (
            PROVIDER_LIFECYCLE_RECEIPT_V1
        )
        assert durable.reservations[2].event["payload"]["state"] == (
            "effect_unknown"
        )


def test_provider_stopped_lead_can_checkpoint_and_park_exactly(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        _resume(supervisor)
        supervisor.admit_department_dispatch(
            "resume-dispatch",
            transaction_id="park-admit-transaction",
            command_id="park-admit-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.begin_department_dispatch(
            "resume-dispatch",
            transaction_id="park-start-transaction",
            command_id="park-start-command",
            recorded_at="2026-07-27T00:04:00Z",
        )
        dispatch_receipt = _provider_receipt(
            supervisor,
            event_kind="dispatch_succeeded",
            transaction_id="park-success-transaction",
            command_id="park-success-command",
            recorded_at="2026-07-27T00:05:00Z",
            provider_dispatch_id="provider-dispatch-park-1",
        )
        dispatched = supervisor.dispatch_department_lead(
            "resume-dispatch",
            dispatch_receipt,
            transaction_id="park-success-transaction",
            command_id="park-success-command",
            recorded_at="2026-07-27T00:05:00Z",
        )
        assert dispatched.execution_id is not None
        stop_receipt = _provider_receipt(
            supervisor,
            event_kind="execution_stopped",
            transaction_id="park-stop-transaction",
            command_id="park-stop-command",
            recorded_at="2026-07-27T00:06:00Z",
        )
        stopped = supervisor.stop_department_execution(
            dispatched.execution_id,
            stop_receipt,
            transaction_id="park-stop-transaction",
            command_id="park-stop-command",
            recorded_at="2026-07-27T00:06:00Z",
        )
        assert stopped.engineering_status == "active"
        assert stopped.runtime_status == "stopped"
        identity, _, _ = _rtl(supervisor)
        premature_document = _park_document(
            supervisor,
            captured_at="2026-07-27T00:06:10Z",
        )
        stop_cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyDepartmentLifecycleError,
            match="lacks provider-confirmed stopped execution evidence",
        ):
            supervisor.park_department(
                identity["department_id"],
                premature_document,
                transaction_id="premature-park-transaction",
                command_id="premature-park-command",
                requested_at="2026-07-27T00:06:05Z",
                recorded_at="2026-07-27T00:06:10Z",
            )
        assert supervisor.heads().global_head.global_sequence == stop_cursor
        disposition_bytes, disposition_receipt = _engineering_disposition(
            supervisor,
            dispatched.execution_id,
            transaction_id="park-idle-transaction",
            command_id="park-idle-command",
            recorded_at="2026-07-27T00:06:15Z",
        )
        idle = supervisor.record_department_execution_idle(
            dispatched.execution_id,
            disposition_bytes,
            disposition_receipt,
            transaction_id="park-idle-transaction",
            command_id="park-idle-command",
            recorded_at="2026-07-27T00:06:15Z",
        )
        assert idle.engineering_status == "idle"
        assert idle.runtime_status == "stopped"
        document = _park_document(
            supervisor,
            captured_at="2026-07-27T00:07:00Z",
        )
        parked = supervisor.park_department(
            identity["department_id"],
            document,
            transaction_id="park-final-transaction",
            command_id="park-final-command",
            requested_at="2026-07-27T00:06:30Z",
            recorded_at="2026-07-27T00:07:00Z",
        )
        assert parked.lifecycle_state == "parked"
        assert parked.snapshot_revision == 2
        parked_identity, parked_lead, parked_snapshot = _rtl(supervisor)
        assert parked_identity["status"] == "parked"
        assert parked_lead["status"] == "parked"
        assert parked_snapshot["snapshot_id"] == "rtl-snapshot-rev2"
        carrier = next(
            item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
            if item["carrier_id"] == "rtl-carrier-1"
        )
        assert carrier["state"] == "parked"
        assert carrier["session_id"] is None
        idle_replay = supervisor.record_department_execution_idle(
            dispatched.execution_id,
            disposition_bytes,
            disposition_receipt,
            transaction_id="park-idle-transaction",
            command_id="park-idle-command",
            recorded_at="2026-07-27T00:06:15Z",
        )
        assert idle_replay.idempotent_replay
        assert idle_replay.global_sequence == idle.global_sequence
        replay = supervisor.park_department(
            identity["department_id"],
            document,
            transaction_id="park-final-transaction",
            command_id="park-final-command",
            requested_at="2026-07-27T00:06:30Z",
            recorded_at="2026-07-27T00:07:00Z",
        )
        assert replay.idempotent_replay
        assert replay.global_sequence == parked.global_sequence


def test_engineering_disposition_rejects_forged_identity_and_raw_bytes(
    tmp_path: Path,
) -> None:
    with _initialize(tmp_path) as supervisor:
        execution_id = _stopped_rtl_execution(supervisor)
        source_bytes, receipt = _engineering_disposition(
            supervisor,
            execution_id,
            transaction_id="adversarial-idle-transaction",
            command_id="adversarial-idle-command",
            recorded_at="2026-07-27T00:06:15Z",
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_department_execution_idle(
                execution_id,
                source_bytes + b"\n",
                receipt,
                transaction_id="adversarial-idle-transaction",
                command_id="adversarial-idle-command",
                recorded_at="2026-07-27T00:06:15Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor

        cases = (
            ("expected_execution_payload_sha256", "f" * 64),
            ("reporter_carrier_id", "wrong-carrier"),
            ("session_id", "wrong-session"),
            ("thread_id", "wrong-thread"),
            ("result_packet_id", "wrong-packet"),
        )
        for field, value in cases:
            mutated_bytes, mutated_receipt = (
                _mutate_engineering_disposition(
                    source_bytes,
                    receipt,
                    field,
                    value,
                )
            )
            with pytest.raises(CompanyDepartmentLifecycleError):
                supervisor.record_department_execution_idle(
                    execution_id,
                    mutated_bytes,
                    mutated_receipt,
                    transaction_id="adversarial-idle-transaction",
                    command_id="adversarial-idle-command",
                    recorded_at="2026-07-27T00:06:15Z",
                )
            assert supervisor.heads().global_head.global_sequence == cursor

        invalid_bytes, invalid_receipt = _mutate_engineering_disposition(
            source_bytes,
            receipt,
            "provenance",
            "AOI_verified",
        )
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_department_execution_idle(
                execution_id,
                invalid_bytes,
                invalid_receipt,
                transaction_id="adversarial-idle-transaction",
                command_id="adversarial-idle-command",
                recorded_at="2026-07-27T00:06:15Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
