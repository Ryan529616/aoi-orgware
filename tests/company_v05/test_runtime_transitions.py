"""Runtime observation transitions never imply engineering completion."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

import aoi_orgware.company.supervisor as supervisor_module
from aoi_orgware.company.contracts import (
    ALERT_V1,
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    COMPANY_MANIFEST_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_NODE_V1,
    EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    EXECUTION_RUNTIME_OBSERVATION_SOURCE_MEDIA_TYPE,
    EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.supervisor import (
    CompanyExecutionRegistrationError,
    CompanySupervisor,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.telemetry import normalize_codex_telemetry
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)
from tests.company_v05.test_department_lifecycle import (
    _initialize as _department_supervisor,
    _provider_receipt as _department_provider_receipt,
    _resume as _resume_department,
)


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"


def _supervisor(tmp_path: Path) -> CompanySupervisor:
    manifest = {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-runtime",
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
    return CompanySupervisor.initialize(
        _state_root(tmp_path),
        manifest,
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        known_carrier={
            "carrier_id": "chief-carrier",
            "provider": "codex",
            "model": "gpt-5",
            "session_id": "chief-session",
            "thread_id": "chief-thread",
            "provenance": "agent_reported",
            "observation": {"state": "known", "reason": "observed"},
        },
        platform="windows" if os.name == "nt" else "posix",
    )


def _state_root(tmp_path: Path) -> Path:
    return tmp_path / "state" / "companies" / "company-runtime"


def _chief_execution(supervisor: CompanySupervisor) -> dict[str, Any]:
    executions = [
        dict(item.payload)
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["role"] == "chief"
        and item.payload["execution_kind"] == "carrier"
    ]
    assert len(executions) == 1
    return executions[0]


def _observation(
    supervisor: CompanySupervisor,
    execution: dict[str, Any],
    *,
    transition: str,
    at: str,
    nonce: str,
    activity_kind: str | None = None,
    provider_registry: str = "unknown",
    host_process: str = "unknown",
    terminal_grace: str = "unknown",
    collector_health: str = "healthy",
    source_event_id: str | None = None,
    provenance: str = "AOI_verified",
) -> tuple[dict[str, Any], bytes, str, str]:
    binding = supervisor._binding()
    receipt_id = f"runtime-receipt-{nonce}"
    source = {
        "source_type": EXECUTION_RUNTIME_OBSERVATION_SOURCE_V1,
        "schema_version": 1,
        **binding,
        "source_event_id": source_event_id or f"runtime-source-{nonce}",
        "receipt_id": receipt_id,
        "execution_id": execution["execution_id"],
        "carrier_id": execution["carrier_id"],
        "transition": transition,
        "activity_kind": activity_kind,
        "provider_registry": provider_registry,
        "host_process": host_process,
        "terminal_grace": terminal_grace,
        "collector_health": collector_health,
        "observed_at": at,
        "provenance": provenance,
        "observation": {"state": "known", "reason": "observed"},
    }
    source_bytes = canonical_company_json_bytes(source)
    transaction_id = f"runtime-transaction-{nonce}"
    command_id = f"runtime-command-{nonce}"
    receipt = {
        "contract_type": EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
        "schema_version": 1,
        **binding,
        "receipt_id": receipt_id,
        "source_event_id": source["source_event_id"],
        "transaction_id": transaction_id,
        "command_id": command_id,
        "execution_id": execution["execution_id"],
        "carrier_id": execution["carrier_id"],
        "transition": transition,
        "activity_kind": activity_kind,
        "provider_registry": provider_registry,
        "host_process": host_process,
        "terminal_grace": terminal_grace,
        "collector_health": collector_health,
        "observed_at": at,
        "provenance": provenance,
        "observation": {"state": "known", "reason": "observed"},
        "raw_artifact": {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
            "size_bytes": len(source_bytes),
            "media_type": EXECUTION_RUNTIME_OBSERVATION_SOURCE_MEDIA_TYPE,
            "availability": "available",
        },
        "receipt_sha256": "0" * 64,
    }
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    })
    return receipt, source_bytes, transaction_id, command_id


def _record(
    supervisor: CompanySupervisor,
    execution: dict[str, Any],
    **kwargs: Any,
) -> Any:
    receipt, source_bytes, transaction_id, command_id = _observation(
        supervisor, execution, **kwargs,
    )
    return supervisor.record_execution_runtime_observation(
        execution["execution_id"], receipt, source_bytes=source_bytes,
        transaction_id=transaction_id, command_id=command_id,
        recorded_at=kwargs["at"],
    )


def _ingest_codex_item_started(
    supervisor: CompanySupervisor,
    *,
    nonce: str,
    received_at: str,
    thread_id: str = "chief-thread",
    turn_id: str = "turn-1",
) -> str:
    raw = json.dumps({
        "method": "item/started",
        "params": {
            "threadId": thread_id,
            "turnId": turn_id,
            "startedAtMs": 12,
            "item": {
                "agentsStates": {},
                "id": f"item-{nonce}",
                "receiverThreadIds": [f"child-{nonce}"],
                "senderThreadId": thread_id,
                "status": "completed",
                "tool": "spawnAgent",
                "type": "collabAgentToolCall",
                "model": "gpt-5",
                "reasoningEffort": "high",
            },
        },
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")
    result = supervisor.ingest_codex_telemetry(
        raw,
        adapter_instance_id="runtime-test-adapter",
        adapter_event_id=f"runtime-test-event-{nonce}",
        intake_sequence=1,
        transaction_id=f"telemetry-transaction-{nonce}",
        command_id=f"telemetry-command-{nonce}",
        received_at=received_at,
    )
    assert result.dispatch_join_state == "exact"
    assert result.normalized_kind == "item_started_runtime_observed"
    return result.receipt_id


def _register_shared_turn(
    supervisor: CompanySupervisor,
    *,
    recorded_at: str,
) -> dict[str, Any]:
    chief = _chief_execution(supervisor)
    execution_id = "registered-shared-turn"
    evidence_id = "registered-shared-turn-evidence"
    registration_id = "registered-shared-turn-event"
    execution = {
        **supervisor._binding(),
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        "execution_id": execution_id,
        "execution_kind": "turn",
        "display_name": "Shared Chief turn",
        "organization_node_id": chief["organization_node_id"],
        "department_id": chief["department_id"],
        "parent_execution_id": chief["execution_id"],
        "execution_depth": chief["execution_depth"] + 1,
        "execution_path": [*chief["execution_path"], execution_id],
        "task_id": chief["task_id"],
        "packet_id": chief["packet_id"],
        "thread_id": chief["thread_id"],
        "turn_id": "provider-shared-turn",
        "agent_id": None,
        "job_id": None,
        "dispatch_id": None,
        "registration_id": registration_id,
        "receipt_id": None,
        "provider": chief["provider"],
        "model": chief["model"],
        "effort": chief["effort"],
        "carrier_id": chief["carrier_id"],
        "role": "chief_turn",
        "delegation_depth": chief["delegation_depth"],
        "engineering_status": "active",
        "runtime_status": "running",
        "attention_overlays": [],
        "objective": "Exercise execution-scoped loss on a shared carrier.",
        "phase": "provider_runtime",
        "created_at": recorded_at,
        "updated_at": recorded_at,
        "last_event_at": recorded_at,
        "heartbeat_at": recorded_at,
        "wait_reason": None,
        "current_tool": None,
        "terminal_at": None,
        "usage_cursor": 0,
        "job_ids": [],
        "evidence_ids": [evidence_id],
        "provenance": "provider_client_emitted",
        "observation": {"state": "known", "reason": "observed"},
    }
    raw = canonical_company_json_bytes(
        supervisor_module._execution_registration_event(execution),
    )
    metadata = supervisor._state.blobs.put(raw)
    evidence = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        **supervisor._binding(),
        "evidence_id": evidence_id,
        "execution_id": execution_id,
        "claim_id": registration_id,
        "evidence_class": "runtime",
        "status": "observed",
        "artifact": {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": metadata.sha256,
            "size_bytes": metadata.size_bytes,
            "media_type": EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE,
            "availability": "available",
        },
        "command_sha256": None,
        "verification_sha256": metadata.sha256,
        "recorded_at": recorded_at,
        "provenance": "provider_client_emitted",
        "observation": {"state": "known", "reason": "observed"},
    }
    supervisor.register_execution(
        execution,
        evidence,
        transaction_id="register-shared-turn-transaction",
        command_id="register-shared-turn-command",
        recorded_at=recorded_at,
    )
    return next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_id"] == execution_id
    )


def test_runtime_observation_requires_exact_recovery_and_preserves_engineering(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    original_engineering = execution["engineering_status"]
    original_phase = execution["phase"]
    original_receipt_id = execution["receipt_id"]
    original_wait_reason = execution["wait_reason"]

    silent = _record(
        supervisor, execution, transition="telemetry_silent",
        at="2026-07-27T00:01:00Z", nonce="silent-1",
    )
    assert silent.runtime_status == "telemetry_silent"
    after_silent = _chief_execution(supervisor)
    assert after_silent["engineering_status"] == original_engineering
    assert after_silent["phase"] == original_phase
    assert after_silent["receipt_id"] == original_receipt_id
    assert after_silent["wait_reason"] == original_wait_reason
    assert after_silent["attention_overlays"] == execution["attention_overlays"]

    for activity_kind in ("codex.thread_token_usage_updated", "codex.turn_completed"):
        with pytest.raises(CompanyExecutionRegistrationError, match="invalid"):
            _record(
                supervisor, after_silent, transition="recovered",
                at="2026-07-27T00:02:00Z", nonce=activity_kind.replace(".", "-"),
                activity_kind=activity_kind,
            )
    assert _chief_execution(supervisor)["runtime_status"] == "telemetry_silent"

    with pytest.raises(
        CompanyExecutionRegistrationError,
        match="durable provider receipt",
    ):
        _record(
            supervisor,
            after_silent,
            transition="recovered",
            at="2026-07-27T00:02:00Z",
            nonce="fabricated-recovered",
            activity_kind="codex.item_started",
        )
    telemetry_receipt_id = _ingest_codex_item_started(
        supervisor,
        nonce="recovered-1",
        received_at="2026-07-27T00:01:30Z",
    )
    recovered = _record(
        supervisor, after_silent, transition="recovered",
        at="2026-07-27T00:02:00Z", nonce="recovered-1",
        activity_kind="codex.item_started",
        source_event_id=telemetry_receipt_id,
    )
    assert recovered.runtime_status == "running"
    assert not recovered.idempotent_replay
    recovered_execution = _chief_execution(supervisor)
    assert recovered_execution["engineering_status"] == original_engineering
    assert recovered_execution["receipt_id"] == original_receipt_id
    assert recovered_execution["wait_reason"] == original_wait_reason
    assert recovered_execution["attention_overlays"] == execution["attention_overlays"]
    assert recovered_execution["heartbeat_at"] == "2026-07-27T00:01:30Z"

    silent_again = _record(
        supervisor, recovered_execution, transition="telemetry_silent",
        at="2026-07-27T00:03:00Z", nonce="silent-2",
    )
    assert silent_again.runtime_status == "telemetry_silent"
    with pytest.raises(CompanyExecutionRegistrationError, match="invalid"):
        _record(
            supervisor, _chief_execution(supervisor), transition="confirmed_lost",
            at="2026-07-27T00:04:00Z", nonce="loss-incomplete",
        )

    lost = _record(
        supervisor, _chief_execution(supervisor), transition="confirmed_lost",
        at="2026-07-27T00:04:00Z", nonce="loss-complete",
        provider_registry="absent", host_process="absent",
        terminal_grace="elapsed", collector_health="healthy",
    )
    assert lost.runtime_status == "confirmed_lost"
    final = _chief_execution(supervisor)
    assert final["engineering_status"] == original_engineering
    assert final["runtime_status"] == "confirmed_lost"
    assert final["receipt_id"] == original_receipt_id
    assert final["wait_reason"] == original_wait_reason
    alerts = [
        dict(item.payload)
        for item in supervisor.objects(contract_type=ALERT_V1)
    ]
    assert len(alerts) == 1
    assert alerts[0]["execution_id"] == execution["execution_id"]
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["state"] == "open"
    assert alerts[0]["category"] == "confirmed_lost"
    assert alerts[0]["detail_sha256"] != "0" * 64
    carrier = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=CARRIER_BINDING_V1)
        if item.payload["carrier_id"] == execution["carrier_id"]
    )
    assert carrier["state"] == "lost"
    assert carrier["session_availability"] == "unavailable"


def test_runtime_observation_rejects_unverified_or_unhealthy_silence(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    with pytest.raises(CompanyExecutionRegistrationError, match="invalid"):
        _record(
            supervisor,
            execution,
            transition="telemetry_silent",
            at="2026-07-27T00:01:00Z",
            nonce="agent-reported-silence",
            provenance="agent_reported",
        )
    with pytest.raises(CompanyExecutionRegistrationError, match="invalid"):
        _record(
            supervisor,
            execution,
            transition="telemetry_silent",
            at="2026-07-27T00:01:00Z",
            nonce="unhealthy-silence",
            collector_health="unhealthy",
        )
    assert _chief_execution(supervisor)["runtime_status"] == "running"


def test_runtime_recovery_rejects_activity_before_silence_boundary(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    stale_receipt_id = _ingest_codex_item_started(
        supervisor,
        nonce="stale-before-silence",
        received_at="2026-07-27T00:00:30Z",
    )
    _record(
        supervisor,
        execution,
        transition="telemetry_silent",
        at="2026-07-27T00:01:00Z",
        nonce="stale-silence",
    )
    silent = _chief_execution(supervisor)
    with pytest.raises(
        CompanyExecutionRegistrationError,
        match="binding is invalid",
    ):
        _record(
            supervisor,
            silent,
            transition="recovered",
            at="2026-07-27T00:02:00Z",
            nonce="stale-recovery",
            activity_kind="codex.item_started",
            source_event_id=stale_receipt_id,
        )
    current = _chief_execution(supervisor)
    assert current["runtime_status"] == "telemetry_silent"
    assert current["heartbeat_at"] == execution["heartbeat_at"]


def test_runtime_observation_preserves_fenced_engineering_wait_reason(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    old_execution = _chief_execution(supervisor)
    carrier = {
        "carrier_id": "replacement-carrier",
        "provider": "claude",
        "model": "claude-model",
        "session_id": "replacement-session",
        "thread_id": "replacement-thread",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }
    capability = supervisor.prepare_chief_takeover(
        carrier,
        user_action_ref="runtime-wait-reason-takeover",
        objective_sha256="e" * 64,
        scope_sha256="f" * 64,
        nonce_sha256="1" * 64,
        issued_at="2026-07-27T00:01:00Z",
        expires_at="2026-07-27T01:00:00Z",
    )
    supervisor.takeover_chief(
        capability,
        carrier,
        consumed_at="2026-07-27T00:02:00Z",
        grant_expires_at=EXPIRY,
    )
    fenced = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_id"] == old_execution["execution_id"]
    )
    assert fenced["wait_reason"] == "fenced_read_only"
    _record(
        supervisor,
        fenced,
        transition="telemetry_silent",
        at="2026-07-27T00:03:00Z",
        nonce="fenced-silent",
    )
    after = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_id"] == old_execution["execution_id"]
    )
    assert after["engineering_status"] == "waiting"
    assert after["wait_reason"] == "fenced_read_only"


def test_confirmed_loss_is_execution_scoped_on_shared_carrier(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    turn = _register_shared_turn(
        supervisor,
        recorded_at="2026-07-27T00:01:00Z",
    )
    root = _chief_execution(supervisor)
    _record(
        supervisor,
        root,
        transition="telemetry_silent",
        at="2026-07-27T00:02:00Z",
        nonce="root-silent",
    )
    _record(
        supervisor,
        _chief_execution(supervisor),
        transition="confirmed_lost",
        at="2026-07-27T00:03:00Z",
        nonce="root-lost",
        provider_registry="absent",
        host_process="absent",
        terminal_grace="elapsed",
    )
    carrier = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=CARRIER_BINDING_V1)
        if item.payload["carrier_id"] == root["carrier_id"]
    )
    assert carrier["state"] == "active"
    assert carrier["session_availability"] == "available"

    current_turn = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_id"] == turn["execution_id"]
    )
    _record(
        supervisor,
        current_turn,
        transition="telemetry_silent",
        at="2026-07-27T00:04:00Z",
        nonce="turn-silent",
    )
    current_turn = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
        if item.payload["execution_id"] == turn["execution_id"]
    )
    _record(
        supervisor,
        current_turn,
        transition="confirmed_lost",
        at="2026-07-27T00:05:00Z",
        nonce="turn-lost",
        provider_registry="absent",
        host_process="absent",
        terminal_grace="elapsed",
    )
    carrier = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=CARRIER_BINDING_V1)
        if item.payload["carrier_id"] == root["carrier_id"]
    )
    assert carrier["state"] == "lost"
    assert carrier["session_availability"] == "unavailable"
    assert len(supervisor.objects(contract_type=ALERT_V1)) == 2


def test_runtime_observation_source_event_is_single_use(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    _record(
        supervisor,
        execution,
        transition="telemetry_silent",
        at="2026-07-27T00:01:00Z",
        nonce="source-first",
        source_event_id="shared-runtime-source-event",
    )
    with pytest.raises(
        CompanyExecutionRegistrationError,
        match="already used",
    ):
        _record(
            supervisor,
            _chief_execution(supervisor),
            transition="recovered",
            at="2026-07-27T00:02:00Z",
            nonce="source-second",
            source_event_id="shared-runtime-source-event",
            activity_kind="codex.item_started",
        )
    assert len(
        supervisor.objects(
            contract_type=EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
        ),
    ) == 1


def test_dispatched_department_lead_preserves_lifecycle_receipt_across_runtime(
    tmp_path: Path,
) -> None:
    supervisor = _department_supervisor(tmp_path)
    _resume_department(supervisor)
    supervisor.admit_department_dispatch(
        "resume-dispatch",
        transaction_id="runtime-admit-transaction",
        command_id="runtime-admit-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    supervisor.begin_department_dispatch(
        "resume-dispatch",
        transaction_id="runtime-start-transaction",
        command_id="runtime-start-command",
        recorded_at="2026-07-27T00:04:00Z",
    )
    lifecycle_receipt = _department_provider_receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id="runtime-success-transaction",
        command_id="runtime-success-command",
        recorded_at="2026-07-27T00:05:00Z",
        provider_dispatch_id="runtime-provider-dispatch",
    )
    dispatched = supervisor.dispatch_department_lead(
        "resume-dispatch",
        lifecycle_receipt,
        transaction_id="runtime-success-transaction",
        command_id="runtime-success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    assert dispatched.execution_id is not None

    def current() -> dict[str, Any]:
        return next(
            dict(item.payload)
            for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == dispatched.execution_id
        )

    execution = current()
    original_receipt_id = execution["receipt_id"]
    original_provenance = execution["provenance"]
    assert original_receipt_id == lifecycle_receipt["receipt_id"]
    assert original_provenance == "adapter_receipt_persisted"

    _record(
        supervisor,
        execution,
        transition="telemetry_silent",
        at="2026-07-27T00:06:00Z",
        nonce="rtl-silent",
    )
    silent = current()
    assert silent["runtime_status"] == "telemetry_silent"
    assert silent["receipt_id"] == original_receipt_id
    assert silent["provenance"] == original_provenance

    telemetry_receipt_id = _ingest_codex_item_started(
        supervisor,
        nonce="rtl-recovered",
        received_at="2026-07-27T00:06:30Z",
        thread_id=str(execution["thread_id"]),
        turn_id="rtl-turn-1",
    )
    telemetry = next(
        dict(item.payload)
        for item in supervisor.objects(
            contract_type=PROVIDER_TELEMETRY_RECEIPT_V1,
        )
        if item.payload["receipt_id"] == telemetry_receipt_id
    )
    assert telemetry["dispatch_join"]["execution_id"] == dispatched.execution_id
    _record(
        supervisor,
        silent,
        transition="recovered",
        at="2026-07-27T00:07:00Z",
        nonce="rtl-recovered",
        activity_kind="codex.item_started",
        source_event_id=telemetry_receipt_id,
    )
    recovered = current()
    assert recovered["runtime_status"] == "running"
    assert recovered["receipt_id"] == original_receipt_id
    assert recovered["provenance"] == original_provenance
    assert recovered["heartbeat_at"] == "2026-07-27T00:06:30Z"

    _record(
        supervisor,
        recovered,
        transition="telemetry_silent",
        at="2026-07-27T00:08:00Z",
        nonce="rtl-silent-again",
    )
    _record(
        supervisor,
        current(),
        transition="confirmed_lost",
        at="2026-07-27T00:09:00Z",
        nonce="rtl-confirmed-lost",
        provider_registry="absent",
        host_process="absent",
        terminal_grace="elapsed",
    )
    lost = current()
    assert lost["runtime_status"] == "confirmed_lost"
    assert lost["engineering_status"] == execution["engineering_status"]
    assert lost["receipt_id"] == original_receipt_id
    assert lost["provenance"] == "AOI_verified"
    alert = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=ALERT_V1)
        if item.payload["execution_id"] == dispatched.execution_id
    )
    assert alert["severity"] == "critical"
    assert alert["category"] == "confirmed_lost"
    carrier = next(
        dict(item.payload)
        for item in supervisor.objects(contract_type=CARRIER_BINDING_V1)
        if item.payload["carrier_id"] == execution["carrier_id"]
    )
    assert carrier["state"] == "lost"


def test_low_level_commit_cannot_forge_foreign_telemetry_join(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    raw = json.dumps({
        "method": "item/started",
        "params": {
            "threadId": "foreign-thread",
            "turnId": "foreign-turn",
            "startedAtMs": 12,
            "item": {
                "agentsStates": {},
                "id": "foreign-item",
                "receiverThreadIds": ["foreign-child"],
                "senderThreadId": "foreign-thread",
                "status": "completed",
                "tool": "spawnAgent",
                "type": "collabAgentToolCall",
                "model": "gpt-5",
                "reasoningEffort": "high",
            },
        },
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")
    normalized = normalize_codex_telemetry(raw)
    metadata = supervisor._state.blobs.put(raw)
    binding = supervisor._binding()
    adapter_instance_id = "forged-adapter"
    adapter_event_id = "forged-event"
    transaction_id = "forged-telemetry-transaction"
    command_id = "forged-telemetry-command"
    received_at = "2026-07-27T00:01:30Z"
    candidate = {
        "execution_id": execution["execution_id"],
        "carrier_id": execution["carrier_id"],
        "dispatch_id": execution["dispatch_id"],
        "registration_id": execution["registration_id"],
    }
    forged_join = {
        "state": "exact",
        "binding_kind": "carrier",
        "registry_cursor": supervisor.heads().global_head.global_sequence,
        "dispatch_request_id": None,
        "dispatch_revision_id": None,
        "registration_id": None,
        "execution_id": execution["execution_id"],
        "carrier_id": execution["carrier_id"],
        "candidate_count": 1,
        "candidates_sha256": company_contract_sha256([candidate]),
        "reason": "exact_registered_native_identity",
    }
    receipt_id = supervisor_module._telemetry_id(
        binding,
        "receipt",
        adapter_instance_id,
        adapter_event_id,
    )
    receipt = supervisor_module._provider_telemetry_receipt_payload(
        binding,
        normalized=normalized,
        raw_artifact=supervisor_module._blob_ref(
            metadata.sha256,
            metadata.size_bytes,
            "application/vnd.aoi.provider-telemetry.raw;version=1",
        ),
        join=forged_join,
        receipt_id=receipt_id,
        adapter_instance_id=adapter_instance_id,
        adapter_event_id=adapter_event_id,
        intake_sequence=1,
        transaction_id=transaction_id,
        command_id=command_id,
        received_at=received_at,
    )
    coverage = supervisor._next_coverage_revision(
        provider="codex",
        source_class="codex_app_server",
        adapter_instance_id=adapter_instance_id,
        surface="lifecycle",
        declared_event_kinds=supervisor_module._coverage_event_kinds(
            "codex",
            "codex_app_server",
            "lifecycle",
        ),
        state="observed",
        reason="observed",
        assessment_source="receipt",
        receipt=receipt,
        dropped_event_count={
            "value": 0,
            "source": "adapter_route",
            "quality": "observed",
            "reason": "observed",
        },
        assessed_at=received_at,
    )
    request = build_company_transaction_request(
        supervisor.heads(),
        supervisor._supervisor_authority(),
        transaction_id=transaction_id,
        command_id=command_id,
        events=[
            CompanyEventDraft(
                supervisor_module._telemetry_id(
                    binding,
                    "event",
                    transaction_id,
                    "1",
                ),
                "provider.telemetry.received",
                received_at,
                receipt,
                "adapter_receipt_persisted",
            ),
            CompanyEventDraft(
                supervisor_module._telemetry_id(
                    binding,
                    "event",
                    transaction_id,
                    "2",
                ),
                "provider.coverage.lifecycle",
                received_at,
                coverage,
                "adapter_receipt_persisted",
            ),
        ],
    )
    with pytest.raises(
        CompanyStateInvariantError,
        match="dispatch join differs",
    ):
        supervisor.commit(request, recorded_at=received_at)
    assert not supervisor.objects(
        contract_type=PROVIDER_TELEMETRY_RECEIPT_V1,
    )

    _record(
        supervisor,
        execution,
        transition="telemetry_silent",
        at="2026-07-27T00:02:00Z",
        nonce="forged-join-silence",
    )
    with pytest.raises(
        CompanyExecutionRegistrationError,
        match="durable provider receipt",
    ):
        _record(
            supervisor,
            _chief_execution(supervisor),
            transition="recovered",
            at="2026-07-27T00:03:00Z",
            nonce="forged-join-recovery",
            activity_kind="codex.item_started",
            source_event_id=receipt_id,
        )


def test_runtime_observation_exact_retry_is_idempotent(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    receipt, source_bytes, transaction_id, command_id = _observation(
        supervisor, execution, transition="telemetry_silent",
        at="2026-07-27T00:01:00Z", nonce="retry",
    )
    first = supervisor.record_execution_runtime_observation(
        execution["execution_id"], receipt, source_bytes=source_bytes,
        transaction_id=transaction_id, command_id=command_id,
        recorded_at="2026-07-27T00:01:00Z",
    )
    second = supervisor.record_execution_runtime_observation(
        execution["execution_id"], receipt, source_bytes=source_bytes,
        transaction_id=transaction_id, command_id=command_id,
        recorded_at="2026-07-27T00:01:00Z",
    )
    assert not first.idempotent_replay
    assert second.idempotent_replay


def test_runtime_observation_rejects_divergent_transaction_reuse(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    receipt, source_bytes, transaction_id, command_id = _observation(
        supervisor, execution, transition="telemetry_silent",
        at="2026-07-27T00:01:00Z", nonce="collision-first",
    )
    supervisor.record_execution_runtime_observation(
        execution["execution_id"], receipt, source_bytes=source_bytes,
        transaction_id=transaction_id, command_id=command_id,
        recorded_at="2026-07-27T00:01:00Z",
    )
    divergent, divergent_source, _, _ = _observation(
        supervisor, execution, transition="telemetry_silent",
        at="2026-07-27T00:01:00Z", nonce="collision-second",
    )
    divergent["transaction_id"] = transaction_id
    divergent["command_id"] = command_id
    divergent["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in divergent.items() if key != "receipt_sha256"
    })
    with pytest.raises(CompanyExecutionRegistrationError, match="differs"):
        supervisor.record_execution_runtime_observation(
            execution["execution_id"], divergent, source_bytes=divergent_source,
            transaction_id=transaction_id, command_id=command_id,
            recorded_at="2026-07-27T00:01:00Z",
        )


def test_runtime_observation_rebuilds_and_keeps_ledger_history(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path)
    execution = _chief_execution(supervisor)
    receipt, source_bytes, transaction_id, command_id = _observation(
        supervisor, execution, transition="telemetry_silent",
        at="2026-07-27T00:01:00Z", nonce="rebuild",
    )
    supervisor.record_execution_runtime_observation(
        execution["execution_id"], receipt, source_bytes=source_bytes,
        transaction_id=transaction_id, command_id=command_id,
        recorded_at="2026-07-27T00:01:00Z",
    )
    readmodel_path = supervisor._state.resolved.incarnation.readmodel
    supervisor.close()
    readmodel_path.unlink()

    with CompanySupervisor.open(_state_root(tmp_path)) as rebuilt:
        receipts = rebuilt.objects(
            contract_type=EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
        )
        assert [item.payload["receipt_id"] for item in receipts] == [
            receipt["receipt_id"],
        ]
        assert _chief_execution(rebuilt)["runtime_status"] == "telemetry_silent"
        assert any(
            event.event["payload"]["contract_type"]
            == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1
            for record in rebuilt.records_after(0)
            for event in record.events
        )
