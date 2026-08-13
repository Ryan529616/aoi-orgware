from __future__ import annotations

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
from typing import Any, Mapping
import urllib.error
import urllib.request

import pytest

import aoi_orgware.company.supervisor as supervisor_module
from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE,
    EXTERNAL_JOB_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
    authority_from_grant,
)
from aoi_orgware.company.process_lock import CompanyProcessLockBusyError
from aoi_orgware.company.readmodel import ProjectedObject
from aoi_orgware.company.registry import CompanyRegistryError
from aoi_orgware.company.state import (
    CompanyStateInvariantError,
    CompanyStateOwner,
)
from aoi_orgware.company.supervisor import (
    CompanyChiefTakeoverError,
    CompanyDepartmentLifecycleError,
    CompanyExecutionRegistrationError,
    CompanySupervisor,
    CompanySupervisorDashboardRefreshError,
    CompanySupervisorError,
    _authority_grant,
)
from aoi_orgware.company.transactions import CompanyEventDraft, build_company_transaction_request
from aoi_orgware.company.views import CompanyViewService


T = "2026-07-27T00:00:00Z"
EXPIRY = "2026-07-28T00:00:00Z"


def manifest(company_id: str = "company-1") -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": company_id,
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


def known_carrier() -> dict[str, Any]:
    return {
        "carrier_id": "carrier-1",
        "provider": "codex",
        "model": "gpt-5",
        "session_id": "session-1",
        "thread_id": "thread-1",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def handoff_carrier(number: int) -> dict[str, Any]:
    return {
        "carrier_id": f"carrier-{number}",
        "provider": "codex" if number % 2 == 0 else "claude",
        "model": f"model-{number}",
        "session_id": f"session-{number}",
        "thread_id": f"thread-{number}",
        "provenance": "agent_reported",
        "observation": {"state": "known", "reason": "observed"},
    }


def initialize(
    tmp_path: Path,
    *,
    company_id: str = "company-1",
    carrier: Mapping[str, Any] | None = None,
) -> CompanySupervisor:
    return CompanySupervisor.initialize(
        tmp_path / "state" / "companies" / "company-1",
        manifest(company_id),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
        known_carrier=carrier,
    )


def _objects(supervisor: CompanySupervisor, contract_type: str) -> list[dict[str, Any]]:
    return [
        dict(item.payload)
        for item in supervisor.objects(contract_type=contract_type)
    ]


def prepare_handoff(
    supervisor: CompanySupervisor,
    carrier: Mapping[str, Any],
    *,
    nonce: str,
    user_action_ref: str,
) -> dict[str, Any]:
    return supervisor.prepare_chief_takeover(
        carrier,
        user_action_ref=user_action_ref,
        objective_sha256="e" * 64,
        scope_sha256="f" * 64,
        nonce_sha256=nonce,
        issued_at="2026-07-27T00:01:00Z",
        expires_at="2026-07-27T01:00:00Z",
    )


def append_queued_job(
    supervisor: CompanySupervisor,
) -> tuple[dict[str, Any], str]:
    owner = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["carrier_id"] == "carrier-1"
    )
    supervisor.queue_external_job(
        str(owner["execution_id"]),
        job_id="durable-vcs-job",
        job_execution_id="durable-vcs-job-execution",
        mutation_intent_id="durable-vcs-intent",
        command_bytes=b"x",
        command_media_type="application/json",
        scope_sha256="f" * 64,
        display_name="Durable VCS job",
        objective="Preserve one external job across Chief takeover.",
        authority_grant_id="durable-vcs-job-grant",
        grant_expires_at="2026-07-28T00:00:00Z",
        transaction_id="durable-vcs-job-transaction",
        command_id="durable-vcs-job-command",
        recorded_at="2026-07-27T00:00:30Z",
    )
    record = next(
        item
        for item in supervisor.records_after(0)
        if item.request["transaction_id"] == "durable-vcs-job-transaction"
    )
    projected = _objects(supervisor, EXTERNAL_JOB_V1)[0]
    event_sha256 = next(
        member.event_sha256
        for member in record.events
        if member.event["payload"]["contract_type"] == EXTERNAL_JOB_V1
    )
    return projected, event_sha256


def fenced_chief_stop_receipt(
    supervisor: CompanySupervisor,
    *,
    execution_id: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
) -> dict[str, Any]:
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
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "source_event_id": f"provider-stop-{transaction_id}",
        "event_kind": "execution_stopped",
        "dispatch_request_id": None,
        "provider_dispatch_id": None,
        "execution_id": execution_id,
        "carrier_id": execution["carrier_id"],
        "organization_node_id": execution["organization_node_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "reconcile_ref": None,
        "observed_at": recorded_at,
        "provenance": "host_process_observed",
        "observation": {"state": "known", "reason": "observed"},
    }
    source_bytes = canonical_company_json_bytes(source)
    metadata = supervisor._state.blobs.put(source_bytes)
    artifact = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": metadata.sha256,
        "size_bytes": metadata.size_bytes,
        "media_type": PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }
    unsigned = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "receipt_id": f"provider-stop-receipt-{transaction_id}",
        "source_event_id": source["source_event_id"],
        "event_kind": "execution_stopped",
        "transaction_id": transaction_id,
        "command_id": command_id,
        "dispatch_request_id": None,
        "dispatch_revision_id": None,
        "dispatch_revision": None,
        "provider_dispatch_id": None,
        "execution_id": execution_id,
        "carrier_id": execution["carrier_id"],
        "organization_node_id": execution["organization_node_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "reconcile_ref": None,
        "observed_at": recorded_at,
        "provenance": "host_process_observed",
        "observation": {"state": "known", "reason": "observed"},
        "raw_artifact": artifact,
    }
    return {
        **unsigned,
        "receipt_sha256": company_contract_sha256(unsigned),
    }


def registration_evidence(
    supervisor: CompanySupervisor,
    *,
    execution: Mapping[str, Any],
    evidence_id: str,
    provenance: str = "provider_client_emitted",
) -> dict[str, Any]:
    source = supervisor_module._execution_registration_event(execution)
    raw = canonical_company_json_bytes(source)
    metadata = supervisor._state.blobs.put(raw)
    return {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "evidence_id": evidence_id,
        "execution_id": execution["execution_id"],
        "claim_id": execution["registration_id"],
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
        "recorded_at": execution["created_at"],
        "provenance": provenance,
        "observation": {"state": "known", "reason": "observed"},
    }


def registered_turn(
    supervisor: CompanySupervisor,
    *,
    execution_id: str = "registered-turn-execution",
    registration_id: str = "registered-turn-event",
    evidence_id: str = "registered-turn-evidence",
    recorded_at: str = "2026-07-27T00:01:00Z",
) -> tuple[dict[str, Any], dict[str, Any]]:
    chief = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["role"] == "chief"
        and item["parent_execution_id"] is None
    )
    execution = {
        **{
            key: chief[key]
            for key in (
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
            )
        },
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        "execution_id": execution_id,
        "execution_kind": "turn",
        "display_name": "Chief turn",
        "organization_node_id": chief["organization_node_id"],
        "department_id": chief["department_id"],
        "parent_execution_id": chief["execution_id"],
        "execution_depth": chief["execution_depth"] + 1,
        "execution_path": [*chief["execution_path"], execution_id],
        "task_id": chief["task_id"],
        "packet_id": chief["packet_id"],
        "thread_id": chief["thread_id"],
        "turn_id": "provider-turn-2",
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
        "objective": "observe Chief turn",
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
    return execution, registration_evidence(
        supervisor,
        execution=execution,
        evidence_id=evidence_id,
    )


def registered_orphan(
    supervisor: CompanySupervisor,
    *,
    execution_id: str = "registered-orphan-execution",
    registration_id: str = "registered-orphan-event",
    evidence_id: str = "registered-orphan-evidence",
    recorded_at: str = "2026-07-27T00:01:00Z",
) -> tuple[dict[str, Any], dict[str, Any]]:
    execution = {
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "execution_id": execution_id,
        "execution_kind": "agent",
        "display_name": "Orphan / Unattributed",
        "organization_node_id": None,
        "department_id": None,
        "parent_execution_id": None,
        "execution_depth": 0,
        "execution_path": [execution_id],
        "task_id": None,
        "packet_id": None,
        "thread_id": "provider-orphan-thread",
        "turn_id": None,
        "agent_id": "provider-orphan-agent",
        "job_id": None,
        "dispatch_id": None,
        "registration_id": registration_id,
        "receipt_id": None,
        "provider": "codex",
        "model": "gpt-5",
        "effort": "high",
        "carrier_id": None,
        "role": "orphan",
        "delegation_depth": 0,
        "engineering_status": "unknown",
        "runtime_status": "unknown",
        "attention_overlays": ["coverage_degraded"],
        "objective": "unattributed provider activity",
        "phase": "provider_runtime",
        "created_at": recorded_at,
        "updated_at": recorded_at,
        "last_event_at": recorded_at,
        "heartbeat_at": None,
        "wait_reason": "unattributed",
        "current_tool": None,
        "terminal_at": None,
        "usage_cursor": 0,
        "job_ids": [],
        "evidence_ids": [evidence_id],
        "provenance": "provider_client_emitted",
        "observation": {"state": "known", "reason": "observed"},
    }
    return execution, registration_evidence(
        supervisor,
        execution=execution,
        evidence_id=evidence_id,
    )


def test_bootstrap_projects_cursor_and_required_object_graph(tmp_path: Path) -> None:
    with initialize(tmp_path) as supervisor:
        assert supervisor.heads().global_head.global_sequence == 1
        assert len(_objects(supervisor, COMPANY_MANIFEST_V1)) == 1
        grants = _objects(supervisor, AUTHORITY_GRANT_V1)
        assert {grant["actor_kind"] for grant in grants} == {"supervisor", "chief"}
        for grant in grants:
            unsigned = {key: value for key, value in grant.items() if key != "grant_sha256"}
            unsigned["permissions"] = list(unsigned["permissions"])
            assert grant["grant_sha256"] == company_contract_sha256(unsigned)
        nodes = _objects(supervisor, ORGANIZATION_NODE_V1)
        assert {node["role"] for node in nodes} == {"chief", "rtl_lead", "dv_lead", "pd_lead"}
        identities = _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        assert {identity["name"] for identity in identities} == {"RTL", "DV", "PD"}
        snapshots = _objects(supervisor, DEPARTMENT_SNAPSHOT_V1)
        assert len(snapshots) == 3
        assert all(snapshot["revision"] == 1 for snapshot in snapshots)
        assert _objects(supervisor, CHIEF_TERM_V1)[0]["state"] == "active"
        assert len(_objects(supervisor, CARRIER_BINDING_V1)) == 1
        assert _objects(supervisor, EXECUTION_NODE_V1) == []


def test_registered_turn_is_durable_visible_and_replayable(
    tmp_path: Path,
) -> None:
    supervisor = initialize(tmp_path, carrier=known_carrier())
    slot = supervisor.slot_root
    execution, evidence = registered_turn(supervisor)
    result = supervisor.register_execution(
        execution,
        evidence,
        transaction_id="register-turn-transaction",
        command_id="register-turn-command",
        recorded_at="2026-07-27T00:01:00Z",
    )
    assert result.engineering_status == "active"
    assert result.runtime_status == "running"
    assert CompanyViewService(supervisor._state).section("meta")["data"][
        "supervisor"
    ]["blob_status"] == "ready"
    assert not result.idempotent_replay
    replay = supervisor.register_execution(
        execution,
        evidence,
        transaction_id="register-turn-transaction",
        command_id="register-turn-command",
        recorded_at="2026-07-27T00:01:00Z",
    )
    assert replay.idempotent_replay
    assert replay.global_sequence == result.global_sequence
    events = _objects(supervisor, EXECUTION_EVENT_V1)
    assert [item["event_type"] for item in events] == [
        "execution.registered",
    ]
    view = CompanyViewService(supervisor._state).section("execution")[
        "data"
    ]
    chief = next(
        item
        for item in view["nodes"]
        if item["role"] == "chief"
        and item["parent_execution_id"] is None
    )
    assert view["children"][chief["execution_id"]] == [
        execution["execution_id"],
    ]
    assert CompanyViewService(supervisor._state).section("company")[
        "data"
    ]["capacity"]["occupied"] == 1
    cursor = supervisor.heads().global_head.global_sequence
    supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        assert reopened._state.rebuild_projection().global_sequence == cursor
        restarted = reopened.register_execution(
            execution,
            evidence,
            transaction_id="register-turn-transaction",
            command_id="register-turn-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        assert restarted.idempotent_replay
        assert restarted.global_sequence == result.global_sequence


def test_registered_orphan_is_visible_and_freezes_capacity_admission(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        execution, evidence = registered_orphan(supervisor)
        supervisor.register_execution(
            execution,
            evidence,
            transaction_id="register-orphan-transaction",
            command_id="register-orphan-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        view = CompanyViewService(supervisor._state)
        execution_view = view.section("execution")["data"]
        alerts_view = view.section("alerts")["data"]
        company_view = view.section("company")["data"]
        assert [
            item["execution_id"]
            for item in execution_view["orphans"]
        ] == [execution["execution_id"]]
        alert = next(
            item
            for item in alerts_view["alerts"]
            if item["category"] == "execution_orphan"
        )
        assert alert["severity"] == "critical"
        assert alert["projection_source"] == "derived_read_only"
        capacity = company_view["capacity"]
        # An unattached registration cannot be converted into a fictitious
        # provider-session count.  Its derived critical alert degrades the
        # projection, which freezes admission while the proven Chief slot
        # remains the only counted carrier.
        assert capacity["occupied"] == 1
        assert capacity["occupied_semantics"] == "lower_bound"
        assert capacity["available"] is None
        assert capacity["reason"] == "projection_incomplete"
        assert capacity["unattributed_active"] == []


def test_registration_rejects_missing_parent_and_divergent_replay(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        execution, evidence = registered_turn(supervisor)
        missing_parent = {
            **execution,
            "parent_execution_id": "missing-parent",
            "execution_path": [
                "missing-parent",
                execution["execution_id"],
            ],
        }
        missing_parent_evidence = registration_evidence(
            supervisor,
            execution=missing_parent,
            evidence_id=str(evidence["evidence_id"]),
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="parent identity is absent",
        ):
            supervisor.register_execution(
                missing_parent,
                missing_parent_evidence,
                transaction_id="register-missing-parent-transaction",
                command_id="register-missing-parent-command",
                recorded_at="2026-07-27T00:01:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before

        supervisor.register_execution(
            execution,
            evidence,
            transaction_id="register-turn-transaction",
            command_id="register-turn-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        divergent = {
            **execution,
            "display_name": "Divergent replay",
        }
        with pytest.raises(
            CompanyExecutionRegistrationError,
            match="durable execution registration bytes differ",
        ):
            supervisor.register_execution(
                divergent,
                evidence,
                transaction_id="register-turn-transaction",
                command_id="register-turn-command",
                recorded_at="2026-07-27T00:01:00Z",
            )


def test_registered_execution_cannot_be_stopped_without_typed_evidence(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        execution, evidence = registered_orphan(supervisor)
        supervisor.register_execution(
            execution,
            evidence,
            transaction_id="register-orphan-transaction",
            command_id="register-orphan-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        stopped_at = "2026-07-27T00:02:00Z"
        stopped = {
            **execution,
            "engineering_status": "completed",
            "runtime_status": "stopped",
            "updated_at": stopped_at,
            "last_event_at": stopped_at,
            "heartbeat_at": None,
            "terminal_at": stopped_at,
            "provenance": "agent_reported",
            "observation": {"state": "known", "reason": "observed"},
        }
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="untyped-orphan-stop-transaction",
            command_id="untyped-orphan-stop-command",
            events=[
                CompanyEventDraft(
                    event_id="untyped-orphan-stop-event",
                    event_type="execution.stopped",
                    recorded_at=stopped_at,
                    payload=stopped,
                    provenance="agent_reported",
                ),
            ],
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="registered ExecutionNode revision lacks typed lifecycle",
        ):
            supervisor.commit(request, recorded_at=stopped_at)
        assert supervisor.heads().global_head.global_sequence == before


def test_registration_rejects_raw_source_with_divergent_identity(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        execution, evidence = registered_turn(supervisor)
        different, _unused_evidence = registered_turn(
            supervisor,
            execution_id="different-execution",
            registration_id="different-registration",
            evidence_id="different-evidence",
        )
        wrong_source = supervisor_module._execution_registration_event(
            different,
        )
        wrong_raw = canonical_company_json_bytes(wrong_source)
        metadata = supervisor._state.blobs.put(wrong_raw)
        divergent = {
            **evidence,
            "artifact": {
                **evidence["artifact"],
                "sha256": metadata.sha256,
                "size_bytes": metadata.size_bytes,
            },
            "verification_sha256": metadata.sha256,
        }
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="registration source differs from its event",
        ):
            supervisor.register_execution(
                execution,
                divergent,
                transaction_id="register-divergent-source-transaction",
                command_id="register-divergent-source-command",
                recorded_at="2026-07-27T00:01:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before


def test_supervisor_owns_cache_backed_dashboard_lifecycle(
    tmp_path: Path,
) -> None:
    supervisor = initialize(tmp_path, carrier=known_carrier())
    assert not hasattr(supervisor, "state")
    url = supervisor.start_dashboard()
    try:
        assert supervisor.dashboard_url == url
        with urllib.request.urlopen(
            url + "api/v1/snapshot",
            timeout=3,
        ) as response:
            snapshot = json.loads(response.read())
        assert response.status == 200
        assert snapshot["cursor"] == 1
        assert snapshot["data"]["execution"]["roots"]
        assert snapshot["data"]["export"]["state"] == "unavailable"
        authority = supervisor.records_after(0)[0].events[0].event[
            "actor_authority"
        ]
        payload = {
            "contract_type": DEPARTMENT_IDENTITY_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "department_id": "dashboard-refresh-department",
            "name": "REFRESH",
            "charter_sha256": "e" * 64,
            "scope_sha256": "f" * 64,
            "lead_node_id": None,
            "created_at": "2026-07-27T00:00:01Z",
            "status": "parked",
            "observation": {"state": "known", "reason": "observed"},
        }
        request = build_company_transaction_request(
            supervisor.heads(),
            authority,
            transaction_id="dashboard-refresh-transaction",
            command_id="dashboard-refresh-command",
            events=[
                CompanyEventDraft(
                    event_id="dashboard-refresh-event",
                    event_type="department.created",
                    recorded_at="2026-07-27T00:00:01Z",
                    payload=payload,
                ),
            ],
        )
        supervisor.commit(
            request,
            recorded_at="2026-07-27T00:00:01Z",
        )
        with urllib.request.urlopen(
            url + "api/v1/snapshot",
            timeout=3,
        ) as response:
            refreshed = json.loads(response.read())
        assert refreshed["cursor"] == 2
        assert any(
            item["department_id"] == "dashboard-refresh-department"
            for item in refreshed["data"]["departments"]
        )
        assert supervisor.refresh_dashboard() == 2
        assert supervisor.start_dashboard() == url
    finally:
        supervisor.close()

    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(url + "api/v1/meta", timeout=1)


def test_dashboard_environment_is_explicit_and_stable_for_server_lifetime(
    tmp_path: Path,
) -> None:
    supervisor = initialize(tmp_path)
    url = supervisor.start_dashboard(
        environment_kind="synthetic_canary",
    )
    try:
        with urllib.request.urlopen(
            url + "api/v1/work",
            timeout=3,
        ) as response:
            work = json.loads(response.read())["data"]
        assert work["environment"] == {
            "environment_kind": "synthetic_canary",
            "source": "explicit_configuration",
            "provider_live_verified": False,
            "reason": "provider_live_verification_not_implemented",
        }
        assert supervisor.start_dashboard(
            environment_kind="synthetic_canary",
        ) == url
        with pytest.raises(
            CompanySupervisorError,
            match="environment differs",
        ):
            supervisor.start_dashboard(environment_kind="unverified")
    finally:
        supervisor.close()


def test_committed_dashboard_refresh_failure_is_typed_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = initialize(tmp_path)
    url = supervisor.start_dashboard()
    authority = supervisor.records_after(0)[0].events[0].event[
        "actor_authority"
    ]
    payload = {
        "contract_type": DEPARTMENT_IDENTITY_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "department_id": "refresh-failure-department",
        "name": "REFRESH FAILURE",
        "charter_sha256": "e" * 64,
        "scope_sha256": "f" * 64,
        "lead_node_id": None,
        "created_at": "2026-07-27T00:00:01Z",
        "status": "parked",
        "observation": {"state": "known", "reason": "observed"},
    }
    request = build_company_transaction_request(
        supervisor.heads(),
        authority,
        transaction_id="refresh-failure-transaction",
        command_id="refresh-failure-command",
        events=[
            CompanyEventDraft(
                event_id="refresh-failure-event",
                event_type="department.created",
                recorded_at="2026-07-27T00:00:01Z",
                payload=payload,
            ),
        ],
    )
    cache = supervisor._dashboard_cache
    assert cache is not None
    original_refresh = cache.refresh

    def fail_refresh() -> int:
        raise RuntimeError("injected Dashboard refresh failure")

    monkeypatch.setattr(cache, "refresh", fail_refresh)
    with pytest.raises(
        CompanySupervisorDashboardRefreshError,
    ) as captured:
        supervisor.commit(
            request,
            recorded_at="2026-07-27T00:00:01Z",
        )
    assert captured.value.result.record.global_sequence == 2
    assert supervisor.heads().global_head.global_sequence == 2
    with urllib.request.urlopen(
        url + "api/v1/snapshot",
        timeout=3,
    ) as response:
        stale = json.loads(response.read())
    assert stale["cursor"] == 1

    monkeypatch.setattr(cache, "refresh", original_refresh)
    replay = supervisor.commit(
        request,
        recorded_at="2026-07-27T00:00:01Z",
    )
    assert replay.record.global_sequence == 2
    assert supervisor.heads().global_head.global_sequence == 2
    with urllib.request.urlopen(
        url + "api/v1/snapshot",
        timeout=3,
    ) as response:
        recovered = json.loads(response.read())
    assert recovered["cursor"] == 2
    supervisor.close()


def test_unknown_carrier_has_no_thread_or_execution_node(tmp_path: Path) -> None:
    with initialize(tmp_path) as supervisor:
        carrier = _objects(supervisor, CARRIER_BINDING_V1)[0]
        assert carrier["session_availability"] == "unknown"
        assert carrier["state"] == "unknown"
        assert carrier["session_id"] is None
        assert _objects(supervisor, EXECUTION_NODE_V1) == []


def test_known_carrier_creates_exact_active_binding_and_running_execution(tmp_path: Path) -> None:
    carrier = known_carrier()
    with initialize(tmp_path, carrier=carrier) as supervisor:
        binding = _objects(supervisor, CARRIER_BINDING_V1)[0]
        execution = _objects(supervisor, EXECUTION_NODE_V1)[0]
        assert binding["carrier_id"] == carrier["carrier_id"]
        assert binding["provider"] == carrier["provider"]
        assert binding["model"] == carrier["model"]
        assert binding["session_id"] == carrier["session_id"]
        assert binding["state"] == "active"
        assert execution["thread_id"] == carrier["thread_id"]
        assert execution["provider"] == carrier["provider"]
        assert execution["runtime_status"] == "running"
        assert execution["provenance"] == carrier["provenance"]


def test_department_resume_is_durable_exact_replay_and_rebuild(
    tmp_path: Path,
) -> None:
    supervisor = initialize(tmp_path, carrier=known_carrier())
    slot = supervisor.slot_root
    department_id = next(
        item["department_id"]
        for item in _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        if item["name"] == "RTL"
    )
    kwargs = {
        "transaction_id": "rtl-resume-transaction",
        "command_id": "rtl-resume-command",
        "dispatch_request_id": "rtl-resume-dispatch",
        "reservation_id": "rtl-resume-reservation",
        "task_id": "rtl-resume-task",
        "packet_id": "rtl-resume-packet",
        "route_policy_id": "rtl-default-route",
        "requested_role": "rtl_lead",
        "requested_capability_tier": "specialist",
        "requested_at": "2026-07-27T00:01:00Z",
        "recorded_at": "2026-07-27T00:01:01Z",
    }
    first = supervisor.resume_department(department_id, **kwargs)
    assert first.operation == "resume"
    assert first.lifecycle_state == "waking"
    assert first.dispatch_state == "queued"
    assert first.global_sequence == 2
    assert not first.idempotent_replay
    identity = next(
        item
        for item in _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        if item["department_id"] == department_id
    )
    lead = next(
        item
        for item in _objects(supervisor, ORGANIZATION_NODE_V1)
        if item["node_id"] == identity["lead_node_id"]
    )
    dispatch = _objects(supervisor, DISPATCH_REQUEST_V1)
    assert identity["status"] == "active"
    assert lead["status"] == "active"
    assert len(dispatch) == 1
    assert dispatch[0]["dispatch_request_id"] == "rtl-resume-dispatch"
    assert dispatch[0]["state"] == "queued"

    replay = supervisor.resume_department(department_id, **kwargs)
    assert replay.idempotent_replay
    assert replay.global_sequence == 2
    assert supervisor.heads().global_head.global_sequence == 2
    with pytest.raises(
        CompanyDepartmentLifecycleError,
        match="routing differs",
    ):
        supervisor.resume_department(
            department_id,
            **{
                **kwargs,
                "task_id": "rtl-divergent-task",
            },
        )
    assert supervisor.heads().global_head.global_sequence == 2
    supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        rebuilt = reopened._state.rebuild_projection()
        assert rebuilt.global_sequence == 2
        restarted = reopened.resume_department(department_id, **kwargs)
        assert restarted.idempotent_replay
        assert restarted.global_sequence == 2
        assert reopened.heads().global_head.global_sequence == 2
        dispatch = _objects(reopened, DISPATCH_REQUEST_V1)
        assert len(dispatch) == 1
        assert dispatch[0]["state"] == "queued"


def test_same_head_chief_race_has_one_consumed_and_one_visible_fenced_loser(
    tmp_path: Path,
) -> None:
    carrier_two = handoff_carrier(2)
    carrier_three = handoff_carrier(3)
    supervisor = initialize(tmp_path, carrier=known_carrier())
    slot = supervisor.slot_root
    durable_job, durable_job_event_sha256 = append_queued_job(supervisor)
    dashboard_url = supervisor.start_dashboard()
    genesis_execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["carrier_id"] == "carrier-1"
    )
    first = prepare_handoff(
        supervisor,
        carrier_two,
        nonce="2" * 64,
        user_action_ref="user-action-handoff-2",
    )
    second = prepare_handoff(
        supervisor,
        carrier_three,
        nonce="3" * 64,
        user_action_ref="user-action-handoff-3",
    )
    assert first["expected_head_sha256"] == second["expected_head_sha256"]

    winner = supervisor.takeover_chief(
        first,
        carrier_two,
        consumed_at="2026-07-27T00:02:00Z",
        grant_expires_at="2026-07-29T00:00:00Z",
    )
    loser = supervisor.takeover_chief(
        second,
        carrier_three,
        consumed_at="2026-07-27T00:03:00Z",
        grant_expires_at="2026-07-29T00:00:00Z",
    )
    assert winner.outcome == "consumed"
    assert winner.term == 2 and winner.epoch == 2
    assert loser.outcome == "fenced"
    assert loser.term is None and loser.epoch is None
    assert winner.global_sequence == 3
    assert loser.global_sequence == 4

    term = _objects(supervisor, CHIEF_TERM_V1)[0]
    assert (term["term"], term["epoch"], term["carrier_id"]) == (
        2,
        2,
        carrier_two["carrier_id"],
    )
    carriers = {
        item["carrier_id"]: item
        for item in _objects(supervisor, CARRIER_BINDING_V1)
    }
    assert carriers["carrier-1"]["state"] == "fenced"
    assert carriers["carrier-2"]["state"] == "active"
    assert carriers["carrier-3"]["state"] == "fenced"
    executions = {
        item["carrier_id"]: item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
    }
    assert (
        executions["carrier-1"]["execution_id"]
        == genesis_execution["execution_id"]
    )
    assert (
        executions["carrier-1"]["created_at"]
        == genesis_execution["created_at"]
    )
    assert (
        executions["carrier-1"]["heartbeat_at"]
        == genesis_execution["heartbeat_at"]
    )
    assert executions["carrier-1"]["runtime_status"] == "running"
    assert executions["carrier-1"]["engineering_status"] == "waiting"
    assert executions["carrier-1"]["wait_reason"] == "fenced_read_only"
    assert executions["carrier-1"]["updated_at"] == "2026-07-27T00:02:00Z"
    assert executions["carrier-2"]["engineering_status"] == "active"
    assert executions["carrier-3"]["engineering_status"] == "waiting"
    assert executions["carrier-3"]["wait_reason"] == "fenced_read_only"
    assert _objects(supervisor, EXTERNAL_JOB_V1) == [durable_job]
    job_record = next(
        item
        for item in supervisor.records_after(0)
        if item.request["transaction_id"] == "durable-vcs-job-transaction"
    )
    assert next(
        member.event_sha256
        for member in job_record.events
        if member.event["payload"]["contract_type"] == EXTERNAL_JOB_V1
    ) == durable_job_event_sha256
    assert all(
        event.event["payload"]["contract_type"] != EXTERNAL_JOB_V1
        for record in supervisor.records_after(2)
        for event in record.events
    )
    with urllib.request.urlopen(
        dashboard_url + "api/v1/snapshot",
        timeout=3,
    ) as response:
        dashboard = json.loads(response.read())
    chief_view = dashboard["data"]["company"]["chief"]
    assert chief_view["term"]["term"] == 2
    assert chief_view["carrier"]["carrier_id"] == "carrier-2"
    assert [
        item["outcome"] for item in chief_view["takeover_attempts"]
    ] == ["fenced", "consumed"]
    execution_states = {
        item["carrier_id"]: item["carrier_state"]
        for item in dashboard["data"]["execution"]["nodes"]
        if item["carrier_id"] is not None
    }
    assert execution_states == {
        "carrier-1": "fenced",
        "carrier-2": "active",
        "carrier-3": "fenced",
    }
    engineering_states = {
        item["carrier_id"]: item["engineering_status"]
        for item in dashboard["data"]["execution"]["nodes"]
        if item["carrier_id"] is not None
    }
    assert engineering_states == {
        "carrier-1": "waiting",
        "carrier-2": "active",
        "carrier-3": "waiting",
    }
    winner_record = next(
        item
        for item in supervisor.records_after(0)
        if item.request["transaction_id"] == winner.transaction_id
    )
    prior_execution_events = [
        member.event
        for member in winner_record.events
        if member.event["event_type"] == "execution.authority_fenced"
    ]
    assert len(prior_execution_events) == 1
    assert (
        prior_execution_events[0]["payload"]["execution_id"]
        == genesis_execution["execution_id"]
    )
    assert prior_execution_events[0]["provenance"] == "AOI_verified"
    assert (
        prior_execution_events[0]["payload"]["provenance"]
        == genesis_execution["provenance"]
        == "agent_reported"
    )
    serialized_dashboard = json.dumps(dashboard, sort_keys=True)
    for secret in (
        "session-1",
        "session-2",
        "session-3",
        "thread-1",
        "thread-2",
        "thread-3",
        "user-action-handoff-2",
        "user-action-handoff-3",
        "2" * 64,
        "3" * 64,
    ):
        assert secret not in serialized_dashboard

    replay = supervisor.takeover_chief(
        first,
        carrier_two,
        consumed_at="2026-07-27T00:02:00Z",
        grant_expires_at="2026-07-29T00:00:00Z",
    )
    assert replay.idempotent_replay
    assert replay.global_sequence == winner.global_sequence
    assert supervisor.heads().global_head.global_sequence == 4
    supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        rebuilt = reopened._state.rebuild_projection()
        assert rebuilt.global_sequence == 4
        restarted_replay = reopened.takeover_chief(
            first,
            carrier_two,
            consumed_at="2026-07-27T00:02:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        assert restarted_replay.idempotent_replay
        assert restarted_replay.global_sequence == 3
        assert reopened.heads().global_head.global_sequence == 4
        reopened_executions = {
            item["carrier_id"]: item
            for item in _objects(reopened, EXECUTION_NODE_V1)
        }
        assert (
            reopened_executions["carrier-1"]["engineering_status"]
            == "waiting"
        )
        assert (
            reopened_executions["carrier-1"]["wait_reason"]
            == "fenced_read_only"
        )
        assert _objects(reopened, EXTERNAL_JOB_V1) == [durable_job]


def test_fenced_chief_runtime_stop_frees_capacity_and_replays(
    tmp_path: Path,
) -> None:
    supervisor = initialize(tmp_path, carrier=known_carrier())
    slot = supervisor.slot_root
    contender = handoff_carrier(2)
    capability = prepare_handoff(
        supervisor,
        contender,
        nonce="9" * 64,
        user_action_ref="user-action-fenced-chief-stop",
    )
    supervisor.takeover_chief(
        capability,
        contender,
        consumed_at="2026-07-27T00:02:00Z",
        grant_expires_at="2026-07-29T00:00:00Z",
    )
    old_execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["carrier_id"] == "carrier-1"
    )
    before_company = CompanyViewService(
        supervisor._state,
    ).section("company")["data"]
    assert before_company["capacity"]["occupied"] == 2
    receipt = fenced_chief_stop_receipt(
        supervisor,
        execution_id=old_execution["execution_id"],
        transaction_id="fenced-chief-stop-transaction",
        command_id="fenced-chief-stop-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    stopped = supervisor.record_fenced_chief_execution_stopped(
        old_execution["execution_id"],
        receipt,
        transaction_id="fenced-chief-stop-transaction",
        command_id="fenced-chief-stop-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    assert stopped.engineering_status == "waiting"
    assert stopped.runtime_status == "stopped"
    executions = {
        item["carrier_id"]: item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
    }
    assert executions["carrier-1"]["runtime_status"] == "stopped"
    assert executions["carrier-1"]["wait_reason"] == "fenced_read_only"
    assert executions["carrier-1"]["heartbeat_at"] is None
    assert executions["carrier-2"]["runtime_status"] == "running"
    after_company = CompanyViewService(
        supervisor._state,
    ).section("company")["data"]
    assert after_company["capacity"]["occupied"] == 1
    stop_record = supervisor._state.record_by_transaction_id(
        "fenced-chief-stop-transaction",
    )
    assert stop_record is not None
    assert [member.event["event_type"] for member in stop_record.events] == [
        "provider.lifecycle.execution_stopped",
        "evidence.provider_lifecycle.observed",
        "execution.chief_fenced.stopped",
    ]
    replay = supervisor.record_fenced_chief_execution_stopped(
        old_execution["execution_id"],
        receipt,
        transaction_id="fenced-chief-stop-transaction",
        command_id="fenced-chief-stop-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    assert replay.idempotent_replay
    assert replay.global_sequence == stopped.global_sequence
    divergent = copy.deepcopy(receipt)
    divergent["receipt_id"] = "provider-stop-receipt-divergent"
    divergent["receipt_sha256"] = company_contract_sha256({
        key: value
        for key, value in divergent.items()
        if key != "receipt_sha256"
    })
    with pytest.raises(
        CompanyChiefTakeoverError,
        match="differs from durable bytes",
    ):
        supervisor.record_fenced_chief_execution_stopped(
            old_execution["execution_id"],
            divergent,
            transaction_id="fenced-chief-stop-transaction",
            command_id="fenced-chief-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
    cursor = supervisor.heads().global_head.global_sequence
    supervisor.close()

    with CompanySupervisor.open(slot) as reopened:
        assert reopened._state.rebuild_projection().global_sequence == cursor
        restarted = reopened.record_fenced_chief_execution_stopped(
            old_execution["execution_id"],
            receipt,
            transaction_id="fenced-chief-stop-transaction",
            command_id="fenced-chief-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        assert restarted.idempotent_replay
        reopened_old = next(
            item
            for item in _objects(reopened, EXECUTION_NODE_V1)
            if item["carrier_id"] == "carrier-1"
        )
        assert reopened_old["engineering_status"] == "waiting"
        assert reopened_old["runtime_status"] == "stopped"
        assert reopened.health().status == "ready"


def test_current_chief_stop_revokes_mutation_and_allows_fresh_takeover(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        old_grant = next(
            item
            for item in _objects(supervisor, AUTHORITY_GRANT_V1)
            if item["actor_kind"] == "chief"
        )
        old_authority = authority_from_grant(
            supervisor_module._plain(old_grant),
        )
        old_execution = next(
            item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["carrier_id"] == "carrier-1"
        )
        receipt = fenced_chief_stop_receipt(
            supervisor,
            execution_id=old_execution["execution_id"],
            transaction_id="current-chief-provider-stop-transaction",
            command_id="current-chief-provider-stop-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        stopped = supervisor.record_current_chief_execution_stopped(
            old_execution["execution_id"],
            receipt,
            transaction_id="current-chief-provider-stop-transaction",
            command_id="current-chief-provider-stop-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        assert stopped.engineering_status == "active"
        assert stopped.runtime_status == "stopped"
        old_carrier = next(
            item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
            if item["carrier_id"] == "carrier-1"
        )
        assert old_carrier["state"] == "lost"
        assert old_carrier["session_availability"] == "unavailable"

        revived_carrier = {
            **old_carrier,
            "session_id": "session-1",
            "session_availability": "available",
            "state": "active",
            "last_observed_at": "2026-07-27T00:01:10Z",
            "observation": {"state": "known", "reason": "observed"},
        }
        revive_request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="forged-chief-carrier-revive-transaction",
            command_id="forged-chief-carrier-revive-command",
            events=[CompanyEventDraft(
                event_id="forged-chief-carrier-revive-event",
                event_type="carrier.forged_recovery",
                recorded_at="2026-07-27T00:01:10Z",
                payload=revived_carrier,
                provenance="AOI_verified",
            )],
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="carrier revision lacks one typed lifecycle",
        ):
            supervisor.commit(
                revive_request,
                recorded_at="2026-07-27T00:01:10Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
        assert next(
            item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
            if item["carrier_id"] == "carrier-1"
        ) == old_carrier

        artifact_metadata = supervisor._state.blobs.put(
            b"unavailable-chief-mutation",
        )
        forged_evidence = {
            "contract_type": EVIDENCE_RECORD_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "evidence_id": "unavailable-chief-mutation-evidence",
            "execution_id": old_execution["execution_id"],
            "claim_id": "unavailable-chief-mutation-claim",
            "evidence_class": "engineering_inference",
            "status": "observed",
            "artifact": {
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": artifact_metadata.sha256,
                "size_bytes": artifact_metadata.size_bytes,
                "media_type": "application/octet-stream",
                "availability": "available",
            },
            "command_sha256": None,
            "verification_sha256": artifact_metadata.sha256,
            "recorded_at": "2026-07-27T00:01:30Z",
            "provenance": "agent_reported",
            "observation": {"state": "known", "reason": "observed"},
        }
        stale_request = build_company_transaction_request(
            supervisor.heads(),
            old_authority,
            transaction_id="unavailable-chief-mutation-transaction",
            command_id="unavailable-chief-mutation-command",
            events=[CompanyEventDraft(
                event_id="unavailable-chief-mutation-event",
                event_type="evidence.unavailable_chief.forged",
                recorded_at="2026-07-27T00:01:30Z",
                payload=forged_evidence,
                provenance="agent_reported",
            )],
        )
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="fenced or unavailable",
        ):
            supervisor.commit(
                stale_request,
                recorded_at="2026-07-27T00:01:30Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor

        contender = handoff_carrier(2)
        capability = supervisor.prepare_chief_takeover(
            contender,
            user_action_ref="fresh-user-takeover-after-stop",
            objective_sha256="e" * 64,
            scope_sha256="f" * 64,
            nonce_sha256="8" * 64,
            issued_at="2026-07-27T00:02:00Z",
            expires_at="2026-07-27T01:00:00Z",
        )
        takeover = supervisor.takeover_chief(
            capability,
            contender,
            consumed_at="2026-07-27T00:03:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        assert takeover.outcome == "consumed"
        carriers = {
            item["carrier_id"]: item
            for item in _objects(supervisor, CARRIER_BINDING_V1)
        }
        assert carriers["carrier-1"]["state"] == "fenced"
        assert (
            carriers["carrier-1"]["session_availability"]
            == "unavailable"
        )
        assert carriers["carrier-2"]["state"] == "active"
        assert carriers["carrier-2"]["session_availability"] == "available"
        stop_replay = supervisor.record_current_chief_execution_stopped(
            old_execution["execution_id"],
            receipt,
            transaction_id="current-chief-provider-stop-transaction",
            command_id="current-chief-provider-stop-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        assert stop_replay.idempotent_replay
        assert stop_replay.global_sequence == stopped.global_sequence


def test_takeover_rejects_provider_session_rebinding(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = {
            **handoff_carrier(2),
            "provider": "codex",
            "model": "gpt-5",
            "session_id": "session-1",
        }
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="b" * 64,
            user_action_ref="user-action-duplicate-provider-session",
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyStateInvariantError,
            match="provider session has multiple current carrier holders",
        ):
            supervisor.takeover_chief(
                capability,
                contender,
                consumed_at="2026-07-27T00:02:00Z",
                grant_expires_at="2026-07-29T00:00:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert len(_objects(supervisor, CHIEF_TERM_V1)) == 1
        assert len(_objects(supervisor, CARRIER_BINDING_V1)) == 1
        assert len(_objects(supervisor, EXECUTION_NODE_V1)) == 1


def test_stopped_fenced_provider_session_can_be_reused_sequentially(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        carrier_two = handoff_carrier(2)
        first_capability = prepare_handoff(
            supervisor,
            carrier_two,
            nonce="c" * 64,
            user_action_ref="user-action-first-handoff",
        )
        supervisor.takeover_chief(
            first_capability,
            carrier_two,
            consumed_at="2026-07-27T00:02:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        old_execution = next(
            item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["carrier_id"] == "carrier-1"
        )
        stop_receipt = fenced_chief_stop_receipt(
            supervisor,
            execution_id=old_execution["execution_id"],
            transaction_id="sequential-reuse-stop-transaction",
            command_id="sequential-reuse-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.record_fenced_chief_execution_stopped(
            old_execution["execution_id"],
            stop_receipt,
            transaction_id="sequential-reuse-stop-transaction",
            command_id="sequential-reuse-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )

        carrier_three = {
            **handoff_carrier(3),
            "provider": "codex",
            "model": "gpt-5",
            "session_id": "session-1",
        }
        second_capability = supervisor.prepare_chief_takeover(
            carrier_three,
            user_action_ref="user-action-sequential-session-reuse",
            objective_sha256="e" * 64,
            scope_sha256="f" * 64,
            nonce_sha256="d" * 64,
            issued_at="2026-07-27T00:04:00Z",
            expires_at="2026-07-27T01:00:00Z",
        )
        result = supervisor.takeover_chief(
            second_capability,
            carrier_three,
            consumed_at="2026-07-27T00:05:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        assert result.outcome == "consumed"
        assert result.term == 3
        company = CompanyViewService(supervisor._state).section(
            "company",
        )["data"]
        assert company["capacity"] == {
            "limit": 16,
            "occupied": 2,
            "occupied_semantics": "exact",
            "available": 14,
            "reason": None,
            "unattributed_active": [],
        }


def test_fenced_chief_runtime_stop_rejects_current_and_forged_updates(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="a" * 64,
            user_action_ref="user-action-fenced-chief-stop-reject",
        )
        supervisor.takeover_chief(
            capability,
            contender,
            consumed_at="2026-07-27T00:02:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        executions = {
            item["carrier_id"]: item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
        }
        current = executions["carrier-2"]
        current_receipt = fenced_chief_stop_receipt(
            supervisor,
            execution_id=current["execution_id"],
            transaction_id="current-chief-stop-transaction",
            command_id="current-chief-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyChiefTakeoverError,
            match="stoppable fenced Chief",
        ):
            supervisor.record_fenced_chief_execution_stopped(
                current["execution_id"],
                current_receipt,
                transaction_id="current-chief-stop-transaction",
                command_id="current-chief-stop-command",
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before

        old = executions["carrier-1"]
        stale_receipt = fenced_chief_stop_receipt(
            supervisor,
            execution_id=old["execution_id"],
            transaction_id="stale-chief-stop-transaction",
            command_id="stale-chief-stop-command",
            recorded_at="2026-07-27T00:01:30Z",
        )
        with pytest.raises(
            CompanyChiefTakeoverError,
            match="predates the Chief fence",
        ):
            supervisor.record_fenced_chief_execution_stopped(
                old["execution_id"],
                stale_receipt,
                transaction_id="stale-chief-stop-transaction",
                command_id="stale-chief-stop-command",
                recorded_at="2026-07-27T00:01:30Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
        stale_evidence = supervisor_module._provider_lifecycle_evidence(
            stale_receipt,
        )
        stale_candidate = {
            **old,
            "runtime_status": "stopped",
            "updated_at": "2026-07-27T00:01:30Z",
            "last_event_at": "2026-07-27T00:01:30Z",
            "heartbeat_at": None,
            "current_tool": None,
            "receipt_id": stale_receipt["receipt_id"],
            "evidence_ids": [
                *old["evidence_ids"],
                stale_evidence["evidence_id"],
            ],
            "provenance": stale_receipt["provenance"],
            "observation": stale_receipt["observation"],
        }
        stale_request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="stale-chief-stop-transaction",
            command_id="stale-chief-stop-command",
            events=[
                *supervisor_module._provider_lifecycle_drafts(
                    stale_receipt,
                    evidence=stale_evidence,
                ),
                CompanyEventDraft(
                    event_id=(
                        supervisor_module
                        ._fenced_chief_execution_stop_event_id(
                            old["execution_id"],
                            transaction_id="stale-chief-stop-transaction",
                            command_id="stale-chief-stop-command",
                        )
                    ),
                    event_type="execution.chief_fenced.stopped",
                    recorded_at="2026-07-27T00:01:30Z",
                    payload=stale_candidate,
                    provenance=stale_receipt["provenance"],
                ),
            ],
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="fenced Chief execution stop transition differs",
        ):
            supervisor.commit(
                stale_request,
                recorded_at="2026-07-27T00:01:30Z",
            )
        assert supervisor.heads().global_head.global_sequence == before

        provenance_receipt = fenced_chief_stop_receipt(
            supervisor,
            execution_id=old["execution_id"],
            transaction_id="provenance-chief-stop-transaction",
            command_id="provenance-chief-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        provenance_evidence = (
            supervisor_module._provider_lifecycle_evidence(
                provenance_receipt,
            )
        )
        provenance_candidate = {
            **old,
            "runtime_status": "stopped",
            "updated_at": "2026-07-27T00:03:00Z",
            "last_event_at": "2026-07-27T00:03:00Z",
            "heartbeat_at": None,
            "current_tool": None,
            "receipt_id": provenance_receipt["receipt_id"],
            "evidence_ids": [
                *old["evidence_ids"],
                provenance_evidence["evidence_id"],
            ],
            # This remains a syntactically valid provider-grade provenance,
            # but it is not the provenance attested by the typed receipt.
            "provenance": "provider_client_emitted",
            "observation": provenance_receipt["observation"],
        }
        provenance_request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="provenance-chief-stop-transaction",
            command_id="provenance-chief-stop-command",
            events=[
                *supervisor_module._provider_lifecycle_drafts(
                    provenance_receipt,
                    evidence=provenance_evidence,
                ),
                CompanyEventDraft(
                    event_id=(
                        supervisor_module
                        ._fenced_chief_execution_stop_event_id(
                            old["execution_id"],
                            transaction_id=(
                                "provenance-chief-stop-transaction"
                            ),
                            command_id="provenance-chief-stop-command",
                        )
                    ),
                    event_type="execution.chief_fenced.stopped",
                    recorded_at="2026-07-27T00:03:00Z",
                    payload=provenance_candidate,
                    provenance="provider_client_emitted",
                ),
            ],
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="fenced Chief execution stop transition differs",
        ):
            supervisor.commit(
                provenance_request,
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before

        forged = {
            **old,
            "runtime_status": "stopped",
            "updated_at": "2026-07-27T00:03:00Z",
            "last_event_at": "2026-07-27T00:03:00Z",
            "heartbeat_at": None,
            "current_tool": None,
        }
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="forged-chief-stop-transaction",
            command_id="forged-chief-stop-command",
            events=[CompanyEventDraft(
                event_id="forged-chief-stop-event",
                event_type="execution.chief_fenced.stopped",
                recorded_at="2026-07-27T00:03:00Z",
                payload=forged,
                provenance="AOI_verified",
            )],
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="Chief execution status transaction membership differs",
        ):
            supervisor.commit(
                request,
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before


def test_fenced_chief_stop_raw_evidence_loss_degrades_current_health(
    tmp_path: Path,
) -> None:
    supervisor = initialize(tmp_path, carrier=known_carrier())
    slot = supervisor.slot_root
    contender = handoff_carrier(2)
    capability = prepare_handoff(
        supervisor,
        contender,
        nonce="b" * 64,
        user_action_ref="user-action-chief-stop-health",
    )
    supervisor.takeover_chief(
        capability,
        contender,
        consumed_at="2026-07-27T00:02:00Z",
        grant_expires_at="2026-07-29T00:00:00Z",
    )
    old_execution = next(
        item
        for item in _objects(supervisor, EXECUTION_NODE_V1)
        if item["carrier_id"] == "carrier-1"
    )
    receipt = fenced_chief_stop_receipt(
        supervisor,
        execution_id=old_execution["execution_id"],
        transaction_id="fenced-chief-health-transaction",
        command_id="fenced-chief-health-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    supervisor.record_fenced_chief_execution_stopped(
        old_execution["execution_id"],
        receipt,
        transaction_id="fenced-chief-health-transaction",
        command_id="fenced-chief-health-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    artifact_path = supervisor._state.blobs.path_for_digest(
        receipt["raw_artifact"]["sha256"],
    )
    assert artifact_path.is_file()
    assert artifact_path.parent.parent.parent == supervisor._state.blobs.root
    supervisor.close()
    artifact_path.unlink()

    with CompanySupervisor.open(slot) as reopened:
        health = reopened.health()
        assert health.status == "degraded"
        assert health.blob_status == "degraded"
        assert (
            "provider_lifecycle_evidence_unavailable"
            in health.degradation_reasons
        )
        meta = CompanyViewService(reopened._state).section("meta")
        assert meta["completeness"] == "partial"
        assert (
            "provider_lifecycle_evidence_unavailable"
            in meta["warnings"]
        )


def test_fenced_chief_stop_rejects_role_evasion_and_timestamp_split(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="c" * 64,
            user_action_ref="user-action-chief-stop-counterexample",
        )
        supervisor.takeover_chief(
            capability,
            contender,
            consumed_at="2026-07-27T00:02:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        old_execution = next(
            item
            for item in _objects(supervisor, EXECUTION_NODE_V1)
            if item["carrier_id"] == "carrier-1"
        )
        receipt = fenced_chief_stop_receipt(
            supervisor,
            execution_id=old_execution["execution_id"],
            transaction_id="chief-stop-counterexample-transaction",
            command_id="chief-stop-counterexample-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        captured: dict[str, Any] = {}
        original_commit = supervisor.commit

        def capture_commit(
            request: Mapping[str, Any],
            **_: Any,
        ) -> None:
            captured["request"] = copy.deepcopy(dict(request))
            raise RuntimeError("captured fenced Chief stop request")

        monkeypatch.setattr(supervisor, "commit", capture_commit)
        with pytest.raises(
            RuntimeError,
            match="captured fenced Chief stop request",
        ):
            supervisor.record_fenced_chief_execution_stopped(
                old_execution["execution_id"],
                receipt,
                transaction_id="chief-stop-counterexample-transaction",
                command_id="chief-stop-counterexample-command",
                recorded_at="2026-07-27T00:03:00Z",
            )
        monkeypatch.setattr(supervisor, "commit", original_commit)
        valid_request = captured["request"]
        before = supervisor.heads().global_head.global_sequence

        role_evasion = copy.deepcopy(valid_request)
        role_event = role_evasion["events"][2]
        role_event["payload"]["role"] = "worker"
        role_event["payload_sha256"] = company_contract_sha256(
            role_event["payload"],
        )
        role_evasion["request_sha256"] = company_contract_sha256({
            key: value
            for key, value in role_evasion.items()
            if key != "request_sha256"
        })
        with pytest.raises(
            CompanyStateInvariantError,
            match="fenced Chief execution stop transition differs",
        ):
            original_commit(
                role_evasion,
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before

        timestamp_split = copy.deepcopy(valid_request)
        execution_event = timestamp_split["events"][2]
        execution_event["payload"]["updated_at"] = "2026-07-27T00:04:00Z"
        execution_event["payload"]["last_event_at"] = "2026-07-27T00:04:00Z"
        execution_event["recorded_at"] = "2026-07-27T00:04:00Z"
        execution_event["payload_sha256"] = company_contract_sha256(
            execution_event["payload"],
        )
        timestamp_split["request_sha256"] = company_contract_sha256({
            key: value
            for key, value in timestamp_split.items()
            if key != "request_sha256"
        })
        with pytest.raises(
            CompanyStateInvariantError,
            match="fenced Chief execution stop transition differs",
        ):
            original_commit(
                timestamp_split,
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before


def test_takeover_preserves_an_already_stopped_prior_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="d" * 64,
            user_action_ref="user-action-stopped-prior-takeover",
        )
        original_objects = supervisor.objects
        prior_item = original_objects(
            contract_type=EXECUTION_NODE_V1,
        )[0]
        stopped_payload = {
            **dict(prior_item.payload),
            "engineering_status": "idle",
            "runtime_status": "stopped",
            "updated_at": "2026-07-27T00:00:30Z",
            "last_event_at": "2026-07-27T00:00:30Z",
            "heartbeat_at": None,
            "wait_reason": "runtime_stopped",
            "current_tool": None,
            "provenance": "host_process_observed",
            "observation": {"state": "known", "reason": "observed"},
        }

        def stopped_projection(
            *,
            contract_type: str | None = None,
        ) -> tuple[ProjectedObject, ...]:
            if contract_type == EXECUTION_NODE_V1:
                return (replace(prior_item, payload=stopped_payload),)
            return original_objects(contract_type=contract_type)

        captured: dict[str, Any] = {}

        def capture_commit(
            request: Mapping[str, Any],
            **_: Any,
        ) -> None:
            captured["request"] = copy.deepcopy(dict(request))
            raise RuntimeError("captured stopped-prior takeover")

        monkeypatch.setattr(supervisor, "objects", stopped_projection)
        monkeypatch.setattr(supervisor, "commit", capture_commit)
        with pytest.raises(
            RuntimeError,
            match="captured stopped-prior takeover",
        ):
            supervisor.takeover_chief(
                capability,
                contender,
                consumed_at="2026-07-27T00:02:00Z",
                grant_expires_at="2026-07-29T00:00:00Z",
            )
        prior_revision = next(
            event["payload"]
            for event in captured["request"]["events"]
            if event["event_type"] == "execution.authority_fenced"
        )
        assert prior_revision["engineering_status"] == "idle"
        assert prior_revision["runtime_status"] == "stopped"
        assert prior_revision["wait_reason"] == "runtime_stopped"
        assert prior_revision["heartbeat_at"] is None
        assert prior_revision["provenance"] == "host_process_observed"
        assert prior_revision["updated_at"] == "2026-07-27T00:02:00Z"
        assert prior_revision["last_event_at"] == "2026-07-27T00:02:00Z"


def test_old_chief_grant_is_fenced_before_ledger_after_takeover(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        old_grant = next(
            item
            for item in _objects(supervisor, AUTHORITY_GRANT_V1)
            if item["actor_kind"] == "chief"
        )
        old_grant["permissions"] = list(old_grant["permissions"])
        old_authority = authority_from_grant(old_grant)
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="4" * 64,
            user_action_ref="user-action-old-chief-fence",
        )
        supervisor.takeover_chief(
            capability,
            contender,
            consumed_at="2026-07-27T00:02:00Z",
            grant_expires_at="2026-07-29T00:00:00Z",
        )
        before = supervisor.heads().global_head.global_sequence
        payload = {
            "contract_type": DEPARTMENT_IDENTITY_V1,
            "schema_version": 1,
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
            "department_id": "late-old-chief-department",
            "name": "LATE",
            "charter_sha256": "a" * 64,
            "scope_sha256": "b" * 64,
            "lead_node_id": None,
            "created_at": "2026-07-27T00:03:00Z",
            "status": "parked",
            "observation": {"state": "known", "reason": "observed"},
        }
        request = build_company_transaction_request(
            supervisor.heads(),
            old_authority,
            transaction_id="late-old-chief-transaction",
            command_id="late-old-chief-command",
            events=[CompanyEventDraft(
                event_id="late-old-chief-event",
                event_type="department.created",
                recorded_at="2026-07-27T00:03:00Z",
                payload=payload,
            )],
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="fenced",
        ):
            supervisor.commit(
                request,
                recorded_at="2026-07-27T00:03:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.record_by_transaction_id(
            "late-old-chief-transaction",
        ) is None


def test_takeover_rejects_expired_or_carrier_divergent_capability(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="5" * 64,
            user_action_ref="user-action-expiry",
        )
        before = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyChiefTakeoverError,
            match="consumption",
        ):
            supervisor.takeover_chief(
                capability,
                contender,
                consumed_at="2026-07-27T01:00:00Z",
                grant_expires_at="2026-07-29T00:00:00Z",
            )
        divergent = dict(contender)
        divergent["thread_id"] = "different-thread"
        with pytest.raises(
            CompanyChiefTakeoverError,
            match="carrier observation",
        ):
            supervisor.takeover_chief(
                capability,
                divergent,
                consumed_at="2026-07-27T00:02:00Z",
                grant_expires_at="2026-07-29T00:00:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert _objects(supervisor, TAKEOVER_CAPABILITY_V1) == []
        assert _objects(
            supervisor,
            TAKEOVER_CONSUMPTION_RECEIPT_V1,
        ) == []


def test_takeover_contender_carrier_id_is_fresh_at_prepare_and_commit(
    tmp_path: Path,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="6" * 64,
            user_action_ref="user-action-carrier-id-race",
        )
        term = _objects(supervisor, CHIEF_TERM_V1)[0]
        binding = {
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
        }
        preexisting_fenced_carrier = {
            "contract_type": CARRIER_BINDING_V1,
            "schema_version": 1,
            **binding,
            "carrier_id": contender["carrier_id"],
            "actor_id": term["chief_id"],
            "provider": contender["provider"],
            "model": contender["model"],
            "session_id": contender["session_id"],
            "session_availability": "available",
            "state": "fenced",
            "bound_at": "2026-07-27T00:01:30Z",
            "last_observed_at": "2026-07-27T00:01:30Z",
            "observation": {"state": "known", "reason": "observed"},
        }
        request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="carrier-id-race-transaction",
            command_id="carrier-id-race-command",
            events=[CompanyEventDraft(
                event_id="carrier-id-race-event",
                event_type="carrier.fenced",
                recorded_at="2026-07-27T00:01:30Z",
                payload=preexisting_fenced_carrier,
            )],
        )
        supervisor.commit(
            request,
            recorded_at="2026-07-27T00:01:30Z",
        )
        before = supervisor.heads().global_head.global_sequence

        with pytest.raises(
            CompanyChiefTakeoverError,
            match="new durable carrier ID",
        ):
            prepare_handoff(
                supervisor,
                contender,
                nonce="7" * 64,
                user_action_ref="user-action-reuse-durable-carrier",
            )
        with pytest.raises(
            CompanyStateInvariantError,
            match="new durable carrier ID",
        ):
            supervisor.takeover_chief(
                capability,
                contender,
                consumed_at="2026-07-27T00:03:00Z",
                grant_expires_at="2026-07-29T00:00:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.record_by_transaction_id(
            str(capability["consumption_transaction_id"]),
        ) is None


def test_takeover_stream_and_provenance_are_rejected_before_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with initialize(tmp_path, carrier=known_carrier()) as supervisor:
        contender = handoff_carrier(2)
        capability = prepare_handoff(
            supervisor,
            contender,
            nonce="8" * 64,
            user_action_ref="user-action-envelope-gate",
        )
        captured: dict[str, Any] = {}
        original_commit = supervisor.commit

        def capture_commit(
            request: Mapping[str, Any],
            **_: Any,
        ) -> None:
            captured["request"] = copy.deepcopy(dict(request))
            raise RuntimeError("captured takeover request")

        monkeypatch.setattr(supervisor, "commit", capture_commit)
        with pytest.raises(RuntimeError, match="captured takeover request"):
            supervisor.takeover_chief(
                capability,
                contender,
                consumed_at="2026-07-27T00:02:00Z",
                grant_expires_at="2026-07-29T00:00:00Z",
            )
        monkeypatch.setattr(supervisor, "commit", original_commit)
        valid_request = captured["request"]
        before = supervisor.heads().global_head.global_sequence

        wrong_stream = copy.deepcopy(valid_request)
        capability_event = next(
            event
            for event in wrong_stream["events"]
            if event["payload"]["contract_type"] == TAKEOVER_CAPABILITY_V1
        )
        capability_event["stream"] = "execution"
        wrong_stream["request_sha256"] = company_contract_sha256({
            key: value
            for key, value in wrong_stream.items()
            if key != "request_sha256"
        })
        with pytest.raises(
            CompanyStateInvariantError,
            match="event envelope",
        ):
            original_commit(
                wrong_stream,
                recorded_at="2026-07-27T00:02:00Z",
            )

        wrong_provenance = copy.deepcopy(valid_request)
        contender_event = next(
            event
            for event in wrong_provenance["events"]
            if (
                event["payload"]["contract_type"] == CARRIER_BINDING_V1
                and event["payload"]["carrier_id"]
                == contender["carrier_id"]
            )
        )
        contender_event["provenance"] = "AOI_verified"
        wrong_provenance["request_sha256"] = company_contract_sha256({
            key: value
            for key, value in wrong_provenance.items()
            if key != "request_sha256"
        })
        with pytest.raises(
            CompanyStateInvariantError,
            match="event envelope",
        ):
            original_commit(
                wrong_provenance,
                recorded_at="2026-07-27T00:02:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == before
        assert supervisor._state.record_by_transaction_id(
            str(capability["consumption_transaction_id"]),
        ) is None


def test_department_identities_and_leads_start_parked(tmp_path: Path) -> None:
    with initialize(tmp_path) as supervisor:
        nodes = _objects(supervisor, ORGANIZATION_NODE_V1)
        identities = _objects(supervisor, DEPARTMENT_IDENTITY_V1)
        assert all(node["status"] == "parked" for node in nodes if node["role"] != "chief")
        assert all(identity["status"] == "parked" for identity in identities)


def test_maximum_company_id_uses_bounded_deterministic_derived_ids(tmp_path: Path) -> None:
    maximum_company_id = "c" * 128
    with initialize(tmp_path, company_id=maximum_company_id) as supervisor:
        ids = [
            item[key]
            for contract_type, key in (
                (AUTHORITY_GRANT_V1, "actor_id"),
                (ORGANIZATION_NODE_V1, "node_id"),
                (DEPARTMENT_IDENTITY_V1, "department_id"),
            )
            for item in _objects(supervisor, contract_type)
        ]
        assert all(len(value) <= 256 and maximum_company_id not in value for value in ids)


def test_exact_restart_reopens_without_second_genesis_transaction(tmp_path: Path) -> None:
    supervisor = initialize(tmp_path)
    slot = supervisor.slot_root
    supervisor.close()
    with CompanySupervisor.initialize(
        slot,
        manifest(),
        bootstrap_at=T,
        grant_expires_at=EXPIRY,
        platform="windows" if os.name == "nt" else "posix",
    ) as restarted:
        assert restarted.heads().global_head.global_sequence == 1
        assert len(restarted.records_after(0)) == 1


def test_initialize_rejects_manifest_and_bootstrap_time_drift(
    tmp_path: Path,
) -> None:
    slot = tmp_path / "state" / "companies" / "company-1"
    with pytest.raises(CompanySupervisorError, match="manifest"):
        CompanySupervisor.initialize(
            slot,
            manifest(),
            bootstrap_at="2026-07-27T00:00:05Z",
            grant_expires_at=EXPIRY,
            platform="windows" if os.name == "nt" else "posix",
        )
    assert not (slot / "current.json").exists()


@pytest.mark.parametrize(
    "grant_expires_at",
    ["not-a-time", T, "2026-07-26T23:59:59Z"],
)
def test_initialize_rejects_invalid_expiry_before_pointer_publication(
    tmp_path: Path,
    grant_expires_at: str,
) -> None:
    slot = tmp_path / "state" / "companies" / "company-1"
    with pytest.raises(CompanySupervisorError, match="authority grant"):
        CompanySupervisor.initialize(
            slot,
            manifest(),
            bootstrap_at=T,
            grant_expires_at=grant_expires_at,
            platform="windows" if os.name == "nt" else "posix",
        )
    assert not (slot / "current.json").exists()


def test_open_rejects_noncanonical_known_carrier_genesis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = supervisor_module._carrier_payload

    def drifted_payload(*args: Any, **kwargs: Any) -> dict[str, Any]:
        payload = dict(original(*args, **kwargs))
        if kwargs.get("known_carrier") is not None:
            payload["bound_at"] = "2026-07-27T00:00:05Z"
            payload["last_observed_at"] = "2026-07-27T00:00:05Z"
        return payload

    monkeypatch.setattr(
        supervisor_module,
        "_carrier_payload",
        drifted_payload,
    )
    supervisor = initialize(tmp_path, carrier=known_carrier())
    slot = supervisor.slot_root
    supervisor.close()
    monkeypatch.setattr(
        supervisor_module,
        "_carrier_payload",
        original,
    )
    with pytest.raises(CompanySupervisorError, match="carrier payload"):
        CompanySupervisor.open(slot)


def test_bootstrap_cannot_self_assert_provider_provenance(
    tmp_path: Path,
) -> None:
    carrier = known_carrier()
    carrier["provenance"] = "provider_client_emitted"
    slot = tmp_path / "state" / "companies" / "company-1"
    with pytest.raises(CompanySupervisorError, match="agent_reported"):
        CompanySupervisor.initialize(
            slot,
            manifest(),
            bootstrap_at=T,
            grant_expires_at=EXPIRY,
            known_carrier=carrier,
            platform="windows" if os.name == "nt" else "posix",
        )
    assert not (slot / "current.json").exists()


def test_retry_rejects_bootstrap_expiry_and_carrier_mode_drift(tmp_path: Path) -> None:
    supervisor = initialize(tmp_path / "unknown")
    slot = supervisor.slot_root
    supervisor.close()
    with pytest.raises(CompanySupervisorError, match="time differs"):
        CompanySupervisor.initialize(slot, manifest(), bootstrap_at="2026-07-27T00:00:01Z", grant_expires_at=EXPIRY, platform="windows" if os.name == "nt" else "posix")
    with pytest.raises(CompanySupervisorError, match="expiry differs"):
        CompanySupervisor.initialize(slot, manifest(), bootstrap_at=T, grant_expires_at="2026-07-29T00:00:00Z", platform="windows" if os.name == "nt" else "posix")
    with pytest.raises(CompanySupervisorError, match="carrier mode"):
        CompanySupervisor.initialize(
            slot,
            manifest(),
            bootstrap_at=T,
            grant_expires_at=EXPIRY,
            known_carrier=known_carrier(),
            platform="windows" if os.name == "nt" else "posix",
        )
    known = initialize(tmp_path / "known", carrier=known_carrier())
    known_slot = known.slot_root
    known.close()
    with pytest.raises(CompanySupervisorError, match="carrier mode"):
        CompanySupervisor.initialize(known_slot, manifest(), bootstrap_at=T, grant_expires_at=EXPIRY, platform="windows" if os.name == "nt" else "posix")
    changed_carrier = dict(known_carrier())
    changed_carrier["thread_id"] = "thread-2"
    with pytest.raises(CompanySupervisorError, match="carrier payload"):
        CompanySupervisor.initialize(
            known_slot,
            manifest(),
            bootstrap_at=T,
            grant_expires_at=EXPIRY,
            known_carrier=changed_carrier,
            platform="windows" if os.name == "nt" else "posix",
        )


def test_open_accepts_legitimate_post_genesis_object(tmp_path: Path) -> None:
    supervisor = initialize(tmp_path)
    slot = supervisor.slot_root
    first = supervisor.records_after(0)[0]
    authority = first.events[0].event["actor_authority"]
    payload = {
        "contract_type": DEPARTMENT_IDENTITY_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "department_id": "extra-department",
        "name": "EXTRA",
        "charter_sha256": "e" * 64,
        "scope_sha256": "f" * 64,
        "lead_node_id": None,
        "created_at": "2026-07-27T00:00:01Z",
        "status": "parked",
        "observation": {"state": "known", "reason": "observed"},
    }
    request = build_company_transaction_request(
        supervisor.heads(),
        authority,
        transaction_id="post-genesis-transaction",
        command_id="post-genesis-command",
        events=[CompanyEventDraft(event_id="post-genesis-department-event", event_type="department.created", recorded_at="2026-07-27T00:00:01Z", payload=payload)],
    )
    supervisor.commit(request, recorded_at="2026-07-27T00:00:01Z")
    supervisor.close()
    with CompanySupervisor.open(slot) as reopened:
        assert any(item["department_id"] == "extra-department" for item in _objects(reopened, DEPARTMENT_IDENTITY_V1))


def test_partial_nonempty_ledger_is_rejected_on_open(tmp_path: Path) -> None:
    slot = tmp_path / "state" / "companies" / "company-1"
    owner = CompanyStateOwner.initialize(
        slot,
        manifest(),
        platform="windows" if os.name == "nt" else "posix",
    )
    try:
        binding = {
            "company_id": "company-1",
            "company_incarnation": 1,
            "lock_domain_generation": 1,
        }
        grant = _authority_grant(
            binding,
            grant_id="partial-grant",
            actor_id="partial-supervisor",
            actor_kind="supervisor",
            carrier_id=None,
            chief_epoch=None,
            permissions=["company.mutate"],
            bootstrap_at=T,
            grant_expires_at=EXPIRY,
        )
        request = build_company_transaction_request(
            owner.heads(),
            authority_from_grant(grant),
            transaction_id="partial-transaction",
            command_id="partial-command",
            events=[
                CompanyEventDraft(
                    event_id="partial-manifest-event",
                    event_type="manifest.recorded",
                    recorded_at=T,
                    payload=manifest(),
                ),
            ],
        )
        owner.commit(request, recorded_at=T)
    finally:
        owner.close()
    with pytest.raises(CompanySupervisorError, match="genesis"):
        CompanySupervisor.open(slot)


def test_open_obeys_lifetime_lock_exclusion(tmp_path: Path) -> None:
    with initialize(tmp_path) as supervisor:
        with pytest.raises(CompanyProcessLockBusyError):
            CompanySupervisor.open(
                supervisor.slot_root,
                lock_timeout_seconds=0.1,
            )


def test_open_fails_closed_on_registry_manifest_binding_drift(tmp_path: Path) -> None:
    supervisor = initialize(tmp_path)
    manifest_path = supervisor.manifest_path
    slot = supervisor.slot_root
    supervisor.close()
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["configuration_sha256"] = "f" * 64
    manifest_path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(CompanyRegistryError, match="manifest"):
        CompanySupervisor.open(slot)
