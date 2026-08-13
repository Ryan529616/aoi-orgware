from __future__ import annotations

import copy
from pathlib import Path
import sys
from types import MappingProxyType
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    ACTOR_AUTHORITY_V1,
    COMPANY_MANIFEST_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    ZERO_SHA256,
    company_contract_sha256,
)
from aoi_orgware.company.ledger import LedgerHead, LedgerHeadsSnapshot
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    CompanyTransactionBuildError,
    build_company_transaction_request,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_company_contracts import (  # type: ignore[import-not-found]
    task_revision,
    work_definition_enforcement,
    work_dispatch_binding,
    work_packet,
    work_result_receipt,
)


H = "a" * 64
T = "2026-07-27T00:00:00Z"
BINDING = {
    "company_id": "company-1",
    "company_incarnation": 1,
    "lock_domain_generation": 1,
}


def authority() -> dict[str, Any]:
    return {
        "contract_type": ACTOR_AUTHORITY_V1,
        "schema_version": 1,
        **BINDING,
        "actor_id": "supervisor-1",
        "actor_kind": "supervisor",
        "carrier_id": None,
        "chief_epoch": None,
        "term": 1,
        "authority_state": "active",
        "permissions": ["company.mutate"],
        "scope_sha256": H,
        "authority_record_sha256": H,
        "provenance": "AOI_verified",
    }


def manifest() -> dict[str, Any]:
    return {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        **BINDING,
        "git_common_dir_sha256": H,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows",
        "created_at": T,
        "observation": {"state": "known", "reason": "observed"},
    }


def execution() -> dict[str, Any]:
    return {
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        **BINDING,
        "execution_id": "execution-1",
        "execution_kind": "carrier",
        "display_name": "Chief",
        "organization_node_id": "chief-1",
        "department_id": None,
        "parent_execution_id": None,
        "execution_depth": 0,
        "execution_path": ["execution-1"],
        "task_id": "task-1",
        "packet_id": None,
        "thread_id": "thread-1",
        "turn_id": "turn-1",
        "agent_id": None,
        "job_id": None,
        "dispatch_id": None,
        "registration_id": None,
        "receipt_id": None,
        "provider": "codex",
        "model": "gpt-5",
        "effort": "unknown",
        "carrier_id": "carrier-1",
        "role": "chief",
        "delegation_depth": 0,
        "engineering_status": "active",
        "runtime_status": "running",
        "attention_overlays": [],
        "objective": "Operate the company",
        "phase": "bootstrap",
        "created_at": T,
        "updated_at": T,
        "last_event_at": T,
        "heartbeat_at": T,
        "wait_reason": None,
        "current_tool": None,
        "terminal_at": None,
        "usage_cursor": 0,
        "job_ids": [],
        "evidence_ids": [],
        "provenance": "provider_client_emitted",
        "observation": {"state": "known", "reason": "observed"},
    }


def dispatch_request(*, command_id: str = "command-1") -> dict[str, Any]:
    return {
        "contract_type": DISPATCH_REQUEST_V1,
        "schema_version": 1,
        **BINDING,
        "dispatch_request_id": "dispatch-request-1",
        "dispatch_revision_id": "dispatch-revision-1",
        "revision": 1,
        "previous_event_id": None,
        "previous_payload_sha256": None,
        "command_id": command_id,
        "reservation_id": "reservation-1",
        "task_id": None,
        "packet_id": None,
        "manager_node_id": "manager-1",
        "target_node_id": "target-1",
        "department_id": None,
        "parent_execution_id": "execution-parent-1",
        "requested_role": "worker",
        "requested_capability_tier": "standard",
        "route_policy_id": "route-policy-1",
        "scope_sha256": H,
        "delegation_depth": 1,
        "state": "queued",
        "attempt": 0,
        "provider_dispatch_id": None,
        "execution_id": None,
        "effect_evidence": [],
        "reconcile_ref": None,
        "resolves_event_ids": [],
        "created_at": T,
        "updated_at": T,
        "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    }


def empty_heads() -> LedgerHeadsSnapshot:
    return LedgerHeadsSnapshot(
        identity=None,
        global_head=LedgerHead(0, ZERO_SHA256),
        stream_heads=MappingProxyType({}),
    )


def bound_work_contract(
    value: dict[str, object],
    *,
    digest_field: str,
) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.update(BINDING)
    result[digest_field] = company_contract_sha256(
        {
            key: member
            for key, member in result.items()
            if key != digest_field
        },
    )
    return result


def test_builds_deterministic_bootstrap_request() -> None:
    drafts = [
        CompanyEventDraft(
            event_id="event-manifest",
            event_type="manifest.recorded",
            recorded_at=T,
            payload=manifest(),
        ),
        CompanyEventDraft(
            event_id="event-execution",
            event_type="execution.started",
            recorded_at=T,
            payload=execution(),
            provenance="provider_client_emitted",
        ),
    ]
    first = build_company_transaction_request(
        empty_heads(),
        authority(),
        transaction_id="transaction-1",
        command_id="command-1",
        events=drafts,
    )
    second = build_company_transaction_request(
        empty_heads(),
        authority(),
        transaction_id="transaction-1",
        command_id="command-1",
        events=drafts,
    )

    assert first == second
    assert first["request_sha256"] == company_contract_sha256(
        {key: value for key, value in first.items() if key != "request_sha256"},
    )
    assert [head["stream"] for head in first["expected_heads"]] == [
        "org",
        "execution",
    ]
    assert [event["stream"] for event in first["events"]] == [
        "org",
        "execution",
    ]


def test_uses_exact_durable_global_and_stream_heads() -> None:
    heads = LedgerHeadsSnapshot(
        identity=("company-1", 1, 1),
        global_head=LedgerHead(7, "f" * 64),
        stream_heads=MappingProxyType(
            {
                "execution": (4, "e" * 64),
                "org": (3, "d" * 64),
            },
        ),
    )
    request = build_company_transaction_request(
        heads,
        authority(),
        transaction_id="transaction-2",
        command_id="command-2",
        events=[
            CompanyEventDraft(
                event_id="event-execution",
                event_type="execution.updated",
                recorded_at=T,
                payload=execution(),
            ),
            CompanyEventDraft(
                event_id="event-manifest",
                event_type="manifest.recorded",
                recorded_at=T,
                payload=manifest(),
            ),
        ],
    )
    assert request["expected_transaction_head"]["global_sequence"] == 7
    assert request["expected_transaction_head"]["transaction_sha256"] == "f" * 64
    assert [
        (head["stream"], head["cursor"], head["event_sha256"])
        for head in request["expected_heads"]
    ] == [
        ("org", 3, "d" * 64),
        ("execution", 4, "e" * 64),
    ]
    assert [event["event_id"] for event in request["events"]] == [
        "event-execution",
        "event-manifest",
    ]


def test_projects_dispatch_request_to_execution_with_exact_command_binding() -> None:
    drafts = [
        CompanyEventDraft(
            event_id="event-dispatch-request",
            event_type="dispatch.requested",
            recorded_at=T,
            payload=dispatch_request(),
        ),
    ]
    first = build_company_transaction_request(
        empty_heads(),
        authority(),
        transaction_id="transaction-1",
        command_id="command-1",
        events=drafts,
    )
    second = build_company_transaction_request(
        empty_heads(),
        authority(),
        transaction_id="transaction-1",
        command_id="command-1",
        events=drafts,
    )

    assert first == second
    assert [head["stream"] for head in first["expected_heads"]] == ["execution"]
    assert first["events"][0]["stream"] == "execution"
    assert first["events"][0]["payload"]["command_id"] == "command-1"


def test_projects_registered_work_definition_contracts_to_fixed_streams() -> None:
    request = build_company_transaction_request(
        empty_heads(),
        authority(),
        transaction_id="transaction-1",
        command_id="command-1",
        events=[
            CompanyEventDraft(
                event_id="event-task",
                event_type="work.task-registered",
                recorded_at=T,
                payload=bound_work_contract(
                    task_revision(),
                    digest_field="task_sha256",
                ),
            ),
            CompanyEventDraft(
                event_id="event-packet",
                event_type="work.packet-registered",
                recorded_at=T,
                payload=bound_work_contract(
                    work_packet(),
                    digest_field="packet_sha256",
                ),
            ),
            CompanyEventDraft(
                event_id="event-binding",
                event_type="work.dispatch-bound",
                recorded_at=T,
                payload=bound_work_contract(
                    work_dispatch_binding(),
                    digest_field="binding_sha256",
                ),
            ),
            CompanyEventDraft(
                event_id="event-result",
                event_type="work.result-recorded",
                recorded_at=T,
                payload=bound_work_contract(
                    work_result_receipt(),
                    digest_field="receipt_sha256",
                ),
            ),
            CompanyEventDraft(
                event_id="event-enforcement",
                event_type="work.enforcement-activated",
                recorded_at=T,
                payload=bound_work_contract(
                    work_definition_enforcement(),
                    digest_field="enforcement_sha256",
                ),
            ),
        ],
    )

    assert [head["stream"] for head in request["expected_heads"]] == [
        "org",
        "execution",
        "evidence",
    ]
    assert [event["stream"] for event in request["events"]] == [
        "org",
        "execution",
        "execution",
        "evidence",
        "org",
    ]


def test_rejects_work_dispatch_binding_with_mismatched_outer_identity() -> None:
    binding = bound_work_contract(
        work_dispatch_binding(),
        digest_field="binding_sha256",
    )
    binding["transaction_id"] = "transaction-other"
    binding["binding_sha256"] = company_contract_sha256(
        {key: value for key, value in binding.items() if key != "binding_sha256"},
    )
    with pytest.raises(
        CompanyTransactionBuildError,
        match="WorkDispatchBinding differs",
    ):
        build_company_transaction_request(
            empty_heads(),
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[
                CompanyEventDraft(
                    event_id="event-binding",
                    event_type="work.dispatch-bound",
                    recorded_at=T,
                    payload=binding,
                ),
            ],
        )


def test_rejects_dispatch_request_with_mismatched_outer_command_id() -> None:
    with pytest.raises(CompanyTransactionBuildError, match="DispatchRequest command_id"):
        build_company_transaction_request(
            empty_heads(),
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[
                CompanyEventDraft(
                    event_id="event-dispatch-request",
                    event_type="dispatch.requested",
                    recorded_at=T,
                    payload=dispatch_request(command_id="command-other"),
                ),
            ],
        )


def test_rejects_empty_events_binding_drift_and_nonprojectable_payload() -> None:
    with pytest.raises(CompanyTransactionBuildError, match="at least one"):
        build_company_transaction_request(
            empty_heads(),
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[],
        )

    wrong_heads = LedgerHeadsSnapshot(
        identity=("company-2", 1, 1),
        global_head=LedgerHead(1, "f" * 64),
        stream_heads=MappingProxyType({"org": (1, "e" * 64)}),
    )
    with pytest.raises(CompanyTransactionBuildError, match="durable ledger"):
        build_company_transaction_request(
            wrong_heads,
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[
                CompanyEventDraft(
                    event_id="event-1",
                    event_type="manifest.recorded",
                    recorded_at=T,
                    payload=manifest(),
                ),
            ],
        )

    wrong_payload = copy.deepcopy(manifest())
    wrong_payload["company_id"] = "company-2"
    with pytest.raises(CompanyTransactionBuildError, match="event payload"):
        build_company_transaction_request(
            empty_heads(),
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[
                CompanyEventDraft(
                    event_id="event-1",
                    event_type="manifest.recorded",
                    recorded_at=T,
                    payload=wrong_payload,
                ),
            ],
        )

    with pytest.raises(CompanyTransactionBuildError, match="not projectable"):
        build_company_transaction_request(
            empty_heads(),
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[
                CompanyEventDraft(
                    event_id="event-1",
                    event_type="authority.observed",
                    recorded_at=T,
                    payload=authority(),
                ),
            ],
        )


def test_final_validator_rejects_duplicate_event_ids() -> None:
    with pytest.raises(ValueError, match="duplicated"):
        build_company_transaction_request(
            empty_heads(),
            authority(),
            transaction_id="transaction-1",
            command_id="command-1",
            events=[
                CompanyEventDraft(
                    event_id="event-1",
                    event_type="manifest.recorded",
                    recorded_at=T,
                    payload=manifest(),
                ),
                CompanyEventDraft(
                    event_id="event-1",
                    event_type="manifest.recorded",
                    recorded_at=T,
                    payload=manifest(),
                ),
            ],
        )
