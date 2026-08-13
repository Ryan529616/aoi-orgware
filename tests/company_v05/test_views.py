from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from types import MappingProxyType
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import (
    ALERT_V1,
    AUTHORITY_GRANT_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    CONTROL_INTENT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_LIFECYCLE_RECEIPT_V1,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    EXECUTION_NODE_V1,
    EXTERNAL_JOB_V1,
    ORGANIZATION_NODE_V1,
    TASK_REVISION_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    company_contract_sha256,
)
from aoi_orgware.company.invariants import UncertainDispatch
from aoi_orgware.company.ledger import (
    LedgerEventRecord,
    LedgerHead,
    LedgerHeadsSnapshot,
    LedgerTransactionRecord,
)
from aoi_orgware.company.readmodel import ProjectedObject, ReadModelHead
from aoi_orgware.company.state import CompanyStateHealth
from aoi_orgware.company.state import CompanyQuerySnapshot
from aoi_orgware.company.views import (
    CompanyViewError,
    CompanyViewService,
    _execution_graph,
    _work_view,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_company_contracts import (  # type: ignore[import-not-found]
    blob,
    capability,
    control_intent,
    department_lifecycle_request,
    department_lifecycle_result,
    dispatch_request,
    family_records,
    grant,
    task_revision,
    work_definition_enforcement,
    work_dispatch_binding,
    work_packet,
    work_result_receipt,
)


H = "a" * 64
T = "2026-07-27T00:00:00Z"


@dataclass(frozen=True)
class _Resolved:
    manifest: Mapping[str, Any]


class _State:
    resolved = _Resolved(MappingProxyType({"company_id": "company-1"}))

    def __init__(
        self,
        *,
        projected: tuple[ProjectedObject, ...] | None = None,
        uncertain: tuple[UncertainDispatch, ...] = (),
        health_status: str = "ready",
        projection_status: str | None = None,
    ) -> None:
        self.records: tuple[LedgerTransactionRecord, ...] = ()
        self._projected = projected or _base_objects()
        self._uncertain = uncertain
        self._health_status = health_status
        self._projection_status = projection_status

    def health(self) -> CompanyStateHealth:
        heads = LedgerHeadsSnapshot(
            ("company-1", 1, 1),
            LedgerHead(4, H),
            MappingProxyType({"org": (2, "b" * 64)}),
        )
        return CompanyStateHealth(
            status=self._health_status,
            ledger_status=("ready" if self._health_status == "ready" else "degraded"),
            projection_status=(
                self._projection_status
                or ("ready" if self._health_status == "ready" else "degraded")
            ),
            pointer_sha256="c" * 64,
            ledger_heads=heads,
            readmodel_head=ReadModelHead(
                "company-1",
                1,
                1,
                4,
                H,
            ),
        )

    def objects(
        self,
        *,
        contract_type: str | None = None,
    ) -> tuple[ProjectedObject, ...]:
        assert contract_type is None
        return self._projected

    def query_snapshot(self) -> CompanyQuerySnapshot:
        return CompanyQuerySnapshot(
            self.health(),
            self.objects(),
            self._uncertain,
        )

    def records_after(
        self,
        cursor: int,
        *,
        limit: int,
    ) -> tuple[LedgerTransactionRecord, ...]:
        return tuple(
            record
            for record in self.records
            if record.global_sequence > cursor
        )[:limit]


def _projected(
    contract_type: str,
    key: str,
    payload: Mapping[str, Any],
    *,
    event_id: str | None = None,
    global_sequence: int = 4,
) -> ProjectedObject:
    return ProjectedObject(
        contract_type=contract_type,
        object_key=key,
        record_id=key,
        global_sequence=global_sequence,
        event_id=event_id or f"event-{key}",
        stream="org",
        payload=MappingProxyType(dict(payload)),
    )


def _base_objects() -> tuple[ProjectedObject, ...]:
    records = family_records()
    department = copy.deepcopy(records[2])
    department["lead_node_id"] = "rtl-lead-1"
    snapshot = copy.deepcopy(records[3])
    snapshot["snapshot_id"] = "rtl-snapshot-1"
    lead = copy.deepcopy(records[1])
    lead.update(
        {
            "node_id": "rtl-lead-1",
            "department_id": "rtl",
            "parent_node_id": "chief-1",
            "role": "department_lead",
            "reports_to_node_id": "chief-1",
            "can_delegate": True,
            "delegation_depth": 1,
            "status": "idle",
            "visibility": "subtree",
        },
    )
    selected = (
        records[0],
        records[1],
        department,
        snapshot,
        lead,
        records[5],
        records[6],
    )
    keys = (
        "company-1",
        "chief-1",
        "rtl",
        "rtl-snapshot-1",
        "rtl-lead-1",
        "carrier-1",
        "exec-1",
    )
    return tuple(
        _projected(str(payload["contract_type"]), key, payload)
        for key, payload in zip(keys, selected, strict=True)
    )


def _target() -> dict[str, object]:
    target = cast(dict[str, object], copy.deepcopy(family_records()[1]))
    target.update(
        {
            "node_id": "target-1",
            "department_id": "rtl",
            "parent_node_id": "chief-1",
            "reports_to_node_id": "chief-1",
            "role": "worker",
            "can_delegate": False,
            "delegation_depth": 1,
            "visibility": "subtree",
        },
    )
    return target


def _dispatch(
    *,
    state: str = "queued",
    request_id: str = "dispatch-1",
    revision_id: str | None = None,
    reservation_id: str | None = None,
    command_id: str | None = None,
) -> dict[str, object]:
    payload = cast(
        dict[str, object],
        copy.deepcopy(dispatch_request(state=state)),
    )
    payload.update(
        {
            "dispatch_request_id": request_id,
            "dispatch_revision_id": revision_id or f"revision-{request_id}",
            "reservation_id": reservation_id or f"reservation-{request_id}",
            "command_id": command_id or f"command-{request_id}",
            "manager_node_id": "chief-1",
            "target_node_id": "target-1",
            "department_id": "rtl",
            "parent_execution_id": "exec-1",
        },
    )
    return payload


def _registered_work_objects() -> tuple[ProjectedObject, ...]:
    task = cast(dict[str, object], copy.deepcopy(task_revision()))
    task["task_sha256"] = company_contract_sha256(
        {
            key: value
            for key, value in task.items()
            if key != "task_sha256"
        },
    )
    packet = cast(
        dict[str, object],
        copy.deepcopy(work_packet(task=task)),
    )
    packet.update(
        {
            "task_sha256": task["task_sha256"],
            "target_node_id": "target-1",
            "expires_at": "2026-07-28T00:00:00Z",
        },
    )
    packet["packet_sha256"] = company_contract_sha256(
        {
            key: value
            for key, value in packet.items()
            if key != "packet_sha256"
        },
    )
    binding = cast(
        dict[str, object],
        copy.deepcopy(work_dispatch_binding()),
    )
    binding.update(
        {
            "dispatch_request_id": "dispatch-1",
            "dispatch_revision_id": "revision-dispatch-1",
            "task_id": task["task_id"],
            "task_revision_id": task["task_revision_id"],
            "task_sha256": task["task_sha256"],
            "packet_id": packet["packet_id"],
            "packet_sha256": packet["packet_sha256"],
            "target_node_id": "target-1",
            "expires_at": "2026-07-28T00:00:00Z",
        },
    )
    binding["binding_sha256"] = company_contract_sha256(
        {
            key: value
            for key, value in binding.items()
            if key != "binding_sha256"
        },
    )
    gate = cast(
        dict[str, object],
        copy.deepcopy(work_definition_enforcement()),
    )
    return (
        _projected(TASK_REVISION_V1, "task-revision-1", task),
        _projected(WORK_PACKET_V1, "packet-1", packet),
        _projected(WORK_DISPATCH_BINDING_V1, "work-binding-1", binding),
        _projected(
            WORK_DEFINITION_ENFORCEMENT_V1,
            "work-definition-enforcement",
            gate,
        ),
    )


def _record() -> LedgerTransactionRecord:
    payload = MappingProxyType(
        {
            "contract_type": EXECUTION_NODE_V1,
            "execution_id": "execution-chief",
            "session_id": "session-event-secret",
            "thread_id": "thread-event-secret",
            "turn_id": "turn-event-secret",
            "native_handle": "native-event-secret",
        },
    )
    event = MappingProxyType(
        {
            "event_id": "event-1",
            "event_type": "execution.started",
            "stream": "execution",
            "recorded_at": T,
            "provenance": "AOI_verified",
            "payload": payload,
        },
    )
    return LedgerTransactionRecord(
        global_sequence=4,
        request=MappingProxyType(
            {
                "transaction_id": "transaction-1",
                "command_id": "command-1",
            },
        ),
        receipt=MappingProxyType(
            {"state": "committed", "recorded_at": T},
        ),
        events=(LedgerEventRecord(event, 2, H, "b" * 64),),
        reservations=(),
    )


def _chief_handoff_objects() -> tuple[ProjectedObject, ...]:
    """Add one current and one fenced carrier without validating mutations."""

    objects = list(_base_objects())
    carrier_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == CARRIER_BINDING_V1
    )
    execution_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == EXECUTION_NODE_V1
    )
    current_carrier = copy.deepcopy(dict(objects[carrier_index].payload))
    current_carrier.update(
        {
            "carrier_id": "carrier-current",
            "session_id": "session-current-secret",
            "state": "active",
        },
    )
    current_execution = copy.deepcopy(dict(objects[execution_index].payload))
    current_execution.update(
        {
            "execution_id": "exec-current",
            "execution_path": ["exec-current"],
            "carrier_id": "carrier-current",
            "thread_id": "thread-current-secret",
        },
    )
    objects[carrier_index] = _projected(
        CARRIER_BINDING_V1,
        "carrier-current",
        current_carrier,
    )
    objects[execution_index] = _projected(
        EXECUTION_NODE_V1,
        "exec-current",
        current_execution,
    )
    fenced_carrier = copy.deepcopy(current_carrier)
    fenced_carrier.update(
        {
            "carrier_id": "carrier-fenced",
            "session_id": "session-fenced-secret",
            "state": "fenced",
        },
    )
    fenced_execution = copy.deepcopy(current_execution)
    fenced_execution.update(
        {
            "execution_id": "exec-fenced",
            "execution_path": ["exec-fenced"],
            "carrier_id": "carrier-fenced",
            "thread_id": "thread-fenced-secret",
        },
    )
    term = copy.deepcopy(family_records()[4])
    term.update({"carrier_id": "carrier-current", "term": 2, "epoch": 2})
    current_grant = grant()
    current_grant.update(
        {
            "grant_id": "grant-current",
            "carrier_id": "carrier-current",
            "chief_epoch": 2,
            "term": 2,
        },
    )
    current_grant["grant_sha256"] = company_contract_sha256(
        {key: value for key, value in current_grant.items() if key != "grant_sha256"},
    )
    old_grant = copy.deepcopy(current_grant)
    old_grant.update(
        {
            "grant_id": "grant-old",
            "carrier_id": "carrier-fenced",
            "chief_epoch": 1,
            "term": 1,
        },
    )
    old_grant["grant_sha256"] = company_contract_sha256(
        {key: value for key, value in old_grant.items() if key != "grant_sha256"},
    )
    fenced_capability = capability()
    fenced_capability.update(
        {
            "capability_id": "capability-fenced",
            "contender_carrier_id": "carrier-fenced",
            "consumption_id": "consume-fenced",
        },
    )
    fenced_capability["capability_sha256"] = company_contract_sha256(
        {
            key: value
            for key, value in fenced_capability.items()
            if key != "capability_sha256"
        },
    )
    receipt = {
        "contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 2,
        "consumption_id": "consume-fenced",
        "transaction_id": "tx-1",
        "command_id": "command-1",
        "capability": fenced_capability,
        "capability_sha256": fenced_capability["capability_sha256"],
        "outcome": "fenced",
        "resulting_chief_term": None,
        "consumed_at": "2026-07-26T00:00:01Z",
    }
    receipt["receipt_sha256"] = company_contract_sha256(receipt)
    return (
        *objects,
        _projected(CARRIER_BINDING_V1, "carrier-fenced", fenced_carrier),
        _projected(EXECUTION_NODE_V1, "exec-fenced", fenced_execution),
        _projected(CHIEF_TERM_V1, "chief-1", term),
        _projected(AUTHORITY_GRANT_V1, "grant-current", current_grant),
        _projected(AUTHORITY_GRANT_V1, "grant-old", old_grant),
        _projected(
            TAKEOVER_CONSUMPTION_RECEIPT_V1,
            "consume-fenced",
            receipt,
        ),
    )


def _secret_event_record() -> LedgerTransactionRecord:
    payload = MappingProxyType(
        {
            "contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1,
            "capability": {
                "contract_type": "takeover_capability_v1",
                "capability_id": "capability-event",
                "user_action_ref": "event-user-action-secret",
                "nonce_sha256": "e" * 64,
            },
            "nested": {
                "session_id": "event-session-secret",
                "thread_id": "event-thread-secret",
            },
        },
    )
    event = MappingProxyType(
        {
            "event_id": "event-secret",
            "event_type": "chief.takeover",
            "stream": "org",
            "recorded_at": T,
            "provenance": "AOI_verified",
            "payload": payload,
        },
    )
    return LedgerTransactionRecord(
        global_sequence=5,
        request=MappingProxyType(
            {"transaction_id": "transaction-secret", "command_id": "command-secret"},
        ),
        receipt=MappingProxyType({"state": "committed", "recorded_at": T}),
        events=(LedgerEventRecord(event, 3, H, "c" * 64),),
        reservations=(),
    )


def _waking_department_objects() -> tuple[ProjectedObject, ...]:
    """A queued wake has no running execution or exposed transport handle."""

    objects = list(_base_objects())
    department_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == DEPARTMENT_IDENTITY_V1
    )
    execution_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == EXECUTION_NODE_V1
    )
    carrier_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == CARRIER_BINDING_V1
    )
    department = copy.deepcopy(dict(objects[department_index].payload))
    department["lead_node_id"] = "target-1"
    objects[department_index] = _projected(
        DEPARTMENT_IDENTITY_V1,
        "rtl",
        department,
    )
    execution = copy.deepcopy(dict(objects[execution_index].payload))
    execution.update(
        {
            "organization_node_id": "target-1",
            "department_id": "rtl",
            "engineering_status": "completed",
            "runtime_status": "stopped",
            "terminal_at": execution["updated_at"],
            "thread_id": "department-thread-secret",
        },
    )
    objects[execution_index] = _projected(
        EXECUTION_NODE_V1,
        "exec-1",
        execution,
    )
    carrier = copy.deepcopy(dict(objects[carrier_index].payload))
    carrier["actor_id"] = "target-1"
    objects[carrier_index] = _projected(
        CARRIER_BINDING_V1,
        "carrier-1",
        carrier,
    )
    lifecycle_request = department_lifecycle_request(
        operation="enqueue",
        expected_department_status="parked",
    )
    lifecycle_request.update(
        {
            "department_id": "rtl",
            "lead_node_id": "target-1",
            "expected_snapshot_id": "rtl-snapshot-1",
            "dispatch_request_id": "dispatch-wake-1",
            "reservation_id": "reservation-dispatch-wake-1",
        },
    )
    lifecycle_result = department_lifecycle_result(lifecycle_request)
    lifecycle_result["dispatch_request_id"] = "dispatch-wake-1"
    lifecycle_intent = control_intent()
    lifecycle_intent.update(
        {
            "control_intent_id": "intent-wake-1",
            "request_payload": lifecycle_request,
            "request_sha256": company_contract_sha256(
                lifecycle_request,
                max_bytes=64 * 1024,
            ),
            "result_payload": lifecycle_result,
            "result_sha256": company_contract_sha256(
                lifecycle_result,
                max_bytes=64 * 1024,
            ),
        },
    )
    lifecycle_receipt = {
        "receipt_type": DEPARTMENT_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": lifecycle_result["company_id"],
        "company_incarnation": lifecycle_result["company_incarnation"],
        "lock_domain_generation": lifecycle_result[
            "lock_domain_generation"
        ],
        "transaction_id": lifecycle_result["transaction_id"],
        "command_id": lifecycle_result["command_id"],
        "committed_cursor": lifecycle_result["committed_cursor"],
        "operation": lifecycle_result["operation"],
        "department_id": lifecycle_result["department_id"],
    }
    lifecycle_intent["terminal_receipt"] = lifecycle_receipt
    lifecycle_intent["receipt_sha256"] = company_contract_sha256(
        lifecycle_receipt,
        max_bytes=64 * 1024,
    )
    waking_lead = _target()
    waking_lead.update({"role": "department_lead", "can_delegate": True})
    return (
        *objects,
        _projected(ORGANIZATION_NODE_V1, "target-1", waking_lead),
        _projected(
            DISPATCH_REQUEST_V1,
            "dispatch-wake-1",
            _dispatch(request_id="dispatch-wake-1"),
        ),
        _projected(CONTROL_INTENT_V1, "intent-wake-1", lifecycle_intent),
    )


def test_current_sections_preserve_dual_status_and_unknown_coverage() -> None:
    service = CompanyViewService(_State(), clock=lambda: T)  # type: ignore[arg-type]
    meta = service.section("meta")
    execution = service.section("execution")
    departments = service.section("departments")

    assert meta["schema_version"] == 1
    assert meta["company_id"] == "company-1"
    assert meta["cursor"] == 4
    assert meta["completeness"] == "complete"
    assert meta["data"]["coverage"] == {
        "state": "unknown",
        "reason": "provider_adapters_not_yet_connected",
    }
    assert meta["data"]["security"]["authentication"] == "unavailable"
    assert service.section("optimizer")["data"]["state"] == "unavailable"
    node = execution["data"]["nodes"][0]
    assert node["engineering_status"] == "active"
    assert node["runtime_status"] == "running"
    assert execution["data"]["roots"] == ["exec-1"]
    assert execution["data"]["children"] == {"exec-1": []}
    assert execution["data"]["invalid_nodes"] == []
    assert execution["data"]["dispatch_queue"] == []
    assert execution["data"]["queue_summary"] == {
        "visible": 0,
        "returned": 0,
        "truncated": False,
        "effect_unknown": 0,
        "by_state": {},
        "completeness": "complete",
        "reason": None,
    }
    assert service.section("company")["data"]["capacity"] == {
        "occupied": 1,
        "occupied_semantics": "exact",
        "limit": 16,
        "available": 15,
        "reason": None,
        "unattributed_active": [],
    }
    assert departments["data"][0]["snapshot"]["snapshot_id"] == (
        "rtl-snapshot-1"
    )
    assert departments["data"][0]["manager_capacity"] == {
        "manager_node_id": "rtl-lead-1",
        "occupied": 0,
        "limit": 4,
        "available": 4,
        "reason": None,
    }
    snapshot = service.section("snapshot")
    assert snapshot["data"]["export"]["state"] == "unavailable"
    export = service.section("export")
    assert export["data"]["state"] == "unavailable"
    assert export["data"]["sanitized"] is False
    assert export["data"]["reason"] == "no_verified_sanitized_export"
    assert export["data"]["checkpoint"]["state"] == "unavailable"
    assert export["data"]["checkpoint"]["reason"] == "no_verified_checkpoint"
    assert export["data"]["redaction"]["security_boundary"] is False
    assert export["data"]["snapshot"] is None
    serialized_export = json.dumps(export, sort_keys=True)
    assert "thread-1" not in serialized_export


def test_department_wake_projection_is_dense_redacted_and_not_running() -> None:
    service = CompanyViewService(
        _State(projected=_waking_department_objects()),  # type: ignore[arg-type]
        clock=lambda: T,
    )

    department = service.section("departments")["data"][0]

    assert department["lifecycle_state"] == "waking"
    assert department["lifecycle_reason"] == "wake_dispatch_pending"
    assert department["lead"] == {
        "node_id": "target-1",
        "organization_status": "active",
    }
    assert department["current_execution"] is None
    assert department["snapshot"] == {
        "availability": "available",
        "snapshot_id": "rtl-snapshot-1",
        "revision": 1,
        "cursor": 1,
    }
    assert department["carrier"]["carrier_id"] == "carrier-1"
    assert department["carrier"]["session_availability"] == "available"
    assert department["wake_dispatch"] == {
        "dispatch_request_id": "dispatch-wake-1",
        "revision": 1,
        "state": "queued",
        "updated_at": "2026-07-26T00:00:01Z",
    }
    rendered = json.dumps(department, sort_keys=True)
    assert "session_id" not in rendered
    assert "thread_id" not in rendered
    assert "department-thread-secret" not in rendered


def test_failed_wake_dispatch_never_implies_a_running_department_after_refresh() -> None:
    objects = list(_waking_department_objects())
    dispatch_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == DISPATCH_REQUEST_V1
        and item.object_key == "dispatch-wake-1"
    )
    failed_dispatch = copy.deepcopy(dict(objects[dispatch_index].payload))
    failed_dispatch.update({
        "state": "failed_known",
        "attempt": 1,
        "effect_evidence": [blob()],
        "updated_at": "2026-07-27T00:00:02Z",
    })
    objects[dispatch_index] = _projected(
        DISPATCH_REQUEST_V1,
        "dispatch-wake-1",
        failed_dispatch,
    )

    department = CompanyViewService(
        _State(projected=tuple(objects)),  # type: ignore[arg-type]
        clock=lambda: T,
    ).section("departments")["data"][0]

    assert department["current_execution"] is None
    assert department["carrier"] is None
    assert department["wake_dispatch"]["state"] == "failed_known"
    assert department["lifecycle_state"] == "failed"
    assert department["lifecycle_reason"] == "wake_dispatch_failed"


def test_department_current_execution_links_to_validated_tree_descendant_count() -> None:
    objects = list(_waking_department_objects())
    parent_index = next(
        index
        for index, item in enumerate(objects)
        if item.contract_type == EXECUTION_NODE_V1
        and item.object_key == "exec-1"
    )
    child = copy.deepcopy(dict(objects[parent_index].payload))
    parent = copy.deepcopy(child)
    parent.update({
        "engineering_status": "active",
        "runtime_status": "running",
        "terminal_at": None,
        "updated_at": "2026-07-27T00:00:00Z",
    })
    objects[parent_index] = _projected(EXECUTION_NODE_V1, "exec-1", parent)
    child.update({
        "execution_id": "exec-child",
        "parent_execution_id": "exec-1",
        "execution_depth": 1,
        "execution_path": ["exec-1", "exec-child"],
        "engineering_status": "completed",
        "runtime_status": "stopped",
        "terminal_at": "2026-07-27T00:00:01Z",
        "updated_at": "2026-07-27T00:00:01Z",
    })
    objects.append(_projected(EXECUTION_NODE_V1, "exec-child", child))

    department = CompanyViewService(
        _State(projected=tuple(objects)),  # type: ignore[arg-type]
        clock=lambda: T,
    ).section("departments")["data"][0]

    assert department["current_execution"]["execution_id"] == "exec-1"
    assert department["current_execution"]["descendant_count"] == 1


def test_chief_handoff_projection_is_effective_and_recursively_redacted() -> None:
    state = _State(projected=_chief_handoff_objects())
    state.records = (_secret_event_record(),)
    service = CompanyViewService(state, clock=lambda: T)  # type: ignore[arg-type]

    company = service.section("company")["data"]
    chief = company["chief"]
    assert {
        key: chief["term"][key]
        for key in (
            "contract_type",
            "chief_id",
            "carrier_id",
            "term",
            "epoch",
            "state",
        )
    } == {
        "contract_type": CHIEF_TERM_V1,
        "chief_id": "chief-1",
        "carrier_id": "carrier-current",
        "term": 2,
        "epoch": 2,
        "state": "active",
    }
    assert chief["carrier"]["carrier_id"] == "carrier-current"
    assert chief["carrier"]["session_availability"] == "available"
    assert {
        grant["grant_id"]: grant["effective_state"]
        for grant in chief["authority_grants"]
    } == {"grant-current": "active", "grant-old": "fenced"}
    assert [attempt["outcome"] for attempt in chief["takeover_attempts"]] == [
        "fenced",
    ]
    assert chief["takeover_attempts"][0]["capability_id"] == "capability-fenced"
    assert chief["fenced_carriers"][0]["carrier_id"] == "carrier-fenced"

    execution = service.section("execution")["data"]
    states = {node["execution_id"]: node["carrier_state"] for node in execution["nodes"]}
    assert states["exec-current"] == "active"
    assert states["exec-fenced"] == "fenced"
    assert execution["roots"] == ["exec-current", "exec-fenced"]
    assert execution["children"] == {"exec-current": [], "exec-fenced": []}

    snapshot = service.section("snapshot")
    events = service.events_after(4)
    rendered = json.dumps({"snapshot": snapshot, "events": events}, sort_keys=True)
    for secret in (
        "session_id",
        "thread_id",
        "user_action_ref",
        "nonce_sha256",
        "session-current-secret",
        "session-fenced-secret",
        "thread-current-secret",
        "thread-fenced-secret",
        "user-action-secret",
        "event-user-action-secret",
        "event-session-secret",
        "event-thread-secret",
    ):
        assert secret not in rendered
    event_payload = events[0]["events"][0]["payload"]
    assert event_payload["contract_type"] == TAKEOVER_CONSUMPTION_RECEIPT_V1
    assert "capability" not in event_payload


def test_external_job_native_handle_is_redacted_from_all_view_projections() -> None:
    job = copy.deepcopy(family_records()[9])
    native_handle = "native-handle-must-not-leak"
    job.update({
        "state": "running",
        "external_handle": {
            "provider": "eda",
            "namespace": "jobs",
            "resolver": "pid",
            "native_handle": native_handle,
            "host_fingerprint_sha256": "d" * 64,
        },
        "process_fingerprint_sha256": "e" * 64,
        "process_observation": {"state": "known", "reason": "observed"},
    })
    state = _State(projected=(
        *_base_objects(),
        _projected(EXTERNAL_JOB_V1, "job-1", job),
    ))
    event = MappingProxyType({
        "event_id": "external-job-event-1",
        "event_type": "external_job.updated",
        "stream": "execution",
        "recorded_at": T,
        "provenance": "AOI_verified",
        "payload": MappingProxyType(job),
    })
    state.records = (LedgerTransactionRecord(
        global_sequence=5,
        request=MappingProxyType({
            "transaction_id": "transaction-external-job-1",
            "command_id": "command-1",
        }),
        receipt=MappingProxyType({"state": "committed", "recorded_at": T}),
        events=(LedgerEventRecord(event, 1, H, "b" * 64),),
        reservations=(),
    ),)
    service = CompanyViewService(state, clock=lambda: T)  # type: ignore[arg-type]

    jobs = service.section("jobs")["data"]
    snapshot = service.section("snapshot")["data"]
    events = service.events_after(4)
    rendered = json.dumps({
        "jobs": jobs,
        "snapshot": snapshot,
        "events": events,
    }, sort_keys=True)

    assert native_handle not in rendered
    for projection in (
        jobs[0],
        snapshot["jobs"][0],
        events[0]["events"][0]["payload"],
    ):
        assert projection["external_handle"] == {
            "availability": "available",
            "provider": "eda",
            "namespace": "jobs",
            "resolver": "pid",
            "host_fingerprint_sha256": "d" * 64,
        }
        assert "native_handle" not in projection["external_handle"]


def test_dispatch_shadow_is_first_and_the_frozen_base_is_not_repeated() -> None:
    current = _dispatch(
        state="in_flight",
        revision_id="revision-dispatch-1-3",
        command_id="command-dispatch-1-3",
    )
    current_event = "event-dispatch-base"
    current.update(
        {
            "revision": 3,
            "previous_event_id": "event-dispatch-admitted",
            "previous_payload_sha256": "a" * 64,
        },
    )
    shadow_payload = _dispatch(
        state="effect_unknown",
        revision_id="revision-dispatch-1-2",
        command_id="command-dispatch-1-2",
    )
    shadow_payload.update(
        {
            "revision": 4,
            "previous_event_id": current_event,
            "previous_payload_sha256": company_contract_sha256(current),
        },
    )
    shadow = UncertainDispatch(
        reservation_id="reservation-dispatch-1",
        dispatch_request_id="dispatch-1",
        source_event_id="uncertain-source-1",
        source_global_sequence=9,
        source_transaction_id="transaction-uncertain-1",
        source_command_id="command-dispatch-1-2",
        receipt_state="effect_unknown",
        requested_state="effect_unknown",
        payload_sha256=company_contract_sha256(shadow_payload),
        payload=shadow_payload,
    )
    state = _State(
        projected=(
            *_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            _projected(
                DISPATCH_REQUEST_V1,
                "dispatch-1",
                current,
                event_id=current_event,
                global_sequence=8,
            ),
        ),
        uncertain=(shadow,),
    )
    execution = CompanyViewService(state).section("execution")["data"]  # type: ignore[arg-type]

    queue = execution["dispatch_queue"]
    assert len(queue) == 1
    assert queue[0]["source"] == "uncertain_receipt"
    assert queue[0]["state"] == "effect_unknown"
    assert queue[0]["source_event_id"] == "uncertain-source-1"
    assert queue[0]["receipt_state"] == "effect_unknown"
    assert queue[0]["evidence_count"] == 1
    assert queue[0]["reconcile_required"] is True
    assert set(queue[0]) == {
        "source",
        "dispatch_request_id",
        "dispatch_revision_id",
        "reservation_id",
        "manager_node_id",
        "target_node_id",
        "department_id",
        "requested_role",
        "requested_capability_tier",
        "delegation_depth",
        "state",
        "attempt",
        "receipt_state",
        "source_cursor",
        "source_event_id",
        "created_at",
        "updated_at",
            "evidence_count",
            "reconcile_required",
            "launch_eligible",
            "launch_eligibility_reason",
    }
    assert "scope_sha256" not in queue[0]
    assert "effect_evidence" not in queue[0]
    assert all(node["execution_id"] != "dispatch-1" for node in execution["nodes"])
    assert execution["queue_summary"]["effect_unknown"] == 1


def test_committed_effect_unknown_dispatch_never_becomes_false_eligibility() -> None:
    state = _State(
        projected=(
            *_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            _projected(
                DISPATCH_REQUEST_V1,
                "dispatch-1",
                _dispatch(state="effect_unknown"),
            ),
        ),
    )

    queue = CompanyViewService(cast(Any, state)).section("execution")[
        "data"
    ]["dispatch_queue"]
    assert queue[0]["state"] == "effect_unknown"
    assert queue[0]["launch_eligible"] is None
    assert queue[0]["launch_eligibility_reason"] == (
        "dispatch_effect_unknown"
    )


def test_dispatch_capacity_and_manager_fanout_are_reducer_derived() -> None:
    admitted = _dispatch(state="admitted")
    state = _State(
        projected=(
            *_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            _projected(DISPATCH_REQUEST_V1, "dispatch-1", admitted),
        ),
    )
    service = CompanyViewService(state)  # type: ignore[arg-type]

    assert service.section("company")["data"]["capacity"] == {
        "occupied": 2,
        "occupied_semantics": "exact",
        "limit": 16,
        "available": 14,
        "reason": None,
        "unattributed_active": [],
    }
    assert service.section("departments")["data"][0]["manager_capacity"] == {
        "manager_node_id": "rtl-lead-1",
        "occupied": 0,
        "limit": 4,
        "available": 4,
        "reason": None,
    }


def test_unattributed_or_degraded_projection_never_invents_capacity() -> None:
    base = list(_base_objects())
    execution = copy.deepcopy(family_records()[6])
    execution["organization_node_id"] = "missing-organization-node"
    base[-1] = _projected(EXECUTION_NODE_V1, "exec-1", execution)
    unattributed = CompanyViewService(_State(projected=tuple(base)))  # type: ignore[arg-type]
    assert unattributed.section("company")["data"]["capacity"] == {
        "occupied": 1,
        "occupied_semantics": "lower_bound",
        "limit": 16,
        "available": None,
        "reason": "active_capacity_unattributed",
        "unattributed_active": ["execution:exec-1"],
    }
    assert unattributed.section("departments")["data"][0]["manager_capacity"]["available"] is None

    degraded = CompanyViewService(_State(health_status="degraded"))  # type: ignore[arg-type]
    capacity = degraded.section("company")["data"]["capacity"]
    assert capacity["occupied"] == 1
    assert capacity["occupied_semantics"] == "lower_bound"
    assert capacity["available"] is None
    assert capacity["reason"] == "company_state_degraded"
    assert degraded.section("execution")["data"]["queue_summary"] == {
        "visible": 0,
        "returned": 0,
        "truncated": False,
        "effect_unknown": 0,
        "by_state": {},
        "completeness": "partial",
        "reason": "company_state_degraded",
    }


def test_dispatch_queue_is_bounded_and_never_exposes_raw_request_fields() -> None:
    queue_objects = []
    for index in range(257):
        request_id = f"dispatch-{index:03d}"
        payload = _dispatch(request_id=request_id)
        queue_objects.append(
            _projected(
                DISPATCH_REQUEST_V1,
                request_id,
                payload,
                event_id=f"event-{request_id}",
                global_sequence=index + 5,
            ),
        )
    state = _State(
        projected=(
            *_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            *queue_objects,
        ),
    )
    execution = CompanyViewService(state).section("execution")["data"]  # type: ignore[arg-type]

    assert len(execution["dispatch_queue"]) == 256
    assert execution["queue_summary"] == {
        "visible": 257,
        "returned": 256,
        "truncated": True,
        "effect_unknown": 0,
        "by_state": {"queued": 257},
        "completeness": "complete",
        "reason": None,
    }
    assert all(
        "scope_sha256" not in row and "route_policy_id" not in row
        for row in execution["dispatch_queue"]
    )
    assert all(row["launch_eligible"] is False for row in execution["dispatch_queue"])
    assert all(
        row["launch_eligibility_reason"] == "dispatch_not_admitted"
        for row in execution["dispatch_queue"]
    )


def test_work_view_is_explicitly_unverified_by_default_and_metadata_only() -> None:
    service = CompanyViewService(cast(Any, _State()), clock=lambda: T)
    work = service.section("work")["data"]
    assert work["environment"] == {
        "environment_kind": "unverified",
        "source": "default_unverified",
        "provider_live_verified": False,
        "reason": "provider_live_verification_not_implemented",
    }
    assert work["provider_worker"] == {
        "state": "unavailable", "reason": "provider_worker_not_implemented",
    }
    assert work["gate"]["active"] is False
    assert work["tasks"] == [] and work["packets"] == []
    encoded = json.dumps(work, sort_keys=True)
    assert "prompt_ref" not in encoded and "context_manifest_ref" not in encoded

    explicit = CompanyViewService(
        cast(Any, _State()),
        clock=lambda: T,
        environment_kind="synthetic_canary",
    ).section("work")["data"]
    assert explicit["environment"]["environment_kind"] == "synthetic_canary"
    assert explicit["environment"]["source"] == "explicit_configuration"


def test_populated_work_view_is_bounded_sanitized_and_gate_only() -> None:
    state = _State(
        projected=(
            *_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            _projected(
                DISPATCH_REQUEST_V1,
                "dispatch-1",
                _dispatch(state="admitted"),
            ),
            *_registered_work_objects(),
        ),
    )
    service = CompanyViewService(cast(Any, state), clock=lambda: T)

    work = service.section("work")["data"]
    queue = service.section("execution")["data"]["dispatch_queue"]
    assert queue[0]["launch_eligible"] is True
    assert queue[0]["launch_eligibility_reason"] == (
        "registered_work_definition_admitted"
    )
    assert work["provider_worker"]["state"] == "unavailable"
    assert work["launch_eligibility_semantics"] == (
        "registered_work_gate_only; provider_worker_unavailable"
    )
    for name in ("tasks", "packets", "bindings"):
        assert work["collection_summary"][name] == {
            "visible": 1,
            "returned": 1,
            "truncated": False,
            "limit": 256,
        }
    assert work["collection_summary"]["results"] == {
        "visible": 0,
        "returned": 0,
        "truncated": False,
        "limit": 256,
    }
    encoded = json.dumps(work, sort_keys=True)
    for forbidden in (
        "prompt_ref",
        "context_manifest_ref",
        "result_ref",
        "expected_execution_payload_sha256",
        "dispatch_payload_sha256",
    ):
        assert forbidden not in encoded


def test_work_result_projection_exposes_metadata_not_raw_result_reference() -> None:
    result = cast(dict[str, Any], copy.deepcopy(work_result_receipt()))
    work, _eligibility = _work_view(
        tasks=[],
        packets=[],
        bindings=[],
        gates=[],
        results=[result],
        queue_items=(),
        completeness="complete",
        historical=False,
        now=T,
        environment_kind="unverified",
        environment_source="default_unverified",
    )

    assert work["results"] == [{
        key: result.get(key)
        for key in (
            "result_receipt_id", "task_id", "task_revision_id",
            "task_sha256", "packet_id", "packet_sha256",
            "producer_execution_id", "engineering_disposition_receipt_id",
            "recorded_at", "receipt_sha256",
        )
    }]
    encoded = json.dumps(work, sort_keys=True)
    assert "result_ref" not in encoded
    assert "expected_execution_payload_sha256" not in encoded


def test_historical_work_eligibility_has_no_current_time_claim() -> None:
    state = _State(
        projected=(
            *_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            _projected(
                DISPATCH_REQUEST_V1,
                "dispatch-1",
                _dispatch(state="admitted"),
            ),
            *_registered_work_objects(),
        ),
        projection_status="historical_prefix_replay",
    )

    queue = CompanyViewService(cast(Any, state), clock=lambda: T).section(
        "execution",
    )["data"]["dispatch_queue"]
    assert queue[0]["launch_eligible"] is None
    assert queue[0]["launch_eligibility_reason"] == (
        "historical_time_basis_unavailable"
    )


def test_work_metadata_collections_are_independently_bounded() -> None:
    tasks: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for index in range(257):
        suffix = f"{index:03d}"
        tasks.append({
            "task_revision_id": f"task-revision-{suffix}",
            "created_at": T,
        })
        packets.append({
            "packet_id": f"packet-{suffix}",
            "created_at": T,
        })
        bindings.append({
            "binding_id": f"binding-{suffix}",
            "dispatch_request_id": f"dispatch-{suffix}",
            "created_at": T,
        })
        results.append({
            "result_receipt_id": f"result-{suffix}",
            "recorded_at": T,
        })

    work, _eligibility = _work_view(
        tasks=tasks,
        packets=packets,
        bindings=bindings,
        gates=[],
        results=results,
        queue_items=(),
        completeness="complete",
        historical=False,
        now=T,
        environment_kind="unverified",
        environment_source="default_unverified",
    )
    for name in ("tasks", "packets", "bindings", "results"):
        assert len(work[name]) == 256
        assert work["collection_summary"][name] == {
            "visible": 257,
            "returned": 256,
            "truncated": True,
            "limit": 256,
        }
    assert work["tasks"][0]["task_revision_id"] == "task-revision-001"
    assert work["tasks"][-1]["task_revision_id"] == "task-revision-256"


def test_degraded_work_queue_marks_launch_eligibility_unknown() -> None:
    state = _State(
        projected=(*_base_objects(),
            _projected(ORGANIZATION_NODE_V1, "target-1", _target()),
            _projected(
                DISPATCH_REQUEST_V1, "dispatch-1", _dispatch(state="admitted"),
            )),
        health_status="degraded",
    )
    queue = CompanyViewService(state, clock=lambda: T).section("execution")["data"]["dispatch_queue"]  # type: ignore[arg-type]
    assert queue[0]["launch_eligible"] is None
    assert queue[0]["launch_eligibility_reason"] == "projection_incomplete"


def test_execution_graph_uses_parent_ancestry_not_flat_depth_sort() -> None:
    nodes: list[dict[str, Any]] = [
        {
            "execution_id": "root-b",
            "parent_execution_id": None,
            "execution_depth": 0,
            "execution_path": ["root-b"],
            "created_at": "2026-07-27T00:00:02Z",
        },
        {
            "execution_id": "child-a",
            "parent_execution_id": "root-a",
            "execution_depth": 1,
            "execution_path": ["root-a", "child-a"],
            "created_at": "2026-07-27T00:00:03Z",
        },
        {
            "execution_id": "root-a",
            "parent_execution_id": None,
            "execution_depth": 0,
            "execution_path": ["root-a"],
            "created_at": "2026-07-27T00:00:01Z",
        },
        {
            "execution_id": "orphan",
            "parent_execution_id": "missing",
            "execution_depth": 1,
            "execution_path": ["missing", "orphan"],
            "created_at": "2026-07-27T00:00:04Z",
        },
    ]

    roots, children, invalid = _execution_graph(nodes)

    assert roots == ["root-a", "root-b"]
    assert children == {
        "child-a": [],
        "root-a": ["child-a"],
        "root-b": [],
    }
    assert invalid == [
        {"execution_id": "orphan", "reason": "parent_missing"},
    ]


def test_orphan_execution_projection_is_visible_alerted_and_redacted() -> None:
    base_execution = dict(next(
        item.payload
        for item in _base_objects()
        if item.contract_type == EXECUTION_NODE_V1
    ))
    org_null_root = copy.deepcopy(base_execution)
    org_null_root.update(
        {
            "execution_id": "orphan-org-null-root",
            "organization_node_id": None,
            "parent_execution_id": None,
            "execution_depth": 0,
            "execution_path": ["orphan-org-null-root"],
            "session_id": "session-orphan-secret",
            "thread_id": "thread-orphan-secret",
            "turn_id": "turn-orphan-secret",
            "native_handle": "native-orphan-secret",
        },
    )
    parent_missing = copy.deepcopy(base_execution)
    parent_missing.update(
        {
            "execution_id": "orphan-parent-missing",
            "organization_node_id": "rtl-lead-1",
            "parent_execution_id": "missing-parent",
            "execution_depth": 1,
            "execution_path": ["missing-parent", "orphan-parent-missing"],
        },
    )
    root_identity = {
        "category": "execution_orphan",
        "execution_id": "orphan-org-null-root",
        "reason": "organization_node_missing",
    }
    colliding_ledger_alert_id = (
        "derived-read-only-execution-orphan-"
        + company_contract_sha256(root_identity)
    )
    ledger_alert = copy.deepcopy(next(
        record
        for record in family_records()
        if record["contract_type"] == ALERT_V1
    ))
    ledger_alert.update(
        {
            "alert_id": colliding_ledger_alert_id,
            "execution_id": "exec-1",
            "severity": "warning",
            "category": "ledger_alert",
            "created_at": T,
        },
    )
    state = _State(projected=(
        *_base_objects(),
        _projected(EXECUTION_NODE_V1, "orphan-org-null-root", org_null_root),
        _projected(EXECUTION_NODE_V1, "orphan-parent-missing", parent_missing),
        _projected(ALERT_V1, colliding_ledger_alert_id, ledger_alert),
    ))
    service = CompanyViewService(state, clock=lambda: T)  # type: ignore[arg-type]

    execution = service.section("execution")["data"]
    alerts = service.section("alerts")["data"]["alerts"]
    snapshot = service.section("snapshot")["data"]
    orphans = execution["orphans"]

    assert [node["execution_id"] for node in orphans] == [
        "orphan-org-null-root",
        "orphan-parent-missing",
    ]
    assert [node["orphan_reason"] for node in orphans] == [
        "organization_node_missing",
        "parent_missing",
    ]
    assert orphans[0]["parent_execution_id"] is None
    assert orphans[1]["parent_execution_id"] == "missing-parent"
    assert all(node["projection_source"] == "derived_read_only" for node in orphans)
    assert execution["invalid_nodes"] == [
        {"execution_id": "orphan-parent-missing", "reason": "parent_missing"},
    ]
    derived = [
        alert for alert in alerts
        if alert.get("projection_source") == "derived_read_only"
    ]
    assert len(derived) == 2
    assert all(alert["severity"] == "critical" for alert in derived)
    assert all(alert["state"] == "open" for alert in derived)
    assert all(alert["category"] == "execution_orphan" for alert in derived)
    assert all(
        alert["observation"] == {"state": "known", "reason": "observed"}
        for alert in derived
    )
    assert len({alert["alert_id"] for alert in alerts}) == len(alerts)
    root_alert = next(
        alert for alert in derived
        if alert["execution_id"] == "orphan-org-null-root"
    )
    assert root_alert["alert_id"] != colliding_ledger_alert_id
    assert root_alert["detail_sha256"] == company_contract_sha256(root_identity)
    assert snapshot["execution"]["orphans"] == orphans
    assert snapshot["alerts"]["alerts"] == alerts
    assert len([
        item for item in state._projected if item.contract_type == ALERT_V1
    ]) == 1
    serialized = json.dumps(snapshot, sort_keys=True)
    for secret in (
        "session-orphan-secret",
        "thread-orphan-secret",
        "turn-orphan-secret",
        "native-orphan-secret",
    ):
        assert secret not in serialized

    repeated_alerts = service.section("alerts")["data"]["alerts"]
    assert repeated_alerts == alerts


def test_unknown_section_and_invalid_event_bounds_fail_closed() -> None:
    service = CompanyViewService(_State())  # type: ignore[arg-type]
    with pytest.raises(CompanyViewError, match="unknown"):
        service.section("mutations")
    for cursor in (-1, True, "0"):
        with pytest.raises(CompanyViewError, match="cursor"):
            service.events_after(cursor)  # type: ignore[arg-type]
    for limit in (0, 1025, True):
        with pytest.raises(CompanyViewError, match="limit"):
            service.events_after(0, limit=limit)


def test_event_delta_is_bounded_and_carries_raw_projected_payload() -> None:
    state = _State()
    state.records = (_record(),)
    service = CompanyViewService(state, clock=lambda: T)  # type: ignore[arg-type]

    assert service.events_after(4) == ()
    delta = service.events_after(3)
    assert len(delta) == 1
    assert delta[0]["cursor"] == 4
    assert delta[0]["events"][0]["contract_type"] == EXECUTION_NODE_V1
    assert delta[0]["events"][0]["payload"]["execution_id"] == (
        "execution-chief"
    )
    assert all(
        key not in delta[0]["events"][0]["payload"]
        for key in ("session_id", "thread_id", "turn_id", "native_handle")
    )
