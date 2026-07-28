from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    WORK_RESULT_RECEIPT_V1,
    canonical_company_json_bytes,
)
from aoi_orgware.company.supervisor import (
    CompanyDepartmentLifecycleError,
    CompanySupervisor,
    CompanyWorkDefinitionError,
    _department_dispatch_event_id,
    _next_department_dispatch_payload,
)
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    build_company_transaction_request,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_work_definition_registration as registration  # type: ignore[import-not-found]


def _registered_stopped_execution(
    tmp_path: Path,
) -> tuple[
    CompanySupervisor,
    dict[str, Any],
    dict[str, Any],
    str,
    bytes,
    dict[str, Any],
]:
    supervisor = lifecycle._initialize(tmp_path)
    task, packet, context, prompt = registration._work_bundle(supervisor)
    registration._register(supervisor, task, packet, context, prompt)
    identity, _, _ = lifecycle._rtl(supervisor)
    queued = supervisor.enqueue_department_dispatch(
        identity["department_id"],
        transaction_id="registered-enqueue-transaction",
        command_id="registered-enqueue-command",
        dispatch_request_id="registered-dispatch",
        reservation_id="registered-reservation",
        task_id=task["task_id"],
        packet_id=packet["packet_id"],
        route_policy_id="registered-route",
        requested_role="rtl_lead",
        requested_capability_tier="standard",
        requested_at="2026-07-27T00:01:00Z",
        recorded_at="2026-07-27T00:02:00Z",
    )
    replay = supervisor.enqueue_department_dispatch(
        identity["department_id"],
        transaction_id="registered-enqueue-transaction",
        command_id="registered-enqueue-command",
        dispatch_request_id="registered-dispatch",
        reservation_id="registered-reservation",
        task_id=task["task_id"],
        packet_id=packet["packet_id"],
        route_policy_id="registered-route",
        requested_role="rtl_lead",
        requested_capability_tier="standard",
        requested_at="2026-07-27T00:01:00Z",
        recorded_at="2026-07-27T00:02:00Z",
    )
    assert queued.dispatch_state == "queued"
    assert replay.idempotent_replay
    bindings = supervisor.objects(contract_type=WORK_DISPATCH_BINDING_V1)
    assert len(bindings) == 1
    binding = dict(bindings[0].payload)
    assert binding["dispatch_request_id"] == "registered-dispatch"
    assert binding["task_sha256"] == task["task_sha256"]
    assert binding["packet_sha256"] == packet["packet_sha256"]

    supervisor.admit_department_dispatch(
        "registered-dispatch",
        transaction_id="registered-admit-transaction",
        command_id="registered-admit-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    supervisor.begin_department_dispatch(
        "registered-dispatch",
        transaction_id="registered-begin-transaction",
        command_id="registered-begin-command",
        recorded_at="2026-07-27T00:04:00Z",
    )
    success_receipt = lifecycle._provider_receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id="registered-success-transaction",
        command_id="registered-success-command",
        recorded_at="2026-07-27T00:05:00Z",
        provider_dispatch_id="provider-registered-dispatch",
    )
    dispatched = supervisor.dispatch_department_lead(
        "registered-dispatch",
        success_receipt,
        transaction_id="registered-success-transaction",
        command_id="registered-success-command",
        recorded_at="2026-07-27T00:05:00Z",
    )
    assert dispatched.execution_id is not None
    stop_receipt = lifecycle._provider_receipt(
        supervisor,
        event_kind="execution_stopped",
        transaction_id="registered-stop-transaction",
        command_id="registered-stop-command",
        recorded_at="2026-07-27T00:06:00Z",
    )
    supervisor.stop_department_execution(
        dispatched.execution_id,
        stop_receipt,
        transaction_id="registered-stop-transaction",
        command_id="registered-stop-command",
        recorded_at="2026-07-27T00:06:00Z",
    )
    disposition_bytes, disposition_receipt = lifecycle._engineering_disposition(
        supervisor,
        dispatched.execution_id,
        transaction_id="registered-idle-transaction",
        command_id="registered-idle-command",
        recorded_at="2026-07-27T00:07:00Z",
    )
    return (
        supervisor,
        task,
        packet,
        dispatched.execution_id,
        disposition_bytes,
        disposition_receipt,
    )


def test_registered_dispatch_result_is_atomic_replayable_and_reopenable(
    tmp_path: Path,
) -> None:
    (
        supervisor,
        task,
        packet,
        execution_id,
        disposition_bytes,
        disposition_receipt,
    ) = _registered_stopped_execution(tmp_path)
    slot_root = supervisor.slot_root
    result_bytes = b'{"review":"accepted","status":"idle"}'
    idle = supervisor.record_department_execution_idle(
        execution_id,
        disposition_bytes,
        disposition_receipt,
        transaction_id="registered-idle-transaction",
        command_id="registered-idle-command",
        recorded_at="2026-07-27T00:07:00Z",
        result_bytes=result_bytes,
        result_media_type="application/json",
    )
    results = supervisor.objects(contract_type=WORK_RESULT_RECEIPT_V1)
    assert len(results) == 1
    result = dict(results[0].payload)
    assert result["task_sha256"] == task["task_sha256"]
    assert result["packet_sha256"] == packet["packet_sha256"]
    assert result["producer_execution_id"] == execution_id
    assert (
        supervisor._state.blobs.read(result["result_ref"]["sha256"])
        == result_bytes
    )
    replay = supervisor.record_department_execution_idle(
        execution_id,
        disposition_bytes,
        disposition_receipt,
        transaction_id="registered-idle-transaction",
        command_id="registered-idle-command",
        recorded_at="2026-07-27T00:07:00Z",
        result_bytes=result_bytes,
        result_media_type="application/json",
    )
    assert replay.idempotent_replay
    assert replay.global_sequence == idle.global_sequence
    cursor = supervisor.heads().global_head.global_sequence
    with pytest.raises(CompanyDepartmentLifecycleError):
        supervisor.record_department_execution_idle(
            execution_id,
            disposition_bytes,
            disposition_receipt,
            transaction_id="registered-idle-transaction",
            command_id="registered-idle-command",
            recorded_at="2026-07-27T00:07:00Z",
            result_bytes=b'{"review":"divergent"}',
            result_media_type="application/json",
        )
    assert supervisor.heads().global_head.global_sequence == cursor
    supervisor.close()

    with CompanySupervisor.open(slot_root) as reopened:
        reopened_results = reopened.objects(
            contract_type=WORK_RESULT_RECEIPT_V1,
        )
        assert len(reopened_results) == 1
        reopened_replay = reopened.record_department_execution_idle(
            execution_id,
            disposition_bytes,
            disposition_receipt,
            transaction_id="registered-idle-transaction",
            command_id="registered-idle-command",
            recorded_at="2026-07-27T00:07:00Z",
            result_bytes=result_bytes,
            result_media_type="application/json",
        )
        assert reopened_replay.idempotent_replay
        assert reopened_replay.global_sequence == idle.global_sequence


def test_registered_idle_requires_exact_result_without_partial_commit(
    tmp_path: Path,
) -> None:
    (
        supervisor,
        _task,
        _packet,
        execution_id,
        disposition_bytes,
        disposition_receipt,
    ) = _registered_stopped_execution(tmp_path)
    try:
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyDepartmentLifecycleError,
            match="result bytes or media type",
        ):
            supervisor.record_department_execution_idle(
                execution_id,
                disposition_bytes,
                disposition_receipt,
                transaction_id="registered-idle-transaction",
                command_id="registered-idle-command",
                recorded_at="2026-07-27T00:07:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
        assert not supervisor.objects(contract_type=WORK_RESULT_RECEIPT_V1)
    finally:
        supervisor.close()


def test_result_cas_orphan_before_ledger_is_safe_to_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        supervisor,
        _task,
        _packet,
        execution_id,
        disposition_bytes,
        disposition_receipt,
    ) = _registered_stopped_execution(tmp_path)
    result_bytes = b'{"status":"retry-after-ledger-fault"}'
    original_commit = supervisor.commit

    def fail_before_ledger(*_args: object, **_kwargs: object) -> Any:
        raise RuntimeError("injected before result ledger commit")

    try:
        cursor = supervisor.heads().global_head.global_sequence
        monkeypatch.setattr(supervisor, "commit", fail_before_ledger)
        with pytest.raises(RuntimeError, match="injected before result ledger"):
            supervisor.record_department_execution_idle(
                execution_id,
                disposition_bytes,
                disposition_receipt,
                transaction_id="registered-idle-transaction",
                command_id="registered-idle-command",
                recorded_at="2026-07-27T00:07:00Z",
                result_bytes=result_bytes,
                result_media_type="application/json",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
        assert not supervisor.objects(contract_type=WORK_RESULT_RECEIPT_V1)

        monkeypatch.setattr(supervisor, "commit", original_commit)
        committed = supervisor.record_department_execution_idle(
            execution_id,
            disposition_bytes,
            disposition_receipt,
            transaction_id="registered-idle-transaction",
            command_id="registered-idle-command",
            recorded_at="2026-07-27T00:07:00Z",
            result_bytes=result_bytes,
            result_media_type="application/json",
        )
        assert not committed.idempotent_replay
        assert len(supervisor.objects(
            contract_type=WORK_RESULT_RECEIPT_V1,
        )) == 1
    finally:
        supervisor.close()


def test_child_context_accepts_only_the_durable_parent_result(
    tmp_path: Path,
) -> None:
    (
        supervisor,
        task,
        parent,
        execution_id,
        disposition_bytes,
        disposition_receipt,
    ) = _registered_stopped_execution(tmp_path)
    try:
        result_bytes = b'{"status":"parent-result"}'
        supervisor.record_department_execution_idle(
            execution_id,
            disposition_bytes,
            disposition_receipt,
            transaction_id="registered-idle-transaction",
            command_id="registered-idle-command",
            recorded_at="2026-07-27T00:07:00Z",
            result_bytes=result_bytes,
            result_media_type="application/json",
        )
        durable_result = registration._plain(
            supervisor.objects(
                contract_type=WORK_RESULT_RECEIPT_V1,
            )[0].payload,
        )
        parent_context = registration._plain(
            supervisor._state._read_work_context_manifest_unlocked(
                parent["context_manifest_ref"],
            ),
        )
        child_context = copy.deepcopy(parent_context)
        child_context["upstream_result_refs"] = [
            durable_result["result_ref"],
        ]
        child_context_bytes = canonical_company_json_bytes(child_context)
        child_prompt = b"Review the durable parent result only."
        child = copy.deepcopy(parent)
        child.update({
            "packet_id": "packet-child-result-1",
            "parent_packet_id": parent["packet_id"],
            "parent_packet_sha256": parent["packet_sha256"],
            "parent_execution_id": execution_id,
            "delegation_depth": 2,
            "prompt_ref": {
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": hashlib.sha256(child_prompt).hexdigest(),
                "size_bytes": len(child_prompt),
                "media_type": WORK_PACKET_PROMPT_MEDIA_TYPE,
                "availability": "available",
            },
            "context_manifest_ref": {
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": hashlib.sha256(child_context_bytes).hexdigest(),
                "size_bytes": len(child_context_bytes),
                "media_type": WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
                "availability": "available",
            },
            "authority_scope": {
                **child["authority_scope"],
                "write_refs": [],
            },
            "created_at": "2026-07-27T00:07:01Z",
        })
        registration._rehash(child, "packet_sha256")
        accepted = supervisor.register_work_definition(
            task,
            child,
            child_context,
            child_prompt,
            **registration._chief_fence(supervisor),
            transaction_id="child-result-register-transaction",
            command_id="child-result-register-command",
            recorded_at="2026-07-27T00:07:01Z",
        )
        assert accepted.packet_id == "packet-child-result-1"

        fake_result_ref = registration._blob_ref(
            b'{"status":"not-a-durable-result"}',
            "application/json",
            supervisor,
        )
        forged_context = copy.deepcopy(parent_context)
        forged_context["upstream_result_refs"] = [fake_result_ref]
        forged_context_bytes = canonical_company_json_bytes(
            forged_context,
        )
        forged = copy.deepcopy(child)
        forged.update({
            "packet_id": "packet-child-result-forged",
            "context_manifest_ref": {
                "contract_type": BLOB_REF_V1,
                "schema_version": 1,
                "sha256": hashlib.sha256(
                    forged_context_bytes,
                ).hexdigest(),
                "size_bytes": len(forged_context_bytes),
                "media_type": WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
                "availability": "available",
            },
        })
        registration._rehash(forged, "packet_sha256")
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="upstream result lacks one durable producer",
        ):
            supervisor.register_work_definition(
                task,
                forged,
                forged_context,
                child_prompt,
                **registration._chief_fence(supervisor),
                transaction_id="forged-child-register-transaction",
                command_id="forged-child-register-command",
                recorded_at="2026-07-27T00:07:02Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor
    finally:
        supervisor.close()


def test_enforcement_gate_is_one_way_and_rejects_new_legacy_queue(
    tmp_path: Path,
) -> None:
    supervisor = lifecycle._initialize(tmp_path)
    try:
        task, packet, context, prompt = registration._work_bundle(supervisor)
        registration._register(supervisor, task, packet, context, prompt)
        fence = registration._chief_fence(supervisor)
        gate = supervisor.activate_work_definition_enforcement(
            **fence,
            transaction_id="enforcement-transaction",
            command_id="enforcement-command",
            activated_at="2026-07-27T00:00:10Z",
        )
        replay = supervisor.activate_work_definition_enforcement(
            **fence,
            transaction_id="enforcement-transaction",
            command_id="enforcement-command",
            activated_at="2026-07-27T00:00:10Z",
        )
        assert gate.mode == "registered_launch_required"
        assert replay.idempotent_replay
        assert len(supervisor.objects(
            contract_type=WORK_DEFINITION_ENFORCEMENT_V1,
        )) == 1
        identity, _, _ = lifecycle._rtl(supervisor)
        cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="unbound queue item",
        ):
            supervisor.enqueue_department_dispatch(
                identity["department_id"],
                transaction_id="legacy-after-gate-transaction",
                command_id="legacy-after-gate-command",
                dispatch_request_id="legacy-after-gate-dispatch",
                reservation_id="legacy-after-gate-reservation",
                task_id="legacy-task",
                packet_id="legacy-packet",
                route_policy_id="legacy-route",
                requested_role="rtl_lead",
                requested_capability_tier="standard",
                requested_at="2026-07-27T00:01:00Z",
                recorded_at="2026-07-27T00:02:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == cursor

        supervisor.enqueue_department_dispatch(
            identity["department_id"],
            transaction_id="registered-after-gate-transaction",
            command_id="registered-after-gate-command",
            dispatch_request_id="registered-after-gate-dispatch",
            reservation_id="registered-after-gate-reservation",
            task_id=task["task_id"],
            packet_id=packet["packet_id"],
            route_policy_id="registered-route",
            requested_role="rtl_lead",
            requested_capability_tier="standard",
            requested_at="2026-07-27T00:01:00Z",
            recorded_at="2026-07-27T00:02:00Z",
        )
        supervisor.admit_department_dispatch(
            "registered-after-gate-dispatch",
            transaction_id="registered-after-gate-admit-transaction",
            command_id="registered-after-gate-admit-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        launch_cursor = supervisor.heads().global_head.global_sequence
        with pytest.raises(
            CompanyWorkDefinitionError,
            match="registered launch gate",
        ):
            supervisor.begin_department_dispatch(
                "registered-after-gate-dispatch",
                transaction_id="expired-launch-transaction",
                command_id="expired-launch-command",
                recorded_at="2026-07-27T02:00:00Z",
            )
        assert supervisor.heads().global_head.global_sequence == launch_cursor

        expired_at = "2026-07-27T02:00:00Z"
        current = supervisor._current_department_dispatch(
            "registered-after-gate-dispatch",
        )
        in_flight = _next_department_dispatch_payload(
            current,
            target_state="in_flight",
            transaction_id="expired-generic-transaction",
            command_id="expired-generic-command",
            recorded_at=expired_at,
            effect_evidence=[],
            reconcile_ref=None,
            provenance="AOI_verified",
            observation={"state": "known", "reason": "observed"},
        )
        generic_request = build_company_transaction_request(
            supervisor.heads(),
            supervisor._supervisor_authority(),
            transaction_id="expired-generic-transaction",
            command_id="expired-generic-command",
            events=[
                CompanyEventDraft(
                    event_id=_department_dispatch_event_id(
                        in_flight,
                        transaction_id="expired-generic-transaction",
                    ),
                    event_type="dispatch.request.in_flight",
                    recorded_at=expired_at,
                    payload=in_flight,
                    provenance="AOI_verified",
                ),
            ],
        )
        with pytest.raises(
            CompanyStateInvariantError,
            match="work dispatch binding is expired",
        ):
            supervisor.commit(
                generic_request,
                recorded_at=expired_at,
            )
        assert supervisor.heads().global_head.global_sequence == launch_cursor
        assert (
            supervisor._current_department_dispatch(
                "registered-after-gate-dispatch",
            ).payload["state"]
            == "admitted"
        )

        with pytest.raises(
            CompanyWorkDefinitionError,
            match="already active",
        ):
            supervisor.activate_work_definition_enforcement(
                **fence,
                transaction_id="second-enforcement-transaction",
                command_id="second-enforcement-command",
                activated_at="2026-07-27T00:00:11Z",
            )
    finally:
        supervisor.close()
