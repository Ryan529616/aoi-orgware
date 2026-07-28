"""Public transaction-builder coverage for provider-worker projections."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import sys
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    BLOB_REF_V1,
    COMPANY_MANIFEST_V1,
    CompanyContractError,
    DISPATCH_REQUEST_V1,
    PROVIDER_CODEX_HOME_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_TURN_RESULT_MEDIA_TYPE,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    PROVIDER_WORKER_RAW_MEDIA_TYPE,
    WORK_DISPATCH_BINDING_V1,
    WORK_RESULT_RECEIPT_V1,
    authority_from_grant,
    canonical_company_json_bytes,
    canonical_provider_turn_result_bytes,
    company_contract_sha256,
    validate_provider_worker_io_receipt,
)
from aoi_orgware.company.state import _plain as state_plain
from aoi_orgware.company.state import CompanyStateInvariantError
from aoi_orgware.company.invariants import (
    CompanyInvariantError,
    InvariantObject,
    _validate_department_dispatch_transition,
)
from aoi_orgware.company.supervisor import (
    CompanyDepartmentLifecycleError,
    CompanySupervisor,
    _department_dispatch_event_id,
    _next_department_dispatch_payload,
)
from aoi_orgware.company.transactions import (
    CompanyEventDraft,
    _PROJECTABLE_STREAM,
    build_company_transaction_request,
)

sys.path[:0] = [
    str(Path(__file__).resolve().parent),
    str(Path(__file__).resolve().parents[1]),
]
import test_department_lifecycle as lifecycle  # type: ignore[import-not-found]
import test_supervisor as supervisor_tests  # type: ignore[import-not-found]
import test_work_definition_registration as registration  # type: ignore[import-not-found]
from test_company_contracts import (  # type: ignore[import-not-found]
    provider_codex_home,
    provider_io_receipt,
    provider_launch_binding,
    provider_operation,
    provider_turn_result,
    provider_turn_result_receipt,
    route_policy,
)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(member) for key, member in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(member) for member in value]
    return value


def _objects(supervisor: Any, contract_type: str) -> list[dict[str, Any]]:
    return [_plain(item.payload) for item in supervisor.objects(
        contract_type=contract_type,
    )]


def _rehash(value: dict[str, Any], field: str) -> None:
    value[field] = company_contract_sha256({
        key: member for key, member in value.items() if key != field
    })


def _authority(supervisor: Any) -> dict[str, Any]:
    return _plain(authority_from_grant(
        _objects(supervisor, AUTHORITY_GRANT_V1)[0],
    ))


def _bound(supervisor: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Apply the live company identity before any cross-record hash."""
    payload.update(_plain(supervisor._binding()))
    return payload


def _commit(
    supervisor: Any, transaction_id: str, command_id: str,
    recorded_at: str, events: list[CompanyEventDraft],
) -> Any:
    request = build_company_transaction_request(
        supervisor.heads(), _authority(supervisor),
        transaction_id=transaction_id, command_id=command_id, events=events,
    )
    return supervisor.commit(request, recorded_at=recorded_at)


def test_provider_worker_contracts_have_exact_projectable_streams() -> None:
    """The public builder must accept the same stream ownership as replay."""
    assert {
        contract_type: _PROJECTABLE_STREAM[contract_type]
        for contract_type in (
            PROVIDER_CODEX_HOME_V1,
            PROVIDER_LAUNCH_BINDING_V1,
            PROVIDER_WORKER_OPERATION_V1,
            PROVIDER_WORKER_IO_RECEIPT_V1,
            PROVIDER_TURN_RESULT_RECEIPT_V1,
        )
    } == {
        PROVIDER_CODEX_HOME_V1: "execution",
        PROVIDER_LAUNCH_BINDING_V1: "execution",
        PROVIDER_WORKER_OPERATION_V1: "execution",
        PROVIDER_WORKER_IO_RECEIPT_V1: "evidence",
        PROVIDER_TURN_RESULT_RECEIPT_V1: "evidence",
    }


def test_projected_provider_io_payload_is_deep_normalized_for_strict_hashing() -> None:
    """Nested frozen readmodel payloads retain their original receipt hash."""
    receipt = provider_io_receipt()
    projected_payload = MappingProxyType({
        **receipt,
        "raw_artifact": MappingProxyType(dict(receipt["raw_artifact"])),
    })

    with pytest.raises(CompanyContractError, match="company contract hash is invalid"):
        validate_provider_worker_io_receipt(projected_payload)

    assert validate_provider_worker_io_receipt(
        state_plain(projected_payload),
    ) == receipt


def test_provider_launch_rejects_a_bare_in_flight_dispatch_revision() -> None:
    """A launch binding makes the process-start CAS indivisible.

    This is a negative guard only; the positive lifecycle remains a public
    Supervisor fixture rather than an InvariantObject fixture.
    """
    recorded_at = "2026-07-27T00:06:00Z"
    dispatch = InvariantObject(
        DISPATCH_REQUEST_V1, "dispatch-1", "dispatch-event", 3, "a" * 64,
        {
            "dispatch_request_id": "dispatch-1", "department_id": "rtl",
            "revision": 3, "state": "in_flight", "updated_at": recorded_at,
            "provenance": "AOI_verified",
        },
    )
    launch = InvariantObject(
        PROVIDER_LAUNCH_BINDING_V1, "launch-1", "launch-event", 2,
        "b" * 64, {"dispatch_request_id": "dispatch-1"},
    )
    request = {"events": [{
        "event_id": "dispatch-event", "recorded_at": recorded_at,
    }]}
    with pytest.raises(
        CompanyInvariantError,
        match="provider-bound department dispatch requires atomic process start",
    ):
        _validate_department_dispatch_transition(
            {(PROVIDER_LAUNCH_BINDING_V1, "launch-1"): launch},
            [dispatch], request, "committed",
        )


def test_provider_process_start_is_one_public_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The launch binding, pending process IO, and in-flight CAS commit together."""
    supervisor = lifecycle._initialize(tmp_path)
    closed = False
    try:
        task, packet, context, prompt = registration._work_bundle(supervisor)
        registration._register(supervisor, task, packet, context, prompt)
        identity, _lead, _snapshot = lifecycle._rtl(supervisor)
        supervisor.enqueue_department_dispatch(
            identity["department_id"],
            transaction_id="provider-enqueue", command_id="provider-enqueue-command",
            dispatch_request_id="provider-dispatch", reservation_id="provider-reservation",
            task_id=task["task_id"], packet_id=packet["packet_id"],
            route_policy_id="provider-route", requested_role="rtl_lead",
            requested_capability_tier="standard", requested_at="2026-07-27T00:03:00Z",
            recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.admit_department_dispatch(
            "provider-dispatch", transaction_id="provider-admit",
            command_id="provider-admit-command", recorded_at="2026-07-27T00:04:00Z",
        )
        dispatch_item = next(
            item for item in supervisor.objects(contract_type=DISPATCH_REQUEST_V1)
            if item.payload["dispatch_request_id"] == "provider-dispatch"
        )
        dispatch = _plain(dispatch_item.payload)
        binding = _objects(supervisor, WORK_DISPATCH_BINDING_V1)[0]
        manifest = _objects(supervisor, COMPANY_MANIFEST_V1)[0]

        policy = _bound(supervisor, route_policy())
        policy.update({
            "policy_id": "provider-route", "created_at": "2026-07-27T00:05:00Z",
        })
        _rehash(policy, "policy_sha256")
        home = _bound(supervisor, provider_codex_home())
        home.update({
            "home_id": "provider-codex-home",
            "dispatch_request_id": dispatch["dispatch_request_id"],
            "created_at": "2026-07-27T00:05:00Z",
            "updated_at": "2026-07-27T00:05:00Z",
        })
        _rehash(home, "home_sha256")
        launch = _bound(supervisor, provider_launch_binding())
        launch.update({
            "launch_binding_id": "provider-launch",
            "work_dispatch_binding_id": binding["binding_id"],
            "work_dispatch_binding_sha256": binding["binding_sha256"],
            "dispatch_request_id": dispatch["dispatch_request_id"],
            "dispatch_revision": dispatch["revision"],
            "dispatch_revision_id": dispatch["dispatch_revision_id"],
            "dispatch_payload_sha256": company_contract_sha256(dispatch),
            "route_policy_id": policy["policy_id"],
            "route_policy_revision": policy["revision"],
            "route_policy_sha256": policy["policy_sha256"],
            "home_id": home["home_id"], "home_revision": home["revision"],
            "home_sha256": home["home_sha256"],
            "manifest_sha256": company_contract_sha256(manifest),
            "source_sha256": packet["source_manifest_sha256"],
            "config_sha256": packet["config_manifest_sha256"],
            "dependency_sha256": packet["dependency_manifest_sha256"],
            "lock_domain_id": manifest["lock_domain_id"],
            "git_common_dir_sha256": manifest["git_common_dir_sha256"],
            "git_remote_sha256": manifest["remote_fingerprint_sha256"],
            "created_at": "2026-07-27T00:05:00Z",
            "expires_at": "2026-07-27T01:00:00Z",
        })
        _rehash(launch, "binding_sha256")
        _commit(
            supervisor, "provider-bind", "provider-bind-command", "2026-07-27T00:05:00Z",
            [
                CompanyEventDraft("provider-route-event", "provider.route_policy.bound", "2026-07-27T00:05:00Z", policy),
                CompanyEventDraft("provider-home-event", "provider.codex_home.ready", "2026-07-27T00:05:00Z", home),
                CompanyEventDraft("provider-launch-event", "provider.launch.bound", "2026-07-27T00:05:00Z", launch),
            ],
        )

        prepared = _bound(supervisor, provider_operation())
        prepared.update({
            "operation_id": "provider-process", "launch_binding_id": launch["launch_binding_id"],
            "launch_binding_sha256": launch["binding_sha256"],
            "dispatch_request_id": launch["dispatch_request_id"],
            "dispatch_revision_id": launch["dispatch_revision_id"],
            "operation_kind": "process_start", "execution_id": None,
            "thread_id": None, "turn_id": None, "created_at": "2026-07-27T00:05:30Z",
            "updated_at": "2026-07-27T00:05:30Z",
        })
        _rehash(prepared, "operation_sha256")
        _commit(
            supervisor, "provider-prepare", "provider-prepare-command", "2026-07-27T00:05:30Z",
            [CompanyEventDraft("provider-process-prepared", "provider.worker.operation.prepared", "2026-07-27T00:05:30Z", prepared)],
        )

        raw = b'{"phase":"process_start_pending"}'
        metadata = supervisor._state.blobs.put(raw)
        assert supervisor._state.blobs.read(metadata.sha256) == raw
        pending_io = _bound(
            supervisor,
            provider_io_receipt(phase="process_start_pending", channel="process"),
        )
        pending_io.update({
            "receipt_id": "provider-process-00-pending-io", "operation_id": prepared["operation_id"],
            "launch_binding_id": launch["launch_binding_id"], "launch_binding_sha256": launch["binding_sha256"],
            "dispatch_request_id": launch["dispatch_request_id"], "dispatch_revision_id": launch["dispatch_revision_id"],
            "execution_id": None, "thread_id": None, "turn_id": None, "sequence": 1,
            "raw_artifact": {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": metadata.sha256, "size_bytes": metadata.size_bytes, "media_type": PROVIDER_WORKER_RAW_MEDIA_TYPE, "availability": "available"},
            "observed_at": "2026-07-27T00:06:00Z",
        })
        _rehash(pending_io, "receipt_sha256")
        pending_operation = {**prepared, "revision": 2,
            "previous_sha256": prepared["operation_sha256"], "previous_state": "prepared",
            "state": "effect_pending", "effect_receipt_ids": [pending_io["receipt_id"]],
            "updated_at": "2026-07-27T00:06:00Z"}
        _rehash(pending_operation, "operation_sha256")
        flight = _next_department_dispatch_payload(
            dispatch_item, target_state="in_flight", transaction_id="provider-start",
            command_id="provider-start-command", recorded_at="2026-07-27T00:06:00Z",
            effect_evidence=(), reconcile_ref=None, provenance="AOI_verified",
            observation={"state": "known", "reason": "observed"},
        )
        _commit(
            supervisor, "provider-start", "provider-start-command", "2026-07-27T00:06:00Z",
            [
                CompanyEventDraft("provider-process-pending-io-event", "provider.worker.io.persisted", "2026-07-27T00:06:00Z", pending_io, provenance="adapter_receipt_persisted"),
                CompanyEventDraft("provider-process-pending-event", "provider.worker.operation.effect_pending", "2026-07-27T00:06:00Z", pending_operation),
                CompanyEventDraft(_department_dispatch_event_id(flight, transaction_id="provider-start"), "dispatch.request.in_flight", "2026-07-27T00:06:00Z", flight),
            ],
        )
        assert next(item.payload for item in supervisor.objects(contract_type=DISPATCH_REQUEST_V1) if item.payload["dispatch_request_id"] == "provider-dispatch")["state"] == "in_flight"

        sequence = 2
        minute = 6

        def stamp() -> str:
            nonlocal minute
            minute += 1
            return f"2026-07-27T00:{minute:02d}:00Z"

        def observe_operation(
            operation_id: str, kind: str, *, phase: str | None,
            response_phase: str | None, method: str | None = None,
            request_id: int | None = None, execution_id: str | None = None,
            thread_id: str | None = None, turn_id: str | None = None,
            extra_observation: tuple[str, ...] = (),
            existing_pending: dict[str, Any] | None = None,
            existing_pending_io: dict[str, Any] | None = None,
            observed_events: Any = None,
            commit_observed: bool = True,
        ) -> dict[str, Any]:
            """Persist one prepared/pending/observed operation with raw IO CAS."""
            nonlocal sequence
            prepared_at = stamp()
            if existing_pending is None:
                operation = _bound(supervisor, provider_operation())
                operation.update({
                    "operation_id": operation_id, "launch_binding_id": launch["launch_binding_id"],
                    "launch_binding_sha256": launch["binding_sha256"],
                    "dispatch_request_id": launch["dispatch_request_id"],
                    "dispatch_revision_id": launch["dispatch_revision_id"],
                    "operation_kind": kind, "execution_id": execution_id,
                    "thread_id": thread_id, "turn_id": turn_id,
                    "created_at": prepared_at, "updated_at": prepared_at,
                })
                _rehash(operation, "operation_sha256")
                _commit(supervisor, f"{operation_id}-prepare", f"{operation_id}-prepare-command", prepared_at, [
                    CompanyEventDraft(f"{operation_id}-prepared", "provider.worker.operation.prepared", prepared_at, operation),
                ])
                assert _plain(next(
                    item.payload for item in supervisor.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
                    if item.payload["operation_id"] == operation_id
                )) == operation
            else:
                operation = existing_pending

            def receipt(
                receipt_id: str, receipt_phase: str, channel: str, observed_at: str,
            ) -> dict[str, Any]:
                nonlocal sequence
                raw = canonical_company_json_bytes({"phase": receipt_phase, "sequence": sequence})
                metadata = supervisor._state.blobs.put(raw)
                assert supervisor._state.blobs.read(metadata.sha256) == raw
                value = _bound(supervisor, provider_io_receipt(
                    phase=receipt_phase, channel=channel,
                ))
                value.update({
                    "receipt_id": receipt_id, "operation_id": operation_id,
                    "launch_binding_id": launch["launch_binding_id"],
                    "launch_binding_sha256": launch["binding_sha256"],
                    "dispatch_request_id": launch["dispatch_request_id"],
                    "dispatch_revision_id": launch["dispatch_revision_id"],
                    "execution_id": execution_id, "thread_id": thread_id, "turn_id": turn_id,
                    "sequence": sequence, "method": method, "request_id": request_id,
                    "raw_artifact": {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": metadata.sha256, "size_bytes": metadata.size_bytes, "media_type": PROVIDER_WORKER_RAW_MEDIA_TYPE, "availability": "available"},
                    "observed_at": observed_at,
                })
                _rehash(value, "receipt_sha256")
                sequence += 1
                return value

            if existing_pending is None:
                pending_at = stamp()
                pending_io = None if phase is None else receipt(
                    f"{operation_id}-00-pending-io",
                    phase,
                    "stdin" if phase in {
                        "request_send_pending",
                        "client_notification_send_pending",
                        "client_notification_written",
                    } else "stdout" if phase in {
                        "response_received", "notification_received",
                    } else "process",
                    pending_at,
                )
                pending = {**operation, "revision": 2,
                    "previous_sha256": operation["operation_sha256"], "previous_state": "prepared",
                    "state": "effect_pending", "effect_receipt_ids": [] if pending_io is None else [pending_io["receipt_id"]],
                    "updated_at": pending_at}
                _rehash(pending, "operation_sha256")
                old_operation = _plain(next(
                    item.payload for item in supervisor.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
                    if item.payload["operation_id"] == operation_id
                ))
                assert (
                    pending["revision"], pending["previous_sha256"], pending["previous_state"],
                    pending["created_at"], pending["updated_at"],
                ) == (
                    old_operation["revision"] + 1, old_operation["operation_sha256"], old_operation["state"],
                    old_operation["created_at"], pending_at,
                )
                _commit(supervisor, f"{operation_id}-pending", f"{operation_id}-pending-command", pending_at, [
                    *([] if pending_io is None else [CompanyEventDraft(f"{operation_id}-pending-io-event", "provider.worker.io.persisted", pending_at, pending_io, provenance="adapter_receipt_persisted")]),
                    CompanyEventDraft(f"{operation_id}-pending-event", "provider.worker.operation.effect_pending", pending_at, pending),
                ])
            else:
                pending = existing_pending
                pending_io = existing_pending_io
            if response_phase is None:
                return pending if pending_io is None else pending_io
            observed_ios = [] if pending_io is None else [pending_io]
            observed_at = stamp()
            for index, observed_phase in enumerate((response_phase, *extra_observation), start=1):
                observed_ios.append(receipt(
                    f"{operation_id}-{index:02d}-observed-io", observed_phase,
                    "stdin" if observed_phase in {
                        "request_send_pending",
                        "client_notification_send_pending",
                        "client_notification_written",
                    } else "stdout" if observed_phase in {
                        "response_received", "notification_received",
                    } else "process",
                    observed_at,
                ))
                observed = {**pending, "revision": 3,
                    "previous_sha256": pending["operation_sha256"], "previous_state": "effect_pending",
                    "state": "effect_observed", "effect_receipt_ids": sorted(item["receipt_id"] for item in observed_ios),
                    "updated_at": observed_at}
            _rehash(observed, "operation_sha256")
            _commit(supervisor, f"{operation_id}-observed", f"{operation_id}-observed-command", observed_at, [
                *[CompanyEventDraft(f"{item['receipt_id']}-event", "provider.worker.io.persisted", observed_at, item, provenance="adapter_receipt_persisted") for item in (observed_ios[1:] if pending_io is not None else observed_ios)],
                CompanyEventDraft(f"{operation_id}-observed-event", "provider.worker.operation.effect_observed", observed_at, observed),
                *([] if observed_events is None else observed_events(observed, observed_ios[-1], observed_at)),
            ])
            if commit_observed:
                committed_at = stamp()
                committed = {**observed, "revision": 4,
                    "previous_sha256": observed["operation_sha256"],
                    "previous_state": "effect_observed", "state": "committed",
                    "updated_at": committed_at}
                _rehash(committed, "operation_sha256")
                _commit(supervisor, f"{operation_id}-committed", f"{operation_id}-committed-command", committed_at, [
                    CompanyEventDraft(f"{operation_id}-committed-event",
                        "provider.worker.operation.committed", committed_at, committed),
                ])
            return observed_ios[-1]

        observe_operation("provider-process", "process_start", phase="process_start_pending", response_phase="process_started", extra_observation=("host_process_observed",), existing_pending=pending_operation, existing_pending_io=pending_io)
        home_active = {**home, "revision": 2, "previous_event_id": "provider-home-event",
            "previous_payload_sha256": company_contract_sha256(home), "state": "active",
            "updated_at": "2026-07-27T00:09:30Z"}
        _rehash(home_active, "home_sha256")
        _commit(supervisor, "provider-home-active", "provider-home-active-command", "2026-07-27T00:09:30Z", [
            CompanyEventDraft("provider-home-active-event", "provider.codex_home.active", "2026-07-27T00:09:30Z", home_active),
        ])
        process_operation = _plain(next(
            item.payload for item in supervisor.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
            if item.payload["operation_id"] == "provider-process"
        ))
        assert (process_operation["state"], process_operation["revision"]) == ("committed", 4)
        assert process_operation["updated_at"] < home_active["updated_at"]
        observe_operation("provider-initialize", "initialize_request", phase="request_send_pending", response_phase="response_received", method="initialize", request_id=1)
        observe_operation("provider-initialized", "initialized_notification", phase="client_notification_send_pending", response_phase="client_notification_written", method="initialized")
        observe_operation("provider-thread", "thread_start_request", phase="request_send_pending", response_phase="response_received", method="thread/start", request_id=2)

        dispatch_receipt = lifecycle._provider_receipt(
            supervisor, event_kind="dispatch_succeeded", transaction_id="provider-dispatch-success",
            command_id="provider-dispatch-success-command", recorded_at="2026-07-27T00:20:00Z",
            provider_dispatch_id="provider-native-dispatch",
        )
        supervisor.dispatch_department_lead(
            "provider-dispatch", dispatch_receipt, transaction_id="provider-dispatch-success",
            command_id="provider-dispatch-success-command", recorded_at="2026-07-27T00:20:00Z",
        )
        agent = next(_plain(item.payload) for item in supervisor.objects(contract_type="execution_node_v1") if item.payload["dispatch_id"] == "provider-dispatch")
        turn_id = "provider-turn"
        minute = 20
        turn_response = observe_operation(
            "provider-turn-start", "turn_start_request", phase="request_send_pending",
            response_phase="response_received", method="turn/start", request_id=3,
            execution_id=turn_id, thread_id=agent["thread_id"], turn_id="provider-turn-1",
        )
        turn = {
            **agent, "execution_id": turn_id, "execution_kind": "turn",
            "display_name": "Provider turn", "parent_execution_id": agent["execution_id"],
            "execution_depth": agent["execution_depth"] + 1,
            "execution_path": [*agent["execution_path"], turn_id], "turn_id": "provider-turn-1",
            "agent_id": None, "dispatch_id": None, "registration_id": launch["launch_binding_id"],
            "receipt_id": turn_response["receipt_id"], "role": agent["role"],
            "created_at": "2026-07-27T00:24:00Z", "updated_at": "2026-07-27T00:24:00Z",
            "last_event_at": "2026-07-27T00:24:00Z", "heartbeat_at": "2026-07-27T00:24:00Z",
            "evidence_ids": ["provider-turn-registration-evidence"],
        }
        evidence = supervisor_tests.registration_evidence(
            supervisor, execution=turn, evidence_id="provider-turn-registration-evidence",
            provenance=agent["provenance"],
        )
        supervisor.register_execution(turn, evidence, transaction_id="provider-turn-register",
            command_id="provider-turn-register-command", recorded_at="2026-07-27T00:24:00Z")
        minute = 24
        terminal_io = observe_operation(
            "provider-turn-observation", "turn_observation", phase=None,
            response_phase="notification_received", method="turn/completed",
            execution_id=turn_id, thread_id=agent["thread_id"], turn_id="provider-turn-1",
        )
        assert terminal_io["phase"] == "notification_received"
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_provider_turn_engineering_idle(
                turn_id,
                "provider-turn-result-receipt",
                transaction_id="provider-turn-idle-pre-exit",
                command_id="provider-turn-idle-pre-exit-command",
                recorded_at=stamp(),
            )
        assert sorted(
            item.payload["sequence"]
            for item in supervisor.objects(contract_type=PROVIDER_WORKER_IO_RECEIPT_V1)
        ) == list(range(1, sequence))
        cleanup_pending = observe_operation(
            "provider-cleanup", "cleanup", phase=None, response_phase=None,
            execution_id=turn_id, thread_id=agent["thread_id"], turn_id="provider-turn-1",
        )
        home_retired: dict[str, Any] | None = None

        def retire_home_with_exit(
            _operation: dict[str, Any], _exit: dict[str, Any], recorded_at: str,
        ) -> list[CompanyEventDraft]:
            nonlocal home_retired
            home_retired = {**home_active, "revision": 3,
                "previous_event_id": "provider-home-active-event",
                "previous_payload_sha256": company_contract_sha256(home_active),
                "state": "retired", "auth_present": False, "auth_size_bytes": 0,
                "updated_at": recorded_at}
            _rehash(home_retired, "home_sha256")
            current_agent = _plain(next(
                item.payload for item in supervisor.objects(contract_type="execution_node_v1")
                if item.payload["execution_id"] == agent["execution_id"]
            ))
            current_turn = _plain(next(
                item.payload for item in supervisor.objects(contract_type="execution_node_v1")
                if item.payload["execution_id"] == turn_id
            ))

            def stopped(node: dict[str, Any]) -> dict[str, Any]:
                return {
                    **node, "runtime_status": "stopped",
                    "updated_at": recorded_at, "last_event_at": recorded_at,
                    "heartbeat_at": None, "current_tool": None,
                }

            return [
                CompanyEventDraft(
                    "provider-home-retired-event", "provider.codex_home.retired",
                    recorded_at, home_retired,
                ),
                CompanyEventDraft(
                    "provider-agent-runtime-stopped", "execution.provider_exit.stopped",
                    recorded_at, stopped(current_agent), provenance=current_agent["provenance"],
                ),
                CompanyEventDraft(
                    "provider-turn-runtime-stopped", "execution.provider_exit.stopped",
                    recorded_at, stopped(current_turn), provenance=current_turn["provenance"],
                ),
            ]

        process_exit_io = observe_operation(
            "provider-cleanup", "cleanup", phase=None,
            response_phase="process_exit_observed", execution_id=turn_id,
            thread_id=agent["thread_id"], turn_id="provider-turn-1",
            existing_pending=cleanup_pending, observed_events=retire_home_with_exit,
        )
        assert process_exit_io["phase"] == "process_exit_observed"
        assert home_retired is not None
        cleanup_observed = _plain(next(
            item.payload for item in supervisor.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
            if item.payload["operation_id"] == "provider-cleanup"
        ))
        assert (cleanup_observed["state"], cleanup_observed["revision"]) == ("committed", 4)
        stopped_agent = next(_plain(item.payload) for item in supervisor.objects(
            contract_type="execution_node_v1",
        ) if item.payload["execution_id"] == agent["execution_id"])
        stopped_turn = next(_plain(item.payload) for item in supervisor.objects(
            contract_type="execution_node_v1",
        ) if item.payload["execution_id"] == turn_id)
        for node in (stopped_agent, stopped_turn):
            assert node["runtime_status"] == "stopped"
            assert node["engineering_status"] == "active"
            assert node["updated_at"] == process_exit_io["observed_at"]
            assert node["last_event_at"] == process_exit_io["observed_at"]
            assert node["heartbeat_at"] is None
            assert node["current_tool"] is None

        terminal_seal = observe_operation(
            "provider-result-extraction", "result_extraction", phase=None,
            response_phase="terminal_sealed", execution_id=turn_id,
            thread_id=agent["thread_id"], turn_id="provider-turn-1",
            commit_observed=False,
        )

        result_operation = _plain(next(
            item.payload for item in supervisor.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
            if item.payload["operation_id"] == "provider-result-extraction"
        ))
        result_document = _bound(supervisor, provider_turn_result())
        result_document.update({
            "launch_binding_id": launch["launch_binding_id"],
            "launch_binding_sha256": launch["binding_sha256"],
            "operation_id": result_operation["operation_id"],
            "agent_execution_id": agent["execution_id"], "turn_execution_id": turn_id,
            "thread_id": agent["thread_id"], "turn_id": "provider-turn-1",
        })
        result_raw = canonical_provider_turn_result_bytes(result_document)
        result_blob = supervisor._state.blobs.put(result_raw)
        assert supervisor._state.blobs.read(result_blob.sha256) == result_raw
        result_receipt = _bound(supervisor, provider_turn_result_receipt())
        result_receipt_at = stamp()
        result_receipt.update({
            "result_receipt_id": "provider-turn-result-receipt",
            "launch_binding_id": launch["launch_binding_id"],
            "launch_binding_sha256": launch["binding_sha256"],
            "operation_id": result_operation["operation_id"],
            "agent_execution_id": agent["execution_id"], "turn_execution_id": turn_id,
            "thread_id": agent["thread_id"], "turn_id": "provider-turn-1",
            "terminal_io_receipt_id": terminal_seal["receipt_id"],
            "result_ref": {"contract_type": BLOB_REF_V1, "schema_version": 1,
                "sha256": result_blob.sha256, "size_bytes": result_blob.size_bytes,
                "media_type": PROVIDER_TURN_RESULT_MEDIA_TYPE,
                "availability": "available"},
            "terminal_status": "completed", "result_sha256": result_blob.sha256,
            "recorded_at": result_receipt_at,
        })
        _rehash(result_receipt, "receipt_sha256")
        result_committed = {**result_operation, "revision": 4,
            "previous_sha256": result_operation["operation_sha256"],
            "previous_state": "effect_observed", "state": "committed",
            "result_receipt_id": result_receipt["result_receipt_id"],
            "updated_at": result_receipt_at}
        _rehash(result_committed, "operation_sha256")
        completed_unavailable_raw = canonical_provider_turn_result_bytes({
            **result_document,
            "terminal_status": "completed",
            "items_view": "not_loaded",
            "availability": "unavailable",
            "reason": "result_unavailable",
            "agent_message_items": [],
        })
        for field, value in (
            ("availability", "unavailable"),
            ("items_view", "not_loaded"),
            ("reason", "result_unavailable"),
        ):
            altered_document = {**result_document, field: value}
            # These are canonical JSON bytes but violate the completed-result
            # contract; append preflight must reject them before durability.
            altered_raw = canonical_company_json_bytes(altered_document)
            altered_blob = supervisor._state.blobs.put(altered_raw)
            altered_receipt = {
                **result_receipt,
                "result_ref": {
                    **result_receipt["result_ref"], "sha256": altered_blob.sha256,
                    "size_bytes": altered_blob.size_bytes,
                },
                "result_sha256": altered_blob.sha256,
            }
            _rehash(altered_receipt, "receipt_sha256")
            with pytest.raises(CompanyStateInvariantError):
                _commit(
                    supervisor, f"provider-turn-result-{field}",
                    f"provider-turn-result-{field}-command", result_receipt_at,
                    [
                        CompanyEventDraft(
                            f"provider-turn-result-{field}-receipt-event",
                            "provider.turn.result.observed", result_receipt_at,
                            altered_receipt, provenance="adapter_receipt_persisted",
                        ),
                        CompanyEventDraft(
                            f"provider-result-extraction-{field}-committed",
                            "provider.worker.operation.committed", result_receipt_at,
                            result_committed,
                        ),
                    ],
                )
        _commit(supervisor, "provider-turn-result", "provider-turn-result-command",
            result_receipt_at, [
                CompanyEventDraft("provider-turn-result-receipt-event",
                    "provider.turn.result.observed", result_receipt_at, result_receipt,
                    provenance="adapter_receipt_persisted"),
                CompanyEventDraft("provider-result-extraction-committed",
                    "provider.worker.operation.committed", result_receipt_at,
                    result_committed),
            ])
        assert len(_objects(supervisor, PROVIDER_TURN_RESULT_RECEIPT_V1)) == 1
        assert _objects(supervisor, WORK_RESULT_RECEIPT_V1) == []
        current_turn = next(
            _plain(item.payload)
            for item in supervisor.objects(contract_type="execution_node_v1")
            if item.payload["execution_id"] == turn_id
        )
        assert (
            current_turn["runtime_status"],
            current_turn["engineering_status"],
        ) == ("stopped", "active")
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_provider_turn_engineering_idle(
                agent["execution_id"],
                result_receipt["result_receipt_id"],
                transaction_id="provider-turn-idle-wrong-turn",
                command_id="provider-turn-idle-wrong-turn-command",
                recorded_at=stamp(),
            )
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_provider_turn_engineering_idle(
                turn_id,
                "wrong-provider-turn-result-receipt",
                transaction_id="provider-turn-idle-wrong-receipt",
                command_id="provider-turn-idle-wrong-receipt-command",
                recorded_at=stamp(),
            )
        wrong_launch_receipt = {
            **result_receipt,
            "launch_binding_id": "wrong-provider-launch",
        }
        _rehash(wrong_launch_receipt, "receipt_sha256")
        original_objects = supervisor.objects
        with monkeypatch.context() as altered_projection:
            altered_projection.setattr(
                supervisor,
                "objects",
                lambda *, contract_type=None: (
                    (SimpleNamespace(payload=wrong_launch_receipt),)
                    if contract_type == PROVIDER_TURN_RESULT_RECEIPT_V1
                    else original_objects(contract_type=contract_type)
                ),
            )
            with pytest.raises(CompanyDepartmentLifecycleError):
                supervisor.record_provider_turn_engineering_idle(
                    turn_id,
                    result_receipt["result_receipt_id"],
                    transaction_id="provider-turn-idle-wrong-launch",
                    command_id="provider-turn-idle-wrong-launch-command",
                    recorded_at=stamp(),
                )
        bad_idle_at = stamp()
        bare_idle = {
            **current_turn,
            "engineering_status": "idle",
            "updated_at": bad_idle_at,
            "last_event_at": bad_idle_at,
            "wait_reason": "park_ready",
            "current_tool": None,
            "provenance": "AOI_verified",
            "observation": {"state": "known", "reason": "observed"},
        }
        with pytest.raises(CompanyStateInvariantError):
            _commit(
                supervisor,
                "provider-turn-idle-bare",
                "provider-turn-idle-bare-command",
                bad_idle_at,
                [CompanyEventDraft(
                    "provider-turn-idle-bare-event",
                    "execution.provider_turn.idle",
                    bad_idle_at,
                    bare_idle,
                    provenance="AOI_verified",
                )],
            )
        original_read = supervisor._state.blobs.read
        for status in ("failed", "interrupted"):
            altered_result = {
                **result_document,
                "terminal_status": status,
                "items_view": "not_loaded",
                "availability": "unavailable",
                "reason": "terminal_not_completed",
                "agent_message_items": [],
            }
            altered_raw = canonical_provider_turn_result_bytes(altered_result)
            with monkeypatch.context() as altered_blob:
                altered_blob.setattr(
                    supervisor._state.blobs,
                    "read",
                    lambda digest, raw=altered_raw: (
                        raw if digest == result_blob.sha256 else original_read(digest)
                    ),
                )
                with pytest.raises(CompanyDepartmentLifecycleError):
                    supervisor.record_provider_turn_engineering_idle(
                        turn_id,
                        result_receipt["result_receipt_id"],
                        transaction_id=f"provider-turn-idle-{status}",
                        command_id=f"provider-turn-idle-{status}-command",
                        recorded_at=stamp(),
                    )
        with monkeypatch.context() as altered_blob:
            altered_blob.setattr(
                supervisor._state.blobs,
                "read",
                lambda digest: (
                    completed_unavailable_raw
                    if digest == result_blob.sha256 else original_read(digest)
                ),
            )
            with pytest.raises(CompanyDepartmentLifecycleError):
                supervisor.record_provider_turn_engineering_idle(
                    turn_id,
                    result_receipt["result_receipt_id"],
                    transaction_id="provider-turn-idle-unavailable",
                    command_id="provider-turn-idle-unavailable-command",
                    recorded_at=stamp(),
                )
        idle_at = stamp()
        idle = supervisor.record_provider_turn_engineering_idle(
            turn_id,
            result_receipt["result_receipt_id"],
            transaction_id="provider-turn-engineering-idle",
            command_id="provider-turn-engineering-idle-command",
            recorded_at=idle_at,
        )
        assert idle.idempotent_replay is False
        idle_turn = next(
            _plain(item.payload)
            for item in supervisor.objects(contract_type="execution_node_v1")
            if item.payload["execution_id"] == turn_id
        )
        assert (
            idle_turn["runtime_status"],
            idle_turn["engineering_status"],
            idle_turn["wait_reason"],
            idle_turn["current_tool"],
            idle_turn["provenance"],
        ) == ("stopped", "idle", "park_ready", None, "AOI_verified")
        assert _objects(supervisor, WORK_RESULT_RECEIPT_V1) == []
        replay = supervisor.record_provider_turn_engineering_idle(
            turn_id,
            result_receipt["result_receipt_id"],
            transaction_id="provider-turn-engineering-idle",
            command_id="provider-turn-engineering-idle-command",
            recorded_at=idle_at,
        )
        assert replay.idempotent_replay is True
        with monkeypatch.context() as altered_blob:
            altered_blob.setattr(
                supervisor._state.blobs,
                "read",
                lambda digest: (
                    completed_unavailable_raw
                    if digest == result_blob.sha256 else original_read(digest)
                ),
            )
            with pytest.raises(CompanyDepartmentLifecycleError):
                supervisor.record_provider_turn_engineering_idle(
                    turn_id,
                    result_receipt["result_receipt_id"],
                    transaction_id="provider-turn-engineering-idle",
                    command_id="provider-turn-engineering-idle-command",
                    recorded_at=idle_at,
                )
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_provider_turn_engineering_idle(
                turn_id,
                result_receipt["result_receipt_id"],
                transaction_id="provider-turn-engineering-idle",
                command_id="provider-turn-engineering-idle-command",
                recorded_at=stamp(),
            )
        with pytest.raises(CompanyDepartmentLifecycleError):
            supervisor.record_provider_turn_engineering_idle(
                turn_id,
                "another-provider-turn-result-receipt",
                transaction_id="provider-turn-engineering-idle",
                command_id="provider-turn-engineering-idle-command",
                recorded_at=idle_at,
            )
        assert _plain(next(
            item.payload
            for item in supervisor.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
            if item.payload["operation_id"] == "provider-result-extraction"
        )) == result_committed
        # B53: a later, unrelated company transaction must retain B50's
        # durable idle disposition while it revalidates the prior result.
        unrelated = supervisor.enqueue_department_dispatch(
            identity["department_id"],
            transaction_id="provider-post-idle-unrelated",
            command_id="provider-post-idle-unrelated-command",
            dispatch_request_id="provider-post-idle-dispatch",
            reservation_id="provider-post-idle-reservation",
            task_id=task["task_id"],
            packet_id=packet["packet_id"],
            route_policy_id="provider-route",
            requested_role="rtl_lead",
            requested_capability_tier="standard",
            requested_at=stamp(),
            recorded_at=stamp(),
        )
        assert unrelated.idempotent_replay is False
        assert _objects(supervisor, WORK_RESULT_RECEIPT_V1) == []
        assert next(
            item.payload["engineering_status"]
            for item in supervisor.objects(contract_type="execution_node_v1")
            if item.payload["execution_id"] == turn_id
        ) == "idle"
        assert cleanup_pending["effect_receipt_ids"] == []
        assert cleanup_observed["state"] == "committed"
        assert cleanup_observed["effect_receipt_ids"] == [
            process_exit_io["receipt_id"],
        ]
        current_home = next(
            _plain(item.payload)
            for item in supervisor.objects(contract_type=PROVIDER_CODEX_HOME_V1)
            if item.payload["home_id"] == home["home_id"]
        )
        assert current_home == home_retired
        operations = _objects(supervisor, PROVIDER_WORKER_OPERATION_V1)
        assert operations and all(
            operation["state"] == "committed" and operation["revision"] == 4
            for operation in operations
        )

        provider_types = (
            PROVIDER_CODEX_HOME_V1,
            PROVIDER_LAUNCH_BINDING_V1,
            PROVIDER_WORKER_OPERATION_V1,
            PROVIDER_WORKER_IO_RECEIPT_V1,
            PROVIDER_TURN_RESULT_RECEIPT_V1,
        )

        def current_membership(owner: Any) -> dict[str, tuple[tuple[Any, ...], ...]]:
            return {
                contract_type: tuple(sorted(
                    (
                        item.object_key,
                        item.event_id,
                        item.global_sequence,
                        _plain(item.payload),
                    )
                    for item in owner.objects(contract_type=contract_type)
                ))
                for contract_type in provider_types
            }

        expected_membership = current_membership(supervisor)
        assert all(expected_membership.values())
        slot = supervisor.slot_root
        cursor = supervisor.heads().global_head.global_sequence
        supervisor.close()
        closed = True
        with CompanySupervisor.open(slot) as reopened:
            assert reopened._state.rebuild_projection().global_sequence == cursor
            assert current_membership(reopened) == expected_membership
            assert _objects(reopened, WORK_RESULT_RECEIPT_V1) == []
            reopened_home = next(
                _plain(item.payload)
                for item in reopened.objects(contract_type=PROVIDER_CODEX_HOME_V1)
                if item.payload["home_id"] == home["home_id"]
            )
            assert reopened_home == home_retired
            reopened_turn = next(
                _plain(item.payload)
                for item in reopened.objects(contract_type="execution_node_v1")
                if item.payload["execution_id"] == turn_id
            )
            assert (
                reopened_turn["runtime_status"],
                reopened_turn["engineering_status"],
            ) == ("stopped", "idle")
    finally:
        if not closed:
            supervisor.close()
