"""Focused B43 projection checks; provider execution remains disabled."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aoi_orgware.company.contracts import (
    COMPANY_MANIFEST_V1,
    DISPATCH_REQUEST_V1,
    EVIDENCE_RECORD_V1,
    EXECUTION_NODE_V1,
    PROVIDER_CODEX_HOME_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    WORK_DISPATCH_BINDING_V1,
    company_contract_sha256,
    validate_company_contract,
)
from aoi_orgware.company.invariants import (
    CompanyInvariantError,
    InvariantObject,
    InvariantTransition,
    _validate_execution_revisions,
    _validate_provider_worker_projection,
    reduce_company_invariants,
)
from aoi_orgware.company.ledger import CompanyLedger
from aoi_orgware.company.readmodel import (
    CompanyReadModel,
    ReadModelCorruptionError,
    _PROJECTION_SPECS,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_company_contracts import (  # type: ignore[import-not-found]
    dispatch_request,
    execution_node,
    provider_codex_home,
    provider_io_receipt,
    provider_launch_binding,
    provider_operation,
    provider_turn_result_receipt,
    route_policy,
    task_revision,
    work_dispatch_binding,
    work_packet,
)
from test_company_readmodel import append_payload, request  # type: ignore[import-not-found]


def _item(payload: dict[str, object], event_id: str, sequence: int = 1) -> InvariantObject:
    key_field = {
        PROVIDER_CODEX_HOME_V1: "home_id",
        PROVIDER_LAUNCH_BINDING_V1: "launch_binding_id",
        PROVIDER_WORKER_OPERATION_V1: "operation_id",
        PROVIDER_WORKER_IO_RECEIPT_V1: "receipt_id",
        PROVIDER_TURN_RESULT_RECEIPT_V1: "result_receipt_id",
        EVIDENCE_RECORD_V1: "evidence_id",
        EXECUTION_NODE_V1: "execution_id",
    }.get(str(payload["contract_type"]))
    key = payload[key_field] if key_field is not None else next((
        payload[field] for field in (
            "dispatch_request_id", "packet_id", "task_revision_id", "policy_id",
        ) if field in payload), event_id)
    return InvariantObject(
        str(payload["contract_type"]),
        str(key),
        event_id,
        sequence,
        company_contract_sha256(payload),
        payload,
    )


def _committed_provider_transition(
    payload: dict[str, object], *, event_id: str,
) -> InvariantTransition:
    """Build one schema-valid public-reducer input around a provider object."""
    value = request(
        payload, tx=f"tx-{event_id}", command=f"cmd-{event_id}",
        event_id=event_id, stream="execution",
    )
    event = value["events"][0]
    event.update({
        "event_type": (
            f"provider.codex_home.{payload['state']}"
            if payload["contract_type"] == PROVIDER_CODEX_HOME_V1
            else f"provider.worker.operation.{payload['state']}"
        ),
        "recorded_at": payload["updated_at"],
        "payload_sha256": company_contract_sha256(payload),
    })
    value["request_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "request_sha256"},
    )
    return InvariantTransition(value, "committed")


def _rehash(value: dict[str, object], field: str) -> None:
    value[field] = company_contract_sha256(
        {key: member for key, member in value.items() if key != field},
    )


def _provider_prefix(
    phases: list[tuple[str, str | None, int | None]],
) -> tuple[dict[tuple[str, str], InvariantObject], list[InvariantObject]]:
    """Schema-valid, reducer-level provider prefix with exact durable joins."""
    manifest = {
        "contract_type": COMPANY_MANIFEST_V1, "schema_version": 1,
        "company_id": "company-1", "company_incarnation": 1,
        "lock_domain_generation": 1, "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64, "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64, "lock_domain_id": "windows-msvcrt-v1",
        "created_at": "2026-07-26T00:00:00Z",
        "observation": {"state": "known", "reason": "observed"},
    }
    task = task_revision()
    packet = work_packet(task=task)
    dispatch = dispatch_request(state="admitted")
    dispatch.update({
        "task_id": task["task_id"], "packet_id": packet["packet_id"],
    })
    binding = work_dispatch_binding()
    binding.update({
        "dispatch_revision_id": dispatch["dispatch_revision_id"],
        "dispatch_payload_sha256": company_contract_sha256(dispatch),
        "task_id": task["task_id"], "task_revision_id": task["task_revision_id"],
        "task_sha256": task["task_sha256"], "packet_id": packet["packet_id"],
        "packet_sha256": packet["packet_sha256"], "prompt_ref": packet["prompt_ref"],
        "context_manifest_ref": packet["context_manifest_ref"],
        "authority_scope_sha256": company_contract_sha256(packet["authority_scope"]),
        "provider_allowlist": packet["authority_scope"]["provider_allowlist"],
    })
    _rehash(binding, "binding_sha256")
    policy = route_policy()
    home = provider_codex_home()
    launch = provider_launch_binding()
    launch.update({
        "work_dispatch_binding_id": binding["binding_id"],
        "work_dispatch_binding_sha256": binding["binding_sha256"],
        "dispatch_revision_id": dispatch["dispatch_revision_id"],
        "dispatch_revision": dispatch["revision"],
        "dispatch_payload_sha256": company_contract_sha256(dispatch),
        "route_policy_sha256": policy["policy_sha256"], "home_sha256": home["home_sha256"],
        "manifest_sha256": company_contract_sha256(manifest),
        "source_sha256": packet["source_manifest_sha256"],
        "config_sha256": packet["config_manifest_sha256"],
        "dependency_sha256": packet["dependency_manifest_sha256"],
        "git_common_dir_sha256": manifest["git_common_dir_sha256"],
        "git_remote_sha256": manifest["remote_fingerprint_sha256"],
    })
    _rehash(launch, "binding_sha256")

    old: list[InvariantObject] = [
        _item(value, f"old-{index}", index + 1)
        for index, value in enumerate((
            manifest, task, packet, dispatch, binding, policy, home, launch,
        ))
    ]
    batch: list[InvariantObject] = []
    grouped: dict[str, list[str]] = {}
    operation_kind = {
        "process_start_pending": "process_start", "process_started": "process_start",
        "host_process_observed": "process_start", "client_notification_send_pending": "initialized_notification",
        "client_notification_written": "initialized_notification", "notification_received": "turn_observation",
        "process_exit_observed": "cleanup", "terminal_sealed": "terminal_seal",
    }

    def _operation_kind(phase: str, method: str | None) -> str:
        if phase in {"request_send_pending", "response_received"}:
            return {
                "initialize": "initialize_request",
                "model/list": "model_list_request",
                "thread/start": "thread_start_request",
                "turn/start": "turn_start_request",
                "turn/interrupt": "turn_interrupt_request",
            }[str(method)]
        return operation_kind[phase]

    for index, (phase, _method, _request_id) in enumerate(phases, start=1):
        kind = _operation_kind(phase, _method)
        operation_id = f"operation-{kind}"
        grouped.setdefault(operation_id, []).append(f"io-{index}")
    for operation_id, receipt_ids in grouped.items():
        kind = operation_id.removeprefix("operation-")
        previous = provider_operation(state="effect_pending", revision=2)
        previous.update({
            "operation_id": operation_id, "previous_sha256": "a" * 64,
            "operation_kind": kind, "execution_id": "turn-exec-1",
            "launch_binding_sha256": launch["binding_sha256"],
            "dispatch_revision_id": launch["dispatch_revision_id"],
            "effect_receipt_ids": [], "previous_state": "prepared",
        })
        _rehash(previous, "operation_sha256")
        old.append(_item(previous, f"{operation_id}-pending", 20))
        observed = copy.deepcopy(previous)
        observed.update({
            "revision": 3, "previous_sha256": previous["operation_sha256"],
            "previous_state": "effect_pending", "state": "effect_observed",
            "effect_receipt_ids": sorted(receipt_ids), "updated_at": "2026-07-26T00:02:00Z",
        })
        _rehash(observed, "operation_sha256")
        batch.append(_item(observed, f"{operation_id}-observed", 21))
    for index, (phase, method, request_id) in enumerate(phases, start=1):
        channel = (
            "stdin" if phase in {"request_send_pending", "client_notification_send_pending", "client_notification_written"}
            else "stdout" if phase in {"response_received", "notification_received"}
            else "process"
        )
        kind = _operation_kind(phase, method)
        receipt = provider_io_receipt(phase=phase, channel=channel)
        receipt.update({
            "receipt_id": f"io-{index}", "operation_id": f"operation-{kind}",
            "launch_binding_sha256": launch["binding_sha256"],
            "dispatch_revision_id": launch["dispatch_revision_id"], "sequence": index,
            "method": method, "request_id": request_id,
            "observed_at": f"2026-07-26T00:00:{index:02d}Z",
        })
        _rehash(receipt, "receipt_sha256")
        batch.append(_item(receipt, f"io-event-{index}", 21))
    for item in (*old, *batch):
        validate_company_contract(item.payload)
    return {(item.contract_type, item.object_key): item for item in old}, batch


def test_provider_projection_specs_keep_logical_ids_and_streams() -> None:
    expected = {
        PROVIDER_CODEX_HOME_V1: ("execution", "home_id", "home_id"),
        PROVIDER_LAUNCH_BINDING_V1: ("execution", "launch_binding_id", "launch_binding_id"),
        PROVIDER_WORKER_IO_RECEIPT_V1: ("evidence", "receipt_id", "receipt_id"),
        PROVIDER_WORKER_OPERATION_V1: ("execution", "operation_id", "operation_id"),
        PROVIDER_TURN_RESULT_RECEIPT_V1: ("evidence", "result_receipt_id", "result_receipt_id"),
    }
    assert {
        contract: (spec.stream, spec.object_key_field, spec.record_id_field)
        for contract, spec in _PROJECTION_SPECS.items()
        if contract in expected
    } == expected


@pytest.mark.parametrize("phases", [
    [("process_start_pending", None, None)],
    [("process_start_pending", None, None), ("process_started", None, None)],
    [
        ("process_start_pending", None, None), ("process_started", None, None),
        ("request_send_pending", "initialize", 1),
        ("response_received", "initialize", 1),
        ("client_notification_send_pending", "initialized", None),
        ("client_notification_written", "initialized", None),
    ],
])
def test_provider_worker_accepts_lawful_incomplete_prefixes(
    phases: list[tuple[str, str | None, int | None]],
) -> None:
    old, batch = _provider_prefix(phases)
    _validate_provider_worker_projection(old, batch, None, "committed")


def test_provider_worker_accepts_ready_home_without_launch() -> None:
    old, batch = _provider_prefix([])
    del old[(PROVIDER_LAUNCH_BINDING_V1, "launch-1")]
    _validate_provider_worker_projection(old, batch, None, "committed")


def test_provider_worker_accepts_terminal_ready_home_without_launch() -> None:
    old, batch = _provider_prefix([])
    del old[(PROVIDER_LAUNCH_BINDING_V1, "launch-1")]
    ready = old[(PROVIDER_CODEX_HOME_V1, "codex-home-1")]
    retired = copy.deepcopy(ready.payload)
    retired.update({
        "revision": 2,
        "previous_event_id": ready.event_id,
        "previous_payload_sha256": ready.payload_sha256,
        "state": "retired",
        "auth_present": False,
        "auth_size_bytes": 0,
        "updated_at": "2026-07-26T00:00:02Z",
    })
    _rehash(retired, "home_sha256")
    _validate_provider_worker_projection(
        old, [*batch, _item(retired, "home-retired-without-launch", 21)], None,
        "committed",
    )


def _validate_rejection(
    old: dict[tuple[str, str], InvariantObject], batch: list[InvariantObject], pattern: str,
) -> None:
    for item in batch:
        validate_company_contract(item.payload)
    with pytest.raises(CompanyInvariantError, match=pattern):
        _validate_provider_worker_projection(old, batch, None, "committed")


def _completed_result_projection(
) -> tuple[dict[tuple[str, str], InvariantObject], list[InvariantObject]]:
    """Targeted projection-only result boundary; not a transaction-history fixture."""
    old, observed = _provider_prefix([
        ("process_start_pending", None, None), ("process_started", None, None),
        ("request_send_pending", "initialize", 1), ("response_received", "initialize", 1),
        ("client_notification_send_pending", "initialized", None),
        ("client_notification_written", "initialized", None),
        ("request_send_pending", "thread/start", 2), ("response_received", "thread/start", 2),
        ("request_send_pending", "turn/start", 3), ("response_received", "turn/start", 3),
        ("notification_received", "turn/completed", None),
        ("process_exit_observed", None, None), ("terminal_sealed", None, None),
    ])
    old.update({(item.contract_type, item.object_key): item for item in observed})
    launch = old[(PROVIDER_LAUNCH_BINDING_V1, "launch-1")].payload
    binding = old[(WORK_DISPATCH_BINDING_V1, "dispatch-request-1")].payload
    terminal_key = (PROVIDER_WORKER_OPERATION_V1, "operation-terminal_seal")
    terminal = copy.deepcopy(old.pop(terminal_key).payload)
    terminal_receipt_key = (PROVIDER_WORKER_IO_RECEIPT_V1, "io-13")
    terminal_receipt = copy.deepcopy(old.pop(terminal_receipt_key).payload)
    terminal.update({
        "operation_id": "operation-result-extraction", "operation_kind": "result_extraction",
        "state": "effect_observed", "result_receipt_id": None,
    })
    _rehash(terminal, "operation_sha256")
    terminal_item = _item(terminal, "result-observed", 30)
    old[(terminal_item.contract_type, terminal_item.object_key)] = terminal_item
    terminal_receipt.update({"operation_id": terminal["operation_id"]})
    _rehash(terminal_receipt, "receipt_sha256")
    terminal_receipt_item = _item(terminal_receipt, "terminal-seal", 30)
    old[(terminal_receipt_item.contract_type, terminal_receipt_item.object_key)] = terminal_receipt_item

    agent = execution_node()
    agent.update({
        "execution_id": "agent-exec-1", "execution_kind": "agent", "display_name": "Provider agent",
        "parent_execution_id": "carrier-exec-1", "execution_depth": 1,
        "execution_path": ["carrier-exec-1", "agent-exec-1"], "task_id": binding["task_id"],
        "packet_id": binding["packet_id"], "dispatch_id": launch["dispatch_request_id"],
        "registration_id": None, "agent_id": "agent-1", "provider": launch["provider"], "model": launch["model"],
        "effort": launch["effort"], "carrier_id": "carrier-1", "role": "worker",
        "runtime_status": "stopped", "engineering_status": "completed",
        "terminal_at": "2026-07-26T00:00:01Z",
    })
    turn = copy.deepcopy(agent)
    turn.update({
        "execution_id": "turn-exec-1", "execution_kind": "turn", "display_name": "Provider turn",
        "parent_execution_id": "agent-exec-1", "execution_depth": 2,
        "execution_path": ["carrier-exec-1", "agent-exec-1", "turn-exec-1"],
        "agent_id": None, "dispatch_id": None, "registration_id": launch["launch_binding_id"], "role": "worker",
        "engineering_status": "completed", "runtime_status": "stopped",
    })
    for index, node in enumerate((agent, turn), start=31):
        validate_company_contract(node)
        item = _item(node, f"execution-{index}", index)
        old[(item.contract_type, item.object_key)] = item

    committed = copy.deepcopy(terminal)
    committed.update({
        "revision": 4, "previous_sha256": terminal["operation_sha256"],
        "previous_state": "effect_observed", "state": "committed",
        "result_receipt_id": "result-receipt-1", "updated_at": "2026-07-26T00:03:00Z",
    })
    _rehash(committed, "operation_sha256")
    result = provider_turn_result_receipt()
    result.update({
        "launch_binding_id": launch["launch_binding_id"], "launch_binding_sha256": launch["binding_sha256"],
        "operation_id": committed["operation_id"], "terminal_io_receipt_id": terminal_receipt["receipt_id"],
        "recorded_at": "2026-07-26T00:04:00Z",
    })
    _rehash(result, "receipt_sha256")
    for value in (committed, result):
        validate_company_contract(value)
    return old, [_item(committed, "result-committed", 40), _item(result, "result-receipt", 40)]


def test_provider_worker_rejects_schema_valid_subject_mismatch() -> None:
    old, batch = _provider_prefix([
        ("process_start_pending", None, None),
    ])
    receipt = copy.deepcopy(next(item for item in batch if item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1).payload)
    receipt["execution_id"] = "other-turn-exec"
    _rehash(receipt, "receipt_sha256")
    altered = [
        _item(receipt, "io-event-subject", 21)
        if item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1 else item
        for item in batch
    ]
    _validate_rejection(old, altered, "execution subject differs")


def test_provider_worker_rejects_initialized_before_initialize_response() -> None:
    old, batch = _provider_prefix([
        ("process_start_pending", None, None), ("process_started", None, None),
        ("client_notification_send_pending", "initialized", None),
    ])
    _validate_rejection(old, batch, "initialized notification")


def test_provider_worker_rejects_request_id_reuse_across_methods() -> None:
    old, batch = _provider_prefix([
        ("process_start_pending", None, None), ("process_started", None, None),
        ("request_send_pending", "initialize", 1), ("response_received", "initialize", 1),
        ("client_notification_send_pending", "initialized", None),
        ("client_notification_written", "initialized", None),
        ("request_send_pending", "model/list", 1),
    ])
    _validate_rejection(old, batch, "resend an existing request")


@pytest.mark.parametrize("phases, pattern", [
    ([("process_start_pending", None, None), ("process_started", None, None),
      ("request_send_pending", "model/list", 1)], "initialize must be the first request"),
    ([("process_start_pending", None, None), ("process_started", None, None),
      ("request_send_pending", "initialize", 1), ("response_received", "initialize", 1),
      ("request_send_pending", "thread/start", 2)], "thread start precedes initialized write"),
    ([("host_process_observed", None, None)], "observation precedes start"),
])
def test_provider_worker_rejects_impossible_fsm_orders(
    phases: list[tuple[str, str | None, int | None]], pattern: str,
) -> None:
    old, batch = _provider_prefix(phases)
    _validate_rejection(old, batch, pattern)


def test_provider_worker_rejects_active_home_without_observed_process_start() -> None:
    old, batch = _provider_prefix([])
    del old[(PROVIDER_LAUNCH_BINDING_V1, "launch-1")]
    ready = old[(PROVIDER_CODEX_HOME_V1, "codex-home-1")]
    active = copy.deepcopy(ready.payload)
    active.update({
        "revision": 2, "previous_event_id": ready.event_id,
        "previous_payload_sha256": ready.payload_sha256, "state": "active",
        "updated_at": "2026-07-26T00:02:00Z",
    })
    _rehash(active, "home_sha256")
    _validate_rejection(old, [_item(active, "home-active", 21)], "active lacks launch process evidence")


def _active_home(
    old: dict[tuple[str, str], InvariantObject],
) -> dict[str, object]:
    ready = old[(PROVIDER_CODEX_HOME_V1, "codex-home-1")]
    active = dict(ready.payload)
    active.update({
        "revision": 2, "previous_event_id": ready.event_id,
        "previous_payload_sha256": ready.payload_sha256, "state": "active",
        "updated_at": "2026-07-26T00:00:01Z",
    })
    _rehash(active, "home_sha256")
    old[(PROVIDER_CODEX_HOME_V1, "codex-home-1")] = _item(active, "home-active", 20)
    return active


def _home_cleanup(
    active: dict[str, object], *, state: str = "retired",
) -> dict[str, object]:
    cleanup = dict(active)
    cleanup.update({
        "revision": 3, "previous_event_id": "home-active",
        "previous_payload_sha256": company_contract_sha256(active), "state": state,
        "updated_at": "2026-07-26T00:00:03Z",
    })
    if state == "retired":
        cleanup.update({"auth_present": False, "auth_size_bytes": 0})
    _rehash(cleanup, "home_sha256")
    return cleanup


def _exit_stop_fixture() -> tuple[
    dict[tuple[str, str], InvariantObject], list[InvariantObject],
    dict[str, object], dict[str, object],
]:
    """One terminal-less exit with the exact pre-existing agent/turn pair."""
    old, batch = _provider_prefix([
        ("process_start_pending", None, None),
        ("process_started", None, None),
        ("process_exit_observed", None, None),
    ])
    active = _active_home(old)
    cleanup = _home_cleanup(active, state="cleanup_failed")
    source, _unused = _completed_result_projection()
    agent = copy.deepcopy(source[(EXECUTION_NODE_V1, "agent-exec-1")].payload)
    turn = copy.deepcopy(source[(EXECUTION_NODE_V1, "turn-exec-1")].payload)
    for node in (agent, turn):
        node.update({
            "engineering_status": "active", "runtime_status": "running",
            "terminal_at": None, "updated_at": "2026-07-26T00:00:02Z",
            "last_event_at": "2026-07-26T00:00:02Z",
            "heartbeat_at": "2026-07-26T00:00:02Z", "current_tool": "provider",
        })
        validate_company_contract(node)
        item = _item(node, f"old-{node['execution_id']}", 20)
        old[(item.contract_type, item.object_key)] = item
    return old, [*batch, _item(cleanup, "home-cleanup", 22)], agent, turn


def _stopped_for_exit(node: dict[str, object], *, event_id: str) -> InvariantObject:
    stopped = dict(node)
    stopped.update({
        "runtime_status": "stopped", "updated_at": "2026-07-26T00:00:03Z",
        "last_event_at": "2026-07-26T00:00:03Z", "heartbeat_at": None,
        "current_tool": None,
    })
    validate_company_contract(stopped)
    return _item(stopped, event_id, 23)


def _provider_exit_envelope(batch: list[InvariantObject]) -> dict[str, object]:
    events: list[dict[str, object]] = []
    for item in batch:
        payload = item.payload
        if item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1:
            stream, event_type, provenance, recorded_at = (
                "evidence", "provider.worker.io.persisted", payload["provenance"],
                payload["observed_at"],
            )
        elif item.contract_type == PROVIDER_WORKER_OPERATION_V1:
            stream, event_type, provenance, recorded_at = (
                "execution", f"provider.worker.operation.{payload['state']}",
                "AOI_verified", payload["updated_at"],
            )
        elif item.contract_type == PROVIDER_CODEX_HOME_V1:
            stream, event_type, provenance, recorded_at = (
                "execution", f"provider.codex_home.{payload['state']}",
                "AOI_verified", payload["updated_at"],
            )
        elif item.contract_type == EXECUTION_NODE_V1:
            stream, event_type, provenance, recorded_at = (
                "execution", "execution.provider_exit.stopped", payload["provenance"],
                payload["updated_at"],
            )
        else:
            continue
        events.append({
            "event_id": item.event_id, "stream": stream, "event_type": event_type,
            "provenance": provenance, "recorded_at": recorded_at,
            "payload_sha256": item.payload_sha256, "payload": payload,
        })
    return {"events": events}


def test_provider_exit_rejects_missing_partial_fake_and_unrelated_runtime_stops() -> None:
    old, base, agent, turn = _exit_stop_fixture()
    missing = _provider_exit_envelope(base)
    with pytest.raises(CompanyInvariantError, match="exact active runtime stops"):
        _validate_provider_worker_projection(old, base, missing, "committed")

    agent_stop = _stopped_for_exit(agent, event_id="agent-exit-stop")
    partial = [*base, agent_stop]
    with pytest.raises(CompanyInvariantError, match="exact active runtime stops"):
        _validate_provider_worker_projection(
            old, partial, _provider_exit_envelope(partial), "committed",
        )

    turn_stop = _stopped_for_exit(turn, event_id="turn-exit-stop")
    fake_turn = dict(turn_stop.payload)
    fake_turn["updated_at"] = "2026-07-26T00:00:04Z"
    fake_turn["last_event_at"] = "2026-07-26T00:00:04Z"
    fake_item = _item(fake_turn, "turn-exit-stop-fake", 23)
    fake = [*base, agent_stop, fake_item]
    with pytest.raises(CompanyInvariantError, match="exact active runtime stops"):
        _validate_provider_worker_projection(
            old, fake, _provider_exit_envelope(fake), "committed",
        )

    unrelated = copy.deepcopy(agent)
    unrelated.update({
        "execution_id": "agent-unrelated", "dispatch_id": "dispatch-other",
        "execution_path": ["carrier-exec-1", "agent-unrelated"],
    })
    unrelated_item = _item(unrelated, "old-agent-unrelated", 20)
    old_unrelated = dict(old)
    old_unrelated[(unrelated_item.contract_type, unrelated_item.object_key)] = unrelated_item
    unrelated_stop = _stopped_for_exit(unrelated, event_id="unrelated-exit-stop")
    valid = [*base, agent_stop, turn_stop, unrelated_stop]
    with pytest.raises(CompanyInvariantError, match="unrelated runtime stop"):
        _validate_provider_worker_projection(
            old_unrelated, valid, _provider_exit_envelope(valid), "committed",
        )


def test_provider_worker_requires_atomic_home_cleanup_for_terminal_less_exit() -> None:
    phases: list[tuple[str, str | None, int | None]] = [
        ("process_start_pending", None, None),
        ("process_started", None, None),
        ("process_exit_observed", None, None),
    ]
    old, batch = _provider_prefix(phases)
    active = _active_home(old)
    _validate_rejection(
        old, batch, "process exit lacks one atomic Codex home cleanup",
    )

    cleanup_failed = _home_cleanup(active, state="cleanup_failed")
    _validate_provider_worker_projection(
        old, [*batch, _item(cleanup_failed, "home-cleanup-failed", 22)], None, "committed",
    )


def test_provider_worker_rejects_home_cleanup_without_atomic_exit() -> None:
    old, batch = _provider_prefix([
        ("process_start_pending", None, None),
        ("process_started", None, None),
    ])
    active = _active_home(old)
    retired = _home_cleanup(active)
    _validate_rejection(
        old, [*batch, _item(retired, "home-retired", 22)],
        "home cleanup lacks one atomic process exit",
    )


def test_provider_worker_rejects_shared_home_or_dispatch_launch_bindings() -> None:
    old, batch = _provider_prefix([])
    duplicate = copy.deepcopy(old[(PROVIDER_LAUNCH_BINDING_V1, "launch-1")].payload)
    duplicate["launch_binding_id"] = "launch-2"
    _rehash(duplicate, "binding_sha256")
    _validate_rejection(
        old, [*batch, _item(duplicate, "launch-2-event", 22)],
        "share a Codex home",
    )

    duplicate["home_id"] = "codex-home-2"
    _rehash(duplicate, "binding_sha256")
    _validate_rejection(
        old, [*batch, _item(duplicate, "launch-2-dispatch-event", 22)],
        "share a dispatch request",
    )


def test_provider_worker_rejects_two_homes_for_one_dispatch() -> None:
    old, batch = _provider_prefix([])
    duplicate = copy.deepcopy(old[(PROVIDER_CODEX_HOME_V1, "codex-home-1")].payload)
    duplicate["home_id"] = "codex-home-2"
    _rehash(duplicate, "home_sha256")
    _validate_rejection(
        old, [*batch, _item(duplicate, "home-2-event", 22)],
        "homes share a dispatch request",
    )


@pytest.mark.parametrize("field, value", [
    ("active", "2026-07-26T00:00:04Z"),
    ("cleanup", "2026-07-26T00:00:04Z"),
])
def test_provider_worker_requires_exit_home_time_causality(
    field: str, value: str,
) -> None:
    old, batch = _provider_prefix([
        ("process_start_pending", None, None),
        ("process_started", None, None),
        ("process_exit_observed", None, None),
    ])
    active = _active_home(old)
    cleanup = _home_cleanup(active, state="cleanup_failed")
    if field == "active":
        active["updated_at"] = value
        _rehash(active, "home_sha256")
        old[(PROVIDER_CODEX_HOME_V1, "codex-home-1")] = _item(
            active, "home-active-late", 20,
        )
        cleanup["previous_event_id"] = "home-active-late"
        cleanup["previous_payload_sha256"] = company_contract_sha256(active)
        cleanup["updated_at"] = "2026-07-26T00:00:05Z"
    else:
        cleanup["updated_at"] = value
    _rehash(cleanup, "home_sha256")
    _validate_rejection(
        old, [*batch, _item(cleanup, "home-cleanup-late", 22)],
        "Codex home causality differs",
    )


def test_provider_worker_rejects_terminal_seal_after_terminal_less_exit() -> None:
    old, batch = _provider_prefix([
        ("process_start_pending", None, None),
        ("process_started", None, None),
        ("process_exit_observed", None, None),
        ("terminal_sealed", None, None),
    ])
    active = _active_home(old)
    cleanup_failed = _home_cleanup(active, state="cleanup_failed")
    _validate_rejection(
        old, [*batch, _item(cleanup_failed, "home-cleanup-failed", 22)],
        "terminal seal lacks terminal process evidence",
    )


def test_provider_terminal_seal_cannot_stop_registered_runtime() -> None:
    old, batch = _completed_result_projection()
    del batch
    previous = dict(old[(EXECUTION_NODE_V1, "turn-exec-1")].payload)
    previous.update({
        "engineering_status": "active", "runtime_status": "running",
        "heartbeat_at": "2026-07-26T00:02:00Z", "current_tool": "provider turn",
    })
    old[(EXECUTION_NODE_V1, "turn-exec-1")] = _item(
        previous, "turn-active", 40,
    )
    stopped = {
        **previous, "runtime_status": "stopped",
        "updated_at": "2026-07-26T00:00:13Z",
        "last_event_at": "2026-07-26T00:00:13Z",
        "heartbeat_at": None, "current_tool": None,
    }
    stopped_item = _item(stopped, "turn-terminal-stop", 41)
    envelope = {"events": [{
        "event_id": stopped_item.event_id, "stream": "execution",
        "event_type": "execution.provider_terminal.stopped",
        "provenance": stopped["provenance"], "recorded_at": stopped["updated_at"],
        "payload_sha256": stopped_item.payload_sha256, "payload": stopped,
    }]}
    with pytest.raises(CompanyInvariantError, match="registered ExecutionNode revision"):
        _validate_execution_revisions(old, [stopped_item], envelope)


def test_provider_worker_rejects_effect_pending_without_atomic_pending_io() -> None:
    old, batch = _provider_prefix([("process_start_pending", None, None)])
    key = (PROVIDER_WORKER_OPERATION_V1, "operation-process_start")
    prepared = copy.deepcopy(old[key].payload)
    prepared.update({
        "revision": 1, "previous_sha256": "0" * 64, "previous_state": None,
        "state": "prepared", "effect_receipt_ids": [],
    })
    _rehash(prepared, "operation_sha256")
    old[key] = _item(prepared, "process-prepared", 20)
    pending = copy.deepcopy(prepared)
    pending.update({
        "revision": 2, "previous_sha256": prepared["operation_sha256"],
        "previous_state": "prepared", "state": "effect_pending",
        "updated_at": "2026-07-26T00:02:00Z",
    })
    _rehash(pending, "operation_sha256")
    _validate_rejection(old, [_item(pending, "process-pending", 21)], "lacks one atomic pending IO")


def test_provider_worker_rejects_prepared_operation_with_receipt() -> None:
    old, batch = _provider_prefix([("process_start_pending", None, None)])
    key = (PROVIDER_WORKER_OPERATION_V1, "operation-process_start")
    prepared = copy.deepcopy(old[key].payload)
    prepared.update({
        "revision": 1, "previous_sha256": "0" * 64, "previous_state": None,
        "state": "prepared", "effect_receipt_ids": [],
    })
    _rehash(prepared, "operation_sha256")
    old[key] = _item(prepared, "process-prepared", 20)
    receipt = next(item for item in batch if item.contract_type == PROVIDER_WORKER_IO_RECEIPT_V1)
    _validate_rejection(old, [receipt], "prepared provider worker operation has durable IO")


@pytest.mark.parametrize("field, replacement", [
    ("turn_execution_id", "other-turn-exec"),
    ("thread_id", "other-thread"),
    ("turn_id", "other-turn"),
])
def test_provider_turn_result_rejects_wrong_execution_thread_or_turn(
    field: str, replacement: str,
) -> None:
    old, batch = _completed_result_projection()
    result = copy.deepcopy(next(
        item for item in batch if item.contract_type == PROVIDER_TURN_RESULT_RECEIPT_V1
    ).payload)
    result[field] = replacement
    _rehash(result, "receipt_sha256")
    altered = [
        _item(result, "result-receipt-altered", 40)
        if item.contract_type == PROVIDER_TURN_RESULT_RECEIPT_V1 else item
        for item in batch
    ]
    _validate_rejection(old, altered, "provider turn result receipt binding differs")


def test_provider_turn_result_projection_does_not_reject_prior_status_but_rejects_same_batch_inference() -> None:
    """Projection-only: durable disposition/history belongs to the transaction slice."""
    old, batch = _completed_result_projection()
    _validate_provider_worker_projection(old, batch, None, "committed")
    turn = old[(EXECUTION_NODE_V1, "turn-exec-1")]
    assert turn.payload["runtime_status"] == "stopped"
    assert turn.payload["engineering_status"] == "completed"

    same_batch_turn = copy.deepcopy(turn.payload)
    same_batch_turn["updated_at"] = "2026-07-26T00:04:00Z"
    same_batch_turn["last_event_at"] = "2026-07-26T00:04:00Z"
    _validate_rejection(
        old,
        [*batch, _item(same_batch_turn, "turn-disposition-same-batch", 40)],
        "provider turn result cannot imply engineering completion",
    )


def _idle_result_projection(
) -> dict[tuple[str, str], InvariantObject]:
    old, result_batch = _completed_result_projection()
    old.update({(item.contract_type, item.object_key): item for item in result_batch})
    result = old[(PROVIDER_TURN_RESULT_RECEIPT_V1, "result-receipt-1")].payload
    turn = copy.deepcopy(old[(EXECUTION_NODE_V1, "turn-exec-1")].payload)
    evidence_id = f"provider-turn-idle-evidence-{result['receipt_sha256']}"
    turn.update({
        "engineering_status": "idle",
        "wait_reason": "park_ready",
        "current_tool": None,
        "updated_at": "2026-07-26T00:05:00Z",
        "last_event_at": "2026-07-26T00:05:00Z",
        "terminal_at": None,
        "evidence_ids": [evidence_id],
        "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    })
    evidence = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": result["company_id"],
        "company_incarnation": result["company_incarnation"],
        "lock_domain_generation": result["lock_domain_generation"],
        "evidence_id": evidence_id,
        "execution_id": turn["execution_id"],
        "claim_id": result["result_receipt_id"],
        "evidence_class": "engineering_inference",
        "status": "observed",
        "artifact": result["result_ref"],
        "command_sha256": None,
        "verification_sha256": result["receipt_sha256"],
        "recorded_at": turn["updated_at"],
        "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    }
    validate_company_contract(turn)
    validate_company_contract(evidence)
    turn_item = _item(turn, "turn-idle", 50)
    evidence_item = _item(evidence, "turn-idle-evidence", 50)
    old[(turn_item.contract_type, turn_item.object_key)] = turn_item
    old[(evidence_item.contract_type, evidence_item.object_key)] = evidence_item
    return old


def test_provider_turn_idle_disposition_survives_reduction_and_rejects_bad_evidence() -> None:
    durable = _idle_result_projection()
    _validate_provider_worker_projection(durable, [], None, "committed")

    missing = dict(durable)
    missing.pop((EVIDENCE_RECORD_V1, next(
        key for contract_type, key in durable if contract_type == EVIDENCE_RECORD_V1
    )))
    _validate_rejection(missing, [], "idle turn lacks durable disposition evidence")

    tampered = dict(durable)
    evidence_key = next(key for contract_type, key in durable if contract_type == EVIDENCE_RECORD_V1)
    evidence = copy.deepcopy(tampered[(EVIDENCE_RECORD_V1, evidence_key)].payload)
    evidence["claim_id"] = "other-result-receipt"
    tampered[(EVIDENCE_RECORD_V1, evidence_key)] = _item(evidence, "turn-idle-evidence-tampered", 51)
    _validate_rejection(tampered, [], "provider turn idle evidence differs")

    ambiguous = dict(durable)
    agent = copy.deepcopy(ambiguous[(EXECUTION_NODE_V1, "agent-exec-1")].payload)
    agent["evidence_ids"] = [evidence_key]
    ambiguous[(EXECUTION_NODE_V1, "agent-exec-1")] = _item(
        agent, "agent-shares-turn-idle-evidence", 51,
    )
    _validate_rejection(ambiguous, [], "provider turn idle evidence differs")


def test_provider_projection_rejects_noncommitted_receipt() -> None:
    payload = provider_codex_home()
    value = request(payload, tx="provider-tx-1", command="provider-cmd-1", event_id="home-event-1", stream="execution")
    event = value["events"][0]
    event.update({
        "event_type": "provider.codex_home.ready",
        "recorded_at": payload["updated_at"],
        "payload_sha256": company_contract_sha256(payload),
    })
    value["request_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "request_sha256"},
    )
    with pytest.raises(CompanyInvariantError, match="require a committed receipt"):
        reduce_company_invariants([], [], InvariantTransition(value, "effect_unknown"))


def test_public_reducer_rejects_schema_valid_provider_genesis_revision_two() -> None:
    home = provider_codex_home(revision=2)
    assert validate_company_contract(home)["revision"] == 2
    with pytest.raises(CompanyInvariantError, match="genesis revision must be one"):
        reduce_company_invariants([], [], _committed_provider_transition(home, event_id="home-v2"))

    operation = provider_operation(state="effect_observed", revision=2)
    assert validate_company_contract(operation)["revision"] == 2
    with pytest.raises(CompanyInvariantError, match="genesis revision must be one"):
        reduce_company_invariants([], [], _committed_provider_transition(operation, event_id="operation-v2"))


def test_home_revision_requires_exact_prior_event_and_payload_digest() -> None:
    old_payload = provider_codex_home()
    old = _item(old_payload, "home-event-1")
    revised = copy.deepcopy(old_payload)
    revised.update({
        "revision": 2,
        "previous_event_id": "different-event",
        "previous_payload_sha256": old.payload_sha256,
        "state": "active",
        "updated_at": "2026-07-26T00:01:00Z",
    })
    revised["home_sha256"] = company_contract_sha256(
        {key: value for key, value in revised.items() if key != "home_sha256"},
    )
    with pytest.raises(CompanyInvariantError, match="home revision predecessor"):
        _validate_provider_worker_projection(
            {(PROVIDER_CODEX_HOME_V1, "codex-home-1"): old},
            [_item(revised, "home-event-2", 2)],
            None,
            "committed",
        )


def test_readmodel_replay_rejects_provider_home_without_projected_dispatch(tmp_path: Path) -> None:
    manifest = {
        "contract_type": COMPANY_MANIFEST_V1,
        "schema_version": 1,
        "company_id": "company-1",
        "company_incarnation": 1,
        "lock_domain_generation": 1,
        "git_common_dir_sha256": "a" * 64,
        "remote_fingerprint_sha256": "b" * 64,
        "configuration_sha256": "c" * 64,
        "state_root_sha256": "d" * 64,
        "lock_domain_id": "windows-msvcrt-v1",
        "created_at": "2026-07-26T00:00:00Z",
        "observation": {"state": "known", "reason": "observed"},
    }
    ledger = CompanyLedger(tmp_path / "provider-ledger.sqlite3")
    first = append_payload(
        ledger, manifest, tx="tx-manifest", command="cmd-manifest",
        event_id="manifest-event", stream="org",
    )
    home = provider_codex_home()
    home["lock_domain_generation"] = 1
    home["home_sha256"] = company_contract_sha256(
        {key: member for key, member in home.items() if key != "home_sha256"},
    )
    value = request(
        home, tx="tx-home", command="cmd-home", event_id="home-event",
        stream="execution", global_sequence=1,
        global_hash=first.receipt["transaction_sha256"],
    )
    event = value["events"][0]
    event.update({
        "event_type": "provider.codex_home.ready",
        "recorded_at": home["updated_at"],
        "payload_sha256": company_contract_sha256(home),
    })
    value["request_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "request_sha256"},
    )
    second = ledger.append(value).record
    model = CompanyReadModel(tmp_path / "provider-readmodel.sqlite3")
    try:
        assert model.apply(first)
        with pytest.raises(ReadModelCorruptionError, match="violates company invariants"):
            model.apply(second)
    finally:
        model.close()
        ledger.close()
