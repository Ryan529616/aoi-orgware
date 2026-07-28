from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import cast

import pytest

from aoi_orgware.company.contracts import (
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    DISPATCH_REQUEST_V1,
    EVIDENCE_RECORD_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_LIFECYCLE_SOURCE_V1,
    TASK_REVISION_V1,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.invariants import (
    CompanyInvariantError,
    InvariantObject,
    InvariantTransition,
    UncertainDispatch,
    reduce_company_invariants,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_company_contracts import (  # type: ignore[import-not-found]
    dispatch_request,
    family_records,
    request,
    task_revision,
    work_definition_enforcement,
    work_dispatch_binding,
    work_packet,
)


def obj(payload: dict[str, object], event_id: str, sequence: int = 1) -> InvariantObject:
    return InvariantObject(str(payload["contract_type"]), event_id, event_id, sequence,
                           company_contract_sha256(payload), payload)


def nodes(*, target: str = "target-1", department: str | None = None) -> list[InvariantObject]:
    chief = cast(dict[str, object], copy.deepcopy(family_records()[1]))
    target_payload = copy.deepcopy(chief)
    target_payload.update({"node_id": target, "department_id": department,
                           "parent_node_id": "chief-1", "reports_to_node_id": "chief-1",
                           "role": "worker", "can_delegate": False, "delegation_depth": 1,
                           "status": "active", "visibility": "company"})
    return [obj(chief, "chief-event"), obj(target_payload, f"{target}-event")]


def dispatch(*, state: str = "queued", request_id: str = "dispatch-request-1",
             reservation: str = "reservation-1", target: str = "target-1",
             command_id: str = "command-1", revision_id: str | None = None) -> dict[str, object]:
    value = cast(dict[str, object], dispatch_request(state=state))
    value.update({
        "dispatch_request_id": request_id,
        "dispatch_revision_id": revision_id or f"revision-{request_id}",
        "command_id": command_id,
        "reservation_id": reservation,
        "manager_node_id": "chief-1",
        "target_node_id": target,
    })
    return value


def transition(
    payload: dict[str, object],
    receipt_state: str = "committed",
    *,
    event_id: str | None = None,
    recorded_at: str | None = None,
) -> InvariantTransition:
    value = cast(dict[str, object], request())
    command_id = str(payload["command_id"])
    value["command_id"] = command_id
    expected_transaction_head = cast(
        dict[str, object],
        value["expected_transaction_head"],
    )
    expected_transaction_head["command_id"] = command_id
    expected_transaction_head.update({
        "global_sequence": 1,
        "transaction_sha256": "f" * 64,
    })
    expected_head = cast(
        dict[str, object],
        cast(list[object], value["expected_heads"])[0],
    )
    expected_head.update({"command_id": command_id, "stream": "execution"})
    value["expected_heads"] = [expected_head]
    event = cast(dict[str, object], cast(list[object], value["events"])[0])
    if event_id is not None:
        event["event_id"] = event_id
    if recorded_at is not None:
        event["recorded_at"] = recorded_at
    event["command_id"] = command_id
    event["stream"] = "execution"
    event["payload"] = payload
    event["payload_sha256"] = company_contract_sha256(payload, max_bytes=64 * 1024)
    value["events"] = [event]
    value["request_sha256"] = company_contract_sha256(
        {key: member for key, member in value.items() if key != "request_sha256"}
    )
    return InvariantTransition(value, receipt_state)


def rehash(value: dict[str, object], field: str) -> None:
    value[field] = company_contract_sha256(
        {key: member for key, member in value.items() if key != field},
    )


def work_task_packet() -> tuple[dict[str, object], dict[str, object]]:
    task = task_revision()
    packet = work_packet(task=task)
    packet.update({
        "manager_node_id": "chief-1",
        "parent_execution_id": "exec-parent-1",
        "target_node_id": "target-1",
        "department_id": "rtl",
        "null_relationship_justifications": {
            "manager_node_id": None,
            "parent_execution_id": None,
            "target_node_id": None,
            "department_id": None,
        },
    })
    rehash(packet, "packet_sha256")
    return task, packet


def work_transition(*payloads: dict[str, object]) -> InvariantTransition:
    value = cast(dict[str, object], copy.deepcopy(transition(dispatch()).request))
    template = cast(dict[str, object], copy.deepcopy(cast(list[object], value["events"])[0]))
    events: list[dict[str, object]] = []
    for index, payload in enumerate(payloads, start=1):
        event = copy.deepcopy(template)
        event["event_id"] = f"work-definition-event-{index}"
        event["payload"] = copy.deepcopy(payload)
        event["payload_sha256"] = company_contract_sha256(event["payload"], max_bytes=64 * 1024)
        events.append(event)
    value["events"] = events
    rehash(value, "request_sha256")
    return InvariantTransition(value, "committed")


def registered_work_definition() -> tuple[
    dict[str, object], dict[str, object], dict[str, object], dict[str, object],
]:
    task, packet = work_task_packet()
    authority_scope = cast(
        dict[str, object],
        packet["authority_scope"],
    )
    queued = dispatch()
    queued.update({
        "task_id": task["task_id"],
        "packet_id": packet["packet_id"],
        "department_id": packet["department_id"],
        "scope_sha256": company_contract_sha256(authority_scope),
    })
    binding = work_dispatch_binding()
    binding.update({
        "transaction_id": "tx-1",
        "command_id": queued["command_id"],
        "dispatch_request_id": queued["dispatch_request_id"],
        "dispatch_revision_id": queued["dispatch_revision_id"],
        "dispatch_payload_sha256": company_contract_sha256(queued),
        "task_id": task["task_id"],
        "task_revision_id": task["task_revision_id"],
        "task_sha256": task["task_sha256"],
        "packet_id": packet["packet_id"],
        "packet_sha256": packet["packet_sha256"],
        "prompt_ref": packet["prompt_ref"],
        "context_manifest_ref": packet["context_manifest_ref"],
        "department_id": packet["department_id"],
        "target_node_id": packet["target_node_id"],
        "manager_node_id": packet["manager_node_id"],
        "parent_execution_id": packet["parent_execution_id"],
        "delegation_depth": packet["delegation_depth"],
        "authority_scope_sha256": company_contract_sha256(authority_scope),
        "provider_allowlist": authority_scope["provider_allowlist"],
        "expires_at": packet["expires_at"],
    })
    rehash(binding, "binding_sha256")
    return task, packet, queued, binding


def in_flight_request(
    *,
    request_id: str = "dispatch-request-1",
    reservation: str = "reservation-1",
    target: str = "target-1",
) -> InvariantObject:
    value = dispatch(
        state="in_flight",
        request_id=request_id,
        reservation=reservation,
        target=target,
        command_id=f"command-{request_id}-3",
        revision_id=f"revision-{request_id}-3",
    )
    value.update({
        "revision": 3,
        "previous_event_id": f"event-{request_id}-2",
        "previous_payload_sha256": "b" * 64,
    })
    return obj(value, f"event-{request_id}-3")


def effect_unknown_successor(
    current: InvariantObject,
    *,
    source_event_id: str = "uncertain-event",
) -> UncertainDispatch:
    old = current.payload
    value = dispatch(
        state="effect_unknown",
        request_id=str(old["dispatch_request_id"]),
        reservation=str(old["reservation_id"]),
        target=str(old["target_node_id"]),
        command_id=f"command-{old['dispatch_request_id']}-4",
        revision_id=f"revision-{old['dispatch_request_id']}-4",
    )
    value.update({
        "revision": int(old["revision"]) + 1,
        "previous_event_id": current.event_id,
        "previous_payload_sha256": current.payload_sha256,
    })
    return UncertainDispatch(
        str(value["reservation_id"]),
        str(value["dispatch_request_id"]),
        source_event_id,
        current.global_sequence + 1,
        f"tx-{source_event_id}",
        str(value["command_id"]),
        "effect_unknown",
        "effect_unknown",
        company_contract_sha256(value),
        value,
    )


def agent_execution(
    *,
    execution_id: str = "agent-execution-1",
    target: str = "target-1",
    carrier_id: str | None = None,
    dispatch_id: str | None = None,
    registration_id: str | None = "registration-1",
    runtime_status: str = "running",
    engineering_status: str = "active",
    provenance: str = "AOI_verified",
) -> dict[str, object]:
    value = cast(dict[str, object], copy.deepcopy(family_records()[6]))
    value.update({
        "execution_id": execution_id,
        "execution_kind": "agent",
        "display_name": execution_id,
        "organization_node_id": target,
        "parent_execution_id": "exec-parent-1",
        "execution_depth": 1,
        "execution_path": ["exec-parent-1", execution_id],
        "agent_id": f"agent-{execution_id}",
        "job_id": None,
        "dispatch_id": dispatch_id,
        "registration_id": registration_id,
        "carrier_id": carrier_id,
        "delegation_depth": 1,
        "engineering_status": engineering_status,
        "runtime_status": runtime_status,
        "provenance": provenance,
        "terminal_at": (
            "2026-07-26T00:00:01Z"
            if engineering_status in {"completed", "cancelled"}
            else None
        ),
    })
    return value


def dispatched_runtime_records(
    dispatched: dict[str, object],
    execution: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Return the carrier, receipt, and evidence required by a generic dispatch."""
    carrier = cast(dict[str, object], copy.deepcopy(family_records()[5]))
    carrier.update({
        "carrier_id": "generic-carrier-1",
        "actor_id": "generic-logical-actor-1",
        "last_observed_at": "2026-07-26T00:00:01Z",
    })
    source = {
        "source_type": PROVIDER_LIFECYCLE_SOURCE_V1,
        "schema_version": 1,
        "company_id": dispatched["company_id"],
        "company_incarnation": dispatched["company_incarnation"],
        "lock_domain_generation": dispatched["lock_domain_generation"],
        "source_event_id": "generic-dispatch-source-1",
        "event_kind": "dispatch_succeeded",
        "dispatch_request_id": dispatched["dispatch_request_id"],
        "provider_dispatch_id": dispatched["provider_dispatch_id"],
        "execution_id": execution["execution_id"],
        "carrier_id": carrier["carrier_id"],
        "organization_node_id": execution["organization_node_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "reconcile_ref": None,
        "observed_at": "2026-07-26T00:00:01Z",
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
    }
    source_bytes = canonical_company_json_bytes(source)
    raw_artifact = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": company_contract_sha256(source),
        "size_bytes": len(source_bytes),
        "media_type": PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
        "availability": "available",
    }
    receipt = {
        "contract_type": PROVIDER_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        "company_id": dispatched["company_id"],
        "company_incarnation": dispatched["company_incarnation"],
        "lock_domain_generation": dispatched["lock_domain_generation"],
        "receipt_id": "generic-dispatch-receipt-1",
        "source_event_id": source["source_event_id"],
        "event_kind": source["event_kind"],
        "transaction_id": "generic-dispatch-transaction-1",
        "command_id": dispatched["command_id"],
        "dispatch_request_id": dispatched["dispatch_request_id"],
        "dispatch_revision_id": dispatched["dispatch_revision_id"],
        "dispatch_revision": dispatched["revision"],
        "provider_dispatch_id": dispatched["provider_dispatch_id"],
        "execution_id": execution["execution_id"],
        "carrier_id": carrier["carrier_id"],
        "organization_node_id": execution["organization_node_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "session_id": carrier["session_id"],
        "thread_id": execution["thread_id"],
        "reconcile_ref": None,
        "observed_at": source["observed_at"],
        "provenance": source["provenance"],
        "observation": source["observation"],
        "raw_artifact": raw_artifact,
        "receipt_sha256": "0" * 64,
    }
    receipt["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    })
    evidence = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": dispatched["company_id"],
        "company_incarnation": dispatched["company_incarnation"],
        "lock_domain_generation": dispatched["lock_domain_generation"],
        "evidence_id": "generic-dispatch-evidence-1",
        "execution_id": execution["execution_id"],
        "claim_id": receipt["receipt_id"],
        "evidence_class": "runtime",
        "status": "observed",
        "artifact": raw_artifact,
        "command_sha256": None,
        "verification_sha256": receipt["receipt_sha256"],
        "recorded_at": receipt["observed_at"],
        "provenance": receipt["provenance"],
        "observation": receipt["observation"],
    }
    execution.update({
        "carrier_id": carrier["carrier_id"],
        "receipt_id": receipt["receipt_id"],
        "evidence_ids": [evidence["evidence_id"]],
        "provenance": receipt["provenance"],
        "observation": receipt["observation"],
    })
    dispatched.update({
        "effect_evidence": [raw_artifact],
        "provenance": receipt["provenance"],
        "observation": receipt["observation"],
    })
    return carrier, receipt, evidence


def test_queued_and_capacity_boundaries_are_normalized() -> None:
    queued = obj(dispatch(), "dispatch-event")
    projection = reduce_company_invariants([*nodes(), queued], [])
    assert projection.company_capacity == 0
    assert projection.queue_items == (queued,)

    carriers: list[InvariantObject] = []
    for index in range(16):
        payload = copy.deepcopy(family_records()[5])
        payload.update({
            "carrier_id": f"carrier-{index}",
            "actor_id": f"actor-{index}",
            "session_id": f"session-{index}",
        })
        carriers.append(obj(payload, f"carrier-event-{index}"))
    assert reduce_company_invariants(carriers, []).company_capacity == 16
    payload = copy.deepcopy(family_records()[5])
    payload.update({
        "carrier_id": "carrier-16",
        "actor_id": "actor-16",
        "session_id": "session-16",
    })
    with pytest.raises(CompanyInvariantError, match="capacity"):
        reduce_company_invariants([*carriers, obj(payload, "carrier-event-16")], [])


def test_dispatch_revision_and_target_relations_are_strict() -> None:
    queued = dispatch()
    current = obj(queued, "event-1")
    admitted = dispatch(
        state="admitted",
        command_id="command-2",
        revision_id="revision-dispatch-request-1-2",
    )
    admitted.update({"revision": 2, "previous_event_id": "event-1",
                     "previous_payload_sha256": current.payload_sha256})
    projection = reduce_company_invariants([*nodes(), current], [], transition(admitted))
    assert projection.company_capacity == 1

    same = copy.deepcopy(admitted); same["state"] = "queued"
    with pytest.raises(CompanyInvariantError, match="transition"):
        reduce_company_invariants([*nodes(), current], [], transition(same))
    drift = copy.deepcopy(admitted); drift["target_node_id"] = "other-target"
    with pytest.raises(CompanyInvariantError, match="immutable"):
        reduce_company_invariants([*nodes(target="other-target"), current], [], transition(drift))
    missing = copy.deepcopy(admitted); missing["target_node_id"] = "missing-target"
    with pytest.raises(CompanyInvariantError, match="immutable"):
        reduce_company_invariants([*nodes(), current], [], transition(missing))
    reused_command = copy.deepcopy(admitted); reused_command["command_id"] = "command-1"
    with pytest.raises(CompanyInvariantError, match="command identity was reused"):
        reduce_company_invariants([*nodes(), current], [], transition(reused_command))
    reused_revision = copy.deepcopy(admitted)
    reused_revision["dispatch_revision_id"] = queued["dispatch_revision_id"]
    with pytest.raises(CompanyInvariantError, match="revision identity was reused"):
        reduce_company_invariants([*nodes(), current], [], transition(reused_revision))


def test_fanout_and_uncertainty_are_conservative() -> None:
    current: list[InvariantObject] = []
    for index in range(4):
        target = f"target-{index}"
        current.extend(nodes(target=target)) if index == 0 else current.append(nodes(target=target)[1])
        current.append(obj(dispatch(state="admitted", request_id=f"request-{index}", reservation=f"reserve-{index}", target=target), f"event-{index}"))
    projection = reduce_company_invariants(current, [])
    assert projection.manager_capacity == (("chief-1", 4),)
    fifth = [*current, nodes(target="target-4")[1], obj(dispatch(state="admitted", request_id="request-4", reservation="reserve-4", target="target-4"), "event-4")]
    with pytest.raises(CompanyInvariantError, match="fanout"):
        reduce_company_invariants(fifth, [])

    current_request = in_flight_request()
    shadow = effect_unknown_successor(current_request)
    uncertain = reduce_company_invariants(
        [*nodes(), current_request],
        [shadow],
    )
    assert uncertain.company_capacity == 1
    assert isinstance(uncertain.queue_items[0], UncertainDispatch)
    assert uncertain.queue_items[0].source_event_id == "uncertain-event"
    assert uncertain.queue_items == (shadow,)


def test_input_order_does_not_change_the_projection() -> None:
    first = obj(dispatch(state="admitted"), "dispatch-event", 4)
    records = [*nodes(), first]
    assert reduce_company_invariants(records, []) == reduce_company_invariants(list(reversed(records)), [])


def test_reusing_current_dispatch_event_id_with_divergent_bytes_is_corruption() -> None:
    current_payload = dispatch(state="queued")
    current = obj(current_payload, "same-event")
    divergent = dispatch(
        state="admitted",
        command_id="command-divergent",
        revision_id="revision-divergent",
    )
    divergent.update({
        "revision": 999,
        "previous_event_id": "wrong-predecessor",
        "previous_payload_sha256": "f" * 64,
    })
    with pytest.raises(CompanyInvariantError, match="event identity.*divergent"):
        reduce_company_invariants(
            [*nodes(), current],
            [],
            transition(divergent, event_id="same-event"),
        )


def test_explicit_resolution_and_divergent_shadows() -> None:
    unknown = dispatch(state="effect_unknown")
    current = obj(unknown, "unknown-event")
    final = dispatch(
        state="failed_known",
        command_id="command-2",
        revision_id="revision-dispatch-request-1-2",
    )
    final.update({"revision": 2, "previous_event_id": "unknown-event",
                  "previous_payload_sha256": current.payload_sha256,
                  "resolves_event_ids": ["unknown-event"]})
    assert reduce_company_invariants([*nodes(), current], [], transition(final)).company_capacity == 0
    final["resolves_event_ids"] = []
    with pytest.raises(CompanyInvariantError, match="resolve"):
        reduce_company_invariants([*nodes(), current], [], transition(final))

    first = effect_unknown_successor(in_flight_request())
    second_payload = cast(dict[str, object], copy.deepcopy(first.payload))
    second_payload["dispatch_request_id"] = "request-2"
    shadows = [
        first,
        UncertainDispatch(
            "reservation-1",
            "request-2",
            first.source_event_id,
            first.source_global_sequence,
            first.source_transaction_id,
            first.source_command_id,
            "effect_unknown",
            "effect_unknown",
            company_contract_sha256(second_payload),
            second_payload,
        ),
    ]
    with pytest.raises(CompanyInvariantError, match="source event.*divergent"):
        reduce_company_invariants([*nodes(), in_flight_request()], shadows)


def test_shadow_resolution_is_exact_and_releases_one_slot() -> None:
    current = in_flight_request()
    shadow = effect_unknown_successor(current, source_event_id="shadow-event")
    final = dispatch(
        state="failed_known",
        command_id="command-resolution",
        revision_id="revision-resolution",
    )
    final.update({
        "revision": 4,
        "previous_event_id": current.event_id,
        "previous_payload_sha256": current.payload_sha256,
        "resolves_event_ids": [shadow.source_event_id],
    })
    projection = reduce_company_invariants(
        [*nodes(), current],
        [shadow],
        transition(final),
    )
    assert projection.company_capacity == 0
    assert projection.unresolved_shadows == ()

    wrong = copy.deepcopy(final)
    wrong["resolves_event_ids"] = ["some-other-event"]
    with pytest.raises(CompanyInvariantError, match="resolve exactly"):
        reduce_company_invariants(
            [*nodes(), current],
            [shadow],
            transition(wrong),
        )


def test_effect_unknown_receipt_materializes_only_a_shadow() -> None:
    current = in_flight_request()
    requested = effect_unknown_successor(current)
    requested_payload = cast(
        dict[str, object],
        copy.deepcopy(requested.payload),
    )
    projection = reduce_company_invariants(
        [*nodes(), current],
        [],
        transition(requested_payload, receipt_state="effect_unknown"),
    )
    assert projection.dispatch_requests == (current,)
    assert len(projection.unresolved_shadows) == 1
    assert projection.unresolved_shadows[0].source_event_id == "event-org"
    assert projection.company_capacity == 1

    invalid = dispatch(
        state="admitted",
        command_id="command-invalid",
        revision_id="revision-invalid",
    )
    invalid.update({
        "revision": 4,
        "previous_event_id": current.event_id,
        "previous_payload_sha256": current.payload_sha256,
    })
    with pytest.raises(
        CompanyInvariantError,
        match="requested state is invalid",
    ):
        reduce_company_invariants(
            [*nodes(), current],
            [],
            transition(invalid, receipt_state="effect_unknown"),
        )


def test_capacity_uses_physical_slots_and_runtime_truth() -> None:
    carrier = cast(dict[str, object], copy.deepcopy(family_records()[5]))
    carrier.update({"carrier_id": "worker-carrier", "actor_id": "target-1"})
    execution = agent_execution(
        carrier_id="worker-carrier",
        registration_id="registration-1",
    )
    projection = reduce_company_invariants(
        [*nodes(), obj(carrier, "carrier-event"), obj(execution, "execution-event")],
        [],
    )
    assert projection.company_capacity == 1
    assert projection.manager_capacity == (("chief-1", 1),)

    completed_running = agent_execution(
        execution_id="completed-running",
        registration_id="registration-completed",
        engineering_status="completed",
    )
    assert reduce_company_invariants(
        [*nodes(), obj(completed_running, "completed-running-event")],
        [],
    ).company_capacity == 1

    unknown_carrier = copy.deepcopy(carrier)
    unknown_carrier.update({
        "carrier_id": "unknown-carrier",
        "state": "unknown",
        "session_id": None,
        "session_availability": "unknown",
        "observation": {"state": "unknown", "reason": "collector_lag"},
    })
    unknown_projection = reduce_company_invariants(
        [*nodes(), obj(unknown_carrier, "unknown-carrier-event")],
        [],
    )
    assert unknown_projection.company_capacity == 1
    assert not unknown_projection.manager_capacity_complete
    assert unknown_projection.unattributed_active == (
        "carrier:unknown-carrier",
    )

    linked_carrier = copy.deepcopy(carrier)
    linked_carrier["actor_id"] = "logical-actor-not-an-organization-node"
    linked_execution = agent_execution(
        execution_id="linked-carrier-execution",
        carrier_id=str(linked_carrier["carrier_id"]),
        registration_id="linked-carrier-registration",
    )
    linked_projection = reduce_company_invariants(
        [
            *nodes(),
            obj(linked_carrier, "linked-carrier-event"),
            obj(linked_execution, "linked-carrier-execution-event"),
        ],
        [],
    )
    assert linked_projection.company_capacity == 1
    assert linked_projection.manager_capacity_complete
    assert linked_projection.unattributed_active == ()


def test_registered_runtime_without_carrier_blocks_new_admission() -> None:
    unattributed_runtime = agent_execution(
        execution_id="registered-unattributed-runtime",
        registration_id="registered-unattributed-registration",
    )
    projection = reduce_company_invariants(
        [*nodes(), obj(unattributed_runtime, "registered-unattributed-event")],
        [],
    )
    assert projection.company_capacity == 1
    assert not projection.manager_capacity_complete
    assert projection.unattributed_active == (
        "execution:registered-unattributed-runtime",
    )

    current = obj(dispatch(), "registered-unattributed-queued-event")
    admitted = dispatch(
        state="admitted",
        command_id="registered-unattributed-admit-command",
        revision_id="registered-unattributed-admit-revision",
    )
    admitted.update({
        "revision": 2,
        "previous_event_id": current.event_id,
        "previous_payload_sha256": current.payload_sha256,
    })
    admission_runtime = copy.deepcopy(unattributed_runtime)
    admission_runtime.update({
        "parent_execution_id": "exec-1",
        "execution_path": ["exec-1", "registered-unattributed-runtime"],
    })
    with pytest.raises(
        CompanyInvariantError,
        match="fanout is unattributed; admission is unsafe",
    ):
        reduce_company_invariants(
            [
                *nodes(),
                obj(cast(dict[str, object], copy.deepcopy(family_records()[5])), "admission-parent-carrier"),
                obj(cast(dict[str, object], copy.deepcopy(family_records()[6])), "admission-parent-execution"),
                obj(admission_runtime, "registered-unattributed-event"),
                current,
            ],
            [],
            transition(admitted),
        )


def test_carrier_execution_link_conflicts_degrade_and_count_conservatively() -> None:
    carrier = cast(dict[str, object], copy.deepcopy(family_records()[5]))
    carrier.update({
        "carrier_id": "carrier-link",
        "actor_id": "logical-actor",
    })

    mismatched = agent_execution(
        execution_id="mismatched-execution",
        carrier_id="carrier-link",
        registration_id="mismatched-registration",
    )
    mismatched["model"] = "different-model"
    mismatch_projection = reduce_company_invariants(
        [
            *nodes(),
            obj(carrier, "carrier-link-event"),
            obj(mismatched, "mismatched-execution-event"),
        ],
        [],
    )
    assert mismatch_projection.company_capacity == 2
    assert not mismatch_projection.manager_capacity_complete
    assert mismatch_projection.unattributed_active == (
        "execution:mismatched-execution",
    )

    parked = copy.deepcopy(carrier)
    parked["state"] = "parked"
    parked_execution = agent_execution(
        execution_id="parked-carrier-execution",
        carrier_id="carrier-link",
        registration_id="parked-carrier-registration",
    )
    parked_projection = reduce_company_invariants(
        [
            *nodes(),
            obj(parked, "parked-carrier-event"),
            obj(parked_execution, "parked-carrier-execution-event"),
        ],
        [],
    )
    assert parked_projection.company_capacity == 1
    assert not parked_projection.manager_capacity_complete
    assert parked_projection.unattributed_active == (
        "execution:parked-carrier-execution",
    )

    missing_binding = agent_execution(
        execution_id="missing-carrier-execution",
        carrier_id="missing-carrier",
        registration_id="missing-carrier-registration",
    )
    missing_projection = reduce_company_invariants(
        [*nodes(), obj(missing_binding, "missing-carrier-execution-event")],
        [],
    )
    assert missing_projection.company_capacity == 1
    assert not missing_projection.manager_capacity_complete
    assert missing_projection.unattributed_active == (
        "execution:missing-carrier-execution",
    )

    first = agent_execution(
        execution_id="shared-carrier-first",
        carrier_id="carrier-link",
        registration_id="shared-carrier-first-registration",
    )
    second = agent_execution(
        execution_id="shared-carrier-second",
        target="target-2",
        carrier_id="carrier-link",
        registration_id="shared-carrier-second-registration",
    )
    shared_projection = reduce_company_invariants(
        [
            *nodes(),
            nodes(target="target-2")[1],
            obj(carrier, "shared-carrier-event"),
            obj(first, "shared-carrier-first-event"),
            obj(second, "shared-carrier-second-event"),
        ],
        [],
    )
    assert shared_projection.company_capacity == 1
    assert shared_projection.manager_capacity == (("chief-1", 2),)
    assert not shared_projection.manager_capacity_complete
    assert shared_projection.unattributed_active == ("carrier:carrier-link",)


def test_provider_session_identity_is_one_physical_carrier_slot() -> None:
    first_carrier = cast(
        dict[str, object],
        copy.deepcopy(family_records()[5]),
    )
    first_carrier.update({
        "carrier_id": "session-carrier-a",
        "actor_id": "logical-actor-a",
    })
    second_carrier = copy.deepcopy(first_carrier)
    second_carrier.update({
        "carrier_id": "session-carrier-b",
        "actor_id": "logical-actor-b",
    })
    first_execution = agent_execution(
        execution_id="session-execution-a",
        carrier_id="session-carrier-a",
        registration_id="session-registration-a",
    )
    second_execution = agent_execution(
        execution_id="session-execution-b",
        carrier_id="session-carrier-b",
        registration_id="session-registration-b",
    )
    projection = reduce_company_invariants(
        [
            *nodes(),
            obj(first_carrier, "session-carrier-a-event"),
            obj(second_carrier, "session-carrier-b-event"),
            obj(first_execution, "session-execution-a-event"),
            obj(second_execution, "session-execution-b-event"),
        ],
        [],
    )
    assert projection.company_capacity == 1
    assert not projection.manager_capacity_complete
    assert projection.unattributed_active == (
        "carrier:session-carrier-a",
        "carrier:session-carrier-b",
    )

    fenced_first = copy.deepcopy(first_carrier)
    fenced_first["state"] = "fenced"
    fenced_projection = reduce_company_invariants(
        [
            *nodes(),
            obj(fenced_first, "session-carrier-a-fenced-event"),
            obj(second_carrier, "session-carrier-b-event"),
            obj(first_execution, "session-execution-a-event"),
            obj(second_execution, "session-execution-b-event"),
        ],
        [],
    )
    assert fenced_projection.company_capacity == 1
    assert not fenced_projection.manager_capacity_complete
    assert fenced_projection.unattributed_active == (
        "carrier:session-carrier-a",
        "carrier:session-carrier-b",
    )


def test_identity_collisions_and_unattributed_fanout_fail_closed() -> None:
    first = obj(
        dispatch(
            state="admitted",
            request_id="request-a",
            reservation="shared-reservation",
        ),
        "request-a-event",
    )
    second = obj(
        dispatch(
            state="admitted",
            request_id="request-b",
            reservation="shared-reservation",
            command_id="command-b",
            revision_id="revision-b",
        ),
        "request-b-event",
    )
    with pytest.raises(CompanyInvariantError, match="reservation.*divergent"):
        reduce_company_invariants([*nodes(), first, second], [])

    registration_a = agent_execution(
        execution_id="registration-execution-a",
        registration_id="shared-registration",
    )
    registration_b = agent_execution(
        execution_id="registration-execution-b",
        registration_id="shared-registration",
    )
    with pytest.raises(CompanyInvariantError, match="registration.*multiple"):
        reduce_company_invariants(
            [
                *nodes(),
                obj(registration_a, "registration-event-a"),
                obj(registration_b, "registration-event-b"),
            ],
            [],
        )

    fanout_objects: list[InvariantObject] = []
    for index in range(5):
        target = f"registered-target-{index}"
        if index == 0:
            fanout_objects.extend(nodes(target=target))
        else:
            fanout_objects.append(nodes(target=target)[1])
        execution = agent_execution(
            execution_id=f"registered-execution-{index}",
            target=target,
            registration_id=f"registration-{index}",
        )
        fanout_objects.append(
            obj(execution, f"registered-execution-event-{index}"),
        )
    with pytest.raises(CompanyInvariantError, match="fanout"):
        reduce_company_invariants(fanout_objects, [])

    orphan = agent_execution(
        execution_id="orphan-execution",
        target="missing-node",
        registration_id="orphan-registration",
    )
    projection = reduce_company_invariants(
        [*nodes(), obj(orphan, "orphan-event")],
        [],
    )
    assert not projection.manager_capacity_complete
    assert projection.unattributed_active == ("execution:orphan-execution",)

    missing_manager_target = nodes()[1]
    managerless_execution = agent_execution(
        execution_id="managerless-execution",
        registration_id="managerless-registration",
    )
    managerless = reduce_company_invariants(
        [
            missing_manager_target,
            obj(managerless_execution, "managerless-event"),
        ],
        [],
    )
    assert not managerless.manager_capacity_complete
    assert managerless.unattributed_active == (
        "execution:managerless-execution",
    )

    current = in_flight_request()
    first_shadow = effect_unknown_successor(
        current,
        source_event_id="uncertain-source-1",
    )
    second_payload = cast(
        dict[str, object],
        copy.deepcopy(first_shadow.payload),
    )
    second_payload.update({
        "dispatch_revision_id": "revision-second-uncertain",
        "command_id": "command-second-uncertain",
    })
    second_shadow = UncertainDispatch(
        first_shadow.reservation_id,
        first_shadow.dispatch_request_id,
        "uncertain-source-2",
        first_shadow.source_global_sequence + 1,
        "tx-uncertain-source-2",
        "command-second-uncertain",
        "effect_unknown",
        "effect_unknown",
        company_contract_sha256(second_payload),
        second_payload,
    )
    with pytest.raises(CompanyInvariantError, match="multiple unresolved"):
        reduce_company_invariants(
            [*nodes(), current],
            [first_shadow, second_shadow],
        )


def test_dispatched_reverse_binding_and_provider_provenance_are_strict() -> None:
    dispatched = dispatch(state="dispatched")
    execution = agent_execution(
        execution_id="exec-1",
        dispatch_id="dispatch-request-1",
        registration_id=None,
        runtime_status="telemetry_silent",
        provenance="unknown",
    )
    with pytest.raises(CompanyInvariantError, match="provider-grade"):
        reduce_company_invariants(
            [*nodes(), obj(dispatched, "dispatch-event"), obj(execution, "execution-event")],
            [],
        )

    carrier, receipt, evidence = dispatched_runtime_records(
        dispatched,
        execution,
    )
    assert reduce_company_invariants(
        [
            *nodes(),
            obj(dispatched, "dispatch-event"),
            obj(execution, "execution-event"),
            obj(carrier, "carrier-event"),
            obj(receipt, "receipt-event"),
            obj(evidence, "evidence-event"),
        ],
        [],
    ).company_capacity == 1

    with pytest.raises(
        CompanyInvariantError,
        match="lacks current provider receipt binding",
    ):
        reduce_company_invariants(
            [
                *nodes(),
                obj(dispatched, "dispatch-event"),
                obj(execution, "execution-event"),
                obj(carrier, "carrier-event"),
                obj(evidence, "evidence-event"),
            ],
            [],
        )

    execution_without_evidence = copy.deepcopy(execution)
    execution_without_evidence["evidence_ids"] = []
    with pytest.raises(
        CompanyInvariantError,
        match="current provider evidence differs",
    ):
        reduce_company_invariants(
            [
                *nodes(),
                obj(dispatched, "dispatch-event"),
                obj(execution_without_evidence, "execution-event"),
                obj(carrier, "carrier-event"),
                obj(receipt, "receipt-event"),
            ],
            [],
        )

    duplicate = agent_execution(
        execution_id="exec-2",
        dispatch_id="dispatch-request-1",
        registration_id=None,
        runtime_status="telemetry_silent",
        provenance="adapter_receipt_persisted",
    )
    with pytest.raises(CompanyInvariantError, match="multiple ExecutionNodes"):
        reduce_company_invariants(
            [
                *nodes(),
                obj(dispatched, "dispatch-event"),
                obj(execution, "execution-event"),
                obj(carrier, "carrier-event"),
                obj(receipt, "receipt-event"),
                obj(evidence, "evidence-event"),
                obj(duplicate, "execution-event-2"),
            ],
            [],
        )


def test_same_sequence_divergence_and_parked_target_are_rejected() -> None:
    active = cast(dict[str, object], copy.deepcopy(family_records()[5]))
    parked = copy.deepcopy(active)
    parked.update({
        "state": "parked",
        "session_id": None,
        "session_availability": "unavailable",
    })
    with pytest.raises(CompanyInvariantError, match="divergent logical"):
        reduce_company_invariants(
            [
                obj(active, "carrier-active", sequence=4),
                obj(parked, "carrier-parked", sequence=4),
            ],
            [],
        )

    queued = dispatch()
    current = obj(queued, "queued-event")
    admitted = dispatch(
        state="admitted",
        command_id="command-2",
        revision_id="revision-2",
    )
    admitted.update({
        "revision": 2,
        "previous_event_id": current.event_id,
        "previous_payload_sha256": current.payload_sha256,
    })
    parked_nodes = nodes()
    target_payload = cast(
        dict[str, object],
        copy.deepcopy(parked_nodes[1].payload),
    )
    target_payload["status"] = "parked"
    parked_nodes[1] = obj(target_payload, "target-parked-event")
    with pytest.raises(CompanyInvariantError, match="active target"):
        reduce_company_invariants(
            [*parked_nodes, current],
            [],
            transition(admitted),
        )


def test_work_definitions_are_order_independent_and_chain_exact() -> None:
    task, packet = work_task_packet()
    child = copy.deepcopy(packet)
    child.update({
        "packet_id": "packet-2",
        "parent_packet_id": packet["packet_id"],
        "parent_packet_sha256": packet["packet_sha256"],
        "delegation_depth": 2,
    })
    rehash(child, "packet_sha256")

    forward = reduce_company_invariants(
        [obj(task, "task-event"), obj(packet, "packet-event"), obj(child, "child-event")],
        [],
    )
    reverse = reduce_company_invariants(
        [obj(child, "child-event"), obj(packet, "packet-event"), obj(task, "task-event")],
        [],
    )
    assert forward.objects == reverse.objects

    second_task = task_revision(revision=2)
    second_task["previous_task_sha256"] = task["task_sha256"]
    rehash(second_task, "task_sha256")
    with pytest.raises(CompanyInvariantError, match="no work packet"):
        reduce_company_invariants(
            [obj(task, "task-event"), obj(packet, "packet-event"), obj(second_task, "task-event-2")],
            [],
        )

    forged_child = copy.deepcopy(child)
    forged_child["parent_packet_sha256"] = "b" * 64
    rehash(forged_child, "packet_sha256")
    with pytest.raises(CompanyInvariantError, match="parent binding"):
        reduce_company_invariants(
            [obj(task, "task-event"), obj(packet, "packet-event"), obj(forged_child, "child-event")],
            [],
        )


def test_work_definition_logical_ids_are_append_once_across_generic_commit() -> None:
    task, packet = work_task_packet()
    current = [obj(task, "task-event"), obj(packet, "packet-event")]

    divergent_task = copy.deepcopy(task)
    divergent_task["display_name"] = "Divergent task revision bytes"
    rehash(divergent_task, "task_sha256")
    with pytest.raises(CompanyInvariantError, match="immutable work definition"):
        reduce_company_invariants(
            current,
            [],
            work_transition(divergent_task),
        )

    divergent_packet = copy.deepcopy(packet)
    divergent_packet["display_name"] = "Divergent work packet bytes"
    rehash(divergent_packet, "packet_sha256")
    with pytest.raises(CompanyInvariantError, match="immutable work definition"):
        reduce_company_invariants(
            current,
            [],
            work_transition(divergent_packet),
        )

    bound_task, bound_packet, queued, binding = registered_work_definition()
    bound_current = [
        *nodes(department="rtl"),
        obj(bound_task, "bound-task-event"),
        obj(bound_packet, "bound-packet-event"),
        obj(queued, "bound-queued-event"),
        obj(binding, "bound-binding-event"),
    ]
    divergent_binding = copy.deepcopy(binding)
    divergent_binding["provider_allowlist"] = ["claude"]
    rehash(divergent_binding, "binding_sha256")
    with pytest.raises(CompanyInvariantError, match="immutable work definition"):
        reduce_company_invariants(
            bound_current,
            [],
            work_transition(divergent_binding),
        )


def test_work_dispatch_binding_is_transactional_and_gate_is_fail_closed() -> None:
    task, packet, queued, binding = registered_work_definition()
    projection = reduce_company_invariants(
        [
            *nodes(department="rtl"),
            obj(task, "task-event"),
            obj(packet, "packet-event"),
            obj(queued, "queued-event"),
            obj(binding, "binding-event"),
        ],
        [],
    )
    assert any(item.contract_type == WORK_DISPATCH_BINDING_V1 for item in projection.objects)

    in_flight = dispatch(state="in_flight")
    in_flight.update({
        "task_id": task["task_id"],
        "packet_id": packet["packet_id"],
        "department_id": packet["department_id"],
        "scope_sha256": company_contract_sha256(packet["authority_scope"]),
        "revision": 3,
        "previous_event_id": "admitted-event",
        "previous_payload_sha256": "b" * 64,
    })
    gate = work_definition_enforcement()
    gate["previous_transaction_sha256"] = "f" * 64
    rehash(gate, "enforcement_sha256")
    with pytest.raises(CompanyInvariantError, match="cannot activate over unbound in-flight"):
        reduce_company_invariants(
            [*nodes(department="rtl"), obj(task, "task-event"), obj(packet, "packet-event"), obj(in_flight, "in-flight-event")],
            [],
            work_transition(gate),
        )


def test_enforcement_blocks_admitted_to_in_flight_without_binding() -> None:
    task, packet = work_task_packet()
    admitted = dispatch(state="admitted")
    admitted.update({
        "task_id": task["task_id"],
        "packet_id": packet["packet_id"],
        "department_id": packet["department_id"],
        "scope_sha256": company_contract_sha256(packet["authority_scope"]),
        "revision": 2,
        "previous_event_id": "queued-event",
        "previous_payload_sha256": "b" * 64,
    })
    in_flight = copy.deepcopy(admitted)
    in_flight.update({
        "dispatch_revision_id": "dispatch-revision-3",
        "command_id": "command-3",
        "revision": 3,
        "previous_event_id": "admitted-event",
        "previous_payload_sha256": company_contract_sha256(admitted),
        "state": "in_flight",
        "attempt": 1,
    })
    gate = work_definition_enforcement()
    with pytest.raises(CompanyInvariantError, match="registered launch requires"):
        reduce_company_invariants(
            [
                *nodes(department="rtl"),
                obj(task, "task-event"),
                obj(packet, "packet-event"),
                obj(admitted, "admitted-event"),
                obj(gate, "gate-event"),
            ],
            [],
            transition(in_flight),
        )


def test_enforcement_blocks_expired_admitted_to_in_flight_with_binding() -> None:
    task, packet, queued, binding = registered_work_definition()
    admitted = copy.deepcopy(queued)
    admitted.update({
        "dispatch_revision_id": "dispatch-revision-2",
        "command_id": "command-2",
        "revision": 2,
        "previous_event_id": "queued-event",
        "previous_payload_sha256": company_contract_sha256(queued),
        "state": "admitted",
        "updated_at": "2026-07-26T00:30:00Z",
    })
    in_flight = copy.deepcopy(admitted)
    in_flight.update({
        "dispatch_revision_id": "dispatch-revision-3",
        "command_id": "command-3",
        "revision": 3,
        "previous_event_id": "admitted-event",
        "previous_payload_sha256": company_contract_sha256(admitted),
        "state": "in_flight",
        "attempt": 1,
        "updated_at": "2026-07-26T02:00:00Z",
    })
    gate = work_definition_enforcement()
    with pytest.raises(
        CompanyInvariantError,
        match="work dispatch binding is expired",
    ):
        reduce_company_invariants(
            [
                *nodes(department="rtl"),
                obj(task, "task-event"),
                obj(packet, "packet-event"),
                obj(admitted, "admitted-event"),
                obj(binding, "binding-event"),
                obj(gate, "gate-event"),
            ],
            [],
            transition(
                in_flight,
                recorded_at="2026-07-26T02:00:00Z",
            ),
        )


def test_registered_queue_requires_atomic_binding_and_binding_id_is_global() -> None:
    task, packet, queued, binding = registered_work_definition()
    with pytest.raises(
        CompanyInvariantError,
        match="registered queued dispatch lacks",
    ):
        reduce_company_invariants(
            [
                *nodes(department="rtl"),
                obj(task, "task-event"),
                obj(packet, "packet-event"),
            ],
            [],
            work_transition(queued),
        )

    second_queued = copy.deepcopy(queued)
    second_queued.update({
        "dispatch_request_id": "dispatch-request-2",
        "dispatch_revision_id": "dispatch-revision-2",
        "command_id": "command-2",
        "reservation_id": "reservation-2",
    })
    second_binding = copy.deepcopy(binding)
    second_binding.update({
        "transaction_id": "tx-2",
        "command_id": second_queued["command_id"],
        "dispatch_request_id": second_queued["dispatch_request_id"],
        "dispatch_revision_id": second_queued["dispatch_revision_id"],
        "dispatch_payload_sha256":
            company_contract_sha256(second_queued),
    })
    rehash(second_binding, "binding_sha256")
    with pytest.raises(
        CompanyInvariantError,
        match="binding ID is bound to multiple",
    ):
        reduce_company_invariants(
            [
                *nodes(department="rtl"),
                obj(task, "task-event"),
                obj(packet, "packet-event"),
                obj(queued, "queued-event"),
                obj(binding, "binding-event"),
                obj(second_queued, "second-queued-event"),
                obj(second_binding, "second-binding-event"),
            ],
            [],
        )
