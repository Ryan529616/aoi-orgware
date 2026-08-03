"""Public-ledger semantic tests for runtime-policy readiness observation."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, cast

import pytest

from aoi_orgware.company.contracts import (
    AUTHORITY_GRANT_V1,
    CHIEF_TERM_V1,
    DEPARTMENT_IDENTITY_V1,
    EXECUTION_NODE_V1,
    ORGANIZATION_NODE_V1,
    canonical_company_json_bytes,
    company_contract_sha256,
)
from aoi_orgware.company.invariant_carriers import InvariantObject
from aoi_orgware.company.runtime_policy import runtime_policy_definition_v2
from aoi_orgware.company.runtime_policy_readiness import (
    RuntimePolicyReadinessObservationV1,
    _role_class,
    derive_runtime_policy_readiness,
    validate_runtime_policy_readiness_observation,
)
from aoi_orgware.company.supervisor import CompanySupervisor


_TEST_DIR = Path(__file__).resolve().parent
if str(_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_TEST_DIR))

import test_chief_first_bind as chief_first_bind  # type: ignore[import-not-found]
import test_department_lifecycle as department_lifecycle  # type: ignore[import-not-found]
import test_supervisor as supervisor_tests  # type: ignore[import-not-found]


def _derive(supervisor: CompanySupervisor) -> RuntimePolicyReadinessObservationV1:
    """The observation API deliberately consumes the owner-held ledger state."""

    return derive_runtime_policy_readiness(supervisor._state)


def _department_lead(
    supervisor: CompanySupervisor,
    *,
    label: str = "readiness",
    requested_at: str = "2026-07-27T00:01:00Z",
    resumed_at: str = "2026-07-27T00:02:00Z",
    admitted_at: str = "2026-07-27T00:03:00Z",
    started_at: str = "2026-07-27T00:04:00Z",
    completed_at: str = "2026-07-27T00:05:00Z",
) -> None:
    """Create one public, provider-bound D1 department-lead execution."""

    department_lifecycle._resume(
        supervisor,
        label=label,
        requested_at=requested_at,
        recorded_at=resumed_at,
    )
    supervisor.admit_department_dispatch(
        f"{label}-dispatch",
        transaction_id=f"{label}-admit-transaction",
        command_id=f"{label}-admit-command",
        recorded_at=admitted_at,
    )
    supervisor.begin_department_dispatch(
        f"{label}-dispatch",
        transaction_id=f"{label}-start-transaction",
        command_id=f"{label}-start-command",
        recorded_at=started_at,
    )
    receipt = department_lifecycle._provider_receipt(
        supervisor,
        event_kind="dispatch_succeeded",
        transaction_id=f"{label}-success-transaction",
        command_id=f"{label}-success-command",
        recorded_at=completed_at,
        provider_dispatch_id=f"provider-dispatch-{label}-1",
    )
    supervisor.dispatch_department_lead(
        f"{label}-dispatch",
        receipt,
        transaction_id=f"{label}-success-transaction",
        command_id=f"{label}-success-command",
        recorded_at=completed_at,
    )


def _effect_unknown_hold(supervisor: CompanySupervisor) -> None:
    """Create the durable/uncertain effect_unknown reservation via public API."""

    department_lifecycle._resume(supervisor)
    supervisor.admit_department_dispatch(
        "resume-dispatch",
        transaction_id="readiness-hold-admit-transaction",
        command_id="readiness-hold-admit-command",
        recorded_at="2026-07-27T00:03:00Z",
    )
    supervisor.begin_department_dispatch(
        "resume-dispatch",
        transaction_id="readiness-hold-start-transaction",
        command_id="readiness-hold-start-command",
        recorded_at="2026-07-27T00:04:00Z",
    )
    receipt = department_lifecycle._provider_receipt(
        supervisor,
        event_kind="dispatch_effect_unknown",
        transaction_id="readiness-hold-effect-transaction",
        command_id="readiness-hold-effect-command",
        recorded_at="2026-07-27T00:05:00Z",
        reconcile_ref="readiness-effect-unknown-reconcile",
    )
    supervisor.mark_department_dispatch_effect_unknown(
        "resume-dispatch",
        receipt,
        transaction_id="readiness-hold-effect-transaction",
        command_id="readiness-hold-effect-command",
        recorded_at="2026-07-27T00:05:00Z",
    )


def _registered_raw_depth(
    supervisor: CompanySupervisor,
    *,
    execution_id: str,
    depth: int,
    runtime_status: str,
    engineering_status: str,
) -> None:
    """Persist a provider-registered but topology-unattributed raw depth."""

    execution, _ = supervisor_tests.registered_orphan(
        supervisor,
        execution_id=execution_id,
        registration_id=f"{execution_id}-registration",
        evidence_id=f"{execution_id}-evidence",
    )
    execution = {
        **execution,
        "delegation_depth": depth,
        "runtime_status": runtime_status,
        "engineering_status": engineering_status,
        "terminal_at": (
            "2026-07-27T00:01:00Z"
            if runtime_status == "stopped" else None
        ),
    }
    evidence = supervisor_tests.registration_evidence(
        supervisor,
        execution=execution,
        evidence_id=f"{execution_id}-evidence",
    )
    supervisor.register_execution(
        execution,
        evidence,
        transaction_id=f"{execution_id}-transaction",
        command_id=f"{execution_id}-command",
        recorded_at="2026-07-27T00:01:00Z",
    )


def _takeover(
    supervisor: CompanySupervisor,
    carrier: dict[str, Any],
    *,
    nonce: str,
    label: str,
    consumed_at: str,
) -> None:
    """Use the public takeover seam with independent, replay-safe identities."""

    capability = supervisor_tests.prepare_handoff(
        supervisor,
        carrier,
        nonce=nonce,
        user_action_ref=f"readiness-{label}-user-action",
    )
    supervisor.takeover_chief(
        capability,
        carrier,
        consumed_at=consumed_at,
        grant_expires_at="2026-07-29T00:00:00Z",
    )


def test_public_reused_stopped_fenced_session_with_active_d1_has_one_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public-ledger regression: a stopped/fenced session no longer binds live work."""

    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        carrier_two = supervisor_tests.handoff_carrier(2)
        _takeover(
            supervisor,
            carrier_two,
            nonce="a" * 64,
            label="first-takeover",
            consumed_at="2026-07-27T00:02:00Z",
        )
        old_chief = next(
            item
            for item in supervisor_tests._objects(
                supervisor, EXECUTION_NODE_V1,
            )
            if item["carrier_id"] == "carrier-1"
        )
        stop_receipt = supervisor_tests.fenced_chief_stop_receipt(
            supervisor,
            execution_id=old_chief["execution_id"],
            transaction_id="readiness-reuse-stop-transaction",
            command_id="readiness-reuse-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        supervisor.record_fenced_chief_execution_stopped(
            old_chief["execution_id"],
            stop_receipt,
            transaction_id="readiness-reuse-stop-transaction",
            command_id="readiness-reuse-stop-command",
            recorded_at="2026-07-27T00:03:00Z",
        )
        carrier_three = supervisor_tests.handoff_carrier(3)
        _takeover(
            supervisor,
            carrier_three,
            nonce="b" * 64,
            label="reused-session-takeover",
            consumed_at="2026-07-27T00:05:00Z",
        )
        department_carrier = department_lifecycle._known_department_carrier()
        monkeypatch.setattr(
            department_lifecycle,
            "_known_department_carrier",
            lambda: {**department_carrier, "session_id": "session-1"},
        )
        _department_lead(
            supervisor,
            label="readiness-post-reuse",
            requested_at="2026-07-27T00:06:00Z",
            resumed_at="2026-07-27T00:07:00Z",
            admitted_at="2026-07-27T00:08:00Z",
            started_at="2026-07-27T00:09:00Z",
            completed_at="2026-07-27T00:10:00Z",
        )
        observation = _derive(supervisor)

    assert observation.subordinate_occupied_lower_bound == 1
    assert len(observation.subordinate_slots) == 1
    assert not any(
        "provider_session_binding_ambiguous" in item.reason_codes
        for item in observation.holds
    )


def test_public_d1_sharing_current_chief_slot_is_held_not_counted(
    tmp_path: Path,
) -> None:
    """Public-ledger regression: Chief coverage cannot also be subordinate capacity."""

    with department_lifecycle._initialize(tmp_path) as supervisor:
        chief = next(
            item.payload
            for item in supervisor.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["role"] == "chief"
        )
        lead_node = next(
            item.payload
            for item in supervisor.objects(contract_type=ORGANIZATION_NODE_V1)
            if item.payload["role"] == "rtl_lead"
        )
        execution, _ = supervisor_tests.registered_turn(
            supervisor,
            execution_id="readiness-chief-slot-overlap-execution",
            registration_id="readiness-chief-slot-overlap-registration",
            evidence_id="readiness-chief-slot-overlap-evidence",
        )
        execution = {
            **execution,
            "execution_kind": "agent",
            "display_name": "RTL lead on Chief carrier",
            "organization_node_id": lead_node["node_id"],
            "department_id": lead_node["department_id"],
            "turn_id": None,
            "agent_id": "readiness-chief-slot-overlap-agent",
            "role": lead_node["role"],
            "delegation_depth": 1,
            "objective": "exercise current-Chief physical-slot exclusion",
        }
        evidence = supervisor_tests.registration_evidence(
            supervisor,
            execution=execution,
            evidence_id="readiness-chief-slot-overlap-evidence",
        )
        supervisor.register_execution(
            execution,
            evidence,
            transaction_id="readiness-chief-slot-overlap-transaction",
            command_id="readiness-chief-slot-overlap-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        observation = _derive(supervisor)

    overlap_holds = [
        item for item in observation.holds
        if "chief_physical_slot_overlap" in item.reason_codes
    ]
    assert observation.subordinate_occupied_lower_bound == 0
    assert observation.subordinate_slots == ()
    assert len(overlap_holds) == 1
    assert "subordinate_chief_physical_slot_overlap" in observation.blockers


def test_all_authority_grants_are_witnessed_for_current_chief_cardinality(
    tmp_path: Path,
) -> None:
    """Real-ledger coverage: cardinality matching consults matching and nonmatching grants."""

    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        term = next(
            item.payload
            for item in supervisor.objects(contract_type=CHIEF_TERM_V1)
        )
        grants = tuple(supervisor.objects(contract_type=AUTHORITY_GRANT_V1))
        observation = _derive(supervisor)

    matching = [
        item for item in grants
        if (
            item.payload["actor_kind"] == "chief"
            and item.payload["actor_id"] == term["chief_id"]
            and item.payload["carrier_id"] == term["carrier_id"]
            and item.payload["term"] == term["term"]
            and item.payload["chief_epoch"] == term["epoch"]
            and item.payload["authority_state"] == "active"
            and "company.mutate" in item.payload["permissions"]
        )
    ]
    nonmatching = [item for item in grants if item not in matching]
    witness_keys = {
        (item.contract_type, item.object_key)
        for item in observation.source_witnesses
    }
    assert len(matching) == 1
    assert len(nonmatching) == 1
    assert {
        (item.contract_type, item.object_key) for item in grants
    } <= witness_keys


def test_public_takeovers_group_same_carrier_chief_executions_but_stack_distinct_carriers(
    tmp_path: Path,
) -> None:
    """Public-ledger regression for retiring-Chief carrier grouping and stacking."""

    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        chief_turn, evidence = supervisor_tests.registered_turn(supervisor)
        chief_root_id = str(chief_turn["parent_execution_id"])
        supervisor.register_execution(
            chief_turn,
            evidence,
            transaction_id="readiness-chief-turn-transaction",
            command_id="readiness-chief-turn-command",
            recorded_at="2026-07-27T00:01:00Z",
        )
        _takeover(
            supervisor,
            supervisor_tests.handoff_carrier(2),
            nonce="c" * 64,
            label="same-carrier-turn-takeover",
            consumed_at="2026-07-27T00:02:00Z",
        )
        same_carrier = _derive(supervisor)
        _takeover(
            supervisor,
            supervisor_tests.handoff_carrier(3),
            nonce="d" * 64,
            label="distinct-carrier-takeover",
            consumed_at="2026-07-27T00:03:00Z",
        )
        distinct_carriers = _derive(supervisor)

    assert len(same_carrier.retiring_candidates) == 1
    assert same_carrier.retiring_candidates[0].carrier_id == "carrier-1"
    assert same_carrier.retiring_candidates[0].execution_ids == tuple(sorted((
        chief_root_id, "registered-turn-execution",
    )))
    assert "retiring_chief_candidate_stack" not in same_carrier.blockers
    assert len(distinct_carriers.retiring_candidates) == 2
    assert {item.carrier_id for item in distinct_carriers.retiring_candidates} == {
        "carrier-1", "carrier-2",
    }
    assert "retiring_chief_candidate_stack" in distinct_carriers.blockers


def test_pure_internal_d2_d3_turn_attribution_inherits_owner_dependencies() -> None:
    """Pure internal semantic coverage, not a public-ledger fixture or claim."""

    def item(
        contract_type: str,
        object_key: str,
        payload: dict[str, object],
    ) -> InvariantObject:
        return InvariantObject(
            contract_type=contract_type,
            object_key=object_key,
            event_id=f"{object_key}-event",
            global_sequence=1,
            payload_sha256=company_contract_sha256(payload),
            payload=payload,
        )

    department_id = "pure-internal-department"
    identity = item(DEPARTMENT_IDENTITY_V1, department_id, {
        "department_id": department_id,
        "lead_node_id": "pure-d1-node",
    })
    nodes = {
        "pure-d1-node": item(ORGANIZATION_NODE_V1, "pure-d1-node", {
            "node_id": "pure-d1-node", "department_id": department_id,
            "delegation_depth": 1, "role": "rtl_lead",
        }),
        "pure-d2-node": item(ORGANIZATION_NODE_V1, "pure-d2-node", {
            "node_id": "pure-d2-node", "department_id": department_id,
            "delegation_depth": 2, "role": "worker",
        }),
        "pure-d3-node": item(ORGANIZATION_NODE_V1, "pure-d3-node", {
            "node_id": "pure-d3-node", "department_id": department_id,
            "delegation_depth": 3, "role": "reviewer",
        }),
    }

    def execution(
        execution_id: str,
        *,
        depth: int,
        node_id: str,
        role: str,
        parent_execution_id: str | None,
        execution_kind: str = "agent",
    ) -> InvariantObject:
        return item(EXECUTION_NODE_V1, execution_id, {
            "execution_id": execution_id,
            "execution_kind": execution_kind,
            "carrier_id": "pure-carrier",
            "department_id": department_id,
            "delegation_depth": depth,
            "organization_node_id": node_id,
            "role": role,
            "parent_execution_id": parent_execution_id,
        })

    d1_owner = execution(
        "pure-d1-owner", depth=1, node_id="pure-d1-node", role="rtl_lead",
        parent_execution_id=None,
    )
    d2_owner = execution(
        "pure-d2-owner", depth=2, node_id="pure-d2-node", role="worker",
        parent_execution_id="pure-d1-owner",
    )
    d2_turn = execution(
        "pure-d2-turn", depth=2, node_id="pure-d2-node", role="worker",
        parent_execution_id="pure-d2-owner", execution_kind="turn",
    )
    d3_owner = execution(
        "pure-d3-owner", depth=3, node_id="pure-d3-node", role="reviewer",
        parent_execution_id="pure-d2-owner",
    )
    d3_turn = execution(
        "pure-d3-turn", depth=3, node_id="pure-d3-node", role="reviewer",
        parent_execution_id="pure-d3-owner", execution_kind="turn",
    )
    executions = {
        value.object_key: value
        for value in (d1_owner, d2_owner, d2_turn, d3_owner, d3_turn)
    }
    policy = runtime_policy_definition_v2()

    d2 = _role_class(
        d2_turn, executions=executions, nodes=nodes,
        identities={department_id: identity}, policy=policy,
    )
    d3 = _role_class(
        d3_turn, executions=executions, nodes=nodes,
        identities={department_id: identity}, policy=policy,
    )

    assert d2 == (
        "worker", department_id, 2, tuple(sorted({
            (DEPARTMENT_IDENTITY_V1, department_id),
            (ORGANIZATION_NODE_V1, "pure-d1-node"),
            (ORGANIZATION_NODE_V1, "pure-d2-node"),
            (EXECUTION_NODE_V1, "pure-d1-owner"),
            (EXECUTION_NODE_V1, "pure-d2-owner"),
            (EXECUTION_NODE_V1, "pure-d2-turn"),
        })),
    )
    assert d3 == (
        "reviewer", department_id, 3, tuple(sorted({
            (DEPARTMENT_IDENTITY_V1, department_id),
            (ORGANIZATION_NODE_V1, "pure-d1-node"),
            (ORGANIZATION_NODE_V1, "pure-d2-node"),
            (ORGANIZATION_NODE_V1, "pure-d3-node"),
            (EXECUTION_NODE_V1, "pure-d1-owner"),
            (EXECUTION_NODE_V1, "pure-d2-owner"),
            (EXECUTION_NODE_V1, "pure-d3-owner"),
            (EXECUTION_NODE_V1, "pure-d3-turn"),
        })),
    )


def test_exact_current_chief_is_separate_from_public_d1_capacity(
    tmp_path: Path,
) -> None:
    with department_lifecycle._initialize(tmp_path) as supervisor:
        _department_lead(supervisor)
        observation = _derive(supervisor)

    assert observation.current_chief_state == "exact_identity_carrier_observed"
    assert len(observation.current_chief) == 1
    chief = observation.current_chief[0]
    assert chief.actor_id is not None and chief.carrier_id == "carrier-1"
    assert chief.physical_slot_id is not None
    assert observation.subordinate_occupied_lower_bound == 1
    assert [(item.role_class, item.delegation_depth) for item in observation.subordinate_slots] == [
        ("working_lead", 1),
    ]
    assert observation.subordinate_slots[0].physical_slot_id != chief.physical_slot_id
    assert observation.subordinate_capacity_quality == "known_lower_bound"
    assert observation.transport_capability_state == "unavailable"
    assert observation.writer_quiescence_state == "unavailable"
    assert observation.activation_state == "inactive"
    assert observation.admission_state == "unavailable"
    assert observation.operational_effect == "none"


def test_unknown_genesis_is_not_invented_as_transport_coverage(
    tmp_path: Path,
) -> None:
    with chief_first_bind._supervisor(tmp_path) as supervisor:
        observation = _derive(supervisor)

    assert observation.current_chief_state == "exact_identity_carrier_unavailable"
    assert len(observation.current_chief) == 1
    assert observation.current_chief[0].physical_slot_id is None
    assert "current_provider_session_unavailable" in observation.current_chief[0].reason_codes
    assert observation.transport_capability_state == "unavailable"
    assert "current_chief_carrier_coverage_unavailable" in observation.blockers
    assert observation.subordinate_occupied_lower_bound == 0


def test_active_raw_d4_and_d6_are_unattributed_blockers_without_clamp(
    tmp_path: Path,
) -> None:
    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        _registered_raw_depth(
            supervisor,
            execution_id="readiness-active-d4",
            depth=4,
            runtime_status="running",
            engineering_status="active",
        )
        _registered_raw_depth(
            supervisor,
            execution_id="readiness-active-d6",
            depth=6,
            runtime_status="unknown",
            engineering_status="unknown",
        )
        observation = _derive(supervisor)

    assert [(item.execution_id, item.raw_depth, item.lifecycle_class) for item in observation.over_depth] == [
        ("readiness-active-d4", 4, "active_legacy_blocker"),
        ("readiness-active-d6", 6, "active_legacy_blocker"),
    ]
    assert "active_over_depth_execution_observed" in observation.blockers
    assert "subordinate_attribution_unavailable" in observation.blockers
    assert observation.subordinate_occupied_lower_bound == 0
    assert {item.holder_id for item in observation.holds} >= {
        "readiness-active-d4", "readiness-active-d6",
    }


def test_terminal_raw_d4_is_retained_without_active_depth_blocker(
    tmp_path: Path,
) -> None:
    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        _registered_raw_depth(
            supervisor,
            execution_id="readiness-terminal-d4",
            depth=4,
            runtime_status="stopped",
            engineering_status="completed",
        )
        observation = _derive(supervisor)

    assert [(item.execution_id, item.raw_depth, item.lifecycle_class) for item in observation.over_depth] == [
        ("readiness-terminal-d4", 4, "historical_terminal_legacy"),
    ]
    assert "active_over_depth_execution_observed" not in observation.blockers


def test_effect_unknown_reservation_is_visible_once_with_all_reasons(
    tmp_path: Path,
) -> None:
    with department_lifecycle._initialize(tmp_path) as supervisor:
        _effect_unknown_hold(supervisor)
        observation = _derive(supervisor)

    holds = [item for item in observation.holds if item.hold_kind == "dispatch_reservation"]
    assert len(holds) == 1
    assert holds[0].holder_id == "resume-reservation"
    assert "dispatch_in_flight" in holds[0].reason_codes
    assert "uncertain_effect_unknown" in holds[0].reason_codes
    assert "effect_unknown_hold_observed" in observation.blockers
    assert "held_dispatch_reservations_observed" in observation.blockers


def test_shared_global_sequence_distinct_events_are_accepted_and_session_is_redacted(
    tmp_path: Path,
) -> None:
    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        observation = _derive(supervisor)

    sequence_groups: dict[int, list[str]] = {}
    for witness in observation.source_witnesses:
        sequence_groups.setdefault(witness.global_sequence, []).append(witness.event_id)
    shared = [event_ids for event_ids in sequence_groups.values() if len(event_ids) > 1]
    assert shared and all(len(set(event_ids)) == len(event_ids) for event_ids in shared)
    wire = canonical_company_json_bytes(observation.to_dict()).decode("utf-8")
    assert "session-1" not in wire
    assert "provider-orphan-thread" not in wire


def test_observation_is_immutable_deterministic_and_exactly_revalidated(
    tmp_path: Path,
) -> None:
    with supervisor_tests.initialize(
        tmp_path,
        carrier=supervisor_tests.known_carrier(),
    ) as supervisor:
        first = _derive(supervisor)
        second = _derive(supervisor)
        assert first == second
        assert validate_runtime_policy_readiness_observation(supervisor._state, first) == first

    assert not hasattr(first, "__dict__")
    with pytest.raises(AttributeError):
        cast(Any, first).activation_state = "active"
    detached = first.to_dict()
    detached["blockers"] = []
    assert first.to_dict()["blockers"]
