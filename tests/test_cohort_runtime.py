from __future__ import annotations

import itertools
from unittest import mock

import pytest

from aoi_orgware import cohorts
from aoi_orgware import harnesslib as h
from aoi_orgware import routing_authority as authority
from aoi_orgware import routing_persistence as routing
from aoi_orgware import semantic_events as semantic
from aoi_orgware import semantic_objects as objects
from aoi_orgware.cohort_runtime import derive_cohort_status
from tests.test_routing_authority import observation, root_arm


TASK = "task-1"


def plan_for(arms: list[dict], *, failure_policy: str = "continue") -> dict:
    packet_ids = [arm["packet_authority"]["packet_id"] for arm in arms]
    return cohorts.seal_cohort(
        {
            "schema_version": 1,
            "cohort_id": "cohort-1",
            "packet_schema_version": 6,
            "resource_envelope_sha256": arms[0]["resource_envelope"][
                "snapshot_sha256"
            ],
            "execution_selection_identity_sha256": cohorts.execution_selection_identity_sha256(
                "selection-1"
            ),
            "execution_selection_target_contract_sha256": "f" * 64,
            "packet_refs": [
                {
                    "packet_id": packet_id,
                    "routing_authority_sha256": authority.authority_sha256(arm),
                }
                for packet_id, arm in zip(packet_ids, arms, strict=True)
            ],
            "dependencies": {
                packet_id: ([] if index == 0 else [packet_ids[index - 1]])
                for index, packet_id in enumerate(packet_ids)
            },
            "waves": [[packet_id] for packet_id in packet_ids],
            "max_concurrency": 2,
            "transport_slots": [
                {
                    "packet_id": packet_id,
                    "transport": arm["transport_authority"]["transport"],
                    "parent_session_id": arm["parent_authority"]["session_id"],
                    "expected_agent_type": arm["transport_authority"][
                        "expected_agent_type"
                    ],
                }
                for packet_id, arm in zip(packet_ids, arms, strict=True)
            ],
            "failure_policy": failure_policy,
            "cancel_policy": "cancel_remaining",
        }
    )


def authority_object(arm: dict) -> dict:
    return objects.create_semantic_object(
        object_type="routing_authority",
        task_id=TASK,
        object_identity=authority.authority_sha256(arm),
        payload=arm,
    )


def authority_group(arm: dict, *, classification: str = "committed") -> dict:
    wrapped = authority_object(arm)
    return {
        "stage": "authority",
        "slot": routing.routing_outcome_slot_sha256(arm),
        "objects": {"routing_authority": wrapped},
        "authority": arm,
        "outcome": None,
        "terminal": None,
        "classification": classification,
    }


def dispatch_outcome(arm: dict, *, observed: bool) -> dict:
    return authority.build_dispatch_outcome(
        arm,
        dispatch_provenance=(
            "codex_subagent_start_observed" if observed else "manual_unverified"
        ),
        observation=(
            observation(
                agent_id=f"agent-{arm['packet_authority']['packet_id']}",
                agent_type=arm["transport_authority"]["expected_agent_type"],
            )
            if observed
            else None
        ),
        recorded_at="2026-01-01T00:02:00Z",
    )


def outcome_group(
    arm: dict, outcome: dict, *, classification: str = "committed"
) -> dict:
    wrapped_authority = authority_object(arm)
    wrapped_outcome = objects.create_semantic_object(
        object_type="routing_outcome",
        task_id=TASK,
        object_identity=outcome["routing_outcome_sha256"],
        payload=outcome,
    )
    return {
        "stage": "outcome",
        "slot": routing.routing_outcome_slot_sha256(arm),
        "objects": {
            "routing_authority": wrapped_authority,
            "routing_outcome": wrapped_outcome,
        },
        "authority": arm,
        "outcome": outcome,
        "terminal": None,
        "classification": classification,
    }


def terminal_group(
    arm: dict,
    outcome: dict,
    *,
    terminal_status: str,
    typed_outcome: str,
    classification: str = "committed",
) -> dict:
    terminal = routing._terminal_payload(
        arm,
        outcome,
        terminal_status=terminal_status,
        typed_outcome=typed_outcome,
    )
    wrapped_terminal = objects.create_semantic_object(
        object_type="routing_terminal",
        task_id=TASK,
        object_identity=semantic.canonical_sha256(terminal),
        payload=terminal,
    )
    return {
        "stage": "terminal",
        "slot": routing.routing_outcome_slot_sha256(arm),
        "objects": {
            "routing_authority": authority_object(arm),
            "routing_outcome": objects.create_semantic_object(
                object_type="routing_outcome",
                task_id=TASK,
                object_identity=outcome["routing_outcome_sha256"],
                payload=outcome,
            ),
            "routing_terminal": wrapped_terminal,
        },
        "authority": arm,
        "outcome": outcome,
        "terminal": terminal,
        "classification": classification,
    }


def derive(plan: dict, groups: list[dict]) -> dict:
    report = {"task_id": TASK, "groups": groups}
    with mock.patch.object(
        routing, "inspect_routing_persistence", return_value=report
    ):
        return derive_cohort_status(mock.sentinel.paths, TASK, [], plan)


def test_empty_routing_truth_is_planned_and_never_claims_launch() -> None:
    arms = [root_arm("packet-a"), root_arm("packet-b", expected_agent_type="worker")]
    status = derive(plan_for(arms), [])

    assert [row["status"] for row in status["packet_states"].values()] == [
        "planned",
        "planned",
    ]
    assert status["transport_launch_claimed"] is False
    assert status["transport_start_observed"] is False
    assert status["launch_actor"] == "unavailable"
    assert status["launcher_receipt_sha256"] is None
    assert status["projection"]["transport_launch_claimed"] is False


def test_authority_pending_and_committed_are_armed_with_honest_recovery_flag() -> None:
    arm = root_arm("packet-a")
    plan = plan_for([arm])

    pending = derive(plan, [authority_group(arm, classification="pending")])
    committed = derive(plan, [authority_group(arm)])

    assert pending["packet_states"]["packet-a"]["status"] == "armed"
    assert pending["packet_evidence"][0]["recovery_pending"] is True
    assert committed["packet_states"]["packet-a"]["status"] == "armed"
    assert committed["packet_evidence"][0]["recovery_pending"] is False


def test_alternate_active_authority_for_plan_packet_fails_closed() -> None:
    expected = root_arm("packet-a", expected_agent_type="explorer")
    alternate = root_arm("packet-a", expected_agent_type="reviewer")
    plan = plan_for([expected])

    with pytest.raises(
        h.HarnessError, match="another active routing authority"
    ):
        derive(plan, [authority_group(alternate)])


def test_manual_outcome_stays_armed_but_observed_start_is_running() -> None:
    arm = root_arm("packet-a")
    plan = plan_for([arm])
    manual = dispatch_outcome(arm, observed=False)
    observed = dispatch_outcome(arm, observed=True)

    manual_status = derive(
        plan, [authority_group(arm), outcome_group(arm, manual)]
    )
    observed_status = derive(
        plan, [authority_group(arm), outcome_group(arm, observed)]
    )

    assert manual_status["packet_states"]["packet-a"]["status"] == "armed"
    assert manual_status["projection"]["packets"][0]["running"] is False
    assert manual_status["transport_start_observed"] is False
    assert observed_status["packet_states"]["packet-a"]["status"] == (
        "start_observed"
    )
    assert observed_status["projection"]["packets"][0]["running"] is True
    assert observed_status["transport_start_observed"] is True
    assert observed_status["transport_launch_claimed"] is False


def test_terminal_without_start_does_not_retroactively_claim_observation() -> None:
    arm = root_arm("packet-a")
    plan = plan_for([arm])
    outcome = dispatch_outcome(arm, observed=False)
    groups = [
        authority_group(arm),
        outcome_group(arm, outcome),
        terminal_group(
            arm, outcome, terminal_status="done", typed_outcome="accepted"
        ),
    ]

    status = derive(plan, groups)

    assert status["packet_states"]["packet-a"] == {
        "status": "terminal",
        "terminal_outcome": "accepted",
    }
    assert status["packet_evidence"][0]["start_observation_sha256"] is None
    assert status["transport_start_observed"] is False


def test_terminal_mapping_and_arrival_permutation_are_deterministic() -> None:
    arm = root_arm("packet-a")
    plan = plan_for([arm])
    outcome = dispatch_outcome(arm, observed=True)
    groups = [
        authority_group(arm),
        outcome_group(arm, outcome),
        terminal_group(
            arm, outcome, terminal_status="failed", typed_outcome="transport_failure"
        ),
    ]

    digests = {
        derive(plan, list(permutation))["status_sha256"]
        for permutation in itertools.permutations(groups)
    }

    assert len(digests) == 1
    status = derive(plan, groups)
    assert status["packet_states"]["packet-a"]["terminal_outcome"] == "failed"
    assert status["transport_start_observed"] is True


def test_cancel_remaining_only_cancels_never_armed_packets() -> None:
    arms = [root_arm("packet-a"), root_arm("packet-b", expected_agent_type="worker")]
    plan = plan_for(arms, failure_policy="cancel_remaining")
    failed = dispatch_outcome(arms[0], observed=False)
    failure_groups = [
        authority_group(arms[0]),
        outcome_group(arms[0], failed),
        terminal_group(
            arms[0],
            failed,
            terminal_status="failed",
            typed_outcome="procedural_failure",
        ),
    ]

    unarmed = derive(plan, failure_groups)
    armed = derive(plan, [*failure_groups, authority_group(arms[1])])

    assert unarmed["packet_states"]["packet-b"]["status"] == "cancelled"
    assert armed["packet_states"]["packet-b"]["status"] == "armed"
    assert armed["projection"]["packets"][1]["running"] is False


def test_pending_terminal_preserves_observed_start_and_marks_recovery() -> None:
    arm = root_arm("packet-a")
    plan = plan_for([arm])
    outcome = dispatch_outcome(arm, observed=True)
    groups = [
        authority_group(arm),
        outcome_group(arm, outcome),
        terminal_group(
            arm,
            outcome,
            terminal_status="done",
            typed_outcome="accepted",
            classification="pending",
        ),
    ]

    status = derive(plan, groups)

    assert status["packet_states"]["packet-a"]["status"] == "start_observed"
    assert status["packet_evidence"][0]["recovery_pending"] is True
    assert status["transport_launch_claimed"] is False
