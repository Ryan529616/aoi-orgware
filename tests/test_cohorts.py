from __future__ import annotations

import copy

import pytest

import aoi_orgware.cohorts as cohorts_module
from aoi_orgware.cohorts import (
    CohortError,
    cohort_sha256,
    project_cohort,
    seal_cohort,
    validate_cohort,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def cohort_base(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "cohort_id": "cohort-1",
        "packet_schema_version": 6,
        "packet_refs": [
            {"packet_id": "packet-a", "routing_authority_sha256": SHA_A},
            {"packet_id": "packet-b", "routing_authority_sha256": SHA_B},
            {"packet_id": "packet-c", "routing_authority_sha256": SHA_C},
        ],
        "dependencies": {"packet-a": [], "packet-b": ["packet-a"], "packet-c": ["packet-b"]},
        "waves": [["packet-a"], ["packet-b"], ["packet-c"]],
        "max_concurrency": 2,
        "transport_slots": [
            {"packet_id": "packet-a", "slot_id": "slot-1"},
            {"packet_id": "packet-b", "slot_id": "slot-1"},
            {"packet_id": "packet-c", "slot_id": "slot-1"},
        ],
        "failure_policy": "cancel_remaining",
        "cancel_policy": "cancel_remaining",
    }
    value.update(changes)
    return value


def sealed(**changes: object) -> dict[str, object]:
    return seal_cohort(cohort_base(**changes))


def test_sealed_cohort_is_canonical_and_pure_projection_never_claims_launch() -> None:
    first = sealed()
    second = sealed(dependencies={"packet-c": ["packet-b"], "packet-a": [], "packet-b": ["packet-a"]})

    assert first == second
    assert first["cohort_sha256"] == cohort_sha256(cohort_base())
    assert validate_cohort(first) == first
    projection = project_cohort(first)
    assert projection["transport_launch_claimed"] is False
    assert [packet["status"] for packet in projection["packets"]] == ["planned"] * 3
    assert [packet["running"] for packet in projection["packets"]] == [False] * 3
    assert projection["waves"][0]["status"] == "ready"


def test_dependency_edge_order_is_canonicalized_before_hashing() -> None:
    packet_refs = [
        {"packet_id": "packet-a", "routing_authority_sha256": SHA_A},
        {"packet_id": "packet-b", "routing_authority_sha256": SHA_B},
        {"packet_id": "packet-c", "routing_authority_sha256": SHA_C},
        {"packet_id": "packet-d", "routing_authority_sha256": SHA_A},
    ]
    common = {
        "packet_refs": packet_refs,
        "waves": [["packet-a", "packet-b"], ["packet-c"], ["packet-d"]],
        "transport_slots": [
            {"packet_id": "packet-a", "slot_id": "slot-a"},
            {"packet_id": "packet-b", "slot_id": "slot-b"},
            {"packet_id": "packet-c", "slot_id": "slot-a"},
            {"packet_id": "packet-d", "slot_id": "slot-a"},
        ],
    }
    first = sealed(**common, dependencies={"packet-a": [], "packet-b": [], "packet-c": ["packet-a", "packet-b"], "packet-d": ["packet-c"]})
    second = sealed(**common, dependencies={"packet-d": ["packet-c"], "packet-c": ["packet-b", "packet-a"], "packet-b": [], "packet-a": []})

    assert first == second


def test_transport_slot_mapping_is_canonicalized_by_packet_identity() -> None:
    first = sealed()
    second = sealed(
        transport_slots=[
            {"packet_id": "packet-c", "slot_id": "slot-1"},
            {"packet_id": "packet-a", "slot_id": "slot-1"},
            {"packet_id": "packet-b", "slot_id": "slot-1"},
        ]
    )

    assert first == second
    assert [slot["packet_id"] for slot in second["transport_slots"]] == [
        "packet-a",
        "packet-b",
        "packet-c",
    ]


def test_schema_dag_capacity_slots_and_tampering_fail_closed() -> None:
    with pytest.raises(CohortError, match="cycle"):
        sealed(dependencies={"packet-a": ["packet-c"], "packet-b": ["packet-a"], "packet-c": ["packet-b"]})
    with pytest.raises(CohortError, match="unknown packet"):
        sealed(waves=[["packet-a"], ["packet-b"], ["missing"]])
    with pytest.raises(CohortError, match="duplicate"):
        sealed(waves=[["packet-a", "packet-a"], ["packet-b"], ["packet-c"]])
    with pytest.raises(CohortError, match="incompatible"):
        sealed(packet_schema_version=5)
    with pytest.raises(CohortError, match="max_concurrency"):
        sealed(max_concurrency=1, waves=[["packet-a", "packet-b"], ["packet-c"]])
    with pytest.raises(CohortError, match="slot conflict"):
        sealed(
            waves=[["packet-a", "packet-b"], ["packet-c"]],
            max_concurrency=2,
            dependencies={"packet-a": [], "packet-b": [], "packet-c": ["packet-b"]},
        )

    tampered = copy.deepcopy(sealed())
    tampered["failure_policy"] = "continue"
    with pytest.raises(CohortError, match="cohort_sha256"):
        validate_cohort(tampered)
    malformed = copy.deepcopy(sealed())
    malformed["unexpected"] = True
    with pytest.raises(CohortError, match="schema"):
        validate_cohort(malformed)


def test_cohort_lifecycle_identifiers_are_canonical_and_bounded() -> None:
    assert sealed(cohort_id="c" * 128)["cohort_id"] == "c" * 128
    for unsafe_id in ("cohort/path", "cohort:ref", "cohort@ref", "c" * 129):
        with pytest.raises(CohortError, match="cohort_id is invalid"):
            sealed(cohort_id=unsafe_id)
    with pytest.raises(CohortError, match="packet_ref.packet_id is invalid"):
        sealed(packet_refs=[{"packet_id": "packet/path", "routing_authority_sha256": SHA_A}])
    with pytest.raises(CohortError, match="wave packet_id is invalid"):
        sealed(waves=[["packet/path"], ["packet-b"], ["packet-c"]])
    with pytest.raises(CohortError, match="transport_slot.slot_id is invalid"):
        sealed(
            transport_slots=[
                {"packet_id": "packet-a", "slot_id": "slot/path"},
                {"packet_id": "packet-b", "slot_id": "slot-1"},
                {"packet_id": "packet-c", "slot_id": "slot-1"},
            ]
        )


def test_iterative_cycle_validation_handles_the_1024_packet_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    packet_ids = [f"p{index}" for index in range(1024)]
    chain = cohort_base(
        cohort_id="chain-1024",
        packet_refs=[{"packet_id": packet_id, "routing_authority_sha256": SHA_A} for packet_id in packet_ids],
        dependencies={
            packet_id: ([] if index == 0 else [packet_ids[index - 1]])
            for index, packet_id in enumerate(packet_ids)
        },
        waves=[[packet_id] for packet_id in packet_ids],
        max_concurrency=1,
        transport_slots=[{"packet_id": packet_id, "slot_id": f"slot-{index}"} for index, packet_id in enumerate(packet_ids)],
    )
    monkeypatch.setattr(cohorts_module, "MAX_COHORT_BYTES", 1024 * 1024)
    assert seal_cohort(chain)["cohort_id"] == "chain-1024"
    cyclic = copy.deepcopy(chain)
    cyclic["dependencies"][packet_ids[0]] = [packet_ids[-1]]  # type: ignore[index]
    with pytest.raises(CohortError, match="cycle"):
        seal_cohort(cyclic)
    with pytest.raises(CohortError, match="packet_refs is invalid"):
        seal_cohort(cohort_base(packet_refs=[{"packet_id": f"p{index}", "routing_authority_sha256": SHA_A} for index in range(1025)]))


def test_observed_start_is_the_only_running_projection_state() -> None:
    cohort = sealed()
    projection = project_cohort(
        cohort,
        {"packet-a": {"status": "start_observed", "terminal_outcome": None}},
    )
    assert projection["packets"][0]["running"] is True
    assert projection["waves"][0]["status"] == "active"
    with pytest.raises(CohortError, match="running requires start_observed"):
        project_cohort(cohort, {"packet-a": {"status": "running", "terminal_outcome": None}})


def test_terminal_arrival_order_does_not_change_next_wave_projection() -> None:
    cohort = sealed()
    first = project_cohort(
        cohort,
        {
            "packet-a": {"status": "terminal", "terminal_outcome": "accepted"},
            "packet-b": {"status": "terminal", "terminal_outcome": "accepted"},
        },
    )
    second = project_cohort(
        cohort,
        {
            "packet-b": {"status": "terminal", "terminal_outcome": "accepted"},
            "packet-a": {"status": "terminal", "terminal_outcome": "accepted"},
        },
    )
    assert first == second
    assert first["waves"][2]["status"] == "ready"
    assert first["packets"][2]["eligible"] is True


def test_failure_and_cancel_policies_apply_only_to_their_matching_outcome() -> None:
    failed = {"packet-a": {"status": "terminal", "terminal_outcome": "failed"}}
    cancelled = {"packet-a": {"status": "terminal", "terminal_outcome": "cancelled"}}

    assert project_cohort(sealed(failure_policy="cancel_remaining", cancel_policy="continue"), failed)["cancel_requested"] is True
    assert project_cohort(sealed(failure_policy="continue", cancel_policy="cancel_remaining"), failed)["cancel_requested"] is False
    assert project_cohort(sealed(failure_policy="continue", cancel_policy="cancel_remaining"), cancelled)["cancel_requested"] is True
    assert project_cohort(sealed(failure_policy="continue", cancel_policy="cancel_remaining"), {"packet-a": {"status": "cancelled", "terminal_outcome": None}})["cancel_requested"] is True
    assert project_cohort(sealed(failure_policy="cancel_remaining", cancel_policy="continue"), cancelled)["cancel_requested"] is False
    assert project_cohort(sealed(), {"packet-a": {"status": "terminal", "terminal_outcome": "rejected"}})["cancel_requested"] is False


def test_continue_policy_allows_later_independent_work_but_not_failed_dependencies() -> None:
    cohort = sealed(
        failure_policy="continue",
        dependencies={"packet-a": [], "packet-b": ["packet-a"], "packet-c": []},
    )
    before_first_wave_finishes = project_cohort(cohort)
    assert before_first_wave_finishes["packets"][2]["eligible"] is False
    assert before_first_wave_finishes["waves"][2]["status"] == "waiting"

    projection = project_cohort(
        cohort,
        {"packet-a": {"status": "terminal", "terminal_outcome": "failed"}},
    )

    assert projection["cancel_requested"] is False
    assert projection["packets"][1]["eligible"] is False
    assert projection["waves"][1]["status"] == "blocked"
    assert projection["packets"][2]["eligible"] is True
    assert projection["waves"][2]["status"] == "ready"


def test_blocked_dependency_closure_allows_a_later_independent_wave() -> None:
    cohort = sealed(
        failure_policy="continue",
        packet_refs=[
            {"packet_id": "packet-a", "routing_authority_sha256": SHA_A},
            {"packet_id": "packet-b", "routing_authority_sha256": SHA_B},
            {"packet_id": "packet-c", "routing_authority_sha256": SHA_C},
            {"packet_id": "packet-d", "routing_authority_sha256": SHA_A},
        ],
        dependencies={"packet-a": [], "packet-b": ["packet-a"], "packet-c": ["packet-b"], "packet-d": []},
        waves=[["packet-a"], ["packet-b"], ["packet-c"], ["packet-d"]],
        transport_slots=[
            {"packet_id": "packet-a", "slot_id": "slot-1"},
            {"packet_id": "packet-b", "slot_id": "slot-1"},
            {"packet_id": "packet-c", "slot_id": "slot-1"},
            {"packet_id": "packet-d", "slot_id": "slot-1"},
        ],
    )
    projection = project_cohort(
        cohort, {"packet-a": {"status": "terminal", "terminal_outcome": "failed"}}
    )

    assert [wave["status"] for wave in projection["waves"]] == [
        "terminal",
        "blocked",
        "blocked",
        "ready",
    ]
    assert projection["packets"][2]["eligible"] is False
    assert projection["packets"][3]["eligible"] is True


def test_observed_starts_must_honor_dependency_success_and_prior_wave_resolution() -> None:
    cohort = sealed()
    with pytest.raises(CohortError, match="successful dependencies"):
        project_cohort(
            cohort,
            {
                "packet-a": {"status": "start_observed", "terminal_outcome": None},
                "packet-b": {"status": "start_observed", "terminal_outcome": None},
            },
        )
    with pytest.raises(CohortError, match="successful dependencies"):
        project_cohort(cohort, {"packet-c": {"status": "start_observed", "terminal_outcome": None}})

    later_independent = sealed(dependencies={"packet-a": [], "packet-b": [], "packet-c": []})
    with pytest.raises(CohortError, match="prior waves resolved"):
        project_cohort(
            later_independent,
            {"packet-c": {"status": "start_observed", "terminal_outcome": None}},
        )

    projection = project_cohort(
        cohort,
        {
            "packet-a": {"status": "terminal", "terminal_outcome": "accepted"},
            "packet-b": {"status": "start_observed", "terminal_outcome": None},
        },
    )
    assert projection["packets"][1]["running"] is True


def test_observed_start_remains_active_after_later_cancellation_request() -> None:
    projection = project_cohort(
        sealed(
            failure_policy="cancel_remaining",
            dependencies={"packet-a": [], "packet-b": ["packet-a"], "packet-c": []},
            waves=[["packet-a", "packet-c"], ["packet-b"]],
            max_concurrency=2,
            transport_slots=[
                {"packet_id": "packet-a", "slot_id": "slot-1"},
                {"packet_id": "packet-b", "slot_id": "slot-1"},
                {"packet_id": "packet-c", "slot_id": "slot-2"},
            ],
        ),
        {
            "packet-a": {"status": "terminal", "terminal_outcome": "failed"},
            "packet-c": {"status": "start_observed", "terminal_outcome": None},
        },
    )

    assert projection["cancel_requested"] is True
    assert projection["packets"][1]["running"] is True
    assert projection["waves"][0]["status"] == "active"


def test_unknown_status_unknown_packet_and_oversize_inputs_are_rejected() -> None:
    cohort = sealed()
    with pytest.raises(CohortError, match="unknown packet"):
        project_cohort(cohort, {"packet-z": {"status": "planned", "terminal_outcome": None}})
    with pytest.raises(CohortError, match="terminal_outcome"):
        project_cohort(cohort, {"packet-a": {"status": "armed", "terminal_outcome": "accepted"}})
    packet_ids = [f"packet-{index:04d}-" + "x" * 110 for index in range(512)]
    oversized = cohort_base(
        packet_refs=[{"packet_id": packet_id, "routing_authority_sha256": SHA_A} for packet_id in packet_ids],
        dependencies={packet_id: [] for packet_id in packet_ids},
        waves=[packet_ids],
        max_concurrency=512,
        transport_slots=[{"packet_id": packet_id, "slot_id": f"slot-{index}"} for index, packet_id in enumerate(packet_ids)],
    )
    with pytest.raises(CohortError, match="byte bound"):
        seal_cohort(oversized)
