from __future__ import annotations

import copy

import pytest

import aoi_orgware.cohorts as cohorts_module
from aoi_orgware.cohorts import (
    CohortError,
    cohort_advance_selection_sha256,
    cohort_sha256,
    eligible_cohort_wave_packet_ids,
    execution_selection_identity_sha256,
    project_cohort,
    seal_cohort,
    seal_cohort_advance_selection,
    validate_cohort,
    validate_cohort_advance_selection,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
SELECTION_IDENTITY_SHA = execution_selection_identity_sha256("selection-1")
SELECTION_TARGET_SHA = SHA_F


def slot(packet_id: str, *, parent_session_id: str = "parent-session", expected_agent_type: str = "default") -> dict[str, str]:
    return {
        "packet_id": packet_id,
        "transport": "codex",
        "parent_session_id": parent_session_id,
        "expected_agent_type": expected_agent_type,
    }


def cohort_base(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "cohort_id": "cohort-1",
        "packet_schema_version": 6,
        "resource_envelope_sha256": SHA_A,
        "execution_selection_identity_sha256": SELECTION_IDENTITY_SHA,
        "execution_selection_target_contract_sha256": SELECTION_TARGET_SHA,
        "packet_refs": [
            {"packet_id": "packet-a", "routing_authority_sha256": SHA_A},
            {"packet_id": "packet-b", "routing_authority_sha256": SHA_B},
            {"packet_id": "packet-c", "routing_authority_sha256": SHA_C},
        ],
        "dependencies": {"packet-a": [], "packet-b": ["packet-a"], "packet-c": ["packet-b"]},
        "waves": [["packet-a"], ["packet-b"], ["packet-c"]],
        "max_concurrency": 2,
        "transport_slots": [
            slot("packet-a"),
            slot("packet-b"),
            slot("packet-c"),
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
            slot("packet-a", expected_agent_type="explorer"),
            slot("packet-b", expected_agent_type="worker"),
            slot("packet-c", expected_agent_type="explorer"),
            slot("packet-d", expected_agent_type="explorer"),
        ],
    }
    first = sealed(**common, dependencies={"packet-a": [], "packet-b": [], "packet-c": ["packet-a", "packet-b"], "packet-d": ["packet-c"]})
    second = sealed(**common, dependencies={"packet-d": ["packet-c"], "packet-c": ["packet-b", "packet-a"], "packet-b": [], "packet-a": []})

    assert first == second


def test_transport_slot_mapping_is_canonicalized_by_packet_identity() -> None:
    first = sealed()
    second = sealed(
        transport_slots=[
            slot("packet-c"),
            slot("packet-a"),
            slot("packet-b"),
        ]
    )

    assert first == second
    assert [entry["packet_id"] for entry in second["transport_slots"]] == [
        "packet-a",
        "packet-b",
        "packet-c",
    ]


def test_codex_slots_are_derived_sealed_and_bound_to_external_hashes() -> None:
    cohort = sealed()
    transport_slot = cohort["transport_slots"][0]
    assert transport_slot == {
        **slot("packet-a"),
        "slot_sha256": transport_slot["slot_sha256"],
    }
    assert transport_slot["slot_sha256"] != SHA_A
    assert cohort["resource_envelope_sha256"] == SHA_A
    assert (
        cohort["execution_selection_identity_sha256"]
        == execution_selection_identity_sha256("selection-1")
    )
    assert cohort["execution_selection_target_contract_sha256"] == SELECTION_TARGET_SHA

    tampered_slot = copy.deepcopy(cohort)
    tampered_slot["transport_slots"][0]["slot_sha256"] = SHA_A
    with pytest.raises(CohortError, match="slot_sha256"):
        validate_cohort(tampered_slot)
    with pytest.raises(CohortError, match="transport_slot schema"):
        sealed(transport_slots=[{**slot("packet-a"), "slot_sha256": SHA_A}, slot("packet-b"), slot("packet-c")])
    with pytest.raises(CohortError, match="resource_envelope_sha256"):
        sealed(resource_envelope_sha256="A" * 64)
    with pytest.raises(CohortError, match="execution_selection_identity_sha256"):
        sealed(execution_selection_identity_sha256="short")
    with pytest.raises(CohortError, match="execution_selection_target_contract_sha256"):
        sealed(execution_selection_target_contract_sha256="short")
    with pytest.raises(CohortError, match="execution_selection_id"):
        execution_selection_identity_sha256("")


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
    with pytest.raises(CohortError, match="max_concurrency"):
        sealed(max_concurrency=13)

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
    for parent_session_id in (
        "/root/parent",
        "operator@example.invalid",
        "/" + "p" * 511,
    ):
        plan = sealed(
            transport_slots=[
                slot("packet-a", parent_session_id=parent_session_id),
                slot("packet-b"),
                slot("packet-c"),
            ]
        )
        assert plan["transport_slots"][0]["parent_session_id"] == parent_session_id
    for parent_session_id in (
        "parent identity",
        "parent+identity",
        "parent\ninvalid",
        "父工作階段",
        "p" * 513,
    ):
        with pytest.raises(CohortError, match="transport_slot.parent_session_id is invalid"):
            sealed(
                transport_slots=[
                    slot("packet-a", parent_session_id=parent_session_id),
                    slot("packet-b"),
                    slot("packet-c"),
                ]
            )
    with pytest.raises(CohortError, match="transport_slot.expected_agent_type is invalid"):
        sealed(
            transport_slots=[
                slot("packet-a", expected_agent_type="general-purpose"),
                slot("packet-b"),
                slot("packet-c"),
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
        transport_slots=[slot(packet_id, parent_session_id=f"parent-{index}") for index, packet_id in enumerate(packet_ids)],
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


def test_codex_slot_collision_serializes_prearm_but_not_observed_execution() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="default"),
            slot("packet-b", expected_agent_type="default"),
            slot("packet-c", expected_agent_type="worker"),
        ],
    )
    initial = project_cohort(cohort)
    assert [packet["eligible"] for packet in initial["packets"]] == [True, False, True]

    armed = project_cohort(
        cohort, {"packet-a": {"status": "armed", "terminal_outcome": None}}
    )
    assert armed["packets"][0]["eligible"] is True
    assert armed["packets"][0]["running"] is False
    assert armed["packets"][1]["eligible"] is False
    with pytest.raises(CohortError, match="simultaneously armed packets collide"):
        project_cohort(
            cohort,
            {
                "packet-a": {"status": "armed", "terminal_outcome": None},
                "packet-b": {"status": "armed", "terminal_outcome": None},
            },
        )

    first_started = project_cohort(
        cohort, {"packet-a": {"status": "start_observed", "terminal_outcome": None}}
    )
    assert [packet["eligible"] for packet in first_started["packets"]] == [False, True, True]
    assert first_started["packets"][0]["running"] is True

    next_armed = project_cohort(
        cohort,
        {
            "packet-a": {"status": "start_observed", "terminal_outcome": None},
            "packet-b": {"status": "armed", "terminal_outcome": None},
        },
    )
    assert [packet["eligible"] for packet in next_armed["packets"]] == [False, True, True]

    overlapping_observations = project_cohort(
        cohort,
        {
            "packet-b": {"status": "start_observed", "terminal_outcome": None},
            "packet-a": {"status": "start_observed", "terminal_outcome": None},
        },
    )
    assert [packet["running"] for packet in overlapping_observations["packets"]] == [True, True, False]


def test_wildcard_slot_conflicts_only_within_the_same_parent_session() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="explorer"),
            slot("packet-b", expected_agent_type="*"),
            slot("packet-c", parent_session_id="other-parent", expected_agent_type="*"),
        ],
    )
    projection = project_cohort(cohort)
    assert [packet["eligible"] for packet in projection["packets"]] == [True, False, True]
    with pytest.raises(CohortError, match="simultaneously armed packets collide"):
        project_cohort(
            cohort,
            {
                "packet-a": {"status": "armed", "terminal_outcome": None},
                "packet-b": {"status": "armed", "terminal_outcome": None},
            },
        )


def test_simultaneously_armed_noncolliding_slots_are_accepted() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="default"),
            slot("packet-b", parent_session_id="other-parent", expected_agent_type="default"),
            slot("packet-c", expected_agent_type="worker"),
        ],
    )

    projection = project_cohort(
        cohort,
        {
            "packet-a": {"status": "armed", "terminal_outcome": None},
            "packet-b": {"status": "armed", "terminal_outcome": None},
        },
    )
    assert [packet["eligible"] for packet in projection["packets"]] == [True, True, True]


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


def test_packet_state_mapping_order_does_not_change_slot_projection() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
    )
    first = project_cohort(
        cohort,
        {
            "packet-a": {"status": "start_observed", "terminal_outcome": None},
            "packet-b": {"status": "planned", "terminal_outcome": None},
        },
    )
    second = project_cohort(
        cohort,
        {
            "packet-b": {"status": "planned", "terminal_outcome": None},
            "packet-a": {"status": "start_observed", "terminal_outcome": None},
        },
    )
    assert first == second


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
            slot("packet-a"),
            slot("packet-b"),
            slot("packet-c"),
            slot("packet-d"),
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
                slot("packet-a"),
                slot("packet-b"),
                slot("packet-c", expected_agent_type="worker"),
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


def test_exact_advance_selection_is_sealed_in_wave_order() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="default"),
            slot("packet-b", expected_agent_type="default"),
            slot("packet-c", expected_agent_type="worker"),
        ],
    )
    base = {
        "schema_version": 1,
        "cohort_sha256": cohort["cohort_sha256"],
        "wave_index": 0,
        "routes": [
            {
                "packet_id": "packet-a",
                "routing_authority_sha256": SHA_A,
                "outcome_slot_sha256": SHA_D,
            },
            {
                "packet_id": "packet-c",
                "routing_authority_sha256": SHA_C,
                "outcome_slot_sha256": SHA_F,
            },
        ],
    }

    selection = seal_cohort_advance_selection(cohort, base, None)

    assert selection["selection_sha256"] == cohort_advance_selection_sha256(
        cohort, base, None
    )
    assert validate_cohort_advance_selection(cohort, selection, None) == selection


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(routes=[]), "routes"),
        (
            lambda value: value.update(routes=list(reversed(value["routes"]))),
            "wave order",
        ),
        (
            lambda value: value["routes"][0].update(
                routing_authority_sha256=SHA_B
            ),
            "sealed packet authority",
        ),
        (
            lambda value: value["routes"][1].update(outcome_slot_sha256=SHA_D),
            "duplicate outcome slot",
        ),
        (
            lambda value: value["routes"][1].update(packet_id="packet-b"),
            "sealed packet authority",
        ),
        (lambda value: value.update(wave_index=True), "wave_index"),
        (lambda value: value.update(extra="widened"), "schema"),
    ],
)
def test_advance_selection_rejects_widening_reordering_and_route_substitution(
    mutate, message: str
) -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="default"),
            slot("packet-b", expected_agent_type="default"),
            slot("packet-c", expected_agent_type="worker"),
        ],
    )
    base = {
        "schema_version": 1,
        "cohort_sha256": cohort["cohort_sha256"],
        "wave_index": 0,
        "routes": [
            {
                "packet_id": "packet-a",
                "routing_authority_sha256": SHA_A,
                "outcome_slot_sha256": SHA_D,
            },
            {
                "packet_id": "packet-c",
                "routing_authority_sha256": SHA_C,
                "outcome_slot_sha256": SHA_F,
            },
        ],
    }
    mutate(base)

    with pytest.raises(CohortError, match=message):
        seal_cohort_advance_selection(cohort, base, None)


def test_advance_selection_rejects_packet_from_another_wave_and_hash_tamper() -> None:
    cohort = sealed()
    base = {
        "schema_version": 1,
        "cohort_sha256": cohort["cohort_sha256"],
        "wave_index": 0,
        "routes": [
            {
                "packet_id": "packet-b",
                "routing_authority_sha256": SHA_B,
                "outcome_slot_sha256": SHA_E,
            }
        ],
    }
    with pytest.raises(CohortError, match="outside its wave"):
        seal_cohort_advance_selection(cohort, base, None)

    valid = seal_cohort_advance_selection(
        cohort,
        {
            **base,
            "routes": [
                {
                    "packet_id": "packet-a",
                    "routing_authority_sha256": SHA_A,
                    "outcome_slot_sha256": SHA_D,
                }
            ],
        },
        None,
    )
    valid["selection_sha256"] = SHA_F
    with pytest.raises(CohortError, match="does not match"):
        validate_cohort_advance_selection(cohort, valid, None)


def test_manual_round_selection_uses_only_planned_eligible_packets() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="default"),
            slot("packet-b", expected_agent_type="default"),
            slot("packet-c", expected_agent_type="worker"),
        ],
    )

    assert eligible_cohort_wave_packet_ids(
        cohort, None, wave_index=0
    ) == ["packet-a", "packet-c"]
    assert eligible_cohort_wave_packet_ids(
        cohort,
        {"packet-a": {"status": "armed", "terminal_outcome": None}},
        wave_index=0,
    ) == ["packet-c"]
    assert eligible_cohort_wave_packet_ids(
        cohort,
        {"packet-a": {"status": "start_observed", "terminal_outcome": None}},
        wave_index=0,
    ) == ["packet-b", "packet-c"]
    assert eligible_cohort_wave_packet_ids(
        cohort,
        {"packet-b": {"status": "armed", "terminal_outcome": None}},
        wave_index=0,
    ) == ["packet-c"]


def test_selection_seal_rejects_ineligible_or_colliding_packet_set() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []},
        waves=[["packet-a", "packet-b", "packet-c"]],
        max_concurrency=3,
        transport_slots=[
            slot("packet-a", expected_agent_type="default"),
            slot("packet-b", expected_agent_type="default"),
            slot("packet-c", expected_agent_type="worker"),
        ],
    )

    def selection(packet_ids: list[str]) -> dict[str, object]:
        route_by_packet = {
            "packet-a": (SHA_A, SHA_D),
            "packet-b": (SHA_B, SHA_E),
            "packet-c": (SHA_C, SHA_F),
        }
        return {
            "schema_version": 1,
            "cohort_sha256": cohort["cohort_sha256"],
            "wave_index": 0,
            "routes": [
                {
                    "packet_id": packet_id,
                    "routing_authority_sha256": route_by_packet[packet_id][0],
                    "outcome_slot_sha256": route_by_packet[packet_id][1],
                }
                for packet_id in packet_ids
            ],
        }

    for packet_ids in (["packet-b"], ["packet-a", "packet-b"]):
        with pytest.raises(CohortError, match="exact eligible"):
            seal_cohort_advance_selection(cohort, selection(packet_ids), None)

    limited = seal_cohort_advance_selection(
        cohort, selection(["packet-a"]), None, available_capacity=1
    )
    assert [route["packet_id"] for route in limited["routes"]] == ["packet-a"]


def test_manual_round_selection_does_not_skip_unresolved_prior_wave() -> None:
    cohort = sealed(
        dependencies={"packet-a": [], "packet-b": [], "packet-c": []}
    )

    assert eligible_cohort_wave_packet_ids(cohort, None, wave_index=1) == []


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
        waves=[packet_ids[index : index + 12] for index in range(0, len(packet_ids), 12)],
        max_concurrency=12,
        transport_slots=[slot(packet_id, parent_session_id=f"parent-{index}") for index, packet_id in enumerate(packet_ids)],
    )
    with pytest.raises(CohortError, match="byte bound"):
        seal_cohort(oversized)
