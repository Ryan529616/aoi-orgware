from __future__ import annotations

import copy

import pytest

from aoi_orgware.routing_authority import (
    build_dispatch_outcome,
    build_legacy_outcome,
    build_unattempted_v6_cancellation_outcome,
)
from aoi_orgware.routing_bundle import (
    RoutingBundleError,
    build_routing_bundle,
    build_v6_record,
    finalize_v6_record,
    routing_capacity_view,
    validate_routing_bundle,
    validate_v6_record,
)
from tests.test_routing_authority import observation, root_arm


def routed(arm: dict, *, agent_id: str = "agent-1") -> dict:
    return build_dispatch_outcome(
        arm,
        dispatch_provenance="codex_subagent_start_observed",
        observation=observation(agent_id=agent_id),
        recorded_at="2026-01-01T00:02:00Z",
    )


def test_v6_record_is_detached_and_finalization_is_pure_one_shot() -> None:
    arm = root_arm()
    outcome = routed(arm)
    record = build_v6_record(arm, outcome)
    before = copy.deepcopy(record)
    arm["attempt_identity"]["arm_id"] = "caller-mutated"
    outcome["verdict"] = "caller-mutated"
    assert record == before
    final = finalize_v6_record(
        record, terminal_status="done", typed_outcome="accepted"
    )
    assert record == before
    assert final["terminal_status"] == "done"
    assert finalize_v6_record(
        final, terminal_status="done", typed_outcome="accepted"
    ) == final
    with pytest.raises(RoutingBundleError, match="finalized differently"):
        finalize_v6_record(
            final, terminal_status="failed", typed_outcome="procedural_failure"
        )


def test_pure_validation_failures_do_not_mutate_inputs() -> None:
    arm = root_arm()
    outcome = routed(arm)
    record = build_v6_record(arm, outcome)
    forged = copy.deepcopy(record)
    forged["outcome"]["verdict"] = "forged"
    before = copy.deepcopy(forged)
    with pytest.raises(RoutingBundleError):
        validate_v6_record(forged)
    assert forged == before

    malformed_records = [{"kind": "unknown"}]
    before_records = copy.deepcopy(malformed_records)
    with pytest.raises(RoutingBundleError):
        build_routing_bundle(malformed_records)
    assert malformed_records == before_records


def test_bundle_rejects_duplicate_packets_and_observations_including_unfinished() -> None:
    arm_a = root_arm("packet-a")
    arm_b = root_arm("packet-b")
    outcome_a = routed(arm_a, agent_id="same-agent")
    outcome_b = routed(arm_b, agent_id="same-agent")
    with pytest.raises(RoutingBundleError, match="duplicate dispatch observation"):
        build_routing_bundle([build_v6_record(arm_a, outcome_a), build_v6_record(arm_b, outcome_b)])

    legacy = build_legacy_outcome(
        {"packet_schema_version": 5, "packet_id": "packet-a", "status": "done"},
        recorded_at="2026-01-01T00:02:00Z",
    )
    with pytest.raises(RoutingBundleError, match="duplicate packet_id"):
        build_routing_bundle(
            [build_v6_record(arm_a, outcome_a), {"kind": "legacy", "legacy_outcome": legacy}]
        )


def test_capacity_excludes_unfinished_v6_but_keeps_terminal_history() -> None:
    arm = root_arm("active")
    active = build_v6_record(arm, routed(arm))
    legacy = build_legacy_outcome(
        {"packet_schema_version": 0, "packet_id": "old", "status": "failed"},
        recorded_at="2026-01-01T00:02:00Z",
    )
    unattempted = build_unattempted_v6_cancellation_outcome(
        {
            "packet_schema_version": 6,
            "packet_id": "cancelled",
            "status": "cancelled",
            "dispatch_provenance": "none",
            "dispatch_attempts": [{"status": "expired", "observation": None}],
        },
        recorded_at="2026-01-01T00:02:00Z",
    )
    bundle = build_routing_bundle(
        [
            active,
            {"kind": "legacy", "legacy_outcome": legacy},
            {"kind": "unattempted_v6", "unattempted_v6_outcome": unattempted},
        ]
    )
    assert {row["packet_id"] for row in routing_capacity_view(bundle)["rows"]} == {
        "old",
        "cancelled",
    }
    finished = finalize_v6_record(
        active, terminal_status="done", typed_outcome="accepted"
    )
    completed_bundle = build_routing_bundle(
        [
            finished,
            {"kind": "legacy", "legacy_outcome": legacy},
            {"kind": "unattempted_v6", "unattempted_v6_outcome": unattempted},
        ]
    )
    assert {row["packet_id"] for row in routing_capacity_view(completed_bundle)["rows"]} == {
        "active",
        "old",
        "cancelled",
    }


def test_bundle_exact_schema_count_and_byte_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RoutingBundleError, match="schema"):
        validate_routing_bundle({"schema_version": 1, "records": [], "extra": True})

    import aoi_orgware.routing_bundle as bundle_impl

    monkeypatch.setattr(bundle_impl, "MAX_ROUTING_BUNDLE_RECORDS", 1)
    with pytest.raises(RoutingBundleError, match="collection"):
        build_routing_bundle(
            [
                {
                    "kind": "legacy",
                    "legacy_outcome": build_legacy_outcome(
                        {"packet_schema_version": 5, "packet_id": "one", "status": "done"},
                        recorded_at="2026-01-01T00:02:00Z",
                    ),
                },
                {
                    "kind": "legacy",
                    "legacy_outcome": build_legacy_outcome(
                        {"packet_schema_version": 5, "packet_id": "two", "status": "done"},
                        recorded_at="2026-01-01T00:02:00Z",
                    ),
                },
            ]
        )

    monkeypatch.setattr(bundle_impl, "MAX_ROUTING_BUNDLE_BYTES", 32)
    with pytest.raises(RoutingBundleError, match="bounded JSON"):
        validate_routing_bundle({"schema_version": 1, "records": []})
