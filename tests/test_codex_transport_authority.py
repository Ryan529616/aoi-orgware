from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
import sys
from typing import Any

import pytest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import codex_transport_authority as authority
from aoi_orgware import codex_transport_contracts as contracts
from aoi_orgware import routing_authority
from aoi_orgware import routing_persistence
from aoi_orgware import semantic_events as semantic
from tests.test_routing_authority import root_arm


HEAD = "d" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
NOW = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)


def _pin() -> dict[str, object]:
    return {
        **contracts.pinned_runtime_binding(),
        "executable_path": "C:/AOI/codex-app-server.exe",
    }


def _attempt(arm: dict[str, Any]) -> dict[str, Any]:
    return {
        **arm["attempt_identity"],
        "arm_authority_sha256": routing_authority.authority_sha256(arm),
        "status": "armed",
        "chief_session_id": arm["chief_authority"]["session_id"],
        "chief_epoch": arm["chief_authority"]["epoch"],
        "authority_sha256": arm["chief_authority"]["authority_sha256"],
        "parent_session_id": arm["parent_authority"]["session_id"],
        "expected_agent_type": arm["transport_authority"]["expected_agent_type"],
    }


def _state(arm: dict[str, Any], *, status: str = "armed") -> dict[str, Any]:
    packet_authority = arm["packet_authority"]
    return {
        "task_id": "task-1",
        "plan_sha256": packet_authority["task_plan_sha256"],
        semantic.SEMANTIC_ENVELOPE_KEY: {"head_event_sha256": HEAD},
        "packets": [
            {
                "packet_id": packet_authority["packet_id"],
                "packet_contract_sha256": packet_authority[
                    "packet_contract_sha256"
                ],
                "delegation_depth": packet_authority["delegation_depth"],
                "parent_packet_id": packet_authority["parent_packet_id"],
                "agent_role": packet_authority["agent_role"],
                "status": status,
                "dispatch_attempts": [_attempt(arm)],
            }
        ],
    }


def _standalone_binding(arm: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "standalone",
        "routing_authority_sha256": routing_authority.authority_sha256(arm),
        "transport": "codex",
        "parent_session_id": arm["parent_authority"]["session_id"],
        "expected_agent_type": arm["transport_authority"]["expected_agent_type"],
    }


def _cohort_binding(arm: dict[str, Any]) -> dict[str, Any]:
    return {
        **_standalone_binding(arm),
        "kind": "cohort",
        "cohort_id": "cohort-1",
        "cohort_sha256": SHA_C,
        "wave_index": 0,
        "transport_slot_sha256": SHA_B,
    }


def _intent(binding: dict[str, Any]) -> dict[str, Any]:
    return contracts.seal_launch_intent(
        {
            "contract_type": contracts.CODEX_TRANSPORT_LAUNCH_INTENT_V1,
            "task_id": "task-1",
            "packet_id": "packet-1",
            "routing_binding": binding,
            "expected_semantic_head_sha256": HEAD,
            "prompt_sha256": SHA_B,
            "prompt_size_bytes": 1,
            "cwd": "C:/scratch/aoi",
            "requested_model": "gpt-5.6",
            "requested_effort": "high",
            "sandbox": "readOnly",
            "approval": "never",
            "runtime_pin": _pin(),
            "pre_git_binding": {
                "git_head_sha256": SHA_B,
                "git_tree_sha256": SHA_B,
                "git_status_sha256": SHA_B,
                "claim_coverage_sha256": SHA_B,
            },
        }
    )


def _group(
    arm: dict[str, Any], *, cohort: bool = False
) -> dict[str, Any]:
    group: dict[str, Any] = {
        "stage": "authority",
        "classification": "committed",
        "composite": True,
        "authority": arm,
        "objects": {
            "routing_authority": {
                "object_identity": routing_authority.authority_sha256(arm)
            }
        },
    }
    if cohort:
        group.update(
            {
                "composite_kind": "cohort",
                "cohort_plan": {
                    "cohort_id": "cohort-1",
                    "cohort_sha256": SHA_C,
                    "waves": [["packet-1"]],
                    "transport_slots": [
                        {"packet_id": "packet-1", "slot_sha256": SHA_B}
                    ],
                },
                "decision": {"parameters": {"wave_index": 0}},
            }
        )
    return group


def _install(
    monkeypatch: pytest.MonkeyPatch,
    state: dict[str, Any],
    groups: list[dict[str, Any]],
    *,
    integrity_errors: list[str] | None = None,
) -> None:
    monkeypatch.setattr(authority.h, "_require_chief_lock", lambda _paths: None)
    monkeypatch.setattr(authority.h, "load_task", lambda _paths, _task: state)
    monkeypatch.setattr(
        authority.packet_integrity,
        "packet_authority_integrity_errors",
        lambda *args, **kwargs: list(integrity_errors or []),
    )
    monkeypatch.setattr(
        authority.routing_persistence,
        "inspect_routing_persistence",
        lambda *args, **kwargs: {"groups": groups},
    )


def _require(intent: dict[str, Any], *, now: datetime = NOW) -> dict[str, Any]:
    return authority.require_canonical_launch_authority(
        object(),  # type: ignore[arg-type]
        task_id="task-1",
        intent=intent,
        event_chain=[{"event_sha256": HEAD}],
        current_time=now,
        packet_integrity_services=object(),  # type: ignore[arg-type]
    )


def test_standalone_launch_requires_unique_live_canonical_arm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arm = root_arm(packet_id="packet-1", expected_agent_type="worker")
    _install(monkeypatch, _state(arm), [_group(arm)])
    result = _require(_intent(_standalone_binding(arm)))
    assert result["contract_type"] == contracts.CODEX_LAUNCH_AUTHORITY_V1
    assert result["arm_id"] == "arm-packet-1"
    assert result["dispatch_attempt_authority_sha256"] == (
        routing_authority.authority_sha256(arm)
    )


@pytest.mark.parametrize("status", ("ready", "dispatched", "done"))
def test_non_armed_packet_states_fail_closed(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    arm = root_arm(packet_id="packet-1", expected_agent_type="worker")
    _install(monkeypatch, _state(arm, status=status), [_group(arm)])
    with pytest.raises(authority.CodexTransportAuthorityError, match="armed state"):
        _require(_intent(_standalone_binding(arm)))


def test_missing_packet_integrity_and_expiry_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arm = root_arm(packet_id="packet-1", expected_agent_type="worker")
    state = _state(arm)
    state["packets"] = []
    _install(monkeypatch, state, [_group(arm)])
    with pytest.raises(authority.CodexTransportAuthorityError, match="exactly one packet"):
        _require(_intent(_standalone_binding(arm)))

    _install(monkeypatch, _state(arm), [_group(arm)], integrity_errors=["bad claim"])
    with pytest.raises(authority.CodexTransportAuthorityError, match="bad claim"):
        _require(_intent(_standalone_binding(arm)))

    _install(monkeypatch, _state(arm), [_group(arm)])
    with pytest.raises(authority.CodexTransportAuthorityError, match="not live"):
        _require(
            _intent(_standalone_binding(arm)),
            now=datetime(2026, 1, 1, 0, 11, tzinfo=UTC),
        )


def test_head_route_and_attempt_substitution_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arm = root_arm(packet_id="packet-1", expected_agent_type="worker")
    state = _state(arm)
    state[semantic.SEMANTIC_ENVELOPE_KEY]["head_event_sha256"] = SHA_B
    _install(monkeypatch, state, [_group(arm)])
    with pytest.raises(authority.CodexTransportAuthorityError, match="semantic head"):
        _require(_intent(_standalone_binding(arm)))

    changed_state = _state(arm)
    changed_state["packets"][0]["dispatch_attempts"][0]["arm_id"] = "other-arm"
    _install(monkeypatch, changed_state, [_group(arm)])
    with pytest.raises(authority.CodexTransportAuthorityError, match="attempt tuple"):
        _require(_intent(_standalone_binding(arm)))

    _install(monkeypatch, _state(arm), [_group(arm), copy.deepcopy(_group(arm))])
    with pytest.raises(authority.CodexTransportAuthorityError, match="unique committed"):
        _require(_intent(_standalone_binding(arm)))


def test_cohort_wave_zero_and_exact_plan_slot_are_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arm = root_arm(packet_id="packet-1", expected_agent_type="worker")
    group = _group(arm, cohort=True)
    _install(monkeypatch, _state(arm), [group])
    result = _require(_intent(_cohort_binding(arm)))
    assert result["routing_binding"]["wave_index"] == 0

    for field, value in (
        ("cohort_sha256", "e" * 64),
        ("transport_slot_sha256", "f" * 64),
        ("parent_session_id", "other-parent"),
    ):
        changed = _cohort_binding(arm)
        changed[field] = value
        with pytest.raises(
            authority.CodexTransportAuthorityError, match="canonical routing authority"
        ):
            _require(_intent(changed))


def test_standalone_cohort_confusion_and_exact_head_conflict_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arm = root_arm(packet_id="packet-1", expected_agent_type="worker")
    _install(monkeypatch, _state(arm), [_group(arm, cohort=True)])
    with pytest.raises(
        authority.CodexTransportAuthorityError, match="canonical routing authority"
    ):
        _require(_intent(_standalone_binding(arm)))

    def conflict(*args: object, **kwargs: object) -> dict[str, Any]:
        raise routing_persistence.RoutingPersistenceError(
            "cohort transport slot conflicts at exact head"
        )

    monkeypatch.setattr(
        authority.routing_persistence, "inspect_routing_persistence", conflict
    )
    with pytest.raises(authority.CodexTransportAuthorityError, match="conflicts"):
        _require(_intent(_cohort_binding(arm)))
