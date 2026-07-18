from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from aoi_orgware.transition_permits import (
    TransitionPermitError,
    permit_consumption_identity,
    permit_replay_marker,
    seal_transition_permit,
    transition_permit_sha256,
    validate_transition_consumption,
    validate_transition_permit,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
NOW = datetime(2026, 7, 18, 4, 0, tzinfo=timezone.utc)


def permit_base(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "task_id": "task-1",
        "expected_semantic_head_sha256": SHA_A,
        "decision_sha256": SHA_B,
        "action": "packet.arm",
        "target_ids": ["packet-1"],
        "parameters": {
            "packet_id": "packet-1",
            "packet_schema_version": 6,
            "routing_authority_sha256": SHA_C,
        },
        "expires_at": "2026-07-18T04:05:00Z",
        "nonce": "A1b2C3d4E5f6G7h8I9j0K_lm",
        "chief_authority": {"session_id": "chief-session-1", "epoch": 7},
    }
    value.update(changes)
    return value


def sealed(**changes: object) -> dict[str, object]:
    return seal_transition_permit(permit_base(**changes))


def consume(permit: dict[str, object], **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "task_id": "task-1",
        "semantic_head_sha256": SHA_A,
        "decision_sha256": SHA_B,
        "action": "packet.arm",
        "target_ids": ["packet-1"],
        "parameters": {
            "packet_id": "packet-1",
            "packet_schema_version": 6,
            "routing_authority_sha256": SHA_C,
        },
        "chief_authority": {"session_id": "chief-session-1", "epoch": 7},
        "current_time": NOW,
    }
    value.update(changes)
    return validate_transition_consumption(permit, **value)  # type: ignore[arg-type]


def test_seal_is_deterministic_and_uses_canonical_hash() -> None:
    first = sealed(parameters={"routing_authority_sha256": SHA_C, "packet_id": "packet-1", "packet_schema_version": 6})
    second = sealed(parameters={"packet_schema_version": 6, "packet_id": "packet-1", "routing_authority_sha256": SHA_C})

    assert first == second
    assert first["permit_sha256"] == transition_permit_sha256(permit_base())
    assert validate_transition_permit(first) == first


def test_sealed_tamper_and_malformed_schema_fail_closed() -> None:
    permit = sealed()
    tampered = copy.deepcopy(permit)
    tampered["action"] = "cohort.advance"
    with pytest.raises(TransitionPermitError, match="parameters schema|permit_sha256"):
        validate_transition_permit(tampered)

    malformed = copy.deepcopy(permit)
    malformed["decision_sha256"] = SHA_B.upper()
    with pytest.raises(TransitionPermitError, match="lowercase SHA-256"):
        validate_transition_permit(malformed)
    malformed = copy.deepcopy(permit)
    malformed["unexpected"] = True
    with pytest.raises(TransitionPermitError, match="schema"):
        validate_transition_permit(malformed)


def test_expiry_head_and_decision_drift_are_rejected() -> None:
    permit = sealed()
    with pytest.raises(TransitionPermitError, match="expired"):
        consume(permit, current_time=datetime(2026, 7, 18, 4, 5, tzinfo=timezone.utc))
    with pytest.raises(TransitionPermitError, match="semantic head"):
        consume(permit, semantic_head_sha256=SHA_C)
    with pytest.raises(TransitionPermitError, match="decision_sha256"):
        consume(permit, decision_sha256=SHA_C)
    with pytest.raises(TransitionPermitError, match="chief_authority"):
        consume(permit, chief_authority={"session_id": "chief-session-1", "epoch": 8})


def test_chief_session_id_uses_the_bounded_canonical_lifecycle_grammar() -> None:
    assert sealed(chief_authority={"session_id": "s" * 128, "epoch": 7})["chief_authority"]["session_id"] == "s" * 128
    for unsafe_session_id in ("C:/credentials/chief.json", "chief/session", "chief:session", "s" * 129):
        with pytest.raises(TransitionPermitError, match="chief_authority.session_id is invalid"):
            sealed(chief_authority={"session_id": unsafe_session_id, "epoch": 7})


def test_targets_and_parameters_must_be_exact_not_widened() -> None:
    permit = sealed()
    with pytest.raises(TransitionPermitError, match="target_ids"):
        consume(permit, target_ids=["packet-1", "task-1", "packet-2"])
    with pytest.raises(TransitionPermitError, match="parameters"):
        consume(
            permit,
            parameters={"packet_id": "packet-1", "packet_schema_version": 6, "routing_authority_sha256": SHA_C, "force": True},
        )


def test_replay_marker_and_consumption_identity_are_distinct_and_one_shot() -> None:
    first = sealed()
    second = sealed(decision_sha256=SHA_C)
    marker = permit_replay_marker(first)
    identity = permit_consumption_identity(first)

    assert marker == permit_replay_marker(second)
    assert identity != permit_consumption_identity(second)
    accepted = consume(first)
    assert accepted["replay_marker"] == marker
    assert accepted["consumption_identity"] == identity
    with pytest.raises(TransitionPermitError, match="identity was already consumed"):
        consume(first, consumed_identities=[identity])
    with pytest.raises(TransitionPermitError, match="replay marker was already consumed"):
        consume(first, consumed_replay_markers=[marker])


@pytest.mark.parametrize(
    "unsafe_parameters",
    (
        {"receipt_path": r"credentials\\chief.json"},
        {"receipt_path": "Bearer reusable-token"},
        {"receipt_path": "github_pat_example"},
        {"receipt_path": "-----BEGIN PRIVATE KEY-----"},
        {"receipt_path": "password=example"},
        {"packet_id": "packet-1", "packet_schema_version": 6, "routing_authority_sha256": SHA_C, "token": "x"},
    ),
)
def test_permit_parameter_schemas_cannot_persist_secret_or_path_material(
    unsafe_parameters: dict[str, object],
) -> None:
    with pytest.raises(TransitionPermitError, match="parameters schema"):
        sealed(parameters=unsafe_parameters)


def test_only_enumerated_action_specific_permit_shapes_are_accepted() -> None:
    with pytest.raises(TransitionPermitError, match="action is invalid"):
        sealed(action="task.transition")
    with pytest.raises(TransitionPermitError, match="target_ids"):
        sealed(target_ids=["packet-1", "packet-2"])
    with pytest.raises(TransitionPermitError, match="target_ids must name"):
        sealed(target_ids=["other"])
    with pytest.raises(TransitionPermitError, match="task_id is invalid"):
        sealed(task_id="tasks/credentials/chief")
    for unsafe_id in ("task:one", "task@one", "C:/tasks/one", "task/one", "t" * 129):
        with pytest.raises(TransitionPermitError, match="task_id is invalid"):
            sealed(task_id=unsafe_id)
        with pytest.raises(TransitionPermitError, match="target_id is invalid"):
            sealed(target_ids=[unsafe_id])
        with pytest.raises(TransitionPermitError, match="parameters.packet_id is invalid"):
            sealed(
                parameters={
                    "packet_id": unsafe_id,
                    "packet_schema_version": 6,
                    "routing_authority_sha256": SHA_C,
                }
            )
    with pytest.raises(TransitionPermitError, match="target_id is invalid"):
        sealed(target_ids=["packet/credentials"])
    with pytest.raises(TransitionPermitError, match="parameters.packet_id is invalid"):
        sealed(parameters={"packet_id": "../credentials", "packet_schema_version": 6, "routing_authority_sha256": SHA_C})
    with pytest.raises(TransitionPermitError, match="packet_schema_version is invalid"):
        sealed(parameters={"packet_id": "packet-1", "packet_schema_version": 7, "routing_authority_sha256": SHA_C})

    cohort = sealed(
        action="cohort.advance",
        target_ids=["cohort-1"],
        parameters={"cohort_id": "cohort-1", "cohort_sha256": SHA_D, "wave_index": 2},
    )
    assert cohort["parameters"]["wave_index"] == 2
    with pytest.raises(TransitionPermitError, match="parameters schema"):
        sealed(action="cohort.advance", target_ids=["cohort-1"], parameters={"cohort_id": "cohort-1", "cohort_sha256": SHA_D, "wave_index": 2, "reason": "text"})
