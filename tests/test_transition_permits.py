from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from aoi_orgware.transition_permits import (
    DECISION_SCHEMA_VERSION,
    TransitionPermitError,
    permit_consumption_identity,
    permit_replay_marker,
    seal_transition_decision,
    seal_transition_permit,
    transition_decision_sha256,
    validate_decision_permit_pair,
    validate_transition_decision,
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


def decision_base(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "task_id": "task-1",
        "action": "packet.arm",
        "target_ids": ["packet-1"],
        "parameters": {
            "packet_id": "packet-1",
            "packet_schema_version": 6,
            "routing_authority_sha256": SHA_C,
        },
        "technical_payload_sha256": SHA_D,
    }
    value.update(changes)
    return value


def sealed_decision(**changes: object) -> dict[str, object]:
    return seal_transition_decision(decision_base(**changes))


def launch_parameters(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "launch_id": "launch-1",
        "launch_intent_sha256": SHA_D,
        "packet_id": "packet-1",
        "routing_binding": {
            "kind": "cohort",
            "routing_authority_sha256": SHA_C,
            "transport": "codex",
            "parent_session_id": "chief-session-1",
            "expected_agent_type": "worker",
            "cohort_id": "cohort-1",
            "cohort_sha256": SHA_A,
            "wave_index": 0,
            "transport_slot_sha256": SHA_B,
        },
    }
    value.update(changes)
    return value


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


def consume_launch(permit: dict[str, object], decision_sha256: str, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "task_id": "task-1",
        "semantic_head_sha256": SHA_A,
        "decision_sha256": decision_sha256,
        "action": "codex.launch",
        "target_ids": ["launch-1"],
        "parameters": launch_parameters(),
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


def test_decision_seal_is_deterministic_and_uses_canonical_hash() -> None:
    first = sealed_decision(
        parameters={
            "routing_authority_sha256": SHA_C,
            "packet_id": "packet-1",
            "packet_schema_version": 6,
        }
    )
    second = sealed_decision(
        parameters={
            "packet_schema_version": 6,
            "packet_id": "packet-1",
            "routing_authority_sha256": SHA_C,
        }
    )

    assert first == second
    assert first["decision_sha256"] == transition_decision_sha256(decision_base())
    assert validate_transition_decision(first) == first


@pytest.mark.parametrize(
    ("builder", "validate", "field", "value"),
    (
        (
            sealed_decision,
            validate_transition_decision,
            "schema_version",
            1.0,
        ),
        (
            sealed,
            validate_transition_permit,
            "schema_version",
            1.0,
        ),
        (
            sealed_decision,
            validate_transition_decision,
            "parameters",
            {"packet_id": "packet-1", "packet_schema_version": 6.0, "routing_authority_sha256": SHA_C},
        ),
        (
            sealed,
            validate_transition_permit,
            "parameters",
            {"packet_id": "packet-1", "packet_schema_version": 6.0, "routing_authority_sha256": SHA_C},
        ),
    ),
)
def test_numeric_fields_reject_equal_floating_point_values_at_seal_and_validate(
    builder: object,
    validate: object,
    field: str,
    value: object,
) -> None:
    with pytest.raises(TransitionPermitError, match="schema_version|packet_schema_version"):
        builder(**{field: value})  # type: ignore[operator]

    malformed = builder()  # type: ignore[operator]
    malformed[field] = value  # type: ignore[index]
    with pytest.raises(TransitionPermitError, match="schema_version|packet_schema_version"):
        validate(malformed)  # type: ignore[operator]


def test_decision_tamper_and_schema_widening_fail_closed() -> None:
    decision = sealed_decision()
    tampered = copy.deepcopy(decision)
    tampered["technical_payload_sha256"] = SHA_A
    with pytest.raises(TransitionPermitError, match="decision_sha256"):
        validate_transition_decision(tampered)

    for widened in (
        {**decision_base(), "technical_payload": "Bearer reusable-token"},
        {**decision_base(), "receipt_path": r"credentials\\chief.json"},
        {**decision_base(), "technical_payload_sha256": "-----BEGIN PRIVATE KEY-----"},
    ):
        with pytest.raises(TransitionPermitError, match="schema|lowercase SHA-256"):
            seal_transition_decision(widened)


def test_decision_permit_pair_requires_exact_same_decision_boundary() -> None:
    decision = sealed_decision()
    permit = sealed(decision_sha256=decision["decision_sha256"])
    paired = validate_decision_permit_pair(decision, permit)
    assert paired == {"decision": decision, "permit": permit}

    cohort_decision = sealed_decision(
        action="cohort.advance",
        target_ids=["cohort-1"],
        parameters={
            "cohort_id": "cohort-1",
            "cohort_sha256": SHA_D,
            "wave_index": 2,
        },
    )
    cohort_permit = sealed(
        decision_sha256=cohort_decision["decision_sha256"],
        action="cohort.advance",
        target_ids=["cohort-1"],
        parameters={
            "cohort_id": "cohort-1",
            "cohort_sha256": SHA_D,
            "wave_index": 2,
        },
    )
    assert validate_decision_permit_pair(cohort_decision, cohort_permit) == {
        "decision": cohort_decision,
        "permit": cohort_permit,
    }

    with pytest.raises(TransitionPermitError, match="permit action"):
        validate_decision_permit_pair(
            decision,
            sealed(
                decision_sha256=decision["decision_sha256"],
                action="cohort.advance",
                target_ids=["cohort-1"],
                parameters={
                    "cohort_id": "cohort-1",
                    "cohort_sha256": SHA_D,
                    "wave_index": 2,
                },
            ),
        )
    with pytest.raises(TransitionPermitError, match="permit decision_sha256"):
        validate_decision_permit_pair(decision, sealed())


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
    authority = sealed(chief_authority={"session_id": "s" * 128, "epoch": 7})[
        "chief_authority"
    ]
    assert isinstance(authority, dict)
    assert authority["session_id"] == "s" * 128
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


def test_codex_launch_permit_is_exact_one_shot_and_binds_launch_intent() -> None:
    parameters = launch_parameters()
    decision = sealed_decision(
        action="codex.launch",
        target_ids=["launch-1"],
        parameters=parameters,
        technical_payload_sha256=SHA_D,
    )
    permit = sealed(
        decision_sha256=decision["decision_sha256"],
        action="codex.launch",
        target_ids=["launch-1"],
        parameters=parameters,
    )
    decision_sha256 = decision["decision_sha256"]
    assert isinstance(decision_sha256, str)

    assert validate_decision_permit_pair(decision, permit) == {
        "decision": decision,
        "permit": permit,
    }
    accepted = consume_launch(permit, decision_sha256)
    consumption_identity = accepted["consumption_identity"]
    assert isinstance(consumption_identity, str)
    with pytest.raises(TransitionPermitError, match="identity was already consumed"):
        consume_launch(
            permit,
            decision_sha256,
            consumed_identities=[consumption_identity],
        )
    with pytest.raises(TransitionPermitError, match="permit is expired"):
        consume_launch(
            permit,
            decision_sha256,
            current_time=datetime(2026, 7, 18, 4, 5, tzinfo=timezone.utc),
        )
    with pytest.raises(TransitionPermitError, match="semantic head"):
        consume_launch(permit, decision_sha256, semantic_head_sha256=SHA_C)

    with pytest.raises(TransitionPermitError, match="technical_payload_sha256 must match"):
        sealed_decision(
            action="codex.launch",
            target_ids=["launch-1"],
            parameters=parameters,
            technical_payload_sha256=SHA_A,
        )
    with pytest.raises(TransitionPermitError, match="target_ids must name"):
        sealed(
            decision_sha256=decision_sha256,
            action="codex.launch",
            target_ids=["packet-1"],
            parameters=parameters,
        )
    for extra_field in ("prompt", "cwd", "credential", "receipt_path"):
        with pytest.raises(TransitionPermitError, match="parameters schema"):
            sealed(
                decision_sha256=decision_sha256,
                action="codex.launch",
                target_ids=["launch-1"],
                parameters={**parameters, extra_field: "unsafe-extra"},
            )

    standalone = launch_parameters(
        routing_binding={
            "kind": "standalone",
            "routing_authority_sha256": SHA_C,
            "transport": "codex",
            "parent_session_id": "chief-session-1",
            "expected_agent_type": "worker",
        }
    )
    standalone_decision = sealed_decision(
        action="codex.launch",
        target_ids=["launch-1"],
        parameters=standalone,
        technical_payload_sha256=SHA_D,
    )
    assert standalone_decision["parameters"] == standalone


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
    cohort_parameters = cohort["parameters"]
    assert isinstance(cohort_parameters, dict)
    assert cohort_parameters["wave_index"] == 2
    with pytest.raises(TransitionPermitError, match="parameters schema"):
        sealed(action="cohort.advance", target_ids=["cohort-1"], parameters={"cohort_id": "cohort-1", "cohort_sha256": SHA_D, "wave_index": 2, "reason": "text"})
