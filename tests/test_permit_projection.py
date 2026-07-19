"""Pure packet/cohort permit projection compatibility tests."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest import mock

import pytest


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "src"))

from aoi_orgware import permit_projection as projection  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402


def contract(action: str) -> tuple[dict, dict]:
    if action == "packet.arm":
        target_ids = ["packet-1"]
        parameters = {
            "packet_id": "packet-1",
            "packet_schema_version": 6,
            "routing_authority_sha256": "a" * 64,
        }
        technical = "a" * 64
    else:
        target_ids = ["cohort-1"]
        parameters = {
            "cohort_id": "cohort-1",
            "cohort_sha256": "b" * 64,
            "wave_index": 2,
        }
        technical = "c" * 64
    decision = permits.seal_transition_decision(
        {
            "schema_version": 1,
            "task_id": "task-1",
            "action": action,
            "target_ids": target_ids,
            "parameters": parameters,
            "technical_payload_sha256": technical,
        }
    )
    permit = permits.seal_transition_permit(
        {
            "schema_version": 1,
            "task_id": "task-1",
            "expected_semantic_head_sha256": "d" * 64,
            "decision_sha256": decision["decision_sha256"],
            "action": action,
            "target_ids": target_ids,
            "parameters": parameters,
            "expires_at": "2027-01-01T00:00:00Z",
            "nonce": f"projection-{action.replace('.', '-')}-nonce",
            "chief_authority": {"session_id": "chief-1", "epoch": 1},
        }
    )
    return decision, permit


def test_packet_receipt_keeps_the_v1_exact_shape() -> None:
    decision, permit = contract("packet.arm")
    identity, receipt = projection.packet_consumption_receipt(
        decision, permit, "e" * 64
    )
    assert receipt == {
        "schema_version": 1,
        "permit_sha256": permit["permit_sha256"],
        "decision_sha256": decision["decision_sha256"],
        "replay_marker": permits.permit_replay_marker(permit),
        "action": "packet.arm",
        "target_ids": ["packet-1"],
        "routing_slots": ["e" * 64],
        "cohort_state": None,
    }
    assert identity == permits.permit_consumption_identity(permit)


def test_cohort_receipt_canonicalizes_slots_and_binds_exact_selection() -> None:
    decision, permit = contract("cohort.advance")
    identity, receipt = projection.cohort_consumption_receipt(
        decision,
        permit,
        cohort_sha256="b" * 64,
        wave_index=2,
        selection_sha256="c" * 64,
        routing_slots=["f" * 64, "e" * 64],
    )
    assert receipt["routing_slots"] == ["e" * 64, "f" * 64]
    assert receipt["cohort_state"] == {
        "schema_version": 1,
        "cohort_sha256": "b" * 64,
        "wave_index": 2,
        "selection_sha256": "c" * 64,
    }
    advanced = projection.advance_permit_projection({}, identity, receipt)
    assert advanced[projection.PERMIT_NAMESPACE_KEY]["consumptions"][identity] == receipt
    with pytest.raises(projection.PermitProjectionError, match="already committed"):
        projection.advance_permit_projection(advanced, identity, receipt)


def test_cohort_receipt_rejects_duplicate_or_noncanonical_rows() -> None:
    decision, permit = contract("cohort.advance")
    with pytest.raises(projection.PermitProjectionError, match="shape"):
        projection.cohort_consumption_receipt(
            decision,
            permit,
            cohort_sha256="b" * 64,
            wave_index=2,
            selection_sha256="c" * 64,
            routing_slots=["e" * 64, "e" * 64],
        )
    _identity, receipt = projection.cohort_consumption_receipt(
        decision,
        permit,
        cohort_sha256="b" * 64,
        wave_index=2,
        selection_sha256="c" * 64,
        routing_slots=["e" * 64],
    )
    tampered = copy.deepcopy(receipt)
    tampered["cohort_state"]["selection_sha256"] = "d" * 64
    assert projection.validate_permit_consumption(tampered) == tampered
    widened = copy.deepcopy(receipt)
    widened["cohort_state"]["extra"] = True
    with pytest.raises(projection.PermitProjectionError, match="state schema"):
        projection.validate_permit_consumption(widened)


def test_namespace_count_and_byte_bounds_fail_closed() -> None:
    decision, permit = contract("cohort.advance")
    identity, receipt = projection.cohort_consumption_receipt(
        decision,
        permit,
        cohort_sha256="b" * 64,
        wave_index=2,
        selection_sha256="c" * 64,
        routing_slots=["e" * 64],
    )
    namespace = projection.advance_permit_projection({}, identity, receipt)[
        projection.PERMIT_NAMESPACE_KEY
    ]
    with mock.patch.object(projection, "MAX_PERMIT_CONSUMPTIONS", 0):
        with pytest.raises(projection.PermitProjectionError, match="over bound"):
            projection.validate_permit_namespace(namespace)
    with mock.patch.object(projection, "MAX_PERMIT_NAMESPACE_BYTES", 1):
        with pytest.raises(projection.PermitProjectionError, match="byte bound"):
            projection.validate_permit_namespace(namespace)
    assert semantic.canonical_sha256(namespace)
