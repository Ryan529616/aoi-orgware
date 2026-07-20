"""End-to-end schema-v2 cohort permit issuance and consumption tests."""

from __future__ import annotations

import copy
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

from aoi_orgware import cohorts
from aoi_orgware import harnesslib as h
from aoi_orgware import permit_runtime as runtime
from aoi_orgware import routing_authority as authority
from aoi_orgware import routing_persistence as routing
from aoi_orgware import semantic_events as semantic
from aoi_orgware import semantic_objects as objects
from aoi_orgware import semantic_store as store
from aoi_orgware import transition_permits as permits
from aoi_orgware.config import default_config_text
from tests.test_routing_authority import root_arm
from tests.test_routing_persistence import execution_selection_domain


TASK = "task-1"


class CohortPermitFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "aoi.toml").write_text(
            default_config_text("Cohort permit runtime"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        h.task_dir(self.paths, TASK).mkdir(parents=True)
        self.domain = execution_selection_domain()
        self.domain.update(
            {
                "status": "active",
                "plan_ready": True,
                "revision": 0,
                "updated_at": "2026-01-01T00:00:00Z",
                "checkpoint_required": False,
                "dispatch_model_version": 1,
            }
        )
        self.domain["packets"].append(
            {
                "task_id": TASK,
                "packet_id": "packet-standalone",
                "packet_contract_sha256": "a" * 64,
                "agent_role": "explorer",
                "status": "ready",
                "packet_schema_version": 5,
                "dispatch_version": 1,
                "dispatch_provenance": "none",
                "dispatch_attempts": [],
                "delegation_depth": 1,
                "parent_packet_id": "",
                "execution_selection_id": "",
                "lane_id": "",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        )
        self.events = [
            semantic.create_genesis_event(
                self.domain,
                command_id="cohort-permit-genesis",
                recorded_at="2026-01-01T00:00:00Z",
                authority_ref="test",
            )
        ]
        store.initialize_semantic_task(
            self.paths,
            self.domain,
            command_id="cohort-permit-genesis",
            recorded_at="2026-01-01T00:00:00Z",
            authority_ref="test",
        )
        self.live = {
            "status": "active",
            "epoch": 1,
            "session_id": "session-1",
            "issued_at": "2026-01-01T00:00:00.000000Z",
            "renewed_at": "2026-01-01T00:00:00.000000Z",
            "expires_at": "2026-01-02T00:00:00.000000Z",
            "renewal_count": 0,
            "transition_seq": 1,
            "audit_tail": [],
        }
        live_sha256 = semantic.canonical_sha256(self.live)
        self.arms = [
            root_arm(
                "packet-route",
                expected_agent_type="explorer",
                execution_selection_id="selection-1",
            ),
            root_arm(
                "packet-route-b",
                expected_agent_type="worker",
                execution_selection_id="selection-1",
            ),
        ]
        for arm in self.arms:
            arm["chief_authority"] = {
                "session_id": "session-1",
                "epoch": 1,
                "authority_sha256": live_sha256,
            }
            authority.validate_arm_authority(arm)
        selection = self.domain["execution_selections"][0]
        self.plan = cohorts.seal_cohort(
            {
                "schema_version": 1,
                "cohort_id": "cohort-1",
                "packet_schema_version": 6,
                "resource_envelope_sha256": self.arms[0]["resource_envelope"][
                    "snapshot_sha256"
                ],
                "execution_selection_identity_sha256": (
                    cohorts.execution_selection_identity_sha256("selection-1")
                ),
                "execution_selection_target_contract_sha256": selection[
                    "target_contract_sha256"
                ],
                "packet_refs": [
                    {
                        "packet_id": arm["packet_authority"]["packet_id"],
                        "routing_authority_sha256": authority.authority_sha256(arm),
                    }
                    for arm in self.arms
                ],
                "dependencies": {
                    arm["packet_authority"]["packet_id"]: []
                    for arm in self.arms
                },
                "waves": [[
                    arm["packet_authority"]["packet_id"] for arm in self.arms
                ]],
                "max_concurrency": 2,
                "transport_slots": [
                    {
                        "packet_id": arm["packet_authority"]["packet_id"],
                        "transport": arm["transport_authority"]["transport"],
                        "parent_session_id": arm["parent_authority"]["session_id"],
                        "expected_agent_type": arm["transport_authority"][
                            "expected_agent_type"
                        ],
                    }
                    for arm in self.arms
                ],
                "failure_policy": "continue",
                "cancel_policy": "continue",
            }
        )
        self.lock = mock.patch.object(h, "_require_chief_lock")
        self.lock.start()

    def close(self) -> None:
        self.lock.stop()
        self.temp.cleanup()

    def transaction(
        self,
        *,
        nonce: str = "cohort-runtime-nonce-0001",
        packet_arms: list[dict] | None = None,
    ) -> dict:
        packet_arms = packet_arms or self.arms
        effect = routing.prepare_cohort_authority_effect(
            self.paths,
            task_id=TASK,
            event_chain=self.events,
            cohort_plan=self.plan,
            wave_index=0,
            arms=packet_arms,
        )
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": TASK,
                "action": "cohort.advance",
                "target_ids": [self.plan["cohort_id"]],
                "parameters": {
                    "cohort_id": self.plan["cohort_id"],
                    "cohort_sha256": self.plan["cohort_sha256"],
                    "wave_index": 0,
                },
                "technical_payload_sha256": effect["selection"][
                    "selection_sha256"
                ],
            }
        )
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": TASK,
                "expected_semantic_head_sha256": self.events[-1]["event_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "action": "cohort.advance",
                "target_ids": decision["target_ids"],
                "parameters": decision["parameters"],
                "expires_at": "2026-01-01T00:10:03Z",
                "nonce": nonce,
                "chief_authority": {"session_id": "session-1", "epoch": 1},
            }
        )
        return runtime.prepare_permitted_cohort_transaction(
            self.paths,
            task_id=TASK,
            event_chain=self.events,
            decision=decision,
            permit=permit,
            cohort_plan=self.plan,
            arms=packet_arms,
            command_id="cohort-permit-round-1",
            recorded_at="2026-01-01T00:04:00Z",
        )

    def issue(self, transaction: dict) -> dict:
        with mock.patch.object(h, "require_chief_authority", return_value=self.live):
            return runtime.issue_permitted_cohort_transaction(
                self.paths,
                transaction,
                self.events,
                chief_session_id="session-1",
                chief_epoch=1,
                chief_token="test-only-token",
                current_time=datetime(
                    2026, 1, 1, 0, 5, tzinfo=timezone.utc
                ),
            )

    def packet_transaction(self, *, nonce: str) -> dict:
        arm = root_arm(
            "packet-standalone",
            expected_agent_type="explorer",
        )
        arm["chief_authority"] = copy.deepcopy(self.arms[0]["chief_authority"])
        arm["attempt_identity"].update(
            {
                "arm_id": "packet-standalone-a1",
                "armed_at": "2026-01-01T00:00:03Z",
                "expires_at": "2026-01-01T00:10:03Z",
            }
        )
        arm = authority.validate_arm_authority(arm)
        arm_sha256 = authority.authority_sha256(arm)
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": TASK,
                "action": "packet.arm",
                "target_ids": ["packet-standalone"],
                "parameters": {
                    "packet_id": "packet-standalone",
                    "packet_schema_version": 6,
                    "routing_authority_sha256": arm_sha256,
                },
                "technical_payload_sha256": arm_sha256,
            }
        )
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": TASK,
                "expected_semantic_head_sha256": self.events[-1]["event_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "action": "packet.arm",
                "target_ids": decision["target_ids"],
                "parameters": decision["parameters"],
                "expires_at": "2026-01-01T00:10:03Z",
                "nonce": nonce,
                "chief_authority": {"session_id": "session-1", "epoch": 1},
            }
        )
        return runtime.prepare_permitted_arm_transaction(
            task_id=TASK,
            event_chain=self.events,
            decision=decision,
            permit=permit,
            arm=arm,
            command_id="packet-permit-round-1",
            recorded_at="2026-01-01T00:04:00Z",
        )

    def issue_packet(self, transaction: dict) -> dict:
        with mock.patch.object(h, "require_chief_authority", return_value=self.live):
            return runtime.issue_permitted_arm_transaction(
                self.paths,
                transaction,
                self.events,
                chief_session_id="session-1",
                chief_epoch=1,
                chief_token="test-only-token",
                current_time=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
                validate_packet_arm_preimage=(
                    lambda _paths, _state, _packet, _arm: None
                ),
            )

    def commit(self, transaction: dict, *, current_time: datetime | None = None) -> dict:
        with mock.patch.object(
            runtime,
            "_current_chief_authority",
            return_value={"session_id": "session-1", "epoch": 1},
        ):
            result = runtime.commit_permitted_cohort_transaction(
                self.paths,
                transaction,
                self.events,
                current_time=current_time
                or datetime(2026, 1, 1, 0, 6, tzinfo=timezone.utc),
            )
        if not any(
            event["event_sha256"] == result["event"]["event_sha256"]
            for event in self.events
        ):
            self.events.append(result["event"])
        return result


@pytest.fixture
def case() -> CohortPermitFixture:
    value = CohortPermitFixture()
    try:
        yield value
    finally:
        value.close()


def test_prepare_is_exact_v2_and_contains_one_consumption(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    assert transaction["schema_version"] == 2
    assert transaction["event_type"] == "permitted_cohort_advance"
    assert transaction["binding"]["binding_kind"] == "cohort_advance"
    assert len(transaction["objects"]) == 5
    namespace = transaction["result_state"][runtime.PERMIT_NAMESPACE_KEY]
    assert len(namespace["consumptions"]) == 1
    receipt = next(iter(namespace["consumptions"].values()))
    assert receipt["action"] == "cohort.advance"
    assert len(receipt["routing_slots"]) == 2
    decision = next(
        row for row in transaction["objects"] if row["object_type"] == "transition_decision"
    )
    assert receipt["cohort_state"]["selection_sha256"] == decision["payload"][
        "technical_payload_sha256"
    ]
    assert runtime.validate_permitted_cohort_transaction(transaction) == transaction


def test_issue_commit_and_exact_retry_use_only_v2_store(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    issued = case.issue(transaction)
    assert issued["idempotent_replay"] is False
    permit_sha256 = issued["permit_sha256"]
    assert runtime.cohort_permit_issuance_path(
        case.paths, TASK, permit_sha256
    ).is_file()
    assert not runtime.permit_issuance_path(case.paths, TASK, permit_sha256).exists()
    committed = case.commit(transaction)
    assert committed["idempotent_replay"] is False
    receipt = committed["permit_report"]["consumptions"][0]["receipt"]
    assert receipt["action"] == "cohort.advance"
    replay = case.commit(transaction)
    assert replay["idempotent_replay"] is True
    assert replay["event"]["event_sha256"] == committed["event"]["event_sha256"]


def test_objects_without_v2_marker_are_not_consumable(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    for wrapped in transaction["objects"]:
        objects.publish_semantic_object(case.paths, wrapped)
    with pytest.raises(runtime.PermitRuntimeError, match="issuance marker"):
        case.commit(transaction)
    assert len(case.events) == 1


def test_pending_binding_recovers_after_expiry_without_claiming_launch(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    case.issue(transaction)
    objects.publish_semantic_binding(case.paths, transaction["binding"], case.events)
    recovered = case.commit(
        transaction,
        current_time=datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc),
    )
    assert recovered["event"]["event_type"] == "permitted_cohort_advance"
    assert recovered["permit_report"]["consumptions"][0]["classification"] == "committed"


def test_committed_event_repairs_a_lost_v2_projection(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    case.issue(transaction)
    old_projection = h.task_state_path(case.paths, TASK).read_bytes()
    objects.publish_semantic_binding(case.paths, transaction["binding"], case.events)
    appended = store.append_semantic_transition(
        case.paths,
        TASK,
        transaction["result_state"],
        event_type=transaction["event_type"],
        command_id=transaction["command_id"],
        recorded_at=transaction["recorded_at"],
        authority_ref=transaction["authority_ref"],
        expected_head_sha256=transaction["expected_head_sha256"],
    )
    assert appended.event["event_sha256"] == transaction["planned_event"][
        "event_sha256"
    ]
    h.atomic_write_bytes(h.task_state_path(case.paths, TASK), old_projection)
    case.events = store.load_semantic_events(case.paths, TASK)
    assert store.semantic_projection_status(case.paths, TASK) == "behind"

    recovered = case.commit(
        transaction,
        current_time=datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc),
    )
    assert recovered["idempotent_replay"] is True
    assert store.semantic_projection_status(case.paths, TASK) == "current"


def test_v2_issuance_marker_tamper_fails_closed(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    issued = case.issue(transaction)
    marker_path = runtime.cohort_permit_issuance_path(
        case.paths, TASK, issued["permit_sha256"]
    )
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["transaction_sha256"] = "0" * 64
    h.atomic_write_bytes(
        marker_path,
        semantic.canonical_json_bytes(
            marker, max_bytes=runtime.MAX_COHORT_PERMIT_ISSUANCE_BYTES
        ),
    )
    with pytest.raises(runtime.PermitRuntimeError, match="marker SHA-256"):
        runtime.inspect_permit_runtime(case.paths, TASK, case.events)


def test_v2_issuance_missing_object_and_unexpected_entry_fail_closed(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    issued = case.issue(transaction)
    missing_digest = transaction["objects"][0]["object_sha256"]
    objects.semantic_object_path(case.paths, TASK, missing_digest).unlink()
    with pytest.raises(runtime.PermitRuntimeError, match="missing object"):
        runtime.inspect_permit_runtime(case.paths, TASK, case.events)

    second = CohortPermitFixture()
    try:
        second_transaction = second.transaction()
        second_issued = second.issue(second_transaction)
        marker_path = runtime.cohort_permit_issuance_path(
            second.paths, TASK, second_issued["permit_sha256"]
        )
        (marker_path.parent / "residue.txt").write_text(
            "unmanaged", encoding="utf-8"
        )
        with pytest.raises(runtime.PermitRuntimeError, match="unexpected entry"):
            runtime.inspect_permit_runtime(second.paths, TASK, second.events)
    finally:
        second.close()


def test_resealed_unrelated_after_image_is_rejected_before_issuance(
    case: CohortPermitFixture,
) -> None:
    transaction = case.transaction()
    tampered = copy.deepcopy(transaction)
    extra_arm = root_arm(
        "packet-extra",
        expected_agent_type="reviewer",
        execution_selection_id="selection-1",
    )
    extra_arm["chief_authority"] = copy.deepcopy(case.arms[0]["chief_authority"])
    extra_effect = routing.prepare_authority_effect(
        task_id=TASK,
        event_chain=case.events,
        arm=extra_arm,
    )
    extra_entry = extra_effect["routing_entry"]
    tampered["result_state"][routing.ROUTING_NAMESPACE_KEY]["entries"][
        extra_entry["outcome_slot_sha256"]
    ] = extra_entry
    planned = semantic.create_transition_event(
        case.events[-1],
        semantic.replay_events(case.events),
        tampered["result_state"],
        event_type=tampered["event_type"],
        command_id=tampered["command_id"],
        recorded_at=tampered["recorded_at"],
        authority_ref=tampered["authority_ref"],
    )
    tampered["planned_event"] = planned
    tampered["binding"] = objects.create_semantic_binding(
        binding_kind="cohort_advance",
        task_id=TASK,
        binding_key=transaction["binding"]["binding_key"],
        expected_semantic_head_sha256=planned["prev_event_sha256"],
        planned_event_sha256=planned["event_sha256"],
        result_projection_sha256=planned["result_projection_sha256"],
        object_sha256s=transaction["binding"]["object_sha256s"],
    )
    preimage = {
        key: value
        for key, value in tampered.items()
        if key != "transaction_sha256"
    }
    tampered["transaction_sha256"] = semantic.canonical_sha256(
        preimage, max_bytes=runtime.MAX_COHORT_PERMIT_TRANSACTION_BYTES
    )
    runtime.validate_permitted_cohort_transaction(tampered)
    with pytest.raises(runtime.PermitRuntimeError, match="current ledger head"):
        case.issue(tampered)
    assert len(case.events) == 1


def test_replay_marker_is_globally_unique_in_both_store_orders(
    case: CohortPermitFixture,
) -> None:
    nonce = "cross-version-replay-nonce"
    cohort_transaction = case.transaction(nonce=nonce)
    packet_transaction = case.packet_transaction(nonce=nonce)
    case.issue(cohort_transaction)
    with pytest.raises(runtime.PermitRuntimeError, match="replay marker"):
        case.issue_packet(packet_transaction)

    second = CohortPermitFixture()
    try:
        packet_transaction = second.packet_transaction(nonce=nonce)
        cohort_transaction = second.transaction(nonce=nonce)
        second.issue_packet(packet_transaction)
        with pytest.raises(runtime.PermitRuntimeError, match="replay marker"):
            second.issue(cohort_transaction)
    finally:
        second.close()
