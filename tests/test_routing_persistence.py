"""Adversarial tests for compact dispatch-v6 semantic persistence."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "src"))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import cohorts  # noqa: E402
from aoi_orgware import permit_projection  # noqa: E402
from aoi_orgware import routing_authority as authority  # noqa: E402
from aoi_orgware import routing_persistence as routing  # noqa: E402
from aoi_orgware import resource_governance  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_objects as objects  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.test_routing_authority import (  # noqa: E402
    execution_resource_envelope,
    observation,
    root_arm,
)


TASK = "task-1"


def execution_selection_domain(
    *,
    selection_id: str = "selection-1",
    status: str = "active",
    max_active_first_level_agents: int = 2,
    max_active_total_agents: int = 2,
) -> dict[str, object]:
    lane_snapshots = [
        {
            "lane_id": lane_id,
            "revision": 1,
            "authority_commit": digest,
            "contract_version": "cv1",
        }
        for lane_id, digest in (("lane-a", "c" * 64), ("lane-b", "d" * 64))
    ]
    envelope = execution_resource_envelope(
        max_active_first_level_agents=max_active_first_level_agents,
        max_active_total_agents=max_active_total_agents,
    )
    domain: dict[str, object] = {
        "task_id": TASK,
        "stage": 0,
        "plan_sha256": "b" * 64,
        "task_execution_schema_version": 2,
        "execution_policy_version": 2,
        "legacy_execution_policy": False,
        "lanes": [
            {
                **snapshot,
                "role": "explorer" if index == 0 else "worker",
            }
            for index, snapshot in enumerate(lane_snapshots)
        ],
        "packets": [],
        "jobs": [],
    }
    selection = {
        "integrity_version": 1,
        "execution_selection_version": 2,
        "selection_id": selection_id,
        "work_unit_id": "work-1",
        "supersedes_selection_id": "",
        "task_plan_sha256": "b" * 64,
        "scope": "Bounded independent routing persistence verification",
        "mode": "centralized_parallel",
        "lane_snapshots": lane_snapshots,
        "steward_snapshot": {},
        "resource_envelope": envelope,
        "resource_envelope_sha256": semantic.canonical_sha256(envelope),
        "task_characteristics": {
            "sequential_dependency": "low",
            "tool_density": "low",
            "shared_context": "low",
        },
        "rationale": "Two independent test lanes exercise deterministic cohort routing",
        "falsification_condition": "Any cross-lane ownership conflict rejects the selection",
        "escalation_condition": "Reduce the wave when either execution cap is exhausted",
        "root_owner": "test",
        "root_session_id": "session-1",
        "status": status,
        "recorded_at": "2026-01-01T00:00:00Z",
    }
    selection["target_contract_sha256"] = semantic.canonical_sha256(
        resource_governance.execution_selection_target_contract_from_record(
            domain, selection
        )
    )
    domain["execution_selections"] = [selection]
    return domain


class RoutingPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "aoi.toml").write_text(
            default_config_text("Routing persistence"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        h.task_dir(self.paths, TASK).mkdir(parents=True)
        self.domain = execution_selection_domain()
        self.selection_target_sha256 = self.domain["execution_selections"][0][
            "target_contract_sha256"
        ]
        self.events = [
            semantic.create_genesis_event(
                self.domain,
                command_id="routing-genesis",
                recorded_at="2026-01-01T00:00:00Z",
                authority_ref="test",
            )
        ]
        store.initialize_semantic_task(
            self.paths,
            self.domain,
            command_id="routing-genesis",
            recorded_at="2026-01-01T00:00:00Z",
            authority_ref="test",
        )
        self.arm = root_arm("packet-route")
        self.manual_outcome = authority.build_dispatch_outcome(
            self.arm,
            dispatch_provenance="manual_unverified",
            observation=None,
            recorded_at="2026-01-01T00:02:00Z",
        )
        self.command = 0
        self.lock = mock.patch.object(h, "_require_chief_lock")
        self.lock.start()

    def tearDown(self) -> None:
        self.lock.stop()
        self.temp.cleanup()

    def next_metadata(self, prefix: str) -> dict[str, str]:
        self.command += 1
        return {
            "command_id": f"routing-{prefix}-{self.command}",
            "recorded_at": f"2026-01-01T00:{self.command + 2:02d}:00Z",
            "authority_ref": "test",
        }

    def prepare_authority(self) -> dict[str, object]:
        return routing.prepare_authority_transaction(
            task_id=TASK,
            event_chain=self.events,
            arm=self.arm,
            **self.next_metadata("authority"),
        )

    def prepare_outcome(self, outcome: dict[str, object] | None = None) -> dict[str, object]:
        return routing.prepare_outcome_transaction(
            task_id=TASK,
            event_chain=self.events,
            arm=self.arm,
            outcome=outcome or self.manual_outcome,
            **self.next_metadata("outcome"),
        )

    def prepare_terminal(self) -> dict[str, object]:
        return routing.prepare_terminal_transaction(
            task_id=TASK,
            event_chain=self.events,
            arm=self.arm,
            outcome=self.manual_outcome,
            terminal_status="done",
            typed_outcome="accepted",
            **self.next_metadata("terminal"),
        )

    def commit(self, transaction: dict[str, object]) -> dict[str, object]:
        result = routing.commit_routing_transaction(self.paths, transaction, self.events)
        event = result["event"]
        if not any(row["event_sha256"] == event["event_sha256"] for row in self.events):
            self.events.append(event)
        self.domain = semantic.projection_domain(result["projection"])
        return result

    def append_unrelated(self, label: str = "successor") -> dict[str, object]:
        replayed = semantic.replay_events(self.events)
        result = semantic.projection_domain(replayed)
        result["unrelated"] = label
        event = store.append_semantic_transition(
            self.paths,
            TASK,
            result,
            event_type="unrelated_test",
            command_id=f"unrelated-{label}",
            recorded_at="2026-01-01T00:20:00Z",
            authority_ref="test",
            expected_head_sha256=self.events[-1]["event_sha256"],
        ).event
        self.events.append(event)
        self.domain = result
        return event

    def append_domain_state(
        self, result: dict[str, object], label: str
    ) -> dict[str, object]:
        event = store.append_semantic_transition(
            self.paths,
            TASK,
            result,
            event_type="unrelated_test",
            command_id=f"domain-{label}",
            recorded_at="2026-01-01T00:21:00Z",
            authority_ref="test",
            expected_head_sha256=self.events[-1]["event_sha256"],
        ).event
        self.events.append(event)
        self.domain = result
        return event

    def publish_transaction_objects(self, transaction: dict[str, object]) -> None:
        for wrapped in transaction["objects"]:
            objects.publish_semantic_object(self.paths, wrapped)

    def permit_composite(
        self,
        *,
        action: str = "packet.arm",
        contract_task_id: str = TASK,
        contract_packet_id: str = "packet-route",
        event_type: str = "permitted_packet_arm",
    ) -> dict[str, object]:
        effect = routing.prepare_authority_effect(
            task_id=TASK, event_chain=self.events, arm=self.arm
        )
        head = self.events[-1]["event_sha256"]
        authority_sha = authority.authority_sha256(self.arm)
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": contract_task_id,
                "action": action,
                "target_ids": [contract_packet_id] if action == "packet.arm" else ["cohort-1"],
                "parameters": (
                    {
                        "packet_id": contract_packet_id,
                        "packet_schema_version": 6,
                        "routing_authority_sha256": authority_sha,
                    }
                    if action == "packet.arm"
                    else {"cohort_id": "cohort-1", "cohort_sha256": "a" * 64, "wave_index": 0}
                ),
                "technical_payload_sha256": "b" * 64,
            }
        )
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": contract_task_id,
                "expected_semantic_head_sha256": head,
                "decision_sha256": decision["decision_sha256"],
                "action": decision["action"],
                "target_ids": decision["target_ids"],
                "parameters": decision["parameters"],
                "expires_at": "2027-01-01T00:00:00Z",
                "nonce": "permit-nonce-0001",
                "chief_authority": {"session_id": "chief-1", "epoch": 1},
            }
        )
        wrapped_decision = objects.create_semantic_object(
            object_type="transition_decision",
            task_id=TASK,
            object_identity=decision["decision_sha256"],
            payload=decision,
        )
        wrapped_permit = objects.create_semantic_object(
            object_type="transition_permit",
            task_id=TASK,
            object_identity=permit["permit_sha256"],
            payload=permit,
        )
        planned = semantic.create_transition_event(
            self.events[-1],
            semantic.replay_events(self.events),
            effect["result_state"],
            event_type=event_type,
            **self.next_metadata("permit"),
        )
        binding = objects.create_semantic_binding(
            binding_kind="permit_consumption",
            task_id=TASK,
            binding_key=permits.permit_consumption_identity(permit),
            expected_semantic_head_sha256=head,
            planned_event_sha256=planned["event_sha256"],
            result_projection_sha256=planned["result_projection_sha256"],
            object_sha256s=sorted(
                row["object_sha256"]
                for row in (wrapped_decision, wrapped_permit, effect["routing_authority"])
            ),
        )
        return {
            "effect": effect,
            "decision": wrapped_decision,
            "permit": wrapped_permit,
            "event": planned,
            "binding": binding,
        }

    def publish_permit_composite(self, composite: dict[str, object]) -> None:
        for key in ("decision", "permit"):
            objects.publish_semantic_object(self.paths, composite[key])
        objects.publish_semantic_object(self.paths, composite["effect"]["routing_authority"])
        objects.publish_semantic_binding(self.paths, composite["binding"], self.events)

    def composite_report(self, composite: dict[str, object]) -> dict[str, object]:
        return {
            "task_id": TASK,
            "objects": [
                {**composite["decision"], "classification": "referenced", "binding_sha256s": []},
                {**composite["permit"], "classification": "referenced", "binding_sha256s": []},
                {
                    **composite["effect"]["routing_authority"],
                    "classification": "referenced",
                    "binding_sha256s": [],
                },
            ],
            "bindings": [{**composite["binding"], "classification": "pending"}],
        }

    def append_permit_composite(self, composite: dict[str, object]) -> None:
        event = composite["event"]
        appended = store.append_semantic_transition(
            self.paths,
            TASK,
            composite["effect"]["result_state"],
            event_type=semantic.command_semantics(event)["event_type"],
            command_id=event["command_id"],
            recorded_at=event["recorded_at"],
            authority_ref=event["authority_ref"],
            expected_head_sha256=self.events[-1]["event_sha256"],
        )
        self.events.append(appended.event)

    def cohort_composite(
        self,
        *,
        event_type: str = "permitted_cohort_advance",
        technical_payload_sha256: str | None = None,
        partial_projection: bool = False,
        supersede_selection_in_event: bool = False,
        resource_envelope_sha256: str | None = None,
        execution_selection_identity_sha256: str | None = None,
        execution_selection_target_contract_sha256: str | None = None,
        parent_session_id: str | None = None,
        arms: list[dict[str, object]] | None = None,
        waves: list[list[str]] | None = None,
        dependencies: dict[str, list[str]] | None = None,
        wave_index: int = 0,
        selected_packet_ids: list[str] | None = None,
        max_concurrency: int | None = None,
        packet_states: dict[str, dict[str, str | None]] | None = None,
        structural_only: bool = False,
    ) -> dict[str, object]:
        arms = arms or [
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
        packet_ids = [arm["packet_authority"]["packet_id"] for arm in arms]
        waves = waves or [packet_ids]
        dependencies = dependencies or {packet_id: [] for packet_id in packet_ids}
        selected_packet_ids = selected_packet_ids or list(waves[wave_index])
        selected = {
            arm["packet_authority"]["packet_id"]: arm for arm in arms
        }
        selected_arms = [selected[packet_id] for packet_id in selected_packet_ids]
        batch = routing.prepare_authority_batch_effect(
            task_id=TASK, event_chain=self.events, arms=selected_arms
        )
        plan = cohorts.seal_cohort(
            {
                "schema_version": 1,
                "cohort_id": "cohort-1",
                "packet_schema_version": 6,
                "resource_envelope_sha256": resource_envelope_sha256
                or arms[0]["resource_envelope"]["snapshot_sha256"],
                "execution_selection_identity_sha256": (
                    execution_selection_identity_sha256
                    or cohorts.execution_selection_identity_sha256("selection-1")
                ),
                "execution_selection_target_contract_sha256": (
                    execution_selection_target_contract_sha256
                    or self.selection_target_sha256
                ),
                "packet_refs": [
                    {
                        "packet_id": arm["packet_authority"]["packet_id"],
                        "routing_authority_sha256": authority.authority_sha256(arm),
                    }
                    for arm in arms
                ],
                "dependencies": dependencies,
                "waves": waves,
                "max_concurrency": max_concurrency or max(
                    len(wave) for wave in waves
                ),
                "transport_slots": [
                    {
                        "packet_id": arm["packet_authority"]["packet_id"],
                        "transport": arm["transport_authority"]["transport"],
                        "parent_session_id": parent_session_id
                        or arm["parent_authority"]["session_id"],
                        "expected_agent_type": arm["transport_authority"][
                            "expected_agent_type"
                        ],
                    }
                    for arm in arms
                ],
                "failure_policy": "continue",
                "cancel_policy": "continue",
            }
        )
        selection_base = {
            "schema_version": 1,
            "cohort_sha256": plan["cohort_sha256"],
            "wave_index": wave_index,
            "routes": [
                {
                    "packet_id": arm["packet_authority"]["packet_id"],
                    "routing_authority_sha256": authority.authority_sha256(arm),
                    "outcome_slot_sha256": routing.routing_outcome_slot_sha256(
                        arm
                    ),
                }
                for arm in selected_arms
            ],
        }
        if structural_only:
            selection = {
                **selection_base,
                "selection_sha256": semantic.canonical_sha256(selection_base),
            }
        else:
            selection = cohorts.seal_cohort_advance_selection(
                plan, selection_base, packet_states
            )
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": TASK,
                "action": "cohort.advance",
                "target_ids": [plan["cohort_id"]],
                "parameters": {
                    "cohort_id": plan["cohort_id"],
                    "cohort_sha256": plan["cohort_sha256"],
                    "wave_index": wave_index,
                },
                "technical_payload_sha256": technical_payload_sha256
                or selection["selection_sha256"],
            }
        )
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": TASK,
                "expected_semantic_head_sha256": self.events[-1]["event_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "action": decision["action"],
                "target_ids": decision["target_ids"],
                "parameters": decision["parameters"],
                "expires_at": "2026-01-01T00:10:03Z",
                "nonce": f"cohort-permit-nonce-{wave_index:04d}",
                "chief_authority": {"session_id": "session-1", "epoch": 1},
            }
        )
        wrapped_decision = objects.create_semantic_object(
            object_type="transition_decision",
            task_id=TASK,
            object_identity=decision["decision_sha256"],
            payload=decision,
        )
        wrapped_permit = objects.create_semantic_object(
            object_type="transition_permit",
            task_id=TASK,
            object_identity=permit["permit_sha256"],
            payload=permit,
        )
        wrapped_plan = objects.create_semantic_object(
            object_type="cohort_plan",
            task_id=TASK,
            object_identity=plan["cohort_sha256"],
            payload=plan,
        )
        result_state = (
            routing.prepare_authority_effect(
                task_id=TASK, event_chain=self.events, arm=selected_arms[0]
            )["result_state"]
            if partial_projection
            else batch["result_state"]
        )
        consumption_identity, consumption_receipt = (
            permit_projection.cohort_consumption_receipt(
                decision,
                permit,
                cohort_sha256=plan["cohort_sha256"],
                wave_index=wave_index,
                selection_sha256=selection["selection_sha256"],
                routing_slots=[
                    entry["outcome_slot_sha256"]
                    for entry in batch["routing_entries"]
                    if entry["packet_id"] in selected_packet_ids
                ],
            )
        )
        result_state = permit_projection.advance_permit_projection(
            result_state,
            consumption_identity,
            consumption_receipt,
        )
        if supersede_selection_in_event:
            result_state = copy.deepcopy(result_state)
            result_state["execution_selections"][0]["status"] = "superseded"
        planned = semantic.create_transition_event(
            self.events[-1],
            semantic.replay_events(self.events),
            result_state,
            event_type=event_type,
            **self.next_metadata("cohort"),
        )
        all_objects = [
            wrapped_decision,
            wrapped_permit,
            wrapped_plan,
            *batch["routing_authority_objects"],
        ]
        binding = objects.create_semantic_binding(
            binding_kind="cohort_advance",
            task_id=TASK,
            binding_key=permits.permit_consumption_identity(permit),
            expected_semantic_head_sha256=self.events[-1]["event_sha256"],
            planned_event_sha256=planned["event_sha256"],
            result_projection_sha256=planned["result_projection_sha256"],
            object_sha256s=sorted(row["object_sha256"] for row in all_objects),
        )
        return {
            "arms": arms,
            "selected_arms": selected_arms,
            "batch": batch,
            "plan": wrapped_plan,
            "decision": wrapped_decision,
            "permit": wrapped_permit,
            "objects": all_objects,
            "result_state": result_state,
            "event": planned,
            "binding": binding,
        }

    def publish_cohort_composite(self, composite: dict[str, object]) -> None:
        for wrapped in composite["objects"]:
            objects.publish_semantic_object(self.paths, wrapped)
        objects.publish_semantic_binding(
            self.paths, composite["binding"], self.events
        )

    def append_cohort_composite(self, composite: dict[str, object]) -> None:
        event = composite["event"]
        appended = store.append_semantic_transition(
            self.paths,
            TASK,
            composite["result_state"],
            event_type=semantic.command_semantics(event)["event_type"],
            command_id=event["command_id"],
            recorded_at=event["recorded_at"],
            authority_ref=event["authority_ref"],
            expected_head_sha256=self.events[-1]["event_sha256"],
        )
        self.events.append(appended.event)

    def test_slot_formula_and_projection_are_compact_digest_only(self) -> None:
        transaction = self.prepare_authority()
        expected_slot = semantic.canonical_sha256(
            {
                "routing_authority_sha256": authority.authority_sha256(self.arm),
                "packet_id": "packet-route",
                "arm_id": "arm-packet-route",
                "attempt": 1,
            },
            max_bytes=authority.MAX_RECORD_BYTES,
        )
        self.assertEqual(routing.routing_outcome_slot_sha256(self.arm), expected_slot)
        namespace = routing.routing_namespace_from_projection(transaction["result_state"])
        entry = namespace["entries"][expected_slot]
        self.assertEqual(entry["phase"], "authority")
        self.assertLessEqual(
            len(semantic.canonical_json_bytes(entry)), routing.MAX_ROUTING_ENTRY_BYTES
        )
        projection_text = json.dumps(transaction["result_state"], sort_keys=True)
        self.assertNotIn("packet_authority", projection_text)
        self.assertNotIn("attempt_identity", projection_text)
        self.assertNotIn("dispatch_provenance", projection_text)
        self.assertNotIn("binding_sha256", projection_text)

    def test_prepare_authority_effect_is_pure_and_matches_direct_authority(self) -> None:
        effect = routing.prepare_authority_effect(
            task_id=TASK, event_chain=self.events, arm=self.arm
        )
        direct = self.prepare_authority()
        self.assertEqual(effect["routing_authority_object"], effect["routing_authority"])
        self.assertEqual(effect["routing_entry"], effect["authority_entry"])
        self.assertEqual(effect["routing_authority"], direct["objects"][0])
        self.assertEqual(effect["result_state"], direct["result_state"])
        slot = routing.routing_outcome_slot_sha256(self.arm)
        self.assertEqual(
            effect["authority_entry"],
            routing.routing_namespace_from_projection(effect["result_state"])["entries"][slot],
        )

    def test_permit_composite_pending_committed_and_exact_retry(self) -> None:
        composite = self.permit_composite()
        self.publish_permit_composite(composite)
        pending = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        self.assertEqual(
            [(row["stage"], row["classification"]) for row in pending["groups"]],
            [("authority", "pending")],
        )
        self.assertEqual(
            pending["routing_binding_sha256s"], [composite["binding"]["binding_sha256"]]
        )
        self.assertEqual(
            objects.publish_semantic_binding(self.paths, composite["binding"], self.events),
            composite["binding"],
        )
        appended = store.append_semantic_transition(
            self.paths,
            TASK,
            composite["effect"]["result_state"],
            event_type="permitted_packet_arm",
            command_id=composite["event"]["command_id"],
            recorded_at=composite["event"]["recorded_at"],
            authority_ref=composite["event"]["authority_ref"],
            expected_head_sha256=self.events[-1]["event_sha256"],
        )
        self.events.append(appended.event)
        committed = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        self.assertEqual(
            [(row["stage"], row["classification"]) for row in committed["groups"]],
            [("authority", "committed")],
        )

    def test_permit_composite_rejects_wrong_refs_key_pair_action_and_nonrouting_reference(self) -> None:
        composite = self.permit_composite()
        self.publish_permit_composite(composite)
        def replacement_binding(rows: list[dict[str, object]], key: str) -> dict[str, object]:
            return objects.create_semantic_binding(
                binding_kind="permit_consumption",
                task_id=TASK,
                binding_key=key,
                expected_semantic_head_sha256=composite["binding"]["expected_semantic_head_sha256"],
                planned_event_sha256=composite["binding"]["planned_event_sha256"],
                result_projection_sha256=composite["binding"]["result_projection_sha256"],
                object_sha256s=sorted(row["object_sha256"] for row in rows),
            )

        bad_key = copy.deepcopy(composite)
        bad_key["binding"] = replacement_binding(
            [bad_key["decision"], bad_key["permit"], bad_key["effect"]["routing_authority"]],
            "f" * 64,
        )
        with mock.patch.object(objects, "inspect_semantic_objects", return_value=self.composite_report(bad_key)):
            with self.assertRaisesRegex(h.HarnessError, "binding key"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

        bad_refs = copy.deepcopy(composite)
        bad_refs["binding"] = replacement_binding(
            [bad_refs["decision"], bad_refs["permit"]],
            permits.permit_consumption_identity(bad_refs["permit"]["payload"]),
        )
        report = self.composite_report(bad_refs)
        report["objects"] = report["objects"][:2]
        with mock.patch.object(objects, "inspect_semantic_objects", return_value=report):
            with self.assertRaisesRegex(h.HarnessError, "types or cardinality"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

        bad_pair = copy.deepcopy(composite)
        decision_payload = copy.deepcopy(bad_pair["decision"]["payload"])
        decision_payload["technical_payload_sha256"] = "c" * 64
        decision_payload.pop("decision_sha256")
        decision_payload = permits.seal_transition_decision(decision_payload)
        bad_pair["decision"] = objects.create_semantic_object(
            object_type="transition_decision",
            task_id=TASK,
            object_identity=decision_payload["decision_sha256"],
            payload=decision_payload,
        )
        bad_pair["binding"] = replacement_binding(
            [bad_pair["decision"], bad_pair["permit"], bad_pair["effect"]["routing_authority"]],
            permits.permit_consumption_identity(bad_pair["permit"]["payload"]),
        )
        with mock.patch.object(objects, "inspect_semantic_objects", return_value=self.composite_report(bad_pair)):
            with self.assertRaisesRegex(h.HarnessError, "decision or permit"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

        cohort = self.permit_composite(action="cohort.advance")
        with mock.patch.object(objects, "inspect_semantic_objects", return_value=self.composite_report(cohort)):
            with self.assertRaisesRegex(h.HarnessError, "does not authorize"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

        nonrouting = copy.deepcopy(composite["binding"])
        nonrouting = objects.create_semantic_binding(
            binding_kind="cohort_advance",
            task_id=TASK,
            binding_key=nonrouting["binding_key"],
            expected_semantic_head_sha256=nonrouting["expected_semantic_head_sha256"],
            planned_event_sha256=nonrouting["planned_event_sha256"],
            result_projection_sha256=nonrouting["result_projection_sha256"],
            object_sha256s=[composite["effect"]["routing_authority"]["object_sha256"]],
        )
        report = self.composite_report(composite)
        report["objects"] = [report["objects"][2]]
        report["bindings"] = [{**nonrouting, "classification": "pending"}]
        with mock.patch.object(objects, "inspect_semantic_objects", return_value=report):
            with self.assertRaisesRegex(h.HarnessError, "cardinality"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_permit_composite_rejects_double_ownership_of_authority_slot(self) -> None:
        composite = self.permit_composite()
        direct = self.prepare_authority()
        report = self.composite_report(composite)
        report["bindings"].append({**direct["binding"], "classification": "pending"})
        with mock.patch.object(objects, "inspect_semantic_objects", return_value=report):
            with self.assertRaisesRegex(h.HarnessError, "multiple owning"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_permit_composite_rejects_foreign_contract_task(self) -> None:
        composite = self.permit_composite(contract_task_id="task-other")
        self.publish_permit_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "contract task"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_permit_composite_rejects_foreign_authority_task(self) -> None:
        composite = self.permit_composite()
        foreign_arm = copy.deepcopy(self.arm)
        foreign_arm["task_id"] = "task-other"
        with mock.patch.object(
            objects, "inspect_semantic_objects", return_value=self.composite_report(composite)
        ):
            with mock.patch.object(authority, "validate_arm_authority", return_value=foreign_arm):
                with mock.patch.object(
                    authority,
                    "authority_sha256",
                    return_value=composite["effect"]["routing_authority"]["object_identity"],
                ):
                    with self.assertRaisesRegex(h.HarnessError, "authority task"):
                        routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_permit_composite_rejects_foreign_contract_packet(self) -> None:
        composite = self.permit_composite(contract_packet_id="packet-other")
        self.publish_permit_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "does not authorize"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_authority_batch_effect_and_cohort_binding_are_atomic_and_ordered(self) -> None:
        composite = self.cohort_composite()
        entries = composite["batch"]["routing_entries"]
        self.assertEqual(
            [entry["packet_id"] for entry in entries],
            ["packet-route", "packet-route-b"],
        )
        self.assertEqual(
            len(
                routing.routing_namespace_from_projection(
                    composite["batch"]["result_state"]
                )["entries"]
            ),
            2,
        )

        self.publish_cohort_composite(composite)
        pending = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        cohort_groups = [
            group
            for group in pending["groups"]
            if group.get("composite_kind") == "cohort"
        ]
        self.assertEqual(len(cohort_groups), 2)
        self.assertEqual(
            [group["classification"] for group in cohort_groups],
            ["pending", "pending"],
        )
        self.assertEqual(
            pending["routing_binding_sha256s"],
            [composite["binding"]["binding_sha256"]],
        )

        self.append_cohort_composite(composite)
        committed = routing.inspect_routing_persistence(
            self.paths, TASK, self.events
        )
        cohort_groups = [
            group
            for group in committed["groups"]
            if group.get("composite_kind") == "cohort"
        ]
        self.assertEqual(
            [group["classification"] for group in cohort_groups],
            ["committed", "committed"],
        )
        self.assertEqual(
            committed["routing_binding_sha256s"],
            [composite["binding"]["binding_sha256"]],
        )

    def test_authority_batch_effect_rejects_empty_duplicate_and_over_bound(self) -> None:
        with self.assertRaisesRegex(h.HarnessError, "empty"):
            routing.prepare_authority_batch_effect(
                task_id=TASK, event_chain=self.events, arms=[]
            )
        with self.assertRaisesRegex(h.HarnessError, "repeats"):
            routing.prepare_authority_batch_effect(
                task_id=TASK, event_chain=self.events, arms=[self.arm, self.arm]
            )
        with self.assertRaisesRegex(h.HarnessError, "count bound"):
            routing.prepare_authority_batch_effect(
                task_id=TASK,
                event_chain=self.events,
                arms=[root_arm(f"packet-{index}") for index in range(13)],
            )

    def test_cohort_binding_rejects_technical_payload_substitution(self) -> None:
        composite = self.cohort_composite(
            technical_payload_sha256="f" * 64
        )
        self.publish_cohort_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "technical payload"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_binding_rejects_resource_and_transport_plan_drift(self) -> None:
        for composite in (
            self.cohort_composite(resource_envelope_sha256="f" * 64),
            self.cohort_composite(parent_session_id="another-session"),
        ):
            with self.subTest(plan=composite["plan"]["payload"]):
                report = {
                    "task_id": TASK,
                    "objects": [
                        {
                            **row,
                            "classification": "referenced",
                            "binding_sha256s": [],
                        }
                        for row in composite["objects"]
                    ],
                    "bindings": [
                        {**composite["binding"], "classification": "pending"}
                    ],
                }
                with mock.patch.object(
                    objects, "inspect_semantic_objects", return_value=report
                ):
                    with self.assertRaisesRegex(h.HarnessError, "sealed plan"):
                        routing.inspect_routing_persistence(
                            self.paths, TASK, self.events
                        )

    def test_cohort_binding_rejects_wrong_event(self) -> None:
        wrong_event = self.cohort_composite(event_type="unrelated_test")
        self.publish_cohort_composite(wrong_event)
        self.append_cohort_composite(wrong_event)
        with self.assertRaisesRegex(h.HarnessError, "event type"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_binding_rejects_partial_projection(self) -> None:
        partial = self.cohort_composite(partial_projection=True)
        self.publish_cohort_composite(partial)
        self.append_cohort_composite(partial)
        with self.assertRaisesRegex(h.HarnessError, "absent from projection"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_binding_rejects_execution_selection_identity_substitution(self) -> None:
        composite = self.cohort_composite(
            execution_selection_identity_sha256="f" * 64
        )
        self.publish_cohort_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "execution-selection identity"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_binding_rejects_execution_selection_target_substitution(self) -> None:
        composite = self.cohort_composite(
            execution_selection_target_contract_sha256="f" * 64
        )
        self.publish_cohort_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "target contract"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_requires_one_active_v2_selection(self) -> None:
        domain = copy.deepcopy(self.domain)
        domain["execution_selections"] = []
        self.append_domain_state(domain, "missing-selection")
        composite = self.cohort_composite(structural_only=True)
        self.publish_cohort_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "exactly one matching"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_inactive_selection(self) -> None:
        domain = copy.deepcopy(self.domain)
        domain["execution_selections"][0]["status"] = "superseded"
        self.append_domain_state(domain, "inactive-selection")
        composite = self.cohort_composite(structural_only=True)
        self.publish_cohort_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "not one active"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_stale_lane_snapshot(self) -> None:
        domain = copy.deepcopy(self.domain)
        domain["lanes"][0]["revision"] = 2
        self.append_domain_state(domain, "stale-lane")
        composite = self.cohort_composite(structural_only=True)
        self.publish_cohort_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "stale"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_enforces_first_level_capacity_from_jobs(self) -> None:
        domain = copy.deepcopy(self.domain)
        domain["jobs"] = [
            {
                "run_id": "job-active",
                "status": "running",
                "execution_selection_id": "selection-1",
                "owner_packet_id": "",
            }
        ]
        self.append_domain_state(domain, "first-level-job")
        forged = self.cohort_composite(structural_only=True)
        self.publish_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "exact semantic head"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_foreign_or_implicit_epoch(self) -> None:
        domain = copy.deepcopy(self.domain)
        domain["packets"] = [
            {
                "packet_id": "packet-foreign",
                "status": "armed",
                "delegation_depth": 1,
                "execution_selection_id": "",
                "dispatch_attempts": [],
            }
        ]
        self.append_domain_state(domain, "foreign-epoch")
        forged = self.cohort_composite(
            selected_packet_ids=["packet-route"], structural_only=True
        )
        self.publish_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "foreign or implicit"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_alternate_active_authority_for_packet(self) -> None:
        alternate = root_arm(
            "packet-route",
            expected_agent_type="reviewer",
            execution_selection_id="selection-1",
        )
        self.commit(
            routing.prepare_authority_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=alternate,
                **self.next_metadata("alternate-authority"),
            )
        )
        forged = self.cohort_composite(
            selected_packet_ids=["packet-route"], structural_only=True
        )
        self.publish_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "another active authority"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_planned_event_partial_after_image_cannot_be_repaired_later(self) -> None:
        partial = self.cohort_composite(partial_projection=True)
        self.publish_cohort_composite(partial)
        self.append_cohort_composite(partial)
        repaired = copy.deepcopy(partial["batch"]["result_state"])
        self.append_domain_state(repaired, "late-cohort-repair")
        with self.assertRaisesRegex(h.HarnessError, "partial or altered"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_planned_event_cannot_smuggle_selection_supersession(self) -> None:
        smuggled = self.cohort_composite(supersede_selection_in_event=True)
        self.publish_cohort_composite(smuggled)
        self.append_cohort_composite(smuggled)
        with self.assertRaisesRegex(h.HarnessError, "exact after-image"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_later_wave_while_prior_wave_is_planned(self) -> None:
        arms = [
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
        forged = self.cohort_composite(
            arms=arms,
            waves=[["packet-route"], ["packet-route-b"]],
            dependencies={"packet-route": [], "packet-route-b": ["packet-route"]},
            wave_index=1,
            selected_packet_ids=["packet-route-b"],
            max_concurrency=1,
            structural_only=True,
        )
        self.publish_cohort_composite(forged)
        self.append_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "exact semantic head"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_noncanonical_colliding_subset(self) -> None:
        arms = [
            root_arm(
                packet_id,
                expected_agent_type="explorer",
                execution_selection_id="selection-1",
            )
            for packet_id in ("packet-route", "packet-route-b")
        ]
        forged = self.cohort_composite(
            arms=arms,
            selected_packet_ids=["packet-route-b"],
            max_concurrency=2,
            structural_only=True,
        )
        self.publish_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "exact semantic head"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_rejects_external_armed_slot_collision(self) -> None:
        external = root_arm(
            "packet-external",
            expected_agent_type="explorer",
            execution_selection_id="selection-1",
        )
        self.commit(
            routing.prepare_authority_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=external,
                **self.next_metadata("external-colliding-authority"),
            )
        )
        forged = self.cohort_composite(
            selected_packet_ids=["packet-route"],
            structural_only=True,
        )
        self.publish_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "armed transport slot"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_exact_head_counts_task_global_active_capacity(self) -> None:
        external = root_arm(
            "packet-external",
            expected_agent_type="reviewer",
            execution_selection_id="selection-1",
        )
        self.commit(
            routing.prepare_authority_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=external,
                **self.next_metadata("external-authority"),
            )
        )
        forged = self.cohort_composite(structural_only=True)
        self.publish_cohort_composite(forged)
        with self.assertRaisesRegex(h.HarnessError, "exact semantic head"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_later_wave_is_valid_after_prior_wave_accepts(self) -> None:
        arms = [
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
        schedule = {
            "arms": arms,
            "waves": [["packet-route"], ["packet-route-b"]],
            "dependencies": {
                "packet-route": [],
                "packet-route-b": ["packet-route"],
            },
            "max_concurrency": 1,
        }
        first = self.cohort_composite(
            **schedule,
            wave_index=0,
            selected_packet_ids=["packet-route"],
        )
        self.publish_cohort_composite(first)
        self.append_cohort_composite(first)

        outcome = authority.build_dispatch_outcome(
            arms[0],
            dispatch_provenance="manual_unverified",
            observation=None,
            recorded_at="2026-01-01T00:04:00Z",
        )
        self.commit(
            routing.prepare_outcome_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=arms[0],
                outcome=outcome,
                **self.next_metadata("wave-zero-outcome"),
            )
        )
        self.commit(
            routing.prepare_terminal_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=arms[0],
                outcome=outcome,
                terminal_status="done",
                typed_outcome="accepted",
                **self.next_metadata("wave-zero-terminal"),
            )
        )
        second = self.cohort_composite(
            **schedule,
            wave_index=1,
            selected_packet_ids=["packet-route-b"],
            packet_states={
                "packet-route": {
                    "status": "terminal",
                    "terminal_outcome": "accepted",
                }
            },
        )
        self.publish_cohort_composite(second)
        self.append_cohort_composite(second)
        report = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        self.assertIn(
            "packet-route-b",
            [
                group["authority"]["packet_authority"]["packet_id"]
                for group in report["groups"]
                if group.get("composite_kind") == "cohort"
                and group["classification"] == "committed"
            ],
        )

    def test_cohort_later_wave_rejects_alternate_active_authority_for_terminal_packet(
        self,
    ) -> None:
        arms = [
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
        schedule = {
            "arms": arms,
            "waves": [["packet-route"], ["packet-route-b"]],
            "dependencies": {
                "packet-route": [],
                "packet-route-b": ["packet-route"],
            },
            "max_concurrency": 1,
        }
        first = self.cohort_composite(
            **schedule,
            wave_index=0,
            selected_packet_ids=["packet-route"],
        )
        self.publish_cohort_composite(first)
        self.append_cohort_composite(first)
        outcome = authority.build_dispatch_outcome(
            arms[0],
            dispatch_provenance="manual_unverified",
            observation=None,
            recorded_at="2026-01-01T00:04:00Z",
        )
        self.commit(
            routing.prepare_outcome_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=arms[0],
                outcome=outcome,
                **self.next_metadata("terminal-plan-outcome"),
            )
        )
        self.commit(
            routing.prepare_terminal_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=arms[0],
                outcome=outcome,
                terminal_status="done",
                typed_outcome="accepted",
                **self.next_metadata("terminal-plan-terminal"),
            )
        )
        alternate = root_arm(
            "packet-route",
            expected_agent_type="reviewer",
            execution_selection_id="selection-1",
        )
        self.commit(
            routing.prepare_authority_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=alternate,
                **self.next_metadata("terminal-packet-alternate"),
            )
        )
        second = self.cohort_composite(
            **schedule,
            wave_index=1,
            selected_packet_ids=["packet-route-b"],
            packet_states={
                "packet-route": {
                    "status": "terminal",
                    "terminal_outcome": "accepted",
                }
            },
        )
        self.publish_cohort_composite(second)
        with self.assertRaisesRegex(h.HarnessError, "another active authority"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_cohort_composite_can_progress_and_recover_through_terminal(self) -> None:
        composite = self.cohort_composite()
        self.publish_cohort_composite(composite)
        self.append_cohort_composite(composite)
        arm = composite["arms"][0]
        outcome = authority.build_dispatch_outcome(
            arm,
            dispatch_provenance="manual_unverified",
            observation=None,
            recorded_at="2026-01-01T00:04:00Z",
        )
        outcome_transaction = routing.prepare_outcome_transaction(
            task_id=TASK,
            event_chain=self.events,
            arm=arm,
            outcome=outcome,
            **self.next_metadata("cohort-progress-outcome"),
        )
        self.commit(outcome_transaction)
        self.commit(
            routing.prepare_terminal_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=arm,
                outcome=outcome,
                terminal_status="done",
                typed_outcome="accepted",
                **self.next_metadata("cohort-progress-terminal"),
            )
        )
        h.task_state_path(self.paths, TASK).unlink()
        recovered = routing.commit_routing_transaction(
            self.paths, outcome_transaction, self.events
        )
        self.assertTrue(recovered["idempotent_replay"])
        slot = routing.routing_outcome_slot_sha256(arm)
        self.assertEqual(
            recovered["routing_report"]["namespace"]["entries"][slot]["phase"],
            "terminal",
        )

    def test_permit_composite_can_progress_through_terminal(self) -> None:
        composite = self.permit_composite()
        self.publish_permit_composite(composite)
        self.append_permit_composite(composite)
        outcome = authority.build_dispatch_outcome(
            self.arm,
            dispatch_provenance="manual_unverified",
            observation=None,
            recorded_at="2026-01-01T00:04:00Z",
        )
        self.commit(
            routing.prepare_outcome_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=self.arm,
                outcome=outcome,
                **self.next_metadata("permit-progress-outcome"),
            )
        )
        terminal = self.commit(
            routing.prepare_terminal_transaction(
                task_id=TASK,
                event_chain=self.events,
                arm=self.arm,
                outcome=outcome,
                terminal_status="done",
                typed_outcome="accepted",
                **self.next_metadata("permit-progress-terminal"),
            )
        )
        slot = routing.routing_outcome_slot_sha256(self.arm)
        self.assertEqual(
            terminal["routing_report"]["namespace"]["entries"][slot]["phase"],
            "terminal",
        )

    def test_cohort_and_direct_binding_cannot_own_the_same_authority_slot(self) -> None:
        composite = self.cohort_composite()
        direct = routing.prepare_authority_transaction(
            task_id=TASK,
            event_chain=self.events,
            arm=composite["arms"][0],
            **self.next_metadata("direct-conflict"),
        )
        by_digest = {
            row["object_sha256"]: row
            for row in [*composite["objects"], *direct["objects"]]
        }
        report = {
            "task_id": TASK,
            "objects": [
                {**row, "classification": "referenced", "binding_sha256s": []}
                for row in by_digest.values()
            ],
            "bindings": [
                {**composite["binding"], "classification": "pending"},
                {**direct["binding"], "classification": "pending"},
            ],
        }
        with mock.patch.object(
            objects, "inspect_semantic_objects", return_value=report
        ):
            with self.assertRaisesRegex(h.HarnessError, "multiple owning"):
                routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_permit_composite_rejects_committed_projection_entry_drift(self) -> None:
        composite = self.permit_composite()
        result_state = copy.deepcopy(composite["effect"]["result_state"])
        slot = routing.routing_outcome_slot_sha256(self.arm)
        result_state[routing.ROUTING_NAMESPACE_KEY]["entries"][slot]["packet_id"] = "packet-other"
        event = semantic.create_transition_event(
            self.events[-1],
            semantic.replay_events(self.events),
            result_state,
            event_type="permitted_packet_arm",
            command_id=composite["event"]["command_id"],
            recorded_at=composite["event"]["recorded_at"],
            authority_ref=composite["event"]["authority_ref"],
        )
        binding = objects.create_semantic_binding(
            binding_kind="permit_consumption",
            task_id=TASK,
            binding_key=composite["binding"]["binding_key"],
            expected_semantic_head_sha256=event["prev_event_sha256"],
            planned_event_sha256=event["event_sha256"],
            result_projection_sha256=event["result_projection_sha256"],
            object_sha256s=composite["binding"]["object_sha256s"],
        )
        composite["effect"]["result_state"] = result_state
        composite["event"] = event
        composite["binding"] = binding
        self.publish_permit_composite(composite)
        self.append_permit_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "projection entry"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_permit_composite_rejects_wrong_committed_event_type(self) -> None:
        composite = self.permit_composite(event_type="wrong_permitted_packet_arm")
        self.publish_permit_composite(composite)
        self.append_permit_composite(composite)
        with self.assertRaisesRegex(h.HarnessError, "event type"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_authority_outcome_terminal_commit_and_capacity_gate(self) -> None:
        self.assertEqual(
            routing.routing_capacity_view_from_store(self.paths, TASK, self.events)["rows"],
            [],
        )
        authority_result = self.commit(self.prepare_authority())
        self.assertFalse(authority_result["idempotent_replay"])
        self.assertEqual(
            routing.routing_capacity_view_from_store(self.paths, TASK, self.events)["rows"],
            [],
        )
        self.commit(self.prepare_outcome())
        self.assertEqual(
            routing.routing_capacity_view_from_store(self.paths, TASK, self.events)["rows"],
            [],
        )
        terminal_result = self.commit(self.prepare_terminal())
        stages = [
            (group["stage"], group["classification"])
            for group in terminal_result["routing_report"]["groups"]
        ]
        self.assertEqual(
            stages,
            [
                ("authority", "committed"),
                ("outcome", "committed"),
                ("terminal", "committed"),
            ],
        )
        capacity = routing.routing_capacity_view_from_store(self.paths, TASK, self.events)
        self.assertEqual(len(capacity["rows"]), 1)
        self.assertEqual(capacity["rows"][0]["packet_id"], "packet-route")

    def test_exact_committed_retry_at_head_and_after_successor_repairs_projection(self) -> None:
        transaction = self.prepare_authority()
        first = self.commit(transaction)
        event_count = len(self.events)
        retry = routing.commit_routing_transaction(self.paths, transaction, self.events)
        self.assertTrue(retry["idempotent_replay"])
        self.assertEqual(retry["event"]["event_sha256"], first["event"]["event_sha256"])
        self.assertEqual(len(self.events), event_count)

        successor = self.append_unrelated()
        h.task_state_path(self.paths, TASK).unlink()
        after_successor = routing.commit_routing_transaction(
            self.paths, transaction, self.events
        )
        self.assertTrue(after_successor["idempotent_replay"])
        self.assertEqual(
            semantic.projection_domain(after_successor["projection"])["unrelated"],
            "successor",
        )
        self.assertEqual(self.events[-1]["event_sha256"], successor["event_sha256"])
        self.assertTrue(h.task_state_path(self.paths, TASK).is_file())

    def test_objects_only_and_pending_binding_crashes_recover(self) -> None:
        authority_transaction = self.prepare_authority()
        self.publish_transaction_objects(authority_transaction)
        before = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        self.assertEqual(len(before["routing_object_sha256s"]), 1)
        self.assertEqual(before["groups"], [])
        self.commit(authority_transaction)

        outcome_transaction = self.prepare_outcome()
        self.publish_transaction_objects(outcome_transaction)
        objects.publish_semantic_binding(
            self.paths, outcome_transaction["binding"], self.events
        )
        pending = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        self.assertIn(
            ("outcome", "pending"),
            [(group["stage"], group["classification"]) for group in pending["groups"]],
        )
        recovered = self.commit(outcome_transaction)
        self.assertEqual(
            recovered["routing_report"]["groups"][-1]["classification"], "committed"
        )

        terminal_transaction = self.prepare_terminal()
        self.publish_transaction_objects(terminal_transaction)
        objects.publish_semantic_binding(
            self.paths, terminal_transaction["binding"], self.events
        )
        pending = routing.inspect_routing_persistence(self.paths, TASK, self.events)
        self.assertEqual(pending["groups"][-1]["classification"], "pending")
        recovered = self.commit(terminal_transaction)
        self.assertEqual(recovered["routing_report"]["groups"][-1]["stage"], "terminal")

    def test_event_before_projection_crash_recovers_from_exact_binding(self) -> None:
        transaction = self.prepare_authority()
        with mock.patch.object(
            store, "repair_semantic_projection", side_effect=RuntimeError("simulated crash")
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                routing.commit_routing_transaction(self.paths, transaction, self.events)

        self.events.append(transaction["planned_event"])
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(
            report["committed_binding_sha256s"],
            [transaction["binding"]["binding_sha256"]],
        )
        recovered = routing.commit_routing_transaction(
            self.paths, transaction, self.events
        )
        self.assertTrue(recovered["idempotent_replay"])
        self.assertEqual(
            semantic.projection_domain(recovered["projection"]),
            transaction["result_state"],
        )

    def test_manual_vs_observed_same_slot_is_cas_conflict_before_object_publish(self) -> None:
        self.commit(self.prepare_authority())
        manual = self.prepare_outcome()
        observed_outcome = authority.build_dispatch_outcome(
            self.arm,
            dispatch_provenance="codex_subagent_start_observed",
            observation=observation(),
            recorded_at="2026-01-01T00:02:00Z",
        )
        observed = self.prepare_outcome(observed_outcome)
        self.assertEqual(
            manual["binding"]["binding_key"], observed["binding"]["binding_key"]
        )
        self.assertNotEqual(
            manual["binding"]["binding_sha256"], observed["binding"]["binding_sha256"]
        )
        self.commit(manual)
        before = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        with self.assertRaisesRegex(h.HarnessError, "CAS slot"):
            routing.commit_routing_transaction(self.paths, observed, self.events)
        after = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(before["objects"], after["objects"])
        self.assertEqual(before["bindings"], after["bindings"])

    def test_stale_chain_and_extra_state_change_fail_before_publication(self) -> None:
        stale = self.prepare_authority()
        self.append_unrelated("head-drift")
        before = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        with self.assertRaises(h.HarnessError):
            routing.commit_routing_transaction(self.paths, stale, self.events[:-1])
        after = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(before, after)

        fresh = self.prepare_authority()
        forged = copy.deepcopy(fresh)
        forged["result_state"]["forged_unrelated"] = True
        replayed = semantic.replay_events(self.events)
        planned = semantic.create_transition_event(
            self.events[-1],
            replayed,
            forged["result_state"],
            event_type=forged["event_type"],
            command_id=forged["command_id"],
            recorded_at=forged["recorded_at"],
            authority_ref=forged["authority_ref"],
        )
        forged["planned_event"] = planned
        forged["expected_head_sha256"] = planned["prev_event_sha256"]
        forged["binding"] = objects.create_semantic_binding(
            binding_kind="packet_authority",
            task_id=TASK,
            binding_key=fresh["binding"]["binding_key"],
            expected_semantic_head_sha256=planned["prev_event_sha256"],
            planned_event_sha256=planned["event_sha256"],
            result_projection_sha256=planned["result_projection_sha256"],
            object_sha256s=fresh["binding"]["object_sha256s"],
        )
        preimage = {key: value for key, value in forged.items() if key != "transaction_sha256"}
        forged["transaction_sha256"] = semantic.canonical_sha256(
            preimage, max_bytes=routing.MAX_ROUTING_TRANSACTION_BYTES
        )
        routing.validate_routing_transaction(forged)
        with self.assertRaisesRegex(h.HarnessError, "outside its exact routing entry"):
            routing.commit_routing_transaction(self.paths, forged, self.events)

    def test_transaction_tamper_cardinality_and_cross_binding_fail_closed(self) -> None:
        self.commit(self.prepare_authority())
        transaction = self.prepare_outcome()
        malformed = copy.deepcopy(transaction)
        malformed["objects"] = malformed["objects"][:1]
        with self.assertRaises(h.HarnessError):
            routing.validate_routing_transaction(malformed)

        malformed = copy.deepcopy(transaction)
        malformed["binding"]["binding_key"] = "f" * 64
        with self.assertRaises(h.HarnessError):
            routing.validate_routing_transaction(malformed)

        terminal = routing.prepare_terminal_transaction(
            task_id=TASK,
            event_chain=[*self.events, transaction["planned_event"]],
            arm=self.arm,
            outcome=self.manual_outcome,
            terminal_status="done",
            typed_outcome="accepted",
            **self.next_metadata("tampered-terminal"),
        )
        malformed = copy.deepcopy(terminal)
        terminal_object = next(
            row for row in malformed["objects"] if row["object_type"] == "routing_terminal"
        )
        terminal_object["payload"]["routing_outcome_sha256"] = "f" * 64
        with self.assertRaises(h.HarnessError):
            routing.validate_routing_transaction(malformed)

    def test_orphan_routing_outcome_requires_immutable_authority_predecessor(self) -> None:
        transaction = routing.prepare_outcome_transaction(
            task_id=TASK,
            event_chain=[self.events[0], self.prepare_authority()["planned_event"]],
            arm=self.arm,
            outcome=self.manual_outcome,
            **self.next_metadata("orphan-outcome"),
        )
        outcome_object = next(
            row for row in transaction["objects"] if row["object_type"] == "routing_outcome"
        )
        objects.publish_semantic_object(self.paths, outcome_object)
        with self.assertRaisesRegex(h.HarnessError, "no authority object"):
            routing.inspect_routing_persistence(self.paths, TASK, self.events)

    def test_projection_and_iterator_bounds_fail_closed(self) -> None:
        transaction = self.prepare_authority()
        entry = next(
            iter(
                routing.routing_namespace_from_projection(transaction["result_state"])[
                    "entries"
                ].values()
            )
        )
        with mock.patch.object(routing, "MAX_ROUTING_ENTRY_BYTES", 100):
            with self.assertRaises(h.HarnessError):
                routing.validate_routing_entry(entry)
        namespace = {
            "schema_version": routing.ROUTING_PERSISTENCE_SCHEMA_VERSION,
            "entries": {entry["outcome_slot_sha256"]: entry},
        }
        with mock.patch.object(routing, "MAX_ROUTING_ENTRIES", 0):
            with self.assertRaisesRegex(h.HarnessError, "collection"):
                routing.validate_routing_namespace(namespace)

        consumed: list[int] = []

        def packets():
            for number in range(3):
                consumed.append(number)
                yield {
                    "packet_id": f"legacy-{number}",
                    "packet_schema_version": 5,
                    "status": "done",
                }

        with mock.patch.object(routing, "MAX_LEGACY_PACKETS", 1):
            with self.assertRaisesRegex(h.HarnessError, "count bound"):
                routing.classify_legacy_cutover(packets())
        self.assertEqual(consumed, [0, 1])

    def test_capacity_preserves_stored_legacy_and_unattempted_rows(self) -> None:
        self.commit(self.prepare_authority())
        self.commit(self.prepare_outcome())
        self.commit(self.prepare_terminal())
        legacy = authority.build_legacy_outcome(
            {
                "packet_id": "legacy-terminal",
                "packet_schema_version": 5,
                "status": "done",
                "typed_outcome": "accepted",
            },
            recorded_at="2026-01-01T00:30:00Z",
        )
        unattempted = authority.build_unattempted_v6_cancellation_outcome(
            {
                "packet_id": "v6-cancelled",
                "packet_schema_version": 6,
                "status": "cancelled",
                "typed_outcome": "cancelled",
                "dispatch_provenance": "none",
                "dispatch_attempts": [],
            },
            recorded_at="2026-01-01T00:31:00Z",
        )
        view = routing.routing_capacity_view_from_store(
            self.paths,
            TASK,
            self.events,
            legacy_outcomes=[legacy],
            unattempted_v6_outcomes=[unattempted],
        )
        self.assertEqual(
            {row["packet_id"] for row in view["rows"]},
            {"packet-route", "legacy-terminal", "v6-cancelled"},
        )

    def test_legacy_cutover_separates_terminal_migration_and_live_blockers(self) -> None:
        report = routing.classify_legacy_cutover(
            [
                {
                    "packet_id": "legacy-done",
                    "packet_schema_version": 5,
                    "status": "done",
                },
                {
                    "packet_id": "legacy-ready",
                    "packet_schema_version": 5,
                    "status": "ready",
                },
                {
                    "packet_id": "legacy-live",
                    "packet_schema_version": 5,
                    "status": "ready",
                    "dispatch_attempts": [{"status": "armed"}],
                },
                {
                    "packet_id": "packet-v6",
                    "packet_schema_version": 6,
                    "status": "ready",
                },
            ]
        )
        self.assertEqual(report["terminal_legacy_packet_ids"], ["legacy-done"])
        self.assertEqual(report["ready_legacy_migration_packet_ids"], ["legacy-ready"])
        self.assertEqual(report["active_legacy_blocker_packet_ids"], ["legacy-live"])
        self.assertEqual(report["v6_packet_ids"], ["packet-v6"])
        self.assertFalse(report["cutover_allowed"])

        allowed = routing.classify_legacy_cutover(
            [
                {
                    "packet_id": "legacy-done",
                    "packet_schema_version": 5,
                    "status": "done",
                },
                {
                    "packet_id": "packet-v6",
                    "packet_schema_version": 6,
                    "status": "ready",
                },
            ]
        )
        self.assertTrue(allowed["cutover_allowed"])


if __name__ == "__main__":
    unittest.main()
