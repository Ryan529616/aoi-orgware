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
from aoi_orgware import routing_authority as authority  # noqa: E402
from aoi_orgware import routing_persistence as routing  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_objects as objects  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.test_routing_authority import observation, root_arm  # noqa: E402


TASK = "task-1"


class RoutingPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "aoi.toml").write_text(
            default_config_text("Routing persistence"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        h.task_dir(self.paths, TASK).mkdir(parents=True)
        self.domain: dict[str, object] = {"task_id": TASK, "stage": 0}
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
            with self.assertRaisesRegex(h.HarnessError, "non-routing"):
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
