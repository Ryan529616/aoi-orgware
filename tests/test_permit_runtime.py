"""Adversarial integration tests for atomic one-shot permit consumption."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import itertools
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "src"))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import permit_runtime as runtime  # noqa: E402
from aoi_orgware import routing_authority as authority  # noqa: E402
from aoi_orgware import routing_persistence as routing  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_objects as objects  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware import transition_permits as permits  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.test_routing_authority import root_arm  # noqa: E402


TASK = "task-1"
NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


class PermitRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "aoi.toml").write_text(
            default_config_text("Permit runtime"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        self.credential_temp = tempfile.TemporaryDirectory()
        self.credential_home = Path(self.credential_temp.name) / "credentials"
        with h.state_lock(self.paths, create_layout=True):
            h.task_dir(self.paths, TASK).mkdir(parents=True)
            store.initialize_semantic_task(
                self.paths,
                {"task_id": TASK, "stage": 0},
                command_id="permit-runtime-genesis",
                recorded_at="2026-07-18T12:00:00Z",
                authority_ref="test",
            )
            self.chief, self.credential_path = h.acquire_chief_authority(
                self.paths,
                session_id="session-1",
                ttl_seconds=3600,
                credential_home=self.credential_home,
                now=NOW,
            )
        self.events = store.load_semantic_events(self.paths, TASK)
        self.command = 0

    def tearDown(self) -> None:
        self.credential_temp.cleanup()
        self.temp.cleanup()

    def make_transaction(
        self,
        *,
        packet_id: str = "packet-route",
        expires_at: str = "2026-07-18T12:10:00Z",
        nonce: str | None = None,
        chief_authority: dict[str, object] | None = None,
        decision_task_id: str = TASK,
        decision_packet_id: str | None = None,
        technical_payload_sha256: str | None = None,
    ) -> dict[str, object]:
        self.command += 1
        arm = root_arm(packet_id)
        arm["attempt_identity"].update(
            {
                "armed_at": "2026-07-18T12:00:00Z",
                "expires_at": "2026-07-18T12:15:00Z",
            }
        )
        arm["chief_authority"]["authority_sha256"] = semantic.canonical_sha256(
            self.chief
        )
        arm = authority.validate_arm_authority(arm)
        arm_sha = authority.authority_sha256(arm)
        contract_packet = decision_packet_id or packet_id
        decision = permits.seal_transition_decision(
            {
                "schema_version": 1,
                "task_id": decision_task_id,
                "action": "packet.arm",
                "target_ids": [contract_packet],
                "parameters": {
                    "packet_id": contract_packet,
                    "packet_schema_version": 6,
                    "routing_authority_sha256": arm_sha,
                },
                "technical_payload_sha256": technical_payload_sha256 or arm_sha,
            }
        )
        permit = permits.seal_transition_permit(
            {
                "schema_version": 1,
                "task_id": decision_task_id,
                "expected_semantic_head_sha256": self.events[-1]["event_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "action": decision["action"],
                "target_ids": decision["target_ids"],
                "parameters": decision["parameters"],
                "expires_at": expires_at,
                "nonce": nonce or f"permit-runtime-nonce-{self.command:04d}",
                "chief_authority": chief_authority
                or {
                    "session_id": self.chief["session_id"],
                    "epoch": self.chief["epoch"],
                },
            }
        )
        return runtime.prepare_permitted_arm_transaction(
            task_id=TASK,
            event_chain=self.events,
            decision=decision,
            permit=permit,
            arm=arm,
            command_id=f"permit-runtime-{self.command}",
            recorded_at=f"2026-07-18T12:{self.command:02d}:00Z",
        )

    def commit(
        self, transaction: dict[str, object], *, current_time: datetime | None = None
    ) -> dict[str, object]:
        with h.state_lock(self.paths, create_layout=False):
            result = runtime.commit_permitted_arm_transaction(
                self.paths,
                transaction,
                store.load_semantic_events(self.paths, TASK),
                current_time=current_time or NOW + timedelta(minutes=5),
            )
        self.events = store.load_semantic_events(self.paths, TASK)
        return result

    def issue(
        self, transaction: dict[str, object], *, current_time: datetime | None = None
    ) -> dict[str, object]:
        planned_time = datetime.fromisoformat(
            str(transaction["recorded_at"]).replace("Z", "+00:00")
        )
        with h.state_lock(self.paths, create_layout=False):
            token, _loaded = h.load_chief_credential(
                self.paths,
                session_id=self.chief["session_id"],
                epoch=self.chief["epoch"],
                credential_file=self.credential_path,
            )
            result = runtime.issue_permitted_arm_transaction(
                self.paths,
                transaction,
                store.load_semantic_events(self.paths, TASK),
                chief_session_id=self.chief["session_id"],
                chief_epoch=self.chief["epoch"],
                chief_token=token,
                current_time=current_time or planned_time,
            )
        self.events = store.load_semantic_events(self.paths, TASK)
        return result

    def publish_pending_binding(self, transaction: dict[str, object]) -> None:
        with h.state_lock(self.paths, create_layout=False):
            for wrapped in transaction["objects"]:
                objects.publish_semantic_object(self.paths, wrapped)
            objects.publish_semantic_binding(
                self.paths, transaction["binding"], self.events
            )

    def append_unrelated(self, label: str) -> None:
        with h.state_lock(self.paths, create_layout=False):
            records = store.load_semantic_events(self.paths, TASK)
            result = semantic.projection_domain(semantic.replay_events(records))
            result["unrelated"] = label
            store.append_semantic_transition(
                self.paths,
                TASK,
                result,
                event_type="unrelated_test",
                command_id=f"unrelated-{label}",
                recorded_at="2026-07-18T12:20:00Z",
                authority_ref="test",
                expected_head_sha256=records[-1]["event_sha256"],
            )
        self.events = store.load_semantic_events(self.paths, TASK)

    def reseal_transaction(
        self,
        original: dict[str, object],
        result_state: dict[str, object],
        *,
        event_type: str = "permitted_packet_arm",
    ) -> dict[str, object]:
        transaction = copy.deepcopy(original)
        planned = semantic.create_transition_event(
            self.events[-1],
            semantic.replay_events(self.events),
            result_state,
            event_type=event_type,
            command_id=transaction["command_id"],
            recorded_at=transaction["recorded_at"],
            authority_ref=transaction["authority_ref"],
        )
        old_binding = transaction["binding"]
        binding = objects.create_semantic_binding(
            binding_kind="permit_consumption",
            task_id=TASK,
            binding_key=old_binding["binding_key"],
            expected_semantic_head_sha256=planned["prev_event_sha256"],
            planned_event_sha256=planned["event_sha256"],
            result_projection_sha256=planned["result_projection_sha256"],
            object_sha256s=old_binding["object_sha256s"],
        )
        transaction.update(
            {
                "event_type": event_type,
                "expected_head_sha256": planned["prev_event_sha256"],
                "result_state": result_state,
                "planned_event": planned,
                "binding": binding,
            }
        )
        transaction["transaction_sha256"] = semantic.canonical_sha256(
            {
                key: value
                for key, value in transaction.items()
                if key != "transaction_sha256"
            },
            max_bytes=runtime.MAX_PERMIT_TRANSACTION_BYTES,
        )
        return transaction

    def test_prepare_is_exact_compact_and_contains_no_live_secret(self) -> None:
        transaction = self.make_transaction()
        self.assertEqual(
            runtime.validate_permitted_arm_transaction(transaction), transaction
        )
        self.assertEqual(
            [row["object_type"] for row in transaction["objects"]],
            ["routing_authority", "transition_decision", "transition_permit"],
        )
        self.assertEqual(transaction["binding"]["binding_kind"], "permit_consumption")
        self.assertEqual(len(transaction["binding"]["object_sha256s"]), 3)
        self.assertLess(
            len(semantic.canonical_json_bytes(transaction)),
            runtime.MAX_PERMIT_TRANSACTION_BYTES,
        )

        serialized = json.dumps(transaction, sort_keys=True)
        for forbidden in (
            "Bearer ",
            "BEGIN PRIVATE KEY",
            str(self.credential_home),
            str(self.credential_path),
            "C:\\\\",
            "/home/",
        ):
            self.assertNotIn(forbidden, serialized)

        reordered = copy.deepcopy(transaction)
        reordered["objects"].reverse()
        reordered["transaction_sha256"] = semantic.canonical_sha256(
            {key: value for key, value in reordered.items() if key != "transaction_sha256"},
            max_bytes=runtime.MAX_PERMIT_TRANSACTION_BYTES,
        )
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "binding contract"):
            runtime.validate_permitted_arm_transaction(reordered)

    def test_controller_cannot_mint_without_chief_issued_objects(self) -> None:
        transaction = self.make_transaction()
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "durably issued"):
            self.commit(transaction)
        empty = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(empty["objects"], [])
        self.assertEqual(empty["bindings"], [])

        with h.state_lock(self.paths, create_layout=False):
            with self.assertRaisesRegex(runtime.PermitRuntimeError, "live Chief"):
                runtime.issue_permitted_arm_transaction(
                    self.paths,
                    transaction,
                    store.load_semantic_events(self.paths, TASK),
                    chief_session_id=self.chief["session_id"],
                    chief_epoch=self.chief["epoch"],
                    chief_token="invalid-chief-token",
                    current_time=NOW + timedelta(minutes=1),
                )
        still_empty = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(still_empty["objects"], [])

        receipt = self.issue(transaction)
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("token", serialized.lower())
        self.assertNotIn(str(self.credential_path), serialized)
        marker_path = runtime.permit_issuance_path(
            self.paths, TASK, receipt["permit_sha256"]
        )
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        self.assertEqual(runtime.validate_permit_issuance(marker), marker)
        marker_text = marker_path.read_text(encoding="utf-8")
        for forbidden in (
            "Bearer ",
            "BEGIN PRIVATE KEY",
            str(self.credential_home),
            str(self.credential_path),
            "C:\\",
            "/home/",
        ):
            self.assertNotIn(forbidden, marker_text)
        replay = self.issue(
            transaction, current_time=NOW + timedelta(minutes=2)
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["issuance_sha256"], receipt["issuance_sha256"])
        report = runtime.inspect_permit_runtime(self.paths, TASK, self.events)
        self.assertEqual(report["issuances"][0]["classification"], "issued")
        result = self.commit(transaction)
        self.assertFalse(result["idempotent_replay"])

    def test_objects_without_a_chief_issuance_marker_are_not_consumable(self) -> None:
        transaction = self.make_transaction(packet_id="packet-objects-crash")
        with h.state_lock(self.paths, create_layout=False):
            for wrapped in transaction["objects"]:
                objects.publish_semantic_object(self.paths, wrapped)
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "issuance marker"):
            self.commit(transaction)
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(len(report["orphan_object_sha256s"]), 3)

        issued = self.issue(
            transaction, current_time=NOW + timedelta(minutes=2)
        )
        self.assertFalse(issued["idempotent_replay"])
        committed = self.commit(transaction)
        self.assertFalse(committed["idempotent_replay"])

    def test_tampered_marker_and_missing_referenced_object_fail_closed(self) -> None:
        transaction = self.make_transaction(packet_id="packet-marker-tamper")
        receipt = self.issue(transaction)
        marker_path = runtime.permit_issuance_path(
            self.paths, TASK, receipt["permit_sha256"]
        )
        original = marker_path.read_bytes()
        tampered = json.loads(original.decode("utf-8"))
        tampered["transaction_sha256"] = "f" * 64
        tampered["issuance_sha256"] = semantic.canonical_sha256(
            {
                key: value
                for key, value in tampered.items()
                if key != "issuance_sha256"
            },
            max_bytes=runtime.MAX_PERMIT_ISSUANCE_BYTES,
        )
        marker_path.write_bytes(semantic.canonical_json_bytes(tampered))
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "exact transaction"):
            self.commit(transaction)

        marker_path.write_bytes(original)
        missing_digest = transaction["objects"][0]["object_sha256"]
        objects.semantic_object_path(self.paths, TASK, missing_digest).unlink()
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "missing semantic object"):
            runtime.inspect_permit_runtime(self.paths, TASK, self.events)

    def test_marker_schema_and_store_bounds_fail_closed(self) -> None:
        transaction = self.make_transaction(packet_id="packet-marker-bounds")
        receipt = self.issue(transaction)
        marker_path = runtime.permit_issuance_path(
            self.paths, TASK, receipt["permit_sha256"]
        )
        marker = json.loads(marker_path.read_text(encoding="utf-8"))

        wrong_version = copy.deepcopy(marker)
        wrong_version["schema_version"] = 1.0
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "version"):
            runtime.validate_permit_issuance(wrong_version)
        noncanonical_time = copy.deepcopy(marker)
        noncanonical_time["issued_at"] = noncanonical_time["issued_at"].replace(
            ".000000Z", "Z"
        )
        noncanonical_time["issuance_sha256"] = semantic.canonical_sha256(
            {
                key: value
                for key, value in noncanonical_time.items()
                if key != "issuance_sha256"
            },
            max_bytes=runtime.MAX_PERMIT_ISSUANCE_BYTES,
        )
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "canonical UTC"):
            runtime.validate_permit_issuance(noncanonical_time)
        mixed_references = copy.deepcopy(marker)
        mixed_references["object_sha256s"][0] = 1
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "references"):
            runtime.validate_permit_issuance(mixed_references)
        float_epoch = copy.deepcopy(marker)
        float_epoch["issuer_chief_authority"]["epoch"] = 1.0
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "epoch"):
            runtime.validate_permit_issuance(float_epoch)

        with mock.patch.object(runtime, "MAX_PERMIT_ISSUANCES", 0):
            with self.assertRaisesRegex(runtime.PermitRuntimeError, "count bound"):
                runtime.inspect_permit_runtime(self.paths, TASK, self.events)
        with mock.patch.object(runtime, "MAX_PERMIT_ISSUANCE_AGGREGATE_BYTES", 1):
            with self.assertRaisesRegex(runtime.PermitRuntimeError, "aggregate"):
                runtime.inspect_permit_runtime(self.paths, TASK, self.events)

        residue = marker_path.parent / "residue.txt"
        residue.write_text("unmanaged", encoding="utf-8")
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "unexpected entry"):
            runtime.inspect_permit_runtime(self.paths, TASK, self.events)

    def test_commit_inspection_and_exact_retry_survive_a_successor(self) -> None:
        transaction = self.make_transaction()
        self.issue(transaction)
        first = self.commit(transaction)
        self.assertFalse(first["idempotent_replay"])
        second = self.commit(transaction)
        self.assertTrue(second["idempotent_replay"])

        self.append_unrelated("after-permit")
        third = self.commit(transaction)
        self.assertTrue(third["idempotent_replay"])
        self.assertEqual(
            sum(event["command_id"] == transaction["command_id"] for event in self.events),
            1,
        )
        report = runtime.inspect_permit_runtime(self.paths, TASK, self.events)
        self.assertEqual(len(report["consumptions"]), 1)
        self.assertEqual(report["consumptions"][0]["classification"], "committed")
        projection = semantic.projection_domain(semantic.replay_events(self.events))
        self.assertEqual(projection["unrelated"], "after-permit")

    def test_new_consumption_rejects_expiry_wrong_chief_and_stale_head(self) -> None:
        expired = self.make_transaction(expires_at="2026-07-18T12:10:00Z")
        self.issue(expired)
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "expired"):
            self.commit(expired, current_time=NOW + timedelta(minutes=11))

        expired_arm = self.make_transaction()
        self.issue(expired_arm)
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "routing arm"):
            self.commit(expired_arm, current_time=NOW + timedelta(minutes=16))

        with self.assertRaisesRegex(runtime.PermitRuntimeError, "routing authority"):
            self.make_transaction(
                chief_authority={"session_id": "another-chief", "epoch": 7}
            )
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "routing authority"):
            self.make_transaction(expires_at="2026-07-18T12:20:00Z")

        stale = self.make_transaction()
        self.issue(stale)
        self.append_unrelated("make-stale")
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "semantic head"):
            self.commit(stale)

        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(report["bindings"], [])
        self.assertGreaterEqual(len(report["objects"]), 3)
        self.assertEqual(
            runtime.permit_namespace_from_projection(semantic.replay_events(self.events))[
                "consumptions"
            ],
            {},
        )

    def test_actual_chief_change_fences_an_old_permit_before_publication(self) -> None:
        transaction = self.make_transaction()
        self.issue(transaction)
        with h.state_lock(self.paths, create_layout=False):
            token, _loaded = h.load_chief_credential(
                self.paths,
                session_id=self.chief["session_id"],
                epoch=self.chief["epoch"],
                credential_file=self.credential_path,
            )
            h.release_chief_authority(
                self.paths,
                session_id=self.chief["session_id"],
                epoch=self.chief["epoch"],
                token=token,
                reason="permit takeover test",
                now=NOW + timedelta(minutes=1),
            )
            h.acquire_chief_authority(
                self.paths,
                session_id="session-2",
                ttl_seconds=3600,
                credential_home=self.credential_home,
                now=NOW + timedelta(minutes=2),
            )
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "chief_authority"):
            self.commit(transaction, current_time=NOW + timedelta(minutes=3))
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(report["bindings"], [])

    def test_contract_rejects_cross_task_packet_and_payload(self) -> None:
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "this task"):
            self.make_transaction(decision_task_id="other-task")
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "routing authority"):
            self.make_transaction(decision_packet_id="other-packet")
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "technical payload"):
            self.make_transaction(technical_payload_sha256="f" * 64)

    def test_objects_only_and_pending_binding_crashes_are_recoverable(self) -> None:
        objects_only = self.make_transaction(packet_id="packet-objects-only")
        self.issue(objects_only)
        first = self.commit(objects_only)
        self.assertFalse(first["idempotent_replay"])

        pending = self.make_transaction(
            packet_id="packet-pending",
            expires_at="2026-07-18T12:10:00Z",
        )
        self.issue(pending)
        self.publish_pending_binding(pending)
        pending_report = runtime.inspect_permit_runtime(
            self.paths, TASK, self.events
        )
        self.assertEqual(
            {
                row["permit_sha256"]: row["classification"]
                for row in pending_report["issuances"]
            }[pending["objects"][2]["payload"]["permit_sha256"]],
            "reserved",
        )
        second = self.commit(pending, current_time=NOW + timedelta(minutes=20))
        self.assertFalse(second["idempotent_replay"])
        report = runtime.inspect_permit_runtime(self.paths, TASK, self.events)
        self.assertEqual(len(report["consumptions"]), 2)
        self.assertEqual(
            {row["classification"] for row in report["consumptions"]}, {"committed"}
        )

    def test_committed_event_repairs_a_lost_projection(self) -> None:
        transaction = self.make_transaction()
        self.issue(transaction)
        old_projection = h.task_state_path(self.paths, TASK).read_bytes()
        self.publish_pending_binding(transaction)
        with h.state_lock(self.paths, create_layout=False):
            appended = store.append_semantic_transition(
                self.paths,
                TASK,
                transaction["result_state"],
                event_type=transaction["event_type"],
                command_id=transaction["command_id"],
                recorded_at=transaction["recorded_at"],
                authority_ref=transaction["authority_ref"],
                expected_head_sha256=transaction["expected_head_sha256"],
            )
            self.assertEqual(
                appended.event["event_sha256"], transaction["planned_event"]["event_sha256"]
            )
            h.atomic_write_bytes(h.task_state_path(self.paths, TASK), old_projection)
        self.events = store.load_semantic_events(self.paths, TASK)
        self.assertEqual(store.semantic_projection_status(self.paths, TASK), "behind")

        recovered = self.commit(transaction, current_time=NOW + timedelta(minutes=40))
        self.assertTrue(recovered["idempotent_replay"])
        self.assertEqual(store.semantic_projection_status(self.paths, TASK), "current")

    def test_resealed_tampering_cannot_expand_the_transition(self) -> None:
        transaction = self.make_transaction()

        extra = copy.deepcopy(transaction["result_state"])
        extra["unrelated_write"] = {"not": "authorized"}
        widened = self.reseal_transaction(transaction, extra)
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "namespaces"):
            runtime.validate_permitted_arm_transaction(widened)

        wrong_route = copy.deepcopy(transaction["result_state"])
        route_namespace = wrong_route[routing.ROUTING_NAMESPACE_KEY]
        route_entry = next(iter(route_namespace["entries"].values()))
        route_entry["packet_id"] = "wrong-packet"
        wrong_route_tx = self.reseal_transaction(transaction, wrong_route)
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "routing projection"):
            runtime.validate_permitted_arm_transaction(wrong_route_tx)

        wrong_event = self.reseal_transaction(
            transaction,
            copy.deepcopy(transaction["result_state"]),
            event_type="unrelated_test",
        )
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "event cross-binding"):
            runtime.validate_permitted_arm_transaction(wrong_event)

        enveloped = copy.deepcopy(transaction)
        enveloped["result_state"][semantic.SEMANTIC_ENVELOPE_KEY] = {
            "schema_version": 1,
            "sequence": 99,
            "head_event_sha256": "a" * 64,
            "domain_sha256": "b" * 64,
        }
        enveloped["transaction_sha256"] = semantic.canonical_sha256(
            {key: value for key, value in enveloped.items() if key != "transaction_sha256"},
            max_bytes=runtime.MAX_PERMIT_TRANSACTION_BYTES,
        )
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "domain projection"):
            runtime.validate_permitted_arm_transaction(enveloped)

    def test_replay_marker_count_byte_and_iterable_bounds_fail_closed(self) -> None:
        transaction = self.make_transaction()
        namespace = transaction["result_state"][runtime.PERMIT_NAMESPACE_KEY]
        receipt = next(iter(namespace["consumptions"].values()))
        identity = next(iter(namespace["consumptions"]))
        marker = receipt["replay_marker"]

        mismatched = copy.deepcopy(namespace)
        mismatched["replay_markers"][marker] = "f" * 64
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "cross-binding"):
            runtime.validate_permit_namespace(mismatched)

        with mock.patch.object(runtime, "MAX_PERMIT_CONSUMPTIONS", 0):
            with self.assertRaisesRegex(runtime.PermitRuntimeError, "over bound"):
                runtime.validate_permit_namespace(namespace)
        with mock.patch.object(runtime, "MAX_PERMIT_NAMESPACE_BYTES", 100):
            with self.assertRaises(runtime.PermitRuntimeError):
                runtime.validate_permit_namespace(namespace)

        self.assertEqual(namespace["replay_markers"][marker], identity)
        with mock.patch.object(semantic, "MAX_LEDGER_EVENTS", 1):
            with self.assertRaisesRegex(runtime.PermitRuntimeError, "count bound"):
                runtime.prepare_permitted_arm_transaction(
                    task_id=TASK,
                    event_chain=itertools.repeat(self.events[0]),
                    decision=transaction["objects"][1]["payload"],
                    permit=transaction["objects"][2]["payload"],
                    arm=transaction["objects"][0]["payload"],
                    command_id="bounded-generator",
                    recorded_at="2026-07-18T12:59:00Z",
                )

    def test_global_replay_marker_blocks_a_second_permit(self) -> None:
        nonce = "permit-runtime-replay-global"
        first = self.make_transaction(packet_id="packet-first", nonce=nonce)
        self.issue(first)
        second = self.make_transaction(packet_id="packet-second", nonce=nonce)
        with self.assertRaisesRegex(runtime.PermitRuntimeError, "replay marker"):
            self.issue(second)
        self.commit(first)

    def test_two_real_lock_contenders_publish_one_event(self) -> None:
        transaction = self.make_transaction()
        self.issue(transaction)
        barrier = threading.Barrier(2)

        def consume() -> dict[str, object]:
            barrier.wait(timeout=10)
            with h.state_lock(self.paths, create_layout=False):
                return runtime.commit_permitted_arm_transaction(
                    self.paths,
                    transaction,
                    store.load_semantic_events(self.paths, TASK),
                    current_time=NOW + timedelta(minutes=5),
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: consume(), range(2)))
        self.events = store.load_semantic_events(self.paths, TASK)
        self.assertEqual(
            sum(event["command_id"] == transaction["command_id"] for event in self.events),
            1,
        )
        self.assertEqual(
            sorted(result["idempotent_replay"] for result in results), [False, True]
        )


if __name__ == "__main__":
    unittest.main()
