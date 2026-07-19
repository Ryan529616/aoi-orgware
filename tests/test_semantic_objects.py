"""Adversarial filesystem tests for immutable semantic object storage."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "src"))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_objects as objects  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402


TASK = "semantic-objects"


class SemanticObjectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "aoi.toml").write_text(default_config_text("Semantic objects"), encoding="utf-8")
        self.paths = h.get_paths(self.root)
        h.task_dir(self.paths, TASK).mkdir(parents=True)
        self.domain = {"task_id": TASK, "stage": 0}
        self.events = [
            semantic.create_genesis_event(
                self.domain,
                command_id="semantic-objects-genesis",
                recorded_at="2026-07-18T00:00:00+00:00",
                authority_ref="test",
            )
        ]
        store.initialize_semantic_task(
            self.paths,
            self.domain,
            command_id="semantic-objects-genesis",
            recorded_at="2026-07-18T00:00:00+00:00",
            authority_ref="test",
        )
        self.plan_number = 0
        self.lock = mock.patch.object(h, "_require_chief_lock")
        self.lock.start()

    def tearDown(self) -> None:
        self.lock.stop()
        self.temp.cleanup()

    def object(self, identity: str, payload: object, kind: str = "routing_outcome") -> dict[str, object]:
        return objects.create_semantic_object(
            object_type=kind, task_id=TASK, object_identity=identity, payload=payload
        )

    def planned_event(self, label: str) -> tuple[dict[str, object], dict[str, object]]:
        self.plan_number += 1
        result = {"task_id": TASK, "stage": self.plan_number, "label": label}
        event = semantic.create_transition_event(
            self.events[-1],
            self.domain,
            result,
            event_type="binding_test",
            command_id=f"semantic-objects-{self.plan_number}",
            recorded_at=f"2026-07-18T00:00:{self.plan_number:02d}+00:00",
            authority_ref="test",
        )
        return event, result

    def commit(self, event: dict[str, object], result: dict[str, object]) -> None:
        appended = store.append_semantic_transition(
            self.paths,
            TASK,
            result,
            event_type=event["event_type"],  # type: ignore[arg-type]
            command_id=event["command_id"],  # type: ignore[arg-type]
            recorded_at=event["recorded_at"],  # type: ignore[arg-type]
            authority_ref=event["authority_ref"],  # type: ignore[arg-type]
            expected_head_sha256=event["prev_event_sha256"],  # type: ignore[arg-type]
        )
        self.assertEqual(appended.event["event_sha256"], event["event_sha256"])
        self.events.append(appended.event)
        self.domain = result

    def binding(
        self,
        key: str,
        digests: list[str],
        *,
        kind: str = "outcome_slot",
        event: dict[str, object] | None = None,
    ) -> dict[str, object]:
        event = event or self.planned_event(key)[0]
        return objects.create_semantic_binding(
            binding_kind=kind,
            task_id=TASK,
            binding_key=key,
            expected_semantic_head_sha256=event["prev_event_sha256"],
            planned_event_sha256=event["event_sha256"],
            result_projection_sha256=event["result_projection_sha256"],
            object_sha256s=digests,
        )

    def publish_object(self, identity: str, payload: object, kind: str = "routing_outcome") -> dict[str, object]:
        return objects.publish_semantic_object(self.paths, self.object(identity, payload, kind))

    def test_exact_object_retry_and_caller_mutation_are_isolated(self) -> None:
        candidate = self.object("route-1", {"rows": [1, 2]})
        first = objects.publish_semantic_object(self.paths, candidate)
        candidate["payload"]["rows"].append(3)  # type: ignore[index]
        second = objects.publish_semantic_object(self.paths, first)
        self.assertEqual(first, second)
        first["payload"]["rows"].append(4)  # type: ignore[index]
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(report["objects"][0]["payload"], {"rows": [1, 2]})
        self.assertEqual(report["orphan_object_sha256s"], [first["object_sha256"]])

    def test_transition_permit_is_a_registered_bounded_small_object(self) -> None:
        self.assertIn("transition_permit", objects.OBJECT_TYPES)
        self.assertIn("transition_permit", objects.SMALL_OBJECT_TYPES)
        candidate = self.object(
            "a" * 64,
            {"permit_sha256": "a" * 64},
            "transition_permit",
        )
        stored = objects.publish_semantic_object(self.paths, candidate)
        self.assertEqual(stored, candidate)

        with mock.patch.object(objects, "MAX_SMALL_OBJECT_BYTES", 100):
            with self.assertRaises(objects.SemanticObjectError):
                self.object("b" * 64, "x" * 200, "transition_permit")

    def test_cohort_plan_wrapper_has_a_distinct_payload_safe_bound(self) -> None:
        self.assertIn("cohort_plan", objects.OBJECT_TYPES)
        self.assertNotIn("cohort_plan", objects.SMALL_OBJECT_TYPES)
        candidate = self.object(
            "c" * 64,
            {"padding": "x" * 65_500},
            "cohort_plan",
        )
        stored = objects.publish_semantic_object(self.paths, candidate)
        self.assertEqual(stored, candidate)
        with mock.patch.object(objects, "MAX_COHORT_OBJECT_BYTES", 100):
            with self.assertRaises(objects.SemanticObjectError):
                self.object("d" * 64, "x" * 200, "cohort_plan")

    def test_exact_binding_retry_and_divergent_same_key_fails(self) -> None:
        item = self.publish_object("route-1", {"answer": 7})
        first = objects.publish_semantic_binding(
            self.paths, self.binding("route:1", [item["object_sha256"]]), self.events
        )
        self.assertEqual(first, objects.publish_semantic_binding(self.paths, first, self.events))
        divergent = self.binding("route:1", [item["object_sha256"]])
        with self.assertRaisesRegex(objects.SemanticObjectError, "collision"):
            objects.publish_semantic_binding(self.paths, divergent, self.events)

    def test_mutation_gates_require_the_existing_state_lock_assertion(self) -> None:
        self.lock.stop()
        with self.assertRaisesRegex(objects.SemanticObjectError, "state lock"):
            objects.publish_semantic_object(self.paths, self.object("locked", {}))
        with self.assertRaisesRegex(objects.SemanticObjectError, "state lock"):
            objects.require_no_pending_bindings(self.paths, TASK, self.events)
        self.lock = mock.patch.object(h, "_require_chief_lock")
        self.lock.start()

    def test_preflight_missing_reference_publishes_no_binding(self) -> None:
        binding = self.binding("route:missing", ["c" * 64])
        path = objects.semantic_binding_path(self.paths, TASK, "outcome_slot", "route:missing")
        with self.assertRaisesRegex(objects.SemanticObjectError, "missing"):
            objects.publish_semantic_binding(self.paths, binding, self.events)
        self.assertFalse(path.exists())

    def test_binding_preflight_validates_every_object_and_object_store_limits(self) -> None:
        referenced = self.publish_object("referenced", {"answer": 1})
        unreferenced = self.publish_object("unreferenced", {"answer": 2})
        binding = self.binding("full-namespace", [referenced["object_sha256"]])
        destination = objects.semantic_binding_path(self.paths, TASK, "outcome_slot", "full-namespace")

        tampered_path = objects.semantic_object_path(self.paths, TASK, unreferenced["object_sha256"])
        tampered = dict(unreferenced)
        tampered["payload"] = {"answer": "tampered"}
        tampered_path.write_bytes(semantic.canonical_json_bytes(tampered))
        with self.assertRaisesRegex(objects.SemanticObjectError, "payload SHA"):
            objects.publish_semantic_binding(self.paths, binding, self.events)
        self.assertFalse(destination.exists())

        tampered_path.write_bytes(semantic.canonical_json_bytes(unreferenced))
        with mock.patch.object(objects, "MAX_OBJECTS_PER_TASK", 1):
            with self.assertRaisesRegex(objects.SemanticObjectError, "object count"):
                objects.publish_semantic_binding(self.paths, binding, self.events)
        aggregate = sum(
            objects.semantic_object_path(self.paths, TASK, item["object_sha256"]).stat().st_size
            for item in (referenced, unreferenced)
        )
        with mock.patch.object(objects, "MAX_OBJECT_AGGREGATE_BYTES", aggregate - 1):
            with self.assertRaisesRegex(objects.SemanticObjectError, "aggregate"):
                objects.publish_semantic_binding(self.paths, binding, self.events)
        self.assertFalse(destination.exists())

    def test_empty_object_root_is_recoverable_only_for_object_publication(self) -> None:
        root = h.task_dir(self.paths, TASK) / "semantic-objects"
        root.mkdir()
        if os.name != "nt":
            root.chmod(0o700)
        binding = self.binding("incomplete-store", ["c" * 64])
        binding_path = objects.semantic_binding_path(self.paths, TASK, "outcome_slot", "incomplete-store")
        with self.assertRaisesRegex(objects.SemanticObjectError, "missing SHA-256 root"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)
        with self.assertRaisesRegex(objects.SemanticObjectError, "missing SHA-256 root"):
            objects.publish_semantic_binding(self.paths, binding, self.events)
        self.assertFalse(binding_path.exists())
        candidate = self.object("interrupted-first-create", {})
        stored = objects.publish_semantic_object(self.paths, candidate)
        self.assertEqual(stored, candidate)
        self.assertTrue((root / "sha256").is_dir())

    def test_object_root_requires_sha256_to_be_a_real_private_directory(self) -> None:
        root = h.task_dir(self.paths, TASK) / "semantic-objects"
        root.mkdir()
        if os.name != "nt":
            root.chmod(0o700)
        (root / "sha256").write_text("not a directory", encoding="utf-8")
        candidate = self.object("fake-sha-root", {})
        with self.assertRaisesRegex(objects.SemanticObjectError, "SHA-256 root"):
            objects.publish_semantic_object(self.paths, candidate)
        self.assertFalse(objects.semantic_object_path(self.paths, TASK, candidate["object_sha256"]).exists())

    def test_object_root_rejects_unexpected_residue(self) -> None:
        self.publish_object("existing", {})
        root = h.task_dir(self.paths, TASK) / "semantic-objects"
        (root / "residue.txt").write_text("not managed", encoding="utf-8")
        candidate = self.object("must-not-publish", {})
        with self.assertRaisesRegex(objects.SemanticObjectError, "root has an unexpected entry"):
            objects.publish_semantic_object(self.paths, candidate)
        self.assertFalse(objects.semantic_object_path(self.paths, TASK, candidate["object_sha256"]).exists())

    def test_object_aggregate_bound_applies_to_exact_retry(self) -> None:
        stored = self.publish_object("aggregate-retry", {"row": 1})
        path = objects.semantic_object_path(self.paths, TASK, stored["object_sha256"])
        with mock.patch.object(objects, "MAX_OBJECT_AGGREGATE_BYTES", path.stat().st_size - 1):
            with self.assertRaisesRegex(objects.SemanticObjectError, "aggregate"):
                objects.publish_semantic_object(self.paths, stored)

    def test_tamper_wrong_filename_and_missing_reference_fail_closed(self) -> None:
        item = self.publish_object("route-1", {"answer": 7})
        path = objects.semantic_object_path(self.paths, TASK, item["object_sha256"])
        tampered = dict(item)
        tampered["payload"] = {"answer": 8}
        path.write_bytes(semantic.canonical_json_bytes(tampered))
        with self.assertRaisesRegex(objects.SemanticObjectError, "payload SHA"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

        path.write_bytes(semantic.canonical_json_bytes(item))
        wrong = path.with_name("f" * 64 + ".json")
        os.replace(path, wrong)
        with self.assertRaisesRegex(objects.SemanticObjectError, "filename|unexpected"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

        os.replace(wrong, path)
        manual = self.binding("route:manual-missing", ["d" * 64])
        target = objects.semantic_binding_path(self.paths, TASK, "outcome_slot", "route:manual-missing")
        binding_root = h.task_dir(self.paths, TASK) / "semantic-bindings"
        for directory in (binding_root, binding_root / "outcome_slot", target.parent):
            directory.mkdir(exist_ok=True)
            if os.name != "nt":
                directory.chmod(0o700)
        h.atomic_create_bytes(target, semantic.canonical_json_bytes(manual))
        with self.assertRaisesRegex(objects.SemanticObjectError, "missing object"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

    def test_count_aggregate_and_byte_bounds_reject_before_publication(self) -> None:
        with mock.patch.object(objects, "MAX_OBJECT_BYTES", 100):
            with self.assertRaises(objects.SemanticObjectError):
                self.object("too-big", "x" * 200)
        with mock.patch.object(objects, "MAX_SMALL_OBJECT_BYTES", 100):
            with self.assertRaises(objects.SemanticObjectError):
                self.object("small-too-big", "x" * 200, "routing_terminal")
        with mock.patch.object(objects, "MAX_BINDING_BYTES", 100):
            with self.assertRaises(objects.SemanticObjectError):
                self.binding("binding-too-big", ["a" * 64])

        candidate = self.object("count", {})
        with mock.patch.object(objects, "MAX_OBJECTS_PER_TASK", 0):
            with self.assertRaisesRegex(objects.SemanticObjectError, "count"):
                objects.publish_semantic_object(self.paths, candidate)
        self.assertFalse(objects.semantic_object_path(self.paths, TASK, candidate["object_sha256"]).exists())
        with mock.patch.object(objects, "MAX_OBJECT_AGGREGATE_BYTES", 1):
            with self.assertRaisesRegex(objects.SemanticObjectError, "aggregate"):
                objects.publish_semantic_object(self.paths, candidate)
        self.assertFalse(objects.semantic_object_path(self.paths, TASK, candidate["object_sha256"]).exists())

        item = self.publish_object("binding-count", {})
        with mock.patch.object(objects, "MAX_BINDINGS_PER_TASK", 0):
            with self.assertRaisesRegex(objects.SemanticObjectError, "count"):
                objects.publish_semantic_binding(
                    self.paths, self.binding("count", [item["object_sha256"]]), self.events
                )

    def test_pending_committed_orphan_and_deterministic_ordering(self) -> None:
        orphan = self.publish_object("z-orphan", {"z": 1})
        first = self.publish_object("a-first", {"a": 1})
        second = self.publish_object("b-second", {"b": 1})
        committed_event, committed_result = self.planned_event("a-slot")
        objects.publish_semantic_binding(
            self.paths,
            self.binding("a-slot", [first["object_sha256"]], kind="terminal_slot", event=committed_event),
            self.events,
        )
        self.commit(committed_event, committed_result)
        pending_event, _pending_result = self.planned_event("z-slot")
        self.assertEqual(
            objects.publish_semantic_binding(
                self.paths, self.binding("z-slot", [second["object_sha256"]], event=pending_event), self.events
            ),
            objects.publish_semantic_binding(
                self.paths, self.binding("z-slot", [second["object_sha256"]], event=pending_event), self.events
            ),
        )
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(report["committed_binding_sha256s"], sorted(report["committed_binding_sha256s"]))
        self.assertEqual(report["pending_binding_sha256s"], sorted(report["pending_binding_sha256s"]))
        self.assertEqual(report["orphan_object_sha256s"], [orphan["object_sha256"]])
        self.assertEqual([row["object_sha256"] for row in report["objects"]], sorted(row["object_sha256"] for row in report["objects"]))
        self.assertEqual([row["binding_kind"] for row in report["bindings"]], ["outcome_slot", "terminal_slot"])

    def test_pending_retry_allowance_is_exact_and_never_commits_orphans(self) -> None:
        item = self.publish_object("pending", {})
        event, _result = self.planned_event("pending")
        binding = objects.publish_semantic_binding(
            self.paths, self.binding("pending", [item["object_sha256"]], event=event), self.events
        )
        with self.assertRaisesRegex(objects.SemanticObjectError, "pending"):
            objects.require_no_pending_bindings(self.paths, TASK, self.events)
        report = objects.require_no_pending_bindings(
            self.paths, TASK, self.events, expected_binding_sha256=binding["binding_sha256"]
        )
        self.assertEqual(report["pending_binding_sha256s"], [binding["binding_sha256"]])
        self.assertFalse(report["orphan_object_sha256s"])
        extra = self.publish_object("orphan", {})
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertIn(extra["object_sha256"], report["orphan_object_sha256s"])

    def test_binding_rejects_empty_object_references(self) -> None:
        with self.assertRaisesRegex(objects.SemanticObjectError, "at least one"):
            self.binding("empty", [])

    def test_binding_reference_iterable_consumption_is_capped(self) -> None:
        class EndlessReferences:
            def __init__(self) -> None:
                self.consumed = 0

            def __iter__(self) -> "EndlessReferences":
                return self

            def __next__(self) -> str:
                self.consumed += 1
                return "a" * 64

        event, _result = self.planned_event("bounded-references")
        references = EndlessReferences()
        with self.assertRaisesRegex(objects.SemanticObjectError, "reference count"):
            objects.create_semantic_binding(
                binding_kind="outcome_slot",
                task_id=TASK,
                binding_key="bounded-references",
                expected_semantic_head_sha256=event["prev_event_sha256"],
                planned_event_sha256=event["event_sha256"],
                result_projection_sha256=event["result_projection_sha256"],
                object_sha256s=references,
            )
        self.assertEqual(references.consumed, objects.MAX_OBJECT_REFERENCES_PER_BINDING + 1)

    def test_object_root_scan_consumption_is_capped(self) -> None:
        root = h.task_dir(self.paths, TASK) / "semantic-objects"
        root.mkdir()
        if os.name != "nt":
            root.chmod(0o700)

        class Entry:
            def __init__(self, name: str) -> None:
                self.name = name

        class RootScan:
            def __init__(self) -> None:
                self.consumed = 0

            def __enter__(self) -> "RootScan":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self) -> "RootScan":
                return self

            def __next__(self) -> Entry:
                self.consumed += 1
                if self.consumed > 2:
                    raise AssertionError("object root scan consumed too many entries")
                return Entry(f"entry-{self.consumed}")

        scan = RootScan()
        with mock.patch.object(objects.os, "scandir", return_value=scan):
            with self.assertRaisesRegex(objects.SemanticObjectError, "root has an unexpected entry"):
                objects._scan_object_paths(self.paths, TASK)
        self.assertEqual(scan.consumed, 2)

    def test_event_chain_must_be_valid_and_task_local(self) -> None:
        with self.assertRaisesRegex(objects.SemanticObjectError, "event chain is invalid"):
            objects.inspect_semantic_objects(self.paths, TASK, [self.events[0], self.events[0]])
        other_chain = [
            semantic.create_genesis_event(
                {"task_id": "other-task", "stage": 0},
                command_id="other-genesis",
                recorded_at="2026-07-18T00:00:00+00:00",
                authority_ref="test",
            )
        ]
        with self.assertRaisesRegex(objects.SemanticObjectError, "task identity"):
            objects.inspect_semantic_objects(self.paths, TASK, other_chain)

    def test_task_identity_transition_cannot_flip_away_and_back(self) -> None:
        flipped = {"task_id": "other-task", "stage": 1}
        flip = semantic.create_transition_event(
            self.events[0],
            self.domain,
            flipped,
            event_type="binding_test",
            command_id="semantic-objects-flip-away",
            recorded_at="2026-07-18T00:01:00+00:00",
            authority_ref="test",
        )
        restored = {"task_id": TASK, "stage": 2}
        flip_back = semantic.create_transition_event(
            flip,
            flipped,
            restored,
            event_type="binding_test",
            command_id="semantic-objects-flip-back",
            recorded_at="2026-07-18T00:02:00+00:00",
            authority_ref="test",
        )
        with self.assertRaisesRegex(objects.SemanticObjectError, "may not mutate task identity"):
            objects.inspect_semantic_objects(self.paths, TASK, [self.events[0], flip, flip_back])

    def test_live_ledger_head_rejects_synthetic_chain(self) -> None:
        synthetic, _result = self.planned_event("synthetic-chain")
        with self.assertRaisesRegex(objects.SemanticObjectError, "live ledger head"):
            objects.inspect_semantic_objects(self.paths, TASK, [*self.events, synthetic])

    def test_stale_prefix_cannot_publish_a_sibling_binding(self) -> None:
        item = self.publish_object("sibling", {})
        sibling_event, _sibling_result = self.planned_event("sibling")
        advance, advance_result = self.planned_event("advance")
        self.commit(advance, advance_result)
        binding = self.binding("sibling", [item["object_sha256"]], event=sibling_event)
        destination = objects.semantic_binding_path(self.paths, TASK, "outcome_slot", "sibling")
        with self.assertRaisesRegex(objects.SemanticObjectError, "live ledger head"):
            objects.publish_semantic_binding(self.paths, binding, self.events[:1])
        self.assertFalse(destination.exists())

    def test_stale_prefix_cannot_downgrade_a_committed_binding(self) -> None:
        item = self.publish_object("committed", {})
        event, result = self.planned_event("committed")
        binding = objects.publish_semantic_binding(
            self.paths,
            self.binding("committed", [item["object_sha256"]], event=event),
            self.events,
        )
        self.commit(event, result)
        current = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(current["committed_binding_sha256s"], [binding["binding_sha256"]])
        with self.assertRaisesRegex(objects.SemanticObjectError, "live ledger head"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events[:1])

    def test_first_publish_checks_head_and_rejects_late_event(self) -> None:
        item = self.publish_object("head", {})
        event, result = self.planned_event("head")
        wrong_head = objects.create_semantic_binding(
            binding_kind="outcome_slot",
            task_id=TASK,
            binding_key="wrong-head",
            expected_semantic_head_sha256="f" * 64,
            planned_event_sha256=event["event_sha256"],
            result_projection_sha256=event["result_projection_sha256"],
            object_sha256s=[item["object_sha256"]],
        )
        with self.assertRaisesRegex(objects.SemanticObjectError, "expected head"):
            objects.publish_semantic_binding(self.paths, wrong_head, self.events)
        self.commit(event, result)
        late = self.binding("late", [item["object_sha256"]], event=event)
        with self.assertRaisesRegex(objects.SemanticObjectError, "already committed"):
            objects.publish_semantic_binding(self.paths, late, self.events)

    def test_committed_event_must_match_binding_result_and_head(self) -> None:
        item = self.publish_object("crosscheck", {})
        event, result = self.planned_event("crosscheck")
        wrong_result = objects.create_semantic_binding(
            binding_kind="outcome_slot",
            task_id=TASK,
            binding_key="wrong-result",
            expected_semantic_head_sha256=event["prev_event_sha256"],
            planned_event_sha256=event["event_sha256"],
            result_projection_sha256="e" * 64,
            object_sha256s=[item["object_sha256"]],
        )
        objects.publish_semantic_binding(self.paths, wrong_result, self.events)
        self.commit(event, result)
        with self.assertRaisesRegex(objects.SemanticObjectError, "does not match"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

    def test_planned_event_is_unique_across_slots_and_injected_duplicates_fail(self) -> None:
        item = self.publish_object("unique-event", {})
        event, _result = self.planned_event("unique-event")
        first = self.binding("first", [item["object_sha256"]], event=event)
        objects.publish_semantic_binding(self.paths, first, self.events)
        second = self.binding("second", [item["object_sha256"]], kind="terminal_slot", event=event)
        with self.assertRaisesRegex(objects.SemanticObjectError, "pending"):
            objects.publish_semantic_binding(self.paths, second, self.events)
        target = objects.semantic_binding_path(self.paths, TASK, "terminal_slot", "second")
        target.parent.mkdir(parents=True)
        if os.name != "nt":
            for directory in (target.parent.parent.parent, target.parent.parent, target.parent):
                directory.chmod(0o700)
        h.atomic_create_bytes(target, semantic.canonical_json_bytes(second))
        with self.assertRaisesRegex(objects.SemanticObjectError, "duplicate planned"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

    def test_exact_pending_and_committed_binding_retry(self) -> None:
        item = self.publish_object("retry-state", {})
        event, result = self.planned_event("retry-state")
        binding = self.binding("retry-state", [item["object_sha256"]], event=event)
        pending = objects.publish_semantic_binding(self.paths, binding, self.events)
        self.assertEqual(pending, objects.publish_semantic_binding(self.paths, binding, self.events))
        self.commit(event, result)
        successor_event, successor_result = self.planned_event("retry-state-successor")
        self.commit(successor_event, successor_result)
        self.assertEqual(pending, objects.publish_semantic_binding(self.paths, binding, self.events))

    def test_real_ledger_sibling_before_advance_is_rejected_without_publication(self) -> None:
        first_item = self.publish_object("first-pending", {})
        second_item = self.publish_object("second-sibling", {})
        first_event, first_result = self.planned_event("first-pending")
        second_event, _second_result = self.planned_event("second-sibling")
        first = self.binding("first-pending", [first_item["object_sha256"]], event=first_event)
        second = self.binding("second-sibling", [second_item["object_sha256"]], event=second_event)
        first_published = objects.publish_semantic_binding(self.paths, first, self.events)
        second_destination = objects.semantic_binding_path(self.paths, TASK, "outcome_slot", "second-sibling")
        with self.assertRaisesRegex(objects.SemanticObjectError, "pending"):
            objects.publish_semantic_binding(self.paths, second, self.events)
        self.assertFalse(second_destination.exists())
        self.commit(first_event, first_result)
        report = objects.inspect_semantic_objects(self.paths, TASK, self.events)
        self.assertEqual(report["committed_binding_sha256s"], [first_published["binding_sha256"]])
        self.assertFalse(report["pending_binding_sha256s"])

    def test_inspection_rejects_injected_two_pending_bindings(self) -> None:
        first_item = self.publish_object("first-injected", {})
        second_item = self.publish_object("second-injected", {})
        first_event, _first_result = self.planned_event("first-injected")
        second_event, _second_result = self.planned_event("second-injected")
        first = self.binding("first-injected", [first_item["object_sha256"]], event=first_event)
        second = self.binding("second-injected", [second_item["object_sha256"]], kind="terminal_slot", event=second_event)
        objects.publish_semantic_binding(self.paths, first, self.events)
        target = objects.semantic_binding_path(self.paths, TASK, "terminal_slot", "second-injected")
        target.parent.mkdir(parents=True)
        if os.name != "nt":
            for directory in (target.parent.parent.parent, target.parent.parent, target.parent):
                directory.chmod(0o700)
        h.atomic_create_bytes(target, semantic.canonical_json_bytes(second))
        with self.assertRaisesRegex(objects.SemanticObjectError, "more than one pending"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

    def test_stale_exact_pending_retry_is_rejected(self) -> None:
        item = self.publish_object("stale-pending", {})
        pending_event, _pending_result = self.planned_event("stale-pending")
        binding = self.binding("stale-pending", [item["object_sha256"]], event=pending_event)
        pending = objects.publish_semantic_binding(self.paths, binding, self.events)
        advance_event, advance_result = self.planned_event("unbound-advance")
        self.commit(advance_event, advance_result)
        with self.assertRaisesRegex(objects.SemanticObjectError, "pending retry expected head"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)
        with self.assertRaisesRegex(objects.SemanticObjectError, "pending retry expected head"):
            objects.require_no_pending_bindings(
                self.paths,
                TASK,
                self.events,
                expected_binding_sha256=pending["binding_sha256"],
            )
        with self.assertRaisesRegex(objects.SemanticObjectError, "pending retry expected head"):
            objects.publish_semantic_binding(self.paths, binding, self.events)

    def test_malformed_schema_bool_versions_duplicate_json_and_path_link_fail(self) -> None:
        item = self.object("schema", {})
        item["schema_version"] = True
        with self.assertRaisesRegex(objects.SemanticObjectError, "schema version"):
            objects.validate_semantic_object(item)
        binding = self.binding("schema", ["a" * 64])
        binding["schema_version"] = True
        with self.assertRaisesRegex(objects.SemanticObjectError, "schema version"):
            objects.validate_semantic_binding(binding)

        stored = self.publish_object("duplicate", {})
        path = objects.semantic_object_path(self.paths, TASK, stored["object_sha256"])
        path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(objects.SemanticObjectError, "duplicate"):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)

        # Restore a valid file and use a symlink only where the platform permits it.
        path.write_bytes(semantic.canonical_json_bytes(stored))
        outside = self.root / "outside.json"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        with self.assertRaises(objects.SemanticObjectError):
            objects.inspect_semantic_objects(self.paths, TASK, self.events)


if __name__ == "__main__":
    unittest.main()
