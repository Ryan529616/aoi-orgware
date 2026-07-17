#!/usr/bin/env python3
"""Pure contracts for semantic-v2 event authority and task projections."""

from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import semantic_events as semantic  # noqa: E402


RECORDED_AT = "2026-07-18T00:00:00+00:00"
AUTHORITY = "chief-session:fixture@2"


def resign(event: dict[str, object], *, payload: bool = False) -> dict[str, object]:
    record = copy.deepcopy(event)
    if payload:
        record["payload_sha256"] = semantic.canonical_sha256(record["payload"])
    record["event_sha256"] = semantic._event_digest(record)
    return record


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_golden_vector(self) -> None:
        value = {"z": [1, True, None], "é": "值", "a": {"b": -0.0}}
        expected = '{"a":{"b":-0.0},"z":[1,true,null],"é":"值"}'.encode()
        self.assertEqual(semantic.canonical_json_bytes(value), expected)
        self.assertEqual(
            semantic.canonical_sha256(value), hashlib.sha256(expected).hexdigest()
        )

    def test_canonical_json_rejects_non_json_nonfinite_cycles_and_depth(self) -> None:
        cycle: list[object] = []
        cycle.append(cycle)
        deep: dict[str, object] = {}
        cursor = deep
        for index in range(semantic.MAX_JSON_DEPTH + 2):
            child: dict[str, object] = {}
            cursor[str(index)] = child
            cursor = child
        for value in ((1, 2), float("nan"), float("inf"), cycle, deep):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(semantic.SemanticEventError):
                    semantic.canonical_json_bytes(value)

    def test_canonical_json_rejects_alias_dag_before_exponential_expansion(self) -> None:
        value: object = 0
        for _ in range(23):
            value = [value, value]
        with self.assertRaisesRegex(semantic.SemanticEventError, "repeated or cyclic"):
            semantic.canonical_json_bytes(value)


class DeltaContractTests(unittest.TestCase):
    def test_nested_delta_is_deterministic_bounded_and_round_trips(self) -> None:
        before = {
            "a": {"x": 1, "gone": 2},
            "items": ["keep", "old", "tail"],
            "remove": True,
            "same": 0,
        }
        after = {
            "a": {"x": 2, "new": 3},
            "items": ["keep", "new-1", "new-2", "tail"],
            "same": 0,
            "z": False,
        }
        expected = {
            "delta_version": 1,
            "operations": [
                {"op": "remove", "path": ["a", "gone"]},
                {"op": "set", "path": ["a", "new"], "value": 3},
                {"op": "set", "path": ["a", "x"], "value": 2},
                {
                    "op": "splice",
                    "path": ["items"],
                    "start": 1,
                    "delete": 1,
                    "values": ["new-1", "new-2"],
                },
                {"op": "remove", "path": ["remove"]},
                {"op": "set", "path": ["z"], "value": False},
            ],
        }
        self.assertEqual(semantic.build_delta(before, after), expected)
        self.assertEqual(semantic.apply_delta(before, expected), after)

    def test_delta_distinguishes_bool_int_and_signed_zero(self) -> None:
        before = {"boolean": True, "zero": 0.0}
        after = {"boolean": 1, "zero": -0.0}
        delta = semantic.build_delta(before, after)
        self.assertEqual(
            delta["operations"],
            [
                {"op": "set", "path": ["boolean"], "value": 1},
                {"op": "set", "path": ["zero"], "value": -0.0},
            ],
        )
        result = semantic.apply_delta(before, delta)
        self.assertIs(type(result["boolean"]), int)
        self.assertEqual(semantic.canonical_json_bytes(result), semantic.canonical_json_bytes(after))

    def test_empty_oversized_and_reserved_deltas_are_rejected(self) -> None:
        with self.assertRaisesRegex(semantic.SemanticEventError, "empty delta"):
            semantic.build_delta({"same": 1}, {"same": 1})
        with self.assertRaisesRegex(semantic.SemanticEventError, "byte bound"):
            semantic.build_delta({}, {"large": "x" * semantic.MAX_TRANSITION_PAYLOAD_BYTES})
        with self.assertRaisesRegex(semantic.SemanticEventError, "empty delta"):
            semantic.build_delta({}, {"_semantic": {"forged": True}})
        with self.assertRaisesRegex(semantic.SemanticEventError, "reserves"):
            semantic.create_genesis_event(
                {"_semantic": {"forged": True}},
                command_id="init-reserved",
                recorded_at=RECORDED_AT,
                authority_ref=AUTHORITY,
            )

    def test_apply_rejects_malformed_or_noncanonical_operations(self) -> None:
        before = {"a": 1, "b": 2, "items": [1, 2, 3]}
        cases = [
            {"delta_version": 1, "operations": []},
            {"delta_version": 2, "operations": [{"op": "remove", "path": ["a"]}]},
            {"delta_version": 1, "operations": [{"op": "remove", "path": ["missing"]}]},
            {
                "delta_version": 1,
                "operations": [{"op": "set", "path": ["_semantic"], "value": {}}],
            },
            {
                "delta_version": 1,
                "operations": [
                    {
                        "op": "splice",
                        "path": ["items"],
                        "start": 4,
                        "delete": 0,
                        "values": [],
                    }
                ],
            },
            {
                "delta_version": 1,
                "operations": [
                    {"op": "set", "path": ["b"], "value": 4},
                    {"op": "set", "path": ["a"], "value": 3},
                ],
            },
            {
                "delta_version": 1,
                "operations": [{"op": "set", "path": ["a"], "value": 1}],
            },
        ]
        for delta in cases:
            with self.subTest(delta=delta):
                with self.assertRaises(semantic.SemanticEventError):
                    semantic.apply_delta(before, delta)


class SemanticEventChainTests(unittest.TestCase):
    def genesis(self, state: dict[str, object] | None = None) -> dict[str, object]:
        return semantic.create_genesis_event(
            state or {"task_id": "task-1", "revision": 1, "rows": ["a", "b"]},
            command_id="init-task-1",
            recorded_at=RECORDED_AT,
            authority_ref=AUTHORITY,
        )

    def transition(
        self,
        previous: dict[str, object],
        before: dict[str, object],
        after: dict[str, object],
        *,
        command_id: str = "checkpoint-task-1-r2",
        event_type: str = "task_checkpointed",
        recorded_at: str = "2026-07-18T00:01:00+00:00",
    ) -> dict[str, object]:
        return semantic.create_transition_event(
            previous,
            before,
            after,
            event_type=event_type,
            command_id=command_id,
            recorded_at=recorded_at,
            authority_ref=AUTHORITY,
        )

    def test_genesis_has_stable_golden_hashes(self) -> None:
        event = self.genesis({"revision": 1, "task_id": "task-1"})
        self.assertEqual(
            event["payload_sha256"],
            "c829752bdc0090495fa8d5c1f2d475094e889521f15ab3606600883e830b71a9",
        )
        self.assertEqual(
            event["event_sha256"],
            "7090425c8c2a05764d67a05d109e3850708e1efb915ceff1e7137cabb4a84689",
        )
        self.assertEqual(event["prev_event_sha256"], semantic.ZERO_SHA256)
        self.assertEqual(event["base_projection_sha256"], semantic.ZERO_SHA256)

    def test_replay_emits_non_circular_projection_envelope(self) -> None:
        before = {"task_id": "task-1", "revision": 1, "rows": ["a", "b"]}
        after = {"task_id": "task-1", "revision": 2, "rows": ["a", "x", "b"]}
        first = self.genesis(before)
        second = self.transition(first, before, after)
        projection = semantic.replay_events([first, second])
        self.assertEqual(semantic.projection_domain(projection), after)
        self.assertEqual(
            projection["_semantic"],
            {
                "schema_version": 2,
                "sequence": 2,
                "head_event_sha256": second["event_sha256"],
                "domain_sha256": second["result_projection_sha256"],
            },
        )
        self.assertEqual(semantic.projection_sha256(projection), second["result_projection_sha256"])
        self.assertNotIn("snapshot", second["payload"])

    def test_replay_rejects_tamper_gaps_hashes_and_malformed_payloads(self) -> None:
        before = {"task_id": "task-1", "revision": 1}
        after = {"task_id": "task-1", "revision": 2}
        first = self.genesis(before)
        second = self.transition(first, before, after)

        payload_tamper = copy.deepcopy(second)
        payload_tamper["payload"]["delta"]["operations"][0]["value"] = 3
        bad_previous = resign({**second, "prev_event_sha256": "1" * 64})
        gap = resign({**second, "sequence": 3})
        bad_base = resign({**second, "base_projection_sha256": "2" * 64})
        bad_result = resign({**second, "result_projection_sha256": "3" * 64})
        full_snapshot = copy.deepcopy(second)
        full_snapshot["payload"] = {"snapshot": after}
        full_snapshot = resign(full_snapshot, payload=True)

        cases = [
            [first, payload_tamper],
            [first, bad_previous],
            [first, gap],
            [first, bad_base],
            [first, bad_result],
            [first, full_snapshot],
        ]
        for events in cases:
            with self.subTest(events=events):
                with self.assertRaises(semantic.SemanticEventError):
                    semantic.replay_events(events)

    def test_replay_rejects_duplicate_command_ids_even_with_valid_chain(self) -> None:
        first_state = {"task_id": "task-1", "revision": 1}
        second_state = {"task_id": "task-1", "revision": 2}
        third_state = {"task_id": "task-1", "revision": 3}
        first = self.genesis(first_state)
        second = self.transition(first, first_state, second_state, command_id="same-command")
        third = self.transition(
            second,
            second_state,
            third_state,
            command_id="same-command",
            recorded_at="2026-07-18T00:02:00+00:00",
        )
        with self.assertRaisesRegex(semantic.SemanticEventError, "duplicate command"):
            semantic.replay_events([first, second, third])

    def test_command_retry_is_exact_and_record_time_sequence_independent(self) -> None:
        before = {"task_id": "task-1", "revision": 1}
        after = {"task_id": "task-1", "revision": 2}
        first = self.genesis(before)
        second = self.transition(first, before, after)
        proposed = resign(
            {
                **second,
                "sequence": 99,
                "prev_event_sha256": "f" * 64,
                "recorded_at": "2026-07-18T01:00:00+00:00",
            }
        )
        self.assertEqual(semantic.resolve_command_retry([first, second], proposed), second)

        divergent = copy.deepcopy(proposed)
        divergent["result_projection_sha256"] = "e" * 64
        divergent = resign(divergent)
        with self.assertRaisesRegex(semantic.SemanticEventError, "different semantics"):
            semantic.resolve_command_retry([first, second], divergent)

        type_alias = copy.deepcopy(proposed)
        type_alias["payload"]["delta"]["operations"][0]["value"] = True
        type_alias = resign(type_alias, payload=True)
        with self.assertRaisesRegex(semantic.SemanticEventError, "different semantics"):
            semantic.resolve_command_retry([first, second], type_alias)

        with self.assertRaisesRegex(semantic.SemanticEventError, "sequence"):
            semantic.resolve_command_retry([second, first], second)

    def test_projection_validation_accepts_only_current_or_exact_prefix(self) -> None:
        before = {"task_id": "task-1", "revision": 1}
        after = {"task_id": "task-1", "revision": 2}
        first = self.genesis(before)
        second = self.transition(first, before, after)
        old_projection = semantic.replay_events([first])
        current_projection = semantic.replay_events([first, second])

        behind = semantic.validate_projection([first, second], old_projection)
        self.assertEqual((behind.status, behind.stored_sequence, behind.head_sequence), ("behind", 1, 2))
        self.assertEqual(behind.canonical_projection, current_projection)
        current = semantic.validate_projection([first, second], current_projection)
        self.assertEqual(current.status, "current")

        missing = semantic.projection_domain(current_projection)
        ahead = copy.deepcopy(current_projection)
        ahead["_semantic"]["sequence"] = 3
        divergent = copy.deepcopy(current_projection)
        divergent["revision"] = 7
        wrong_head = copy.deepcopy(old_projection)
        wrong_head["_semantic"]["head_event_sha256"] = "a" * 64
        for projection in (missing, ahead, divergent, wrong_head):
            with self.subTest(projection=projection):
                with self.assertRaises(semantic.SemanticEventError):
                    semantic.validate_projection([first, second], projection)

    def test_invalid_event_identity_schema_and_transition_base_fail_closed(self) -> None:
        before = {"task_id": "task-1", "revision": 1}
        first = self.genesis(before)
        invalid_cases = [
            {**first, "extra": True},
            resign({**first, "recorded_at": "2026-07-18T00:00:00"}),
            resign({**first, "recorded_at": "2026-07-18 00:00:00+00:00"}),
            resign({**first, "command_id": " bad"}),
        ]
        for event in invalid_cases:
            with self.subTest(event=event):
                with self.assertRaises(semantic.SemanticEventError):
                    semantic.replay_events([event])
        with self.assertRaisesRegex(semantic.SemanticEventError, "base does not match"):
            self.transition(first, {"task_id": "task-1", "revision": 9}, before)

    def test_legacy_genesis_is_explicit_and_replayable(self) -> None:
        state = {"task_id": "legacy-task", "revision": 17}
        legacy_bytes = b'{"task_id":"legacy-task", "revision":17}\n'
        legacy_sha = hashlib.sha256(legacy_bytes).hexdigest()
        event = semantic.create_legacy_genesis_event(
            state,
            legacy_snapshot_sha256=legacy_sha,
            command_id="migrate-legacy-task",
            recorded_at=RECORDED_AT,
            authority_ref=AUTHORITY,
        )
        self.assertEqual(event["payload"]["legacy_snapshot_sha256"], legacy_sha)
        self.assertEqual(semantic.projection_domain(semantic.replay_events([event])), state)

        missing_binding = copy.deepcopy(event)
        del missing_binding["payload"]["legacy_snapshot_sha256"]
        missing_binding = resign(missing_binding, payload=True)
        with self.assertRaisesRegex(semantic.SemanticEventError, "genesis payload"):
            semantic.replay_events([missing_binding])


class EventFilenameTests(unittest.TestCase):
    def test_short_sequence_filenames_round_trip_and_reject_aliases(self) -> None:
        self.assertEqual(semantic.event_filename(1), "000000000001.json")
        self.assertEqual(semantic.parse_event_filename("999999999999.json"), 999999999999)
        for name in ("1.json", "000000000000.json", "000000000001.JSON", "000000000001.json.tmp"):
            with self.subTest(name=name):
                with self.assertRaises(semantic.SemanticEventError):
                    semantic.parse_event_filename(name)


if __name__ == "__main__":
    unittest.main()
