"""Focused adversarial tests for the bounded Codex hook receipt store."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import codex_hook_receipts as receipts  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.semantic_events import canonical_json_bytes  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


def _validated_adapter_receipt(value: object) -> dict[str, object]:
    """A small stand-in for the separately-owned adapter contract validator."""

    if not isinstance(value, dict):
        raise ValueError("receipt is not an object")
    expected = {"receipt_type", "event_identity", "observation", "receipt_sha256"}
    if set(value) != expected or not isinstance(value["event_identity"], dict):
        raise ValueError("receipt schema is invalid")
    base = {key: value[key] for key in expected - {"receipt_sha256"}}
    digest = hashlib.sha256(canonical_json_bytes(base)).hexdigest()
    if value["receipt_sha256"] != digest:
        raise ValueError("receipt SHA-256 is invalid")
    return json.loads(canonical_json_bytes(value).decode("utf-8"))


class CodexHookReceiptStoreTests(HarnessTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.paths = h.get_paths(self.root)
        self.validator = mock.patch.object(
            receipts, "_adapter_validator", side_effect=_validated_adapter_receipt
        )
        self.validator.start()
        self.addCleanup(self.validator.stop)

    def receipt(self, **changes: object) -> dict[str, object]:
        base: dict[str, object] = {
            "receipt_type": "post_tool_use",
            "event_identity": {
                "session_id": "codex-session-1",
                "turn_id": "turn-1",
                "tool_use_id": "toolu-1",
                "agent_id": "agent-1",
                "event_id": "event-1",
            },
            "observation": {"status": "observed"},
        }
        base.update(changes)
        return {
            **base,
            "receipt_sha256": hashlib.sha256(canonical_json_bytes(base)).hexdigest(),
        }

    def doctor_report(self) -> dict[str, object]:
        self.install_hook_layers()
        paths = h.get_paths(self.root)
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            cli_impl.cmd_doctor(argparse.Namespace(task=None, json=True), paths)
        return json.loads(output.getvalue())

    def test_filename_binds_event_identity_not_receipt_digest(self) -> None:
        first = self.receipt()
        divergent = self.receipt(observation={"status": "different"})
        self.assertNotEqual(first["receipt_sha256"], divergent["receipt_sha256"])
        self.assertEqual(
            receipts.codex_hook_receipt_key(first),
            receipts.codex_hook_receipt_key(divergent),
        )
        stored = receipts.store_codex_hook_receipt(self.paths, first)
        path = receipts.codex_hook_receipt_path(self.paths, first)
        self.assertEqual(path.name, f"{receipts.codex_hook_receipt_key(first)}.json")
        self.assertEqual(path.read_bytes(), canonical_json_bytes(stored))
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "collision"):
            receipts.store_codex_hook_receipt(self.paths, divergent)
        self.assertEqual(path.read_bytes(), canonical_json_bytes(stored))

    def test_exact_replay_is_idempotent_and_does_not_recreate(self) -> None:
        original = receipts.store_codex_hook_receipt(self.paths, self.receipt())
        with mock.patch.object(h, "atomic_create_bytes") as create:
            replay = receipts.store_codex_hook_receipt(self.paths, self.receipt())
        self.assertEqual(replay, original)
        create.assert_not_called()

    def test_identity_only_load_returns_exact_validated_pre_receipt(self) -> None:
        value = self.receipt(receipt_type="pre_tool_use")
        stored = receipts.store_codex_hook_receipt(self.paths, value)
        loaded = receipts.load_codex_hook_receipt_by_identity(
            self.paths,
            receipt_type="pre_tool_use",
            event_identity=value["event_identity"],  # type: ignore[arg-type]
        )
        self.assertEqual(loaded, stored)
        with self.assertRaisesRegex(
            receipts.CodexHookReceiptError, "missing|match"
        ):
            receipts.load_codex_hook_receipt_by_identity(
                self.paths,
                receipt_type="pre_tool_use",
                event_identity={
                    **value["event_identity"],  # type: ignore[arg-type]
                    "tool_use_id": "different",
                },
            )

    def test_validator_failure_creates_no_store(self) -> None:
        bad = self.receipt()
        bad["receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "invalid"):
            receipts.store_codex_hook_receipt(self.paths, bad)
        self.assertFalse(receipts.codex_hook_receipts_dir(self.paths).exists())

    def test_store_uses_the_real_adapter_validator_not_a_local_schema(self) -> None:
        self.validator.stop()
        from aoi_orgware import codex_adapter_contracts as contracts

        observed = lambda value: {"status": "observed", "value": value}
        sealed = contracts.seal_codex_subagent_stop_receipt(
            {
                "receipt_type": contracts.CODEX_SUBAGENT_STOP_V1,
                "event_identity": {
                    "session_id": "session-1",
                    "turn_id": "turn-1",
                    "agent_id": "agent-1",
                    "event_id": "stop-1",
                },
                "observed_at": "2026-07-19T01:02:03Z",
                "transcript_path_observation": observed("C:/transcript.jsonl"),
                "last_assistant_message": {
                    "sha256": observed("a" * 64),
                    "size_bytes": observed("123"),
                    "presence": observed("present"),
                },
                "model_observation": observed("gpt-5.6"),
                "permission_mode_observation": observed("workspace-write"),
                "start_correlation": {
                    "status": "matched",
                    "start_receipt_sha256": observed("b" * 64),
                },
                "no_material_work_verified": False,
            }
        )
        self.assertEqual(receipts.store_codex_hook_receipt(self.paths, sealed), sealed)

        legacy_base = {
            key: value for key, value in sealed.items() if key != "receipt_sha256"
        }
        legacy_base["event_identity"] = {
            **legacy_base["event_identity"],  # type: ignore[arg-type]
            "agent_id": "legacy reviewer",
        }
        legacy = {
            **legacy_base,
            "receipt_sha256": hashlib.sha256(
                canonical_json_bytes(legacy_base)
            ).hexdigest(),
        }
        self.assertEqual(
            contracts.validate_codex_subagent_stop_receipt(legacy), legacy
        )
        with self.assertRaisesRegex(
            receipts.CodexHookReceiptError, "canonical agent identity"
        ):
            receipts.store_codex_hook_receipt(self.paths, legacy)

        directory = receipts.codex_hook_receipts_dir(self.paths)
        directory.mkdir(parents=True, exist_ok=True)
        path = receipts.codex_hook_receipt_path(self.paths, legacy)
        h.atomic_create_bytes(path, canonical_json_bytes(legacy))
        with mock.patch.object(h, "atomic_create_bytes") as create:
            self.assertEqual(
                receipts.store_codex_hook_receipt(self.paths, legacy), legacy
            )
        create.assert_not_called()

    def test_store_holds_cooperative_lock_through_create(self) -> None:
        real_create = h.atomic_create_bytes

        def observed(path: Path, payload: bytes) -> None:
            self.assertTrue(h._chief_lock_is_held(self.paths))
            real_create(path, payload)

        with mock.patch.object(h, "atomic_create_bytes", side_effect=observed):
            receipts.store_codex_hook_receipt(self.paths, self.receipt())

    def test_same_event_race_is_one_winner_and_one_divergent_collision(self) -> None:
        barrier = threading.Barrier(2)
        first = self.receipt(observation={"race": "left"})
        second = self.receipt(observation={"race": "right"})

        def store(value: dict[str, object]) -> object:
            barrier.wait(timeout=10)
            try:
                return receipts.store_codex_hook_receipt(self.paths, value)
            except Exception as exc:  # Result class is the assertion target.
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(store, (first, second)))
        successes = [item for item in outcomes if isinstance(item, dict)]
        failures = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], receipts.CodexHookReceiptError)
        self.assertIn("collision", str(failures[0]))
        self.assertEqual(
            receipts.load_codex_hook_receipt(self.paths, first), successes[0]
        )

    @mock.patch.object(receipts, "MAX_CODEX_HOOK_RECEIPT_ENTRIES", 1)
    def test_entry_cap_is_honest_and_replay_at_cap_still_works(self) -> None:
        first = self.receipt()
        stored = receipts.store_codex_hook_receipt(self.paths, first)
        self.assertEqual(receipts.store_codex_hook_receipt(self.paths, first), stored)
        self.assertEqual(
            receipts.inspect_codex_hook_receipt_store(self.paths)["capacity_status"],
            "full",
        )
        second = self.receipt(
            event_identity={
                **first["event_identity"],  # type: ignore[arg-type]
                "tool_use_id": "toolu-2",
            }
        )
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "receipt_store_full"):
            receipts.store_codex_hook_receipt(self.paths, second)
        self.assertFalse(receipts.codex_hook_receipt_path(self.paths, second).exists())

    def test_aggregate_cap_never_claims_space_that_it_did_not_account(self) -> None:
        first = self.receipt()
        receipts.store_codex_hook_receipt(self.paths, first)
        first_path = receipts.codex_hook_receipt_path(self.paths, first)
        second = self.receipt(
            event_identity={
                **first["event_identity"],  # type: ignore[arg-type]
                "tool_use_id": "toolu-2",
            }
        )
        with mock.patch.object(
            receipts, "MAX_CODEX_HOOK_RECEIPT_STORE_BYTES", first_path.stat().st_size
        ):
            self.assertEqual(receipts.store_codex_hook_receipt(self.paths, first), first)
            with self.assertRaisesRegex(receipts.CodexHookReceiptError, "receipt_store_full"):
                receipts.store_codex_hook_receipt(self.paths, second)
        self.assertFalse(receipts.codex_hook_receipt_path(self.paths, second).exists())

    @mock.patch.object(receipts, "MAX_CODEX_HOOK_RECEIPT_ENTRIES", 1)
    def test_doctor_reports_full_receipt_capacity_as_error(self) -> None:
        receipts.store_codex_hook_receipt(self.paths, self.receipt())
        report = self.doctor_report()
        self.assertEqual(report["codex_hook_receipts"]["capacity_status"], "full")
        self.assertIn(
            "Codex hook receipt store is full; PreToolUse denies until receipts are preserved or rotated.",
            report["errors"],
        )

    @mock.patch.object(receipts, "MAX_CODEX_HOOK_RECEIPT_ENTRIES", 10)
    def test_doctor_warns_when_receipt_capacity_is_near_full(self) -> None:
        for index in range(9):
            receipts.store_codex_hook_receipt(
                self.paths,
                self.receipt(
                    event_identity={
                        "session_id": "codex-session-1",
                        "turn_id": "turn-1",
                        "tool_use_id": f"toolu-{index}",
                        "agent_id": "agent-1",
                        "event_id": f"event-{index}",
                    }
                ),
            )
        report = self.doctor_report()
        self.assertEqual(report["codex_hook_receipts"]["capacity_status"], "near_full")
        self.assertIn(
            "Codex hook receipt store is near capacity; PreToolUse will deny once it is full.",
            report["warnings"],
        )

    def test_hardlink_and_corrupt_members_fail_closed(self) -> None:
        value = self.receipt()
        receipts.store_codex_hook_receipt(self.paths, value)
        path = receipts.codex_hook_receipt_path(self.paths, value)
        alias = path.with_name("hardlink-alias")
        os.link(path, alias)
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "non-linked"):
            receipts.load_codex_hook_receipt(self.paths, value)
        alias.unlink()
        path.write_bytes(b'{"forged":true}')
        with self.assertRaisesRegex(receipts.CodexHookReceiptError, "invalid|corrupt"):
            receipts.inspect_codex_hook_receipt_store(self.paths)

    def test_symlink_and_identity_path_mismatch_fail_closed_when_supported(self) -> None:
        value = self.receipt()
        receipts.store_codex_hook_receipt(self.paths, value)
        path = receipts.codex_hook_receipt_path(self.paths, value)
        outside = self.root / "outside-receipt.json"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        with self.assertRaises(h.HarnessError):
            receipts.load_codex_hook_receipt(self.paths, value)

    def test_inspection_has_deterministic_counts(self) -> None:
        first = self.receipt()
        second = self.receipt(
            receipt_type="subagent_stop",
            event_identity={
                "session_id": "codex-session-1",
                "turn_id": "turn-1",
                "agent_id": "agent-1",
                "event_id": "event-stop-1",
            },
        )
        receipts.store_codex_hook_receipt(self.paths, first)
        receipts.store_codex_hook_receipt(self.paths, second)
        report = receipts.inspect_codex_hook_receipt_store(self.paths)
        expected_bytes = sum(
            receipts.codex_hook_receipt_path(self.paths, item).stat().st_size
            for item in (first, second)
        )
        self.assertEqual(
            report,
            {
                "entry_count": 2,
                "aggregate_bytes": expected_bytes,
                "entry_capacity": receipts.MAX_CODEX_HOOK_RECEIPT_ENTRIES,
                "aggregate_byte_capacity": receipts.MAX_CODEX_HOOK_RECEIPT_STORE_BYTES,
                "capacity_status": "available",
                "receipt_type_counts": {"post_tool_use": 1, "subagent_stop": 1},
                "corruption": [],
            },
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
