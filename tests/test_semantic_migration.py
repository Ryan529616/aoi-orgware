#!/usr/bin/env python3
"""Byte-preserving semantic-v2 migration and rollback contracts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


AUTHORITY = "chief:harness-test-chief@1"
MIGRATED_AT = "2026-07-18T00:00:00+00:00"


class SemanticMigrationTests(HarnessTestCase):
    TASK = "semantic-migration"
    COMMAND = "migrate-semantic-v2-r1"

    def setUp(self) -> None:
        super().setUp()
        self.init_task(self.TASK)
        self.paths = h.get_paths(self.root)

    def legacy_bytes(self) -> bytes:
        return h.task_state_path(self.paths, self.TASK).read_bytes()

    def migrate(self) -> store.SemanticAppendResult:
        raw = self.legacy_bytes()
        with h.state_lock(self.paths, create_layout=False):
            return store.migrate_legacy_task(
                self.paths,
                self.TASK,
                command_id=self.COMMAND,
                expected_legacy_sha256=hashlib.sha256(raw).hexdigest(),
                recorded_at=MIGRATED_AT,
                authority_ref=AUTHORITY,
            )

    def test_migration_preserves_exact_bytes_and_retry_is_idempotent(self) -> None:
        raw = self.legacy_bytes()
        legacy = json.loads(raw.decode("utf-8"))
        migrated = self.migrate()

        self.assertFalse(migrated.idempotent_replay)
        self.assertEqual(store.legacy_snapshot_path(self.paths, self.TASK).read_bytes(), raw)
        self.assertEqual(migrated.event["event_type"], "legacy_genesis")
        self.assertTrue(store.has_semantic_ledger(self.paths, self.TASK))
        self.assertEqual(
            semantic.projection_domain(h.load_task(self.paths, self.TASK)), legacy
        )
        receipt = store.validate_semantic_migration(self.paths, self.TASK)
        self.assertEqual(receipt["legacy_snapshot_sha256"], hashlib.sha256(raw).hexdigest())
        event_before = (
            store.semantic_event_directory(self.paths, self.TASK)
            / semantic.event_filename(1)
        ).read_bytes()

        with h.state_lock(self.paths, create_layout=False):
            retried = store.migrate_legacy_task(
                self.paths,
                self.TASK,
                command_id=self.COMMAND,
                expected_legacy_sha256=hashlib.sha256(raw).hexdigest(),
                recorded_at="2026-07-18T02:00:00+00:00",
                authority_ref=AUTHORITY,
            )
        self.assertTrue(retried.idempotent_replay)
        self.assertEqual(
            (
                store.semantic_event_directory(self.paths, self.TASK)
                / semantic.event_filename(1)
            ).read_bytes(),
            event_before,
        )

    def test_exact_retry_accepts_historically_sealed_tool_version(self) -> None:
        raw = self.legacy_bytes()
        self.migrate()
        receipt_path = store.migration_receipt_path(self.paths, self.TASK)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["tool_version"] = "0.3.0"
        receipt["migration_receipt_sha256"] = semantic.canonical_sha256(
            {
                key: value
                for key, value in receipt.items()
                if key != "migration_receipt_sha256"
            },
            max_bytes=store.MAX_MIGRATION_RECORD_BYTES,
        )
        receipt_path.write_bytes(
            semantic.canonical_json_bytes(
                receipt, max_bytes=store.MAX_MIGRATION_RECORD_BYTES
            )
        )

        with h.state_lock(self.paths, create_layout=False):
            retried = store.migrate_legacy_task(
                self.paths,
                self.TASK,
                command_id=self.COMMAND,
                expected_legacy_sha256=hashlib.sha256(raw).hexdigest(),
                recorded_at="2026-07-18T02:00:00+00:00",
                authority_ref=AUTHORITY,
            )
        self.assertTrue(retried.idempotent_replay)
        self.assertEqual(
            store.validate_semantic_migration(self.paths, self.TASK)["tool_version"],
            "0.3.0",
        )

    def test_live_packet_job_and_temporary_residue_block_without_ledger(self) -> None:
        raw = self.legacy_bytes()
        state = json.loads(raw.decode("utf-8"))
        state["packets"] = [
            {"packet_id": "live-packet", "status": "dispatched", "dispatch_attempts": []}
        ]
        h.atomic_write_json(h.task_state_path(self.paths, self.TASK), state)
        blocked_raw = self.legacy_bytes()
        with self.assertRaisesRegex(store.SemanticStoreError, "not quiescent"):
            self.migrate()
        self.assertEqual(self.legacy_bytes(), blocked_raw)
        self.assertFalse(store.semantic_event_directory(self.paths, self.TASK).exists())

        state["packets"] = []
        h.atomic_write_json(h.task_state_path(self.paths, self.TASK), state)
        with mock.patch.object(h, "scan_atomic_temporaries", return_value=[object()]):
            with self.assertRaisesRegex(store.SemanticStoreError, "temporary residue"):
                self.migrate()
        self.assertFalse(store.semantic_event_directory(self.paths, self.TASK).exists())

        state["subagent_incidents"] = [
            {"incident_id": "unknown-hook-event", "status": "open"}
        ]
        h.atomic_write_json(h.task_state_path(self.paths, self.TASK), state)
        with self.assertRaisesRegex(store.SemanticStoreError, "incident"):
            self.migrate()
        self.assertFalse(store.semantic_event_directory(self.paths, self.TASK).exists())

    def test_event_first_and_receipt_first_failures_recover_on_exact_retry(self) -> None:
        raw = self.legacy_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        original_create = h.atomic_create_bytes

        def publish_event_then_raise(path: Path, payload: bytes) -> None:
            original_create(path, payload)
            if path.name == semantic.event_filename(1):
                raise h.HarnessError("injected post-event interruption")

        with mock.patch.object(h, "atomic_create_bytes", side_effect=publish_event_then_raise):
            with self.assertRaisesRegex(h.HarnessError, "post-event interruption"):
                self.migrate()
        self.assertTrue(
            (
                store.semantic_event_directory(self.paths, self.TASK)
                / semantic.event_filename(1)
            ).is_file()
        )
        self.assertFalse(store.migration_receipt_path(self.paths, self.TASK).exists())
        self.assertEqual(self.legacy_bytes(), raw)

        with h.state_lock(self.paths, create_layout=False):
            recovered = store.migrate_legacy_task(
                self.paths,
                self.TASK,
                command_id=self.COMMAND,
                expected_legacy_sha256=digest,
                recorded_at="2026-07-18T03:00:00+00:00",
                authority_ref="chief:successor@2",
            )
        self.assertTrue(recovered.idempotent_replay)
        self.assertTrue(store.migration_receipt_path(self.paths, self.TASK).is_file())
        self.assertEqual(store.semantic_projection_status(self.paths, self.TASK), "current")
        self.assertEqual(recovered.event["authority_ref"], AUTHORITY)
        with h.state_lock(self.paths, create_layout=False):
            with self.assertRaisesRegex(store.SemanticStoreError, "conflicts"):
                store.migrate_legacy_task(
                    self.paths,
                    self.TASK,
                    command_id="different-migration-command",
                    expected_legacy_sha256=digest,
                    recorded_at="2026-07-18T04:00:00+00:00",
                    authority_ref="chief:different@2",
                )

    def test_malformed_nested_execution_collections_are_bounded(self) -> None:
        original = self.legacy_bytes()
        cases = {
            "packets": {"not": "a list"},
            "packet-entry": ["not an object"],
            "packet-attempts": [
                {"packet_id": "packet-1", "status": "ready", "dispatch_attempts": 1}
            ],
            "packet-attempt": [
                {
                    "packet_id": "packet-1",
                    "status": "ready",
                    "dispatch_attempts": ["not an object"],
                }
            ],
            "packet-status": [
                {"packet_id": "packet-1", "status": {}, "dispatch_attempts": []}
            ],
            "packet-status-future": [
                {
                    "packet_id": "packet-1",
                    "status": "future_status",
                    "dispatch_attempts": [],
                }
            ],
            "packet-attempt-status": [
                {
                    "packet_id": "packet-1",
                    "status": "ready",
                    "dispatch_attempts": [{"status": []}],
                }
            ],
            "packet-attempt-status-future": [
                {
                    "packet_id": "packet-1",
                    "status": "ready",
                    "dispatch_attempts": [{"status": "future_status"}],
                }
            ],
            "jobs": {"not": "a list"},
            "job-entry": ["not an object"],
            "job-status": [{"job_id": "job-1", "status": []}],
            "job-status-future": [{"job_id": "job-1", "status": "future_status"}],
            "subagent-incidents": {"not": "a list"},
            "subagent-incident-entry": ["not an object"],
            "subagent-incident-status": [
                {"incident_id": "incident-1", "status": {}}
            ],
            "subagent-incident-status-future": [
                {"incident_id": "incident-1", "status": "future_status"}
            ],
        }
        for name, malformed in cases.items():
            with self.subTest(name=name):
                raw_state = json.loads(self.legacy_bytes().decode("utf-8"))
                if name.startswith("packet"):
                    raw_state["packets"] = malformed
                elif name.startswith("job"):
                    raw_state["jobs"] = malformed
                else:
                    raw_state["subagent_incidents"] = malformed
                h.atomic_write_json(h.task_state_path(self.paths, self.TASK), raw_state)
                with self.assertRaises(store.SemanticStoreError) as caught:
                    self.migrate()
                self.assertNotIn("TypeError", str(caught.exception))
                self.assertNotIn("Traceback", str(caught.exception))
                shown = self.cli(
                    "semantic-migrate",
                    "--task",
                    self.TASK,
                    "--command-id",
                    self.COMMAND,
                    "--expected-legacy-state-sha256",
                    hashlib.sha256(self.legacy_bytes()).hexdigest(),
                    ok=False,
                )
                self.assertNotIn("TypeError", shown.stderr)
                self.assertNotIn("Traceback", shown.stderr)
                self.assertFalse(store.semantic_event_directory(self.paths, self.TASK).exists())
                h.atomic_write_bytes(h.task_state_path(self.paths, self.TASK), original)

    def test_successor_completes_existing_rollback_marker_without_rewriting_it(self) -> None:
        raw = self.legacy_bytes()
        migrated = self.migrate()
        receipt = store.validate_semantic_migration(self.paths, self.TASK)
        command_id = "rollback-successor-r1"
        marker_path = (
            h.task_dir(self.paths, self.TASK)
            / store.SEMANTIC_DIRECTORY_NAME
            / store.MIGRATION_ROLLBACK_NAME
        )
        original_create = h.atomic_create_bytes

        def publish_marker_then_raise(path: Path, payload: bytes) -> None:
            original_create(path, payload)
            if path == marker_path:
                raise h.HarnessError("injected post-marker interruption")

        with mock.patch.object(h, "atomic_create_bytes", side_effect=publish_marker_then_raise):
            with h.state_lock(self.paths, create_layout=False):
                with self.assertRaisesRegex(h.HarnessError, "post-marker"):
                    store.rollback_semantic_migration(
                        self.paths,
                        self.TASK,
                        command_id=command_id,
                        expected_head_sha256=migrated.event["event_sha256"],
                        expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                        recorded_at="2026-07-18T00:01:00+00:00",
                        authority_ref=AUTHORITY,
                    )
        marker_before = marker_path.read_bytes()
        with h.state_lock(self.paths, create_layout=False):
            marker, replay = store.rollback_semantic_migration(
                self.paths,
                self.TASK,
                command_id=command_id,
                expected_head_sha256=migrated.event["event_sha256"],
                expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                recorded_at="2026-07-18T00:02:00+00:00",
                authority_ref="chief:successor@2",
            )
        self.assertTrue(replay)
        self.assertEqual(marker_path.read_bytes(), marker_before)
        self.assertEqual(marker["authority_ref"], AUTHORITY)
        self.assertEqual(self.legacy_bytes(), raw)

        with h.state_lock(self.paths, create_layout=False):
            with self.assertRaisesRegex(store.SemanticStoreError, "command conflicts"):
                store.rollback_semantic_migration(
                    self.paths,
                    self.TASK,
                    command_id="rollback-successor-wrong-command",
                    expected_head_sha256=migrated.event["event_sha256"],
                    expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                    recorded_at="2026-07-18T00:03:00+00:00",
                    authority_ref="chief:successor@2",
                )
            with self.assertRaisesRegex(store.SemanticStoreError, "untouched migration genesis"):
                store.rollback_semantic_migration(
                    self.paths,
                    self.TASK,
                    command_id=command_id,
                    expected_head_sha256="0" * 64,
                    expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                    recorded_at="2026-07-18T00:03:00+00:00",
                    authority_ref="chief:successor@2",
                )

    def test_snapshot_only_retry_refuses_to_erase_newer_legacy_state(self) -> None:
        raw = self.legacy_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        snapshot = store.legacy_snapshot_path(self.paths, self.TASK)
        event_directory = store.semantic_event_directory(self.paths, self.TASK)
        event_directory.mkdir(parents=True)
        if sys.platform != "win32":
            snapshot.parent.chmod(0o700)
            event_directory.chmod(0o700)
        h.atomic_create_bytes(snapshot, raw)

        newer = json.loads(raw.decode("utf-8"))
        newer["revision"] = int(newer["revision"]) + 1
        newer["updated_at"] = "2026-07-18T00:00:01+00:00"
        h.atomic_write_json(h.task_state_path(self.paths, self.TASK), newer)
        newer_bytes = self.legacy_bytes()

        with h.state_lock(self.paths, create_layout=False):
            with self.assertRaisesRegex(
                store.SemanticStoreError, "changed after the migration snapshot"
            ):
                store.migrate_legacy_task(
                    self.paths,
                    self.TASK,
                    command_id=self.COMMAND,
                    expected_legacy_sha256=digest,
                    recorded_at=MIGRATED_AT,
                    authority_ref=AUTHORITY,
                )
        self.assertEqual(self.legacy_bytes(), newer_bytes)
        self.assertFalse(
            (
                store.semantic_event_directory(self.paths, self.TASK)
                / semantic.event_filename(1)
            ).exists()
        )

    def test_pre_transition_rollback_restores_exact_legacy_bytes_and_is_idempotent(self) -> None:
        raw = self.legacy_bytes()
        migrated = self.migrate()
        receipt = store.validate_semantic_migration(self.paths, self.TASK)
        with h.state_lock(self.paths, create_layout=False):
            marker, replay = store.rollback_semantic_migration(
                self.paths,
                self.TASK,
                command_id="rollback-semantic-v2-r1",
                expected_head_sha256=migrated.event["event_sha256"],
                expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                recorded_at="2026-07-18T00:01:00+00:00",
                authority_ref=AUTHORITY,
            )
        self.assertFalse(replay)
        self.assertEqual(self.legacy_bytes(), raw)
        self.assertTrue(store.semantic_migration_rolled_back(self.paths, self.TASK))
        self.assertFalse(store.has_semantic_ledger(self.paths, self.TASK))
        self.assertNotIn("_semantic", h.load_task(self.paths, self.TASK))

        with h.state_lock(self.paths, create_layout=False):
            marker2, replay2 = store.rollback_semantic_migration(
                self.paths,
                self.TASK,
                command_id="rollback-semantic-v2-r1",
                expected_head_sha256=migrated.event["event_sha256"],
                expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                recorded_at="2026-07-18T05:00:00+00:00",
                authority_ref=AUTHORITY,
            )
        self.assertTrue(replay2)
        self.assertEqual(marker2, marker)
        self.assertEqual(self.legacy_bytes(), raw)

        # Completion, rather than permanent live-state equality with the old
        # snapshot, makes the semantic archive inert.  A later legacy mutation
        # must not reactivate the ledger or be erased by an exact rollback
        # replay.
        with h.state_lock(self.paths, create_layout=False):
            legacy = h.load_task(self.paths, self.TASK)
            h.bump_task(legacy)
            h.write_task(self.paths, legacy)
        advanced_legacy_bytes = self.legacy_bytes()
        self.assertNotEqual(advanced_legacy_bytes, raw)
        self.assertFalse(store.has_semantic_ledger(self.paths, self.TASK))
        self.assertTrue(store.semantic_migration_rolled_back(self.paths, self.TASK))
        self.assertEqual(store.semantic_integrity_errors(self.paths, self.TASK), [])
        with h.state_lock(self.paths, create_layout=False):
            marker3, replay3 = store.rollback_semantic_migration(
                self.paths,
                self.TASK,
                command_id="rollback-semantic-v2-r1",
                expected_head_sha256=migrated.event["event_sha256"],
                expected_migration_receipt_sha256=receipt[
                    "migration_receipt_sha256"
                ],
                recorded_at="2026-07-18T06:00:00+00:00",
                authority_ref=AUTHORITY,
            )
        self.assertTrue(replay3)
        self.assertEqual(marker3, marker)
        self.assertEqual(self.legacy_bytes(), advanced_legacy_bytes)

    def test_migration_receipt_tamper_reaches_integrity_gate(self) -> None:
        self.migrate()
        receipt_path = store.migration_receipt_path(self.paths, self.TASK)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["tool_version"] = "tampered"
        receipt_path.write_bytes(semantic.canonical_json_bytes(receipt))
        errors = store.semantic_integrity_errors(self.paths, self.TASK)
        self.assertTrue(any("digest mismatch" in error for error in errors), errors)
        shown = self.cli("semantic-head", "--task", self.TASK, "--json", ok=False)
        self.assertIn("semantic authority is invalid", shown.stderr)

    def test_rollback_is_forbidden_after_first_post_genesis_transition(self) -> None:
        migrated = self.migrate()
        receipt = store.validate_semantic_migration(self.paths, self.TASK)
        result = semantic.projection_domain(migrated.projection)
        result["revision"] = int(result["revision"]) + 1
        with h.state_lock(self.paths, create_layout=False):
            store.append_semantic_transition(
                self.paths,
                self.TASK,
                result,
                event_type="task_checkpointed",
                command_id="post-migration-r2",
                recorded_at="2026-07-18T00:01:00+00:00",
                authority_ref=AUTHORITY,
                expected_head_sha256=migrated.event["event_sha256"],
            )
        with h.state_lock(self.paths, create_layout=False):
            with self.assertRaisesRegex(store.SemanticStoreError, "untouched migration genesis"):
                store.rollback_semantic_migration(
                    self.paths,
                    self.TASK,
                    command_id="rollback-too-late-r1",
                    expected_head_sha256=migrated.event["event_sha256"],
                    expected_migration_receipt_sha256=receipt["migration_receipt_sha256"],
                    recorded_at="2026-07-18T00:02:00+00:00",
                    authority_ref=AUTHORITY,
                )

    def test_cli_migrate_head_and_pre_transition_rollback(self) -> None:
        raw = self.legacy_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        migrated = json.loads(
            self.cli(
                "semantic-migrate",
                "--task",
                self.TASK,
                "--command-id",
                self.COMMAND,
                "--expected-legacy-state-sha256",
                digest,
                "--json",
            ).stdout
        )
        head = json.loads(
            self.cli("semantic-head", "--task", self.TASK, "--json").stdout
        )
        self.assertEqual(head["event_sha256"], migrated["head_event_sha256"])
        self.assertEqual(head["migration_receipt_sha256"], migrated["migration_receipt_sha256"])

        unavailable = self.cli("semantic-transition", "--help", ok=False)
        self.assertIn("invalid choice", unavailable.stderr)

        other = "semantic-cli-rollback"
        self.init_task(other)
        other_state_path = h.task_state_path(self.paths, other)
        other_raw = other_state_path.read_bytes()
        other_migration = json.loads(
            self.cli(
                "semantic-migrate",
                "--task",
                other,
                "--command-id",
                "migrate-cli-rollback-r1",
                "--expected-legacy-state-sha256",
                hashlib.sha256(other_raw).hexdigest(),
                "--json",
            ).stdout
        )
        rolled_back = json.loads(
            self.cli(
                "semantic-migration-rollback",
                "--task",
                other,
                "--command-id",
                "rollback-cli-r1",
                "--expected-head-sha256",
                other_migration["head_event_sha256"],
                "--expected-migration-receipt-sha256",
                other_migration["migration_receipt_sha256"],
                "--json",
            ).stdout
        )
        self.assertEqual(rolled_back["semantic_history"], "inert_preserved_archive")
        self.assertEqual(other_state_path.read_bytes(), other_raw)
        archived_head = json.loads(
            self.cli("semantic-head", "--task", other, "--json").stdout
        )
        self.assertEqual(
            archived_head["semantic_authority_status"], "inert_rollback_archive"
        )

    def test_cli_close_appends_final_semantic_event_and_exact_retry(self) -> None:
        self.cli(
            "set-delivery",
            "--task",
            self.TASK,
            "--mode",
            "local-only",
            "--detail",
            "Semantic close test remains local",
        )
        self.cli(
            "checkpoint",
            "--task",
            self.TASK,
            "--fact",
            "Pre-existing fact is not the close summary",
            "--next-action",
            "Close through the semantic writer",
        )
        raw = self.legacy_bytes()
        migrated = json.loads(
            self.cli(
                "semantic-migrate",
                "--task",
                self.TASK,
                "--command-id",
                self.COMMAND,
                "--expected-legacy-state-sha256",
                hashlib.sha256(raw).hexdigest(),
                "--json",
            ).stdout
        )
        close_args = (
            "close-task",
            "--task",
            self.TASK,
            "--summary",
            "Semantic close is event-authoritative",
            "--outcome",
            "partial",
            "--boundary-disposition",
            "The test intentionally validates only semantic close mechanics",
            "--semantic-command-id",
            "semantic-close-r2",
            "--semantic-expected-head-sha256",
            migrated["head_event_sha256"],
            "--json",
        )
        checkpoint_path = h.task_dir(self.paths, self.TASK) / "checkpoint.md"
        checkpoint_before = checkpoint_path.read_bytes()
        stale_args = list(close_args)
        stale_args[stale_args.index("semantic-close-r2")] = "semantic-close-stale-r2"
        stale_args[stale_args.index(migrated["head_event_sha256"])] = "0" * 64
        self.cli(*stale_args, ok=False)
        self.assertEqual(checkpoint_path.read_bytes(), checkpoint_before)

        reused_args = list(close_args)
        reused_args[reused_args.index("semantic-close-r2")] = self.COMMAND
        self.cli(*reused_args, ok=False)
        self.assertEqual(checkpoint_path.read_bytes(), checkpoint_before)

        closed = json.loads(self.cli(*close_args).stdout)
        self.assertEqual(closed["status"], "done")
        self.assertFalse(closed["idempotent_replay"])
        state = h.load_task(self.paths, self.TASK)
        self.assertEqual(state["status"], "done")
        self.assertEqual(state["_semantic"]["sequence"], 2)
        closed_checkpoint = checkpoint_path.read_bytes()
        unrelated_fact_retry = list(close_args)
        unrelated_fact_retry[
            unrelated_fact_retry.index("Semantic close is event-authoritative")
        ] = "Pre-existing fact is not the close summary"
        rejected = self.cli(*unrelated_fact_retry, ok=False)
        self.assertIn("semantic close retry differs", rejected.stderr)
        self.assertEqual(checkpoint_path.read_bytes(), closed_checkpoint)
        checkpoint_path.unlink()
        retried = json.loads(self.cli(*close_args).stdout)
        self.assertTrue(retried["idempotent_replay"])
        self.assertEqual(retried["semantic_head_sha256"], closed["semantic_head_sha256"])
        self.assertEqual(checkpoint_path.read_bytes(), closed_checkpoint)


if __name__ == "__main__":
    import unittest

    unittest.main()
