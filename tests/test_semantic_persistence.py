#!/usr/bin/env python3
"""Filesystem adversarial tests for the opt-in semantic-v2 genesis store."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import codex_hook  # noqa: E402
from aoi_orgware import semantic_events as semantic  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware.config import default_config_text  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


TASK_ID = "semantic-persistence"
AUTHORITY = "chief-session:fixture@2"
RECORDED_AT = "2026-07-18T00:00:00+00:00"


class SemanticPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "aoi.toml").write_text(
            default_config_text("Semantic persistence tests"), encoding="utf-8"
        )
        self.paths = h.get_paths(self.root)
        h.task_dir(self.paths, TASK_ID).mkdir(parents=True)
        self.state = {"task_id": TASK_ID, "revision": 1, "rows": ["a", "b"]}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def initialize(self) -> dict[str, object]:
        return store.initialize_semantic_task(
            self.paths,
            self.state,
            command_id="init-semantic-persistence",
            recorded_at=RECORDED_AT,
            authority_ref=AUTHORITY,
        )

    def append(self, *args, **kwargs):
        # This low-level fixture intentionally builds only the task directory,
        # not a complete AOI Chief layout. CLI/migration integration tests use
        # the real state lock; these tests isolate append/recovery mechanics.
        with mock.patch.object(h, "_require_chief_lock"):
            return store.append_semantic_transition(*args, **kwargs)

    def event_path(self, sequence: int = 1) -> Path:
        return store.semantic_event_directory(self.paths, TASK_ID) / semantic.event_filename(sequence)

    def test_genesis_is_canonical_event_before_current_projection_and_retry_is_idempotent(self) -> None:
        projection = self.initialize()
        raw = self.event_path().read_bytes()
        self.assertEqual(raw, semantic.canonical_json_bytes(json.loads(raw.decode("utf-8"))))
        self.assertTrue(store.has_semantic_ledger(self.paths, TASK_ID))
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "current")
        self.assertEqual(store.load_semantic_task(self.paths, TASK_ID), projection)
        before = raw

        retried = store.initialize_semantic_task(
            self.paths,
            self.state,
            command_id="init-semantic-persistence",
            recorded_at="2026-07-18T01:00:00+00:00",
            authority_ref=AUTHORITY,
        )
        self.assertEqual(retried, projection)
        self.assertEqual(self.event_path().read_bytes(), before)

        changed = dict(self.state, revision=2)
        with self.assertRaisesRegex(store.SemanticStoreError, "command conflict"):
            store.initialize_semantic_task(
                self.paths,
                changed,
                command_id="init-semantic-persistence",
                recorded_at=RECORDED_AT,
                authority_ref=AUTHORITY,
            )
        self.assertEqual(self.event_path().read_bytes(), before)

    def test_empty_private_init_directory_is_recoverable_but_residue_is_not(self) -> None:
        event_directory = store.semantic_event_directory(self.paths, TASK_ID)
        event_directory.mkdir(parents=True)
        if os.name != "nt":
            event_directory.parent.chmod(0o700)
            event_directory.chmod(0o700)
        projection = self.initialize()
        self.assertEqual(semantic.projection_domain(projection), self.state)

        h.task_state_path(self.paths, TASK_ID).unlink()
        self.event_path().unlink()
        residue = event_directory / ".aoi-v2-c.invalid"
        residue.write_bytes(b"residue")
        with self.assertRaisesRegex(store.SemanticStoreError, "unexpected file"):
            self.initialize()

    def test_private_empty_root_only_interrupt_is_recoverable_but_residue_is_not(self) -> None:
        semantic_root = store.semantic_event_directory(self.paths, TASK_ID).parent
        semantic_root.mkdir(parents=True)
        if os.name != "nt":
            semantic_root.chmod(0o700)
        projection = self.initialize()
        self.assertEqual(semantic.projection_domain(projection), self.state)

        h.task_state_path(self.paths, TASK_ID).unlink()
        self.event_path().unlink()
        store.semantic_event_directory(self.paths, TASK_ID).rmdir()
        residue = semantic_root / "unexpected.txt"
        residue.write_text("residue", encoding="utf-8")
        with self.assertRaisesRegex(store.SemanticStoreError, "not empty"):
            self.initialize()

    def test_projection_without_ledger_is_rejected_before_event_publication(self) -> None:
        h.atomic_write_json(h.task_state_path(self.paths, TASK_ID), self.state)
        with self.assertRaisesRegex(store.SemanticStoreError, "without a genesis event"):
            self.initialize()
        self.assertFalse(store.semantic_event_directory(self.paths, TASK_ID).exists())

    def test_duplicate_keys_and_noncanonical_event_bytes_fail_closed(self) -> None:
        self.initialize()
        self.event_path().write_bytes(b'{"schema_version":2,"schema_version":2}')
        with self.assertRaisesRegex(store.SemanticStoreError, "duplicate key"):
            store.load_semantic_task(self.paths, TASK_ID)

        self.event_path().write_bytes(
            json.dumps(
                semantic.create_genesis_event(
                    self.state,
                    command_id="init-semantic-persistence",
                    recorded_at=RECORDED_AT,
                    authority_ref=AUTHORITY,
                ),
                indent=2,
                ensure_ascii=False,
            ).encode("utf-8")
        )
        with self.assertRaisesRegex(store.SemanticStoreError, "not canonical"):
            store.load_semantic_task(self.paths, TASK_ID)

    def test_gap_unexpected_file_and_tamper_fail_closed(self) -> None:
        self.initialize()
        self.event_path().rename(self.event_path(2))
        with self.assertRaisesRegex(store.SemanticStoreError, "sequence gap"):
            store.load_semantic_task(self.paths, TASK_ID)

        self.event_path(2).rename(self.event_path())
        extra = store.semantic_event_directory(self.paths, TASK_ID) / "notes.txt"
        extra.write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(store.SemanticStoreError, "unexpected file"):
            store.load_semantic_task(self.paths, TASK_ID)
        extra.unlink()

        event = json.loads(self.event_path().read_text(encoding="utf-8"))
        event["payload"]["snapshot"]["revision"] = 99
        self.event_path().write_bytes(semantic.canonical_json_bytes(event))
        with self.assertRaisesRegex(store.SemanticStoreError, "replay failed"):
            store.load_semantic_task(self.paths, TASK_ID)

    def test_private_bounded_event_namespace_fails_before_replay(self) -> None:
        self.initialize()
        # The bytes need not be a valid event: reaching a second entry is
        # already beyond this test's artificial enumeration budget.
        self.event_path(2).write_bytes(b"{}")
        with mock.patch.object(store, "MAX_SEMANTIC_EVENT_FILES", 1):
            with self.assertRaisesRegex(store.SemanticStoreError, "enumeration bound"):
                store.load_semantic_task(self.paths, TASK_ID)
        if os.name != "nt":
            self.event_path(2).unlink()
            self.event_path().chmod(0o644)
            with self.assertRaisesRegex(store.SemanticStoreError, "not private"):
                store.load_semantic_task(self.paths, TASK_ID)

    def test_projection_size_is_rejected_before_genesis_publication(self) -> None:
        self.state["large"] = "x" * 512
        with mock.patch.object(h, "MANAGED_JSON_MAX_BYTES", 256):
            with self.assertRaisesRegex(store.SemanticStoreError, "state byte bound"):
                self.initialize()
        self.assertFalse(store.semantic_event_directory(self.paths, TASK_ID).exists())

    def test_missing_behind_and_current_projection_are_distinguished_and_repaired(self) -> None:
        first_projection = self.initialize()
        h.task_state_path(self.paths, TASK_ID).unlink()
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "missing")
        self.assertEqual(store.load_semantic_task(self.paths, TASK_ID), first_projection)
        with self.assertRaisesRegex(store.SemanticStoreError, "command id differs"):
            store.repair_semantic_projection(
                self.paths, TASK_ID, expected_command_id="different-init-command"
            )
        self.assertEqual(store.repair_semantic_projection(self.paths, TASK_ID), first_projection)
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "current")

        first_event = json.loads(self.event_path().read_text(encoding="utf-8"))
        second_state = dict(self.state, revision=2, rows=["a", "x", "b"])
        second_event = semantic.create_transition_event(
            first_event,
            self.state,
            second_state,
            event_type="task_checkpointed",
            command_id="checkpoint-semantic-persistence-r2",
            recorded_at="2026-07-18T00:01:00+00:00",
            authority_ref=AUTHORITY,
        )
        h.atomic_create_bytes(
            self.event_path(2), semantic.canonical_json_bytes(second_event)
        )
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "behind")
        replayed = store.load_semantic_task(self.paths, TASK_ID)
        self.assertEqual(semantic.projection_domain(replayed), second_state)
        self.assertEqual(store.repair_semantic_projection(self.paths, TASK_ID), replayed)
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "current")

    def test_authoritative_append_uses_expected_head_and_exact_retry(self) -> None:
        initial = self.initialize()
        head = store.semantic_head(self.paths, TASK_ID)
        result_state = dict(semantic.projection_domain(initial), revision=2)

        appended = self.append(
            self.paths,
            TASK_ID,
            result_state,
            event_type="task_checkpointed",
            command_id="checkpoint-semantic-persistence-r2",
            recorded_at="2026-07-18T00:01:00+00:00",
            authority_ref=AUTHORITY,
            expected_head_sha256=head["event_sha256"],
        )
        self.assertFalse(appended.idempotent_replay)
        self.assertEqual(appended.event["sequence"], 2)
        self.assertEqual(
            semantic.projection_domain(appended.projection), result_state
        )
        event_before = self.event_path(2).read_bytes()

        retried = self.append(
            self.paths,
            TASK_ID,
            result_state,
            event_type="task_checkpointed",
            command_id="checkpoint-semantic-persistence-r2",
            recorded_at="2026-07-18T05:00:00+00:00",
            authority_ref=AUTHORITY,
            expected_head_sha256=head["event_sha256"],
        )
        self.assertTrue(retried.idempotent_replay)
        self.assertEqual(self.event_path(2).read_bytes(), event_before)
        self.assertEqual(store.semantic_head(self.paths, TASK_ID)["sequence"], 2)

        with self.assertRaisesRegex(store.SemanticStoreError, "expected head"):
            self.append(
                self.paths,
                TASK_ID,
                dict(result_state, revision=3),
                event_type="task_checkpointed",
                command_id="checkpoint-semantic-persistence-r3",
                recorded_at="2026-07-18T00:02:00+00:00",
                authority_ref=AUTHORITY,
                expected_head_sha256=head["event_sha256"],
            )
        with self.assertRaisesRegex(store.SemanticStoreError, "different semantics"):
            self.append(
                self.paths,
                TASK_ID,
                dict(result_state, revision=99),
                event_type="task_checkpointed",
                command_id="checkpoint-semantic-persistence-r2",
                recorded_at="2026-07-18T00:02:00+00:00",
                authority_ref=AUTHORITY,
                expected_head_sha256=head["event_sha256"],
            )

    def test_authoritative_append_requires_the_project_state_lock(self) -> None:
        initial = self.initialize()
        head = store.semantic_head(self.paths, TASK_ID)
        with self.assertRaisesRegex(h.HarnessError, "requires the project state lock"):
            store.append_semantic_transition(
                self.paths,
                TASK_ID,
                dict(semantic.projection_domain(initial), revision=2),
                event_type="task_checkpointed",
                command_id="checkpoint-without-lock-r2",
                recorded_at="2026-07-18T00:01:00+00:00",
                authority_ref=AUTHORITY,
                expected_head_sha256=head["event_sha256"],
            )

    def test_event_first_append_retry_repairs_projection_without_duplicate(self) -> None:
        initial = self.initialize()
        head = store.semantic_head(self.paths, TASK_ID)
        result_state = dict(semantic.projection_domain(initial), revision=2)
        original_write = h.atomic_write_bytes
        failed = False

        def fail_projection_once(path: Path, payload: bytes) -> None:
            nonlocal failed
            if path == h.task_state_path(self.paths, TASK_ID) and not failed:
                failed = True
                raise h.HarnessError("injected projection publication failure")
            original_write(path, payload)

        with mock.patch.object(h, "atomic_write_bytes", side_effect=fail_projection_once):
            with self.assertRaisesRegex(store.SemanticStoreError, "publish semantic projection"):
                self.append(
                    self.paths,
                    TASK_ID,
                    result_state,
                    event_type="task_checkpointed",
                    command_id="checkpoint-event-first-r2",
                    recorded_at="2026-07-18T00:01:00+00:00",
                    authority_ref=AUTHORITY,
                    expected_head_sha256=head["event_sha256"],
                )
        self.assertTrue(self.event_path(2).is_file())
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "behind")

        retried = self.append(
            self.paths,
            TASK_ID,
            result_state,
            event_type="task_checkpointed",
            command_id="checkpoint-event-first-r2",
            recorded_at="2026-07-18T00:02:00+00:00",
            authority_ref=AUTHORITY,
            expected_head_sha256=head["event_sha256"],
        )
        self.assertTrue(retried.idempotent_replay)
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "current")
        self.assertFalse(self.event_path(3).exists())

    def test_successor_chief_can_repair_exact_published_transition_without_rewriting_event(
        self,
    ) -> None:
        initial = self.initialize()
        head = store.semantic_head(self.paths, TASK_ID)
        result_state = dict(semantic.projection_domain(initial), revision=2)
        appended = self.append(
            self.paths,
            TASK_ID,
            result_state,
            event_type="task_checkpointed",
            command_id="checkpoint-successor-recovery-r2",
            recorded_at="2026-07-18T00:01:00+00:00",
            authority_ref=AUTHORITY,
            expected_head_sha256=head["event_sha256"],
        )
        event_before = self.event_path(2).read_bytes()
        h.atomic_write_bytes(
            h.task_state_path(self.paths, TASK_ID), store._projection_bytes(initial)
        )
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "behind")

        with mock.patch.object(h, "_require_chief_lock"):
            recovered = store.recover_published_semantic_transition(
                self.paths,
                TASK_ID,
                result_state,
                event_type="task_checkpointed",
                command_id="checkpoint-successor-recovery-r2",
                expected_head_sha256=head["event_sha256"],
            )
        self.assertTrue(recovered.idempotent_replay)
        self.assertEqual(recovered.event, appended.event)
        self.assertEqual(self.event_path(2).read_bytes(), event_before)
        self.assertEqual(store.semantic_projection_status(self.paths, TASK_ID), "current")


class SemanticLifecycleIntegrationTests(HarnessTestCase):
    TASK = "semantic-lifecycle"
    COMMAND = "init-semantic-lifecycle-v1"

    def init_semantic(
        self,
        *,
        title: str | None = None,
        next_action: str | None = None,
        worktree: Path | None = None,
        ok: bool = True,
    ):
        command = [
            "init-task",
            "--task-id",
            self.TASK,
            "--title",
            title or f"Task {self.TASK}",
            "--objective",
            "Exercise the semantic lifecycle boundary",
            "--owner",
            "test-root",
            "--completion-boundary",
            "Genesis is replayable and unported mutation is rejected",
            "--semantic-v2",
            "--semantic-command-id",
            self.COMMAND,
            "--json",
        ]
        if next_action is not None:
            command.extend(["--next-action", next_action])
        if worktree is not None:
            command.extend(["--worktree", str(worktree)])
        return self.cli(*command, ok=ok)

    def test_cli_init_read_surfaces_idempotency_and_mutation_boundary(self) -> None:
        initialized = json.loads(self.init_semantic().stdout)
        self.assertTrue(initialized["semantic_v2"])
        self.assertFalse(initialized["idempotent_retry"])
        paths = h.get_paths(self.root)
        state = h.load_task(paths, self.TASK)
        self.assertIn("_semantic", state)
        self.assertEqual(state["semantic_write_policy"], "explicit_transition_only")
        event_path = store.semantic_event_directory(paths, self.TASK) / semantic.event_filename(1)
        event_before = event_path.read_bytes()

        status = json.loads(self.cli("status", "--task", self.TASK, "--json").stdout)
        self.assertEqual(status["task_id"], self.TASK)
        doctor = json.loads(self.cli("doctor", "--task", self.TASK, "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)

        blocked = self.cli(
            "set-phase", "--task", self.TASK, "--phase", "implementing", ok=False
        )
        self.assertIn("requires explicit semantic transitions", blocked.stderr)
        self.assertEqual(event_path.read_bytes(), event_before)

        retried = json.loads(self.init_semantic().stdout)
        self.assertTrue(retried["idempotent_retry"])
        self.assertFalse(retried["projection_repaired"])
        self.assertEqual(event_path.read_bytes(), event_before)
        conflict = self.init_semantic(title="Different request", ok=False)
        self.assertIn("differs in request field", conflict.stderr)

    def test_exact_retry_rejects_different_next_action_and_effective_worktree(self) -> None:
        self.init_semantic(next_action="First exact action")
        paths = h.get_paths(self.root)
        event_path = store.semantic_event_directory(paths, self.TASK) / semantic.event_filename(1)
        event_before = event_path.read_bytes()

        changed_action = self.init_semantic(
            next_action="Different action", ok=False
        )
        self.assertIn("next_action", changed_action.stderr)
        self.assertEqual(event_path.read_bytes(), event_before)

        other = self.root / "other-worktree"
        subprocess.run(
            ["git", "init", "-b", "main", str(other)],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(other), "config", "user.name", "Semantic Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(other), "config", "user.email", "semantic@test.invalid"],
            check=True,
        )
        (other / "tracked.txt").write_text("other\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(other), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(other), "commit", "-m", "other worktree"],
            check=True,
            text=True,
            capture_output=True,
        )
        changed_worktree = self.init_semantic(
            next_action="First exact action", worktree=other, ok=False
        )
        self.assertIn("worktree", changed_worktree.stderr)
        self.assertEqual(event_path.read_bytes(), event_before)

    def test_exact_retry_rejects_a_missing_plan_without_mutation(self) -> None:
        self.init_semantic()
        paths = h.get_paths(self.root)
        plan_path = h.task_dir(paths, self.TASK) / "plan.md"
        event_path = store.semantic_event_directory(paths, self.TASK) / semantic.event_filename(1)
        event_before = event_path.read_bytes()
        state_before = h.task_state_path(paths, self.TASK).read_bytes()
        plan_path.unlink()

        failed = self.init_semantic(ok=False)
        self.assertIn("existing private plan", failed.stderr)
        self.assertFalse(plan_path.exists())
        self.assertEqual(event_path.read_bytes(), event_before)
        self.assertEqual(h.task_state_path(paths, self.TASK).read_bytes(), state_before)

    def test_event_only_task_is_readable_and_exact_init_retry_repairs_projection(self) -> None:
        self.init_semantic()
        paths = h.get_paths(self.root)
        state_path = h.task_state_path(paths, self.TASK)
        state_path.unlink()

        replayed = h.load_task(paths, self.TASK)
        self.assertEqual(replayed["task_id"], self.TASK)
        self.assertIn(self.TASK, {state["task_id"] for state in h.load_all_tasks(paths)})
        doctor = json.loads(self.cli("doctor", "--task", self.TASK, "--json").stdout)
        self.assertTrue(doctor["ok"], doctor)
        self.assertTrue(
            any("projection is missing" in warning for warning in doctor["warnings"]),
            doctor,
        )

        repaired = json.loads(self.init_semantic().stdout)
        self.assertTrue(repaired["idempotent_retry"])
        self.assertTrue(repaired["projection_repaired"])
        self.assertTrue(state_path.is_file())
        self.assertEqual(store.semantic_projection_status(paths, self.TASK), "current")

    def test_session_hook_fails_closed_and_legacy_task_remains_mutable(self) -> None:
        self.init_semantic()
        paths = h.get_paths(self.root)
        session_id = "forged-semantic-session"
        mapping = {
            "schema_version": 1,
            "session_id": session_id,
            "task_id": self.TASK,
            "mapping_kind": "root",
        }
        h.atomic_write_json(h.session_path(paths, session_id), mapping)
        self.assertEqual(codex_hook.session_state(self.root, session_id), ("corrupt", None))
        mapping_path = h.session_path(paths, session_id)
        mapping_before = mapping_path.read_bytes()
        unbind = self.cli(
            "unbind-session", "--session-id", session_id, ok=False
        )
        self.assertIn("requires explicit semantic transitions", unbind.stderr)
        self.assertEqual(mapping_path.read_bytes(), mapping_before)

        token = "forged-semantic-claim"
        claim_path = h.claim_path(paths, token, active=True)
        h.atomic_write_json(
            claim_path,
            {
                "schema_version": h.SCHEMA_VERSION,
                "legacy": False,
                "source": "structured",
                "token": token,
                "task_id": self.TASK,
                "owner": "test-root",
                "kind": "implementation",
                "locks": [],
                "status": "active",
                "worktree": str(self.root),
            },
        )
        claim_before = claim_path.read_bytes()
        blocked_status = self.cli(
            "set-claim-status",
            "--token",
            token,
            "--status",
            "blocked",
            "--reason",
            "must not mutate",
            ok=False,
        )
        self.assertIn("requires explicit semantic transitions", blocked_status.stderr)
        self.assertEqual(claim_path.read_bytes(), claim_before)
        blocked_release = self.cli(
            "release-claim",
            "--token",
            token,
            "--status",
            "released",
            "--reason",
            "must not mutate",
            ok=False,
        )
        self.assertIn("requires explicit semantic transitions", blocked_release.stderr)
        self.assertEqual(claim_path.read_bytes(), claim_before)

        legacy = "legacy-still-mutable"
        self.init_task(legacy)
        self.cli("set-phase", "--task", legacy, "--phase", "implementing")
        self.assertEqual(h.load_task(paths, legacy)["phase"], "implementing")

    def test_semantic_init_rejects_session_and_missing_command_id_before_ledger(self) -> None:
        base = [
            "init-task",
            "--task-id",
            "semantic-invalid-init",
            "--title",
            "Invalid semantic init",
            "--objective",
            "Prove input gates",
            "--owner",
            "test-root",
            "--completion-boundary",
            "No partial semantic ledger exists",
            "--semantic-v2",
        ]
        missing = self.cli(*base, ok=False)
        self.assertIn("invalid semantic command id", missing.stderr)
        with_session = self.cli(
            *base,
            "--semantic-command-id",
            "invalid-init-v1",
            "--session-id",
            "not-supported",
            ok=False,
        )
        self.assertIn("does not support --session-id", with_session.stderr)
        paths = h.get_paths(self.root)
        self.assertFalse(store.has_semantic_ledger(paths, "semantic-invalid-init"))


if __name__ == "__main__":
    unittest.main()
