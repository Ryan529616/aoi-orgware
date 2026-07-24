"""Focused closed-contract tests for semantic claim objects.

Lifecycle integration is exercised through the CLI migration tests; these
small tests pin the object boundary so malformed side data cannot become an
immutable semantic object merely by using the registered object type.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import semantic_claims as claims  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import semantic_store as store  # noqa: E402
from aoi_orgware.commands import task_lifecycle as lifecycle  # noqa: E402
from aoi_orgware.semantic_claims import (  # noqa: E402
    SemanticClaimError,
    validate_semantic_claim_object_payload,
)
from tests.harness_case import HarnessTestCase  # noqa: E402


TASK = "semantic-claim-test"
COMMAND = "semantic-claim-command"
AT = "2026-07-24T00:00:00+00:00"


def payload() -> dict[str, object]:
    claim = {
        "schema_version": 1,
        "legacy": False,
        "source": "structured",
        "token": "claim-token",
        "task_id": TASK,
        "owner": "owner",
        "kind": "implementation",
        "locks": ["repo:file:src/a.py"],
        "intent": "implement contract",
        "validation": "unit test",
        "status": "active",
        "created_at": AT,
        "updated_at": AT,
        "expires_at": "2026-07-25T00:00:00+00:00",
        "worktree": "C:/worktree",
        "baselines": {},
    }
    return {
        "schema_version": 1,
        "operation": "acquire",
        "task_id": TASK,
        "token": "claim-token",
        "command_id": COMMAND,
        "recorded_at": AT,
        "expected_head_sha256": "a" * 64,
        "authority_ref": "chief:test:e1:claim",
        "prior_object_sha256": "0" * 64,
        "claim": claim,
    }


class SemanticClaimObjectPayloadTests(unittest.TestCase):
    def test_closed_acquire_payload_normalizes(self) -> None:
        normalized = validate_semantic_claim_object_payload(payload(), task_id=TASK)
        self.assertEqual(normalized["claim"]["token"], "claim-token")
        self.assertEqual(normalized["prior_object_sha256"], "0" * 64)

    def test_unknown_claim_field_fails_closed(self) -> None:
        value = payload()
        value["claim"]["unreviewed"] = True  # type: ignore[index]
        with self.assertRaisesRegex(SemanticClaimError, "incomplete structured-claim"):
            validate_semantic_claim_object_payload(value, task_id=TASK)

    def test_pending_side_field_cannot_enter_object(self) -> None:
        value = payload()
        value["claim"]["semantic_authority"] = {}  # type: ignore[index]
        with self.assertRaisesRegex(SemanticClaimError, "side-record"):
            validate_semantic_claim_object_payload(value, task_id=TASK)

    def test_acquire_requires_zero_prior(self) -> None:
        value = payload()
        value["prior_object_sha256"] = "a" * 64
        with self.assertRaisesRegex(SemanticClaimError, "zero prior"):
            validate_semantic_claim_object_payload(value, task_id=TASK)

    @staticmethod
    def _authority(phase: str) -> dict[str, object]:
        return {
            "schema_version": 1, "phase": phase, "operation": "acquire",
            "object_sha256": "b" * 64, "binding_sha256": "c" * 64,
            "expected_head_sha256": "a" * 64, "planned_event_sha256": "d" * 64,
            "result_projection_sha256": "e" * 64, "command_id": COMMAND,
            "recorded_at": AT,
        }

    def test_pending_create_rejects_divergent_existing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claim.json"
            path.write_bytes(b"{\"divergent\": true}\n")
            with self.assertRaisesRegex(SemanticClaimError, "divergent bytes"):
                claims._create_or_accept_exact_side(
                    path, claims._side_payload(payload()["claim"], self._authority("pending"))
                )

    def test_release_archives_before_removing_active_side(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            active = Path(temporary) / "active.json"
            archive = Path(temporary) / "archive.json"
            prior = payload()["claim"]
            terminal = dict(prior)
            terminal.update({
                "status": "released", "close_reason": "complete",
                "final_baselines": {}, "baseline_changed": {},
            })
            pending = claims._side_payload(prior, self._authority("pending"))
            active.write_bytes(claims._side_bytes(pending))
            archive.write_bytes(b"{\"divergent\": true}\n")
            with self.assertRaisesRegex(SemanticClaimError, "divergent bytes"):
                claims._repair_release_archive_then_unlink(
                    active, archive, active_claim=prior,
                    pending_authority=self._authority("pending"), archive_claim=terminal,
                    committed_authority=self._authority("committed"),
                )
            self.assertTrue(active.exists(), "active reservation must survive archive failure")
            archive.unlink()
            claims._repair_release_archive_then_unlink(
                active, archive, active_claim=prior,
                pending_authority=self._authority("pending"), archive_claim=terminal,
                committed_authority=self._authority("committed"),
            )
            self.assertTrue(archive.exists())
            self.assertFalse(active.exists())

    def test_retry_rejects_changed_head_metadata(self) -> None:
        args = SimpleNamespace(
            semantic_command_id=COMMAND, expected_head_sha256="b" * 64,
            recorded_at=AT, _aoi_authority_ref="chief:test:e1:claim",
            lock=["repo:file:src/a.py"], owner="owner", kind="implementation",
            intent="implement contract", validation="unit test",
            expires_at="2026-07-25T00:00:00+00:00",
        )
        with self.assertRaisesRegex(SemanticClaimError, "different command metadata"):
            claims._request_matches(payload(), args)


class SemanticClaimCheckpointTests(HarnessTestCase):
    """Pin checkpoint recovery to the event-authoritative claim boundary."""

    def setUp(self) -> None:
        super().setUp()
        self.paths = h.get_paths(self.root)
        self._task_number = 0

    def semantic_task(self, suffix: str) -> tuple[str, str]:
        self._task_number += 1
        task_id = f"semantic-checkpoint-{suffix}-{self._task_number}"
        self.init_task(task_id)
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "local-only",
            "--detail",
            "Focused semantic checkpoint test remains local.",
        )
        state_path = h.task_state_path(self.paths, task_id)
        migrated = json.loads(
            self.cli(
                "semantic-migrate",
                "--task",
                task_id,
                "--command-id",
                f"migrate-{suffix}-{self._task_number}",
                "--expected-legacy-state-sha256",
                hashlib.sha256(state_path.read_bytes()).hexdigest(),
                "--json",
            ).stdout
        )
        return task_id, migrated["head_event_sha256"]

    def checkpoint_args(
        self,
        task_id: str,
        head: str,
        command: str,
        recorded_at: str,
        *,
        fact: str = "Checkpoint fact",
        risk: str = "Checkpoint risk",
        next_action: str = "Run the exact semantic checkpoint retry.",
    ) -> list[str]:
        return [
            "checkpoint",
            "--task",
            task_id,
            "--fact",
            fact,
            "--risk",
            risk,
            "--next-action",
            next_action,
            "--semantic-command-id",
            command,
            "--semantic-expected-head-sha256",
            head,
            "--semantic-recorded-at",
            recorded_at,
            "--json",
        ]

    def semantic_head(self, task_id: str) -> str:
        return json.loads(
            self.cli("semantic-head", "--task", task_id, "--json").stdout
        )["event_sha256"]

    def semantic_claim(self, task_id: str, head: str, token: str) -> str:
        claimed_file = self.root / f"{token}.txt"
        claimed_file.write_text("semantic checkpoint claim fixture\n", encoding="utf-8")
        result = json.loads(
            self.cli(
                "claim",
                "--task",
                task_id,
                "--token",
                token,
                "--owner",
                "checkpoint-test",
                "--kind",
                "implementation",
                "--lock",
                f"repo:file:{claimed_file.name}",
                "--intent",
                "exercise semantic checkpoint claim gating",
                "--validation",
                "focused unittest",
                "--expires-at",
                "2026-07-25T00:00:00+00:00",
                "--semantic-command-id",
                f"acquire-{token}",
                "--semantic-expected-head-sha256",
                head,
                "--semantic-recorded-at",
                "2026-07-24T00:01:00+00:00",
                "--json",
            ).stdout
        )
        return result["event_sha256"]

    def test_checkpoint_requires_complete_semantic_options_and_rejects_legacy_options(self) -> None:
        task_id, head = self.semantic_task("options")
        partial = self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--semantic-command-id",
            "partial-checkpoint",
            "--semantic-expected-head-sha256",
            head,
            ok=False,
        )
        self.assertIn("requires --semantic-command-id", partial.stderr)
        self.assertEqual(self.semantic_head(task_id), head)

        legacy_task = "legacy-checkpoint-options"
        self.init_task(legacy_task)
        rejected = self.cli(
            "checkpoint",
            "--task",
            legacy_task,
            "--semantic-command-id",
            "legacy-command",
            ok=False,
        )
        self.assertIn("require a semantic-v2 task", rejected.stderr)

    def test_checkpoint_is_deterministic_for_revision_timestamp_risk_and_digest(self) -> None:
        task_id, head = self.semantic_task("deterministic")
        before = h.load_task(self.paths, task_id)
        args = self.checkpoint_args(
            task_id,
            head,
            "checkpoint-deterministic",
            "2026-07-24T00:02:00+00:00",
            fact="Deterministic checkpoint fact",
            risk="Deterministic checkpoint risk",
        )
        result = json.loads(self.cli(*args).stdout)
        state = h.load_task(self.paths, task_id)
        checkpoint = h.task_dir(self.paths, task_id) / "checkpoint.md"
        self.assertEqual(state["revision"], before["revision"] + 1)
        self.assertEqual(state["updated_at"], "2026-07-24T00:02:00+00:00")
        self.assertEqual(state["risks"][-1], {
            "id": "r1",
            "text": "Deterministic checkpoint risk",
            "status": "open",
            "recorded_at": "2026-07-24T00:02:00+00:00",
        })
        self.assertEqual(result["checkpoint_sha256"], state["checkpoint_sha256"])
        self.assertEqual(
            state["checkpoint_sha256"], hashlib.sha256(checkpoint.read_bytes()).hexdigest()
        )
        event_before = self.semantic_head(task_id)
        state_before = h.task_state_path(self.paths, task_id).read_bytes()
        checkpoint_before = checkpoint.read_bytes()
        replay = json.loads(self.cli(*args).stdout)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(self.semantic_head(task_id), event_before)
        self.assertEqual(h.task_state_path(self.paths, task_id).read_bytes(), state_before)
        self.assertEqual(checkpoint.read_bytes(), checkpoint_before)

    def test_exact_tail_retry_repairs_missing_or_damaged_checkpoint_without_head_advance(self) -> None:
        task_id, head = self.semantic_task("repair")
        args = self.checkpoint_args(
            task_id, head, "checkpoint-repair", "2026-07-24T00:03:00+00:00"
        )
        first = json.loads(self.cli(*args).stdout)
        checkpoint = h.task_dir(self.paths, task_id) / "checkpoint.md"
        expected = checkpoint.read_bytes()
        checkpoint.unlink()
        repaired = json.loads(self.cli(*args).stdout)
        self.assertTrue(repaired["idempotent_replay"])
        self.assertEqual(repaired["semantic_head_sha256"], first["semantic_head_sha256"])
        self.assertEqual(checkpoint.read_bytes(), expected)
        checkpoint.write_bytes(b"damaged checkpoint\n")
        repaired_again = json.loads(self.cli(*args).stdout)
        self.assertTrue(repaired_again["idempotent_replay"])
        self.assertEqual(repaired_again["semantic_head_sha256"], first["semantic_head_sha256"])
        self.assertEqual(checkpoint.read_bytes(), expected)

    def test_checkpoint_retry_rejects_changed_request_head_or_timestamp(self) -> None:
        task_id, head = self.semantic_task("retry-reject")
        args = self.checkpoint_args(
            task_id, head, "checkpoint-retry-reject", "2026-07-24T00:04:00+00:00"
        )
        self.cli(*args)
        checkpoint = h.task_dir(self.paths, task_id) / "checkpoint.md"
        before = checkpoint.read_bytes()
        cases = (
            ("changed request", "Checkpoint fact changed", head, "2026-07-24T00:04:00+00:00"),
            ("changed head", "Checkpoint fact", "0" * 64, "2026-07-24T00:04:00+00:00"),
            ("changed timestamp", "Checkpoint fact", head, "2026-07-24T00:04:01+00:00"),
        )
        for label, fact, candidate_head, recorded_at in cases:
            with self.subTest(label=label):
                rejected = self.cli(
                    *self.checkpoint_args(
                        task_id,
                        candidate_head,
                        "checkpoint-retry-reject",
                        recorded_at,
                        fact=fact,
                    ),
                    ok=False,
                )
                self.assertIn("semantic checkpoint", rejected.stderr)
                self.assertEqual(checkpoint.read_bytes(), before)

    def test_old_checkpoint_command_cannot_rewrite_after_successor_head(self) -> None:
        task_id, head = self.semantic_task("successor")
        old_args = self.checkpoint_args(
            task_id, head, "checkpoint-old", "2026-07-24T00:05:00+00:00"
        )
        self.cli(*old_args)
        successor_head = self.semantic_head(task_id)
        successor_args = self.checkpoint_args(
            task_id,
            successor_head,
            "checkpoint-successor",
            "2026-07-24T00:05:01+00:00",
            fact="Successor checkpoint fact",
        )
        successor = json.loads(self.cli(*successor_args).stdout)
        checkpoint = h.task_dir(self.paths, task_id) / "checkpoint.md"
        successor_bytes = checkpoint.read_bytes()
        rejected = self.cli(*old_args, ok=False)
        self.assertIn("not the matching terminal transition", rejected.stderr)
        self.assertEqual(self.semantic_head(task_id), successor["semantic_head_sha256"])
        self.assertEqual(checkpoint.read_bytes(), successor_bytes)

    def test_checkpoint_fault_boundaries_recover_with_one_exact_retry(self) -> None:
        original_append = lifecycle.append_semantic_transition
        original_repair = store.repair_semantic_projection
        original_checkpoint = lifecycle.atomic_write_text
        original_index = lifecycle.write_index

        def append_then_interrupt(*args: object, **kwargs: object) -> object:
            original_append(*args, **kwargs)
            raise h.HarnessError("injected checkpoint event interruption")

        def repair_then_interrupt(*args: object, **kwargs: object) -> object:
            original_repair(*args, **kwargs)
            raise h.HarnessError("injected checkpoint projection interruption")

        def checkpoint_then_interrupt(*args: object, **kwargs: object) -> object:
            original_checkpoint(*args, **kwargs)
            raise h.HarnessError("injected checkpoint file interruption")

        def index_then_interrupt(*args: object, **kwargs: object) -> object:
            original_index(*args, **kwargs)
            raise h.HarnessError("injected checkpoint index interruption")

        boundaries = (
            ("event", lifecycle, "append_semantic_transition", append_then_interrupt),
            ("projection", store, "repair_semantic_projection", repair_then_interrupt),
            ("checkpoint", lifecycle, "atomic_write_text", checkpoint_then_interrupt),
            ("index", lifecycle, "write_index", index_then_interrupt),
        )
        for label, module, attribute, interruption in boundaries:
            with self.subTest(boundary=label):
                task_id, head = self.semantic_task(f"fault-{label}")
                args = self.checkpoint_args(
                    task_id,
                    head,
                    f"checkpoint-fault-{label}",
                    "2026-07-24T00:06:00+00:00",
                )
                with mock.patch.object(module, attribute, side_effect=interruption):
                    interrupted = self.cli_in_process(*args, ok=False)
                self.assertIn("injected checkpoint", interrupted.stderr)
                advanced_head = self.semantic_head(task_id)
                self.assertNotEqual(advanced_head, head)
                replay = json.loads(self.cli(*args).stdout)
                self.assertTrue(replay["idempotent_replay"])
                self.assertEqual(replay["semantic_head_sha256"], advanced_head)

    def test_pending_or_divergent_claim_side_blocks_checkpoint_before_event(self) -> None:
        for kind in ("pending", "divergent"):
            with self.subTest(side=kind):
                task_id, head = self.semantic_task(f"claim-{kind}")
                token = f"checkpoint-{kind}"
                claim_head = self.semantic_claim(task_id, head, token)
                active = h.claim_path(self.paths, token, active=True)
                side = h.load_json(active)
                authority = side["semantic_authority"]
                if kind == "pending":
                    authority["phase"] = "pending"
                else:
                    authority["binding_sha256"] = "0" * 64
                h.atomic_write_json(active, side)
                event_count = len(store.load_semantic_events(self.paths, task_id))
                rejected = self.cli(
                    *self.checkpoint_args(
                        task_id,
                        claim_head,
                        f"checkpoint-{kind}-blocked",
                        "2026-07-24T00:07:00+00:00",
                    ),
                    ok=False,
                )
                self.assertIn("semantic claim", rejected.stderr)
                self.assertEqual(
                    len(store.load_semantic_events(self.paths, task_id)), event_count
                )

    def test_acquire_release_checkpoint_and_close_reachability(self) -> None:
        task_id, head = self.semantic_task("close")
        token = "checkpoint-close-claim"
        acquired_head = self.semantic_claim(task_id, head, token)
        released = json.loads(
            self.cli(
                "release-claim",
                "--task",
                task_id,
                "--token",
                token,
                "--status",
                "released",
                "--reason",
                "checkpoint reachability complete",
                "--semantic-command-id",
                "release-checkpoint-close",
                "--semantic-expected-head-sha256",
                acquired_head,
                "--semantic-recorded-at",
                "2026-07-24T00:08:00+00:00",
                "--json",
            ).stdout
        )
        checkpoint = json.loads(
            self.cli(
                *self.checkpoint_args(
                    task_id,
                    released["event_sha256"],
                    "checkpoint-before-close",
                    "2026-07-24T00:08:01+00:00",
                )
            ).stdout
        )
        closed = json.loads(
            self.cli(
                "close-task",
                "--task",
                task_id,
                "--summary",
                "Semantic claim lifecycle reached close.",
                "--outcome",
                "partial",
                "--boundary-disposition",
                "This test covers semantic lifecycle reachability only.",
                "--semantic-command-id",
                "close-after-semantic-claim",
                "--semantic-expected-head-sha256",
                checkpoint["semantic_head_sha256"],
                "--json",
            ).stdout
        )
        self.assertEqual(closed["status"], "done")
        self.assertFalse(h.claim_path(self.paths, token, active=True).exists())
        self.assertTrue(h.claim_path(self.paths, token, active=False).exists())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
