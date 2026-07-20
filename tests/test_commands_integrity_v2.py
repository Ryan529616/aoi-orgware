#!/usr/bin/env python3
"""Focused v2 command identity and semantic-retry contracts."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.commands import integrity_v2 as commands  # noqa: E402


class IntegrityV2CommandTests(unittest.TestCase):
    SHA_A = "a" * 64
    SHA_B = "b" * 64
    SHA_C = "c" * 64

    def _state(self) -> dict[str, object]:
        # Same content SHA is intentionally not the lookup key in v2.
        return {
            "integrity_contract": {
                "schema_version": 2,
                "mode": "required_v2",
                "records": [
                    {"record_type": "snapshot", "record_sha256": self.SHA_A, "snapshot_sha256": self.SHA_C, "claim_scope_sha256": self.SHA_C},
                    {"record_type": "snapshot", "record_sha256": self.SHA_B, "snapshot_sha256": self.SHA_C, "claim_scope_sha256": self.SHA_C},
                ],
                "seal": None,
            }
        }

    def test_snapshot_lookup_uses_record_sha_not_duplicate_content_sha(self) -> None:
        contract = self._state()["integrity_contract"]
        selected = commands._find(contract, "snapshot", "record_sha256", self.SHA_B, "snapshot")
        self.assertEqual(selected["record_sha256"], self.SHA_B)
        self.assertEqual(selected["snapshot_sha256"], self.SHA_C)

    def test_verification_retry_binds_exact_fix_and_snapshot_attempt(self) -> None:
        state = self._state()
        state["integrity_contract"]["records"].append({
            "record_type": "review_verification",
            "record_sha256": self.SHA_C,
            "finding_id": "finding-1",
            "fix_record_sha256": self.SHA_A,
            "verification_snapshot_record_sha256": self.SHA_B,
            "reviewer_agent_id": "verifier",
            "outcome": "pass",
            "verification_artifact": {"sha256": self.SHA_A},
        })
        args = argparse.Namespace(
            finding_id="finding-1", fix_record_sha256=self.SHA_A,
            verification_snapshot_record_sha256=self.SHA_B,
            reviewer_agent_id="verifier", outcome="pass",
            verification_artifact=f"{Path.cwd() / 'artifact.txt'}={self.SHA_A}",
        )
        commands._retry_verify(args, state)
        args.verification_snapshot_record_sha256 = self.SHA_A
        with self.assertRaisesRegex(h.HarnessError, "published v2 semantics"):
            commands._retry_verify(args, state)

    def test_seal_retry_requires_exact_terminal_snapshot_and_recorded_at(self) -> None:
        state = self._state()
        state["integrity_contract"]["records"].append({
            "record_type": "review_result",
            "record_sha256": self.SHA_C,
            "snapshot_record_sha256": self.SHA_B,
            "outcome": "clean",
        })
        state["integrity_contract"]["seal"] = commands.records.build_integrity_seal(
            integrity_seq=4,
            terminal_snapshot_record_sha256=self.SHA_B,
            terminal_review_result_record_sha256=self.SHA_C,
            claim_scope_sha256=self.SHA_C,
            sealed_at="2026-07-19T12:00:00+00:00",
        )
        args = argparse.Namespace(recorded_at="2026-07-19T12:00:00+00:00")
        with mock.patch.object(commands, "_validate"):
            commands._retry_seal(args, state)
            args.recorded_at = "2026-07-19T12:00:01+00:00"
            with self.assertRaisesRegex(h.HarnessError, "published v2 seal"):
                commands._retry_seal(args, state)
            args.recorded_at = "2026-07-19T12:00:00+00:00"
            state["integrity_contract"]["seal"]["terminal_snapshot_record_sha256"] = self.SHA_A
            with self.assertRaisesRegex(h.HarnessError, "seal target"):
                commands._retry_seal(args, state)

    def test_upgrade_retry_requires_exact_source_digest_timestamp_and_provenance(self) -> None:
        args = argparse.Namespace(
            expected_v1_contract_sha256=self.SHA_A,
            recorded_at="2026-07-19T12:00:00+00:00",
            expected_head_sha256=self.SHA_B,
        )
        state = {
            "task_id": "task-v2",
            "integrity_contract": {
                "schema_version": 2,
                "mode": "required_v2",
                "records": [],
                "seal": None,
                "migration_receipt": {
                    "source_schema_version": 1,
                    "source_mode": "required_v1",
                    "source_contract_sha256": self.SHA_A,
                    "source_contract_artifact": {"sha256": self.SHA_A},
                    "migrated_at": args.recorded_at,
                    "source_semantic_head_sha256": self.SHA_B,
                },
            },
        }
        with mock.patch.object(h, "is_semantic_v2_task", return_value=True):
            commands._retry_upgrade(args, mock.sentinel.paths, state)
            args.expected_head_sha256 = self.SHA_C
            with self.assertRaisesRegex(h.HarnessError, "upgrade provenance"):
                commands._retry_upgrade(args, mock.sentinel.paths, state)
            args.expected_head_sha256 = self.SHA_B
            args.recorded_at = "2026-07-19T12:00:01+00:00"
            with self.assertRaisesRegex(h.HarnessError, "upgrade semantics"):
                commands._retry_upgrade(args, mock.sentinel.paths, state)

    def test_response_loss_retries_require_exact_persisted_recorded_at(self) -> None:
        """All nonterminal v2 mutations bind retry time in their ledger event."""

        artifact = f"{Path.cwd() / 'artifact.txt'}={self.SHA_C}"
        base = {"integrity_contract": {"schema_version": 2, "mode": "required_v2", "seal": None}}
        cases = (
            (
                "snapshot", "integrity_snapshot",
                {**base, "integrity_contract": {**base["integrity_contract"], "records": [
                    {"record_type": "snapshot", "record_sha256": self.SHA_A, "purpose": "candidate"},
                ]}},
                argparse.Namespace(purpose="candidate"), commands._retry_snapshot,
            ),
            (
                "review", "integrity_review",
                {**base, "integrity_contract": {**base["integrity_contract"], "records": [
                    {"record_type": "snapshot", "record_sha256": self.SHA_A},
                    {"record_type": "review_result", "record_sha256": self.SHA_B,
                     "snapshot_record_sha256": self.SHA_A, "reviewer_agent_id": "reviewer",
                     "outcome": "clean", "finding_ids": [], "result_artifact": {"sha256": self.SHA_C}},
                ]}},
                argparse.Namespace(snapshot_record_sha256=self.SHA_A, reviewer_agent_id="reviewer",
                                   outcome="clean", finding_id=[], result_artifact=artifact), commands._retry_review,
            ),
            (
                "fix", "integrity_fix",
                {**base, "integrity_contract": {**base["integrity_contract"], "records": [
                    {"record_type": "fix", "record_sha256": self.SHA_B, "finding_id": "finding-1",
                     "post_fix_snapshot_record_sha256": self.SHA_A, "fix_artifact": {"sha256": self.SHA_C}},
                ]}},
                argparse.Namespace(finding_id="finding-1", post_fix_snapshot_record_sha256=self.SHA_A,
                                   fix_artifact=artifact), commands._retry_fix,
            ),
            (
                "verify", "integrity_verify",
                {**base, "integrity_contract": {**base["integrity_contract"], "records": [
                    {"record_type": "review_verification", "record_sha256": self.SHA_C,
                     "finding_id": "finding-1", "fix_record_sha256": self.SHA_A,
                     "verification_snapshot_record_sha256": self.SHA_B,
                     "reviewer_agent_id": "verifier", "outcome": "pass",
                     "verification_artifact": {"sha256": self.SHA_C}},
                ]}},
                argparse.Namespace(finding_id="finding-1", fix_record_sha256=self.SHA_A,
                                   verification_snapshot_record_sha256=self.SHA_B,
                                   reviewer_agent_id="verifier", outcome="pass",
                                   verification_artifact=artifact), commands._retry_verify,
            ),
        )
        exact_time = "2026-07-19T12:00:00+00:00"
        changed_time = "2026-07-19T12:00:01+00:00"
        for name, event_type, state, command_args, retry in cases:
            with self.subTest(command=name), mock.patch.object(commands, "_validate"), \
                    mock.patch.object(h, "is_semantic_v2_task", return_value=True), \
                    mock.patch.object(h, "load_task", return_value=state), \
                    mock.patch.object(commands.store, "semantic_head", return_value={"event_sha256": self.SHA_B}), \
                    mock.patch.object(commands.store, "load_semantic_events") as load_events, \
                    mock.patch.object(commands.store, "recover_published_semantic_transition") as recover:
                command_args.command_id = f"retry-{name}"
                command_args.recorded_at = exact_time
                command_args.expected_head_sha256 = self.SHA_A
                command_args._aoi_authority_ref = "test-authority"
                event = {
                    "command_id": command_args.command_id,
                    "event_type": event_type,
                    "prev_event_sha256": self.SHA_A,
                    "recorded_at": exact_time,
                    "event_sha256": self.SHA_C,
                }
                load_events.return_value = [event]
                recover.return_value = SimpleNamespace(event=event)
                mutate = mock.Mock()
                result = commands._persist(
                    command_args, mock.sentinel.paths, "task-v2", event_type,
                    mutate, lambda recovered_state: retry(command_args, recovered_state),
                )
                self.assertTrue(result["idempotent_replay"])
                mutate.assert_not_called()
                command_args.recorded_at = changed_time
                recover.reset_mock()
                with self.assertRaisesRegex(h.HarnessError, "published recorded_at"):
                    commands._persist(
                        command_args, mock.sentinel.paths, "task-v2", event_type,
                        mutate, lambda recovered_state: retry(command_args, recovered_state),
                    )
                recover.assert_not_called()

    def test_review_findings_publishes_one_validated_batch(self) -> None:
        contract = commands.records.build_integrity_contract(
            baseline_head="a" * 40, adopted_at="2026-07-19T12:00:00+00:00"
        )
        snapshot = commands.records.build_snapshot_record(
            integrity_seq=1, attempt_id=1, task_id="task-v2", worktree="/work/aoi",
            baseline_head="a" * 40, current_head="b" * 40,
            artifact={"path": "evidence/candidate.json", "sha256": self.SHA_A, "size_bytes": 1},
            snapshot_sha256=self.SHA_B, claim_scope_sha256=self.SHA_C,
            covered_claim_tokens=["claim-1"], purpose="candidate",
            producer_agent_ids=["producer"],
        )
        contract = commands.records.append_snapshot(contract, snapshot)
        state = {"task_id": "task-v2", "worktree": "/work/aoi", "integrity_contract": contract}
        artifact = {"path": "evidence/review.md", "sha256": self.SHA_C, "size_bytes": 1}
        args = argparse.Namespace(
            task="task-v2", snapshot_record_sha256=snapshot["record_sha256"],
            reviewer_agent_id="reviewer", result_artifact="ignored", outcome="findings",
            finding_id=["finding-1", "finding-2"], json=True,
        )

        def persist(*call_args: object) -> dict[str, object]:
            updated, result = call_args[4](state)  # type: ignore[operator]
            state.update(updated)
            return dict(result)

        with mock.patch.object(commands.h, "state_lock", return_value=nullcontext()), \
                mock.patch.object(commands.h, "validate_id", return_value="task-v2"), \
                mock.patch.object(commands, "_persist", side_effect=persist), \
                mock.patch.object(commands, "_preflight_artifact", return_value=artifact), \
                mock.patch.object(commands, "_bound_artifact", return_value=artifact), \
                mock.patch.object(commands.records, "append_integrity_record", side_effect=AssertionError("single append is forbidden")), \
                mock.patch.object(commands.records, "append_integrity_records", wraps=commands.records.append_integrity_records) as batch_append, \
                mock.patch.object(commands, "_emit"):
            self.assertEqual(commands.cmd_integrity_review(args, mock.sentinel.paths), 0)

        batch_append.assert_called_once()
        self.assertEqual(
            [record["record_type"] for record in state["integrity_contract"]["records"]],
            ["snapshot", "review_result", "finding", "finding"],
        )


if __name__ == "__main__":
    unittest.main()
