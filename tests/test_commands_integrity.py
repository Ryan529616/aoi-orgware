"""Focused command-layer contracts for the integrity lifecycle."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from aoi_orgware import harnesslib as h
from aoi_orgware import integrity_records as records
from aoi_orgware.commands import integrity
from harness_case import HarnessTestCase


class IntegrityPersistenceTests(unittest.TestCase):
    def test_legacy_persists_through_write_task(self) -> None:
        state = {"task_id": "task-1", "revision": 1}
        args = SimpleNamespace()
        changed: list[dict[str, object]] = []

        def mutate(value: dict[str, object]):
            value["integrity_contract"] = {"draft": True}
            return value, {"record": "legacy"}

        with (
            mock.patch.object(h, "is_semantic_v2_task", return_value=False),
            mock.patch.object(h, "load_task", return_value=state),
            mock.patch.object(h, "write_task", side_effect=lambda _p, s: changed.append(dict(s))),
            mock.patch.object(h, "write_index"),
        ):
            result = integrity._persist(args, mock.sentinel.paths, "task-1", "integrity_test", mutate)
        self.assertEqual(result["record"], "legacy")
        self.assertFalse(result["idempotent_replay"])
        self.assertEqual(changed[0]["integrity_contract"], {"draft": True})

    def test_semantic_event_is_first_and_exact_retry_never_mutates_again(self) -> None:
        args = SimpleNamespace(
            command_id="integrity-1", recorded_at="2026-07-19T00:00:00+00:00",
            expected_head_sha256="a" * 64, _aoi_authority_ref="chief:s@1",
        )
        state = {"task_id": "task-1"}
        event = {"event_sha256": "b" * 64}
        append = mock.Mock(return_value=SimpleNamespace(event=event, idempotent_replay=False))
        preflight = mock.Mock(return_value={"event_sha256": "a" * 64})
        mutate = mock.Mock(return_value=({"task_id": "task-1", "changed": True}, {"record": "semantic"}))
        with (
            mock.patch.object(h, "is_semantic_v2_task", return_value=True),
            mock.patch.object(h, "load_task", return_value=state),
            mock.patch.object(integrity.store, "semantic_head", return_value={"event_sha256": "a" * 64}),
            mock.patch.object(integrity.store, "preflight_semantic_append", preflight),
            mock.patch.object(integrity.store, "append_semantic_transition", append),
        ):
            result = integrity._persist(args, mock.sentinel.paths, "task-1", "integrity_test", mutate)
        self.assertEqual(result["event_sha256"], "b" * 64)
        preflight.assert_called_once_with(
            mock.sentinel.paths,
            "task-1",
            command_id="integrity-1",
            expected_head_sha256="a" * 64,
        )
        append.assert_called_once()
        self.assertEqual(append.call_args.kwargs["expected_head_sha256"], "a" * 64)

        recover = mock.Mock(return_value=SimpleNamespace(event=event))
        retry_mutate = mock.Mock()
        with (
            mock.patch.object(h, "is_semantic_v2_task", return_value=True),
            mock.patch.object(h, "load_task", return_value={"task_id": "task-1", "changed": True}),
            mock.patch.object(integrity.store, "semantic_head", return_value={"event_sha256": "b" * 64}),
            mock.patch.object(integrity.store, "recover_published_semantic_transition", recover),
        ):
            retry = integrity._persist(
                args, mock.sentinel.paths, "task-1", "integrity_test", retry_mutate,
                retry_intent=lambda _state: None,
            )
        retry_mutate.assert_not_called()
        self.assertTrue(retry["idempotent_replay"])
        recover.assert_called_once()

    def test_semantic_retry_checks_intent_before_recovery_and_never_calls_mutate(self) -> None:
        args = SimpleNamespace(
            command_id="integrity-1", recorded_at="2026-07-19T00:00:00+00:00",
            expected_head_sha256="a" * 64, _aoi_authority_ref="chief:s@1",
        )
        intent = mock.Mock(side_effect=h.HarnessError("changed argument"))
        mutate = mock.Mock()
        recover = mock.Mock()
        with (
            mock.patch.object(h, "is_semantic_v2_task", return_value=True),
            mock.patch.object(h, "load_task", return_value={"task_id": "task-1"}),
            mock.patch.object(integrity.store, "semantic_head", return_value={"event_sha256": "b" * 64}),
            mock.patch.object(integrity.store, "recover_published_semantic_transition", recover),
        ):
            with self.assertRaisesRegex(h.HarnessError, "changed argument"):
                integrity._persist(args, mock.sentinel.paths, "task-1", "integrity_test", mutate, intent)
        intent.assert_called_once()
        mutate.assert_not_called()
        recover.assert_not_called()


class IntegritySemanticRetryIntentTests(unittest.TestCase):
    SHA = "a" * 64
    OTHER_SHA = "b" * 64
    TIME = "2026-07-19T00:00:00+00:00"

    def _artifact_arg(self, sha: str) -> str:
        return f"{Path.cwd() / 'retry-artifact.txt'}={sha}"

    def _contract(self) -> dict[str, object]:
        return {
            "snapshots": [{"purpose": "candidate", "snapshot_sha256": self.SHA, "claim_scope_sha256": self.SHA}],
            "review_results": [{
                "snapshot_sha256": self.SHA, "record_sha256": self.OTHER_SHA,
                "reviewer_agent_id": "reviewer", "outcome": "findings",
                "finding_ids": ["finding-1"], "result_artifact": {"sha256": self.SHA},
            }],
            "fixes": [{
                "finding_id": "finding-1", "post_fix_snapshot_sha256": self.OTHER_SHA,
                "fix_artifact": {"sha256": self.SHA},
            }],
            "review_verifications": [{
                "finding_id": "finding-1", "fix_record_sha256": self.SHA,
                "snapshot_sha256": self.OTHER_SHA, "reviewer_agent_id": "reviewer",
                "outcome": "pass", "verification_artifact": {"sha256": self.SHA},
            }],
        }

    def test_adopt_retry_requires_effective_baseline_and_semantic_timestamp(self) -> None:
        args = SimpleNamespace(baseline_head=None, recorded_at=self.TIME)
        state = {"worktree": str(Path.cwd())}
        contract = {"baseline_head": self.SHA[:40], "adopted_at": self.TIME}
        with (
            mock.patch.object(integrity, "_retry_contract", return_value=contract),
            mock.patch.object(
                integrity.git,
                "git_metadata",
                side_effect=AssertionError("retry must not observe ambient Git HEAD"),
            ),
        ):
            integrity._retry_adopt_intent(args, mock.sentinel.paths, state)
            args.baseline_head = self.OTHER_SHA[:40]
            with self.assertRaisesRegex(h.HarnessError, "published adopt"):
                integrity._retry_adopt_intent(args, mock.sentinel.paths, state)
            args.baseline_head = None
            args.recorded_at = "2026-07-19T00:00:01+00:00"
            with self.assertRaisesRegex(h.HarnessError, "published adopt"):
                integrity._retry_adopt_intent(args, mock.sentinel.paths, state)

    def test_snapshot_review_fix_and_verify_retries_reject_changed_parameters(self) -> None:
        contract = self._contract()
        with mock.patch.object(integrity, "_retry_contract", return_value=contract):
            snapshot = SimpleNamespace(purpose="candidate")
            integrity._retry_snapshot_intent(snapshot, {})
            snapshot.purpose = "post_fix"
            with self.assertRaisesRegex(h.HarnessError, "published snapshot"):
                integrity._retry_snapshot_intent(snapshot, {})

            review = SimpleNamespace(
                snapshot_sha256=self.SHA, reviewer_agent_id="reviewer", outcome="findings",
                finding_id=["finding-1"], result_artifact=self._artifact_arg(self.SHA),
            )
            integrity._retry_review_intent(review, {})
            review.reviewer_agent_id = "other-reviewer"
            with self.assertRaisesRegex(h.HarnessError, "published review"):
                integrity._retry_review_intent(review, {})

            fix = SimpleNamespace(
                finding_id="finding-1", post_fix_snapshot_sha256=self.OTHER_SHA,
                fix_artifact=self._artifact_arg(self.SHA),
            )
            integrity._retry_fix_intent(fix, {})
            fix.post_fix_snapshot_sha256 = self.SHA
            with self.assertRaisesRegex(h.HarnessError, "published fix"):
                integrity._retry_fix_intent(fix, {})

            verify = SimpleNamespace(
                finding_id="finding-1", fix_record_sha256=self.SHA,
                snapshot_sha256=self.OTHER_SHA, reviewer_agent_id="reviewer", outcome="pass",
                verification_artifact=self._artifact_arg(self.SHA),
            )
            integrity._retry_verify_intent(verify, {})
            verify.outcome = "fail"
            with self.assertRaisesRegex(h.HarnessError, "published verification"):
                integrity._retry_verify_intent(verify, {})

    def test_seal_retry_requires_exact_terminal_seal(self) -> None:
        contract = self._contract()
        contract["review_results"] = [{
            "snapshot_sha256": self.SHA, "record_sha256": self.OTHER_SHA,
        }]
        seal = records.build_integrity_seal(
            latest_candidate_snapshot_sha256=self.SHA,
            latest_review_result_record_sha256=self.OTHER_SHA,
            claim_scope_sha256=self.SHA,
            sealed_at=self.TIME,
        )
        contract["seal"] = seal
        args = SimpleNamespace(recorded_at=self.TIME)
        with mock.patch.object(integrity, "_retry_contract", return_value=contract):
            integrity._retry_seal_intent(args, {})
            args.recorded_at = "2026-07-19T00:00:01+00:00"
            with self.assertRaisesRegex(h.HarnessError, "published seal"):
                integrity._retry_seal_intent(args, {})


class IntegrityCompositionTests(unittest.TestCase):
    def test_producers_include_owner_live_claim_and_done_mutator(self) -> None:
        state = {
            "task_id": "task-1", "owner": "/root/chief",
            "packets": [
                {
                    "status": "done",
                    "packet_mode": "bounded_mutation",
                    "agent_id": "/root/implementer",
                },
                {"status": "done", "packet_mode": "read_only", "agent_id": "reader"},
            ],
        }
        with mock.patch.object(h, "claims_owned_by_task", return_value=[
            {"status": "active", "owner": "/root/claimer"},
            {"status": "done", "owner": "old-claimer"},
        ]):
            self.assertEqual(
                integrity._producer_ids(mock.sentinel.paths, state),
                ["/root/chief", "/root/claimer", "/root/implementer"],
            )

    def test_producers_reject_agent_identity_outside_hook_bounds(self) -> None:
        state = {
            "task_id": "task-1",
            "owner": "owner",
            "packets": [
                {
                    "status": "done",
                    "packet_mode": "bounded_mutation",
                    "agent_id": "a" * 513,
                }
            ],
        }
        with (
            mock.patch.object(h, "claims_owned_by_task", return_value=[]),
            self.assertRaisesRegex(h.HarnessError, "1-512 ASCII"),
        ):
            integrity._producer_ids(mock.sentinel.paths, state)

    def test_snapshot_rejects_bad_producer_before_cas_publication(self) -> None:
        state = {
            "task_id": "task-1",
            "owner": "owner with spaces",
            "worktree": "/repo",
            "packets": [],
            "integrity_contract": {"baseline_head": "a" * 40},
        }
        with (
            mock.patch.object(integrity.git, "task_mutation_snapshot", return_value={}),
            mock.patch.object(integrity.h, "claims_owned_by_task", return_value=[]),
            mock.patch.object(
                integrity.git,
                "task_mutation_snapshot_claim_coverage",
                return_value={"covered": True},
            ),
            mock.patch.object(integrity.artifacts, "preserve_generated_artifact_blob") as cas,
        ):
            with self.assertRaisesRegex(h.HarnessError, "task owner agent id"):
                integrity._snapshot(mock.sentinel.paths, state, "candidate")
        cas.assert_not_called()

    def test_snapshot_rejects_uncovered_mutations_before_cas_publication(self) -> None:
        state = {"task_id": "task-1", "worktree": "/repo", "integrity_contract": {"baseline_head": "a" * 40}}
        with (
            mock.patch.object(integrity.git, "task_mutation_snapshot", return_value={}),
            mock.patch.object(integrity.h, "claims_owned_by_task", return_value=[]),
            mock.patch.object(integrity.git, "task_mutation_snapshot_claim_coverage", return_value={"covered": False}),
            mock.patch.object(integrity.artifacts, "preserve_generated_artifact_blob") as cas,
        ):
            with self.assertRaisesRegex(h.HarnessError, "uncovered"):
                integrity._snapshot(mock.sentinel.paths, state, "candidate")
        cas.assert_not_called()

    def test_review_fix_and_verify_reject_bad_principals_before_cas(self) -> None:
        sha = "a" * 64
        artifact_arg = f"{Path(self._tmp.name) / 'preflight.txt'}={sha}"
        cases = [
            (
                integrity.cmd_integrity_review,
                {
                    "snapshots": [{
                        "snapshot_sha256": sha, "purpose": "candidate",
                        "producer_agent_ids": ["producer"],
                    }],
                },
                self._args_for_preflight(
                    snapshot_sha256=sha, reviewer_agent_id="producer",
                    result_artifact=artifact_arg, outcome="clean", finding_id=[],
                ),
                "self-review",
            ),
            (
                integrity.cmd_integrity_fix,
                {
                    "findings": [{"finding_id": "finding-1", "record_sha256": sha}],
                    "snapshots": [{"snapshot_sha256": sha, "purpose": "post_fix"}],
                },
                self._args_for_preflight(
                    finding_id="finding-1", post_fix_snapshot_sha256=sha,
                    fix_artifact=artifact_arg,
                ),
                "task owner agent id",
            ),
            (
                integrity.cmd_integrity_verify,
                {
                    "findings": [{"finding_id": "finding-1"}],
                    "fixes": [{
                        "record_sha256": sha, "finding_id": "finding-1",
                        "post_fix_snapshot_sha256": sha,
                    }],
                },
                self._args_for_preflight(
                    finding_id="finding-1", fix_record_sha256=sha,
                    snapshot_sha256=sha, reviewer_agent_id="reviewer with spaces",
                    verification_artifact=artifact_arg, outcome="pass",
                ),
                "1-512 ASCII",
            ),
        ]
        for command, contract, command_args, message in cases:
            state = {
                "task_id": "task-1", "owner": "owner with spaces",
                "packets": [], "integrity_contract": contract,
            }

            def execute(*call_args: object, **_kwargs: object) -> object:
                mutate = call_args[4]
                return mutate(state)[1]  # type: ignore[operator]

            with (
                self.subTest(command=command.__name__),
                mock.patch.object(h, "state_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(integrity, "_persist", side_effect=execute),
                mock.patch.object(integrity, "_bound_artifact") as cas,
                mock.patch.object(h, "claims_owned_by_task", return_value=[]),
                self.assertRaisesRegex(h.HarnessError, message),
            ):
                command(command_args, mock.sentinel.paths)
            cas.assert_not_called()

    @staticmethod
    def _args_for_preflight(**values: object) -> argparse.Namespace:
        return argparse.Namespace(
            task="task-1", json=True, command_id=None, recorded_at=None,
            expected_head_sha256=None, **values,
        )

    def test_registrar_exposes_all_contract_commands(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command", required=True)
        handlers = {name: mock.Mock() for name in (
            "integrity_adopt", "integrity_snapshot", "integrity_review", "integrity_fix",
            "integrity_verify", "integrity_seal", "integrity_show",
        )}
        integrity.register_integrity_commands(sub, handlers=handlers, add_json_argument=lambda p: p.add_argument("--json", action="store_true"))
        parsed = parser.parse_args(["integrity-snapshot", "--task", "task-1", "--purpose", "candidate"])
        self.assertIs(parsed.handler, handlers["integrity_snapshot"])

    def test_bound_artifact_uses_task_relative_cas_ref_and_final_equals_split(self) -> None:
        source = Path(self._tmp.name) / "result=exact.txt"
        source.write_bytes(b"review bytes\n")
        paths = mock.sentinel.paths
        preserved = {
            "path": str(Path("C:/state/tasks/task-1/results/artifact-blobs/aa/blob")),
            "sha256": "a" * 64,
            "size_bytes": 13,
        }
        with (
            mock.patch.object(h, "task_dir", return_value=Path("C:/state/tasks/task-1")),
            mock.patch.object(integrity.artifacts, "prepare_bound_artifacts", return_value=[{}]) as prepare,
            mock.patch.object(integrity.artifacts, "preserve_bound_artifacts", return_value=[preserved]),
        ):
            ref = integrity._bound_artifact(paths, "task-1", f"{source}={'a' * 64}", "review artifact")
        self.assertEqual(ref["path"], "results/artifact-blobs/aa/blob")
        self.assertEqual(prepare.call_args.args[0], [f"{source}={'a' * 64}"])
        with self.assertRaisesRegex(h.HarnessError, "absolute-path=sha256"):
            integrity._bound_artifact(paths, "task-1", f"={'a' * 64}", "review artifact")

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._tmp.cleanup()


class IntegrityLegacyEndToEndTests(HarnessTestCase):
    """Exercise the real CAS path; CLI registration intentionally remains external."""

    TASK = "integrity-legacy"

    def _args(self, **values: object) -> argparse.Namespace:
        return argparse.Namespace(json=True, command_id=None, recorded_at=None,
                                  expected_head_sha256=None, **values)

    def test_adopt_rejects_ineligible_owner_before_one_way_transition(self) -> None:
        task_id = "integrity-ineligible-owner"
        self.cli(
            "init-task",
            "--task-id", task_id,
            "--title", "Integrity owner preflight",
            "--objective", "Prove one-way adoption validates producer principals",
            "--owner", "owner with spaces",
            "--completion-boundary", "Adoption rejects before persistence",
        )
        result = self.cli("integrity-adopt", "--task", task_id, ok=False)
        self.assertIn("task owner agent id", result.stderr)
        self.assertNotIn("integrity_contract", h.load_task(h.get_paths(self.root), task_id))

    def test_post_adopt_claim_rejects_bad_owner_without_any_mutation(self) -> None:
        task_id = "integrity-claim-owner-gate"
        self.init_task(task_id)
        self.cli("integrity-adopt", "--task", task_id)
        paths = h.get_paths(self.root)
        state_path = h.task_dir(paths, task_id) / "state.json"
        before = state_path.read_bytes()
        result = self.cli(
            "claim", "--task", task_id, "--token", "invalid-owner-claim",
            "--owner", "owner with spaces", "--kind", "implementation",
            "--lock", "repo:file:invalid-owner.txt", "--allow-nonexistent",
            "--intent", "must fail before claim publication",
            "--validation", "claim and task bytes remain unchanged",
            "--expires-at", "2099-01-01T00:00:00+00:00", ok=False,
        )
        self.assertIn("claim owner agent id", result.stderr)
        self.assertEqual(state_path.read_bytes(), before)
        self.assertFalse(h.claim_path(paths, "invalid-owner-claim", active=True).exists())
        self.assertFalse(h.claim_path(paths, "invalid-owner-claim", active=False).exists())

    def test_adopt_candidate_clean_review_and_seal_with_real_cas(self) -> None:
        self.init_task(self.TASK)
        self.cli(
            "claim", "--task", self.TASK, "--token", "integrity-evidence",
            "--owner", "test-root", "--kind", "implementation",
            "--lock", "repo:file:evidence.txt", "--allow-nonexistent", "--intent", "bind integrity evidence",
            "--validation", "candidate snapshot is covered", "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        paths = h.get_paths(self.root)
        integrity.cmd_integrity_adopt(self._args(task=self.TASK, baseline_head=None), paths)
        (self.root / "evidence.txt").write_bytes(b"candidate mutation\n")
        integrity.cmd_integrity_snapshot(self._args(task=self.TASK, purpose="candidate"), paths)
        state = h.load_task(paths, self.TASK)
        candidate = state["integrity_contract"]["snapshots"][-1]
        review_file = Path(self.backup_temp.name) / "review=clean.txt"
        review_file.write_bytes(b"independent review: no findings\n")
        review_digest = hashlib.sha256(review_file.read_bytes()).hexdigest()
        integrity.cmd_integrity_review(
            self._args(
                task=self.TASK, snapshot_sha256=candidate["snapshot_sha256"],
                reviewer_agent_id="independent-reviewer",
                result_artifact=f"{review_file}={review_digest}", outcome="clean",
                finding_id=[],
            ), paths,
        )
        state = h.load_task(paths, self.TASK)
        review = state["integrity_contract"]["review_results"][-1]
        self.assertTrue(review["result_artifact"]["path"].startswith("results/artifact-blobs/"))
        self.assertFalse(Path(review["result_artifact"]["path"]).is_absolute())
        integrity.cmd_integrity_seal(self._args(task=self.TASK), paths)
        sealed = h.load_task(paths, self.TASK)["integrity_contract"]
        self.assertIsNotNone(sealed["seal"])


if __name__ == "__main__":
    unittest.main()
