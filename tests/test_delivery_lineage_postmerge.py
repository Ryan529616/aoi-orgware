"""Post-merge delivery lineage and empty semantic supersession regressions."""
from __future__ import annotations

import copy
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest

from aoi_orgware import (
    cli,
    delivery_lineage,
    empty_semantic_supersession,
    git_plumbing,
    harnesslib,
    semantic_events,
    semantic_store,
)
from aoi_orgware.harnesslib import HarnessError
from tests.harness_case import HarnessTestCase


START = "a" * 40
CURRENT = "b" * 40
EVENT = "c" * 64
WORKTREE = r"C:\bounded\worktree"


@pytest.mark.parametrize(
    ("branch", "accepted"),
    [
        ("main", True),
        ("feature/x", True),
        ("release-1.2", True),
        ("a/B.LOCK", True),
        ("a/b./c", True),
        ("HEAD", False),
        ("head", True),
        ("Head", True),
        ("FETCH_HEAD", True),
        ("ORIG_HEAD", True),
        ("MERGE_HEAD", True),
        ("REBASE_HEAD", True),
        ("CHERRY_PICK_HEAD", True),
        ("REVERT_HEAD", True),
        ("BISECT_HEAD", True),
        ("AUTO_MERGE", True),
        ("main..bad", False),
        ("a/.b", False),
        ("a/b.lock", False),
        ("a//b", False),
        ("a/b.", False),
        ("a/.", False),
        ("a/", False),
    ],
)
def test_empty_terminal_branch_grammar_matches_git(
    branch: str, accepted: bool
) -> None:
    git_result = subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        text=True,
        capture_output=True,
        check=False,
    )
    assert (git_result.returncode == 0) is accepted
    assert (
        empty_semantic_supersession._canonical_merge_branch(branch) is not None
    ) is accepted


def _empty_semantic_state() -> dict[str, object]:
    state: dict[str, object] = {
        "task_id": "empty-semantic-task",
        "status": "active",
        "phase": "planning",
        "outcome": "in_progress",
        "plan_ready": False,
        "plan_sha256": "",
        "checkpoint_required": True,
        "checkpoint_revision": 0,
        "checkpoint_sha256": "",
        "delivery": {"commit": "", "detail": "", "mode": "pending"},
        "integrity_contract": {
            "schema_version": 2,
            "mode": "required_v2",
            "adopted_at": "2026-08-14T00:00:00Z",
            "baseline_head": START,
            "records": [],
            "seal": None,
            "migration_receipt": None,
        },
        "worktree": WORKTREE,
        "branch": "feature",
        "head_sha": START,
        "_semantic": {
            "schema_version": 2,
            "sequence": 2,
            "head_event_sha256": EVENT,
        },
    }
    for field in empty_semantic_supersession.EMPTY_NATIVE_SEMANTIC_COLLECTION_FIELDS:
        state[field] = []
    return state


def _semantic_mocks(*, ancestor: bool = True, event_types: tuple[str, ...] = ("genesis", "integrity_adopt")):
    events = [
        {
            "event_type": event_type,
            "event_sha256": EVENT if index == len(event_types) - 1 else "d" * 64,
        }
        for index, event_type in enumerate(event_types)
    ]
    return (
        mock.patch.object(empty_semantic_supersession.semantic_store, "load_semantic_events", return_value=events),
        mock.patch.object(empty_semantic_supersession, "claims_owned_by_task", return_value=[]),
        mock.patch.object(empty_semantic_supersession, "state_worktree", return_value=Path(WORKTREE)),
        mock.patch.object(
            empty_semantic_supersession,
            "git_metadata",
            return_value={"worktree": WORKTREE, "branch": "main", "head_sha": CURRENT},
        ),
        mock.patch.object(empty_semantic_supersession, "git_is_ancestor", return_value=ancestor),
    )


def test_empty_native_semantic_supersession_is_exact_and_atomic() -> None:
    state = _empty_semantic_state()
    patches = _semantic_mocks()
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        assert cli._prepare_empty_native_semantic_supersession(
            SimpleNamespace(), state, intended_outcome="superseded"
        )
    assert state["branch"] == "main"
    assert state["delivery"] == {
        "commit": "",
        "detail": "Superseded before plan approval or material work; no delivery exists.",
        "mode": "none",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("changed_files", ["src/changed.py"]),
        ("claims", ["claim-1"]),
        ("packets", [{"packet_id": "packet-1"}]),
        ("jobs", [{"run_id": "run-1"}]),
        ("verification", [{"status": "pass"}]),
    ],
)
def test_empty_native_semantic_supersession_rejects_material_work(
    field: str, value: list[object]
) -> None:
    state = _empty_semantic_state()
    state[field] = value
    before = copy.deepcopy(state)
    patches = _semantic_mocks()
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        with pytest.raises(HarnessError, match=f"material {field}"):
            cli._prepare_empty_native_semantic_supersession(
                SimpleNamespace(), state, intended_outcome="superseded"
            )
    assert state == before


def test_empty_native_semantic_supersession_rejects_extra_event() -> None:
    state = _empty_semantic_state()
    before = copy.deepcopy(state)
    patches = _semantic_mocks(event_types=("genesis", "integrity_adopt", "packet_created"))
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        with pytest.raises(HarnessError, match="exactly genesis plus integrity_adopt"):
            cli._prepare_empty_native_semantic_supersession(
                SimpleNamespace(), state, intended_outcome="superseded"
            )
    assert state == before


def test_empty_native_semantic_supersession_rejects_rewind() -> None:
    state = _empty_semantic_state()
    before = copy.deepcopy(state)
    patches = _semantic_mocks(ancestor=False)
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        with pytest.raises(HarnessError, match="no longer contains task starting HEAD"):
            cli._prepare_empty_native_semantic_supersession(
                SimpleNamespace(), state, intended_outcome="superseded"
            )
    assert state == before


def test_non_superseded_close_does_not_use_empty_recovery() -> None:
    state = _empty_semantic_state()
    before = copy.deepcopy(state)
    assert not cli._prepare_empty_native_semantic_supersession(
        SimpleNamespace(), state, intended_outcome="partial"
    )
    assert state == before


def test_worktree_branch_transition_requires_explicit_opt_in() -> None:
    state = {
        "worktree": WORKTREE,
        "branch": "feature",
        "head_sha": START,
        "status": "done",
    }
    current = {"worktree": WORKTREE, "branch": "main", "head_sha": CURRENT}
    with mock.patch.object(git_plumbing, "state_worktree", return_value=Path(WORKTREE)), mock.patch.object(
        git_plumbing, "git_metadata", return_value=current
    ), mock.patch.object(delivery_lineage, "state_worktree", return_value=Path(WORKTREE)), mock.patch.object(
        delivery_lineage, "git_is_ancestor", return_value=True
    ):
        strict, _ = git_plumbing.worktree_integrity_errors(SimpleNamespace(), state)
        terminal, _, is_terminal = delivery_lineage.delivery_worktree_lineage_errors(
            SimpleNamespace(), state, START
        )
    assert strict == ["task branch changed from 'feature' to 'main'"]
    assert terminal == []
    assert is_terminal is True


def test_branch_opt_in_never_hides_path_or_identity_corruption() -> None:
    state = {"worktree": WORKTREE, "branch": "", "head_sha": "short"}
    current = {
        "worktree": r"C:\different\worktree",
        "branch": "main",
        "head_sha": CURRENT,
    }
    state["status"] = "done"
    with mock.patch.object(git_plumbing, "state_worktree", return_value=Path(WORKTREE)), mock.patch.object(
        git_plumbing, "git_metadata", return_value=current
    ), mock.patch.object(delivery_lineage, "state_worktree", return_value=Path(WORKTREE)), mock.patch.object(
        delivery_lineage, "git_is_ancestor", return_value=True
    ):
        errors, _, _ = delivery_lineage.delivery_worktree_lineage_errors(
            SimpleNamespace(), state, START
        )
    assert any("recorded worktree" in error for error in errors)
    assert "task branch is missing or invalid" in errors
    assert "task starting HEAD is missing or invalid" in errors


def test_terminal_branch_exception_fails_closed_if_strict_error_is_missing() -> None:
    state = {
        "worktree": WORKTREE,
        "branch": "feature",
        "head_sha": START,
        "status": "done",
    }
    current = {"worktree": WORKTREE, "branch": "main", "head_sha": CURRENT}
    with mock.patch.object(
        delivery_lineage, "worktree_integrity_errors", return_value=([], current)
    ), mock.patch.object(
        delivery_lineage, "state_worktree", return_value=Path(WORKTREE)
    ), mock.patch.object(delivery_lineage, "git_is_ancestor", return_value=True):
        errors, _, _ = delivery_lineage.delivery_worktree_lineage_errors(
            SimpleNamespace(), state, START
        )
    assert errors == ["terminal branch transition validation is inconsistent"]


class EmptyNativeSemanticCloseTests(HarnessTestCase):
    TASK = "empty-native-semantic"

    def test_exact_semantic_close_supersedes_after_branch_transition(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), "switch", "-c", "feature"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.cli(
            "init-task",
            "--task-id",
            self.TASK,
            "--title",
            "Empty semantic task",
            "--objective",
            "Prove exact empty semantic supersession",
            "--owner",
            "test-root",
            "--completion-boundary",
            "Task is superseded without material work",
            "--semantic-v2",
            "--semantic-command-id",
            "init-empty-native-semantic-v1",
        )
        genesis = json.loads(
            self.cli("semantic-head", "--task", self.TASK, "--json").stdout
        )
        start_head = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        adopted = json.loads(
            self.cli(
                "integrity-adopt",
                "--task",
                self.TASK,
                "--baseline-head",
                start_head,
                "--command-id",
                "integrity-adopt-empty-native-semantic-v1",
                "--recorded-at",
                "2026-08-14T00:00:00+00:00",
                "--expected-head-sha256",
                genesis["event_sha256"],
                "--json",
            ).stdout
        )
        subprocess.run(
            ["git", "-C", str(self.root), "switch", "main"],
            check=True,
            text=True,
            capture_output=True,
        )
        close_args = (
            "close-task",
            "--task",
            self.TASK,
            "--summary",
            "Empty semantic task is superseded by a governed successor",
            "--outcome",
            "superseded",
            "--boundary-disposition",
            "The original boundary moved to an explicit successor task",
            "--semantic-command-id",
            "close-empty-native-semantic-v1",
            "--semantic-expected-head-sha256",
            adopted["event_sha256"],
            "--json",
        )
        closed = json.loads(self.cli(*close_args).stdout)
        assert closed["status"] == "done"
        assert closed["idempotent_replay"] is False
        state = harnesslib.load_task(harnesslib.get_paths(self.root), self.TASK)
        assert state["branch"] == "main"
        assert state["outcome"] == "superseded"
        assert state["delivery"]["mode"] == "none"
        assert state["delivery"]["commit"] == ""
        assert state["integrity_contract"]["records"] == []
        assert state["integrity_contract"]["seal"] is None
        assert len(semantic_store.load_semantic_events(harnesslib.get_paths(self.root), self.TASK)) == 3

        events = semantic_store.load_semantic_events(
            harnesslib.get_paths(self.root), self.TASK
        )

        def assert_terminal_chain_requires_seal(
            *,
            before_mutation: Callable[[dict[str, Any]], None] | None = None,
            after_mutation: Callable[[dict[str, Any]], None] | None = None,
        ) -> None:
            genesis_domain = semantic_events.projection_domain(
                semantic_events.replay_events(events[:1])
            )
            before = semantic_events.projection_domain(
                semantic_events.replay_events(events[:2])
            )
            after = semantic_events.projection_domain(
                semantic_events.replay_events(events)
            )
            if before_mutation is not None:
                before_mutation(before)
            if after_mutation is not None:
                after_mutation(after)
            adopted_event = semantic_events.create_transition_event(
                events[0],
                genesis_domain,
                before,
                event_type="integrity_adopt",
                command_id=str(events[1]["command_id"]),
                recorded_at=str(events[1]["recorded_at"]),
                authority_ref=str(events[1]["authority_ref"]),
            )
            closed_event = semantic_events.create_transition_event(
                adopted_event,
                before,
                after,
                event_type="task_closed",
                command_id=str(events[2]["command_id"]),
                recorded_at=str(events[2]["recorded_at"]),
                authority_ref=str(events[2]["authority_ref"]),
            )
            forged_events = [events[0], adopted_event, closed_event]
            invalid = semantic_events.replay_events(forged_events)
            with mock.patch.object(
                empty_semantic_supersession.semantic_store,
                "load_semantic_events",
                return_value=forged_events,
            ):
                assert not empty_semantic_supersession.is_empty_native_semantic_terminal_supersession(
                    harnesslib.get_paths(self.root),
                    invalid,
                    invalid["integrity_contract"],
                )
                with self.assertRaisesRegex(
                    HarnessError, "complete integrity contract requires a seal"
                ):
                    harnesslib.validate_task_state(
                        invalid,
                        paths=harnesslib.get_paths(self.root),
                    )

        for field, value in (
            ("branch", None),
            ("branch", ""),
            ("branch", "detached"),
            ("branch", " main"),
            ("branch", "main "),
            ("branch", "main~invalid"),
            ("branch", "main\x00control"),
            ("branch", "HEAD"),
            ("branch", "main..bad"),
            ("branch", "a/.b"),
            ("branch", "a/b.lock"),
            ("branch", "a//b"),
            ("branch", "a/b."),
            ("branch", "a/."),
            ("branch", "a/"),
        ):
            for side in ("before", "after"):
                mutation = lambda target, field=field, value=value: target.update(
                    {field: value}
                )
                assert_terminal_chain_requires_seal(
                    before_mutation=mutation if side == "before" else None,
                    after_mutation=mutation if side == "after" else None,
                )

        with mock.patch.object(
            empty_semantic_supersession,
            "normalize_lock",
            side_effect=lambda lock: lock.casefold(),
        ):
            assert_terminal_chain_requires_seal(
                before_mutation=lambda value: value.update(branch="Feature"),
                after_mutation=lambda value: value.update(branch="feature"),
            )

        for side, field, value in (
            ("before", "updated_at", None),
            ("before", "updated_at", True),
            ("before", "updated_at", "2026-08-14T00:00:00"),
            ("before", "updated_at", "not-a-time"),
            ("before", "updated_at", " 2026-08-14T00:00:00+00:00"),
            ("before", "updated_at", "2099-08-14T00:00:00+00:00"),
            ("after", "updated_at", None),
            ("after", "updated_at", True),
            ("after", "updated_at", "2026-08-14T00:00:00"),
            ("after", "updated_at", "not-a-time"),
            ("after", "updated_at", "2026-08-14T00:00:00+00:00 "),
            ("after", "updated_at", "2099-08-14T00:00:00+00:00"),
            ("after", "closed_at", None),
            ("after", "closed_at", True),
            ("after", "closed_at", "2026-08-14T00:00:00"),
            ("after", "closed_at", "not-a-time"),
            ("after", "closed_at", " 2026-08-14T00:00:00+00:00"),
        ):
            mutation = lambda target, field=field, value=value: target.update(
                {field: value}
            )
            assert_terminal_chain_requires_seal(
                before_mutation=mutation if side == "before" else None,
                after_mutation=mutation if side == "after" else None,
            )

        for mutation in (
            lambda value: value["facts"].append("unexpected second fact"),
            lambda value: value["delivery"].update(detail="different detail"),
            lambda value: value["_semantic"].update(sequence=4),
            lambda value: value.update(title="forged title"),
            lambda value: value.update(owner="forged owner"),
            lambda value: value.update(created_at="2026-08-14T00:00:01+00:00"),
            lambda value: value.pop("closed_head_sha"),
        ):
            invalid = copy.deepcopy(state)
            mutation(invalid)
            with self.assertRaisesRegex(
                HarnessError, "complete integrity contract requires a seal"
            ):
                harnesslib.validate_task_state(
                    invalid,
                    paths=harnesslib.get_paths(self.root),
                )

        replayed = json.loads(self.cli(*close_args).stdout)
        assert replayed["idempotent_replay"] is True
        assert replayed["semantic_head_sha256"] == closed["semantic_head_sha256"]
