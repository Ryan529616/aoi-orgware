#!/usr/bin/env python3
"""Close honesty, scope retargeting, plan-approval history, and typed risks.

These behaviors close the structural-honesty gaps found by the 2026-07 ARISE
evidence audit: outcome was hardcoded "achieved", registered scope was
immutable after creation, plan approval was a history-free scalar, risks were
unretirable prose, and cancelled tasks could disown recorded mutations.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402


class CloseOutcomeTests(HarnessTestCase):
    def _prepare_closable(self, task_id: str, **verification_kwargs) -> None:
        self.init_task(task_id)
        self.add_passing_verification(task_id, **verification_kwargs)
        self.cli(
            "set-delivery",
            "--task",
            task_id,
            "--mode",
            "none",
            "--detail",
            "test task has no tracked delivery",
        )
        self.cli(
            "checkpoint",
            "--task",
            task_id,
            "--next-action",
            "Close the task",
        )

    def _state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def test_achieved_close_requires_boundary_asserting_verification(self) -> None:
        self._prepare_closable("honesty-a", asserts_completion_boundary=False)
        failed = self.cli(
            "close-task",
            "--task",
            "honesty-a",
            "--outcome",
            "achieved",
            "--summary",
            "done",
            ok=False,
        )
        self.assertIn("asserts-completion-boundary", failed.stderr)
        self.add_passing_verification("honesty-a")
        self.cli(
            "checkpoint",
            "--task",
            "honesty-a",
            "--next-action",
            "Close the task",
        )
        self.cli(
            "close-task",
            "--task",
            "honesty-a",
            "--outcome",
            "achieved",
            "--summary",
            "done",
        )
        state = self._state("honesty-a")
        self.assertEqual(state["outcome"], "achieved")

    def test_non_achieved_close_requires_boundary_disposition(self) -> None:
        self._prepare_closable("honesty-b", asserts_completion_boundary=False)
        failed = self.cli(
            "close-task",
            "--task",
            "honesty-b",
            "--outcome",
            "scope_changed",
            "--summary",
            "scope moved to follow-up task",
            ok=False,
        )
        self.assertIn("--boundary-disposition", failed.stderr)
        self.cli(
            "close-task",
            "--task",
            "honesty-b",
            "--outcome",
            "scope_changed",
            "--boundary-disposition",
            "Boundary re-anchored; remaining scope lives in honesty-b-v2",
            "--summary",
            "scope moved to follow-up task",
        )
        state = self._state("honesty-b")
        self.assertEqual(state["outcome"], "scope_changed")
        self.assertIn("honesty-b-v2", state["boundary_disposition"])

    def test_superseded_close_allowed_without_boundary_asserting_verification(
        self,
    ) -> None:
        # A superseded task must be closable honestly even though no
        # verification covers its registered boundary.
        self._prepare_closable("honesty-c", asserts_completion_boundary=False)
        self.cli(
            "close-task",
            "--task",
            "honesty-c",
            "--outcome",
            "superseded",
            "--boundary-disposition",
            "Superseded by the consolidated v2 task before any boundary run",
            "--summary",
            "superseded",
        )
        self.assertEqual(self._state("honesty-c")["outcome"], "superseded")

    def test_achieved_close_with_blockers_requires_disposition(self) -> None:
        self._prepare_closable("honesty-d")
        self.cli(
            "checkpoint",
            "--task",
            "honesty-d",
            "--blocker",
            "vendor licence renewal pending",
            "--next-action",
            "Close the task",
        )
        failed = self.cli(
            "close-task",
            "--task",
            "honesty-d",
            "--outcome",
            "achieved",
            "--summary",
            "done",
            ok=False,
        )
        self.assertIn("--blockers-disposition", failed.stderr)
        self.cli(
            "close-task",
            "--task",
            "honesty-d",
            "--outcome",
            "achieved",
            "--blockers-disposition",
            "Licence renewal tracked outside this task; no impact on boundary",
            "--summary",
            "done",
        )
        state = self._state("honesty-d")
        self.assertEqual(state["outcome"], "achieved")
        self.assertIn("Licence renewal", state["blockers_disposition"])


class RetargetTests(HarnessTestCase):
    def _state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def test_retarget_records_revision_and_forces_replan(self) -> None:
        self.init_task("retarget-a")
        self.cli(
            "retarget-task",
            "--task",
            "retarget-a",
            "--completion-boundary",
            "One exact layer retires within budget on the streamed config",
            "--reason",
            "Measured decomposition shows the original boundary is unreachable",
        )
        state = self._state("retarget-a")
        self.assertFalse(state["plan_ready"])
        self.assertEqual(len(state["scope_revisions"]), 1)
        revision = state["scope_revisions"][0]
        self.assertEqual(
            revision["old"]["completion_boundary"],
            "All requested test evidence is accounted",
        )
        self.assertIn("unreachable", revision["reason"])
        self.assertEqual(
            state["completion_boundary"],
            "One exact layer retires within budget on the streamed config",
        )
        # The stale plan no longer gates work: re-approval is required.
        failed = self.cli(
            "close-task",
            "--task",
            "retarget-a",
            "--outcome",
            "achieved",
            "--summary",
            "done",
            ok=False,
        )
        self.assertIn("plan", failed.stderr.lower())
        self.cli(
            "approve-plan",
            "--task",
            "retarget-a",
            "--note",
            "Plan re-approved against the retargeted completion boundary",
        )
        self.assertTrue(self._state("retarget-a")["plan_ready"])

    def test_retarget_rejects_noop(self) -> None:
        self.init_task("retarget-b")
        self.cli(
            "retarget-task",
            "--task",
            "retarget-b",
            "--title",
            "Task retarget-b",
            "--reason",
            "no actual change requested",
            ok=False,
        )

    def test_retarget_requires_some_field(self) -> None:
        self.init_task("retarget-c")
        self.cli(
            "retarget-task",
            "--task",
            "retarget-c",
            "--reason",
            "nothing to change",
            ok=False,
        )


class PlanApprovalHistoryTests(HarnessTestCase):
    def _state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def test_plan_approvals_accumulate(self) -> None:
        self.init_task("plans-a")
        state = self._state("plans-a")
        self.assertEqual(len(state["plan_approvals"]), 1)
        self.assertEqual(
            state["plan_approvals"][0]["plan_sha256"], state["plan_sha256"]
        )
        plan_path = self.root / ".aoi" / "tasks" / "plans-a" / "plan.md"
        plan_path.write_text(
            plan_path.read_text(encoding="utf-8") + "\nRevised evidence appendix.\n",
            encoding="utf-8",
        )
        self.cli(
            "approve-plan",
            "--task",
            "plans-a",
            "--note",
            "Plan revised with the evidence appendix before any dispatch",
        )
        state = self._state("plans-a")
        self.assertEqual(len(state["plan_approvals"]), 2)
        self.assertNotEqual(
            state["plan_approvals"][0]["plan_sha256"],
            state["plan_approvals"][1]["plan_sha256"],
        )

    def test_replacing_plan_after_dispatched_work_requires_coverage_note(self) -> None:
        self.init_task("plans-b")
        receipt, receipt_sha = self.write_source_receipt("plans-b-receipt.json")
        self.cli(
            "claim",
            "--task",
            "plans-b",
            "--token",
            "plans-b-run",
            "--owner",
            "root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/aoi-example-run",
            "--intent",
            "bounded smoke run",
            "--validation",
            "job gate",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
        )
        self.cli(
            "job-start",
            "--task",
            "plans-b",
            "--run-id",
            "job-1",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/aoi-example-run",
            "--log",
            "/tmp/aoi-example-run/driver.log",
            "--stop-condition",
            "PASS or first fatal",
            "--source-sha",
            receipt_sha,
            "--source-manifest",
            str(receipt),
            "--tool-path",
            "/tools/vcs",
            "--tool-version",
            "VCS-test",
            "--command",
            "timeout 1m run.sh",
        )
        plan_path = self.root / ".aoi" / "tasks" / "plans-b" / "plan.md"
        plan_path.write_text(
            plan_path.read_text(encoding="utf-8") + "\nAudit-scope replacement.\n",
            encoding="utf-8",
        )
        failed = self.cli(
            "approve-plan",
            "--task",
            "plans-b",
            "--note",
            "Replacing the plan after the job ran",
            ok=False,
        )
        self.assertIn("--coverage-note", failed.stderr)
        self.cli(
            "approve-plan",
            "--task",
            "plans-b",
            "--note",
            "Replacing the plan after the job ran",
            "--coverage-note",
            "job-1 ran under the initial approved plan; audit scope starts here",
        )
        state = self._state("plans-b")
        self.assertEqual(len(state["plan_approvals"]), 2)
        self.assertIn("job-1", state["plan_approvals"][1]["coverage_note"])


class TypedRiskTests(HarnessTestCase):
    def _state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def test_risks_are_typed_deduplicated_and_retirable(self) -> None:
        self.init_task("risks-a")
        self.cli(
            "checkpoint",
            "--task",
            "risks-a",
            "--risk",
            "hooks are not yet trusted",
            "--risk",
            "hooks are not yet trusted",
            "--next-action",
            "Deploy the hook adapter",
        )
        state = self._state("risks-a")
        self.assertEqual(len(state["risks"]), 1)
        risk = state["risks"][0]
        self.assertEqual(risk["id"], "r1")
        self.assertEqual(risk["status"], "open")
        self.cli(
            "retire-risk",
            "--task",
            "risks-a",
            "--id",
            "r1",
            "--reason",
            "hook adapter deployed and validated",
            "--superseded-by",
            "fact: hook adapter deployed",
        )
        state = self._state("risks-a")
        self.assertEqual(state["risks"][0]["status"], "retired")
        self.cli(
            "checkpoint",
            "--task",
            "risks-a",
            "--next-action",
            "Continue after risk retirement",
        )
        checkpoint = (
            self.root / ".aoi" / "tasks" / "risks-a" / "checkpoint.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("RISK[r1]", checkpoint)

    def test_retired_risks_leave_open_ones_rendered(self) -> None:
        self.init_task("risks-b")
        self.cli(
            "checkpoint",
            "--task",
            "risks-b",
            "--risk",
            "first risk stays open",
            "--risk",
            "second risk gets retired",
            "--next-action",
            "Retire the second risk",
        )
        self.cli(
            "retire-risk",
            "--task",
            "risks-b",
            "--id",
            "r2",
            "--reason",
            "second risk resolved by design change",
        )
        self.cli(
            "checkpoint",
            "--task",
            "risks-b",
            "--next-action",
            "Continue",
        )
        checkpoint = (
            self.root / ".aoi" / "tasks" / "risks-b" / "checkpoint.md"
        ).read_text(encoding="utf-8")
        self.assertIn("RISK[r1]: first risk stays open", checkpoint)
        self.assertNotIn("second risk gets retired", checkpoint)
        self.assertIn("RISKS ACCOUNTED: retired=1 (r2)", checkpoint)

    def test_legacy_string_risk_retires_by_exact_text(self) -> None:
        self.init_task("risks-c")
        state_path = self.root / ".aoi" / "tasks" / "risks-c" / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["risks"] = ["legacy prose risk from 0.2.1"]
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self.cli(
            "retire-risk",
            "--task",
            "risks-c",
            "--text-exact",
            "legacy prose risk from 0.2.1",
            "--reason",
            "superseded during audit",
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["risks"][0]["status"], "retired")
        self.assertEqual(state["risks"][0]["text"], "legacy prose risk from 0.2.1")

    def test_retire_materialized(self) -> None:
        self.init_task("risks-d")
        self.cli(
            "checkpoint",
            "--task",
            "risks-d",
            "--risk",
            "flaky fixture may hide a regression",
            "--next-action",
            "Watch the fixture",
        )
        self.cli(
            "retire-risk",
            "--task",
            "risks-d",
            "--id",
            "r1",
            "--materialized",
            "--reason",
            "the regression happened in run 7",
        )
        state = self._state("risks-d")
        self.assertEqual(state["risks"][0]["status"], "materialized")


class CancelDispositionTests(HarnessTestCase):
    def test_cancel_with_changed_files_requires_disposition(self) -> None:
        self.init_task("cancel-a")
        self.cli(
            "set-delivery",
            "--task",
            "cancel-a",
            "--mode",
            "none",
            "--detail",
            "cancelled test task has no tracked delivery",
        )
        self.cli(
            "checkpoint",
            "--task",
            "cancel-a",
            "--changed-file",
            "notes/draft.md",
            "--next-action",
            "Decide task fate",
        )
        failed = self.cli(
            "cancel-task",
            "--task",
            "cancel-a",
            "--reason",
            "superseded by another effort",
            ok=False,
        )
        self.assertIn("--changed-files-disposition", failed.stderr)
        self.cli(
            "cancel-task",
            "--task",
            "cancel-a",
            "--reason",
            "superseded by another effort",
            "--changed-files-disposition",
            "notes/draft.md stays committed; ownership moves to the v2 task",
        )
        state_path = self.root / ".aoi" / "tasks" / "cancel-a" / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "cancelled")
        self.assertIn("v2 task", state["changed_files_disposition"])


class ChangedFileWorktreeTests(HarnessTestCase):
    def test_absolute_changed_file_outside_worktree_is_rejected(self) -> None:
        self.init_task("wt-a")
        outside = self.root.parent / "elsewhere" / "other-repo" / "file.py"
        failed = self.cli(
            "checkpoint",
            "--task",
            "wt-a",
            "--changed-file",
            str(outside),
            "--next-action",
            "Record the cross-repo edit",
            ok=False,
        )
        self.assertIn("outside the task worktree", failed.stderr)
        self.cli(
            "checkpoint",
            "--task",
            "wt-a",
            "--changed-file",
            str(outside),
            "--allow-outside-worktree",
            "--next-action",
            "Record the cross-repo edit",
        )

    def test_relative_changed_file_is_allowed(self) -> None:
        self.init_task("wt-b")
        self.cli(
            "checkpoint",
            "--task",
            "wt-b",
            "--changed-file",
            "src/module.py",
            "--next-action",
            "Continue",
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
