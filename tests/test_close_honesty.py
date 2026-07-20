#!/usr/bin/env python3
"""Close honesty, scope retargeting, plan-approval history, and typed risks.

These behaviors close the structural-honesty gaps found by the 2026-07 ARISE
evidence audit: outcome was hardcoded "achieved", registered scope was
immutable after creation, plan approval was a history-free scalar, risks were
unretirable prose, and cancelled tasks could disown recorded mutations.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import sys
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware.commands import task_lifecycle as lifecycle_cmds  # noqa: E402


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

    def _update_plan_to_current_scope(self, task_id: str) -> None:
        state = self._state(task_id)
        destination = self.root / ".aoi" / "tasks" / task_id / "plan.md"
        candidate = destination.read_text(encoding="utf-8")
        for label, key in (
            ("Title", "title"),
            ("Objective", "objective"),
            ("Completion boundary", "completion_boundary"),
        ):
            candidate = re.sub(
                rf"(?m)^- {re.escape(label)}:.*$",
                f"- {label}: {state[key]}",
                candidate,
            )
        source = Path(self.backup_temp.name) / f"{task_id}-revised-plan.md"
        source.write_text(candidate, encoding="utf-8")
        self.cli(
            "plan-update",
            "--task",
            task_id,
            "--source",
            str(source),
            "--expected-source-sha256",
            hashlib.sha256(source.read_bytes()).hexdigest(),
            "--expected-current-plan-sha256",
            hashlib.sha256(destination.read_bytes()).hexdigest(),
            "--reason",
            "Replace the stale plan with the retargeted registered scope",
        )

    def test_plan_update_file_and_scope_falsification_boundaries(self) -> None:
        self.init_task("retarget-plan-boundaries")
        paths = h.get_paths(self.root)
        destination = self.root / ".aoi" / "tasks" / "retarget-plan-boundaries" / "plan.md"
        outside = Path(self.backup_temp.name)
        inside = self.root / ".aoi" / "candidate.md"
        inside.write_text("inside state", encoding="utf-8")
        with self.assertRaisesRegex(h.HarnessError, "inside AOI state"):
            lifecycle_cmds._read_plan_update_source(paths, str(inside))
        oversized = outside / "oversized-plan.md"
        oversized.write_bytes(b"x" * (lifecycle_cmds.PLAN_UPDATE_MAX_BYTES + 1))
        with self.assertRaisesRegex(h.HarnessError, "exceeds"):
            lifecycle_cmds._read_plan_update_source(paths, str(oversized))
        invalid = outside / "invalid-utf8.md"
        invalid.write_bytes(b"\xff")
        with self.assertRaisesRegex(h.HarnessError, "valid UTF-8"):
            lifecycle_cmds._read_plan_update_source(paths, str(invalid))
        with self.assertRaisesRegex(h.HarnessError, "regular"):
            lifecycle_cmds._read_plan_update_source(paths, str(outside))
        linked = outside / "linked-plan.md"
        try:
            os.symlink(destination, linked)
        except OSError:
            linked = None
        if linked is not None:
            with self.assertRaisesRegex(h.HarnessError, "symlink|junction"):
                lifecycle_cmds._read_plan_update_source(paths, str(linked))
        hardlink = outside / "hardlinked-plan.md"
        os.link(destination, hardlink)
        with self.assertRaisesRegex(h.HarnessError, "regular"):
            lifecycle_cmds._read_plan_update_source(paths, str(hardlink))
        with self.assertRaisesRegex(h.HarnessError, "regular"):
            lifecycle_cmds._plan_snapshot(outside, "nonregular destination")

        state = self._state("retarget-plan-boundaries")
        plan = destination.read_text(encoding="utf-8")
        with self.assertRaisesRegex(h.HarnessError, "exactly one"):
            lifecycle_cmds._plan_scope_fields(plan.replace("- Title:", "- Missing:"))
        with self.assertRaisesRegex(h.HarnessError, "exactly one"):
            lifecycle_cmds._plan_scope_fields(plan + f"\n- Title: {state['title']}\n")
        with self.assertRaisesRegex(h.HarnessError, "single-line"):
            lifecycle_cmds._plan_scope_fields(
                plan.replace(f"- Objective: {state['objective']}", "- Objective: one\n  two")
            )
        with self.assertRaisesRegex(h.HarnessError, "does not match current task state"):
            lifecycle_cmds._require_plan_scope_matches_state(
                plan.replace(state["objective"], "different objective"), state
            )

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
        stale = self.cli(
            "approve-plan",
            "--task",
            "retarget-a",
            "--note",
            "Plan re-approved against the retargeted completion boundary",
            ok=False,
        )
        self.assertIn("does not match current task state", stale.stderr)
        self._update_plan_to_current_scope("retarget-a")
        self.cli(
            "approve-plan",
            "--task",
            "retarget-a",
            "--note",
            "Plan re-approved against the retargeted completion boundary",
        )
        self.assertTrue(self._state("retarget-a")["plan_ready"])

    def test_retarget_invalidates_stale_boundary_assertions(self) -> None:
        # Review finding: an assertion recorded against boundary B1 must not
        # satisfy an achieved close after the task retargets to boundary B2.
        self.init_task("retarget-d")
        self.add_passing_verification("retarget-d")
        self.cli(
            "set-delivery",
            "--task",
            "retarget-d",
            "--mode",
            "none",
            "--detail",
            "test task has no tracked delivery",
        )
        self.cli(
            "retarget-task",
            "--task",
            "retarget-d",
            "--completion-boundary",
            "A structurally different boundary the old assertion never covered",
            "--reason",
            "boundary re-anchored after measurement",
        )
        self._update_plan_to_current_scope("retarget-d")
        self.cli(
            "approve-plan",
            "--task",
            "retarget-d",
            "--note",
            "Plan re-approved against the retargeted completion boundary",
        )
        self.cli(
            "checkpoint",
            "--task",
            "retarget-d",
            "--next-action",
            "Close the task",
        )
        failed = self.cli(
            "close-task",
            "--task",
            "retarget-d",
            "--outcome",
            "achieved",
            "--summary",
            "done",
            ok=False,
        )
        self.assertIn("CURRENT registered completion boundary", failed.stderr)
        self.add_passing_verification(
            "retarget-d",
            evidence="fresh run covering the retargeted boundary",
        )
        self.cli(
            "checkpoint",
            "--task",
            "retarget-d",
            "--next-action",
            "Close the task",
        )
        self.cli(
            "close-task",
            "--task",
            "retarget-d",
            "--outcome",
            "achieved",
            "--summary",
            "done",
        )
        self.assertEqual(self._state("retarget-d")["outcome"], "achieved")

    def test_plan_update_binds_source_current_digest_and_reapproval(self) -> None:
        self.init_task("retarget-plan-update")
        destination = self.root / ".aoi" / "tasks" / "retarget-plan-update" / "plan.md"
        before = destination.read_bytes()
        source = Path(self.backup_temp.name) / "candidate-plan.md"
        source.write_bytes(before + b"\n<!-- bounded plan revision -->\n")
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        current_digest = hashlib.sha256(before).hexdigest()
        rejected = self.cli(
            "plan-update",
            "--task",
            "retarget-plan-update",
            "--source",
            str(source),
            "--expected-source-sha256",
            "0" * 64,
            "--expected-current-plan-sha256",
            current_digest,
            "--reason",
            "Wrong source digest must not publish bytes",
            ok=False,
        )
        self.assertIn("source SHA-256", rejected.stderr)
        self.assertEqual(destination.read_bytes(), before)
        rejected = self.cli(
            "plan-update",
            "--task",
            "retarget-plan-update",
            "--source",
            str(source),
            "--expected-source-sha256",
            source_digest,
            "--expected-current-plan-sha256",
            "f" * 64,
            "--reason",
            "Wrong current digest must not publish bytes",
            ok=False,
        )
        self.assertIn("current plan SHA-256", rejected.stderr)
        self.assertEqual(destination.read_bytes(), before)
        self.cli(
            "plan-update",
            "--task",
            "retarget-plan-update",
            "--source",
            str(source),
            "--expected-source-sha256",
            source_digest,
            "--expected-current-plan-sha256",
            current_digest,
            "--reason",
            "Record the exact bounded plan revision before re-approval",
        )
        state = self._state("retarget-plan-update")
        self.assertFalse(state["plan_ready"])
        self.assertEqual(state["plan_revisions"][-1]["before_plan_sha256"], current_digest)
        self.assertEqual(state["plan_revisions"][-1]["after_plan_sha256"], source_digest)
        self.assertEqual(state["checkpoint_revision"], state["revision"])
        self.cli(
            "approve-plan",
            "--task",
            "retarget-plan-update",
            "--note",
            "Re-approved after the digest-bound plan revision",
        )

    def test_plan_update_exact_retry_recovers_each_post_prepare_crash_boundary(self) -> None:
        self.init_task("retarget-plan-retry")
        destination = self.root / ".aoi" / "tasks" / "retarget-plan-retry" / "plan.md"
        source = Path(self.backup_temp.name) / "retry-plan.md"
        source.write_bytes(destination.read_bytes() + b"\n<!-- retry-safe -->\n")
        args = argparse.Namespace(
            task="retarget-plan-retry", source=str(source),
            expected_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            expected_current_plan_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            reason="prove exact retry finalizes a durable pending revision", json=False,
        )
        paths = h.get_paths(self.root)
        services = cli_impl._task_lifecycle_cmd_services()
        with mock.patch.object(lifecycle_cmds, "atomic_write_bytes", side_effect=OSError("injected pre-publish crash")):
            with self.assertRaisesRegex(OSError, "pre-publish"):
                lifecycle_cmds.cmd_plan_update(args, paths, services=services)
        pending = h.load_task(paths, "retarget-plan-retry")
        self.assertFalse(pending["plan_ready"])
        self.assertIn("plan_update_pending", pending)
        lifecycle_cmds.cmd_plan_update(args, paths, services=services)
        self.assertNotIn("plan_update_pending", h.load_task(paths, "retarget-plan-retry"))

        self.init_task("retarget-plan-retry-after-publish")
        destination = self.root / ".aoi" / "tasks" / "retarget-plan-retry-after-publish" / "plan.md"
        source = Path(self.backup_temp.name) / "retry-after-publish-plan.md"
        source.write_bytes(destination.read_bytes() + b"\n<!-- retry-after-publish -->\n")
        after_args = argparse.Namespace(
            task="retarget-plan-retry-after-publish", source=str(source),
            expected_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            expected_current_plan_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            reason="prove exact retry finalizes after the plan side effect", json=False,
        )
        failing_services = dataclasses.replace(
            services, commit_checkpoint=mock.Mock(side_effect=OSError("injected post-publish crash"))
        )
        with self.assertRaisesRegex(OSError, "post-publish"):
            lifecycle_cmds.cmd_plan_update(after_args, paths, services=failing_services)
        pending = h.load_task(paths, "retarget-plan-retry-after-publish")
        self.assertIn("plan_update_pending", pending)
        self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), after_args.expected_source_sha256)
        lifecycle_cmds.cmd_plan_update(after_args, paths, services=services)
        self.assertNotIn("plan_update_pending", h.load_task(paths, "retarget-plan-retry-after-publish"))

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

    def test_retired_risk_text_can_be_reraised(self) -> None:
        self.init_task("risks-e")
        self.cli(
            "checkpoint",
            "--task",
            "risks-e",
            "--risk",
            "loader starves under back-pressure",
            "--next-action",
            "Investigate",
        )
        self.cli(
            "retire-risk",
            "--task",
            "risks-e",
            "--id",
            "r1",
            "--reason",
            "fixed by refill rework",
        )
        self.cli(
            "checkpoint",
            "--task",
            "risks-e",
            "--risk",
            "loader starves under back-pressure",
            "--next-action",
            "It came back",
        )
        state = self._state("risks-e")
        self.assertEqual(len(state["risks"]), 2)
        self.assertEqual(state["risks"][0]["status"], "retired")
        self.assertEqual(state["risks"][1]["status"], "open")
        self.assertEqual(state["risks"][1]["id"], "r2")

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
