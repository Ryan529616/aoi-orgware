"""AOI-SYNTHETIC-FIXTURE-V1 external-job lifecycle regressions."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.harness_case import CLI_MODULE, HarnessTestCase


class JobLifecycleIntegrityTests(HarnessTestCase):
    def test_external_job_can_be_owned_by_one_dispatched_packet_chain(self) -> None:
        task_id = "owned-job-chain"
        self.init_task(task_id, session_id="chief-owned-job")
        commit = self.git_commit(task_id)
        self.create_lane(
            task_id,
            "rtl",
            kind="implementation",
            role="implementation_specialist",
            authority_commit=commit,
        )
        self.cli(
            "execution-select",
            "--task",
            task_id,
            "--selection-id",
            "owned-job-single",
            "--work-unit-id",
            "owned-job-work",
            "--mode",
            "single",
            "--lane",
            "rtl",
            "--scope",
            "One specialist packet owns one external command lifecycle",
            "--sequential-dependency",
            "high",
            "--tool-density",
            "high",
            "--shared-context",
            "high",
            "--rationale",
            "The job is nested in the already-authorized packet chain",
            "--falsification-condition",
            "Reject if packet and job authorities diverge",
            "--escalation-condition",
            "Stop the job before completing its owner packet",
            "--session-id",
            "chief-owned-job",
        )
        self.cli(
            "claim",
            "--task",
            task_id,
            "--token",
            "owned-job-claim",
            "--owner",
            "test-root",
            "--kind",
            "EDA-RUN",
            "--lock",
            "external:tree:/tmp/owned-job-chain",
            "--lock",
            "repo:file:job-owner-job-command.sh",
            "--intent",
            "Exercise nested job authority without launching a real tool",
            "--validation",
            "Owner packet cannot finish while its job remains active",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
        )
        self.create_exact_job_owner(
            task_id,
            "job-owner",
            command="timeout 1m run.sh",
            work_root="/tmp/owned-job-chain",
            agent_role="implementation_specialist",
            model_tier="expert",
            lane_id="rtl",
            execution_selection_id="owned-job-single",
        )
        receipt, receipt_sha = self.write_source_receipt("owned-job-source.json")
        self.cli(
            "job-start",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--host",
            "eda",
            "--tool",
            "VCS",
            "--work-root",
            "/tmp/owned-job-chain",
            "--log",
            "/tmp/owned-job-chain/driver.log",
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
            "--lane-id",
            "rtl",
            "--execution-selection-id",
            "owned-job-single",
            "--owner-packet-id",
            "job-owner",
        )
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        owner_packet = next(
            packet for packet in state["packets"] if packet["packet_id"] == "job-owner"
        )
        owner_contract = Path(owner_packet["path"])
        owner_contract_bytes = owner_contract.read_bytes()
        owner_contract.write_bytes(owner_contract_bytes + b"\nphysical drift\n")
        drifted_launch = self.cli(
            "job-update",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--status",
            "running",
            "--pid",
            "424242",
            "--evidence",
            "Owner contract drift must be rejected at the launch boundary",
            ok=False,
        )
        self.assertIn("owner packet authority is missing or tampered", drifted_launch.stderr)
        owner_contract.write_bytes(owner_contract_bytes)

        valid_state_bytes = state_path.read_bytes()
        lock_drift = json.loads(valid_state_bytes)
        next(
            packet
            for packet in lock_drift["packets"]
            if packet["packet_id"] == "job-owner"
        )["locks"] = []
        state_path.write_text(
            json.dumps(lock_drift, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        lock_doctor = subprocess.run(
            [sys.executable, "-m", CLI_MODULE, "doctor", "--task", task_id, "--json"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(lock_doctor.returncode, 1, lock_doctor.stderr)
        self.assertIn("output paths exceed the owner packet locks", lock_doctor.stdout)
        state_path.write_bytes(valid_state_bytes)

        self.cli(
            "job-update",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--status",
            "running",
            "--pid",
            "424242",
            "--evidence",
            "Physical owner authority and canonical output locks were revalidated",
        )
        blocked = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "job-owner",
            "--status",
            "done",
            "--summary",
            "Owner attempted to finish before its job",
            "--evidence",
            "The active owned job must block this transition",
            ok=False,
        )
        self.assertIn("child work is active", blocked.stderr)
        self.cli(
            "job-update",
            "--task",
            task_id,
            "--run-id",
            "owned-run",
            "--status",
            "stopped",
            "--evidence",
            "The bounded external job was stopped before owner completion",
            "--exit-code",
            "143",
        )
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "job-owner",
            "--status",
            "done",
            "--summary",
            "Owner completed after its nested job became terminal",
            "--evidence",
            "The job lifecycle and owner packet share one exact chain",
        )
        doctor = json.loads(
            self.cli("doctor", "--task", task_id, "--json").stdout
        )
        self.assertTrue(doctor["ok"], doctor)

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
            "--lock",
            "repo:file:plans-b-job-owner-job-command.sh",
            "--intent",
            "bounded smoke run",
            "--validation",
            "job gate",
            "--expires-at",
            "2099-01-01T00:00:00+00:00",
            "--allow-nonexistent",
        )
        self.create_exact_job_owner(
            "plans-b",
            "plans-b-job-owner",
            command="timeout 1m run.sh",
            work_root="/tmp/aoi-example-run",
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
            "--owner-packet-id",
            "plans-b-job-owner",
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
        state = self.task_state("plans-b")
        self.assertEqual(len(state["plan_approvals"]), 2)
        self.assertIn("job-1", state["plan_approvals"][1]["coverage_note"])
