#!/usr/bin/env python3
"""WS5/WS6 — typed technical outcomes and the recommendation-only sample gate.

Adversarial contract: packet transport status (done/failed/cancelled) must
never be readable as a model-quality verdict; only explicit accepted/rejected
outcomes enter the model-quality denominator; a capacity recommendation below
its declared eligible-sample minimum must fail closed; the phase stays
recommendation_only and doctor-level invariants reject tampered sample
boundaries.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402

from tests.harness_case import HarnessTestCase  # noqa: E402


class _TypedOutcomeCase(HarnessTestCase):
    def _task_state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def _authority_commit(self, name: str) -> str:
        import subprocess

        marker = self.root / f"authority-{name}.txt"
        marker.write_text(f"{name}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", marker.name], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", f"authority {name}"],
            check=True,
            text=True,
            capture_output=True,
        )
        import subprocess as sp

        return sp.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

    def _create_lane(
        self,
        task_id: str,
        lane_id: str,
        *,
        kind: str,
        role: str,
        commit: str,
        status: str = "active",
    ) -> None:
        self.cli(
            "lane-create",
            "--task",
            task_id,
            "--lane-id",
            lane_id,
            "--kind",
            kind,
            "--status",
            status,
            "--owner",
            f"{lane_id}-agent",
            "--role",
            role,
            "--authority-commit",
            commit,
            "--contract-version",
            "cv1",
            "--generator-version",
            "gv1",
            "--adapter-version",
            "av1",
            "--next-action",
            f"Advance {lane_id} independently",
        )


class TypedOutcomeTests(_TypedOutcomeCase):

    def _create_packet(self, task_id: str, packet_id: str, **kwargs: str) -> None:
        args = [
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            kwargs.get("role", "explorer"),
            "--model-tier",
            kwargs.get("tier", "standard"),
            "--objective",
            "Produce one bounded typed-outcome fixture",
            "--scope",
            "Isolated fixture",
            "--deliverable",
            "Canonical terminal result",
            "--validation",
            "Result identity is recorded",
        ]
        for key in ("lane_id", "task_type"):
            if key in kwargs:
                args.extend([f"--{key.replace('_', '-')}", kwargs[key]])
        self.cli(*args)

    def test_explicit_outcome_recorded_with_provenance(self) -> None:
        task_id = "typed-explicit"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        self.dispatch_packet(task_id, "probe", "agent-1")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "done",
            "--typed-outcome",
            "rejected",
            "--summary",
            "Result was reviewed and rejected on quality grounds",
            "--evidence",
            "review found the conclusion unsupported by cited lines",
        )
        packet = self._task_state(task_id)["packets"][0]
        self.assertEqual(packet["typed_outcome"], "rejected")
        self.assertEqual(packet["typed_outcome_provenance"], "operator_declared")
        result_text = Path(packet["result_path"]).read_text(encoding="utf-8")
        self.assertIn("Typed outcome: `rejected` (`operator_declared`)", result_text)

    def test_done_without_outcome_is_unclassified_and_ineligible(self) -> None:
        task_id = "typed-default"
        self.init_task(task_id)
        commit = self._authority_commit(task_id)
        self._create_lane(
            task_id, "rtl", kind="implementation",
            role="implementation_specialist", commit=commit,
        )
        self._create_packet(task_id, "probe", lane_id="rtl", task_type="fixture")
        self.dispatch_packet(task_id, "probe", "agent-1")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "done",
            "--summary",
            "Completed without an explicit typed outcome",
            "--evidence",
            "result cites exact source paths",
        )
        state = self._task_state(task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["typed_outcome"], "unclassified")
        records = cli_impl._capacity_records(state, "rtl", "fixture")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["typed_outcome"], "unclassified")
        self.assertFalse(records[0]["model_quality_eligible"])
        self.assertEqual(
            records[0]["engineering_acceptance"],
            "not_inferred_from_packet_status",
        )

    def test_failed_without_outcome_is_unclassified(self) -> None:
        task_id = "typed-failed-default"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        self.dispatch_packet(task_id, "probe", "agent-1")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "failed",
            "--summary",
            "Failed without an explicit typed outcome",
            "--evidence",
            "the runner reported a non-zero exit",
        )
        packet = self._task_state(task_id)["packets"][0]
        self.assertEqual(packet["typed_outcome"], "unclassified")
        self.assertEqual(packet["typed_outcome_provenance"], "unclassified")

    def test_cancelled_defaults_to_cancelled_outcome(self) -> None:
        task_id = "typed-cancel"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "cancelled",
            "--summary",
            "Cancelled before dispatch",
        )
        packet = self._task_state(task_id)["packets"][0]
        self.assertEqual(packet["typed_outcome"], "cancelled")
        self.assertEqual(packet["typed_outcome_provenance"], "derived_from_status")

    def test_status_outcome_mismatch_fails_closed(self) -> None:
        task_id = "typed-mismatch"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        self.dispatch_packet(task_id, "probe", "agent-1")
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "failed",
            "--typed-outcome",
            "accepted",
            "--summary",
            "A failed packet cannot be accepted",
            "--evidence",
            "the runner reported a non-zero exit",
            ok=False,
        )
        self.assertIn("not valid for status", rejected.stderr)
        # 'cancelled' as an outcome for a done packet is equally invalid.
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "done",
            "--typed-outcome",
            "cancelled",
            "--summary",
            "A done packet cannot be outcome-cancelled",
            "--evidence",
            "terminal result exists",
            ok=False,
        )
        self.assertIn("not valid for status", rejected.stderr)

    def test_outcome_on_non_terminal_transition_fails_closed(self) -> None:
        task_id = "typed-nonterminal"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        self.arm_packet(task_id, "probe")
        rejected = self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "dispatched",
            "--agent-id",
            "agent-1",
            "--typed-outcome",
            "accepted",
            ok=False,
        )
        self.assertIn("terminal packet transition", rejected.stderr)


class SampleGateTests(_TypedOutcomeCase):
    def _capacity_fixture(self, task_id: str, *, typed_outcome: str | None) -> dict:
        """Build lanes + one terminal dataset packet, return the snapshot review."""

        self.init_task(task_id, session_id="harness-test-chief")
        commit = self._authority_commit(task_id)
        self._create_lane(
            task_id, "rtl", kind="implementation",
            role="implementation_specialist", commit=commit,
        )
        self._create_lane(
            task_id, "steward", kind="coordination_steward",
            role="default", commit=commit,
        )
        self._create_lane(
            task_id, "capacity", kind="capacity_planning",
            role="architect", commit=commit, status="standby",
        )
        self.cli(
            "lane-set-status",
            "--task",
            task_id,
            "--lane-id",
            "capacity",
            "--expected-revision",
            "1",
            "--expected-status",
            "standby",
            "--status",
            "active",
            "--next-action",
            "Analyze the fixture capacity dataset",
            "--reason",
            "Chief activates capacity planning for this bounded review",
            "--session-id",
            "harness-test-chief",
        )
        update_args = [
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "history",
            "--status",
            "done",
            "--summary",
            "Completed bounded fixture",
            "--evidence",
            "Canonical result records the terminal outcome",
        ]
        if typed_outcome:
            update_args.extend(["--typed-outcome", typed_outcome])
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "history",
            "--agent-role",
            "worker",
            "--model-tier",
            "advanced",
            "--objective",
            "Produce bounded fixture evidence",
            "--scope",
            "Isolated fixture",
            "--deliverable",
            "Canonical terminal result",
            "--validation",
            "Result identity is recorded",
            "--lane-id",
            "rtl",
            "--task-type",
            "fixture",
        )
        self.dispatch_packet(task_id, "history", "/root/history")
        self.cli(*update_args)
        return json.loads(
            self.cli(
                "capacity-snapshot",
                "--task",
                task_id,
                "--review-id",
                "fixture-review",
                "--capacity-lane-id",
                "capacity",
                "--target-lane-id",
                "rtl",
                "--task-type",
                "fixture",
                "--leaf-role",
                "worker",
                "--expected-lane-revision",
                "1",
                "--json",
            ).stdout
        )

    def _recommend(self, task_id: str, review: dict, *, ok: bool = True):
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "analysis",
            "--agent-role",
            "architect",
            "--model-tier",
            "frontier",
            "--objective",
            "Analyze the capacity dataset",
            "--scope",
            "Isolated fixture",
            "--deliverable",
            "Canonical terminal result",
            "--validation",
            "Result identity is recorded",
            "--lane-id",
            "capacity",
            "--task-type",
            "capacity-analysis",
            "--capacity-review-source-id",
            "fixture-review",
            "--input-artifact",
            f"{review['dataset']['path']}={review['dataset']['sha256']}",
        )
        self.dispatch_packet(task_id, "analysis", "/root/analysis")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "analysis",
            "--status",
            "done",
            "--typed-outcome",
            "accepted",
            "--summary",
            "Dataset analysis complete",
            "--evidence",
            "analysis cites the exact dataset sha",
        )
        return self.cli(
            "capacity-recommend",
            "--task",
            task_id,
            "--review-id",
            "fixture-review",
            "--expected-version",
            str(review["version"]),
            "--source-packet-id",
            "analysis",
            "--capability-tier",
            "c3_advanced",
            "--rationale",
            "Historical fixture evidence justifies the advanced tier",
            "--risk",
            "Single-unit sample keeps this recommendation deliberately narrow",
            "--confidence-boundary",
            "Requested routing is auditable; actual routing remains unobserved",
            "--min-eligible-records",
            "1",
            "--json",
            ok=ok,
        )

    def test_zero_eligible_records_fail_the_sample_gate(self) -> None:
        task_id = "gate-zero-eligible"
        # done WITHOUT a typed outcome -> unclassified -> ineligible.
        review = self._capacity_fixture(task_id, typed_outcome=None)
        self.assertEqual(review["dataset"]["record_count"], 1)
        self.assertEqual(review["dataset"]["eligible_record_count"], 0)
        rejected = self._recommend(task_id, review, ok=False)
        self.assertIn("sample gate failed", rejected.stderr)
        self.assertIn("never count toward the model-quality sample", rejected.stderr)

    def test_eligible_record_passes_gate_and_records_boundary(self) -> None:
        task_id = "gate-one-eligible"
        review = self._capacity_fixture(task_id, typed_outcome="accepted")
        self.assertEqual(review["dataset"]["eligible_record_count"], 1)
        result = self._recommend(task_id, review)
        recommendation = json.loads(result.stdout)["recommendation"]
        self.assertEqual(recommendation["phase"], "recommendation_only")
        self.assertEqual(
            recommendation["sample_boundary"],
            {
                "min_eligible_records": 1,
                "eligible_record_count": 1,
                "record_count": 1,
            },
        )

    def test_capacity_recommendation_only_config_key(self) -> None:
        base = (self.root / "aoi.toml").read_text(encoding="utf-8")
        candidate = self.root / "config-candidate.toml"
        # Explicit false parses (operator consciously leaves the phase).
        candidate.write_text(
            base.replace(
                'external_lock_namespace = "external"',
                'external_lock_namespace = "external"\n'
                "capacity_recommendation_only = false",
            ),
            encoding="utf-8",
        )
        self.cli("config-check", "--file", str(candidate))
        # Non-boolean value fails closed.
        candidate.write_text(
            base.replace(
                'external_lock_namespace = "external"',
                'external_lock_namespace = "external"\n'
                'capacity_recommendation_only = "yes"',
            ),
            encoding="utf-8",
        )
        rejected = self.cli("config-check", "--file", str(candidate), ok=False)
        self.assertIn("capacity_recommendation_only", rejected.stderr)
        # Absent key defaults to the restrictive phase.
        from aoi_orgware import config as config_impl

        parsed = config_impl.parse_config_bytes(
            self.root, base.encode("utf-8"), self.root / "aoi.toml"
        )
        self.assertTrue(parsed.capacity_recommendation_only)

    def test_tampered_sample_boundary_fails_portfolio_integrity(self) -> None:
        task_id = "gate-tamper"
        review = self._capacity_fixture(task_id, typed_outcome="accepted")
        self._recommend(task_id, review)
        state = self._task_state(task_id)
        from aoi_orgware import harnesslib as h

        paths = h.get_paths(self.root)
        self.assertEqual(cli_impl.portfolio_integrity_errors(state, paths), [])
        tampered = copy.deepcopy(state)
        tampered["capacity_reviews"][0]["recommendation"]["sample_boundary"][
            "eligible_record_count"
        ] = 0
        self.assertTrue(
            any(
                "sample boundary is malformed" in error
                for error in cli_impl.portfolio_integrity_errors(tampered, paths)
            )
        )
        phase_tampered = copy.deepcopy(state)
        phase_tampered["capacity_reviews"][0]["recommendation"]["phase"] = "auto_apply"
        self.assertTrue(
            any(
                "sample boundary is malformed" in error
                for error in cli_impl.portfolio_integrity_errors(
                    phase_tampered, paths
                )
            )
        )
        # Evasion by DELETING the sample fields must also fail: the
        # sha-anchored dataset file pins the review to the typed contract.
        stripped = copy.deepcopy(state)
        del stripped["capacity_reviews"][0]["recommendation"]["sample_boundary"]
        del stripped["capacity_reviews"][0]["recommendation"]["phase"]
        self.assertTrue(
            any(
                "phase/sample-boundary contract" in error
                for error in cli_impl.portfolio_integrity_errors(stripped, paths)
            )
        )
        count_stripped = copy.deepcopy(state)
        del count_stripped["capacity_reviews"][0]["dataset"][
            "eligible_record_count"
        ]
        self.assertTrue(
            any(
                "diverges from its sha-anchored dataset file" in error
                for error in cli_impl.portfolio_integrity_errors(
                    count_stripped, paths
                )
            )
        )
