#!/usr/bin/env python3
"""Relocation contract for the lane command family (Wave D6).

The ``lane-*`` command bodies (set-status, create, revise, dependency-add,
dependency-update) moved from the monolithic ``cli`` into
:mod:`aoi_orgware.commands.lanes`.  Like the resource family, these bodies carry
a frozen :class:`LanesCmdServices` injected from the composition root.

No test fault-injects ``write_task``/``write_index``/``state_lock`` while driving
a lane command, so those stay direct imports from ``harnesslib`` in the command
module (the capacity precedent).  The load-bearing sentinel here is the
*late binding* of the two ``apply_project_config``-mutable vocabularies:
``lane_kinds`` and ``role_tier_map`` are zero-argument callables resolving the
``cli`` global at call time.  A regression that value-binds them at factory-build
time would silently capture a stale snapshot after ``apply_project_config``
rebinds a project's roles/departments; the sentinel below catches exactly that
and proves it is load-bearing by showing a build-time snapshot misses the rebind.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import lanes as lane_cmds  # noqa: E402
from tests.harness_case import HarnessTestCase  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "lanes.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "aoi_orgware.cli" for alias in node.names):
                    violations.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"cli", "aoi_orgware.cli"} or any(
                    alias.name == "cli" for alias in node.names
                ):
                    violations.append(f"{path.name}:{node.lineno}")
        self.assertEqual(violations, [])


class RelocationContractTests(unittest.TestCase):
    RELOCATED = (
        "cmd_lane_set_status",
        "cmd_lane_create",
        "cmd_lane_revise",
        "cmd_lane_dependency_add",
        "cmd_lane_dependency_update",
    )

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(lane_cmds, name),
                f"cli re-export {name} is not the relocated object",
            )

    def test_build_parser_wires_relocated_bodies_as_service_partials(self) -> None:
        parser = cli_impl.build_parser()
        subactions = [
            a
            for a in parser._actions  # noqa: SLF001
            if a.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        choices = subactions[0].choices
        expected = {
            "lane-set-status": lane_cmds.cmd_lane_set_status,
            "lane-create": lane_cmds.cmd_lane_create,
            "lane-revise": lane_cmds.cmd_lane_revise,
            "lane-dependency-add": lane_cmds.cmd_lane_dependency_add,
            "lane-dependency-update": lane_cmds.cmd_lane_dependency_update,
        }
        for command, body in expected.items():
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"], lane_cmds.LanesCmdServices
            )

    def test_module_leaf_helpers_are_module_local(self) -> None:
        # emit/require_text/require_evidence_detail are pure leaf helpers
        # redeclared inside the command module; the relocated bodies must bind the
        # module-local copies, never reach back into cli.
        self.assertIsNot(lane_cmds.emit, cli_impl.emit)
        self.assertIsNot(lane_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(
            lane_cmds.require_evidence_detail, cli_impl.require_evidence_detail
        )


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._lanes_cmd_services()
        self.assertIsInstance(services, lane_cmds.LanesCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.max_engaged_lanes = 0  # type: ignore[misc]

    def test_direct_bound_fields_are_the_cli_resident_callables(self) -> None:
        services = cli_impl._lanes_cmd_services()
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.require_root_session, cli_impl.require_root_session)
        self.assertIs(
            services.portfolio_integrity_errors, cli_impl.portfolio_integrity_errors
        )

    def test_immutable_constants_are_value_bound_to_cli(self) -> None:
        services = cli_impl._lanes_cmd_services()
        self.assertEqual(services.max_engaged_lanes, cli_impl.MAX_ENGAGED_LANES)
        self.assertEqual(
            services.terminal_coordination_statuses,
            cli_impl.TERMINAL_COORDINATION_STATUSES,
        )
        self.assertEqual(
            services.terminal_improvement_statuses,
            cli_impl.TERMINAL_IMPROVEMENT_STATUSES,
        )
        self.assertEqual(services.change_classes, cli_impl.CHANGE_CLASSES)
        self.assertEqual(services.dependency_kinds, cli_impl.DEPENDENCY_KINDS)


class MutableVocabLateBindingSentinelTests(unittest.TestCase):
    """Permanent guard for the late-bound ``apply_project_config`` vocabularies.

    ``lane-create`` validates ``args.kind`` against ``LANE_KINDS`` and
    ``args.role`` against ``ROLE_TIER_MAP``; both are rebound by
    ``apply_project_config`` for the active project profile.  The relocated body
    must observe the *current* binding, so the service is a zero-argument callable
    reading the ``cli`` global at call time, never a build-time snapshot.
    """

    def test_lane_kinds_service_observes_cli_rebind(self) -> None:
        services = cli_impl._lanes_cmd_services()
        self.assertEqual(services.lane_kinds(), cli_impl.LANE_KINDS)
        sentinel = {"architecture", "sentinel_department"}
        with mock.patch.object(cli_impl, "LANE_KINDS", sentinel):
            self.assertIs(services.lane_kinds(), sentinel)

    def test_role_tier_map_service_observes_cli_rebind(self) -> None:
        services = cli_impl._lanes_cmd_services()
        self.assertEqual(services.role_tier_map(), cli_impl.ROLE_TIER_MAP)
        sentinel = {"architect": "frontier"}
        with mock.patch.object(cli_impl, "ROLE_TIER_MAP", sentinel):
            self.assertIs(services.role_tier_map(), sentinel)

    def test_late_binding_is_load_bearing_versus_build_time_snapshot(self) -> None:
        # Load-bearing contrast: a build-time value binding (the anti-pattern the
        # late-binding rule forbids) would capture the pre-rebind object and NOT
        # observe the ``apply_project_config`` / patch rebind, whereas the lambda
        # service does.
        services = cli_impl._lanes_cmd_services()
        build_time_snapshot = cli_impl.LANE_KINDS
        sentinel = {"sentinel_only"}
        with mock.patch.object(cli_impl, "LANE_KINDS", sentinel):
            self.assertIs(services.lane_kinds(), sentinel)
            self.assertIsNot(build_time_snapshot, sentinel)


class LaneClosureConsistencyTests(HarnessTestCase):
    """Terminal lane closure records derived packet stats and refuses a
    closure kind that contradicts the lane's own packet ledger.

    Guards the ARISE audit defect where lane ``rtl`` was closed with the
    narrative "No RTL implementation was authorized" while it owned two
    ``rtl_implementation`` done packets and a ``...-vcs-v1..v7`` series: free
    text must not overwrite what the ledger shows.
    """

    def git_commit(self, name: str) -> str:
        marker = self.root / f"authority-{name}.txt"
        marker.write_text(f"{name}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", marker.name], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-m", f"authority {name}"],
            check=True,
            text=True,
            capture_output=True,
        )
        return subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

    def task_state(self, task_id: str) -> dict:
        return json.loads(
            (self.root / ".aoi" / "tasks" / task_id / "state.json").read_text(
                encoding="utf-8"
            )
        )

    def lane_state(self, task_id: str, lane_id: str) -> dict:
        return next(
            lane
            for lane in self.task_state(task_id)["lanes"]
            if lane["lane_id"] == lane_id
        )

    def create_rtl_lane(self, task_id: str, commit: str, lane_id: str = "rtl") -> None:
        self.cli(
            "lane-create",
            "--task",
            task_id,
            "--lane-id",
            lane_id,
            "--kind",
            "implementation",
            "--status",
            "active",
            "--owner",
            f"{lane_id}-agent",
            "--role",
            "implementation_specialist",
            "--authority-commit",
            commit,
            "--contract-version",
            "cv1",
            "--generator-version",
            "gv1",
            "--adapter-version",
            "av1",
            "--next-action",
            f"Advance {lane_id} implementation independently",
        )

    def create_lane_packet(
        self, task_id: str, packet_id: str, lane_id: str, task_type: str
    ) -> None:
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            "implementation_specialist",
            "--model-tier",
            cli_impl.ROLE_TIER_MAP["implementation_specialist"],
            "--objective",
            f"Implement the bounded {lane_id} unit tracked by {packet_id}",
            "--scope",
            "One bounded specialist implementation under the lane authority",
            "--deliverable",
            "One committed implementation with exact evidence",
            "--validation",
            "The Chief checks the result against the lane authority",
            "--lane-id",
            lane_id,
            "--task-type",
            task_type,
        )

    def drive_packet_done(self, task_id: str, packet_id: str) -> None:
        self.dispatch_packet(task_id, packet_id, f"/root/{packet_id}")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "done",
            "--summary",
            f"Completed the bounded {packet_id} implementation under its lane",
            "--evidence",
            f"The canonical result for {packet_id} is bound to the lane authority",
        )

    def cancel_packet(self, task_id: str, packet_id: str) -> None:
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "cancelled",
            "--summary",
            f"The {packet_id} packet was cancelled without material work",
        )

    def close_lane(
        self,
        task_id: str,
        lane_id: str,
        closure_kind: str,
        *,
        ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        lane = self.lane_state(task_id, lane_id)
        return self.cli(
            "lane-set-status",
            "--task",
            task_id,
            "--lane-id",
            lane_id,
            "--expected-revision",
            str(lane["revision"]),
            "--expected-status",
            str(lane["status"]),
            "--status",
            "done",
            "--closure-kind",
            closure_kind,
            "--next-action",
            f"No further specialist work remains in {lane_id}",
            "--reason",
            "The lane owns no active packets or jobs and is terminal",
            "--session-id",
            f"chief-{task_id}",
            ok=ok,
        )

    def test_no_work_closure_contradicting_done_packet_is_rejected(self) -> None:
        # Exact ARISE shape: no_work narrative over a lane that owns a done packet.
        task_id = "lane-close-nowork"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        self.create_lane_packet(task_id, "rtl-impl-1", "rtl", "rtl_implementation")
        self.drive_packet_done(task_id, "rtl-impl-1")
        rejected = self.close_lane(task_id, "rtl", "no_work", ok=False)
        self.assertIn("no_work lane closure contradicts done packets", rejected.stderr)
        self.assertIn("rtl-impl-1", rejected.stderr)
        # The lane stays open because the contradictory close was refused.
        self.assertEqual(self.lane_state(task_id, "rtl")["status"], "active")

    def test_completed_work_closure_records_derived_packet_stats(self) -> None:
        task_id = "lane-close-completed"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        self.create_lane_packet(task_id, "rtl-impl-1", "rtl", "rtl_implementation")
        self.create_lane_packet(task_id, "rtl-vcs-1", "rtl", "rtl_vcs")
        self.create_lane_packet(task_id, "rtl-vcs-2", "rtl", "rtl_vcs")
        self.drive_packet_done(task_id, "rtl-impl-1")
        self.drive_packet_done(task_id, "rtl-vcs-1")
        self.cancel_packet(task_id, "rtl-vcs-2")
        self.close_lane(task_id, "rtl", "completed_work")
        lane = self.lane_state(task_id, "rtl")
        self.assertEqual(lane["status"], "done")
        event = lane["status_events"][-1]
        self.assertEqual(event["new_status"], "done")
        self.assertEqual(event["closure_kind"], "completed_work")
        self.assertEqual(
            event["packet_terminal_stats"],
            {
                "total": 3,
                "by_status": {"cancelled": 1, "done": 2},
                "by_task_type": {"rtl_implementation": 1, "rtl_vcs": 2},
            },
        )

    def test_completed_work_closure_without_a_done_packet_is_rejected(self) -> None:
        task_id = "lane-close-completed-empty"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        self.create_lane_packet(task_id, "rtl-vcs-1", "rtl", "rtl_vcs")
        self.cancel_packet(task_id, "rtl-vcs-1")
        rejected = self.close_lane(task_id, "rtl", "completed_work", ok=False)
        self.assertIn(
            "completed_work lane closure requires at least one done owned packet",
            rejected.stderr,
        )
        self.assertEqual(self.lane_state(task_id, "rtl")["status"], "active")

    def test_aborted_closure_over_mixed_packets_is_allowed_and_records_stats(
        self,
    ) -> None:
        task_id = "lane-close-aborted"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        self.create_lane_packet(task_id, "rtl-impl-1", "rtl", "rtl_implementation")
        self.create_lane_packet(task_id, "rtl-vcs-1", "rtl", "rtl_vcs")
        self.drive_packet_done(task_id, "rtl-impl-1")
        self.cancel_packet(task_id, "rtl-vcs-1")
        self.close_lane(task_id, "rtl", "aborted")
        lane = self.lane_state(task_id, "rtl")
        self.assertEqual(lane["status"], "done")
        event = lane["status_events"][-1]
        self.assertEqual(event["closure_kind"], "aborted")
        self.assertEqual(
            event["packet_terminal_stats"],
            {
                "total": 2,
                "by_status": {"cancelled": 1, "done": 1},
                "by_task_type": {"rtl_implementation": 1, "rtl_vcs": 1},
            },
        )

    def test_closing_a_lane_to_done_requires_closure_kind(self) -> None:
        task_id = "lane-close-missing-kind"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        lane = self.lane_state(task_id, "rtl")
        rejected = self.cli(
            "lane-set-status",
            "--task",
            task_id,
            "--lane-id",
            "rtl",
            "--expected-revision",
            str(lane["revision"]),
            "--expected-status",
            str(lane["status"]),
            "--status",
            "done",
            "--next-action",
            "No further specialist work remains in rtl",
            "--reason",
            "The lane owns no active packets or jobs and is terminal",
            "--session-id",
            f"chief-{task_id}",
            ok=False,
        )
        self.assertIn("closing a lane to done requires --closure-kind", rejected.stderr)

    def test_closure_kind_rejects_an_invalid_choice_at_argparse(self) -> None:
        task_id = "lane-close-bad-kind"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        lane = self.lane_state(task_id, "rtl")
        rejected = self.cli(
            "lane-set-status",
            "--task",
            task_id,
            "--lane-id",
            "rtl",
            "--expected-revision",
            str(lane["revision"]),
            "--expected-status",
            str(lane["status"]),
            "--status",
            "done",
            "--closure-kind",
            "no_such_kind",
            "--next-action",
            "No further specialist work remains in rtl",
            "--reason",
            "The lane owns no active packets or jobs and is terminal",
            "--session-id",
            f"chief-{task_id}",
            ok=False,
        )
        self.assertIn("--closure-kind", rejected.stderr)

    def test_closure_kind_is_rejected_on_a_non_closing_transition(self) -> None:
        task_id = "lane-close-nonterminal"
        self.init_task(task_id, session_id=f"chief-{task_id}")
        commit = self.git_commit(task_id)
        self.create_rtl_lane(task_id, commit)
        lane = self.lane_state(task_id, "rtl")
        rejected = self.cli(
            "lane-set-status",
            "--task",
            task_id,
            "--lane-id",
            "rtl",
            "--expected-revision",
            str(lane["revision"]),
            "--expected-status",
            str(lane["status"]),
            "--status",
            "standby",
            "--closure-kind",
            "completed_work",
            "--next-action",
            "Hold rtl until the next authorized phase",
            "--reason",
            "The lane is paused with no active packets or jobs",
            "--session-id",
            f"chief-{task_id}",
            ok=False,
        )
        self.assertIn(
            "--closure-kind applies only when closing a lane to done", rejected.stderr
        )


if __name__ == "__main__":
    unittest.main()
