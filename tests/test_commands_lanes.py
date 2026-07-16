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


if __name__ == "__main__":
    unittest.main()
