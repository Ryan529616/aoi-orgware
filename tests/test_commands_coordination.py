#!/usr/bin/env python3
"""Relocation contract for the coordination command family (Wave D6).

The ``cross-lane-*``, ``needs-user-*``, ``coordination-*`` and ``baseline-freeze``
command bodies (with the ``_baseline_lane_snapshot`` helper) moved from the
monolithic ``cli`` into :mod:`aoi_orgware.commands.coordination`.  Ten bodies
carry a frozen :class:`CoordinationCmdServices`; three
(``cross-lane-close``/``cross-lane-cancel``/``coordination-directive-ack``)
depend on no composition-root concern and stay bare ``(args, paths)`` handlers.

No test fault-injects a ``cli`` attribute while driving a coordination command,
so every service is direct-bound (helpers) or value-bound (immutable policy
constants); none needs late binding.  The load-bearing proof of the relocation
is therefore object identity — the composition root must wire the *relocated*
callables (a stale copy left behind in ``cli`` is caught here), the service-fed
bodies must arrive as ``functools.partial(..., services=...)``, and the bare
handlers must arrive unwrapped.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import coordination as coord_cmds  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "coordination.py"
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
        "cmd_cross_lane_open",
        "cmd_cross_lane_close",
        "cmd_cross_lane_cancel",
        "cmd_needs_user_create",
        "cmd_needs_user_resolve",
        "cmd_coordination_create",
        "cmd_coordination_update",
        "cmd_coordination_arbitrate",
        "cmd_coordination_directive_ack",
        "cmd_coordination_resolve",
        "cmd_coordination_implementation_submit",
        "cmd_coordination_verify",
        "cmd_baseline_freeze",
    )

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(coord_cmds, name),
                f"cli re-export {name} is not the relocated object",
            )

    def test_baseline_lane_snapshot_helper_left_no_stale_copy_in_cli(self) -> None:
        # The private helper moved wholesale into the command module; a future
        # regression that leaves a duplicate behind in cli is caught here.
        self.assertFalse(hasattr(cli_impl, "_baseline_lane_snapshot"))
        self.assertTrue(hasattr(coord_cmds, "_baseline_lane_snapshot"))

    def test_build_parser_wires_service_partials_and_bare_handlers(self) -> None:
        parser = cli_impl.build_parser()
        subactions = [
            a
            for a in parser._actions  # noqa: SLF001
            if a.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        choices = subactions[0].choices
        service_bodies = {
            "cross-lane-open": coord_cmds.cmd_cross_lane_open,
            "needs-user-create": coord_cmds.cmd_needs_user_create,
            "needs-user-resolve": coord_cmds.cmd_needs_user_resolve,
            "coordination-create": coord_cmds.cmd_coordination_create,
            "coordination-update": coord_cmds.cmd_coordination_update,
            "coordination-arbitrate": coord_cmds.cmd_coordination_arbitrate,
            "coordination-resolve": coord_cmds.cmd_coordination_resolve,
            "coordination-implementation-submit": (
                coord_cmds.cmd_coordination_implementation_submit
            ),
            "coordination-verify": coord_cmds.cmd_coordination_verify,
            "baseline-freeze": coord_cmds.cmd_baseline_freeze,
        }
        for command, body in service_bodies.items():
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"], coord_cmds.CoordinationCmdServices
            )
        bare = {
            "cross-lane-close": coord_cmds.cmd_cross_lane_close,
            "cross-lane-cancel": coord_cmds.cmd_cross_lane_cancel,
            "coordination-directive-ack": coord_cmds.cmd_coordination_directive_ack,
        }
        for command, body in bare.items():
            handler = choices[command].get_default("handler")
            self.assertIs(handler, body)

    def test_module_leaf_helpers_are_module_local(self) -> None:
        self.assertIsNot(coord_cmds.emit, cli_impl.emit)
        self.assertIsNot(coord_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(
            coord_cmds.require_evidence_detail, cli_impl.require_evidence_detail
        )


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._coordination_cmd_services()
        self.assertIsInstance(services, coord_cmds.CoordinationCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.cooperative_authority_boundary = ""  # type: ignore[misc]

    def test_direct_bound_fields_are_the_cli_resident_callables(self) -> None:
        services = cli_impl._coordination_cmd_services()
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.require_root_session, cli_impl.require_root_session)
        self.assertIs(
            services.portfolio_integrity_errors, cli_impl.portfolio_integrity_errors
        )
        self.assertIs(
            services.snapshot_evidence_artifact, cli_impl.snapshot_evidence_artifact
        )

    def test_immutable_constants_are_value_bound_to_cli(self) -> None:
        services = cli_impl._coordination_cmd_services()
        self.assertEqual(services.change_classes, cli_impl.CHANGE_CLASSES)
        self.assertEqual(services.dependency_kinds, cli_impl.DEPENDENCY_KINDS)
        self.assertEqual(
            services.terminal_coordination_statuses,
            cli_impl.TERMINAL_COORDINATION_STATUSES,
        )
        self.assertEqual(
            services.cooperative_authority_boundary,
            cli_impl.COOPERATIVE_AUTHORITY_BOUNDARY,
        )


if __name__ == "__main__":
    unittest.main()
