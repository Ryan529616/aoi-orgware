#!/usr/bin/env python3
"""Relocation contract for the execution-selection command family (Wave D7).

The ``execution-select-plan`` / ``execution-select`` / ``execution-brief-record``
command bodies and their argument-validation and target-contract helpers moved
from the monolithic ``cli`` into :mod:`aoi_orgware.commands.execution_selection`.
Like the resource/lane families, these bodies carry a frozen
:class:`ExecutionSelectionCmdServices` injected from the composition root.

Two helpers stay in ``cli`` as single sources of truth and are only *injected*
here: ``_selection_terminal_packet_bindings`` and ``_steward_packet_binding`` are
wired into the CLI-resident ``PacketIntegrityServices`` /
``ExecutionTopologyServices`` / ``PortfolioIntegrityServices`` factories (and are
identity-asserted off ``cli`` in ``test_packet_integrity``), and
``_execution_brief_coverage_error`` is unit-tested off ``cli`` and consumed by the
keep-list task-integrity projection.  The factory-wiring tests below prove the
relocated family consumes the *same* ``cli`` objects (no forked copy).

No test fault-injects ``write_task``/``write_index``/``state_lock`` while driving
an execution-selection command, so those stay direct imports from ``harnesslib``
in the command module (the capacity precedent).  The load-bearing sentinel here
is the *late binding* of ``role_tier_map``: ``execution-select-plan`` validates
``--proposed-setting`` roles against ``cli.ROLE_TIER_MAP``, which the suite
fault-injects via ``mock.patch.object`` and ``apply_project_config`` rebinds.  A
regression that value-binds it at factory-build time would silently capture a
stale snapshot; the sentinel below catches exactly that.
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
from aoi_orgware.commands import execution_selection as es_cmds  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "execution_selection.py"
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
        "cmd_execution_select_plan",
        "cmd_execution_select",
        "cmd_execution_brief_record",
    )

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(es_cmds, name),
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
            "execution-select-plan": es_cmds.cmd_execution_select_plan,
            "execution-select": es_cmds.cmd_execution_select,
            "execution-brief-record": es_cmds.cmd_execution_brief_record,
        }
        for command, body in expected.items():
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"], es_cmds.ExecutionSelectionCmdServices
            )

    def test_module_leaf_helpers_are_module_local(self) -> None:
        # emit/require_text/require_evidence_detail/canonical_record_sha256/
        # _is_exact_int are pure leaf helpers redeclared inside the command
        # module; the relocated bodies must bind the module-local copies, never
        # reach back into cli.
        self.assertIsNot(es_cmds.emit, cli_impl.emit)
        self.assertIsNot(es_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(
            es_cmds.require_evidence_detail, cli_impl.require_evidence_detail
        )
        self.assertIsNot(
            es_cmds.canonical_record_sha256, cli_impl.canonical_record_sha256
        )
        self.assertIsNot(es_cmds._is_exact_int, cli_impl._is_exact_int)


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._execution_selection_cmd_services()
        self.assertIsInstance(services, es_cmds.ExecutionSelectionCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.require_plan_ready = None  # type: ignore[misc]

    def test_direct_bound_fields_are_the_cli_resident_callables(self) -> None:
        services = cli_impl._execution_selection_cmd_services()
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.require_root_session, cli_impl.require_root_session)
        self.assertIs(
            services.approved_override_settings, cli_impl.approved_override_settings
        )
        self.assertIs(
            services.require_override_target_contract,
            cli_impl.require_override_target_contract,
        )
        self.assertIs(services.override_by_id, cli_impl.override_by_id)
        self.assertIs(
            services.packet_authority_integrity_errors,
            cli_impl.packet_authority_integrity_errors,
        )
        self.assertIs(
            services.packet_result_integrity_errors,
            cli_impl.packet_result_integrity_errors,
        )
        self.assertIs(
            services.selection_done_packet_authority_errors,
            cli_impl.selection_done_packet_authority_errors,
        )

    def test_single_source_helpers_are_the_cli_resident_objects(self) -> None:
        # These helpers stay defined in cli (single source of truth: they feed
        # the CLI-resident packet/topology/portfolio wiring and the keep-list
        # projection).  New execution-brief writes deliberately use the strict
        # identity helper; historical portfolio readback retains the legacy
        # compatibility helper.
        services = cli_impl._execution_selection_cmd_services()
        self.assertIs(
            services.build_execution_resource_envelope,
            cli_impl._build_execution_resource_envelope,
        )
        self.assertIs(
            services.lane_authority_snapshot, cli_impl._lane_authority_snapshot
        )
        self.assertIs(
            services.execution_brief_coverage_error,
            cli_impl._execution_brief_coverage_error,
        )
        self.assertIs(
            services.steward_packet_binding, cli_impl._new_steward_packet_binding
        )
        self.assertIs(
            services.selection_terminal_packet_bindings,
            cli_impl._selection_terminal_packet_bindings,
        )

    def test_immutable_constant_is_value_bound_to_cli(self) -> None:
        services = cli_impl._execution_selection_cmd_services()
        self.assertEqual(
            services.terminal_coordination_statuses,
            cli_impl.TERMINAL_COORDINATION_STATUSES,
        )


class RoleTierMapLateBindingSentinelTests(unittest.TestCase):
    """Permanent guard for the late-bound ``ROLE_TIER_MAP`` vocabulary.

    ``execution-select-plan`` validates ``--proposed-setting`` roles against
    ``cli.ROLE_TIER_MAP``, which ``apply_project_config`` rebinds per project
    profile and the suite fault-injects via ``mock.patch.object``.  The relocated
    body must observe the *current* binding, so the service is a zero-argument
    callable reading the ``cli`` global at call time, never a build-time snapshot.
    """

    def test_role_tier_map_service_observes_cli_rebind(self) -> None:
        services = cli_impl._execution_selection_cmd_services()
        self.assertIs(services.role_tier_map(), cli_impl.ROLE_TIER_MAP)
        sentinel = {"architect": "frontier"}
        with mock.patch.object(cli_impl, "ROLE_TIER_MAP", sentinel):
            self.assertIs(services.role_tier_map(), sentinel)

    def test_late_binding_is_load_bearing_versus_build_time_snapshot(self) -> None:
        # Load-bearing contrast: a build-time value binding (the anti-pattern the
        # late-binding rule forbids) would capture the pre-rebind object and NOT
        # observe the patch rebind, whereas the lambda service does.
        services = cli_impl._execution_selection_cmd_services()
        build_time_snapshot = cli_impl.ROLE_TIER_MAP
        sentinel = {"sentinel_only": "frontier"}
        with mock.patch.object(cli_impl, "ROLE_TIER_MAP", sentinel):
            self.assertIs(services.role_tier_map(), sentinel)
            self.assertIsNot(build_time_snapshot, sentinel)


if __name__ == "__main__":
    unittest.main()
