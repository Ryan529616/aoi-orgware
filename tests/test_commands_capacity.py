#!/usr/bin/env python3
"""Relocation contract for the capacity command family (Wave D4).

The ``capacity-*`` command bodies moved from the monolithic ``cli`` into
:mod:`aoi_orgware.commands.capacity`.  ``capacity-snapshot``,
``capacity-recommend`` and ``capacity-arbitrate`` carry a frozen
:class:`CapacityCmdServices` injected from the composition root;
``capacity-distribute`` and ``capacity-ack`` depend on no composition-root
concern and stay bare ``(args, paths)`` handlers (pure verbatim moves).

Unlike the resource family, no capacity body is fault-injected via
``mock.patch.object(cli, ...)``: the only capacity coupling to ``cli`` state is
that ``_capacity_records`` and ``_records_fingerprint`` remain defined in ``cli``
(shared with the packet/portfolio wiring and called directly off ``cli_impl`` in
``tests/test_cli.py``) and are injected here as direct-bound services.  These
tests pin that contract so a future regression that moves the helpers or swaps
the wiring is caught.
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
from aoi_orgware.commands import capacity as capacity_cmds  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "capacity.py"
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
        "cmd_capacity_snapshot",
        "cmd_capacity_recommend",
        "cmd_capacity_arbitrate",
        "cmd_capacity_distribute",
        "cmd_capacity_ack",
    )
    SERVICE_WIRED = {
        "capacity-snapshot": "cmd_capacity_snapshot",
        "capacity-recommend": "cmd_capacity_recommend",
        "capacity-arbitrate": "cmd_capacity_arbitrate",
    }
    BARE_WIRED = {
        "capacity-distribute": "cmd_capacity_distribute",
        "capacity-ack": "cmd_capacity_ack",
    }

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(capacity_cmds, name),
                f"cli re-export {name} is not the relocated object",
            )

    def _choices(self) -> dict[str, object]:
        parser = cli_impl.build_parser()
        subactions = [
            a
            for a in parser._actions  # noqa: SLF001
            if a.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        return subactions[0].choices

    def test_build_parser_wires_service_bodies_as_partials(self) -> None:
        choices = self._choices()
        for command, body_name in self.SERVICE_WIRED.items():
            body = getattr(capacity_cmds, body_name)
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"], capacity_cmds.CapacityCmdServices
            )

    def test_build_parser_wires_serviceless_bodies_as_bare_handlers(self) -> None:
        choices = self._choices()
        for command, body_name in self.BARE_WIRED.items():
            body = getattr(capacity_cmds, body_name)
            handler = choices[command].get_default("handler")
            self.assertIs(handler, body)
            self.assertNotIsInstance(handler, functools.partial)

    def test_module_leaf_helpers_are_module_local(self) -> None:
        # emit/require_text/require_evidence_detail are pure leaf helpers
        # redeclared inside the command module; the relocated bodies must bind the
        # module-local copies, never reach back into cli.
        self.assertIsNot(capacity_cmds.emit, cli_impl.emit)
        self.assertIsNot(capacity_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(
            capacity_cmds.require_evidence_detail, cli_impl.require_evidence_detail
        )


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._capacity_cmd_services()
        self.assertIsInstance(services, capacity_cmds.CapacityCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.capacity_records = None  # type: ignore[misc]

    def test_direct_bound_callables_are_the_cli_resident_objects(self) -> None:
        services = cli_impl._capacity_cmd_services()
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.require_root_session, cli_impl.require_root_session)
        self.assertIs(
            services.packet_authority_integrity_errors,
            cli_impl.packet_authority_integrity_errors,
        )

    def test_shared_capacity_helpers_stay_in_cli_single_source(self) -> None:
        # _capacity_records / _records_fingerprint are also consumed by the
        # CLI-resident packet/portfolio wiring and called directly off cli_impl
        # in tests/test_cli.py, so cli remains their single source of truth; the
        # services simply inject the same objects.
        services = cli_impl._capacity_cmd_services()
        self.assertIs(services.capacity_records, cli_impl._capacity_records)
        self.assertIs(services.records_fingerprint, cli_impl._records_fingerprint)

    def test_policy_constants_are_bound_from_cli_globals(self) -> None:
        services = cli_impl._capacity_cmd_services()
        self.assertEqual(
            services.capability_catalog_version, cli_impl.CAPABILITY_CATALOG_VERSION
        )
        self.assertIs(services.capability_tier_map, cli_impl.CAPABILITY_TIER_MAP)
        self.assertIs(services.depth_two_roles, cli_impl.DEPTH_TWO_ROLES)


if __name__ == "__main__":
    unittest.main()
