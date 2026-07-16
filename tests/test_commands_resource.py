#!/usr/bin/env python3
"""Relocation contract for the resource command family (Wave D2).

The ``override-*`` and ``codex-config-*`` command bodies (and their
plan/apply/rollback recovery helpers) moved from the monolithic ``cli`` into
:mod:`aoi_orgware.commands.resource`.  Unlike the backup family, these bodies
carry a frozen :class:`ResourceCmdServices` injected from the composition root.

The load-bearing proof lives in :class:`WriteTaskPatchSentinelTests`:
``tests/test_resource_config.py`` fault-injects ``mock.patch.object(cli,
"write_task", ...)`` and drives ``codex-config-rollback`` in-process, expecting
the recovery path to fire.  That only keeps working because the service is bound
LATE (a lambda resolving the ``cli`` global at call time).  A future regression
that rebinds the service to the imported function object directly would silently
stop the patch from biting; the sentinel below catches exactly that, and proves
it is load-bearing by showing a direct binding misses the same patch.
"""

from __future__ import annotations

import ast
import dataclasses
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
from aoi_orgware import harnesslib as harnesslib_impl  # noqa: E402
from aoi_orgware.commands import resource as resource_cmds  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "resource.py"
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
        "cmd_override_request",
        "cmd_override_arbitrate",
        "cmd_override_revoke",
        "cmd_codex_config_plan",
        "cmd_codex_config_apply",
        "cmd_codex_config_rollback",
    )

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(resource_cmds, name),
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
            "override-request": resource_cmds.cmd_override_request,
            "override-arbitrate": resource_cmds.cmd_override_arbitrate,
            "override-revoke": resource_cmds.cmd_override_revoke,
            "codex-config-plan": resource_cmds.cmd_codex_config_plan,
            "codex-config-apply": resource_cmds.cmd_codex_config_apply,
            "codex-config-rollback": resource_cmds.cmd_codex_config_rollback,
        }
        for command, body in expected.items():
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, __import__("functools").partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"], resource_cmds.ResourceCmdServices
            )

    def test_module_leaf_helpers_are_module_local(self) -> None:
        # emit/require_text/require_evidence_detail/_extend_unique are pure leaf
        # helpers redeclared inside the command module; the relocated bodies must
        # bind the module-local copies, never reach back into cli.
        self.assertIsNot(resource_cmds.emit, cli_impl.emit)
        self.assertIsNot(resource_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(
            resource_cmds.require_evidence_detail, cli_impl.require_evidence_detail
        )
        self.assertIsNot(resource_cmds._extend_unique, cli_impl._extend_unique)


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._resource_cmd_services()
        self.assertIsInstance(services, resource_cmds.ResourceCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.write_task = None  # type: ignore[misc]

    def test_direct_bound_fields_are_the_cli_resident_callables(self) -> None:
        services = cli_impl._resource_cmd_services()
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.require_root_session, cli_impl.require_root_session)
        self.assertIs(
            services.approved_override_settings, cli_impl.approved_override_settings
        )
        self.assertIs(
            services.validate_selection_resource_envelope,
            cli_impl._validate_selection_resource_envelope,
        )


class WriteTaskPatchSentinelTests(unittest.TestCase):
    """Permanent guard for the migrated ``cli.write_task`` fault-injection.

    ``test_resource_config.py`` patches ``cli.write_task`` and expects the
    relocated ``codex-config-rollback`` recovery path to observe it.  These fast
    tests pin the mechanism that makes that possible.
    """

    def test_cli_write_task_patch_bites_through_late_bound_service(self) -> None:
        services = cli_impl._resource_cmd_services()
        with mock.patch.object(
            cli_impl,
            "write_task",
            side_effect=HarnessError("SENTINEL rollback write failure"),
        ):
            with self.assertRaises(HarnessError) as ctx:
                services.write_task(object(), {})
        self.assertIn("SENTINEL rollback write failure", str(ctx.exception))

    def test_state_lock_and_write_index_are_late_bound_too(self) -> None:
        services = cli_impl._resource_cmd_services()
        with mock.patch.object(
            cli_impl, "write_index", side_effect=HarnessError("SENTINEL index")
        ):
            with self.assertRaisesRegex(HarnessError, "SENTINEL index"):
                services.write_index(object())
        with mock.patch.object(
            cli_impl, "state_lock", side_effect=HarnessError("SENTINEL lock")
        ):
            with self.assertRaisesRegex(HarnessError, "SENTINEL lock"):
                services.state_lock(object())

    def test_role_tier_map_service_observes_apply_project_config_rebind(self) -> None:
        # apply_project_config rebinds cli.ROLE_TIER_MAP; the service must read
        # the current binding, never a stale snapshot.
        services = cli_impl._resource_cmd_services()
        self.assertIs(services.role_tier_map(), cli_impl.ROLE_TIER_MAP)
        sentinel = {"architect": "frontier"}
        with mock.patch.object(cli_impl, "ROLE_TIER_MAP", sentinel):
            self.assertIs(services.role_tier_map(), sentinel)

    def test_direct_function_binding_would_miss_the_patch(self) -> None:
        # Load-bearing contrast: binding the imported ``write_task`` object
        # directly (the anti-pattern the late-binding rule forbids) keeps
        # pointing at the original and would NOT observe the ``cli`` patch.
        direct = harnesslib_impl.write_task
        with mock.patch.object(
            cli_impl, "write_task", side_effect=HarnessError("boom")
        ):
            self.assertIs(direct, harnesslib_impl.write_task)
            self.assertIsNot(cli_impl.write_task, direct)


if __name__ == "__main__":
    unittest.main()
