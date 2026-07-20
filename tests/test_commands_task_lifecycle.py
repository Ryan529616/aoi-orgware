#!/usr/bin/env python3
"""Relocation contract for the task-lifecycle command family (Wave D8).

The repo-bootstrap (``init``/``config-check``), task/claim state-machine
(``init-task`` through ``checkpoint``), ``chief-*`` Chief-lease, and ``pilot-*``
kit command bodies (and their small helpers) moved from the monolithic ``cli``
into :mod:`aoi_orgware.commands.task_lifecycle`.  Bodies that touch a
composition-root concern carry a frozen :class:`TaskLifecycleCmdServices`
injected from the CLI; the rest are bare handlers.

The load-bearing proof lives in :class:`StateLockPatchSentinelTests`:
``tests/test_cli.py`` fault-injects ``mock.patch.object(cli, "state_lock", ...)``
and drives ``init`` in-process (the init/config-race tests), expecting the
relocated body to observe the swap.  That only keeps working because
``state_lock`` is bound LATE (a lambda resolving the ``cli`` global at call
time).  A future regression rebinding it to the imported function object would
silently stop the patch from biting; the sentinel below catches exactly that and
proves it is load-bearing by showing a direct binding misses the same patch.
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
from aoi_orgware import harnesslib as harnesslib_impl  # noqa: E402
from aoi_orgware.commands import task_lifecycle as tl_cmds  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "task_lifecycle.py"
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
    DIRECT_REEXPORTS = (
        "cmd_unbind_session",
        "cmd_config_check",
        "cmd_chief_acquire",
        "cmd_chief_renew",
        "cmd_chief_release",
        "cmd_chief_takeover",
        "cmd_chief_status",
        "cmd_pilot_init",
        "cmd_pilot_validate",
        "cmd_pilot_summary",
        "cmd_init_task",
        "cmd_start_mini",
        "cmd_approve_plan",
        "cmd_plan_update",
        "cmd_bind_session",
        "cmd_import_legacy",
        "cmd_check_locks",
        "cmd_inspect_legacy",
        "cmd_claim",
        "cmd_set_claim_status",
        "cmd_release_claim",
        "cmd_audit_legacy",
        "cmd_set_phase",
        "cmd_adopt_current_branch",
        "cmd_checkpoint",
        "_chief_credential",
    )

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.DIRECT_REEXPORTS:
            self.assertIs(
                getattr(cli_impl, name),
                getattr(tl_cmds, name),
                f"cli re-export {name} is not the relocated object",
            )

    def test_cmd_init_reexport_wraps_relocated_body_with_services(self) -> None:
        self.assertIs(cli_impl._cmd_init, tl_cmds.cmd_init)
        self.assertIsNot(cli_impl.cmd_init, tl_cmds.cmd_init)
        self.assertTrue(callable(cli_impl.cmd_init))

    def test_build_parser_wires_service_partials_and_bare_handlers(self) -> None:
        parser = cli_impl.build_parser({})
        subactions = [
            a
            for a in parser._actions  # noqa: SLF001
            if a.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        choices = subactions[0].choices

        service_partials = {
            "chief-acquire": tl_cmds.cmd_chief_acquire,
            "chief-renew": tl_cmds.cmd_chief_renew,
            "chief-release": tl_cmds.cmd_chief_release,
            "chief-takeover": tl_cmds.cmd_chief_takeover,
            "init-task": tl_cmds.cmd_init_task,
            "start-mini": tl_cmds.cmd_start_mini,
            "approve-plan": tl_cmds.cmd_approve_plan,
            "plan-update": tl_cmds.cmd_plan_update,
            "bind-session": tl_cmds.cmd_bind_session,
            "unbind-session": tl_cmds.cmd_unbind_session,
            "claim": tl_cmds.cmd_claim,
            "adopt-current-branch": tl_cmds.cmd_adopt_current_branch,
            "checkpoint": tl_cmds.cmd_checkpoint,
        }
        for command, body in service_partials.items():
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial, command)
            self.assertIs(handler.func, body, command)
            self.assertIsInstance(
                handler.keywords["services"], tl_cmds.TaskLifecycleCmdServices
            )

        bare_handlers = {
            "config-check": tl_cmds.cmd_config_check,
            "chief-status": tl_cmds.cmd_chief_status,
            "pilot-init": tl_cmds.cmd_pilot_init,
            "pilot-validate": tl_cmds.cmd_pilot_validate,
            "pilot-summary": tl_cmds.cmd_pilot_summary,
            "import-legacy": tl_cmds.cmd_import_legacy,
            "check-locks": tl_cmds.cmd_check_locks,
            "inspect-legacy": tl_cmds.cmd_inspect_legacy,
            "set-claim-status": tl_cmds.cmd_set_claim_status,
            "release-claim": tl_cmds.cmd_release_claim,
            "audit-legacy": tl_cmds.cmd_audit_legacy,
            "set-phase": tl_cmds.cmd_set_phase,
        }
        for command, body in bare_handlers.items():
            self.assertIs(choices[command].get_default("handler"), body, command)

        self.assertIs(choices["init"].get_default("handler"), cli_impl.cmd_init)

    def test_module_leaf_helpers_are_module_local(self) -> None:
        self.assertIsNot(tl_cmds.emit, cli_impl.emit)
        self.assertIsNot(tl_cmds.require_text, cli_impl.require_text)
        self.assertIsNot(tl_cmds._extend_unique, cli_impl._extend_unique)
        self.assertIsNot(tl_cmds._resource_text, cli_impl._resource_text)

    def test_cli_has_no_stale_moved_definitions(self) -> None:
        path = SRC / "aoi_orgware" / "cli.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        defined = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        moved = set(self.DIRECT_REEXPORTS) | {
            "_explicit_config",
            "_config_summary",
            "_require_pristine_bootstrap_state",
            "_chief_identity",
            "_chief_acquisition_payload",
            "uncovered_dependencies_after_release",
        }
        self.assertEqual(defined & moved, set())

    def test_cli_keep_list_definitions_stay(self) -> None:
        path = SRC / "aoi_orgware" / "cli.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        defined = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        expected = {
            "bind_session_unlocked",
            "ensure_subagent_parent_mapping_unlocked",
            "unbind_all_sessions_unlocked",
            "_resource_text",
            "_extend_unique",
            "emit",
            "require_text",
        }
        self.assertEqual(expected - defined, set())


class ServicesFactoryWiringTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = cli_impl._task_lifecycle_cmd_services()
        self.assertIsInstance(services, tl_cmds.TaskLifecycleCmdServices)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.reload_locked_paths = None  # type: ignore[misc]

    def test_direct_bound_fields_are_the_cli_resident_callables(self) -> None:
        services = cli_impl._task_lifecycle_cmd_services()
        self.assertIs(services.reload_locked_paths, cli_impl._reload_locked_paths)
        self.assertIs(services.require_plan_ready, cli_impl.require_plan_ready)
        self.assertIs(services.check_session_id, cli_impl.check_session_id)
        self.assertIs(services.validate_mini_locks, cli_impl.validate_mini_locks)
        self.assertIs(services.plan_path, cli_impl.plan_path)
        self.assertIs(services.commit_checkpoint, cli_impl.commit_checkpoint)
        self.assertIs(services.substitute, cli_impl.substitute)
        self.assertIs(services.template_text, cli_impl.template_text)
        self.assertIs(services.bind_session_unlocked, cli_impl.bind_session_unlocked)

    def test_value_bound_constants_are_the_cli_owned_objects(self) -> None:
        services = cli_impl._task_lifecycle_cmd_services()
        self.assertIs(
            services.root_session_mapping_kind, cli_impl.ROOT_SESSION_MAPPING_KIND
        )
        self.assertIs(
            services.subagent_parent_mapping_kind,
            cli_impl.SUBAGENT_PARENT_MAPPING_KIND,
        )
        self.assertIs(
            services.known_managed_policy_sha256,
            cli_impl.KNOWN_MANAGED_POLICY_SHA256,
        )
        self.assertIs(services.plan_fallback, cli_impl.PLAN_FALLBACK)


class StateLockPatchSentinelTests(unittest.TestCase):
    def test_cli_state_lock_patch_bites_through_late_bound_service(self) -> None:
        services = cli_impl._task_lifecycle_cmd_services()
        with mock.patch.object(
            cli_impl,
            "state_lock",
            side_effect=HarnessError("SENTINEL init lock swap"),
        ):
            with self.assertRaises(HarnessError) as ctx:
                services.state_lock(object())
        self.assertIn("SENTINEL init lock swap", str(ctx.exception))

    def test_direct_function_binding_would_miss_the_patch(self) -> None:
        direct = harnesslib_impl.state_lock
        with mock.patch.object(
            cli_impl, "state_lock", side_effect=HarnessError("boom")
        ):
            self.assertIs(direct, harnesslib_impl.state_lock)
            self.assertIsNot(cli_impl.state_lock, direct)


if __name__ == "__main__":
    unittest.main()
