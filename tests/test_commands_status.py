#!/usr/bin/env python3
"""Relocation and behavior contracts for the status command family."""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import functools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware.commands import status as status_cmds  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


def _services(**overrides: object) -> status_cmds.StatusCmdServices:
    values: dict[str, object] = {
        "check_session_id": lambda value: value,
        "plan_digest": lambda paths, state: str(state.get("plan_sha256", "")),
        "terminal_coordination_statuses": frozenset(
            {"rejected", "resolved", "superseded"}
        ),
        "terminal_improvement_statuses": frozenset(
            {"rejected", "adopted", "rolled_back", "deprecated"}
        ),
        "max_engaged_lanes": 12,
        "critical_view_max_bytes": 12 * 1024,
        "critical_text_limit": 160,
    }
    values.update(overrides)
    return status_cmds.StatusCmdServices(**values)  # type: ignore[arg-type]


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_import_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "commands" / "status.py"
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
        "_clip_critical",
        "critical_projection",
        "resolve_resume_task",
        "cmd_resume",
        "cmd_status",
        "cmd_render_index",
    )

    def test_cli_reexports_are_the_relocated_objects(self) -> None:
        for name in self.RELOCATED:
            self.assertIs(getattr(cli_impl, name), getattr(status_cmds, name), name)

    def test_cli_has_no_stale_moved_definitions(self) -> None:
        path = SRC / "aoi_orgware" / "cli.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        defined = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertEqual(defined & set(self.RELOCATED), set())

    def test_build_parser_wires_status_services(self) -> None:
        parser = cli_impl.build_parser({})
        subactions = [
            action
            for action in parser._actions  # noqa: SLF001
            if action.__class__.__name__ == "_SubParsersAction"
        ]
        self.assertEqual(len(subactions), 1)
        choices = subactions[0].choices
        for command, body in {
            "resume": status_cmds.cmd_resume,
            "status": status_cmds.cmd_status,
        }.items():
            handler = choices[command].get_default("handler")
            self.assertIsInstance(handler, functools.partial)
            self.assertIs(handler.func, body)
            self.assertIsInstance(
                handler.keywords["services"], status_cmds.StatusCmdServices
            )
        self.assertIs(
            choices["render-index"].get_default("handler"),
            status_cmds.cmd_render_index,
        )


class ServicesFactoryTests(unittest.TestCase):
    def test_services_are_frozen_and_bound_to_cli_policy(self) -> None:
        services = cli_impl._status_cmd_services()
        self.assertIsInstance(services, status_cmds.StatusCmdServices)
        self.assertIs(services.check_session_id, cli_impl.check_session_id)
        self.assertIs(services.plan_digest, cli_impl.plan_digest)
        self.assertEqual(services.critical_view_max_bytes, 12 * 1024)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.critical_text_limit = 1  # type: ignore[misc]


class CriticalProjectionTests(unittest.TestCase):
    def test_utf8_clip_respects_byte_limit(self) -> None:
        services = _services(critical_text_limit=8)
        clipped = status_cmds._clip_critical("一二三", services=services)
        self.assertLessEqual(len(clipped.encode("utf-8")), 8)
        self.assertTrue(clipped.endswith("..."))

    def test_projection_remains_within_twelve_kibibytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tasks = Path(temporary)
            state_path = tasks / "critical-task" / "state.json"
            state_path.parent.mkdir()
            state_path.write_text("{}\n", encoding="utf-8")
            long_id = "x" * 1800
            state = {
                "task_id": "critical-task",
                "revision": 1,
                "coordination_requests": [
                    {
                        "request_id": f"r{index}-{long_id}",
                        "source_lane": f"source-{long_id}",
                        "target_lane": f"target-{long_id}",
                        "severity": "hard_gate",
                        "status": "open",
                        "request": long_id,
                    }
                    for index in range(8)
                ],
            }
            payload = status_cmds.critical_projection(
                SimpleNamespace(tasks=tasks), state, services=_services()
            )
        encoded = json.dumps(
            payload, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), 12 * 1024)
        self.assertEqual(payload["coordination_inbox"], [])
        self.assertFalse(payload["view_complete"])


class CommandBehaviorTests(unittest.TestCase):
    def test_resolve_resume_task_uses_validated_session_mapping(self) -> None:
        paths = object()
        services = _services(check_session_id=lambda value: f"checked-{value}")
        expected = {"task_id": "task-from-session"}
        with (
            mock.patch.object(
                status_cmds,
                "session_path",
                return_value=Path("mapping.json"),
            ) as session_path,
            mock.patch.object(
                status_cmds,
                "load_json",
                return_value={"task_id": "task-from-session"},
            ),
            mock.patch.object(
                status_cmds, "load_task", return_value=expected
            ) as load_task,
        ):
            result = status_cmds.resolve_resume_task(
                paths, None, "session", services=services
            )
        self.assertIs(result, expected)
        session_path.assert_called_once_with(paths, "checked-session")
        load_task.assert_called_once_with(paths, "task-from-session")

    def test_resume_reports_stale_checkpoint_plan_and_terminal_task(self) -> None:
        def missing_plan(paths: object, state: dict[str, object]) -> str:
            raise HarnessError("missing plan")

        services = _services(plan_digest=missing_plan)
        state = {
            "task_id": "resume-task",
            "status": "done",
            "plan_ready": True,
            "plan_sha256": "old",
        }
        with tempfile.TemporaryDirectory() as temporary:
            task_root = Path(temporary) / "resume-task"
            with (
                mock.patch.object(
                    status_cmds, "resolve_resume_task", return_value=state
                ),
                mock.patch.object(
                    status_cmds,
                    "checkpoint_matches",
                    return_value=(False, "revision mismatch"),
                ),
                mock.patch.object(status_cmds, "task_dir", return_value=task_root),
                mock.patch.object(
                    status_cmds,
                    "task_summary",
                    return_value={"task_id": "resume-task"},
                ),
                mock.patch.object(status_cmds, "emit") as emit,
            ):
                result = status_cmds.cmd_resume(
                    SimpleNamespace(task="resume-task", session_id=None, json=True),
                    object(),
                    services=services,
                )
        self.assertEqual(result, 0)
        payload = emit.call_args.args[0]
        self.assertEqual(
            payload["warnings"],
            [
                "checkpoint is stale: revision mismatch",
                "plan is not approved/current",
                "task is not active",
            ],
        )

    def test_status_critical_requires_task(self) -> None:
        with self.assertRaisesRegex(HarnessError, "requires --task"):
            status_cmds.cmd_status(
                SimpleNamespace(critical=True, task=None, legacy=False, json=True),
                object(),
                services=_services(),
            )

    def test_render_index_preserves_lock_and_write_order(self) -> None:
        paths = SimpleNamespace(index=Path("INDEX.md"))
        events: list[str] = []

        @contextlib.contextmanager
        def locked(target: object):
            self.assertIs(target, paths)
            events.append("lock-enter")
            yield
            events.append("lock-exit")

        def write(target: object) -> None:
            self.assertIs(target, paths)
            events.append("write")

        with (
            mock.patch.object(status_cmds, "state_lock", side_effect=locked),
            mock.patch.object(status_cmds, "write_index", side_effect=write),
            mock.patch.object(status_cmds, "emit") as emit,
        ):
            result = status_cmds.cmd_render_index(
                SimpleNamespace(json=True), paths
            )
        self.assertEqual(result, 0)
        self.assertEqual(events, ["lock-enter", "write", "lock-exit"])
        emit.assert_called_once_with({"index": "INDEX.md"}, True)


if __name__ == "__main__":
    unittest.main()
