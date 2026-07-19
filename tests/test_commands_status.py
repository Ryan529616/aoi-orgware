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

    def test_projection_rejects_malformed_incident_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tasks = Path(temporary)
            state_path = tasks / "critical-malformed-incidents" / "state.json"
            state_path.parent.mkdir()
            state_path.write_text("{}\n", encoding="utf-8")
            for malformed, expected_error in (
                (None, "subagent incidents must be an array"),
                (7, "subagent incidents must be an array"),
                ({"not": "an array"}, "subagent incidents must be an array"),
                ([None], "spawn incident record is malformed"),
            ):
                with self.subTest(malformed=repr(malformed)):
                    with self.assertRaisesRegex(
                        HarnessError, f"^{expected_error}$"
                    ):
                        status_cmds.critical_projection(
                            SimpleNamespace(tasks=tasks),
                            {
                                "task_id": "critical-malformed-incidents",
                                "subagent_incidents": malformed,
                            },
                            services=_services(),
                        )


class CommandBehaviorTests(unittest.TestCase):
    SEMANTIC_SHA_1 = "a" * 64
    SEMANTIC_SHA_2 = "b" * 64

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

    def test_status_json_without_since_preserves_machine_payload(self) -> None:
        task = {"task_id": "task-a"}
        structured = {
            "token": "active-claim",
            "task_id": "task-a",
            "owner": "owner",
            "status": "active",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "locks": ["repo:file:one.py"],
        }
        legacy = {
            "legacy": True,
            "token": "legacy-claim",
            "status": "active",
            "legacy_classification": "expired_unverified",
        }
        with (
            mock.patch.object(status_cmds, "require_complete_layout"),
            mock.patch.object(status_cmds, "load_all_tasks", return_value=[task]),
            mock.patch.object(
                status_cmds, "load_all_claims", return_value=[structured, legacy]
            ),
            mock.patch.object(
                status_cmds,
                "chief_authority_summary",
                return_value={"status": "active"},
            ),
            mock.patch.object(
                status_cmds, "task_summary", return_value={"task_id": "task-a"}
            ),
            mock.patch.object(status_cmds, "emit") as emit,
        ):
            result = status_cmds.cmd_status(
                SimpleNamespace(
                    critical=False, task=None, legacy=False, json=True, since=None
                ),
                SimpleNamespace(root=Path("root")),
                services=_services(),
            )
        self.assertEqual(result, 0)
        emit.assert_called_once_with(
            {
                "root": "root",
                "chief_authority": {"status": "active"},
                "tasks": [{"task_id": "task-a"}],
                "structured_claims": [
                    {
                        "token": "active-claim",
                        "task_id": "task-a",
                        "owner": "owner",
                        "status": "active",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "expired_still_reserved": False,
                        "locks": ["repo:file:one.py"],
                    }
                ],
                "legacy_pending_count": 1,
                "legacy_expired_unverified_count": 1,
            },
            True,
        )

    def test_bare_status_renders_compact_human_summary(self) -> None:
        state = {
            "task_id": "task-a",
            "status": "active",
            "profile": "full",
            "phase": "implementing",
            "revision": 4,
            "owner": "root-owner",
            "packets": [{"packet_id": "packet-a", "status": "queued"}],
            "jobs": [{"run_id": "job-a", "status": "running"}],
            "needs_user_escalations": [
                {"escalation_id": "ask-user", "status": "needs_user"}
            ],
            "lanes": [{"lane_id": "lane-a", "status": "blocked"}],
            "verification": [
                {
                    "category": "unit_test",
                    "boundary": "Focused status tests passed\nsecondary detail",
                }
            ],
            "risks": ["Runtime delivery remains unobserved"],
            "next_action": "resolve the gate",
        }
        claims = [
            {
                "task_id": "task-a",
                "token": "active-claim",
                "owner": "owner",
                "status": "active",
                "expires_at": "2099-01-01T00:00:00+00:00",
            },
            {
                "task_id": "task-a",
                "token": "stale-claim",
                "owner": "owner",
                "status": "active",
                "expires_at": "2000-01-01T00:00:00+00:00",
            },
        ]
        with (
            mock.patch.object(
                status_cmds,
                "chief_authority_summary",
                return_value={
                    "status": "active",
                    "session_id": "chief-session",
                    "epoch": 3,
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            ),
            mock.patch.object(status_cmds, "is_semantic_v2_task", return_value=False),
            mock.patch.object(
                status_cmds,
                "checkpoint_matches",
                return_value=(False, "checkpoint revision differs from state revision"),
            ),
        ):
            rendered = status_cmds._render_human_status(object(), [state], claims)
        self.assertIn("Chief: active", rendered)
        self.assertIn(
            "Task task-a: active profile=full phase=implementing revision=4 owner=root-owner",
            rendered,
        )
        self.assertIn("semantic-head: unavailable", rendered)
        self.assertIn("claims: active=1", rendered)
        self.assertIn("stale=1", rendered)
        self.assertIn("job:job-a", rendered)
        self.assertIn("needs-user: ask-user", rendered)
        self.assertIn("blocked: lane-a", rendered)
        self.assertIn("checkpoint revision differs from state revision", rendered)
        self.assertIn("evidence: unit_test: Focused status tests passed", rendered)
        self.assertIn("risks: Runtime delivery remains unobserved", rendered)
        self.assertNotIn('"task_id"', rendered)

    def test_bare_global_status_omits_terminal_tasks_but_json_contract_keeps_them(self) -> None:
        active = {"task_id": "active-task", "status": "active", "revision": 1}
        done = {"task_id": "done-task", "status": "done", "revision": 2}
        with (
            mock.patch.object(status_cmds, "require_complete_layout"),
            mock.patch.object(status_cmds, "load_all_tasks", return_value=[active, done]),
            mock.patch.object(status_cmds, "load_all_claims", return_value=[]),
            mock.patch.object(
                status_cmds, "chief_authority_summary", return_value={"status": "active"}
            ),
            mock.patch.object(status_cmds, "is_semantic_v2_task", return_value=False),
            mock.patch.object(
                status_cmds, "checkpoint_matches", return_value=(False, "not recorded")
            ),
            mock.patch.object(status_cmds, "emit") as emit,
        ):
            status_cmds.cmd_status(
                SimpleNamespace(
                    critical=False, task=None, legacy=False, json=False, since=None
                ),
                SimpleNamespace(root=Path("root")),
                services=_services(),
            )
        rendered = emit.call_args.args[0]
        self.assertIn("Task active-task:", rendered)
        self.assertNotIn("Task done-task:", rendered)
        self.assertIn("terminal tasks omitted: 1", rendered)

    def test_status_since_current_head_returns_empty_delta_and_cursor(self) -> None:
        events = [
            {
                "sequence": 1,
                "event_sha256": self.SEMANTIC_SHA_1,
                "event_type": "genesis",
                "command_id": "genesis-command",
            },
            {
                "sequence": 2,
                "event_sha256": self.SEMANTIC_SHA_2,
                "event_type": "advance",
                "command_id": "advance-command",
            },
        ]
        with (
            mock.patch.object(
                status_cmds, "load_task", return_value={"task_id": "semantic-task"}
            ),
            mock.patch.object(status_cmds, "is_semantic_v2_task", return_value=True),
            mock.patch.object(status_cmds, "load_semantic_events", return_value=events),
            mock.patch.object(status_cmds, "emit") as emit,
        ):
            result = status_cmds.cmd_status(
                SimpleNamespace(
                    critical=False,
                    task="semantic-task",
                    legacy=False,
                    json=True,
                    since=f"2:{self.SEMANTIC_SHA_2}",
                ),
                object(),
                services=_services(),
            )
        self.assertEqual(result, 0)
        emit.assert_called_once_with(
            {
                "task_id": "semantic-task",
                "events": [],
                "next_cursor": f"2:{self.SEMANTIC_SHA_2}",
            },
            True,
        )

    def test_status_since_rejects_malformed_or_unknown_cursor(self) -> None:
        events = [
            {
                "sequence": 1,
                "event_sha256": self.SEMANTIC_SHA_1,
                "event_type": "genesis",
                "command_id": "genesis-command",
            }
        ]
        args = SimpleNamespace(
            critical=False,
            task="semantic-task",
            legacy=False,
            json=True,
            since="not-a-cursor",
        )
        with (
            mock.patch.object(
                status_cmds, "load_task", return_value={"task_id": "semantic-task"}
            ),
            mock.patch.object(status_cmds, "is_semantic_v2_task", return_value=True),
            mock.patch.object(status_cmds, "load_semantic_events", return_value=events),
            mock.patch.object(status_cmds, "emit") as emit,
        ):
            with self.assertRaisesRegex(HarnessError, "malformed"):
                status_cmds.cmd_status(args, object(), services=_services())
            args.since = f"2:{self.SEMANTIC_SHA_2}"
            with self.assertRaisesRegex(HarnessError, "unknown"):
                status_cmds.cmd_status(args, object(), services=_services())
        emit.assert_not_called()

    def test_status_since_is_unavailable_for_legacy_task(self) -> None:
        with (
            mock.patch.object(
                status_cmds, "load_task", return_value={"task_id": "legacy-task"}
            ),
            mock.patch.object(status_cmds, "is_semantic_v2_task", return_value=False),
            mock.patch.object(status_cmds, "load_semantic_events") as events,
        ):
            with self.assertRaisesRegex(HarnessError, "unavailable for legacy"):
                status_cmds.cmd_status(
                    SimpleNamespace(
                        critical=False,
                        task="legacy-task",
                        legacy=False,
                        json=True,
                        since=f"1:{self.SEMANTIC_SHA_1}",
                    ),
                    object(),
                    services=_services(),
                )
        events.assert_not_called()

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
