#!/usr/bin/env python3
"""Fast contract tests for extracted resource-governance boundaries."""

from __future__ import annotations

import argparse
import ast
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import resource_governance as rg  # noqa: E402
from aoi_orgware.commands.resource import register_resource_commands  # noqa: E402
from aoi_orgware.harnesslib import HarnessError, get_paths  # noqa: E402
from aoi_orgware.resource_config import (  # noqa: E402
    AOI_MAX_DELEGATION_DEPTH,
    ARISE_MAX_THREADS_CEILING,
)


def make_policy(
    role_tier_map: dict[str, str] | None = None,
    executing_packet_statuses: set[str] | None = None,
) -> rg.ResourceGovernancePolicy:
    return rg.ResourceGovernancePolicy(
        role_tier_map=role_tier_map
        or {
            "batch": "economy",
            "explorer": "standard",
            "worker": "standard",
        },
        depth_two_roles={"batch", "explorer", "worker"},
        executing_packet_statuses=executing_packet_statuses
        or {"armed", "dispatched", "running"},
        override_target_kinds={"execution_resource", "resource_config"},
        override_statuses={"pending", "approved", "consumed", "rejected"},
        resource_config_event_statuses={"applied", "rolled_back"},
        default_parallel_agents=4,
    )


class ResourceGovernancePolicyTests(unittest.TestCase):
    def test_policy_snapshots_mutable_inputs(self) -> None:
        roles = {"explorer": "standard"}
        executing = {"armed"}
        policy = make_policy(roles, executing)

        roles["explorer"] = "deep"
        executing.add("running")

        self.assertEqual(policy.role_tier_map["explorer"], "standard")
        self.assertEqual(policy.executing_packet_statuses, frozenset({"armed"}))
        with self.assertRaises(TypeError):
            policy.role_tier_map["worker"] = "standard"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "parallel agent count"):
            rg.ResourceGovernancePolicy(
                role_tier_map={},
                depth_two_roles=set(),
                executing_packet_statuses=set(),
                override_target_kinds=set(),
                override_statuses=set(),
                resource_config_event_statuses=set(),
                default_parallel_agents=0,
            )

    def test_domain_builds_envelope_without_cli_import(self) -> None:
        policy = make_policy()
        lanes = [
            {"lane_id": "analysis", "role": "explorer"},
            {"lane_id": "implementation", "role": "worker"},
        ]
        envelope, digest = rg.build_execution_resource_envelope(
            mode="centralized_parallel",
            lanes=lanes,
            steward=None,
            override_id="bounded-resource-change",
            override_settings={
                "envelope.max_active_first_level_agents": 2,
                "envelope.max_active_total_agents": 3,
                "agents.explorer.model_reasoning_effort": "high",
            },
            policy=policy,
        )

        self.assertEqual(envelope["max_active_first_level_agents"], 2)
        self.assertEqual(envelope["max_active_total_agents"], 3)
        self.assertEqual(
            envelope["role_config_overrides"],
            {"agents.explorer.model_reasoning_effort": "high"},
        )
        self.assertEqual(len(digest), 64)
        with self.assertRaisesRegex(HarnessError, "unselected role"):
            rg.build_execution_resource_envelope(
                mode="centralized_parallel",
                lanes=lanes,
                steward=None,
                override_id="bad-role",
                override_settings={"agents.reviewer.model": "gpt-test"},
                policy=policy,
            )


def resource_event(
    event_id: str,
    applied_at: str,
    *,
    rollback_at: str | None = None,
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "applied_at": applied_at,
        "status": "rolled_back" if rollback_at is not None else "applied",
        "rollback": (
            {
                "recorded_at": rollback_at,
                "reason": "bounded regression rollback",
                "root_session_id": "session",
            }
            if rollback_at is not None
            else None
        ),
    }


class ResourceTransitionReplayTests(unittest.TestCase):
    def state(self, *events: dict[str, object]) -> dict[str, object]:
        return {"resource_config_events": list(events)}

    def test_replay_validates_nested_lifo_history_and_current_event(self) -> None:
        state = self.state(
            resource_event(
                "a", "2026-07-18T00:00:01+00:00", rollback_at="2026-07-18T00:00:04+00:00"
            ),
            resource_event(
                "b", "2026-07-18T00:00:02+00:00", rollback_at="2026-07-18T00:00:03+00:00"
            ),
        )

        replay = rg.replay_resource_transitions(state)

        self.assertIsNone(replay.current_event)
        self.assertEqual(len(replay.transitions), 4)
        self.assertEqual(
            replay.latest_transition_at.isoformat(), "2026-07-18T00:00:04+00:00"
        )
        self.assertEqual(
            rg.applied_resource_event_at(state, "2026-07-18T00:00:02.500000+00:00")["event_id"],
            "b",
        )
        self.assertEqual(
            rg.applied_resource_event_at(state, "2026-07-18T00:00:03.500000+00:00")["event_id"],
            "a",
        )
        self.assertIsNone(
            rg.applied_resource_event_at(state, "2026-07-18T00:00:04.500000+00:00")
        )

    def test_replay_rejects_reversed_apply_order(self) -> None:
        state = self.state(
            resource_event("a", "2026-07-18T00:00:02+00:00"),
            resource_event("b", "2026-07-18T00:00:01+00:00"),
        )

        with self.assertRaisesRegex(HarnessError, "follow event append order"):
            rg.replay_resource_transitions(state)

    def test_replay_rejects_equal_absolute_transition_instants(self) -> None:
        state = self.state(
            resource_event("a", "2026-07-18T08:00:01+08:00"),
            resource_event("b", "2026-07-18T00:00:01+00:00"),
        )

        with self.assertRaisesRegex(HarnessError, "not unique"):
            rg.replay_resource_transitions(state)

    def test_replay_rejects_naive_transition_time(self) -> None:
        with self.assertRaisesRegex(HarnessError, "timezone-aware"):
            rg.replay_resource_transitions(
                self.state(resource_event("a", "2026-07-18T00:00:01"))
            )

    def test_replay_rejects_non_lifo_rollback(self) -> None:
        state = self.state(
            resource_event(
                "a", "2026-07-18T00:00:01+00:00", rollback_at="2026-07-18T00:00:03+00:00"
            ),
            resource_event("b", "2026-07-18T00:00:02+00:00"),
        )

        with self.assertRaisesRegex(HarnessError, "current stack top"):
            rg.replay_resource_transitions(state)

    def test_observation_requires_a_strictly_between_transition_instant(self) -> None:
        state = self.state(
            resource_event(
                "a", "2026-07-18T00:00:01+00:00", rollback_at="2026-07-18T00:00:03+00:00"
            )
        )

        with self.assertRaisesRegex(HarnessError, "coincides with a resource transition"):
            rg.applied_resource_event_at(state, "2026-07-18T00:00:01+00:00")
        with self.assertRaisesRegex(HarnessError, "coincides with a resource transition"):
            rg.applied_resource_event_at(state, "2026-07-18T00:00:03+00:00")
        with self.assertRaisesRegex(HarnessError, "observation time is invalid"):
            rg.applied_resource_event_at(state, "2026-07-18T00:00:02")

    def test_integrity_errors_include_replay_failure(self) -> None:
        state = self.state(resource_event("a", "2026-07-18T00:00:01"))
        state.update({"task_id": "timeline-test", "session_ids": []})

        errors = rg.resource_config_integrity_errors(
            get_paths(REPO), state, policy=make_policy()
        )

        self.assertTrue(any("timezone-aware" in error for error in errors))

    def test_integrity_errors_report_malformed_event_without_traceback(self) -> None:
        state: dict[str, object] = {
            "task_id": "timeline-test",
            "session_ids": [],
            "resource_config_events": [None],
        }

        errors = rg.resource_config_integrity_errors(
            get_paths(REPO), state, policy=make_policy()
        )

        self.assertTrue(
            any("event at index 0 must be an object" in error for error in errors),
            errors,
        )


class ResourceCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "override_request",
        "override_arbitrate",
        "override_revoke",
        "codex_config_plan",
        "codex_config_apply",
        "codex_config_rollback",
        "codex_session_register",
        "codex_startup_receipt_show",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_resource_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
        )
        return parser, handlers

    def test_registry_injects_handlers_and_preserves_resource_defaults(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "codex-config-plan",
                "--task",
                "task",
                "--event-id",
                "event",
                "--role",
                "explorer",
                "--json",
            ]
        )

        self.assertIs(args.handler, handlers["codex_config_plan"])
        self.assertEqual(args.max_threads, ARISE_MAX_THREADS_CEILING)
        self.assertEqual(args.max_depth, AOI_MAX_DELEGATION_DEPTH)
        self.assertEqual(args.role, ["explorer"])
        self.assertTrue(args.json)

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_resource_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
            )


class ImportBoundaryTests(unittest.TestCase):
    def test_extracted_modules_do_not_depend_on_monolithic_cli(self) -> None:
        paths = [
            SRC / "aoi_orgware" / "resource_governance.py",
            SRC / "aoi_orgware" / "commands" / "resource.py",
        ]
        violations: list[str] = []
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
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


if __name__ == "__main__":
    unittest.main()
