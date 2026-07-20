#!/usr/bin/env python3
"""Fast contract tests for extracted parser-registrar modules.

Each parser domain lifted out of the monolithic ``cli`` into ``commands/`` is
covered here by three checks: it never imports the monolith, its handler map is
validated, and one representative command parses its expected arguments.  The
import-boundary machinery (:data:`REGISTRAR_MODULES`,
:func:`cli_import_violations`) is deliberately generic so later extraction steps
only append a module path.
"""

from __future__ import annotations

import argparse
import ast
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware.commands.backup import register_backup_commands  # noqa: E402
from aoi_orgware.commands.capacity import register_capacity_commands  # noqa: E402
from aoi_orgware.commands.context_memory import (  # noqa: E402
    register_context_memory_commands,
)
from aoi_orgware.commands.coordination import (  # noqa: E402
    register_coordination_commands,
    register_cross_lane_commands,
)
from aoi_orgware.commands.execution_selection import (  # noqa: E402
    register_execution_selection_commands,
)
from aoi_orgware.commands.improvement import (  # noqa: E402
    register_improvement_commands,
)
from aoi_orgware.commands.jobs import register_job_commands  # noqa: E402
from aoi_orgware.commands.lanes import register_lane_commands  # noqa: E402
from aoi_orgware.commands.packets import register_packet_commands  # noqa: E402
from aoi_orgware.commands.status import register_status_commands  # noqa: E402
from aoi_orgware.commands.task_lifecycle import (  # noqa: E402
    register_bootstrap_commands,
    register_chief_commands,
    register_pilot_commands,
    register_task_lifecycle_commands,
)
from aoi_orgware.commands.verification import (  # noqa: E402
    register_verification_commands,
)


# Extracted registrar modules that must never import the monolithic CLI.
# Later extraction steps append their new module paths here.
REGISTRAR_MODULES = [
    SRC / "aoi_orgware" / "commands" / "lanes.py",
    SRC / "aoi_orgware" / "commands" / "coordination.py",
    SRC / "aoi_orgware" / "commands" / "packets.py",
    SRC / "aoi_orgware" / "commands" / "jobs.py",
    SRC / "aoi_orgware" / "commands" / "capacity.py",
    SRC / "aoi_orgware" / "commands" / "improvement.py",
    SRC / "aoi_orgware" / "commands" / "execution_selection.py",
    SRC / "aoi_orgware" / "commands" / "task_lifecycle.py",
    SRC / "aoi_orgware" / "commands" / "verification.py",
    SRC / "aoi_orgware" / "commands" / "status.py",
    SRC / "aoi_orgware" / "commands" / "backup.py",
    SRC / "aoi_orgware" / "commands" / "context_memory.py",
    SRC / "aoi_orgware" / "commands" / "resource.py",
]


def cli_import_violations(path: Path) -> list[str]:
    """Return ``file:lineno`` markers for any ``cli`` import in ``path``."""

    violations: list[str] = []
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
    return violations


class ImportBoundaryTests(unittest.TestCase):
    def test_registrar_modules_do_not_import_monolithic_cli(self) -> None:
        violations: list[str] = []
        for path in REGISTRAR_MODULES:
            violations.extend(cli_import_violations(path))
        self.assertEqual(violations, [])


def _make_vocab() -> SimpleNamespace:
    """A minimal stand-in for ``cli.ParserVocabulary`` for parser tests."""

    return SimpleNamespace(
        capability_tier_map=("c1_mechanical", "c2_routine", "c5_frontier"),
        change_classes=frozenset(
            {"genesis", "evidence_only", "semantic_change"}
        ),
        close_qualifying_categories=frozenset(
            {"unit_test", "integration_test", "static_check"}
        ),
        dependency_kinds=("hard_gate", "soft_dependency", "informational"),
        dependency_levels=("low", "medium", "high"),
        depth_two_roles=("batch", "explorer", "worker"),
        execution_modes=("single", "centralized_parallel", "hybrid"),
        improvement_option_ids=("maintain-current", "capacity", "skill-automation"),
        improvement_trigger_classes=("repeated_pain", "critical_single_incident"),
        lane_kinds=("architecture", "implementation", "verification"),
        lane_statuses=("active", "waiting", "blocked", "done"),
        needs_user_categories=("goal_change", "accuracy_budget", "cost_budget"),
        role_tier_map=("architect", "reviewer", "worker"),
        role_tier_values=frozenset({"frontier", "expert", "advanced", "standard"}),
        skill_adoption_actions=("canary", "adopt", "pause", "rollback", "deprecate"),
        tool_densities=("low", "medium", "high"),
        verification_categories=frozenset(
            {"static_check", "unit_test", "integration_test", "compile_acceptance"}
        ),
    )


class LaneCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "lane_set_status",
        "lane_create",
        "lane_revise",
        "lane_dependency_add",
        "lane_dependency_update",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_lane_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_lane_create_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "lane-create",
                "--task",
                "T1",
                "--lane-id",
                "L1",
                "--kind",
                "implementation",
                "--owner",
                "alice",
                "--role",
                "worker",
                "--authority-commit",
                "abc1234",
                "--contract-version",
                "1",
                "--next-action",
                "start",
                "--json",
            ]
        )

        self.assertIs(args.handler, handlers["lane_create"])
        # default from the moved block survives extraction
        self.assertEqual(args.status, "active")
        self.assertEqual(args.generator_version, "not_applicable")
        self.assertEqual(args.adapter_version, "not_applicable")
        self.assertTrue(args.json)

    def test_registry_uses_injected_vocab_for_status_choices(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "lane-set-status",
                "--task",
                "T1",
                "--lane-id",
                "L1",
                "--expected-revision",
                "2",
                "--expected-status",
                "active",
                "--status",
                "blocked",
                "--next-action",
                "hold",
                "--reason",
                "dep",
                "--session-id",
                "S1",
            ]
        )
        self.assertIs(args.handler, handlers["lane_set_status"])
        self.assertEqual(args.status, "blocked")

    def test_registry_rejects_out_of_vocab_choice(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "lane-dependency-add",
                    "--task",
                    "T1",
                    "--dependency-id",
                    "D1",
                    "--source-lane",
                    "L1",
                    "--target-lane",
                    "L2",
                    "--kind",
                    "not_a_kind",
                    "--reason",
                    "because",
                ]
            )

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_lane_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


class CrossLaneCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "cross_lane_open",
        "cross_lane_close",
        "cross_lane_cancel",
        "needs_user_create",
        "needs_user_resolve",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_cross_lane_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_cross_lane_open_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "cross-lane-open",
                "--task",
                "T1",
                "--cross-lane-session-id",
                "X1",
                "--execution-selection-id",
                "E1",
                "--request-id",
                "R1",
                "--steward-lane-id",
                "L1",
                "--participant-lane",
                "L2",
                "--topic",
                "sync",
                "--evidence-boundary",
                "b",
                "--expires-at",
                "2026-01-01T00:00:00Z",
                "--json",
            ]
        )
        self.assertIs(args.handler, handlers["cross_lane_open"])
        self.assertEqual(args.participant_lane, ["L2"])
        self.assertTrue(args.json)

    def test_registry_uses_injected_vocab_for_needs_user_category_choices(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "needs-user-create",
                "--task",
                "T1",
                "--escalation-id",
                "N1",
                "--category",
                "cost_budget",
                "--source-lane",
                "L1",
                "--problem",
                "p",
                "--option",
                "opt",
                "--evidence",
                "e",
                "--chief-recommendation",
                "r",
                "--session-id",
                "S1",
            ]
        )
        self.assertIs(args.handler, handlers["needs_user_create"])
        self.assertEqual(args.category, "cost_budget")

    def test_registry_rejects_out_of_vocab_needs_user_category(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "needs-user-create",
                    "--task",
                    "T1",
                    "--escalation-id",
                    "N1",
                    "--category",
                    "not_a_category",
                    "--source-lane",
                    "L1",
                    "--problem",
                    "p",
                    "--option",
                    "opt",
                    "--evidence",
                    "e",
                    "--chief-recommendation",
                    "r",
                    "--session-id",
                    "S1",
                ]
            )

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_cross_lane_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


class CoordinationCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "coordination_create",
        "coordination_update",
        "coordination_arbitrate",
        "coordination_directive_ack",
        "coordination_resolve",
        "coordination_implementation_submit",
        "coordination_verify",
        "baseline_freeze",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_coordination_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_coordination_create_args(
        self,
    ) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "coordination-create",
                "--task",
                "T1",
                "--request-id",
                "R1",
                "--source-lane",
                "L1",
                "--target-lane",
                "L2",
                "--severity",
                "hard_gate",
                "--request",
                "req",
                "--outcome",
                "out",
                "--evidence",
                "e",
                "--json",
            ]
        )
        self.assertIs(args.handler, handlers["coordination_create"])
        # defaults from the moved block survive extraction
        self.assertEqual(args.change_class, "same_contract_implementation")
        self.assertEqual(args.closure_category, "integration_test")
        self.assertTrue(args.json)

    def test_registry_uses_injected_vocab_for_closure_category_choices(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "coordination-verify",
                "--task",
                "T1",
                "--request-id",
                "R1",
                "--expected-version",
                "1",
                "--verifier-lane",
                "L1",
                "--category",
                "unit_test",
                "--status",
                "pass",
                "--test-oracle",
                "o",
                "--command",
                "c",
                "--boundary",
                "b",
                "--evidence-artifact",
                "a",
                "--evidence-sha256",
                "deadbeef",
            ]
        )
        self.assertIs(args.handler, handlers["coordination_verify"])
        self.assertEqual(args.category, "unit_test")

    def test_registry_rejects_out_of_vocab_change_class(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "coordination-create",
                    "--task",
                    "T1",
                    "--request-id",
                    "R1",
                    "--source-lane",
                    "L1",
                    "--target-lane",
                    "L2",
                    "--severity",
                    "hard_gate",
                    "--request",
                    "req",
                    "--outcome",
                    "out",
                    "--evidence",
                    "e",
                    "--change-class",
                    "genesis",
                ]
            )

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_coordination_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


class PacketCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "create_packet",
        "packet_arm",
        "packet_disarm",
        "packet_update",
        "packet_attest_result",
        "subagent_incident_account",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_packet_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_create_packet_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "create-packet",
                "--task",
                "T1",
                "--packet-id",
                "P1",
                "--agent-role",
                "worker",
                "--model-tier",
                "standard",
                "--objective",
                "obj",
                "--scope",
                "scope",
                "--deliverable",
                "d",
                "--validation",
                "v",
                "--capability-tier",
                "c2_routine",
                "--json",
            ]
        )
        self.assertIs(args.handler, handlers["create_packet"])
        # defaults from the moved block survive extraction
        self.assertEqual(args.task_type, "general")
        self.assertEqual(args.delegation_depth, 1)
        self.assertEqual(args.packet_mode, "read_only")
        self.assertTrue(args.json)

    def test_registry_uses_harnesslib_packet_statuses_minus_ready_armed(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "packet-update",
                    "--task",
                    "T1",
                    "--packet-id",
                    "P1",
                    "--status",
                    "ready",
                ]
            )

    def test_registry_accepts_packet_update_with_vocab_role_choices(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "packet-update",
                "--task",
                "T1",
                "--packet-id",
                "P1",
                "--status",
                "done",
                "--actual-role",
                "worker",
                "--actual-model-tier",
                "advanced",
            ]
        )
        self.assertIs(args.handler, handlers["packet_update"])
        self.assertEqual(args.actual_role, "worker")
        self.assertEqual(args.actual_model_tier, "advanced")

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_packet_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


class JobCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {"job_start", "job_update"}

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_job_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_job_start_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "job-start",
                "--task",
                "T1",
                "--run-id",
                "R1",
                "--host",
                "h",
                "--tool",
                "vcs",
                "--work-root",
                "/tmp/w",
                "--log",
                "/tmp/w/log",
                "--stop-condition",
                "done",
                "--source-sha",
                "abc123",
                "--source-manifest",
                "m",
                "--tool-path",
                "/opt/vcs",
                "--tool-version",
                "1.0",
                "--command",
                "vcs run",
                "--json",
            ]
        )
        self.assertIs(args.handler, handlers["job_start"])
        self.assertEqual(args.status, "queued")
        self.assertEqual(args.success_exit_code, 0)
        self.assertTrue(args.json)

    def test_registry_uses_harnesslib_job_statuses_for_job_update_choices(
        self,
    ) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "job-update",
                "--task",
                "T1",
                "--run-id",
                "R1",
                "--status",
                "pass",
                "--evidence",
                "e",
            ]
        )
        self.assertIs(args.handler, handlers["job_update"])
        self.assertEqual(args.status, "pass")

    def test_registry_rejects_out_of_vocab_job_status(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "job-update",
                    "--task",
                    "T1",
                    "--run-id",
                    "R1",
                    "--status",
                    "not_a_status",
                    "--evidence",
                    "e",
                ]
            )

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_job_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
            )


class CapacityCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "capacity_snapshot",
        "capacity_recommend",
        "capacity_arbitrate",
        "capacity_distribute",
        "capacity_ack",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_capacity_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_capacity_snapshot_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "capacity-snapshot",
                "--task",
                "T1",
                "--review-id",
                "R1",
                "--capacity-lane-id",
                "L1",
                "--target-lane-id",
                "L2",
                "--task-type",
                "batch_job",
                "--leaf-role",
                "worker",
                "--expected-lane-revision",
                "2",
                "--json",
            ]
        )
        self.assertIs(args.handler, handlers["capacity_snapshot"])
        self.assertTrue(args.json)

    def test_registry_uses_injected_vocab_for_capability_tier_choices(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "capacity-recommend",
                "--task",
                "T1",
                "--review-id",
                "R1",
                "--expected-version",
                "1",
                "--source-packet-id",
                "P1",
                "--capability-tier",
                "c2_routine",
                "--rationale",
                "r",
                "--risk",
                "low",
                "--confidence-boundary",
                "b",
                "--min-eligible-records",
                "1",
            ]
        )
        self.assertIs(args.handler, handlers["capacity_recommend"])
        self.assertEqual(args.capability_tier, "c2_routine")
        self.assertEqual(args.min_eligible_records, 1)

    def test_registry_rejects_out_of_vocab_leaf_role(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "capacity-snapshot",
                    "--task",
                    "T1",
                    "--review-id",
                    "R1",
                    "--capacity-lane-id",
                    "L1",
                    "--target-lane-id",
                    "L2",
                    "--task-type",
                    "batch_job",
                    "--leaf-role",
                    "not_a_role",
                    "--expected-lane-revision",
                    "2",
                ]
            )

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_capacity_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


class ImprovementCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "improvement_create",
        "improvement_brief",
        "improvement_arbitrate",
        "improvement_link_project",
        "skill_release_record",
        "skill_adoption_record",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_improvement_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_improvement_create_args(
        self,
    ) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "improvement-create",
                "--task",
                "T1",
                "--request-id",
                "N1",
                "--source-lane",
                "L1",
                "--task-type",
                "batch_job",
                "--trigger-class",
                "repeated_pain",
                "--pain-statement",
                "p",
                "--desired-outcome",
                "o",
                "--occurrence",
                "e1",
                "--json",
            ]
        )
        self.assertIs(args.handler, handlers["improvement_create"])
        self.assertFalse(args.release_blocking)
        self.assertTrue(args.json)

    def test_registry_uses_injected_vocab_for_skill_adoption_action_choices(
        self,
    ) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "skill-adoption-record",
                "--task",
                "T1",
                "--request-id",
                "N1",
                "--expected-version",
                "1",
                "--release-id",
                "REL1",
                "--action",
                "canary",
                "--session-id",
                "S1",
                "--evidence-artifact",
                "a",
                "--evidence-sha256",
                "deadbeef",
                "--rationale",
                "r",
            ]
        )
        self.assertIs(args.handler, handlers["skill_adoption_record"])
        self.assertEqual(args.action, "canary")

    def test_registry_rejects_out_of_vocab_trigger_class(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "improvement-create",
                    "--task",
                    "T1",
                    "--request-id",
                    "N1",
                    "--source-lane",
                    "L1",
                    "--task-type",
                    "batch_job",
                    "--trigger-class",
                    "not_a_trigger",
                    "--pain-statement",
                    "p",
                    "--desired-outcome",
                    "o",
                    "--occurrence",
                    "e1",
                ]
            )

    def test_registry_accepts_skill_release_record_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "skill-release-record",
                "--task",
                "T1",
                "--request-id",
                "N1",
                "--expected-version",
                "1",
                "--release-id",
                "REL1",
                "--skill-id",
                "SK1",
                "--skill-version",
                "1.0",
                "--maintenance-owner",
                "alice",
                "--rollback-plan",
                "plan",
                "--bundle",
                "b.tar",
                "--bundle-sha256",
                "deadbeef",
                "--manifest",
                "m.json",
                "--manifest-sha256",
                "deadbeef",
                "--validation-receipt",
                "v.json",
                "--validation-receipt-sha256",
                "deadbeef",
            ]
        )
        self.assertIs(args.handler, handlers["skill_release_record"])

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_improvement_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


class ExecutionSelectionCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "execution_select_plan",
        "execution_select",
        "execution_brief_record",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}

        def add_json_argument(command: argparse.ArgumentParser) -> None:
            command.add_argument("--json", action="store_true")

        register_execution_selection_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=add_json_argument,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def _base_execution_select_args(self) -> list[str]:
        return [
            "--task",
            "T1",
            "--selection-id",
            "E1",
            "--work-unit-id",
            "W1",
            "--mode",
            "single",
            "--lane",
            "L1",
            "--scope",
            "s",
            "--sequential-dependency",
            "low",
            "--tool-density",
            "medium",
            "--shared-context",
            "low",
            "--rationale",
            "r",
            "--falsification-condition",
            "f",
            "--escalation-condition",
            "e",
            "--session-id",
            "S1",
        ]

    def test_registry_injects_handler_and_accepts_execution_select_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            ["execution-select", *self._base_execution_select_args(), "--json"]
        )
        self.assertIs(args.handler, handlers["execution_select"])
        self.assertEqual(args.override_id, "")
        self.assertTrue(args.json)

    def test_registry_requires_override_id_for_execution_select_plan(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "execution-select-plan",
                    *self._base_execution_select_args(),
                    "--proposed-setting",
                    "x=1",
                ]
            )

    def test_registry_accepts_execution_select_plan_with_override_id(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "execution-select-plan",
                *self._base_execution_select_args(),
                "--override-id",
                "OV1",
                "--proposed-setting",
                "x=1",
            ]
        )
        self.assertIs(args.handler, handlers["execution_select_plan"])
        self.assertEqual(args.override_id, "OV1")
        self.assertEqual(args.proposed_setting, ["x=1"])

    def test_registry_rejects_out_of_vocab_mode(self) -> None:
        parser, _ = self.parser()
        args = self._base_execution_select_args()
        mode_index = args.index("--mode") + 1
        args[mode_index] = "not_a_mode"
        with self.assertRaises(SystemExit):
            parser.parse_args(["execution-select", *args])

    def test_registry_accepts_execution_brief_record_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "execution-brief-record",
                "--task",
                "T1",
                "--brief-id",
                "B1",
                "--execution-selection-id",
                "E1",
                "--steward-lane-id",
                "L1",
                "--packet-id",
                "P1",
                "--summary",
                "s",
                "--dissent",
                "d",
                "--blocker",
                "b",
                "--recommendation",
                "r",
                "--session-id",
                "S1",
            ]
        )
        self.assertIs(args.handler, handlers["execution_brief_record"])

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_execution_selection_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=lambda _parser: None,
                vocab=_make_vocab(),
            )


def _add_json(command: argparse.ArgumentParser) -> None:
    command.add_argument("--json", action="store_true")


class BootstrapCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {"init", "config_check"}

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_bootstrap_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_init_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["init", "--project-name", "demo", "--json"])
        self.assertIs(args.handler, handlers["init"])
        self.assertTrue(args.json)

    def test_registry_accepts_config_check_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["config-check", "--file", "aoi.toml"])
        self.assertIs(args.handler, handlers["config_check"])

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_bootstrap_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


class ChiefCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "chief_acquire",
        "chief_renew",
        "chief_release",
        "chief_takeover",
        "chief_status",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_chief_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_chief_acquire_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["chief-acquire", "--session-id", "S1"])
        self.assertIs(args.handler, handlers["chief_acquire"])
        # default TTL from the moved block survives extraction
        self.assertEqual(args.ttl_seconds, 60 * 60)

    def test_registry_accepts_chief_takeover_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "chief-takeover",
                "--session-id",
                "S1",
                "--expected-epoch",
                "2",
                "--reason",
                "expired",
                "--force-live",
            ]
        )
        self.assertIs(args.handler, handlers["chief_takeover"])
        self.assertTrue(args.force_live)

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_chief_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


class PilotCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {"pilot_init", "pilot_validate", "pilot_summary"}

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_pilot_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_pilot_init_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["pilot-init", "--output", "out/", "--force"])
        self.assertIs(args.handler, handlers["pilot_init"])
        self.assertTrue(args.force)

    def test_registry_accepts_pilot_summary_format_choice(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "pilot-summary",
                "--record",
                "r1.json",
                "--output",
                "out.csv",
                "--format",
                "csv",
            ]
        )
        self.assertIs(args.handler, handlers["pilot_summary"])
        self.assertEqual(args.format, "csv")

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_pilot_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


class TaskLifecycleCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "init_task",
        "start_mini",
        "finish_mini",
        "approve_plan",
        "plan_update",
        "bind_session",
        "unbind_session",
        "import_legacy",
        "check_locks",
        "inspect_legacy",
        "claim",
        "set_claim_status",
        "release_claim",
        "audit_legacy",
        "set_phase",
        "adopt_current_branch",
        "checkpoint",
        "retarget_task",
        "retire_risk",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_task_lifecycle_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_init_task_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "init-task",
                "--task-id",
                "T1",
                "--title",
                "title",
                "--objective",
                "obj",
                "--owner",
                "alice",
                "--completion-boundary",
                "cb",
            ]
        )
        self.assertIs(args.handler, handlers["init_task"])

    def test_registry_injects_handler_and_accepts_finish_mini_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "finish-mini",
                "--task",
                "T1",
                "--mode",
                "local-only",
                "--detail",
                "bounded local delivery",
                "--summary",
                "verified mini task complete",
            ]
        )
        self.assertIs(args.handler, handlers["finish_mini"])
        self.assertEqual(args.mode, "local-only")

    def test_registry_injects_handler_and_requires_plan_update_cas_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "plan-update", "--task", "T1", "--source", "C:/candidate.md",
                "--expected-source-sha256", "a" * 64,
                "--expected-current-plan-sha256", "b" * 64,
                "--reason", "replace stale plan",
            ]
        )
        self.assertIs(args.handler, handlers["plan_update"])

    def test_registry_uses_injected_vocab_for_claim_status_choices(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "set-claim-status",
                "--token",
                "TOK1",
                "--status",
                "active",
                "--reason",
                "r",
            ]
        )
        self.assertIs(args.handler, handlers["set_claim_status"])
        self.assertEqual(args.status, "active")

    def test_registry_rejects_out_of_vocab_release_claim_status(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "release-claim",
                    "--token",
                    "TOK1",
                    "--status",
                    "active",
                    "--reason",
                    "r",
                ]
            )

    def test_registry_rejects_out_of_vocab_phase(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "set-phase",
                    "--task",
                    "T1",
                    "--phase",
                    "not_a_phase",
                ]
            )

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_task_lifecycle_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


class VerificationCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "reconcile",
        "add_verification",
        "materialize_artifacts",
        "packet_input_recover_from_tar",
        "verification_supersede",
        "verification_supersession_seal",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_verification_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
            vocab=_make_vocab(),
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_add_verification_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "add-verification",
                "--task",
                "T1",
                "--category",
                "unit_test",
                "--status",
                "pass",
                "--evidence",
                "e",
                "--command",
                "cmd",
                "--boundary",
                "b",
            ]
        )
        self.assertIs(args.handler, handlers["add_verification"])
        self.assertEqual(args.category, "unit_test")

    def test_registry_rejects_out_of_vocab_category(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "add-verification",
                    "--task",
                    "T1",
                    "--category",
                    "not_a_category",
                    "--status",
                    "pass",
                    "--evidence",
                    "e",
                    "--command",
                    "cmd",
                    "--boundary",
                    "b",
                ]
            )

    def test_registry_rejects_out_of_vocab_status(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "add-verification",
                    "--task",
                    "T1",
                    "--category",
                    "unit_test",
                    "--status",
                    "not_a_status",
                    "--evidence",
                    "e",
                    "--command",
                    "cmd",
                    "--boundary",
                    "b",
                ]
            )

    def test_registry_accepts_verification_supersession_seal_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "verification-supersession-seal",
                "--task",
                "T1",
                "--verification-index",
                "1",
                "--expected-current-record-sha256",
                "deadbeef",
                "--expected-source-record-sha256",
                "deadbeef",
                "--replacement-index",
                "2",
                "--expected-replacement-before-materialize-sha256",
                "deadbeef",
                "--expected-replacement-current-sha256",
                "deadbeef",
            ]
        )
        self.assertIs(args.handler, handlers["verification_supersession_seal"])

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_verification_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
                vocab=_make_vocab(),
            )


class StatusCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {"resume", "status", "render_index"}

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_status_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_resume_task(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["resume", "--task", "T1"])
        self.assertIs(args.handler, handlers["resume"])

    def test_registry_resume_requires_mutually_exclusive_group(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["resume"])

    def test_registry_rejects_resume_with_both_task_and_session(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["resume", "--task", "T1", "--session-id", "S1"]
            )

    def test_registry_accepts_status_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["status", "--critical"])
        self.assertIs(args.handler, handlers["status"])
        self.assertTrue(args.critical)

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_status_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


class BackupCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {"backup_state", "verify_backup"}

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_backup_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_backup_state_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(["backup-state", "--destination", "/tmp/b"])
        self.assertIs(args.handler, handlers["backup_state"])

    def test_registry_verify_backup_requires_manifest(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["verify-backup"])

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_backup_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


class ContextMemoryCommandRegistryTests(unittest.TestCase):
    HANDLER_NAMES = {
        "context_receipt_record",
        "codebase_memory_benchmark_validate",
        "codebase_memory_benchmark_record",
    }

    def parser(self) -> tuple[argparse.ArgumentParser, dict[str, object]]:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        handlers = {name: object() for name in self.HANDLER_NAMES}
        register_context_memory_commands(
            subparsers,
            handlers=handlers,  # type: ignore[arg-type]
            add_json_argument=_add_json,
        )
        return parser, handlers

    def test_registry_injects_handler_and_accepts_context_receipt_record_args(
        self,
    ) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "context-receipt-record",
                "--task",
                "T1",
                "--provider",
                "codebase-memory",
                "--receipt-id",
                "R1",
                "--receipt",
                "payload",
                "--receipt-sha256",
                "deadbeef",
                "--session-id",
                "S1",
            ]
        )
        self.assertIs(args.handler, handlers["context_receipt_record"])
        # defaults from the moved block survive extraction
        self.assertEqual(args.requirement, "optional")
        self.assertEqual(args.freshness_profile, "receipt-only")

    def test_registry_rejects_out_of_vocab_freshness_profile(self) -> None:
        parser, _ = self.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "context-receipt-record",
                    "--task",
                    "T1",
                    "--provider",
                    "codebase-memory",
                    "--receipt-id",
                    "R1",
                    "--receipt",
                    "payload",
                    "--receipt-sha256",
                    "deadbeef",
                    "--session-id",
                    "S1",
                    "--freshness-profile",
                    "not_a_profile",
                ]
            )

    def test_registry_accepts_codebase_memory_benchmark_record_args(self) -> None:
        parser, handlers = self.parser()
        args = parser.parse_args(
            [
                "codebase-memory-benchmark-record",
                "--task",
                "T1",
                "--benchmark-id",
                "B1",
                "--receipt-id",
                "R1",
                "--record",
                "rec1.json",
                "--record-sha256",
                "deadbeef",
                "--session-id",
                "S1",
            ]
        )
        self.assertIs(args.handler, handlers["codebase_memory_benchmark_record"])

    def test_registry_rejects_incomplete_or_extra_handler_maps(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        with self.assertRaisesRegex(ValueError, "handler map mismatch"):
            register_context_memory_commands(
                subparsers,
                handlers={"unexpected": object()},  # type: ignore[dict-item]
                add_json_argument=_add_json,
            )


if __name__ == "__main__":
    unittest.main()
