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

from aoi_orgware.commands.coordination import (  # noqa: E402
    register_coordination_commands,
    register_cross_lane_commands,
)
from aoi_orgware.commands.jobs import register_job_commands  # noqa: E402
from aoi_orgware.commands.lanes import register_lane_commands  # noqa: E402
from aoi_orgware.commands.packets import register_packet_commands  # noqa: E402


# Extracted registrar modules that must never import the monolithic CLI.
# Later extraction steps append their new module paths here.
REGISTRAR_MODULES = [
    SRC / "aoi_orgware" / "commands" / "lanes.py",
    SRC / "aoi_orgware" / "commands" / "coordination.py",
    SRC / "aoi_orgware" / "commands" / "packets.py",
    SRC / "aoi_orgware" / "commands" / "jobs.py",
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
        lane_kinds=("architecture", "implementation", "verification"),
        lane_statuses=("active", "waiting", "blocked", "done"),
        needs_user_categories=("goal_change", "accuracy_budget", "cost_budget"),
        role_tier_map=("architect", "reviewer", "worker"),
        role_tier_values=frozenset({"frontier", "expert", "advanced", "standard"}),
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


if __name__ == "__main__":
    unittest.main()
