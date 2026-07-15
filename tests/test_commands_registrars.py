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

from aoi_orgware.commands.lanes import register_lane_commands  # noqa: E402


# Extracted registrar modules that must never import the monolithic CLI.
# Later extraction steps append their new module paths here.
REGISTRAR_MODULES = [
    SRC / "aoi_orgware" / "commands" / "lanes.py",
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
    """A minimal stand-in for ``cli.ParserVocabulary`` for lane parsing."""

    return SimpleNamespace(
        change_classes=frozenset(
            {"genesis", "evidence_only", "semantic_change"}
        ),
        dependency_kinds=("hard_gate", "soft_dependency", "informational"),
        lane_kinds=("architecture", "implementation", "verification"),
        lane_statuses=("active", "waiting", "blocked", "done"),
        role_tier_map=("architect", "reviewer", "worker"),
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


if __name__ == "__main__":
    unittest.main()
