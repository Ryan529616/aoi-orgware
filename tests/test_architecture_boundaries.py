#!/usr/bin/env python3
"""Small ratchets that keep command extraction moving in one direction."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src" / "aoi_orgware"

ALLOWED_CLI_COMMAND_DEFINITIONS = frozenset(
    {
        "cmd_add_verification",
        "cmd_block_task",
        "cmd_cancel_task",
        "cmd_claude_init",
        "cmd_close_task",
        "cmd_codex_init",
        "cmd_create_packet",
        "cmd_doctor",
        "cmd_init",
        "cmd_job_start",
        "cmd_job_update",
        "cmd_materialize_artifacts",
        "cmd_packet_arm",
        "cmd_packet_attest_result",
        "cmd_packet_disarm",
        "cmd_packet_input_recover_from_tar",
        "cmd_packet_update",
        "cmd_reconcile",
        "cmd_set_delivery",
        "cmd_subagent_incident_account",
        "cmd_verification_supersede",
        "cmd_verification_supersession_seal",
    }
)


def _cli_import_lines(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name == "aoi_orgware.cli"
                or alias.name.startswith("aoi_orgware.cli.")
                for alias in node.names
            ):
                violations.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if (
                module in {"cli", "aoi_orgware.cli"}
                or module.startswith("aoi_orgware.cli.")
                or any(alias.name == "cli" for alias in node.names)
            ):
                violations.append(node.lineno)
    return violations


class CommandImportBoundaryTests(unittest.TestCase):
    def test_every_command_module_is_independent_of_cli(self) -> None:
        violations: list[str] = []
        for path in sorted((SRC / "commands").glob("*.py")):
            violations.extend(
                f"{path.relative_to(SRC)}:{line}"
                for line in _cli_import_lines(path)
            )
        self.assertEqual(violations, [])


class CliCommandBodyRatchetTests(unittest.TestCase):
    def test_cli_command_definition_allowlist_does_not_grow(self) -> None:
        path = SRC / "cli.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        actual = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("cmd_")
        }
        self.assertEqual(actual, ALLOWED_CLI_COMMAND_DEFINITIONS)


if __name__ == "__main__":
    unittest.main()
