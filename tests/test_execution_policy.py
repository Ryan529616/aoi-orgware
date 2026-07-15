#!/usr/bin/env python3
"""Fast contract tests for the extracted execution-policy boundary."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import execution_policy as ep  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class ExecutionPolicyV2EnabledTests(unittest.TestCase):
    def test_bare_state_is_legacy(self) -> None:
        self.assertFalse(ep._execution_policy_v2_enabled({}))

    def test_v2_markers_enable_policy(self) -> None:
        state = {
            "task_execution_schema_version": ep.TASK_EXECUTION_SCHEMA_VERSION,
            "execution_policy_version": ep.EXECUTION_POLICY_VERSION,
        }
        self.assertTrue(ep._execution_policy_v2_enabled(state))

    def test_downgraded_schema_version_fails_closed(self) -> None:
        with self.assertRaisesRegex(HarnessError, "task_execution_schema_version must be"):
            ep._execution_policy_v2_enabled({"task_execution_schema_version": 1})

    def test_legacy_provenance_conflicting_with_v2_state_is_rejected(self) -> None:
        state = {
            "legacy_execution_policy": True,
            "task_execution_schema_version": ep.TASK_EXECUTION_SCHEMA_VERSION,
            "execution_policy_version": ep.EXECUTION_POLICY_VERSION,
        }
        with self.assertRaisesRegex(HarnessError, "conflicts with v2 execution state"):
            ep._execution_policy_v2_enabled(state)


class AdoptExecutionPolicyV2Tests(unittest.TestCase):
    def test_adopts_v2_markers_on_a_quiescent_legacy_task(self) -> None:
        state: dict[str, object] = {}
        ep._adopt_execution_policy_v2_for_new_work(state)
        self.assertEqual(
            state["task_execution_schema_version"], ep.TASK_EXECUTION_SCHEMA_VERSION
        )
        self.assertEqual(state["execution_policy_version"], ep.EXECUTION_POLICY_VERSION)
        self.assertIs(state["legacy_execution_policy"], False)

    def test_rejects_adoption_with_active_packets(self) -> None:
        state = {"packets": [{"packet_id": "p1", "status": "armed"}]}
        with self.assertRaisesRegex(HarnessError, "must be quiescent"):
            ep._adopt_execution_policy_v2_for_new_work(state)


class AdoptLegacyProvenanceTests(unittest.TestCase):
    def test_seals_a_clean_pre_marker_task_as_legacy(self) -> None:
        state: dict[str, object] = {}
        ep._adopt_legacy_execution_provenance_for_v4_migration(state)
        self.assertIs(state["legacy_execution_policy"], True)

    def test_rejects_migration_for_a_native_execution_policy_task(self) -> None:
        with self.assertRaisesRegex(HarnessError, "forbidden for a native"):
            ep._adopt_legacy_execution_provenance_for_v4_migration(
                {"legacy_execution_policy": False}
            )


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "execution_policy.py"
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


if __name__ == "__main__":
    unittest.main()
