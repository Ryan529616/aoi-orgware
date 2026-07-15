#!/usr/bin/env python3
"""Fast contract tests for the extracted by-id state-lookup boundary."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import state_lookup as sl  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class RequireOpenTaskTests(unittest.TestCase):
    def test_accepts_active_or_blocked_and_rejects_others(self) -> None:
        sl.require_open_task({"status": "active"}, "do a thing")
        sl.require_open_task({"status": "blocked"}, "do a thing")
        with self.assertRaisesRegex(HarnessError, "cannot do a thing task"):
            sl.require_open_task({"status": "done", "task_id": "t1"}, "do a thing")


class RequireFullCommitTests(unittest.TestCase):
    def test_normalizes_case_and_rejects_short_ids(self) -> None:
        self.assertEqual(sl.require_full_commit("A" * 40, "commit"), "a" * 40)
        with self.assertRaisesRegex(HarnessError, "full 40-64 hex"):
            sl.require_full_commit("abc123", "commit")


class LaneByIdTests(unittest.TestCase):
    def test_finds_exactly_one_lane_or_raises(self) -> None:
        state = {"lanes": [{"lane_id": "analysis"}, {"lane_id": "implementation"}]}
        self.assertEqual(sl.lane_by_id(state, "analysis"), {"lane_id": "analysis"})
        with self.assertRaisesRegex(HarnessError, "expected exactly one lane"):
            sl.lane_by_id(state, "missing")


class PacketByIdTests(unittest.TestCase):
    def test_finds_exactly_one_packet_or_raises(self) -> None:
        state = {"packets": [{"packet_id": "p1"}, {"packet_id": "p2"}]}
        self.assertEqual(sl._packet_by_id(state, "p2"), {"packet_id": "p2"})
        with self.assertRaisesRegex(HarnessError, "expected exactly one packet"):
            sl._packet_by_id(state, "missing")


class EngagedLaneTests(unittest.TestCase):
    def test_engaged_steward_lane_requires_exactly_one(self) -> None:
        state = {
            "lanes": [
                {"kind": "coordination_steward", "status": "active", "lane_id": "s1"},
                {"kind": "implementation", "status": "active", "lane_id": "i1"},
            ]
        }
        self.assertEqual(sl._engaged_steward_lane(state)["lane_id"], "s1")
        with self.assertRaisesRegex(HarnessError, "exactly one engaged"):
            sl._engaged_steward_lane({"lanes": []})

    def test_engaged_capacity_lane_requires_capacity_planning_kind(self) -> None:
        state = {
            "lanes": [
                {"lane_id": "cap1", "kind": "capacity_planning", "status": "active"},
                {"lane_id": "impl1", "kind": "implementation", "status": "active"},
            ]
        }
        self.assertEqual(sl._engaged_capacity_lane(state, "cap1")["lane_id"], "cap1")
        with self.assertRaisesRegex(HarnessError, "engaged capacity_planning lane"):
            sl._engaged_capacity_lane(state, "impl1")


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        paths = [SRC / "aoi_orgware" / "state_lookup.py"]
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
