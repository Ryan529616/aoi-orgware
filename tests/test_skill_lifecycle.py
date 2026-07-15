#!/usr/bin/env python3
"""Fast contract tests for the extracted skill-lifecycle boundary."""

from __future__ import annotations

import ast
import dataclasses
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import skill_lifecycle as sl  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "skill_lifecycle.py"
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


class SkillLifecycleServicesTests(unittest.TestCase):
    def test_services_is_frozen_and_carries_reviewer_callback(self) -> None:
        sentinel = object()
        services = sl.SkillLifecycleServices(require_done_reviewer_packet=sentinel)
        self.assertIs(services.require_done_reviewer_packet, sentinel)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.require_done_reviewer_packet = None  # type: ignore[misc]


class SkillManifestFileTests(unittest.TestCase):
    def test_manifest_files_accept_canonical_and_reject_unsafe(self) -> None:
        good = [
            {"path": "SKILL.md", "sha256": "a" * 64},
            {"path": "scripts/run.py", "sha256": "b" * 64},
        ]
        self.assertTrue(sl._valid_skill_manifest_files(good))
        for bad in (
            [],
            "not-a-list",
            [{"path": "/abs.md", "sha256": "a" * 64}],
            [{"path": "../escape.md", "sha256": "a" * 64}],
            [{"path": "dup.md", "sha256": "a" * 64}, {"path": "dup.md", "sha256": "b" * 64}],
            [{"path": "bad.md", "sha256": "not-hex"}],
        ):
            with self.subTest(value=bad):
                self.assertFalse(sl._valid_skill_manifest_files(bad))


class JsonNonNegativeIntTests(unittest.TestCase):
    def test_requires_non_negative_non_boolean_integer(self) -> None:
        self.assertEqual(sl._json_nonnegative_int({"units": 3}, "units"), 3)
        self.assertEqual(sl._json_nonnegative_int({}, "missing"), 0)
        for payload in ({"units": True}, {"units": -1}, {"units": "3"}):
            with self.subTest(payload=payload):
                with self.assertRaises(HarnessError):
                    sl._json_nonnegative_int(payload, "units")


class CanaryWorkUnitBindingTests(unittest.TestCase):
    def test_binding_requires_both_ids_or_neither(self) -> None:
        self.assertIsNone(
            sl._validate_skill_canary_work_unit_binding(
                {}, "", "", require_live_canary=False
            )
        )
        with self.assertRaisesRegex(HarnessError, "requires both"):
            sl._validate_skill_canary_work_unit_binding(
                {}, "skill-v1", "", require_live_canary=False
            )


class AdoptionWorkUnitResolutionTests(unittest.TestCase):
    def test_terminal_packet_must_be_bound_to_exact_canary(self) -> None:
        # Exercises the module-local TERMINAL_PACKET_STATUSES recompute and the
        # self-module _resolve_improvement_occurrence delegation.
        packet = {
            "packet_id": "candidate",
            "status": "done",
            "result_sha256": "a" * 64,
            "completed_at": "2026-07-13T23:59:59+00:00",
            "lane_id": "rtl",
        }
        state = {"packets": [packet]}
        with self.assertRaisesRegex(HarnessError, "not bound to the exact skill canary"):
            sl._resolve_adoption_work_units(
                state,
                ["packet:candidate"],
                label="skill canary",
                minimum=1,
                canary_recorded_at="2026-07-14T00:00:00+00:00",
                require_after_canary=True,
                expected_skill_release_id="skill-v1",
                expected_skill_version="1.0.0",
                expected_canary_event_id="canary-1",
            )

    def test_non_terminal_packet_is_rejected(self) -> None:
        state = {"packets": [{"packet_id": "candidate", "status": "armed"}]}
        with self.assertRaisesRegex(HarnessError, "is not a terminal packet"):
            sl._resolve_improvement_occurrence(state, "packet:candidate")


if __name__ == "__main__":
    unittest.main()
