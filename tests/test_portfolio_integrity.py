#!/usr/bin/env python3
"""Fast contract tests for the extracted portfolio-integrity boundary."""

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

from aoi_orgware import portfolio_integrity as pi  # noqa: E402


def _policy(**overrides) -> pi.PortfolioIntegrityPolicy:
    base = dict(
        lane_kinds={"work", "coordination_steward"},
        lane_statuses={"active", "waiting"},
        max_engaged_lanes=12,
        dependency_kinds={"hard_gate", "soft_dependency", "informational"},
        dependency_statuses={"open", "satisfied", "waived", "superseded"},
        coordination_statuses={"open", "accepted", "resolved"},
        close_qualifying_categories={"integration_test"},
        capability_catalog_version=1,
        capability_tier_map={"tier_a": "expert"},
        improvement_statuses={"submitted", "awaiting_chief", "approved"},
        improvement_trigger_classes={"repeated_pain", "critical_single_incident"},
        execution_modes={"single", "centralized_parallel", "hybrid"},
        executing_packet_statuses={"armed", "dispatched"},
        cross_lane_session_statuses={"open", "closed", "cancelled"},
        needs_user_statuses={"needs_user", "resolved", "cancelled"},
        needs_user_categories={"policy", "capability"},
    )
    base.update(overrides)
    return pi.PortfolioIntegrityPolicy(**base)


def _services(**overrides) -> pi.PortfolioIntegrityServices:
    def _unexpected(*args, **kwargs):  # pragma: no cover - guards against misuse
        raise AssertionError("service was not expected to be called")

    names = (
        "records_fingerprint",
        "steward_packet_binding",
        "skill_release_semantic_integrity_errors",
        "validate_packet_activation_topology",
        "validate_job_activation_topology",
        "job_launch_authority_errors",
    )
    return pi.PortfolioIntegrityServices(
        **{name: overrides.get(name, _unexpected) for name in names}
    )


def _lane(**overrides) -> dict:
    lane = {
        "lane_id": "lane-1",
        "integrity_version": 1,
        "kind": "work",
        "status": "active",
        "revision": 1,
        "authority_commit": "0" * 40,
        "owner": "owner",
        "role": "role",
        "contract_version": "v1",
        "next_action": "do",
        "revisions": [{"revision": 1}],
    }
    lane.update(overrides)
    return lane


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "portfolio_integrity.py"
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


class ModuleSurfaceTests(unittest.TestCase):
    def test_public_surface_is_sorted_and_complete(self) -> None:
        self.assertEqual(pi.__all__, sorted(pi.__all__))
        self.assertEqual(
            set(pi.__all__),
            {
                "JobLaunchAuthorityErrors",
                "PortfolioIntegrityPolicy",
                "PortfolioIntegrityServices",
                "RecordsFingerprint",
                "SkillReleaseSemanticIntegrityErrors",
                "StewardPacketBinding",
                "ValidateJobActivationTopology",
                "ValidatePacketActivationTopology",
                "_hard_dependency_cycle",
                "portfolio_integrity_errors",
            },
        )


class PortfolioIntegrityPolicyTests(unittest.TestCase):
    def test_post_init_freezes_set_fields_only(self) -> None:
        policy = _policy()
        self.assertIsInstance(policy.lane_kinds, frozenset)
        self.assertIsInstance(policy.needs_user_categories, frozenset)
        self.assertIsInstance(policy.close_qualifying_categories, frozenset)
        # Non-set fields keep their concrete type.
        self.assertIsInstance(policy.max_engaged_lanes, int)
        self.assertEqual(policy.capability_tier_map, {"tier_a": "expert"})

    def test_policy_is_immutable(self) -> None:
        policy = _policy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.max_engaged_lanes = 1  # type: ignore[misc]

    def test_cli_factory_snapshots_live_globals_freshly(self) -> None:
        # LANE_KINDS is rebound by apply_project_config, so the composition-root
        # factory must observe the current global on every call.
        from aoi_orgware import cli as cli_impl

        original = cli_impl.LANE_KINDS
        try:
            cli_impl.LANE_KINDS = {"work", "sentinel_department"}
            policy = cli_impl._portfolio_integrity_policy()
            self.assertIn("sentinel_department", policy.lane_kinds)
            self.assertIsInstance(policy.lane_kinds, frozenset)
        finally:
            cli_impl.LANE_KINDS = original


class PortfolioIntegrityServicesTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = _services()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.records_fingerprint = None  # type: ignore[misc]


class HardDependencyCycleTests(unittest.TestCase):
    def test_active_hard_gate_cycle_is_detected(self) -> None:
        deps = [
            {"kind": "hard_gate", "source_lane": "a", "target_lane": "b"},
            {"kind": "hard_gate", "source_lane": "b", "target_lane": "a"},
        ]
        self.assertTrue(pi._hard_dependency_cycle(deps))

    def test_superseded_and_soft_edges_never_form_a_cycle(self) -> None:
        deps = [
            {"kind": "hard_gate", "source_lane": "a", "target_lane": "b",
             "status": "superseded"},
            {"kind": "hard_gate", "source_lane": "b", "target_lane": "a",
             "status": "superseded"},
            {"kind": "soft_dependency", "source_lane": "a", "target_lane": "b"},
            {"kind": "soft_dependency", "source_lane": "b", "target_lane": "a"},
        ]
        self.assertFalse(pi._hard_dependency_cycle(deps))


class PortfolioIntegrityErrorsTests(unittest.TestCase):
    def test_empty_state_short_circuits(self) -> None:
        self.assertEqual(
            pi.portfolio_integrity_errors(
                {}, None, policy=_policy(), services=_services()
            ),
            [],
        )

    def test_lane_vocabulary_is_taken_from_policy(self) -> None:
        state = {
            "lane_model_version": 1,
            "lanes": [_lane(kind="not_a_kind", status="not_a_status")],
        }
        errors = pi.portfolio_integrity_errors(
            state, None, policy=_policy(), services=_services()
        )
        self.assertTrue(any("has invalid kind" in e for e in errors), errors)
        self.assertTrue(any("has invalid status" in e for e in errors), errors)

    def test_engaged_lane_ceiling_comes_from_policy(self) -> None:
        state = {
            "lane_model_version": 1,
            "lanes": [
                _lane(lane_id="lane-1"),
                _lane(lane_id="lane-2"),
            ],
        }
        errors = pi.portfolio_integrity_errors(
            state, None, policy=_policy(max_engaged_lanes=1), services=_services()
        )
        self.assertTrue(
            any("exceeds hard ceiling 1" in e for e in errors), errors
        )


if __name__ == "__main__":
    unittest.main()
