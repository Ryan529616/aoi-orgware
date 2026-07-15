#!/usr/bin/env python3
"""Fast contract tests for the extracted execution-topology boundary."""

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

from aoi_orgware import execution_topology as et  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402


def _services(
    *,
    packet_authority_integrity_errors=None,
    validate_packet_resource_envelope=None,
    selection_terminal_packet_bindings=None,
) -> et.ExecutionTopologyServices:
    def _unexpected(*args, **kwargs):  # pragma: no cover - guards against misuse
        raise AssertionError("service was not expected to be called")

    return et.ExecutionTopologyServices(
        packet_authority_integrity_errors=(
            packet_authority_integrity_errors or _unexpected
        ),
        validate_packet_resource_envelope=(
            validate_packet_resource_envelope or _unexpected
        ),
        selection_terminal_packet_bindings=(
            selection_terminal_packet_bindings or _unexpected
        ),
    )


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "execution_topology.py"
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


class ServicesInjectionTests(unittest.TestCase):
    def test_services_dataclass_is_frozen(self) -> None:
        services = _services()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            services.packet_authority_integrity_errors = None  # type: ignore[misc]

    def test_owned_job_authority_uses_injected_authority_check(self) -> None:
        owner = {
            "packet_id": "p1",
            "delegation_depth": 1,
            "packet_mode": "bounded_mutation",
            "lane_id": "L1",
            "execution_selection_id": "S1",
            "status": "dispatched",
            "packet_contract_sha256": "abc",
        }
        job = {
            "run_id": "j1",
            "owner_packet_id": "p1",
            "lane_id": "L1",
            "execution_selection_id": "S1",
            "owner_packet_contract_sha256": "abc",
        }
        state = {"packets": [owner]}

        # With paths=None the injected authority check is never consulted.
        self.assertIs(
            et._validate_owned_job_authority(
                None, state, job, require_dispatched=True, services=_services()
            ),
            owner,
        )

        calls: list[tuple] = []

        def forged(paths, state_arg, packet, *, require_origin):
            calls.append((packet.get("packet_id"), require_origin))
            return ["forged authority"]

        with self.assertRaisesRegex(HarnessError, "tampered.*forged authority"):
            et._validate_owned_job_authority(
                object(),
                state,
                job,
                require_dispatched=True,
                services=_services(packet_authority_integrity_errors=forged),
            )
        self.assertEqual(calls, [("p1", False)])


class TopologyPredicateTests(unittest.TestCase):
    def test_steward_synthesis_packet_predicate(self) -> None:
        self.assertTrue(
            et._is_steward_synthesis_packet({"packet_purpose": "steward_synthesis"})
        )
        self.assertFalse(et._is_steward_synthesis_packet({"packet_purpose": "work"}))
        self.assertFalse(et._is_steward_synthesis_packet({}))

    def test_synthesis_freeze_ids_are_sorted_and_exclude_terminal_failures(self) -> None:
        state = {
            "packets": [
                {
                    "packet_id": "syn-b",
                    "execution_selection_id": "S1",
                    "packet_purpose": "steward_synthesis",
                    "status": "ready",
                },
                {
                    "packet_id": "syn-a",
                    "execution_selection_id": "S1",
                    "packet_purpose": "steward_synthesis",
                    "status": "dispatched",
                },
                {
                    "packet_id": "syn-cancelled",
                    "execution_selection_id": "S1",
                    "packet_purpose": "steward_synthesis",
                    "status": "cancelled",
                },
                {
                    "packet_id": "worker",
                    "execution_selection_id": "S1",
                    "packet_purpose": "work",
                    "status": "ready",
                },
                {
                    "packet_id": "syn-other-selection",
                    "execution_selection_id": "S2",
                    "packet_purpose": "steward_synthesis",
                    "status": "ready",
                },
            ]
        }
        self.assertEqual(
            et._selection_synthesis_freeze_packet_ids(state, "S1"),
            ["syn-a", "syn-b"],
        )


class ActiveExecutionSelectionTests(unittest.TestCase):
    def test_active_topology_requires_explicit_selection_binding(self) -> None:
        state = {"execution_selections": [{"selection_id": "S1", "status": "active"}]}
        with self.assertRaisesRegex(HarnessError, "active execution topology"):
            et._validate_active_execution_selection(state, "L1", "")

    def test_no_selection_and_no_active_topology_returns_none(self) -> None:
        self.assertIsNone(
            et._validate_active_execution_selection(
                {"execution_selections": []}, "", ""
            )
        )


if __name__ == "__main__":
    unittest.main()
