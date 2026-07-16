#!/usr/bin/env python3
"""Fast contract tests for the extracted packet-integrity boundary."""

from __future__ import annotations

import ast
import dataclasses
import sys
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402
from aoi_orgware import packet_integrity as pi  # noqa: E402
from aoi_orgware.harnesslib import HarnessError  # noqa: E402

from tests.harness_case import HarnessTestCase  # noqa: E402


def _services(
    *,
    validate_packet_resource_envelope=None,
    selection_terminal_packet_bindings=None,
    dispatch_attempt_authority_sha256=None,
    active_dispatch_attempt=None,
    safe_hook_observation_text=None,
    subagent_event_id=None,
) -> pi.PacketIntegrityServices:
    def _unexpected(*args, **kwargs):  # pragma: no cover - guards against misuse
        raise AssertionError("service was not expected to be called")

    return pi.PacketIntegrityServices(
        validate_packet_resource_envelope=(
            validate_packet_resource_envelope or _unexpected
        ),
        selection_terminal_packet_bindings=(
            selection_terminal_packet_bindings or _unexpected
        ),
        dispatch_attempt_authority_sha256=(
            dispatch_attempt_authority_sha256 or _unexpected
        ),
        active_dispatch_attempt=(active_dispatch_attempt or _unexpected),
        safe_hook_observation_text=(safe_hook_observation_text or _unexpected),
        subagent_event_id=(subagent_event_id or _unexpected),
    )


class ImportBoundaryTests(unittest.TestCase):
    def test_module_does_not_depend_on_monolithic_cli(self) -> None:
        path = SRC / "aoi_orgware" / "packet_integrity.py"
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
            services.validate_packet_resource_envelope = None  # type: ignore[misc]

    def test_resource_envelope_check_is_injected_not_imported(self) -> None:
        # No selection and no digest is inert; the injected check is untouched.
        self.assertEqual(
            pi.packet_resource_envelope_integrity_errors(
                {}, {}, services=_services()
            ),
            [],
        )
        # A digest without a selection fails closed before any injected call.
        self.assertEqual(
            pi.packet_resource_envelope_integrity_errors(
                {}, {"resource_envelope_sha256": "a" * 64}, services=_services()
            ),
            ["packet has a resource envelope digest without an execution selection"],
        )
        # With a live selection, the composition-root envelope check is consulted.
        calls: list[tuple] = []

        def envelope(state, packet, selection, *, enforce_active_limit):
            calls.append(
                (packet.get("packet_id"), selection.get("selection_id"), enforce_active_limit)
            )
            raise HarnessError("forged envelope drift")

        state = {
            "execution_selections": [{"selection_id": "sel-1", "status": "active"}]
        }
        packet = {"packet_id": "p1", "execution_selection_id": "sel-1"}
        self.assertEqual(
            pi.packet_resource_envelope_integrity_errors(
                state,
                packet,
                services=_services(validate_packet_resource_envelope=envelope),
            ),
            ["forged envelope drift"],
        )
        self.assertEqual(calls, [("p1", "sel-1", False)])

    def test_subagent_incident_uses_injected_active_attempt(self) -> None:
        seen: list[str] = []

        def active(packet):
            seen.append(str(packet.get("packet_id")))
            return {"parent_session_id": "sess", "expected_agent_type": "impl"}

        state = {
            "dispatch_model_version": 1,
            "subagent_incidents": [],
            "packets": [
                {"packet_id": "a", "status": "armed"},
                {"packet_id": "b", "status": "armed"},
            ],
        }
        errors = pi.subagent_incident_integrity_errors(
            state, services=_services(active_dispatch_attempt=active)
        )
        self.assertEqual(seen, ["a", "b"])
        self.assertTrue(
            any("multiple armed packets occupy" in item for item in errors), errors
        )


class PureValidatorTests(unittest.TestCase):
    def test_packet_command_integrity_error_modes(self) -> None:
        self.assertIsNone(pi.packet_command_integrity_error({"packet_mode": "legacy"}))
        self.assertIsNone(
            pi.packet_command_integrity_error({"packet_mode": "bounded_mutation"})
        )
        self.assertEqual(
            pi.packet_command_integrity_error(
                {"packet_id": "p1", "packet_mode": "nonsense"}
            ),
            "packet p1 has invalid packet mode 'nonsense'",
        )
        missing = pi.packet_command_integrity_error(
            {"packet_id": "p2", "packet_mode": "exact_command", "command_path": ""}
        )
        self.assertEqual(
            missing, "packet p2 exact command artifact is missing/non-regular"
        )

    def test_packet_result_integrity_errors_requires_terminal_status(self) -> None:
        self.assertEqual(
            pi.packet_result_integrity_errors(
                None, {"task_id": "t"}, {"packet_id": "p1", "status": "ready"}
            ),
            ["packet p1 result is not terminal"],
        )

    def test_packet_integrity_warnings_flags_legacy_dispatch(self) -> None:
        state = {
            "packets": [
                {
                    "packet_id": "legacy-1",
                    "packet_schema_version": 4,
                    "status": "done",
                }
            ]
        }
        warnings = pi.packet_integrity_warnings(state)
        self.assertIn(
            "packet legacy-1 dispatch timing/provenance is legacy_unverified",
            warnings,
        )


class EvidenceSelfReferenceGateTests(unittest.TestCase):
    """The ARISE reviewer packet closed `done` while its only evidence bullet was
    its own `results/<id>.md` path, making the finding unverifiable."""

    def setUp(self) -> None:
        self.task_dir = Path("/aoi/tasks/audit")
        self.own_result = str(self.task_dir / "results" / "review.md")

    def test_self_only_absolute_reference_is_rejected(self) -> None:
        error = pi.packet_evidence_self_reference_error(
            "review", [self.own_result], self.task_dir
        )
        self.assertIsNotNone(error)
        self.assertIn("its own result file", str(error))

    def test_self_only_relative_reference_is_rejected(self) -> None:
        self.assertIsNotNone(
            pi.packet_evidence_self_reference_error(
                "review", ["results/review.md"], self.task_dir
            )
        )

    def test_empty_evidence_is_rejected(self) -> None:
        error = pi.packet_evidence_self_reference_error("review", [], self.task_dir)
        self.assertIsNotNone(error)
        self.assertIn("at least one evidence reference", str(error))
        # Whitespace-only references collapse to empty and are rejected too.
        self.assertIsNotNone(
            pi.packet_evidence_self_reference_error("review", ["   "], self.task_dir)
        )

    def test_other_packet_result_is_external(self) -> None:
        other = str(self.task_dir / "results" / "explorer.md")
        self.assertIsNone(
            pi.packet_evidence_self_reference_error("review", [other], self.task_dir)
        )

    def test_artifact_blob_reference_is_external(self) -> None:
        blob = "results/artifact-blobs/artifact-sha256-abc.blob"
        self.assertIsNone(
            pi.packet_evidence_self_reference_error("review", [blob], self.task_dir)
        )

    def test_descriptive_primary_artifact_is_external(self) -> None:
        self.assertIsNone(
            pi.packet_evidence_self_reference_error(
                "review", ["/runs/vcs/driver.log lines 12-88"], self.task_dir
            )
        )

    def test_mixed_self_and_external_is_accepted(self) -> None:
        self.assertIsNone(
            pi.packet_evidence_self_reference_error(
                "review",
                [self.own_result, "/runs/vcs/driver.log"],
                self.task_dir,
            )
        )


class EvidenceGateIntegrityWiringTests(HarnessTestCase):
    """The re-validation runs ONLY for packets carrying evidence_gate_version>=1;
    the surrounding fences are isolated so the assertion binds to the gate alone."""

    def _run(self, *, gate: bool) -> list[str]:
        paths = h.get_paths(self.root)
        own_result = str(h.task_dir(paths, "audit") / "results" / "review.md")
        packet = {
            "packet_id": "review",
            "status": "done",
            "packet_purpose": "work",
            "packet_mode": "read_only",
            "evidence": [own_result],
        }
        if gate:
            packet["evidence_gate_version"] = 1
        state = {"task_id": "audit", "packets": [packet]}
        with (
            mock.patch.object(pi, "packet_lock_integrity_errors", return_value=[]),
            mock.patch.object(
                pi, "packet_resource_envelope_integrity_errors", return_value=[]
            ),
            mock.patch.object(pi, "packet_contract_integrity_error", return_value=None),
            mock.patch.object(pi, "packet_input_integrity_errors", return_value=[]),
            mock.patch.object(pi, "packet_command_integrity_error", return_value=None),
            mock.patch.object(pi, "packet_result_integrity_errors", return_value=[]),
        ):
            return pi.packet_integrity_errors(
                paths, state, services=_services()
            )

    def test_gate_version_revalidates_self_only_evidence(self) -> None:
        errors = self._run(gate=True)
        self.assertTrue(
            any("cites only its own result file" in item for item in errors), errors
        )

    def test_legacy_packet_without_gate_version_is_untouched(self) -> None:
        errors = self._run(gate=False)
        self.assertFalse(
            any("cites only its own result file" in item for item in errors), errors
        )


class CliFactoryWiringTests(unittest.TestCase):
    def test_cli_factory_wires_the_composition_root_callables(self) -> None:
        services = cli_impl._packet_integrity_services()
        self.assertIsInstance(services, pi.PacketIntegrityServices)
        self.assertIs(
            services.validate_packet_resource_envelope,
            cli_impl._validate_packet_resource_envelope,
        )
        self.assertIs(
            services.selection_terminal_packet_bindings,
            cli_impl._selection_terminal_packet_bindings,
        )
        self.assertIs(
            services.dispatch_attempt_authority_sha256,
            cli_impl._dispatch_attempt_authority_sha256,
        )
        self.assertIs(
            services.active_dispatch_attempt, cli_impl._active_dispatch_attempt
        )
        self.assertIs(
            services.safe_hook_observation_text, cli_impl._safe_hook_observation_text
        )
        self.assertIs(services.subagent_event_id, cli_impl._subagent_event_id)


class PacketAuthorityIsolationTests(HarnessTestCase):
    """Migrated from test_cli.py: after extraction the isolation patches must
    target ``packet_integrity.<name>`` (the module the recursion resolves), not
    the CLI re-export.  Patching the CLI wrapper silently stops isolating."""

    def _chain_state(self) -> tuple[object, dict, dict, dict]:
        paths = h.get_paths(self.root)
        parent = {
            "packet_id": "parent-authority",
            "delegation_depth": 1,
            "locks": ["host:tree:C:/PROGRA~1"],
        }
        child = {
            "packet_id": "child-authority",
            "delegation_depth": 2,
            "parent_packet_id": "parent-authority",
            "locks": [],
        }
        specialist = {
            "packet_id": "specialist-authority",
            "status": "done",
            "execution_selection_id": "selection-authority",
            "locks": ["host:tree:C:/PROGRA~1"],
        }
        synthesis = {
            "packet_id": "steward-authority",
            "packet_purpose": "steward_synthesis",
            "execution_selection_id": "selection-authority",
            "locks": [],
        }
        packet_state = {
            "task_id": "packet-authority-chain",
            "worktree": str(self.root.resolve()),
            "packets": [parent, child, specialist, synthesis],
        }
        return paths, packet_state, child, synthesis

    def test_authority_recursion_isolated_on_module_local_patches(self) -> None:
        paths, packet_state, child, synthesis = self._chain_state()
        with (
            mock.patch.object(
                pi, "packet_contract_integrity_error", return_value=None
            ),
            mock.patch.object(
                pi, "packet_input_integrity_errors", return_value=[]
            ),
            mock.patch.object(
                pi, "packet_command_integrity_error", return_value=None
            ),
        ):
            child_errors = pi.packet_authority_integrity_errors(
                paths,
                packet_state,
                child,
                require_origin=False,
                services=_services(),
            )
            self.assertTrue(
                any(
                    "parent authority" in item
                    and "non-canonical lock authority" in item
                    for item in child_errors
                ),
                child_errors,
            )
            synthesis_errors = pi.packet_authority_integrity_errors(
                paths,
                packet_state,
                synthesis,
                require_origin=False,
                services=_services(),
            )
            self.assertTrue(
                any(
                    "specialist specialist-authority authority" in item
                    and "non-canonical lock authority" in item
                    for item in synthesis_errors
                ),
                synthesis_errors,
            )

    def test_patch_target_bites_on_module_and_misses_on_cli_wrapper(self) -> None:
        # Proves the migration is load-bearing: patching packet_integrity.<name>
        # reaches the intra-module recursion, patching cli.<name> does not.
        paths, packet_state, _child, _synthesis = self._chain_state()
        parent = packet_state["packets"][0]

        with mock.patch.object(
            pi, "packet_command_integrity_error", return_value="SENTINEL-BITES"
        ):
            bitten = pi.packet_authority_integrity_errors(
                paths, packet_state, parent, require_origin=False, services=_services()
            )
        self.assertIn("SENTINEL-BITES", bitten)

        with mock.patch.object(
            cli_impl, "packet_command_integrity_error", return_value="SENTINEL-MISSES"
        ):
            unbitten = pi.packet_authority_integrity_errors(
                paths, packet_state, parent, require_origin=False, services=_services()
            )
        self.assertNotIn("SENTINEL-MISSES", unbitten)


if __name__ == "__main__":
    unittest.main()
