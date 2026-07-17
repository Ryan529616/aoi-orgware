#!/usr/bin/env python3
"""WS1 — hook-observed routing records and derived routing verification.

Adversarial contract: routing_verified must never become true from CLI free
text alone; the only trusted source for an observed model is the SubagentStart
hook payload, and verification additionally requires an applied
resource-config binding for the packet's role. Helper-spawn model capture is
exercised end-to-end by the WS4 canary tests; incidents and root observations
are covered here.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402

from tests.harness_case import HarnessTestCase  # noqa: E402


class RoutingObservabilityTests(HarnessTestCase):
    def _task_state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def _create_packet(self, task_id: str, packet_id: str) -> None:
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Inspect one bounded routing question",
            "--scope",
            "read-only, exact sources",
            "--deliverable",
            "conclusion with exact evidence paths",
            "--validation",
            "root cross-checks the cited lines",
        )

    def _parent_session(self, task_id: str) -> str:
        suffix = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:16]
        return f"dispatch-parent-{suffix}"

    def _observe(self, task_id: str, packet_id: str, *, model: str | None) -> dict:
        self.arm_packet(task_id, packet_id, expected_agent_type="explorer")
        payload = {
            "hook_event_name": "SubagentStart",
            "session_id": self._parent_session(task_id),
            "turn_id": f"turn-{packet_id}",
            "agent_id": f"/root/{packet_id}",
            "agent_type": "explorer",
            "permission_mode": "default",
        }
        if model is not None:
            payload["model"] = model
        return self.hook(payload)

    def test_hook_observation_persists_transport_model(self) -> None:
        task_id = "routing-model-observed"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        observed = self._observe(task_id, "probe", model="gpt-test-sol")
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("valid pre-armed dispatch", context)
        state = self._task_state(task_id)
        packet = state["packets"][0]
        observation = packet["dispatch_attempts"][0]["observation"]
        self.assertEqual(observation["model"], "gpt-test-sol")
        self.assertEqual(
            cli_impl._hook_observed_routing_model(packet), "gpt-test-sol"
        )
        # Hook observation alone is necessary but not sufficient: with no
        # applied resource-config binding the packet must stay unverified.
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "probe",
            "--status",
            "done",
            "--summary",
            "Bounded probe complete",
            "--evidence",
            "result cites exact source paths",
        )
        state = self._task_state(task_id)
        packet = state["packets"][0]
        self.assertFalse(packet["routing_verified"])

    def test_cli_free_text_never_verifies_routing(self) -> None:
        task_id = "routing-cli-spoof"
        self.init_task(task_id)
        self._create_packet(task_id, "spoof")
        # Manual dispatch (no hook observation) plus a fully consistent
        # operator claim — the exact pre-change recipe for routing_verified.
        self.dispatch_packet(
            task_id,
            "spoof",
            "agent-spoof",
            "--actual-role",
            "explorer",
            "--actual-model-tier",
            "standard",
            "--routing-evidence",
            "operator asserts the platform used the requested tier",
        )
        state = self._task_state(task_id)
        packet = state["packets"][0]
        self.assertFalse(packet["routing_verified"])
        self.assertEqual(packet["routing_claim"]["provenance"], "cli_claimed")
        self.assertEqual(packet["routing_claim"]["actual_role"], "explorer")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "spoof",
            "--status",
            "done",
            "--summary",
            "Bounded probe complete",
            "--evidence",
            "result cites exact source paths",
        )
        state = self._task_state(task_id)
        packet = state["packets"][0]
        self.assertFalse(packet["routing_verified"])
        result_text = Path(packet["result_path"]).read_text(encoding="utf-8")
        self.assertIn("operator claim", result_text)
        self.assertIn(
            "Routing verified (hook-observed vs applied binding): `false`",
            result_text,
        )
        self.assertIn("Hook-observed model: `not exposed by transport`", result_text)

    def test_hook_observation_without_model_stays_unverified(self) -> None:
        task_id = "routing-legacy-transport"
        self.init_task(task_id)
        self._create_packet(task_id, "legacy")
        self._observe(task_id, "legacy", model=None)
        state = self._task_state(task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["dispatch_attempts"][0]["observation"]["model"], "")
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "legacy",
            "--status",
            "done",
            "--summary",
            "Bounded probe complete",
            "--evidence",
            "result cites exact source paths",
            "--actual-role",
            "explorer",
            "--actual-model-tier",
            "standard",
            "--routing-evidence",
            "operator asserts routing although transport exposed no model",
        )
        state = self._task_state(task_id)
        packet = state["packets"][0]
        self.assertFalse(packet["routing_verified"])

    def test_derived_routing_verified_requires_binding_match(self) -> None:
        packet = {
            "agent_role": "explorer",
            "dispatch_provenance": "codex_subagent_start_observed",
            "dispatch_attempts": [
                {
                    "status": "consumed",
                    "observation": {"model": "gpt-test-sol"},
                }
            ],
        }
        applied_event = {
            "status": "applied",
            "rollback": None,
            "resolved": {"agents": {"explorer": {"model": "gpt-test-sol"}}},
        }
        state_match = {"resource_config_events": [applied_event]}
        self.assertTrue(cli_impl._derived_routing_verified(state_match, packet))
        # Wrong bound model -> unverified.
        state_mismatch = copy.deepcopy(state_match)
        state_mismatch["resource_config_events"][0]["resolved"]["agents"][
            "explorer"
        ]["model"] = "gpt-test-luna"
        self.assertFalse(cli_impl._derived_routing_verified(state_mismatch, packet))
        # Rolled-back binding -> unverified.
        state_rolled = copy.deepcopy(state_match)
        state_rolled["resource_config_events"][0]["rollback"] = {"at": "x"}
        self.assertFalse(cli_impl._derived_routing_verified(state_rolled, packet))
        # No binding at all -> unverified.
        self.assertFalse(cli_impl._derived_routing_verified({}, packet))
        # Manual provenance -> unverified even with a matching binding.
        manual = copy.deepcopy(packet)
        manual["dispatch_provenance"] = "manual_unverified"
        self.assertFalse(cli_impl._derived_routing_verified(state_match, manual))
        # Empty observed model -> unverified.
        unexposed = copy.deepcopy(packet)
        unexposed["dispatch_attempts"][0]["observation"]["model"] = ""
        self.assertFalse(cli_impl._derived_routing_verified(state_match, unexposed))

    def test_incident_records_carry_observed_model(self) -> None:
        task_id = "routing-incident-model"
        self.init_task(task_id)
        session = self._parent_session(task_id)
        self.cli("bind-session", "--task", task_id, "--session-id", session)
        outcome = self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": session,
                "turn_id": "turn-unmanaged",
                "agent_id": "/root/unmanaged",
                "agent_type": "explorer",
                "permission_mode": "default",
                "model": "gpt-test-terra",
            }
        )
        context = outcome["hookSpecificOutput"]["additionalContext"]
        self.assertIn("without one valid, unique pre-armed packet", context)
        state = self._task_state(task_id)
        incident = state["subagent_incidents"][0]
        self.assertEqual(incident["model"], "gpt-test-terra")
        self.assertEqual(incident["reason_code"], "no_matching_arm")

    def test_observation_schema_accepts_legacy_and_rejects_tamper(self) -> None:
        task_id = "routing-integrity"
        self.init_task(task_id)
        self._create_packet(task_id, "probe")
        self._observe(task_id, "probe", model="gpt-test-sol")
        state = self._task_state(task_id)
        paths = h.get_paths(self.root)
        self.assertEqual(cli_impl.packet_integrity_errors(paths, state), [])
        # Legacy eight-field observation (no model, no digest) must stay valid.
        legacy = copy.deepcopy(state)
        legacy_observation = legacy["packets"][0]["dispatch_attempts"][0][
            "observation"
        ]
        del legacy_observation["model"]
        del legacy_observation["observation_sha256"]
        self.assertEqual(cli_impl.packet_integrity_errors(paths, legacy), [])
        # Retrofitting a model onto a legacy observation (no digest) must be
        # rejected as a schema violation.
        retrofit = copy.deepcopy(legacy)
        retrofit["packets"][0]["dispatch_attempts"][0]["observation"][
            "model"
        ] = "gpt-forged"
        self.assertTrue(
            any(
                "invalid observation schema" in error
                for error in cli_impl.packet_integrity_errors(paths, retrofit)
            )
        )
        # Editing the observed model after consumption must break the digest.
        rewritten = copy.deepcopy(state)
        rewritten["packets"][0]["dispatch_attempts"][0]["observation"][
            "model"
        ] = "gpt-forged"
        self.assertTrue(
            any(
                "observation lost identity integrity" in error
                for error in cli_impl.packet_integrity_errors(paths, rewritten)
            )
        )
        # Non-string model must fail identity integrity.
        tampered = copy.deepcopy(state)
        tampered["packets"][0]["dispatch_attempts"][0]["observation"]["model"] = 7
        self.assertTrue(
            any(
                "observation lost identity integrity" in error
                for error in cli_impl.packet_integrity_errors(paths, tampered)
            )
        )
        # Unknown extra observation key must still be rejected.
        alien = copy.deepcopy(state)
        alien["packets"][0]["dispatch_attempts"][0]["observation"]["alien"] = "x"
        self.assertTrue(
            any(
                "invalid observation schema" in error
                for error in cli_impl.packet_integrity_errors(paths, alien)
            )
        )
