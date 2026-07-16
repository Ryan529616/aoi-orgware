#!/usr/bin/env python3
"""Claude Code hook adapter tests: pre-spawn gate + SubagentStart consumption."""

from __future__ import annotations

import copy
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_case import HarnessTestCase  # noqa: E402
from aoi_orgware import cli as cli_impl  # noqa: E402
from aoi_orgware import harnesslib as h  # noqa: E402


CLAUDE_HOOK_MODULE = "aoi_orgware.claude_hook"


class ClaudeHookTestCase(HarnessTestCase):
    def claude_hook(
        self,
        payload: dict,
        *,
        hook_version: str = "1",
        env_extra: dict[str, str] | None = None,
    ) -> dict:
        env = dict(self.env)
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, "-m", CLAUDE_HOOK_MODULE, "--hook-version", hook_version],
            cwd=self.root,
            env=env,
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout.decode("utf-8"))

    def task_state(self, task_id: str) -> dict:
        return json.loads(
            (self.root / ".aoi" / "tasks" / task_id / "state.json").read_text(
                encoding="utf-8"
            )
        )

    def create_hook_packet(self, task_id: str, packet_id: str) -> None:
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
            "Inspect one bounded source question under an observed dispatch",
            "--scope",
            "Read-only packet with no harness mutation authority",
            "--deliverable",
            "One evidence-backed conclusion and exact inspected paths",
            "--validation",
            "The parent checks the conclusion against the named source paths",
        )

    def arm(
        self, task_id: str, packet_id: str, agent_type: str = "general-purpose"
    ) -> None:
        expires_at = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        armed = json.loads(
            self.cli(
                "packet-arm",
                "--task",
                task_id,
                "--packet-id",
                packet_id,
                "--expected-agent-type",
                agent_type,
                "--expires-at",
                expires_at,
                "--json",
            ).stdout
        )
        self.assertEqual(armed["status"], "armed")

    def pretooluse_payload(
        self,
        *,
        session_id: str = "harness-test-chief",
        subagent_type: str = "general-purpose",
        tool_name: str = "Agent",
        agent_id: str = "",
    ) -> dict:
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": session_id,
            "prompt_id": "prompt-gate-1",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {
                "description": "governed dispatch probe",
                "prompt": "Execute the packet contract.",
                "subagent_type": subagent_type,
            },
            "tool_use_id": "toolu_gate_000001",
        }
        if agent_id:
            payload["agent_id"] = agent_id
        return payload

    def start_payload(
        self,
        *,
        session_id: str = "harness-test-chief",
        agent_type: str = "general-purpose",
        agent_id: str = "agent-claude-0001",
        prompt_id: str = "prompt-start-1",
    ) -> dict:
        return {
            "hook_event_name": "SubagentStart",
            "session_id": session_id,
            "prompt_id": prompt_id,
            "agent_id": agent_id,
            "agent_type": agent_type,
        }

    # ------------------------------------------------------------------
    # PreToolUse gate
    # ------------------------------------------------------------------

    def test_gate_denies_unarmed_governed_spawn_without_state_writes(self) -> None:
        task_id = "claude-gate-unarmed"
        self.init_task(task_id, session_id="harness-test-chief")
        before = self.task_state(task_id)
        decision = self.claude_hook(self.pretooluse_payload())
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("packet-arm", output["permissionDecisionReason"])
        after = self.task_state(task_id)
        self.assertEqual(before["revision"], after["revision"])
        self.assertEqual(after.get("subagent_incidents", []), [])

    def test_gate_allows_exactly_one_live_arm(self) -> None:
        task_id = "claude-gate-armed"
        packet_id = "claude-armed-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        decision = self.claude_hook(self.pretooluse_payload())
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn(packet_id, output["permissionDecisionReason"])
        # The gate is read-only: the packet must remain armed for SubagentStart.
        state = self.task_state(task_id)
        self.assertEqual(state["packets"][0]["status"], "armed")

    def test_gate_denies_live_slots_with_stale_exact_authority(self) -> None:
        task_id = "claude-gate-drift"
        self.init_task(task_id, session_id="harness-test-chief")
        cases = (
            (
                "chief",
                lambda attempt: attempt.__setitem__(
                    "chief_epoch", int(attempt["chief_epoch"]) + 1
                ),
                "authority",
            ),
            (
                "plan",
                lambda attempt: attempt.__setitem__("plan_sha256", "f" * 64),
                "authority",
            ),
            (
                "contract",
                lambda attempt: attempt.__setitem__(
                    "packet_contract_sha256", "e" * 64
                ),
                "authority",
            ),
            (
                "topology",
                lambda attempt: attempt.__setitem__(
                    "lane_snapshot", {"lane_id": "forged"}
                ),
                "topology",
            ),
        )
        for label, mutate, expected_reason in cases:
            with self.subTest(label=label):
                packet_id = f"claude-drift-{label}"
                agent_type = f"governed-{label}"
                self.create_hook_packet(task_id, packet_id)
                self.arm(task_id, packet_id, agent_type=agent_type)
                state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
                state = self.task_state(task_id)
                pristine_state = copy.deepcopy(state)
                before_revision = state["revision"]
                packet = next(
                    item for item in state["packets"] if item["packet_id"] == packet_id
                )
                attempt = packet["dispatch_attempts"][0]
                mutate(attempt)
                attempt["arm_authority_sha256"] = (
                    cli_impl._dispatch_attempt_authority_sha256(attempt)
                )
                h.atomic_write_json(state_path, state)

                decision = self.claude_hook(
                    self.pretooluse_payload(subagent_type=agent_type),
                    env_extra={"AOI_CLAUDE_GOVERNED_AGENT_TYPES": agent_type},
                )
                output = decision["hookSpecificOutput"]
                self.assertEqual(output["permissionDecision"], "deny")
                self.assertIn(
                    expected_reason, output["permissionDecisionReason"].lower()
                )
                after = self.task_state(task_id)
                self.assertEqual(after["revision"], before_revision)
                after_packet = next(
                    packet
                    for packet in after["packets"]
                    if packet["packet_id"] == packet_id
                )
                self.assertEqual(after_packet["status"], "armed")
                h.atomic_write_json(state_path, pristine_state)
                self.cli(
                    "packet-disarm",
                    "--task",
                    task_id,
                    "--packet-id",
                    packet_id,
                    "--reason",
                    "test cleanup after read-only stale-arm gate",
                )

    def test_gate_denies_expired_arm(self) -> None:
        task_id = "claude-gate-expired"
        packet_id = "claude-expired-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        stale = (
            dt.datetime.now().astimezone() - dt.timedelta(minutes=1)
        ).isoformat(timespec="microseconds")
        state["packets"][0]["dispatch_attempts"][0]["expires_at"] = stale
        h.atomic_write_json(state_path, state)
        decision = self.claude_hook(self.pretooluse_payload())
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("expired", output["permissionDecisionReason"])

    def test_gate_denies_corrupt_session_mapping(self) -> None:
        task_id = "claude-gate-corrupt"
        self.init_task(task_id, session_id="harness-test-chief")
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        before = state["revision"]
        # Break the session_id<->session_ids backlink so session_state() -> corrupt.
        state["session_ids"] = [
            sid for sid in state.get("session_ids", []) if sid != "harness-test-chief"
        ]
        h.atomic_write_json(state_path, state)
        decision = self.claude_hook(self.pretooluse_payload())
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("corrupt", output["permissionDecisionReason"])
        # The gate stays read-only even on the fail-closed deny path.
        self.assertEqual(self.task_state(task_id)["revision"], before)

    def test_gate_denies_nested_governed_spawn(self) -> None:
        task_id = "claude-gate-nested"
        self.init_task(task_id, session_id="harness-test-chief")
        decision = self.claude_hook(
            self.pretooluse_payload(agent_id="agent-depth-one-live")
        )
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("depth-two", output["permissionDecisionReason"])

    def test_gate_allows_nested_governed_spawn_when_session_is_unbound(self) -> None:
        decision = self.claude_hook(
            self.pretooluse_payload(
                session_id="never-bound-nested",
                agent_id="ambient-parent-agent",
            )
        )
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn("not bound", output["permissionDecisionReason"])

    def test_gate_announces_passthrough_and_stays_silent_for_other_tools(self) -> None:
        task_id = "claude-gate-passthrough"
        self.init_task(task_id, session_id="harness-test-chief")
        # Unbound session: not gated, but the dispatch is announced (agent + task).
        unbound = self.claude_hook(
            self.pretooluse_payload(session_id="never-bound-session")
        )
        unbound_out = unbound["hookSpecificOutput"]
        self.assertEqual(unbound_out["permissionDecision"], "allow")
        self.assertIn("general-purpose", unbound_out["permissionDecisionReason"])
        self.assertIn("governed dispatch probe", unbound_out["permissionDecisionReason"])
        # Ambient (ungoverned) agent type: announced as ungoverned, still allowed.
        ambient = self.claude_hook(self.pretooluse_payload(subagent_type="Explore"))
        ambient_out = ambient["hookSpecificOutput"]
        self.assertEqual(ambient_out["permissionDecision"], "allow")
        self.assertIn("ungoverned", ambient_out["permissionDecisionReason"])
        self.assertIn("Explore", ambient_out["permissionDecisionReason"])
        # A non-Agent tool is untouched (silent pass-through).
        other_tool = self.claude_hook(self.pretooluse_payload(tool_name="Bash"))
        self.assertEqual(other_tool, {"continue": True})

    def test_gate_env_override_changes_governed_set(self) -> None:
        task_id = "claude-gate-env"
        self.init_task(task_id, session_id="harness-test-chief")
        env_extra = {"AOI_CLAUDE_GOVERNED_AGENT_TYPES": "explorer, reviewer"}
        governed = self.claude_hook(
            self.pretooluse_payload(subagent_type="explorer"), env_extra=env_extra
        )
        self.assertEqual(
            governed["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        released = self.claude_hook(
            self.pretooluse_payload(subagent_type="general-purpose"),
            env_extra=env_extra,
        )
        released_out = released["hookSpecificOutput"]
        self.assertEqual(released_out["permissionDecision"], "allow")
        self.assertIn("ungoverned", released_out["permissionDecisionReason"])

    # ------------------------------------------------------------------
    # SubagentStart consumption
    # ------------------------------------------------------------------

    def test_subagent_start_consumes_arm_with_claude_provenance(self) -> None:
        task_id = "claude-observed-dispatch"
        packet_id = "claude-observed-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        event = self.start_payload()
        observed = self.claude_hook(event)
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn(packet_id, context)
        self.assertIn("valid pre-armed dispatch", context)
        self.assertIn("Claude transport", context)
        state = self.task_state(task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        self.assertEqual(
            packet["dispatch_provenance"], "claude_subagent_start_observed"
        )
        observation = packet["dispatch_attempts"][0]["observation"]
        self.assertEqual(observation["agent_id"], "agent-claude-0001")
        self.assertEqual(observation["turn_id"], "prompt-start-1")
        self.assertEqual(packet["agent_id"], "agent-claude-0001")
        # Idempotent replay does not advance state.
        revision = state["revision"]
        replay = self.claude_hook(event)
        self.assertIn(
            packet_id, replay["hookSpecificOutput"]["additionalContext"]
        )
        self.assertEqual(self.task_state(task_id)["revision"], revision)
        # Tampered packet/observation binding is a doctor-visible error.
        tampered = copy.deepcopy(state)
        tampered["packets"][0]["agent_id"] = "agent-forged"
        self.assertTrue(
            any(
                "packet/observation binding" in error
                for error in cli_impl.packet_integrity_errors(
                    h.get_paths(self.root), tampered
                )
            )
        )
        # Terminal accounting surfaces the observed timing for capacity records.
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--status",
            "done",
            "--summary",
            "The observed read-only packet returned its bounded conclusion",
            "--evidence",
            "The result is bound to the consumed SubagentStart observation",
        )
        terminal_state = self.task_state(task_id)
        record = cli_impl._capacity_records(terminal_state, "", "general")[0]
        observed_at = terminal_state["packets"][0]["dispatch_attempts"][0][
            "observation"
        ]["observed_at"]
        self.assertEqual(
            record["dispatch_provenance"], "claude_subagent_start_observed"
        )
        self.assertEqual(record["subagent_start_observed_at"], observed_at)
        self.assertEqual(record["dispatch_recorded_at"], observed_at)

    def test_unarmed_governed_start_records_accountable_incident(self) -> None:
        task_id = "claude-unmanaged-start"
        self.init_task(task_id, session_id="harness-test-chief")
        observed = self.claude_hook(self.start_payload())
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("without one valid, unique pre-armed packet", context)
        state = self.task_state(task_id)
        incidents = state.get("subagent_incidents", [])
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["kind"], "unmanaged_subagent_start")
        self.assertEqual(incident["reason_code"], "no_matching_arm")
        self.assertEqual(incident["agent_type"], "general-purpose")
        self.cli(
            "subagent-incident-account",
            "--task",
            task_id,
            "--incident-id",
            incident["incident_id"],
            "--disposition",
            "no_material_work",
            "--reason",
            "The gate was bypassed by a runtime path without PreToolUse coverage",
            "--evidence",
            "The spawned agent stopped without material work per hook instruction",
            "--session-id",
            "harness-test-chief",
        )
        accounted = self.task_state(task_id)["subagent_incidents"][0]
        self.assertEqual(accounted["status"], "accounted")

    def test_ambient_start_passes_through_without_incident(self) -> None:
        task_id = "claude-ambient-start"
        self.init_task(task_id, session_id="harness-test-chief")
        before = self.task_state(task_id)
        observed = self.claude_hook(
            self.start_payload(agent_type="workflow-subagent")
        )
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("ambient sub-agent start", context)
        self.assertIn("never packet evidence", context)
        after = self.task_state(task_id)
        self.assertEqual(before["revision"], after["revision"])
        self.assertEqual(after.get("subagent_incidents", []), [])

    def test_ambient_type_with_expired_arm_records_one_accountable_incident(
        self,
    ) -> None:
        """Pin the ambient+expired-arm boundary: an expired arm was still an
        explicit Chief arm for that exact slot, so the start is routed into the
        core exactly once and recorded as an accountable expired_arm incident;
        the sweep then returns the packet to ready, and the next ambient start
        of the same type passes through silently."""
        task_id = "claude-ambient-expired"
        packet_id = "claude-ambient-expired-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id, agent_type="Explore")
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        state = self.task_state(task_id)
        stale = (
            dt.datetime.now().astimezone() - dt.timedelta(minutes=1)
        ).isoformat(timespec="microseconds")
        state["packets"][0]["dispatch_attempts"][0]["expires_at"] = stale
        h.atomic_write_json(state_path, state)
        observed = self.claude_hook(self.start_payload(agent_type="Explore"))
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("without one valid, unique pre-armed packet", context)
        self.assertIn("expired_arm", context)
        after = self.task_state(task_id)
        incidents = after.get("subagent_incidents", [])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["reason_code"], "expired_arm")
        self.assertEqual(after["packets"][0]["status"], "ready")
        # One-shot: the swept slot no longer routes ambient starts into core.
        revision = after["revision"]
        replayed = self.claude_hook(
            self.start_payload(agent_type="Explore", agent_id="agent-claude-0002")
        )
        replay_context = replayed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("ambient sub-agent start", replay_context)
        self.assertEqual(self.task_state(task_id)["revision"], revision)

    def test_ambient_type_with_explicit_arm_is_consumed(self) -> None:
        task_id = "claude-ambient-armed"
        packet_id = "claude-ambient-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id, agent_type="Explore")
        observed = self.claude_hook(self.start_payload(agent_type="Explore"))
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn(packet_id, context)
        packet = self.task_state(task_id)["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        self.assertEqual(
            packet["dispatch_provenance"], "claude_subagent_start_observed"
        )

    # ------------------------------------------------------------------
    # Shared lifecycle handlers and adapter plumbing
    # ------------------------------------------------------------------

    def test_session_start_and_stop_delegate_to_shared_handlers(self) -> None:
        task_id = "claude-shared-handlers"
        self.init_task(task_id, session_id="harness-test-chief")
        started = self.claude_hook(
            {
                "hook_event_name": "SessionStart",
                "session_id": "harness-test-chief",
                "source": "startup",
            }
        )
        context = started["hookSpecificOutput"]["additionalContext"]
        self.assertIn("AOI is active", context)
        self.assertIn(task_id, context)
        stopped = self.claude_hook(
            {
                "hook_event_name": "Stop",
                "session_id": "harness-test-chief",
                "stop_hook_active": False,
            }
        )
        self.assertEqual(stopped.get("decision"), "block")
        self.assertIn("checkpoint", stopped.get("reason", ""))

    def test_unsupported_hook_version_fails_open(self) -> None:
        outcome = self.claude_hook(self.pretooluse_payload(), hook_version="9")
        self.assertEqual(outcome, {"continue": True})

    def test_unknown_event_fails_open(self) -> None:
        outcome = self.claude_hook(
            {"hook_event_name": "SubagentStop", "session_id": "harness-test-chief"}
        )
        self.assertEqual(outcome, {"continue": True})
