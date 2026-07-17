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

    def arm_wildcard(self, task_id: str, packet_id: str) -> None:
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
                "--any-agent-type",
                "--expires-at",
                expires_at,
                "--json",
            ).stdout
        )
        self.assertEqual(armed["status"], "armed")
        self.assertEqual(armed["expected_agent_type"], "*")

    def create_budget_packet(
        self, task_id: str, packet_id: str, budget: int
    ) -> None:
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
            "Inspect one bounded source question and delegate read-only helpers",
            "--scope",
            "Read-only packet permitted a bounded depth-two helper budget",
            "--deliverable",
            "One evidence-backed conclusion and exact inspected paths",
            "--validation",
            "The parent checks the conclusion against the named source paths",
            "--helper-spawn-budget",
            str(budget),
        )

    def dispatch_parent_agent(
        self, task_id: str, packet_id: str, parent_agent_id: str
    ) -> None:
        """Arm + observe a depth-one packet so its agent gains a parent mapping."""

        self.arm(task_id, packet_id)
        observed = self.claude_hook(
            self.start_payload(agent_id=parent_agent_id, prompt_id="parent-start")
        )
        self.assertIn(
            "valid pre-armed dispatch",
            observed["hookSpecificOutput"]["additionalContext"],
        )

    def pretooluse_payload(
        self,
        *,
        session_id: str = "harness-test-chief",
        subagent_type: str = "general-purpose",
        tool_name: str = "Agent",
        agent_id: str = "",
        model: str = "",
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
        if model:
            payload["tool_input"]["model"] = model
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
        decision = self.claude_hook(self.pretooluse_payload(model="sonnet"))
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn(packet_id, output["permissionDecisionReason"])
        self.assertIn(
            "within tier 'standard'", output["permissionDecisionReason"]
        )
        # The gate is read-only: the packet must remain armed for SubagentStart.
        state = self.task_state(task_id)
        self.assertEqual(state["packets"][0]["status"], "armed")

    def test_gate_denies_authorized_dispatch_without_model(self) -> None:
        task_id = "claude-gate-no-model"
        packet_id = "claude-no-model-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        decision = self.claude_hook(self.pretooluse_payload())
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("requires an explicit model", output["permissionDecisionReason"])
        self.assertIn("Chief session's model", output["permissionDecisionReason"])
        # The deny is read-only: the arm stays live for a corrected dispatch.
        state = self.task_state(task_id)
        self.assertEqual(state["packets"][0]["status"], "armed")

    def test_gate_denies_authorized_dispatch_with_out_of_tier_model(self) -> None:
        task_id = "claude-gate-tier-breach"
        packet_id = "claude-tier-breach-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        decision = self.claude_hook(self.pretooluse_payload(model="opus"))
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("outside packet tier 'standard'", output["permissionDecisionReason"])
        state = self.task_state(task_id)
        self.assertEqual(state["packets"][0]["status"], "armed")

    def test_gate_matches_fully_qualified_model_ids_by_family(self) -> None:
        task_id = "claude-gate-full-id"
        packet_id = "claude-full-id-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        decision = self.claude_hook(
            self.pretooluse_payload(model="claude-sonnet-5")
        )
        output = decision["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn("within tier 'standard'", output["permissionDecisionReason"])

    def test_gate_tier_model_families_env_override(self) -> None:
        task_id = "claude-gate-tier-env"
        packet_id = "claude-tier-env-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        env_extra = {"AOI_CLAUDE_TIER_MODELS": '{"standard": ["opus"]}'}
        allowed = self.claude_hook(
            self.pretooluse_payload(model="opus"), env_extra=env_extra
        )
        self.assertEqual(
            allowed["hookSpecificOutput"]["permissionDecision"], "allow"
        )
        denied = self.claude_hook(
            self.pretooluse_payload(model="sonnet"), env_extra=env_extra
        )
        denied_out = denied["hookSpecificOutput"]
        self.assertEqual(denied_out["permissionDecision"], "deny")
        self.assertIn("outside packet tier", denied_out["permissionDecisionReason"])

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
    # B1 wildcard arm
    # ------------------------------------------------------------------

    def test_wildcard_arm_consumes_any_transport_type(self) -> None:
        task_id = "claude-wildcard"
        packet_id = "claude-wildcard-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm_wildcard(task_id, packet_id)
        # An ungoverned transport type still routes into core because the
        # wildcard arm owns the parent slot.
        observed = self.claude_hook(self.start_payload(agent_type="default"))
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn(packet_id, context)
        self.assertIn("valid pre-armed dispatch", context)
        state = self.task_state(task_id)
        packet = state["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        attempt = packet["dispatch_attempts"][0]
        self.assertEqual(attempt["expected_agent_type"], "*")
        self.assertEqual(attempt["observation"]["agent_type"], "default")
        # The consumed wildcard observation passes doctor-visible integrity.
        self.assertEqual(
            cli_impl.packet_integrity_errors(h.get_paths(self.root), state), []
        )

    def test_wildcard_collides_with_an_existing_exact_arm(self) -> None:
        task_id = "claude-collide-wild"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, "exact-packet")
        self.create_hook_packet(task_id, "wild-packet")
        self.arm(task_id, "exact-packet", agent_type="general-purpose")
        expires = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        blocked = self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            "wild-packet",
            "--any-agent-type",
            "--expires-at",
            expires,
            ok=False,
        )
        self.assertIn("already occupies", blocked.stderr)

    def test_exact_type_collides_with_an_existing_wildcard_arm(self) -> None:
        task_id = "claude-collide-exact"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, "wild-packet")
        self.create_hook_packet(task_id, "exact-packet")
        self.arm_wildcard(task_id, "wild-packet")
        expires = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        blocked = self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            "exact-packet",
            "--expected-agent-type",
            "general-purpose",
            "--expires-at",
            expires,
            ok=False,
        )
        self.assertIn("already occupies", blocked.stderr)

    def test_packet_arm_requires_exactly_one_agent_type_selector(self) -> None:
        task_id = "claude-arm-selector"
        packet_id = "claude-arm-selector-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        expires = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        both = self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--expected-agent-type",
            "general-purpose",
            "--any-agent-type",
            "--expires-at",
            expires,
            ok=False,
        )
        self.assertNotIn("Traceback", both.stderr)
        neither = self.cli(
            "packet-arm",
            "--task",
            task_id,
            "--packet-id",
            packet_id,
            "--expires-at",
            expires,
            ok=False,
        )
        self.assertNotIn("Traceback", neither.stderr)
        # The CLI rejections above are argparse's mutually-exclusive group.
        # The in-handler guard exists for programmatic callers that bypass
        # argparse entirely; exercise it directly so it is not dead code.
        with self.assertRaisesRegex(
            cli_impl.HarnessError,
            "exactly one of --expected-agent-type or --any-agent-type",
        ):
            cli_impl.cmd_packet_arm(
                cli_impl.argparse.Namespace(
                    any_agent_type=True,
                    expected_agent_type="general-purpose",
                ),
                h.get_paths(self.root),
            )

    # ------------------------------------------------------------------
    # B2 resume is not a spawn
    # ------------------------------------------------------------------

    def test_resume_same_parent_is_authorized_not_an_incident(self) -> None:
        task_id = "claude-resume"
        packet_id = "claude-resume-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        self.claude_hook(
            self.start_payload(agent_id="agent-claude-0001", prompt_id="dispatch-1")
        )
        dispatched = self.task_state(task_id)["packets"][0]
        self.assertEqual(dispatched["status"], "dispatched")
        resumed = self.claude_hook(
            self.start_payload(agent_id="agent-claude-0001", prompt_id="resume-2")
        )
        context = resumed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("resumed dispatch", context)
        after = self.task_state(task_id)
        packet = after["packets"][0]
        self.assertEqual(packet["status"], "dispatched")
        self.assertEqual(len(packet["agent_resumptions"]), 1)
        self.assertEqual(packet["agent_resumptions"][0]["turn_id"], "resume-2")
        self.assertEqual(
            cli_impl.packet_integrity_errors(h.get_paths(self.root), after), []
        )
        # Replaying the same resume event is idempotent.
        revision = after["revision"]
        replay = self.claude_hook(
            self.start_payload(agent_id="agent-claude-0001", prompt_id="resume-2")
        )
        self.assertIn("resumed dispatch", replay["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.task_state(task_id)["revision"], revision)

    def test_same_agent_id_from_a_different_parent_stays_duplicate_incident(
        self,
    ) -> None:
        task_id = "claude-resume-stranger"
        packet_id = "claude-resume-stranger-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        self.arm(task_id, packet_id)
        self.claude_hook(
            self.start_payload(agent_id="agent-claude-0001", prompt_id="dispatch-1")
        )
        # A second root session bound to the same task is a different parent.
        self.cli(
            "bind-session",
            "--task",
            task_id,
            "--session-id",
            "stranger-session",
        )
        observed = self.claude_hook(
            self.start_payload(
                session_id="stranger-session",
                agent_id="agent-claude-0001",
                prompt_id="stranger-3",
            )
        )
        context = observed["hookSpecificOutput"]["additionalContext"]
        self.assertIn("without one valid, unique pre-armed packet", context)
        incident = self.task_state(task_id)["subagent_incidents"][-1]
        self.assertEqual(incident["reason_code"], "duplicate_agent")
        packet = self.task_state(task_id)["packets"][0]
        self.assertEqual(packet.get("agent_resumptions", []), [])

    # ------------------------------------------------------------------
    # B3 depth-two helper spawn budget
    # ------------------------------------------------------------------

    def test_helper_budget_authorizes_bounded_depth_two_spawns(self) -> None:
        task_id = "claude-helper"
        packet_id = "claude-helper-parent"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 2)
        self.dispatch_parent_agent(task_id, packet_id, "parent-agent-1")
        for index, remaining in ((1, 1), (2, 0)):
            observed = self.claude_hook(
                self.start_payload(
                    session_id="parent-agent-1",
                    agent_id=f"helper-{index}",
                    agent_type="general-purpose",
                    prompt_id=f"helper-{index}",
                )
            )
            context = observed["hookSpecificOutput"]["additionalContext"]
            self.assertIn("budgeted depth-two helper", context)
            self.assertIn(f"remaining helper budget={remaining}", context)
        packet = self.task_state(task_id)["packets"][0]
        self.assertEqual(len(packet["helper_spawns"]), 2)
        self.assertEqual(
            cli_impl.packet_integrity_errors(
                h.get_paths(self.root), self.task_state(task_id)
            ),
            [],
        )
        # The third spawn exceeds the budget and becomes an accountable incident.
        exceeded = self.claude_hook(
            self.start_payload(
                session_id="parent-agent-1",
                agent_id="helper-3",
                agent_type="general-purpose",
                prompt_id="helper-3",
            )
        )
        self.assertIn(
            "without one valid, unique pre-armed packet",
            exceeded["hookSpecificOutput"]["additionalContext"],
        )
        incident = self.task_state(task_id)["subagent_incidents"][-1]
        self.assertEqual(incident["reason_code"], "helper_budget_exhausted")
        self.assertEqual(len(self.task_state(task_id)["packets"][0]["helper_spawns"]), 2)

    def test_helper_spawn_replay_is_idempotent(self) -> None:
        task_id = "claude-helper-replay"
        packet_id = "claude-helper-replay-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 2)
        self.dispatch_parent_agent(task_id, packet_id, "parent-agent-1")
        event = self.start_payload(
            session_id="parent-agent-1",
            agent_id="helper-1",
            agent_type="general-purpose",
            prompt_id="helper-1",
        )
        self.claude_hook(event)
        revision = self.task_state(task_id)["revision"]
        replay = self.claude_hook(event)
        self.assertIn(
            "budgeted depth-two helper",
            replay["hookSpecificOutput"]["additionalContext"],
        )
        self.assertEqual(self.task_state(task_id)["revision"], revision)
        self.assertEqual(len(self.task_state(task_id)["packets"][0]["helper_spawns"]), 1)

    def test_zero_budget_depth_two_helper_records_incident(self) -> None:
        task_id = "claude-helper-zero"
        packet_id = "claude-helper-zero-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 0)
        self.dispatch_parent_agent(task_id, packet_id, "parent-agent-1")
        observed = self.claude_hook(
            self.start_payload(
                session_id="parent-agent-1",
                agent_id="helper-1",
                agent_type="general-purpose",
                prompt_id="helper-1",
            )
        )
        self.assertIn(
            "without one valid, unique pre-armed packet",
            observed["hookSpecificOutput"]["additionalContext"],
        )
        incident = self.task_state(task_id)["subagent_incidents"][-1]
        self.assertEqual(incident["reason_code"], "no_helper_budget")

    def test_pretooluse_depth_two_allows_with_helper_budget(self) -> None:
        task_id = "claude-helper-gate"
        packet_id = "claude-helper-gate-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 1)
        self.dispatch_parent_agent(task_id, packet_id, "parent-agent-1")
        allowed = self.claude_hook(
            self.pretooluse_payload(
                session_id="parent-agent-1",
                subagent_type="general-purpose",
                agent_id="parent-agent-1",
                model="haiku",
            )
        )
        allowed_out = allowed["hookSpecificOutput"]
        self.assertEqual(allowed_out["permissionDecision"], "allow")
        self.assertIn("helper-budget dispatch", allowed_out["permissionDecisionReason"])

    def test_pretooluse_depth_two_denies_model_over_parent_tier(self) -> None:
        task_id = "claude-helper-tier-cap"
        packet_id = "claude-helper-tier-cap-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 1)
        self.dispatch_parent_agent(task_id, packet_id, "parent-agent-1")
        denied = self.claude_hook(
            self.pretooluse_payload(
                session_id="parent-agent-1",
                subagent_type="general-purpose",
                agent_id="parent-agent-1",
                model="opus",
            )
        )
        denied_out = denied["hookSpecificOutput"]
        self.assertEqual(denied_out["permissionDecision"], "deny")
        self.assertIn("capped at the parent", denied_out["permissionDecisionReason"])
        self.assertIn("outside packet tier 'standard'", denied_out["permissionDecisionReason"])

    def test_pretooluse_depth_two_denies_without_helper_budget(self) -> None:
        task_id = "claude-helper-gate-zero"
        packet_id = "claude-helper-gate-zero-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 0)
        self.dispatch_parent_agent(task_id, packet_id, "parent-agent-1")
        denied = self.claude_hook(
            self.pretooluse_payload(
                session_id="parent-agent-1",
                subagent_type="general-purpose",
                agent_id="parent-agent-1",
            )
        )
        denied_out = denied["hookSpecificOutput"]
        self.assertEqual(denied_out["permissionDecision"], "deny")
        self.assertIn("--helper-spawn-budget", denied_out["permissionDecisionReason"])

    def test_helper_spawn_budget_field_is_contract_sealed(self) -> None:
        task_id = "claude-helper-seal"
        packet_id = "claude-helper-seal-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 3)
        state = self.task_state(task_id)
        self.assertEqual(state["packets"][0]["helper_spawn_budget"], 3)
        self.assertEqual(
            cli_impl.packet_integrity_errors(h.get_paths(self.root), state), []
        )
        # Silently raising the budget in state without rewriting the sealed
        # contract is a doctor-visible error.
        raised = copy.deepcopy(state)
        raised["packets"][0]["helper_spawn_budget"] = 7
        self.assertTrue(
            any(
                "helper spawn budget" in error
                for error in cli_impl.packet_integrity_errors(
                    h.get_paths(self.root), raised
                )
            )
        )
        # Dropping the field while the contract still declares it is also caught.
        dropped = copy.deepcopy(state)
        dropped["packets"][0]["helper_spawn_budget"] = 0
        self.assertTrue(
            any(
                "helper spawn budget" in error
                for error in cli_impl.packet_integrity_errors(
                    h.get_paths(self.root), dropped
                )
            )
        )

    # ------------------------------------------------------------------
    # B4 guard outcome measurability
    # ------------------------------------------------------------------

    def test_incident_records_live_arms_and_guard_metrics(self) -> None:
        task_id = "claude-guard-metrics"
        packet_id = "claude-guard-metrics-packet"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_hook_packet(task_id, packet_id)
        # The exact ARISE shape: armed under an AOI role label, observed as a
        # governed transport that never intersects it.
        self.arm(task_id, packet_id, agent_type="eda_operator")
        observed = self.claude_hook(self.start_payload(agent_type="general-purpose"))
        self.assertIn(
            "without one valid, unique pre-armed packet",
            observed["hookSpecificOutput"]["additionalContext"],
        )
        incident = self.task_state(task_id)["subagent_incidents"][-1]
        self.assertEqual(incident["reason_code"], "no_matching_arm")
        self.assertEqual(len(incident["live_arms"]), 1)
        self.assertEqual(incident["live_arms"][0]["packet_id"], packet_id)
        self.assertEqual(
            incident["live_arms"][0]["expected_agent_type"], "eda_operator"
        )
        # Account it with a machine-readable guard-outcome tag.
        self.cli(
            "subagent-incident-account",
            "--task",
            task_id,
            "--incident-id",
            incident["incident_id"],
            "--disposition",
            "no_material_work",
            "--disposition-kind",
            "false_positive_guard",
            "--reason",
            "Chief armed an AOI role label while the transport reported a different type",
            "--evidence",
            "The spawned agent stopped without material work per hook instruction",
            "--session-id",
            "harness-test-chief",
        )
        accounted = self.task_state(task_id)["subagent_incidents"][-1]
        self.assertEqual(
            accounted["resolution"]["disposition_kind"], "false_positive_guard"
        )
        summary = json.loads(self.cli("status", "--task", task_id, "--json").stdout)
        guard = summary["subagent_guard"]
        self.assertEqual(guard["incidents"], 1)
        self.assertEqual(guard["by_reason"]["no_matching_arm"], 1)
        self.assertEqual(guard["false_positive_guard"], 1)

    # ------------------------------------------------------------------
    # Codex path shares the same dispatch core
    # ------------------------------------------------------------------

    def test_codex_helper_budget_shares_core_observation(self) -> None:
        task_id = "codex-helper"
        packet_id = "codex-helper-parent"
        self.init_task(task_id, session_id="harness-test-chief")
        self.create_budget_packet(task_id, packet_id, 1)
        self.arm(task_id, packet_id, agent_type="default")
        self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "harness-test-chief",
                "turn_id": "codex-parent-turn",
                "agent_id": "codex-parent-1",
                "agent_type": "default",
            }
        )
        self.assertEqual(self.task_state(task_id)["packets"][0]["status"], "dispatched")
        helper = self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "codex-parent-1",
                "turn_id": "codex-helper-turn",
                "agent_id": "codex-helper-1",
                "agent_type": "default",
            }
        )
        context = helper["hookSpecificOutput"]["additionalContext"]
        self.assertIn("budgeted depth-two helper", context)
        self.assertEqual(
            len(self.task_state(task_id)["packets"][0]["helper_spawns"]), 1
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
