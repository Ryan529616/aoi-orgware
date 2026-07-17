#!/usr/bin/env python3
"""WS4 — nested-helper transport canary against recorded hook observations.

Adversarial contract: "helper budget works" may only be claimed from observed
transport behavior. Direct-parent association must consume exactly one slot
per spawn; budget=0 and over-budget spawns must produce their own distinct
incident reason codes; a transport that only exposes the root session id must
yield an explicit unsupported verdict, never a silent pass.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from tests.harness_case import HarnessTestCase  # noqa: E402


class HelperCanaryTests(HarnessTestCase):
    maxDiff = None

    def _task_state(self, task_id: str) -> dict:
        state_path = self.root / ".aoi" / "tasks" / task_id / "state.json"
        return json.loads(state_path.read_text(encoding="utf-8"))

    def _parent_session(self, task_id: str) -> str:
        suffix = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:16]
        return f"dispatch-parent-{suffix}"

    def _window_start(self) -> str:
        return (
            dt.datetime.now().astimezone() - dt.timedelta(minutes=1)
        ).isoformat()

    def _create_parent(self, task_id: str, *, budget: int) -> None:
        args = [
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "parent",
            "--agent-role",
            "worker",
            "--model-tier",
            "advanced",
            "--objective",
            "Own one bounded helper canary probe",
            "--scope",
            "Isolated canary fixture",
            "--deliverable",
            "Canary observations",
            "--validation",
            "Transport probe verdict is recorded",
        ]
        if budget:
            args.extend(["--helper-spawn-budget", str(budget)])
        self.cli(*args)

    def _observe_parent(self, task_id: str) -> None:
        self.arm_packet(task_id, "parent", expected_agent_type="worker")
        outcome = self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": self._parent_session(task_id),
                "turn_id": "turn-parent",
                "agent_id": "/root/parent-agent",
                "agent_type": "worker",
                "permission_mode": "default",
                "model": "gpt-test-terra",
            }
        )
        self.assertIn(
            "valid pre-armed dispatch",
            outcome["hookSpecificOutput"]["additionalContext"],
        )

    def _spawn_child(
        self, *, session_id: str, agent_id: str, model: str = "gpt-test-luna"
    ) -> dict:
        return self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": session_id,
                "turn_id": f"turn-{agent_id.rsplit('/', 1)[-1]}",
                "agent_id": agent_id,
                "agent_type": "helper",
                "permission_mode": "default",
                "model": model,
            }
        )

    def _canary(
        self, task_id: str, window_start: str, *, probe_id: str = "probe-1",
        ok: bool = True
    ):
        return self.cli(
            "codex-helper-canary",
            "--task",
            task_id,
            "--probe-id",
            probe_id,
            "--parent-packet-id",
            "parent",
            "--window-start",
            window_start,
            "--session-id",
            "harness-test-chief",
            "--json",
            ok=ok,
        )

    def test_budget_one_direct_parent_consumes_exactly_once(self) -> None:
        task_id = "canary-supported"
        self.init_task(task_id, session_id="harness-test-chief")
        window = self._window_start()
        self._create_parent(task_id, budget=1)
        self._observe_parent(task_id)
        authorized = self._spawn_child(
            session_id="/root/parent-agent", agent_id="/root/helper-1"
        )
        context = authorized["hookSpecificOutput"]["additionalContext"]
        self.assertIn("budgeted depth-two helper", context)
        self.assertIn("remaining helper budget=0", context)
        # Second spawn under the same parent must NOT get a second slot.
        exhausted = self._spawn_child(
            session_id="/root/parent-agent", agent_id="/root/helper-2"
        )
        self.assertIn(
            "without one valid, unique pre-armed packet",
            exhausted["hookSpecificOutput"]["additionalContext"],
        )
        state = self._task_state(task_id)
        parent = state["packets"][0]
        self.assertEqual(len(parent["helper_spawns"]), 1)
        self.assertEqual(parent["helper_spawns"][0]["model"], "gpt-test-luna")
        incident_reasons = [
            item["reason_code"] for item in state["subagent_incidents"]
        ]
        self.assertEqual(incident_reasons, ["helper_budget_exhausted"])
        probe = json.loads(self._canary(task_id, window).stdout)
        self.assertEqual(probe["verdict"], "supported")
        self.assertEqual(probe["helper_slots_consumed"], 1)
        self.assertEqual(
            probe["evidence"]["helper_observed_models"], ["gpt-test-luna"]
        )

    def test_budget_zero_yields_no_helper_budget_incident(self) -> None:
        task_id = "canary-budget-zero"
        self.init_task(task_id, session_id="harness-test-chief")
        window = self._window_start()
        self._create_parent(task_id, budget=0)
        self._observe_parent(task_id)
        refused = self._spawn_child(
            session_id="/root/parent-agent", agent_id="/root/helper-1"
        )
        self.assertIn(
            "without one valid, unique pre-armed packet",
            refused["hookSpecificOutput"]["additionalContext"],
        )
        state = self._task_state(task_id)
        self.assertEqual(state["packets"][0].get("helper_spawns", []), [])
        self.assertEqual(
            [item["reason_code"] for item in state["subagent_incidents"]],
            ["no_helper_budget"],
        )
        probe = json.loads(self._canary(task_id, window).stdout)
        self.assertEqual(probe["verdict"], "supported_budget_enforced")
        self.assertIn("budget gate refused", probe["basis"])

    def test_root_keyed_spawn_yields_unsupported_verdict(self) -> None:
        task_id = "canary-root-only"
        self.init_task(task_id, session_id="harness-test-chief")
        window = self._window_start()
        self._create_parent(task_id, budget=1)
        self._observe_parent(task_id)
        # Transport limitation simulation: the child spawn is keyed to the
        # ROOT session id, not the depth-one agent's own session.
        self.cli(
            "bind-session",
            "--task",
            task_id,
            "--session-id",
            "root-session-canary",
        )
        refused = self._spawn_child(
            session_id="root-session-canary", agent_id="/root/helper-1"
        )
        self.assertIn(
            "without one valid, unique pre-armed packet",
            refused["hookSpecificOutput"]["additionalContext"],
        )
        state = self._task_state(task_id)
        self.assertEqual(state["packets"][0].get("helper_spawns", []), [])
        self.assertEqual(
            [item["reason_code"] for item in state["subagent_incidents"]],
            ["no_matching_arm"],
        )
        probe = json.loads(self._canary(task_id, window).stdout)
        self.assertEqual(probe["verdict"], "unsupported_root_parent_only")
        self.assertIn("does NOT deliver nested helpers", probe["basis"])
        self.assertEqual(
            probe["evidence"]["root_keyed_incident_ids"],
            [state["subagent_incidents"][0]["incident_id"]],
        )

    def test_refusal_incidents_do_not_cross_contaminate_parents(self) -> None:
        task_id = "canary-scoping"
        self.init_task(task_id, session_id="harness-test-chief")
        window = self._window_start()
        # Parent A: the probe target, zero helper activity. Terminalize it so
        # the single-chain topology admits parent B; the canary evaluates
        # records post-hoc and does not need a live parent.
        self._create_parent(task_id, budget=1)
        self._observe_parent(task_id)
        self.cli(
            "packet-update",
            "--task",
            task_id,
            "--packet-id",
            "parent",
            "--status",
            "done",
            "--typed-outcome",
            "no_material_work",
            "--summary",
            "Probe target completed without helper activity",
            "--evidence",
            "no helper spawn was attempted under this parent",
        )
        # Parent B: a second depth-one packet that hits a budget refusal
        # inside the same window.
        self.cli(
            "create-packet",
            "--task",
            task_id,
            "--packet-id",
            "parent-b",
            "--agent-role",
            "explorer",
            "--model-tier",
            "standard",
            "--objective",
            "Second parent for scoping proof",
            "--scope",
            "Isolated fixture",
            "--deliverable",
            "Refusal incident",
            "--validation",
            "Incident is scoped to parent-b",
        )
        self.arm_packet(
            task_id,
            "parent-b",
            expected_agent_type="explorer",
            parent_session_id="parent-b-dispatcher",
        )
        self.hook(
            {
                "hook_event_name": "SubagentStart",
                "session_id": "parent-b-dispatcher",
                "turn_id": "turn-parent-b",
                "agent_id": "/root/parent-b-agent",
                "agent_type": "explorer",
                "permission_mode": "default",
            }
        )
        refused = self._spawn_child(
            session_id="/root/parent-b-agent", agent_id="/root/helper-b"
        )
        self.assertIn(
            "without one valid, unique pre-armed packet",
            refused["hookSpecificOutput"]["additionalContext"],
        )
        state = self._task_state(task_id)
        incident = state["subagent_incidents"][0]
        self.assertEqual(incident["reason_code"], "no_helper_budget")
        self.assertEqual(incident["helper_parent_packet_id"], "parent-b")
        # Parent A's probe must NOT inherit parent B's refusal.
        probe = json.loads(self._canary(task_id, window).stdout)
        self.assertEqual(probe["verdict"], "unknown")

    def test_empty_window_yields_unknown(self) -> None:
        task_id = "canary-unknown"
        self.init_task(task_id, session_id="harness-test-chief")
        self._create_parent(task_id, budget=1)
        self._observe_parent(task_id)
        future_window = (
            dt.datetime.now().astimezone() + dt.timedelta(minutes=5)
        ).isoformat()
        probe = json.loads(self._canary(task_id, future_window).stdout)
        self.assertEqual(probe["verdict"], "unknown")
        self.assertIn("proves nothing", probe["basis"])

    def test_probe_hygiene_fails_closed(self) -> None:
        task_id = "canary-hygiene"
        self.init_task(task_id, session_id="harness-test-chief")
        window = self._window_start()
        self._create_parent(task_id, budget=1)
        self._observe_parent(task_id)
        self._canary(task_id, window)
        duplicate = self._canary(task_id, window, ok=False)
        self.assertIn("already exists", duplicate.stderr)
        naive = self.cli(
            "codex-helper-canary",
            "--task",
            task_id,
            "--probe-id",
            "probe-naive",
            "--parent-packet-id",
            "parent",
            "--window-start",
            "2026-07-17T09:00:00",
            "--session-id",
            "harness-test-chief",
            ok=False,
        )
        self.assertIn("timezone-aware", naive.stderr)
