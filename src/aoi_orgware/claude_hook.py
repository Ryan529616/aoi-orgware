#!/usr/bin/env python3
"""Tiny, fail-open, opt-in Claude Code hook adapter for AOI.

Transport mapping (dispatch protocol v6, Claude adapter v1):

- ``PreToolUse`` on the ``Agent`` tool is a *pre-spawn gate*. For governed
  agent types it denies a spawn that has no exact live arm, before the
  sub-agent exists. Codex has no pre-spawn control; this gate is therefore
  strictly stronger, but it is still a cooperative guardrail, not a sandbox.
- ``SubagentStart`` consumes the arm exactly like the Codex adapter and is
  the only mutation point. The payload carries the same coordinates
  (parent ``session_id``, ``agent_id``, ``agent_type``); Claude's
  ``prompt_id`` fills the protocol's turn slot. Provenance is recorded as
  ``claude_subagent_start_observed``, never as a Codex observation.
- Ambient agent types (research/analysis helpers, ``workflow-subagent``)
  outside ``AOI_CLAUDE_GOVERNED_AGENT_TYPES`` pass through without arms or
  incidents unless the Chief explicitly armed that exact slot. Their output
  is Chief-side engineering inference and never packet evidence.
- ``SessionStart``/``UserPromptSubmit``/``Stop`` share the Codex adapter's
  runtime-neutral handlers verbatim.

Workflow-orchestrated spawns bypass ``PreToolUse`` (observed empirically);
the ``SubagentStart`` path still sees them, which is why arm consumption and
incident recording live there and not in the gate.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path
from typing import Any

from .codex_hook import (
    SAFE_DISPLAY_ID,
    allow,
    read_input,
    root_path,
    session_start,
    session_state,
    stop,
    user_prompt_submit,
    write_output,
)
from .harnesslib import get_paths


SUPPORTED_HOOK_VERSION = "1"
GOVERNED_AGENT_TYPES_ENV = "AOI_CLAUDE_GOVERNED_AGENT_TYPES"
DEFAULT_GOVERNED_AGENT_TYPES = ("general-purpose",)
AGENT_TOOL_NAME = "Agent"


def governed_agent_types() -> frozenset[str]:
    raw = os.environ.get(GOVERNED_AGENT_TYPES_ENV, "")
    if not raw.strip():
        return frozenset(DEFAULT_GOVERNED_AGENT_TYPES)
    return frozenset(
        item.strip() for item in raw.split(",") if item.strip()
    )


def pretooluse_decision(decision: str, reason: str) -> None:
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )


def _live_arm_slots(
    state: dict[str, Any], *, parent_session_id: str, agent_type: str
) -> tuple[list[str], list[str]]:
    """Read-only scan: (live packet ids, expired-by-clock packet ids) for one slot."""

    current = dt.datetime.now().astimezone()
    live: list[str] = []
    expired: list[str] = []
    for packet in state.get("packets", []):
        if packet.get("status") != "armed":
            continue
        for attempt in packet.get("dispatch_attempts", []):
            if not isinstance(attempt, dict) or attempt.get("status") != "armed":
                continue
            if (
                attempt.get("parent_session_id") != parent_session_id
                or attempt.get("expected_agent_type") != agent_type
            ):
                continue
            packet_id = str(packet.get("packet_id", ""))
            try:
                expires_at = dt.datetime.fromisoformat(
                    str(attempt.get("expires_at", ""))
                )
            except ValueError:
                expired.append(packet_id)
                continue
            if expires_at.tzinfo is None or expires_at <= current:
                expired.append(packet_id)
            else:
                live.append(packet_id)
    return live, expired


def _armed_slot_exists(
    root: Path, parent_session_id: str, agent_type: str
) -> bool:
    mapping_status, mapped = session_state(root, parent_session_id)
    if mapping_status not in {"valid", "subagent_parent"} or mapped is None:
        return False
    live, expired = _live_arm_slots(
        mapped[0], parent_session_id=parent_session_id, agent_type=agent_type
    )
    return bool(live or expired)


def pre_tool_use(root: Path, payload: dict[str, Any]) -> None:
    if str(payload.get("tool_name", "")) != AGENT_TOOL_NAME:
        allow()
        return
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    subagent_type = str(tool_input.get("subagent_type", ""))
    session_id = str(payload.get("session_id", ""))
    description = str(tool_input.get("description", "")).strip()
    task_suffix = f" for: {description}" if description else ""
    if subagent_type not in governed_agent_types():
        # Ungoverned agent type: not gated, but still announce the dispatch so the
        # spawn (what agent, what task) is visible rather than silent.
        pretooluse_decision(
            "allow",
            f"AOI: dispatching ungoverned sub-agent {subagent_type!r}{task_suffix}. "
            "Ambient Chief-side tooling; its output is engineering inference, not "
            "packet evidence.",
        )
        return
    mapping_status, mapped = session_state(root, session_id)
    if mapping_status == "unbound":
        # Not an AOI-bound session: governance does not apply. Announce and allow.
        pretooluse_decision(
            "allow",
            f"AOI: dispatching {subagent_type!r}{task_suffix}. This session is not "
            "bound to an AOI task, so the dispatch is not packet-gated; bind a task "
            "to govern sub-agent dispatch.",
        )
        return
    if mapping_status not in {"valid", "subagent_parent"} or mapped is None:
        pretooluse_decision(
            "deny",
            "AOI session mapping is corrupt or inconsistent; run `aoi doctor` and "
            "repair or rebind the session before dispatching a governed sub-agent.",
        )
        return
    if str(payload.get("agent_id", "")):
        pretooluse_decision(
            "deny",
            "A depth-one agent tried to spawn a nested governed sub-agent. The "
            "Claude adapter v1 does not hook-verify depth-two spawns; the Chief "
            "must arm and register depth-two packets through the manual dispatch "
            "path instead.",
        )
        return
    live, expired = _live_arm_slots(
        mapped[0], parent_session_id=session_id, agent_type=subagent_type
    )
    if len(live) == 1:
        pretooluse_decision(
            "allow",
            f"AOI pre-armed dispatch: packet {live[0]} is armed for this "
            f"parent-session/agent-type slot ({subagent_type}){task_suffix}. The "
            "following SubagentStart observation consumes the arm.",
        )
        return
    if live:
        pretooluse_decision(
            "deny",
            "AOI found more than one live arm for this parent-session/agent-type "
            "slot; the state is inconsistent. Run `aoi doctor` before dispatching.",
        )
        return
    if expired:
        pretooluse_decision(
            "deny",
            f"The AOI packet arm for this slot expired ({', '.join(expired)}). "
            "Re-arm the packet with `aoi packet-arm` and spawn again.",
        )
        return
    pretooluse_decision(
        "deny",
        f"No AOI packet is armed for governed agent type {subagent_type!r} in "
        "this bound session. Create and arm a bounded packet first "
        "(`aoi create-packet` + `aoi packet-arm`), or use an ungoverned agent "
        "type for Chief-side ambient analysis.",
    )


def subagent_start(root: Path, payload: dict[str, Any]) -> None:
    raw_agent_type = str(payload.get("agent_type", ""))
    display_agent_type = (
        raw_agent_type if SAFE_DISPLAY_ID.fullmatch(raw_agent_type) else "subagent"
    )
    session_id = str(payload.get("session_id", ""))
    paths = get_paths(root)
    if raw_agent_type not in governed_agent_types() and not _armed_slot_exists(
        root, session_id, raw_agent_type
    ):
        write_output(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SubagentStart",
                    "additionalContext": (
                        f"AOI: ambient sub-agent start ({display_agent_type}) in "
                        f"{paths.project.name!r}. This agent is ungoverned "
                        "Chief-side tooling: its output is engineering inference "
                        "for the Chief and never packet evidence. Do not mutate "
                        f"AOI state under {paths.harness} and do not present "
                        "conclusions as verified task results."
                    ),
                }
            }
        )
        return
    protocol_payload = {
        "hook_event_name": "SubagentStart",
        "session_id": session_id,
        # Claude has no per-turn id in this event; prompt_id is the turn analog.
        "turn_id": str(payload.get("prompt_id", "")),
        "agent_id": str(payload.get("agent_id", "")),
        "agent_type": raw_agent_type,
        "permission_mode": str(payload.get("permission_mode", "")),
    }
    # Import lazily so ordinary hook startup remains tiny and bytecode-free.
    from .cli import observe_claude_subagent_start

    outcome = observe_claude_subagent_start(paths, protocol_payload)
    status = outcome.get("status")
    if status == "authorized":
        context = (
            f"AOI observed a valid pre-armed dispatch for {paths.project.name!r}: "
            f"task={outcome.get('task_id')}, packet={outcome.get('packet_id')}, "
            f"contract={outcome.get('packet_path')}. Claude transport "
            f"agent_type={display_agent_type}; the AOI technical role is defined by the "
            "packet contract. Read that exact packet before work and stay inside its "
            "scope. The root owns AOI state, claims, plan, checkpoint, and final "
            f"completion; do not edit {paths.harness}. Return a bounded conclusion "
            "with exact evidence/artifact paths, files inspected or changed, "
            "verification, unresolved risks, and one next action; never paste raw logs."
        )
    elif status == "incident":
        context = (
            "AOI observed this sub-agent start without one valid, unique pre-armed "
            f"packet. Incident={outcome.get('incident_id')}; "
            f"reason={outcome.get('reason_code')}. The start already occurred and "
            "this hook cannot terminate it. Stop without material work, do not "
            "inspect or edit project files, and report the incident id to the "
            "parent so the Chief can account it explicitly."
        )
    elif status == "corrupt":
        context = (
            "AOI could not validate the parent task mapping or packet authority for "
            f"this start; reason={outcome.get('reason_code')}. Stop without material "
            "work and report the corrupt authority to the parent. This hook observes "
            "starts but cannot terminate an already-created sub-agent."
        )
    else:
        context = (
            "AOI found no task mapping for the parent session, so it could not "
            "consume a packet arm or persist a task incident. Stop without material "
            "work and ask the parent to bind a task and arm an exact packet before "
            "retrying."
        )
    if outcome.get("index_refresh_deferred") is True:
        context += (
            " AOI committed the target task event but deferred the derived INDEX "
            "refresh; report this to the parent so the Chief can run doctor/status."
        )
    if outcome.get("parent_mapping_deferred") is True:
        context += (
            " AOI could not publish this depth-one agent's parent-only mapping; do "
            "not spawn a child and report the condition to the Chief."
        )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": context,
            }
        }
    )


def dispatch(payload: dict[str, Any]) -> None:
    root = root_path()
    event = str(payload.get("hook_event_name", ""))
    if event == "SessionStart":
        session_start(root, payload)
    elif event == "UserPromptSubmit":
        user_prompt_submit(root, payload)
    elif event == "PreToolUse":
        pre_tool_use(root, payload)
    elif event == "SubagentStart":
        subagent_start(root, payload)
    elif event == "Stop":
        stop(root, payload)
    else:
        allow()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optional fail-open Claude Code lifecycle adapter for AOI"
    )
    parser.add_argument("--hook-version", required=True)
    args = parser.parse_args()
    if args.hook_version != SUPPORTED_HOOK_VERSION:
        allow()
        return 0
    try:
        dispatch(read_input())
    except Exception:
        # Hooks must never strand a task because the local harness is missing or
        # malformed. Doctor/status expose the defect on the next normal turn.
        allow()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
