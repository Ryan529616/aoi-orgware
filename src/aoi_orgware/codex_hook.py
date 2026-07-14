#!/usr/bin/env python3
"""Tiny, fail-open, opt-in Codex hook adapter for AOI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .harnesslib import get_paths


SUPPORTED_HOOK_VERSION = "6"
SAFE_DISPLAY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HOOK_INPUT_MAX_BYTES = 64 * 1024
ROOT_SESSION_MAPPING_KIND = "root"
SUBAGENT_PARENT_MAPPING_KIND = "subagent_parent"


def root_path() -> Path:
    return get_paths().root


def read_input() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(HOOK_INPUT_MAX_BYTES + 1)
    if len(payload) > HOOK_INPUT_MAX_BYTES:
        raise ValueError("hook payload exceeds the supported size")
    raw = payload.decode("utf-8-sig")
    value = json.loads(raw or "{}")
    return value if isinstance(value, dict) else {}


def write_output(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False) + "\n")


def allow() -> None:
    write_output({"continue": True})


def session_state(
    root: Path, session_id: str
) -> tuple[str, tuple[dict[str, Any], Path] | None]:
    if not session_id:
        return "unbound", None
    if len(session_id) > 512 or "\x00" in session_id:
        return "corrupt", None
    paths = get_paths(root)
    key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    mapping_path = paths.sessions / f"{key}.json"
    if not mapping_path.exists():
        return "unbound", None
    try:
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        if not isinstance(mapping, dict) or mapping.get("session_id") != session_id:
            return "corrupt", None
        task_id = str(mapping.get("task_id", ""))
        if not SAFE_TASK_ID.fullmatch(task_id):
            return "corrupt", None
        task_dir = paths.tasks / task_id
        state_path = task_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("task_id") != task_id:
            return "corrupt", None
        mapping_kind = mapping.get("mapping_kind", ROOT_SESSION_MAPPING_KIND)
        if mapping_kind == ROOT_SESSION_MAPPING_KIND:
            session_ids = state.get("session_ids")
            if not isinstance(session_ids, list) or session_id not in session_ids:
                return "corrupt", None
            return "valid", (state, task_dir)
        if mapping_kind == SUBAGENT_PARENT_MAPPING_KIND:
            parent_ids = state.get("subagent_parent_session_ids")
            packets = state.get("packets")
            if (
                not isinstance(parent_ids, list)
                or session_id not in parent_ids
                or not isinstance(packets, list)
            ):
                return "corrupt", None
            matches = [
                packet
                for packet in packets
                if isinstance(packet, dict)
                and packet.get("packet_id") == mapping.get("packet_id")
                and packet.get("agent_id") == session_id
                and packet.get("delegation_depth", 1) == 1
            ]
            if len(matches) != 1:
                return "corrupt", None
            return "subagent_parent", (state, task_dir)
        return "corrupt", None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return "corrupt", None


def session_start(root: Path, payload: dict[str, Any]) -> None:
    session_id = str(payload.get("session_id", ""))
    source = str(payload.get("source", "startup"))
    mapping_status, mapped = session_state(root, session_id)
    paths = get_paths(root)
    base = (
        f"AOI is active for {paths.project.name!r} at {paths.root}. Read "
        f"{paths.harness / 'POLICY.md'} and the short {paths.index}. Root alone "
        "writes AOI state; use bounded sub-agent packets. This hook is a "
        "procedural guardrail, not a security boundary. "
    )
    if mapping_status == "subagent_parent" and mapped:
        state, _ = mapped
        packet = next(
            item
            for item in state.get("packets", [])
            if isinstance(item, dict) and item.get("agent_id") == session_id
        )
        context = (
            base
            + f"This is the bounded depth-one agent for task {state.get('task_id')}, "
            + f"packet {packet.get('packet_id')} at {packet.get('path')}. This mapping "
            + "permits nested SubagentStart lookup only; it is not Chief/root authority. "
            + "Stay inside the packet, do not mutate AOI state, and do not reuse this "
            + "session for unrelated work. "
        )
    elif mapping_status == "valid" and mapped:
        state, task_dir = mapped
        checkpoint = task_dir / "checkpoint.md"
        status = state.get("status")
        phase = state.get("phase")
        revision = state.get("revision")
        checkpoint_revision = state.get("checkpoint_revision")
        if status not in {"active", "blocked", "done", "cancelled"}:
            status = "unknown"
        if phase not in {
            "planning",
            "gathering",
            "diagnosing",
            "implementing",
            "waiting_external",
            "verifying",
            "reviewing",
            "closing",
        }:
            phase = "unknown"
        if not isinstance(revision, int):
            revision = "unknown"
        if not isinstance(checkpoint_revision, int):
            checkpoint_revision = "unknown"
        context = (
            base
            + f"This session is bound to task {state.get('task_id')} "
            + f"({status}/{phase}, state revision "
            + f"{revision}, checkpoint revision "
            + f"{checkpoint_revision}). Read {checkpoint} and run "
            + f"aoi resume --task "
            + f"{state.get('task_id')} before continuing. "
        )
        if source in {"resume", "compact"}:
            context += (
                "This is a resume/compaction boundary: reconstruct from the "
                "task checkpoint and current files, not from conversational memory. "
            )
    elif mapping_status == "corrupt":
        context = (
            base
            + "This session has a corrupt or inconsistent harness mapping. Do not "
            + "perform material work until root runs harness doctor and explicitly "
            + "repairs or rebinds the session. The hook is a procedural guardrail, "
            + "not a filesystem sandbox. "
        )
    else:
        display_id = session_id if SAFE_DISPLAY_ID.fullmatch(session_id) else ""
        context = (
            base
            + "No unambiguous task mapping exists for this session. Before any "
            + "material edit or external action, resume or initialize exactly one task "
            + "and bind this session. "
        )
        if display_id:
            context += (
                "After selecting the task, run "
                + "aoi bind-session --task "
                + f"<task-id> --session-id {display_id}. "
            )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": context,
            }
        }
    )


def subagent_start(root: Path, payload: dict[str, Any]) -> None:
    agent_type = str(payload.get("agent_type", "subagent"))
    if not SAFE_DISPLAY_ID.fullmatch(agent_type):
        agent_type = "subagent"
    paths = get_paths(root)
    # Import lazily so ordinary hook startup remains tiny and bytecode-free.
    from .cli import observe_subagent_start

    outcome = observe_subagent_start(paths, payload)
    status = outcome.get("status")
    if status == "authorized":
        context = (
            f"AOI observed a valid pre-armed dispatch for {paths.project.name!r}: "
            f"task={outcome.get('task_id')}, packet={outcome.get('packet_id')}, "
            f"contract={outcome.get('packet_path')}. Role={agent_type}. Read that exact "
            "packet before work and stay inside its scope. The root owns AOI state, "
            f"claims, plan, checkpoint, and final completion; do not edit {paths.harness}. "
            "Return a bounded conclusion with exact evidence/artifact paths, files inspected "
            "or changed, verification, unresolved risks, and one next action; never paste raw logs."
        )
    elif status == "incident":
        context = (
            "AOI observed this sub-agent start without one valid, unique pre-armed packet. "
            f"Incident={outcome.get('incident_id')}; reason={outcome.get('reason_code')}. "
            "The start already occurred and this hook cannot terminate it. Stop without "
            "material work, do not inspect or edit project files, and report the incident id "
            "to the parent so the Chief can account it explicitly."
        )
    elif status == "corrupt":
        context = (
            "AOI could not validate the parent task mapping or packet authority for this "
            f"start; reason={outcome.get('reason_code')}. Stop without material work and "
            "report the corrupt authority to the parent. This hook observes starts but "
            "cannot terminate an already-created sub-agent."
        )
    else:
        context = (
            "AOI found no task mapping for the parent session, so it could not consume a "
            "packet arm or persist a task incident. Stop without material work and ask the "
            "parent to bind a task and arm an exact packet before retrying."
        )
    if outcome.get("index_refresh_deferred") is True:
        context += (
            " AOI committed the target task event but deferred the derived INDEX refresh; "
            "report this to the parent so the Chief can run doctor/status."
        )
    if outcome.get("parent_mapping_deferred") is True:
        context += (
            " AOI could not publish this depth-one agent's parent-only mapping; do not "
            "spawn a child and report the condition to the Chief."
        )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": context,
            }
        }
    )


def user_prompt_submit(root: Path, payload: dict[str, Any]) -> None:
    session_id = str(payload.get("session_id", ""))
    mapping_status, mapped = session_state(root, session_id)
    base = (
        "AOI per-turn check: substantial implementation/document/evidence "
        "work requires one approved plan, explicit claims, bounded packets, and a "
        "semantic checkpoint. Trivial read-only answers do not require a task. "
    )
    if mapping_status == "subagent_parent" and mapped:
        state, _ = mapped
        packet = next(
            item
            for item in state.get("packets", [])
            if isinstance(item, dict) and item.get("agent_id") == session_id
        )
        context = (
            base
            + f"Continue only bounded packet {packet.get('packet_id')} for task "
            + f"{state.get('task_id')}. This parent-only mapping is not Chief/root "
            + "authority; do not mutate AOI lifecycle state."
        )
    elif mapping_status == "unbound":
        context = (
            base
            + "This session is not bound to a valid harness task. Before any material "
            "mutation or external launch, initialize/resume and bind exactly one task. "
            "Read-only work requires no task; do not add lifecycle boilerplate unless "
            "it is relevant to the user's request."
        )
    elif mapping_status == "corrupt":
        context = (
            base
            + "This session has a corrupt or inconsistent harness mapping. Do not "
            + "perform material work until root runs harness doctor and explicitly "
            + "repairs or rebinds the session."
        )
    else:
        assert mapped is not None
        state, task_dir = mapped
        status = state.get("status")
        if status in {"done", "cancelled"}:
            context = (
                base
                + f"The mapped task {state.get('task_id')} is {status}. Do not reuse its "
                "closed lifecycle for new material work; initialize/resume another task "
                "and rebind this session."
            )
        else:
            context = (
                base
                + f"Continue task {state.get('task_id')} and reconstruct from "
                + f"{task_dir / 'checkpoint.md'} plus current files."
            )
    write_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": context,
            }
        }
    )


def stop(root: Path, payload: dict[str, Any]) -> None:
    if payload.get("stop_hook_active") is True:
        allow()
        return
    session_id = str(payload.get("session_id", ""))
    mapping_status, mapped = session_state(root, session_id)
    if mapping_status == "subagent_parent":
        allow()
        return
    if mapping_status == "unbound":
        allow()
        return
    if mapping_status == "corrupt" or mapped is None:
        write_output(
            {
                "decision": "block",
                "reason": (
                    "AOI session mapping is corrupt or inconsistent. Run `aoi doctor` "
                    "and explicitly repair or rebind the session before stopping."
                ),
            }
        )
        return
    state, _ = mapped
    try:
        revision = int(state["revision"])
        checkpoint_revision = int(state["checkpoint_revision"])
        required = state["checkpoint_required"]
        status = state["status"]
    except (KeyError, TypeError, ValueError):
        write_output(
            {
                "decision": "block",
                "reason": "AOI task state is malformed; run harness doctor before stopping.",
            }
        )
        return
    if not isinstance(required, bool):
        write_output(
            {
                "decision": "block",
                "reason": "AOI task state is malformed; run harness doctor before stopping.",
            }
        )
        return
    if status in {"done", "cancelled"}:
        write_output(
            {
                "decision": "block",
                "reason": (
                    f"This session is still mapped to closed AOI task {state.get('task_id')}. "
                    "For read-only follow-up, state that explicitly; for new material work, "
                    "initialize/resume a task and rebind before stopping."
                ),
            }
        )
        return
    if status not in {"active", "blocked"}:
        write_output(
            {
                "decision": "block",
                "reason": "AOI task status is invalid; run harness doctor before stopping.",
            }
        )
        return
    checkpoint = get_paths(root).tasks / state["task_id"] / "checkpoint.md"
    expected_hash = state.get("checkpoint_sha256")
    try:
        actual_hash = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    except OSError:
        actual_hash = "missing"
    if (
        required
        or checkpoint_revision != revision
        or not isinstance(expected_hash, str)
        or actual_hash != expected_hash
    ):
        task_id = state["task_id"]
        write_output(
            {
                "decision": "block",
                "reason": (
                    f"AOI task {task_id} has stale semantic state "
                    f"(state rev {revision}, checkpoint rev {checkpoint_revision}, "
                    f"required={str(required).lower()}, file_hash_match="
                    f"{str(actual_hash == expected_hash).lower()}). Before stopping, run "
                    f"aoi checkpoint --task "
                    f"{task_id} --next-action \"<one exact next action>\" and summarize "
                    "material facts, changed files, evidence boundary, and risks."
                ),
            }
        )
        return
    allow()


def dispatch(payload: dict[str, Any]) -> None:
    root = root_path()
    event = str(payload.get("hook_event_name", ""))
    if event == "SessionStart":
        session_start(root, payload)
    elif event == "UserPromptSubmit":
        user_prompt_submit(root, payload)
    elif event == "SubagentStart":
        subagent_start(root, payload)
    elif event == "Stop":
        stop(root, payload)
    else:
        allow()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optional fail-open Codex lifecycle adapter for AOI"
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
