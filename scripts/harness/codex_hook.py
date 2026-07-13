#!/usr/bin/env python3
"""Tiny, fail-open Codex hook dispatcher for the ARISE harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SUPPORTED_HOOK_VERSION = "5"
SAFE_DISPLAY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def root_path() -> Path:
    configured = os.environ.get("ARISE_HARNESS_ROOT")
    return (
        Path(configured).resolve()
        if configured
        else Path(__file__).resolve().parents[2]
    )


def read_input() -> dict[str, Any]:
    raw = sys.stdin.buffer.read().decode("utf-8-sig")
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
    key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    mapping_path = root / "notes" / "harness" / "sessions" / f"{key}.json"
    if not mapping_path.exists():
        return "unbound", None
    try:
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        if not isinstance(mapping, dict) or mapping.get("session_id") != session_id:
            return "corrupt", None
        task_id = str(mapping.get("task_id", ""))
        if not SAFE_TASK_ID.fullmatch(task_id):
            return "corrupt", None
        task_dir = root / "notes" / "harness" / "tasks" / task_id
        state_path = task_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("task_id") != task_id:
            return "corrupt", None
        session_ids = state.get("session_ids")
        if not isinstance(session_ids, list) or session_id not in session_ids:
            return "corrupt", None
        return "valid", (state, task_dir)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return "corrupt", None


def session_start(root: Path, payload: dict[str, Any]) -> None:
    session_id = str(payload.get("session_id", ""))
    source = str(payload.get("source", "startup"))
    mapping_status, mapped = session_state(root, session_id)
    base = (
        "ARISE harness v1 is active. The implementation repo is "
        "/workspace/project, even when this task is opened from "
        "D:\\Documents\\ARISE. Read AGENTS.md, notes/harness/POLICY.md, and the "
        "short notes/harness/INDEX.md. Root alone writes harness state; use "
        "bounded sub-agent packets and do not scan the full legacy "
        "notes/SESSION_CONTROL.md unless a warning names a row. "
    )
    if mapping_status == "valid" and mapped:
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
            "waiting_eda",
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
            + f"python3 scripts/harness/arise_harness.py resume --task "
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
            + "material edit or EDA action, resume or initialize exactly one task "
            + "and bind this session. "
        )
        if display_id:
            context += (
                "After selecting the task, run "
                + "python3 scripts/harness/arise_harness.py bind-session --task "
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
    context = (
        "ARISE sub-agent contract: actual repo=/workspace/project. "
        f"Role={agent_type}. Work only inside the packet named by the root. "
        "The root owns task state, claims, plan, checkpoint, and final completion. "
        "Do not edit notes/harness, do not scan the full legacy SESSION_CONTROL.md, "
        "and do not launch an unrequested long EDA job. Return a bounded summary "
        "with conclusion, exact evidence/artifact paths, files inspected or changed, "
        "verification, unresolved risks, and one next action; never paste raw logs."
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
        "ARISE per-turn harness check: substantial code/RTL/EDA/document/evidence "
        "work requires one approved plan, explicit claims, bounded packets, and a "
        "semantic checkpoint. Trivial read-only answers do not require a task. "
    )
    if mapping_status == "unbound":
        context = (
            base
            + "This session is not bound to a valid harness task. Before any material "
            "mutation or EDA launch, initialize/resume and bind exactly one task. "
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
    if mapping_status == "unbound":
        allow()
        return
    if mapping_status == "corrupt" or mapped is None:
        write_output(
            {
                "decision": "block",
                "reason": (
                    "ARISE session mapping is corrupt or inconsistent. Run harness "
                    "doctor and explicitly repair or rebind the session before stopping."
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
                "reason": "ARISE task state is malformed; run harness doctor before stopping.",
            }
        )
        return
    if not isinstance(required, bool):
        write_output(
            {
                "decision": "block",
                "reason": "ARISE task state is malformed; run harness doctor before stopping.",
            }
        )
        return
    if status in {"done", "cancelled"}:
        write_output(
            {
                "decision": "block",
                "reason": (
                    f"This session is still mapped to closed ARISE task {state.get('task_id')}. "
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
                "reason": "ARISE task status is invalid; run harness doctor before stopping.",
            }
        )
        return
    checkpoint = root / "notes" / "harness" / "tasks" / state["task_id"] / "checkpoint.md"
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
                    f"ARISE task {task_id} has stale semantic state "
                    f"(state rev {revision}, checkpoint rev {checkpoint_revision}, "
                    f"required={str(required).lower()}, file_hash_match="
                    f"{str(actual_hash == expected_hash).lower()}). Before stopping, run "
                    f"python3 scripts/harness/arise_harness.py checkpoint --task "
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
    parser = argparse.ArgumentParser(add_help=False)
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
